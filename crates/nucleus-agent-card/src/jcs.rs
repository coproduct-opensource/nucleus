//! RFC 8785 JSON Canonicalization Scheme (JCS) for [`AgentCard`] —
//! A2A v1.0 §8.4.1.
//!
//! Both the signer and the verifier MUST canonicalize the card the exact
//! same way, or a valid signature would fail to verify. This module is the
//! single source of that canonicalization, built on the [`serde_jcs`]
//! crate (RFC 8785 compliant).
//!
//! Spec rules implemented here (§8.4.1):
//!
//! 1. **Presence**: unset optional fields and default-valued fields are
//!    omitted — enforced by the serde `skip_serializing_if` attributes on
//!    [`AgentCard`], so serialization already reflects field presence.
//! 2. **RFC 8785**: lexicographic key order, canonical number/string
//!    forms, no insignificant whitespace — `serde_jcs`.
//! 3. **Signature exclusion**: the `signatures` field MUST be excluded
//!    from the content being signed — removed here, structurally, for
//!    both signer and verifier.

use crate::card::AgentCard;
use crate::{Error, Result};

/// Canonicalize an [`AgentCard`] to its A2A §8.4.1 signing payload: the
/// RFC 8785 (JCS) bytes of the card **with the `signatures` field
/// excluded**.
///
/// The output is deterministic: lexicographically-sorted object keys,
/// no insignificant whitespace, and canonical number/string formatting.
/// These are exactly the bytes the JWS signature covers — for an unsigned
/// and a signed copy of the same card they are identical, which is what
/// makes the detached signature verifiable at all.
///
/// This is the SIGNER's path (and the verify path for callers who only
/// hold a typed struct): it covers exactly the fields [`AgentCard`]
/// models. A verifier that received the card as raw JSON should
/// canonicalize the received document instead — see
/// [`canonicalize_received`] — so the signature is checked over what was
/// actually received, unknown members included.
pub fn canonicalize(card: &AgentCard) -> Result<Vec<u8>> {
    let value = serde_json::to_value(card).map_err(|e| Error::Canonicalize(e.to_string()))?;
    canonicalize_received(&value)
}

/// Canonicalize a RECEIVED Agent Card document (raw JSON) to its A2A
/// §8.4.3 verification payload: remove the `signatures` member (§8.4.1
/// rule 3), keep **every other member exactly as received**, and RFC 8785
/// (JCS)-canonicalize the result.
///
/// # Why "keep everything as received" satisfies §8.4.1's presence rules
///
/// §8.4.3 steps 3–6 operate on "the received Agent Card", and step 3 says
/// to "remove properties with default values". Read against §8.4.1 rule 1,
/// that removal is schema-directed: it distinguishes `optional` fields
/// (explicit presence — include when present, even at a default value)
/// from non-`optional`, non-`REQUIRED` fields (implicit presence — omit at
/// the default value). The §8.4.1 worked example shows both:
/// `capabilities.streaming: false` is *kept* ("optional field, present in
/// JSON (explicitly set)") while `capabilities.extensions: []` is
/// *omitted* ("repeated field (not REQUIRED) with empty array").
///
/// A verifier of a raw received document cannot apply that distinction to
/// members it does not model — it has no schema for them. But it does not
/// need to, because of how conformant producers serialize (A2A ADR-001,
/// ProtoJSON): an implicit-presence field at its default value is *never
/// emitted on the wire* in the first place, and the §8.4.2 signing
/// procedure strips the same members before signing. So for a conformantly
/// serialized card, presence in the received JSON IS the §8.4.1 rule-1
/// signal: every member present was either `REQUIRED`, an explicitly-set
/// `optional`, or non-default — all of which the canonical form INCLUDES —
/// and every member the canonical form would omit is already absent.
/// "Remove `signatures`, keep the rest, JCS" therefore computes exactly
/// the §8.4.1 canonical payload, without needing a schema for unknown
/// members — which is what makes verifying a card signed by a newer
/// implementation (over members this version does not model) possible at
/// all.
///
/// For a NON-conformant document that materializes an implicit-presence
/// default (e.g. a literal `"extensions": []` a conformant signer would
/// have stripped), this canonicalization yields different bytes than the
/// signer's and verification fails. That is the fail-closed direction: we
/// never accept a signature over bytes that differ from what was received.
///
/// # Errors
///
/// [`Error::Canonicalize`] if the document is not a JSON object or JCS
/// serialization fails.
pub fn canonicalize_received(received: &serde_json::Value) -> Result<Vec<u8>> {
    let obj = received.as_object().ok_or_else(|| {
        Error::Canonicalize("received Agent Card document is not a JSON object".to_string())
    })?;
    let mut stripped = obj.clone();
    // §8.4.1 rule 3: the signatures member itself MUST be excluded from
    // the content being signed (avoids the circular dependency).
    stripped.remove("signatures");
    serde_jcs::to_vec(&serde_json::Value::Object(stripped))
        .map_err(|e| Error::Canonicalize(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    use crate::card::{
        AgentCapabilities, AgentCardSignature, AgentInterface, MutualTlsSecurityScheme,
        SecurityScheme, A2A_PROTOCOL_VERSION,
    };

    /// RFC 8785 Appendix B reference vector. Pins our JCS implementation
    /// against the spec's own example so a future dependency swap that
    /// silently changes canonicalization is caught immediately.
    // The RFC 8785 vector intentionally feeds a float with more digits
    // than an f64 can hold — that excess precision is the POINT (JCS must
    // round it to the shortest round-trippable form). Allow the lint here.
    #[allow(clippy::excessive_precision)]
    #[test]
    fn jcs_matches_rfc8785_reference_vector() {
        // The `string` value is the exact char sequence from the spec:
        // €, $, U+000F, newline, A, ', B, ", \, ", / — built from char
        // escapes so no stray bytes sneak in via the source file.
        let string_value: String = [
            '\u{20ac}', '$', '\u{000F}', '\n', 'A', '\'', 'B', '"', '\\', '"', '/',
        ]
        .iter()
        .collect();
        let value = serde_json::json!({
            "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
            "string": string_value,
            "literals": [null, true, false]
        });

        // Expected canonical output per RFC 8785: keys sorted, whitespace
        // stripped, numbers in shortest round-trippable form, control chars
        // below 0x20 as lowercase `\u00xx` (U+000F here), `\n` short escape,
        // and `"`/`\` backslash-escaped.
        let expected = concat!(
            r#"{"literals":[null,true,false],"#,
            r#""numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"#,
            "\"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\"/\"}"
        );

        let got = serde_jcs::to_string(&value).unwrap();
        assert_eq!(got, expected, "JCS output must match RFC 8785 reference");
    }

    /// The smaller, independently-checkable invariant the signer/verifier
    /// rely on: key ordering is normalized regardless of input order.
    #[test]
    fn jcs_sorts_keys_independent_of_insertion_order() {
        let a = serde_json::json!({"b": 1, "a": 2, "c": 3});
        let b = serde_json::json!({"c": 3, "a": 2, "b": 1});
        assert_eq!(
            serde_jcs::to_vec(&a).unwrap(),
            serde_jcs::to_vec(&b).unwrap()
        );
        assert_eq!(serde_jcs::to_string(&a).unwrap(), r#"{"a":2,"b":1,"c":3}"#);
    }

    fn minimal_card() -> AgentCard {
        AgentCard {
            name: "Minimal Agent".to_string(),
            description: "canonicalization test".to_string(),
            supported_interfaces: vec![AgentInterface {
                url: "https://min.example.com/a2a/v1".to_string(),
                protocol_binding: "JSONRPC".to_string(),
                tenant: None,
                protocol_version: A2A_PROTOCOL_VERSION.to_string(),
            }],
            provider: None,
            version: "0.1.0".to_string(),
            documentation_url: None,
            capabilities: AgentCapabilities::default(),
            security_schemes: BTreeMap::from([
                (
                    "b".to_string(),
                    SecurityScheme::MutualTls(MutualTlsSecurityScheme {
                        description: "first inserted".to_string(),
                    }),
                ),
                (
                    "a".to_string(),
                    SecurityScheme::MutualTls(MutualTlsSecurityScheme::default()),
                ),
            ]),
            security_requirements: vec![],
            default_input_modes: vec!["application/json".to_string()],
            default_output_modes: vec!["application/json".to_string()],
            skills: vec![],
            signatures: vec![],
            icon_url: None,
        }
    }

    /// `canonicalize(card)` is stable across clones and re-serialization —
    /// the property the whole sign/verify contract depends on.
    #[test]
    fn canonicalize_is_deterministic() {
        let card = minimal_card();
        let first = canonicalize(&card).unwrap();
        let second = canonicalize(&card.clone()).unwrap();
        assert_eq!(first, second);
        // Keys inside the nested securitySchemes map are sorted ("a"
        // before "b" despite "b" being listed first above).
        let s = String::from_utf8(first).unwrap();
        assert!(
            s.contains(
                r#""securitySchemes":{"a":{"mtlsSecurityScheme":{}},"b":{"mtlsSecurityScheme":{"description":"first inserted"}}}"#
            ),
            "got: {s}"
        );
    }

    /// §8.4.1 rule 3: the signatures field is excluded — an unsigned card
    /// and the same card carrying signatures canonicalize to the SAME
    /// bytes, which is what lets a verifier reconstruct the signed payload.
    #[test]
    fn signatures_field_is_excluded_from_canonical_bytes() {
        let unsigned = minimal_card();
        let mut signed = unsigned.clone();
        signed.signatures = vec![AgentCardSignature {
            protected: "eyJhbGciOiJFUzI1NiJ9".to_string(),
            signature: "c2ln".to_string(),
            header: None,
        }];
        let a = canonicalize(&unsigned).unwrap();
        let b = canonicalize(&signed).unwrap();
        assert_eq!(a, b, "signatures must not be part of the signed content");
        assert!(!String::from_utf8(b).unwrap().contains("signatures"));
    }

    /// The typed path and the received-document path agree byte-for-byte
    /// on a card this version fully models — the equivalence that lets
    /// `verify_card` (struct) and `verify_card_json` (raw document)
    /// accept the same signatures.
    #[test]
    fn received_document_canonicalization_matches_the_struct_path() {
        let card = minimal_card();
        let doc = serde_json::to_value(&card).unwrap();
        assert_eq!(
            canonicalize(&card).unwrap(),
            canonicalize_received(&doc).unwrap()
        );
    }

    /// A member present in the received document — modeled or not — is
    /// part of the canonical payload. This is the §8.4.1 rule-1 reading
    /// (presence in the received JSON is the explicitly-set signal): an
    /// unknown member must CHANGE the bytes, so a signature that did not
    /// cover it cannot verify, and one that did cover it can.
    #[test]
    fn received_document_keeps_unknown_members() {
        let mut doc = serde_json::to_value(minimal_card()).unwrap();
        let baseline = canonicalize_received(&doc).unwrap();
        doc.as_object_mut()
            .unwrap()
            .insert("futureField".to_string(), serde_json::json!("v1.1"));
        let with_unknown = canonicalize_received(&doc).unwrap();
        assert_ne!(baseline, with_unknown);
        assert!(String::from_utf8(with_unknown)
            .unwrap()
            .contains(r#""futureField":"v1.1""#));
    }

    #[test]
    fn received_document_must_be_a_json_object() {
        for not_a_card in [
            serde_json::json!([1, 2, 3]),
            serde_json::json!("string"),
            serde_json::json!(null),
        ] {
            assert!(matches!(
                canonicalize_received(&not_a_card),
                Err(Error::Canonicalize(_))
            ));
        }
    }
}
