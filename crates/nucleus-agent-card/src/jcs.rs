//! RFC 8785 JSON Canonicalization Scheme (JCS) for [`AgentCard`].
//!
//! Both the signer and the verifier MUST canonicalize the card the exact
//! same way, or a valid signature would fail to verify. This module is the
//! single source of that canonicalization, built on the [`serde_jcs`]
//! crate (RFC 8785 compliant).

use crate::card::AgentCard;
use crate::{Error, Result};

/// Canonicalize an [`AgentCard`] to RFC 8785 (JCS) bytes.
///
/// The output is deterministic: lexicographically-sorted object keys,
/// no insignificant whitespace, and canonical number/string formatting.
/// These are exactly the bytes the JWS signature covers.
pub fn canonicalize(card: &AgentCard) -> Result<Vec<u8>> {
    serde_jcs::to_vec(card).map_err(|e| Error::Canonicalize(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// `canonicalize(card)` is stable across clones and re-serialization —
    /// the property the whole sign/verify contract depends on.
    #[test]
    fn canonicalize_is_deterministic() {
        let card = AgentCard {
            spiffe_id: "spiffe://prod.example.com/ns/agents/sa/coder".to_string(),
            did: "did:web:coder.prod.example.com".to_string(),
            security_schemes: serde_json::json!({"b": 1, "a": 2}),
            supported_envelope_schema_versions: vec!["1".to_string()],
            jwks_uri: None,
            trust_jwks: nucleus_lineage::Jwks { keys: vec![] },
            runtime_guarantees: None,
        };
        let first = canonicalize(&card).unwrap();
        let second = canonicalize(&card.clone()).unwrap();
        assert_eq!(first, second);
        // Keys inside the nested object are sorted.
        let s = String::from_utf8(first).unwrap();
        assert!(
            s.contains(r#""security_schemes":{"a":2,"b":1}"#),
            "got: {s}"
        );
    }
}
