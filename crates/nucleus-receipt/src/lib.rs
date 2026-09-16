//! # nucleus-receipt — the colimit receipt envelope
//!
//! This crate ships **three things**:
//!
//! 1. [`Session`] — the agent-action object every projection projects from.
//! 2. [`Projection`] — a sealed, adjacently-tagged sum type whose
//!    variants are one-per-projection-functor (Identity, Capability,
//!    Flow, Economic, …).
//! 3. [`Receipt`] — the Ed25519-signed colimit envelope holding a
//!    session and any subset of its projections.
//!
//! The envelope is the *law layer*: it defines what a receipt **is**
//! (a colimit of independently-verifiable views of one session) and
//! how its signature is computed. The concrete body type behind each
//! projection kind lives in a downstream lifter crate; this crate
//! keeps bodies as `serde_json::Value` to stay dependency-light.
//!
//! ## Wire-format guarantee
//!
//! The canonical signing input is the **RFC 8785 (JCS)** serialization
//! of `{projections, session, version}` (see
//! [`canonical_signing_bytes`]) — lexicographically sorted keys,
//! canonical number formatting, independent of how `serde_json`'s
//! features were unified in the enclosing build. Plain
//! `serde_json::to_vec` would NOT be canonical: with
//! `preserve_order` unified ON (cedar does this in full-workspace
//! builds) the same envelope serializes with different key order than
//! in a standalone build, silently splitting signers from verifiers.
//! Tests pin the exact canonical string so any drift fails CI loudly.
//!
//! ## Quick example
//!
//! ```
//! use nucleus_receipt::{Session, Receipt, Projection};
//! use ed25519_dalek::SigningKey;
//!
//! let sk = SigningKey::from_bytes(&[7u8; 32]);
//! let session = Session {
//!     session_id: "spiffe://test/agent-x".into(),
//!     issuer_kid: "test-kid".into(),
//!     issued_at_micros: 1_717_000_000_000_000,
//!     parent_chain: vec![],
//! };
//!
//! let projection = Projection::Identity(serde_json::json!({
//!     "sub": "spiffe://test/agent-x",
//!     "aud": "nucleus-substrate-test",
//! }));
//!
//! let receipt = Receipt::sign(session, vec![projection], &sk);
//!
//! // Anyone with the issuer's verifying key can verify offline.
//! let vk: [u8; 32] = sk.verifying_key().to_bytes();
//! receipt.verify(&vk).expect("self-built receipt verifies");
//! ```
//!
//! ## What's NOT in scope here
//!
//! - The concrete types each `Projection` variant carries — those live
//!   in projection-lifter crates downstream.
//! - The HTTP wire (REST routes) and the mechanism kernels (VCG,
//!   Pigouvian re-weighting) — those are *mechanisms* that emit
//!   projections; they instantiate this envelope, they don't define it.

use base64::Engine;
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};

pub const RECEIPT_VERSION: u32 = 1;

/// The unit of authorship. Every projection projects from this.
///
/// Composition: a child session adds one delegation hop to
/// `parent_chain` and gets its own `session_id` (the SPIFFE id minted
/// by the issuer for this hop). The issuer's pinned key id (`kid`)
/// stays the same across hops within one boot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Session {
    /// SPIFFE id of this session's subject.
    pub session_id: String,
    /// Key id of the issuer that signed this session's delegation.
    pub issuer_kid: String,
    /// Microseconds since UNIX epoch when the session was issued.
    pub issued_at_micros: u64,
    /// Delegation chain — SPIFFE ids of every prior hop. Empty for
    /// root sessions, non-empty for child sessions.
    pub parent_chain: Vec<String>,
}

/// One projection of a session into a verifiable record.
///
/// **Adjacently tagged** for wire compatibility with in-toto and SLSA
/// predicates. **`non_exhaustive`** so new projection kinds can be
/// added in minor releases without breaking external matchers.
///
/// Each variant's body is a `serde_json::Value` because the concrete
/// type per kind lives in a downstream lifter crate; lifters narrow
/// the JSON to their typed shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", content = "body", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Projection {
    /// Identity functor — a JWT-SVID + delegation-chain record.
    Identity(serde_json::Value),
    /// Capability functor — a point in the Portcullis quotient lattice.
    Capability(serde_json::Value),
    /// Flow functor — a FlowTracker DAG snapshot (Denning lattice).
    Flow(serde_json::Value),
    /// Economic functor — a bid+match record with Clarke-pivot payments.
    Economic(serde_json::Value),
    /// CI functor — a continuous-integration gate verdict: the gate definition,
    /// scope and environment digests it is keyed on, the tree it ran at, the
    /// verdict, and the log/output digests. The typed body lives in the
    /// consuming CI system; this crate keeps it as `serde_json::Value` like
    /// every other projection.
    Ci(serde_json::Value),
}

impl Projection {
    /// The discriminant string used on the wire. Stable across versions.
    pub fn kind(&self) -> &'static str {
        match self {
            Projection::Identity(_) => "identity",
            Projection::Capability(_) => "capability",
            Projection::Flow(_) => "flow",
            Projection::Economic(_) => "economic",
            Projection::Ci(_) => "ci",
        }
    }
}

/// **The colimit envelope.** Holds a session + any subset of its
/// projections, signed with the issuer's Ed25519 key.
///
/// Verifiers re-canonicalize the signing input (session, projections,
/// and version), recompute the BLAKE3 root hash, and re-verify the
/// signature. Each projection MAY ADDITIONALLY be re-checked by the
/// lifter that produced it; the lifter's per-kind verifier is
/// independent of this top-level signature check.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Receipt {
    pub version: u32,
    pub session: Session,
    pub projections: Vec<Projection>,
    /// BLAKE3 over [`canonical_signing_bytes`].
    pub root_hash_hex: String,
    /// Ed25519 signature over the same canonical bytes.
    pub signature_b64: String,
}

impl Receipt {
    /// Build + sign a fresh receipt with the supplied issuer key.
    pub fn sign(
        session: Session,
        projections: Vec<Projection>,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> Self {
        let canonical = canonical_signing_bytes(&session, &projections);
        let root_hash_hex = hex::encode(blake3::hash(&canonical).as_bytes());
        let sig = signing_key.sign(&canonical);
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_bytes());
        Self {
            version: RECEIPT_VERSION,
            session,
            projections,
            root_hash_hex,
            signature_b64,
        }
    }

    /// Verify this receipt against the supplied 32-byte Ed25519
    /// verifying key (as found in the issuer's JWKS `x` field).
    /// Re-canonicalizes + re-hashes independently of how the receipt
    /// was built.
    #[must_use = "the verification result must be checked; a dropped `Err` silently accepts an unverified receipt"]
    pub fn verify(&self, verifying_key_bytes: &[u8; 32]) -> Result<(), ReceiptError> {
        self.verify_strict(verifying_key_bytes)
    }

    /// Explicitly named strict Ed25519 verification, including canonical-body
    /// hash validation. `verify` is the compatibility spelling of this method.
    #[must_use = "the verification result must be checked"]
    pub fn verify_strict(&self, verifying_key_bytes: &[u8; 32]) -> Result<(), ReceiptError> {
        let vk = ed25519_dalek::VerifyingKey::from_bytes(verifying_key_bytes)
            .map_err(|e| ReceiptError::InvalidKey(e.to_string()))?;
        // The signature covers RECEIPT_VERSION, not this field: without the
        // comparison any wire `version` verifies.
        if self.version != RECEIPT_VERSION {
            return Err(ReceiptError::UnsupportedVersion {
                got: self.version,
                supported: RECEIPT_VERSION,
            });
        }
        // JCS writes numbers as doubles: an integer past ±(2^53 − 1) shares its
        // canonical form with a neighbour, so the signature could not tell them
        // apart.
        let signed = signing_value(&self.session, &self.projections);
        if let Some(path) = jcs_inexact_integer(&signed) {
            return Err(ReceiptError::InexactInteger { path });
        }
        let canonical = canonical_signing_bytes(&self.session, &self.projections);
        let computed_hash_hex = hex::encode(blake3::hash(&canonical).as_bytes());
        if computed_hash_hex != self.root_hash_hex {
            return Err(ReceiptError::RootHashMismatch {
                expected: self.root_hash_hex.clone(),
                actual: computed_hash_hex,
            });
        }
        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.signature_b64)
            .map_err(|e| ReceiptError::InvalidSignatureEncoding(e.to_string()))?;
        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| ReceiptError::InvalidSignatureEncoding("len != 64".into()))?;
        let sig = ed25519_dalek::Signature::from_bytes(&sig_array);
        vk.verify_strict(&canonical, &sig)
            .map_err(|e| ReceiptError::SignatureMismatch(e.to_string()))?;
        Ok(())
    }
}

/// Canonical signing input for a receipt. Same function is called
/// when *building* and when *verifying* — that's the entire trust
/// surface for the colimit identity.
///
/// RFC 8785 (JCS): keys lexicographically sorted at every depth,
/// canonical number formatting. Deterministic regardless of feature
/// unification (`serde_json/preserve_order`) and of the insertion
/// order of any `Value` map inside a projection body, so a receipt
/// signed by one binary verifies in every other binary built from any
/// subset of the workspace.
pub fn canonical_signing_bytes(session: &Session, projections: &[Projection]) -> Vec<u8> {
    serde_json_canonicalizer::to_vec(&signing_value(session, projections))
        .expect("envelope canonicalizes deterministically (Value cannot hold NaN/Inf)")
}

/// The JSON value [`canonical_signing_bytes`] canonicalizes.
fn signing_value(session: &Session, projections: &[Projection]) -> serde_json::Value {
    serde_json::json!({
        "version": RECEIPT_VERSION,
        "session": session,
        "projections": projections,
    })
}

/// The largest integer magnitude RFC 8785 represents exactly (2^53 − 1).
pub const MAX_EXACT_JSON_INTEGER: u64 = (1 << 53) - 1;

/// The JSON-pointer path of the first integer in `v` that RFC 8785 (JCS)
/// cannot represent exactly, if any.
///
/// JCS serializes every number as an IEEE-754 double, so `2^53` and `2^53 + 1`
/// canonicalize to the same bytes. Anything that signs JCS bytes must refuse
/// such a value, or a signature over one verifies the other. Floats are exact
/// by construction: JCS and `serde_json` both write a double's shortest form.
/// `nucleus-envelope`'s payload binding uses this too — one decider.
pub fn jcs_inexact_integer(v: &serde_json::Value) -> Option<String> {
    first_inexact_integer(v, "")
}

fn first_inexact_integer(v: &serde_json::Value, path: &str) -> Option<String> {
    use serde_json::Value;
    match v {
        Value::Number(n) => {
            let exact = match (n.as_u64(), n.as_i64()) {
                (Some(u), _) => u <= MAX_EXACT_JSON_INTEGER,
                (None, Some(i)) => i.unsigned_abs() <= MAX_EXACT_JSON_INTEGER,
                (None, None) => true,
            };
            (!exact).then(|| path.to_string())
        }
        Value::Array(items) => items
            .iter()
            .enumerate()
            .find_map(|(i, item)| first_inexact_integer(item, &format!("{path}/{i}"))),
        Value::Object(map) => map
            .iter()
            .find_map(|(k, item)| first_inexact_integer(item, &format!("{path}/{k}"))),
        Value::Null | Value::Bool(_) | Value::String(_) => None,
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReceiptError {
    #[error("verifying key invalid: {0}")]
    InvalidKey(String),
    #[error("signature encoding invalid: {0}")]
    InvalidSignatureEncoding(String),
    #[error("root hash mismatch: expected {expected}, computed {actual}")]
    RootHashMismatch { expected: String, actual: String },
    #[error("signature did not verify: {0}")]
    SignatureMismatch(String),
    /// The wire `version` is not the version the signature covers.
    #[error("receipt version {got} is not the signed version {supported}")]
    UnsupportedVersion { got: u32, supported: u32 },
    /// A signed integer has no exact RFC 8785 form, so a neighbouring value
    /// would verify in its place.
    #[error("integer at {path} is beyond ±(2^53 − 1) and has no exact canonical form")]
    InexactInteger { path: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_session() -> Session {
        Session {
            session_id: "spiffe://test/agent".into(),
            issuer_kid: "kid-1".into(),
            issued_at_micros: 1_717_000_000_000_000,
            parent_chain: vec![],
        }
    }

    fn dummy_projections() -> Vec<Projection> {
        vec![
            Projection::Identity(serde_json::json!({"sub": "spiffe://test/agent"})),
            Projection::Flow(serde_json::json!({"node_count": 3, "any_adversarial": false})),
        ]
    }

    #[test]
    fn receipt_round_trips_through_verify() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let vk: [u8; 32] = sk.verifying_key().to_bytes();
        let receipt = Receipt::sign(dummy_session(), dummy_projections(), &sk);
        receipt.verify(&vk).expect("fresh receipt must verify");
    }

    #[test]
    fn tampered_session_fails_verify() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let vk: [u8; 32] = sk.verifying_key().to_bytes();
        let mut receipt = Receipt::sign(dummy_session(), dummy_projections(), &sk);
        receipt.session.session_id = "spiffe://attacker/imposter".into();
        assert!(matches!(
            receipt.verify(&vk),
            Err(ReceiptError::RootHashMismatch { .. })
        ));
    }

    #[test]
    fn projection_added_after_signing_fails_verify() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let vk: [u8; 32] = sk.verifying_key().to_bytes();
        let mut receipt = Receipt::sign(dummy_session(), dummy_projections(), &sk);
        receipt.projections.push(Projection::Economic(
            serde_json::json!({"forged": "payment"}),
        ));
        assert!(matches!(
            receipt.verify(&vk),
            Err(ReceiptError::RootHashMismatch { .. })
        ));
    }

    /// The signature covers `RECEIPT_VERSION`, so the wire field must equal it:
    /// otherwise any version verifies.
    #[test]
    fn a_version_other_than_the_signed_one_is_refused() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let vk: [u8; 32] = sk.verifying_key().to_bytes();
        let signed = Receipt::sign(dummy_session(), dummy_projections(), &sk);
        signed.verify(&vk).expect("the signed version verifies");
        for version in [0, RECEIPT_VERSION + 1, u32::MAX] {
            let mut receipt = signed.clone();
            receipt.version = version;
            assert!(
                matches!(
                    receipt.verify(&vk),
                    Err(ReceiptError::UnsupportedVersion { got, .. }) if got == version
                ),
                "version {version} must be refused"
            );
        }
    }

    /// JCS writes numbers as doubles, so `2^53` and `2^53 + 1` share canonical
    /// bytes: a receipt signed over one would verify with the other in its place.
    #[test]
    fn an_integer_without_an_exact_canonical_form_is_refused() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let vk: [u8; 32] = sk.verifying_key().to_bytes();
        let body = |n: u64| vec![Projection::Economic(serde_json::json!({"amount": n}))];
        Receipt::sign(dummy_session(), body(MAX_EXACT_JSON_INTEGER), &sk)
            .verify(&vk)
            .expect("2^53 − 1 is exact");
        let signed = Receipt::sign(dummy_session(), body(1 << 53), &sk);
        let mut swapped = signed.clone();
        swapped.projections = body((1 << 53) + 1);
        assert_eq!(
            canonical_signing_bytes(&signed.session, &signed.projections),
            canonical_signing_bytes(&swapped.session, &swapped.projections),
            "the collision this check exists for"
        );
        for receipt in [signed, swapped] {
            assert!(matches!(
                receipt.verify(&vk),
                Err(ReceiptError::InexactInteger { ref path }) if path == "/projections/0/body/amount"
            ));
        }
    }

    #[test]
    fn wrong_verifying_key_fails_verify() {
        let sk_a = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let sk_b = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
        let receipt = Receipt::sign(dummy_session(), dummy_projections(), &sk_a);
        let vk_b: [u8; 32] = sk_b.verifying_key().to_bytes();
        assert!(matches!(
            receipt.verify(&vk_b),
            Err(ReceiptError::SignatureMismatch(_))
        ));
    }

    /// Ed25519 identity/neutral-point key encoding: y = 1, x = 0, sign 0.
    /// A small-order (order-1) verifying key.
    fn identity_vk_bytes() -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = 1;
        id
    }

    /// The "identity triple" signature: R = identity encoding, s = 0.
    /// For A = R = identity and s = 0 the cofactored verification
    /// equation `[s]B == R + [k]A` reduces to `identity == identity` for
    /// EVERY message, so non-strict `verify()` ACCEPTS it under the
    /// identity key — a key-substitution / weak-binding forgery. Strict
    /// `verify_strict()` rejects it because it refuses small-order A/R.
    fn identity_sig_bytes() -> [u8; 64] {
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&identity_vk_bytes()); // R = identity, s = 0
        sig
    }

    /// M-2 strong-binding regression (site: `Receipt::verify`, the
    /// `vk.verify_strict` call). Proves the receipt trust path rejects a
    /// small-order-key forgery that non-strict `vk.verify` would ACCEPT.
    /// If line 187 is reverted to `vk.verify(...)`, assertion (ii) fails.
    #[test]
    fn small_order_key_is_rejected_by_verify_strict() {
        // (i) No regression: an honest keypair still verifies end-to-end.
        let sk = ed25519_dalek::SigningKey::from_bytes(&[42u8; 32]);
        let honest_vk: [u8; 32] = sk.verifying_key().to_bytes();
        let honest = Receipt::sign(dummy_session(), dummy_projections(), &sk);
        honest
            .verify(&honest_vk)
            .expect("honest receipt must still verify through verify_strict");

        // (ii) Strong binding: take a well-formed receipt (correct root
        // hash over session+projections), swap in the identity-triple
        // signature, and verify against the small-order identity key.
        // Non-strict `verify` accepts this; `verify_strict` rejects it.
        let mut forged = Receipt::sign(dummy_session(), dummy_projections(), &sk);
        forged.signature_b64 =
            base64::engine::general_purpose::STANDARD.encode(identity_sig_bytes());
        assert!(
            matches!(
                forged.verify(&identity_vk_bytes()),
                Err(ReceiptError::SignatureMismatch(_))
            ),
            "small-order identity key must be REJECTED by verify_strict; \
             a revert to non-strict verify() would ACCEPT this forgery"
        );
    }

    #[test]
    fn projection_wire_format_is_adjacent_tagged() {
        // Stability check: the wire format must stay
        // `{"kind": "...", "body": ...}` for downstream consumers.
        let p = Projection::Capability(serde_json::json!({"label": "trusted"}));
        let v: serde_json::Value = serde_json::to_value(&p).unwrap();
        assert_eq!(v["kind"], "capability");
        assert!(v["body"].is_object());
    }

    #[test]
    fn projection_kind_strings_are_stable() {
        // External code may dispatch on `kind()` — assert wire names.
        assert_eq!(
            Projection::Identity(serde_json::Value::Null).kind(),
            "identity"
        );
        assert_eq!(
            Projection::Capability(serde_json::Value::Null).kind(),
            "capability"
        );
        assert_eq!(Projection::Flow(serde_json::Value::Null).kind(), "flow");
        assert_eq!(
            Projection::Economic(serde_json::Value::Null).kind(),
            "economic"
        );
        assert_eq!(Projection::Ci(serde_json::Value::Null).kind(), "ci");
    }

    #[test]
    fn canonical_bytes_are_pinned_rfc8785_json() {
        // GOLDEN: every binary that signs or verifies receipts must
        // produce these exact bytes for this envelope, or signers and
        // verifiers split. RFC 8785 (JCS) sorts keys at every depth —
        // and unlike plain `serde_json::to_vec`, the result cannot
        // flip with feature unification. (The first CI run of this
        // crate caught exactly that: cedar-policy-core unifies
        // `serde_json/preserve_order` ON in the full workspace, while
        // a standalone `cargo test -p nucleus-receipt` resolves it
        // OFF, so the pre-JCS bytes differed between the two builds.)
        let canonical = canonical_signing_bytes(&dummy_session(), &dummy_projections());
        let s = String::from_utf8(canonical).expect("canonical bytes are UTF-8 JSON");
        assert_eq!(
            s,
            concat!(
                r#"{"projections":["#,
                r#"{"body":{"sub":"spiffe://test/agent"},"kind":"identity"},"#,
                r#"{"body":{"any_adversarial":false,"node_count":3},"kind":"flow"}],"#,
                r#""session":{"issued_at_micros":1717000000000000,"issuer_kid":"kid-1","#,
                r#""parent_chain":[],"session_id":"spiffe://test/agent"},"version":1}"#
            )
        );
    }

    #[test]
    fn canonical_bytes_ignore_value_insertion_order() {
        // Two logically-equal bodies built in opposite insertion
        // order must canonicalize identically. Under
        // `preserve_order` (ON in full-workspace builds via cedar)
        // plain serialization would emit them differently; JCS must
        // not. This is the regression test for the signer/verifier
        // split the golden test caught in CI.
        let mut ab = serde_json::Map::new();
        ab.insert("alpha".into(), serde_json::json!(1));
        ab.insert("beta".into(), serde_json::json!(2));
        let mut ba = serde_json::Map::new();
        ba.insert("beta".into(), serde_json::json!(2));
        ba.insert("alpha".into(), serde_json::json!(1));

        let p_ab = vec![Projection::Flow(serde_json::Value::Object(ab))];
        let p_ba = vec![Projection::Flow(serde_json::Value::Object(ba))];
        assert_eq!(
            canonical_signing_bytes(&dummy_session(), &p_ab),
            canonical_signing_bytes(&dummy_session(), &p_ba),
        );
    }
}
