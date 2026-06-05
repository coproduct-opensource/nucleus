//! Verifier for [`Proof`]-bearing [`LineageEdge`] records.
//!
//! Loads a JWKS (JSON Web Key Set, RFC 7517 + 8037 for Ed25519 OKP keys),
//! looks up signing keys by `kid`, and verifies signatures against
//! [`canonical_edge_bytes`].
//!
//! This module is always compiled — production binaries that only verify
//! lineage logs (e.g. `nucleus lineage`) need exactly this surface. The
//! signing side ([`LocalIssuer`](crate::local_issuer)) is gated behind the
//! `dev` cargo feature.
//!
//! # Trust model
//!
//! - `Jwks` is the verifier's trust anchor: every key in the set is
//!   considered authoritative for its `kid`. The walker is responsible for
//!   loading the JWKS from a trusted source (file, signed bundle, OIDC
//!   discovery).
//! - `verify_proof` rejects on missing-key, wrong-algorithm, malformed-key,
//!   and signature mismatch. It does NOT check expiry — proofs themselves
//!   carry no `exp`; the JWT-SVID's `exp` is the lifetime constraint and
//!   that's verified separately by the relying party of the JWT (not here).
//! - The trust-domain authority of the `child` is NOT cross-checked against
//!   the JWKS at this layer; that's a policy decision (e.g. "audit-log
//!   issuer must have authority X"). Add such checks at the caller.

use std::collections::HashMap;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::edge::LineageEdge;
use crate::proof::canonical_edge_bytes;

/// JSON Web Key Set — a small subset sufficient to verify Ed25519 OKP keys.
///
/// Wire format compatible with [RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517);
/// unrecognized fields are ignored on parse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

/// One JSON Web Key, restricted to Ed25519 (OKP / Ed25519). Other key types
/// in the same JWKS are parsed-but-ignored for verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(default)]
    pub crv: Option<String>,
    pub kid: String,
    /// Base64url-encoded public-key bytes (32 bytes for Ed25519).
    #[serde(default)]
    pub x: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default, rename = "use")]
    pub use_: Option<String>,
    /// Optional validity-window start. If present, an edge signed before this
    /// instant is rejected for this key. Non-standard per RFC 7517 but
    /// conventional in JWKS-with-overlap rotation deployments: during a
    /// rotation the issuer publishes the old key with `not_after = now` and the
    /// new key with `not_before = now`, so edges signed under either key still
    /// verify for the overlap window. Absent ⇒ no lower bound (legacy keys keep
    /// verifying exactly as before).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<DateTime<Utc>>,
    /// Optional validity-window end. If present, an edge signed after this
    /// instant is rejected for this key. Absent ⇒ no upper bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_after: Option<DateTime<Utc>>,
}

impl Jwk {
    /// Check that `at` falls within this key's optional `[not_before, not_after]`
    /// validity window. Keys with neither bound set always pass (legacy
    /// behavior). Used by the walker to honor JWKS rotation: a key only
    /// verifies edges whose timestamp is inside the window it was published for.
    fn check_validity_window(&self, at: DateTime<Utc>) -> Result<(), VerifyError> {
        if let Some(nbf) = self.not_before {
            if at < nbf {
                return Err(VerifyError::KeyNotYetValid {
                    kid: self.kid.clone(),
                    ts: at,
                    not_before: nbf,
                });
            }
        }
        if let Some(exp) = self.not_after {
            if at > exp {
                return Err(VerifyError::KeyExpired {
                    kid: self.kid.clone(),
                    ts: at,
                    not_after: exp,
                });
            }
        }
        Ok(())
    }
}

/// Errors returned by [`verify_proof`].
#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("edge has no `proof` field")]
    Unsigned,
    #[error("no key in JWKS with kid {kid:?}")]
    UnknownKid { kid: String },
    #[error("JWKS key {kid:?} has unsupported alg {alg:?} (expected EdDSA)")]
    UnsupportedAlg { kid: String, alg: String },
    #[error("JWKS key {kid:?} has unsupported kty/crv {kty:?}/{crv:?} (expected OKP/Ed25519)")]
    UnsupportedKey {
        kid: String,
        kty: String,
        crv: String,
    },
    #[error("JWKS key {kid:?} has missing or malformed `x` parameter")]
    MalformedKey { kid: String },
    #[error("signature length {got} != 64 bytes (Ed25519)")]
    BadSignatureLength { got: usize },
    #[error("signature verification failed for kid {kid:?}")]
    BadSignature { kid: String },
    #[error("JWKS key {kid:?} is not yet valid: edge ts {ts} < not_before {not_before}")]
    KeyNotYetValid {
        kid: String,
        ts: DateTime<Utc>,
        not_before: DateTime<Utc>,
    },
    #[error("JWKS key {kid:?} is expired: edge ts {ts} > not_after {not_after}")]
    KeyExpired {
        kid: String,
        ts: DateTime<Utc>,
        not_after: DateTime<Utc>,
    },
    #[error(
        "hash chain broken: edge claims prev_hash={claimed_hex:?} but expected {expected_hex:?}"
    )]
    BrokenChain {
        claimed_hex: String,
        expected_hex: String,
    },
}

impl Jwks {
    /// Parse a JWKS from JSON bytes (e.g., contents of a `.jwks.json` file).
    pub fn parse(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Lookup verifying key by `kid`. Only Ed25519 / OKP keys are returned;
    /// other types yield `Err(UnsupportedKey)`.
    pub fn verifying_key(&self, kid: &str) -> Result<VerifyingKey, VerifyError> {
        let jwk =
            self.keys
                .iter()
                .find(|k| k.kid == kid)
                .ok_or_else(|| VerifyError::UnknownKid {
                    kid: kid.to_string(),
                })?;
        if jwk.kty != "OKP" || jwk.crv.as_deref() != Some("Ed25519") {
            return Err(VerifyError::UnsupportedKey {
                kid: kid.to_string(),
                kty: jwk.kty.clone(),
                crv: jwk.crv.clone().unwrap_or_default(),
            });
        }
        if let Some(alg) = jwk.alg.as_deref() {
            if alg != "EdDSA" {
                return Err(VerifyError::UnsupportedAlg {
                    kid: kid.to_string(),
                    alg: alg.to_string(),
                });
            }
        }
        let x_b64 = jwk.x.as_deref().ok_or_else(|| VerifyError::MalformedKey {
            kid: kid.to_string(),
        })?;
        let bytes = URL_SAFE_NO_PAD
            .decode(x_b64)
            .map_err(|_| VerifyError::MalformedKey {
                kid: kid.to_string(),
            })?;
        let arr: [u8; 32] = bytes.try_into().map_err(|_| VerifyError::MalformedKey {
            kid: kid.to_string(),
        })?;
        VerifyingKey::from_bytes(&arr).map_err(|_| VerifyError::MalformedKey {
            kid: kid.to_string(),
        })
    }
}

/// Verify a signed [`LineageEdge`] against a JWKS.
///
/// Validates the cryptographic signature on the edge's `Proof` against the
/// canonical bytes derived from the edge content + the supplied `prev_hash`
/// from the chain. Use [`canonical_edge_bytes`] to compute the right bytes.
///
/// Returns `Err(VerifyError::Unsigned)` if the edge has no `proof`.
pub fn verify_proof(
    edge: &LineageEdge,
    prev_hash: Option<&[u8; 32]>,
    jwks: &Jwks,
) -> Result<(), VerifyError> {
    let proof = edge.proof.as_ref().ok_or(VerifyError::Unsigned)?;

    // Cross-check the chain: if the proof claims a prev_hash, it must match
    // what the verifier computed independently from the previous edge.
    if let Some(claimed) = proof.prev_hash.as_ref() {
        let expected = prev_hash.copied().unwrap_or([0u8; 32]);
        if claimed != &expected {
            return Err(VerifyError::BrokenChain {
                claimed_hex: hex::encode(claimed),
                expected_hex: hex::encode(expected),
            });
        }
    }

    // alg / kid / sig length sanity.
    if proof.alg != "EdDSA" {
        return Err(VerifyError::UnsupportedAlg {
            kid: proof.kid.clone(),
            alg: proof.alg.clone(),
        });
    }
    if proof.sig.len() != 64 {
        return Err(VerifyError::BadSignatureLength {
            got: proof.sig.len(),
        });
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&proof.sig);
    let sig = Signature::from_bytes(&sig_arr);

    // Honor JWKS rotation: if the key carries a validity window, the edge's
    // timestamp must fall inside it. Keys without a window verify as before.
    if let Some(jwk) = jwks.keys.iter().find(|k| k.kid == proof.kid) {
        jwk.check_validity_window(edge.ts)?;
    }

    let vk = jwks.verifying_key(&proof.kid)?;
    let bytes = canonical_edge_bytes(edge, prev_hash);
    vk.verify_strict(&bytes, &sig)
        .map_err(|_| VerifyError::BadSignature {
            kid: proof.kid.clone(),
        })
}

/// Convenience: verify a sequence of edges in chain order. Each edge's
/// `prev_hash` must match the previous edge's `edge_content_hash`. Returns
/// the index + error of the first failure; on success returns `Ok(())`.
pub fn verify_chain(edges: &[LineageEdge], jwks: &Jwks) -> Result<(), (usize, VerifyError)> {
    let mut prev: Option<[u8; 32]> = None;
    for (i, edge) in edges.iter().enumerate() {
        verify_proof(edge, prev.as_ref(), jwks).map_err(|e| (i, e))?;
        prev = Some(crate::proof::edge_content_hash(edge, prev.as_ref()));
    }
    Ok(())
}

/// Resolve a kid to a `VerifyingKey` from a static map. Useful for tests or
/// for callers that want to bypass JWKS parsing entirely.
pub struct StaticKeyResolver {
    keys: HashMap<String, VerifyingKey>,
}

impl StaticKeyResolver {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    pub fn insert(mut self, kid: impl Into<String>, key: VerifyingKey) -> Self {
        self.keys.insert(kid.into(), key);
        self
    }

    /// Convert into a JWKS so callers can pass it to [`verify_proof`].
    pub fn into_jwks(self) -> Jwks {
        Jwks {
            keys: self
                .keys
                .into_iter()
                .map(|(kid, vk)| Jwk {
                    kty: "OKP".to_string(),
                    crv: Some("Ed25519".to_string()),
                    kid,
                    x: Some(URL_SAFE_NO_PAD.encode(vk.as_bytes())),
                    alg: Some("EdDSA".to_string()),
                    use_: Some("sig".to_string()),
                    not_before: None,
                    not_after: None,
                })
                .collect(),
        }
    }
}

impl Default for StaticKeyResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[cfg(feature = "insecure-local-issuer")]
mod tests {
    use super::*;
    use crate::edge::{EdgeKind, LineageEdge};
    use crate::id::CallSpiffeId;
    use crate::issuer::EdgeSigner;
    use crate::local_issuer::LocalIssuer;
    use crate::proof::{canonical_edge_bytes, edge_content_hash, Proof};

    fn pod() -> CallSpiffeId {
        CallSpiffeId::pod("prod.example.com", "agents", "coder").unwrap()
    }

    fn sign_edge(issuer: &LocalIssuer, edge: &LineageEdge, prev: Option<&[u8; 32]>) -> Proof {
        let bytes = canonical_edge_bytes(edge, prev);
        let sig = issuer.sign(&bytes).unwrap();
        let mut p = Proof::new(issuer.kid().to_string(), issuer.alg().to_string(), sig);
        if let Some(h) = prev {
            p = p.with_prev_hash(*h);
        }
        p
    }

    #[test]
    fn round_trip_jwks_to_verifying_key() {
        let issuer = LocalIssuer::random().unwrap();
        let jwks_json = issuer.publish_jwks();
        let jwks: Jwks = serde_json::from_value(jwks_json).unwrap();
        let vk = jwks.verifying_key(issuer.kid()).unwrap();
        assert_eq!(vk.as_bytes(), &issuer.verifying_key_bytes());
    }

    #[test]
    fn verify_proof_accepts_valid_signature() {
        let issuer = LocalIssuer::random().unwrap();
        let p = pod();
        let child = p.derive_artifact(b"x").unwrap();
        let mut edge = LineageEdge::from_parent(child, p, EdgeKind::ArtifactProduced);
        edge.proof = Some(sign_edge(&issuer, &edge, None));
        let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
        verify_proof(&edge, None, &jwks).expect("valid signature must verify");
    }

    #[test]
    fn verify_proof_rejects_tampered_edge() {
        let issuer = LocalIssuer::random().unwrap();
        let p = pod();
        let child = p.derive_artifact(b"original").unwrap();
        let mut edge = LineageEdge::from_parent(child, p.clone(), EdgeKind::ArtifactProduced);
        edge.proof = Some(sign_edge(&issuer, &edge, None));

        // Tamper: swap child to a different SPIFFE ID.
        edge.child = p.derive_artifact(b"tampered").unwrap();

        let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
        let err = verify_proof(&edge, None, &jwks).expect_err("tampered edge must not verify");
        assert!(matches!(err, VerifyError::BadSignature { .. }));
    }

    #[test]
    fn verify_proof_rejects_unknown_kid() {
        let issuer_a = LocalIssuer::random().unwrap();
        let issuer_b = LocalIssuer::random().unwrap();
        let p = pod();
        let child = p.derive_artifact(b"x").unwrap();
        let mut edge = LineageEdge::from_parent(child, p, EdgeKind::ArtifactProduced);
        edge.proof = Some(sign_edge(&issuer_a, &edge, None));
        let jwks: Jwks = serde_json::from_value(issuer_b.publish_jwks()).unwrap();
        let err = verify_proof(&edge, None, &jwks).expect_err("unknown kid must fail");
        assert!(matches!(err, VerifyError::UnknownKid { .. }));
    }

    /// Build a signed edge + a JWKS, then mutate the key's validity window.
    fn signed_edge_and_jwks() -> (LineageEdge, Jwks) {
        let issuer = LocalIssuer::random().unwrap();
        let p = pod();
        let child = p.derive_artifact(b"x").unwrap();
        let mut edge = LineageEdge::from_parent(child, p, EdgeKind::ArtifactProduced);
        edge.proof = Some(sign_edge(&issuer, &edge, None));
        let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
        (edge, jwks)
    }

    #[test]
    fn verify_proof_honors_validity_window_accept() {
        let (edge, mut jwks) = signed_edge_and_jwks();
        // Window straddling the edge timestamp → accepted.
        jwks.keys[0].not_before = Some(edge.ts - chrono::Duration::days(1));
        jwks.keys[0].not_after = Some(edge.ts + chrono::Duration::days(1));
        verify_proof(&edge, None, &jwks).expect("edge within window must verify");
    }

    #[test]
    fn verify_proof_rejects_expired_key() {
        let (edge, mut jwks) = signed_edge_and_jwks();
        // Key retired before the edge was signed → rejected (rotation).
        jwks.keys[0].not_after = Some(edge.ts - chrono::Duration::seconds(1));
        let err = verify_proof(&edge, None, &jwks).expect_err("expired key must reject");
        assert!(matches!(err, VerifyError::KeyExpired { .. }));
    }

    #[test]
    fn verify_proof_rejects_not_yet_valid_key() {
        let (edge, mut jwks) = signed_edge_and_jwks();
        // Key not active until after the edge was signed → rejected.
        jwks.keys[0].not_before = Some(edge.ts + chrono::Duration::seconds(1));
        let err = verify_proof(&edge, None, &jwks).expect_err("not-yet-valid key must reject");
        assert!(matches!(err, VerifyError::KeyNotYetValid { .. }));
    }

    #[test]
    fn verify_proof_no_window_verifies_as_before() {
        // Absent not_before/not_after ⇒ legacy behavior (always valid).
        let (edge, jwks) = signed_edge_and_jwks();
        assert!(jwks.keys[0].not_before.is_none() && jwks.keys[0].not_after.is_none());
        verify_proof(&edge, None, &jwks).expect("windowless key must verify");
    }

    #[test]
    fn verify_proof_rejects_unsigned_edge() {
        let p = pod();
        let edge = LineageEdge::pod_admit(p);
        let jwks = Jwks { keys: vec![] };
        let err = verify_proof(&edge, None, &jwks).expect_err("unsigned must fail");
        assert!(matches!(err, VerifyError::Unsigned));
    }

    #[test]
    fn verify_proof_rejects_broken_chain() {
        let issuer = LocalIssuer::random().unwrap();
        let p = pod();
        let child = p.derive_artifact(b"x").unwrap();
        let mut edge = LineageEdge::from_parent(child, p, EdgeKind::ArtifactProduced);
        // Sign claiming prev_hash = [0xAA; 32].
        edge.proof = Some(sign_edge(&issuer, &edge, Some(&[0xAA; 32])));
        // But verifier's actual prev_hash differs.
        let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
        let err =
            verify_proof(&edge, Some(&[0xBB; 32]), &jwks).expect_err("broken chain must fail");
        assert!(matches!(err, VerifyError::BrokenChain { .. }));
    }

    #[test]
    fn verify_chain_walks_a_3_edge_chain() {
        let issuer = LocalIssuer::random().unwrap();
        let p = pod();

        let mut e1 = LineageEdge::pod_admit(p.clone());
        e1.proof = Some(sign_edge(&issuer, &e1, None));
        let h1 = edge_content_hash(&e1, None);

        let bash = p.derive_tool("Bash", Some(b"x")).unwrap();
        let mut e2 = LineageEdge::from_parent(
            bash.clone(),
            p,
            EdgeKind::ToolCall {
                tool: "Bash".to_string(),
            },
        );
        e2.proof = Some(sign_edge(&issuer, &e2, Some(&h1)));
        let h2 = edge_content_hash(&e2, Some(&h1));

        let derived = bash.derive_artifact(b"y").unwrap();
        let mut e3 = LineageEdge::from_parent(derived, bash, EdgeKind::ArtifactProduced);
        e3.proof = Some(sign_edge(&issuer, &e3, Some(&h2)));

        let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
        verify_chain(&[e1, e2, e3], &jwks).expect("3-edge signed chain should verify");
    }

    #[test]
    fn static_key_resolver_round_trips_to_jwks() {
        let issuer = LocalIssuer::random().unwrap();
        let resolver = StaticKeyResolver::new().insert(
            issuer.kid().to_string(),
            VerifyingKey::from_bytes(&issuer.verifying_key_bytes()).unwrap(),
        );
        let jwks = resolver.into_jwks();
        let vk = jwks.verifying_key(issuer.kid()).unwrap();
        assert_eq!(vk.as_bytes(), &issuer.verifying_key_bytes());
    }

    #[test]
    fn jwks_ignores_unknown_extra_fields() {
        let json = serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "k1",
                "x": "AAAA_AAAAAA-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                "alg": "EdDSA",
                "use": "sig",
                "extra_unrecognized": "should be ignored",
            }]
        });
        let jwks: Jwks = serde_json::from_value(json).unwrap();
        assert_eq!(jwks.keys.len(), 1);
    }
}
