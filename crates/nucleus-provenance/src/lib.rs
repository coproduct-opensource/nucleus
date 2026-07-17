//! Fail-closed third-party **artifact provenance** verification at the pod
//! spawn boundary (most-paranoid next-bet #3).
//!
//! Move 2 made the Executor refuse to spawn unless declared *containment* meets
//! policy (`ContainmentMode::Unconfigured` ⇒ refuse). This crate extends that
//! boundary to *artifacts*: a pod must not spawn unless every third-party
//! artifact it declares (container image / package / model / MCP-server binary)
//! carries a **verified provenance attestation** — a DSSE-signed in-toto v1
//! Statement, signed by a policy-trusted Ed25519 key, whose subject digest binds
//! the declared artifact and whose `predicateType` is policy-allowed.
//!
//! Closes the install-time supply-chain gap (LiteLLM, Shai-Hulud, NullifAI):
//! an unsigned / untrusted-key / digest-mismatched / wrong-predicate artifact is
//! REFUSED, and a pod with **no provenance config but declared artifacts** is
//! refused too (fail-closed, mirroring `ContainmentMode::Unconfigured`).
//!
//! # Scope (honest)
//!
//! This is the **offline, local-key** verifier: it operates on already-resolved
//! bytes (artifact digest + attestation envelope) and verifies an Ed25519
//! signature over the DSSE PAE against a policy-listed trusted key. **Sigstore
//! keyless (Fulcio cert-chain + Rekor inclusion), live registry/attestation
//! fetch, OCI image digest-pinning, and TEE measured-boot are out of scope** and
//! are named follow-up bridges. The verifier is pure (no I/O, no network, no
//! clock) and fully unit-testable.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// in-toto v1 Statement type URI.
pub const IN_TOTO_STATEMENT_V1: &str = "https://in-toto.io/Statement/v1";
/// DSSE payload type for in-toto.
pub const IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// Digest algorithm of an artifact subject. in-toto/SLSA use `sha256`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgo {
    /// SHA-256 (the in-toto/SLSA ecosystem default).
    Sha256,
}

/// Kind of third-party artifact a pod pulls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactKind {
    /// OCI container image.
    ContainerImage,
    /// Language package (pip/npm/cargo/…).
    Package,
    /// Model weights.
    Model,
    /// MCP server binary.
    McpServerBinary,
}

/// A declared third-party artifact the pod will pull/use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRef {
    /// Artifact kind.
    pub kind: ArtifactKind,
    /// Human name / locator (e.g. `pypi:requests@2.32.0`).
    pub name: String,
    /// Subject digest algorithm.
    pub digest_algo: DigestAlgo,
    /// Expected content digest (hex) the attestation subject must bind.
    pub digest_hex: String,
}

/// A trusted Ed25519 verifying key (by keyid) that may sign attestations.
#[derive(Debug, Clone)]
pub struct TrustedKey {
    /// DSSE keyid this key answers to.
    pub keyid: String,
    /// 32-byte Ed25519 public key.
    pub key: [u8; 32],
}

/// One DSSE signature.
#[derive(Debug, Clone)]
pub struct DsseSignature {
    /// keyid identifying the signer (matched against [`TrustedKey::keyid`]).
    pub keyid: String,
    /// Raw 64-byte Ed25519 signature over the DSSE PAE.
    pub sig: Vec<u8>,
}

/// A DSSE-signed in-toto statement (already base64-decoded).
#[derive(Debug, Clone)]
pub struct SignedAttestation {
    /// The in-toto v1 Statement JSON bytes (the DSSE payload).
    pub dsse_payload: Vec<u8>,
    /// DSSE payload type (must be [`IN_TOTO_PAYLOAD_TYPE`]).
    pub payload_type: String,
    /// Signatures over the DSSE PAE of (`payload_type`, `dsse_payload`).
    pub signatures: Vec<DsseSignature>,
}

/// Provenance policy. Fail-closed by default ([`ProvenancePolicy::Unconfigured`]),
/// exactly like `ContainmentMode::Unconfigured`.
#[derive(Debug, Clone, Default)]
pub enum ProvenancePolicy {
    /// No provenance configured: if ANY artifact is declared, every spawn is
    /// refused. (A pod that declares no artifacts is vacuously admitted.)
    #[default]
    Unconfigured,
    /// Verification required against this trust anchor.
    Required {
        /// Keys allowed to sign attestations.
        trusted_keys: Vec<TrustedKey>,
        /// Allowed `predicateType` values (e.g. SLSA provenance v1).
        required_predicates: Vec<String>,
    },
}

/// Why provenance verification refused an artifact.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProvenanceError {
    /// Artifacts declared but no provenance policy configured (fail-closed).
    #[error("provenance not configured but artifact '{artifact}' is declared")]
    NotConfigured {
        /// The offending artifact name.
        artifact: String,
    },
    /// No attestation present for the artifact.
    #[error("no attestation for artifact '{artifact}'")]
    Missing {
        /// The artifact lacking an attestation.
        artifact: String,
    },
    /// An attestation exists but no policy-trusted key produced a valid signature.
    #[error("attestation for '{artifact}' not signed by any trusted key")]
    Untrusted {
        /// The artifact whose attestation failed signature verification.
        artifact: String,
    },
    /// A trusted, valid attestation exists but its subject digest doesn't match.
    #[error("attestation subject digest does not bind declared artifact '{artifact}'")]
    DigestMismatch {
        /// The artifact whose declared digest was not bound.
        artifact: String,
    },
    /// A trusted, digest-bound attestation has a non-allowed predicateType.
    #[error("attestation predicateType not allowed for artifact '{artifact}'")]
    PredicateRejected {
        /// The artifact with a rejected predicate.
        artifact: String,
    },
}

/// Result of provenance verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceVerdict {
    /// Every declared artifact is attested by a trusted, digest-bound,
    /// allowed-predicate signature.
    Admitted,
    /// At least one artifact failed; carries the first (most-specific) reason.
    Refused(ProvenanceError),
}

impl ProvenanceVerdict {
    /// Whether the verdict admits the spawn.
    pub fn is_admitted(&self) -> bool {
        matches!(self, ProvenanceVerdict::Admitted)
    }
}

/// Minimal in-toto v1 Statement (only the fields the gate binds against).
#[derive(Debug, Deserialize)]
struct InTotoStatement {
    #[serde(rename = "_type")]
    statement_type: String,
    subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    predicate_type: String,
}

#[derive(Debug, Deserialize)]
struct Subject {
    #[allow(dead_code)]
    name: String,
    /// algo → hex digest (e.g. `{"sha256": "abcd…"}`).
    digest: BTreeMap<String, String>,
}

/// Standard DSSE Pre-Authentication Encoding:
/// `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body` (LEN = ASCII-decimal).
fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + payload_type.len() + payload.len());
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// Build the DSSE PAE bytes for an attestation (the message that is signed).
pub fn attestation_pae(att: &SignedAttestation) -> Vec<u8> {
    pae(&att.payload_type, &att.dsse_payload)
}

/// SHA-256 hex of bytes — for binding artifact bytes to the declared digest.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Does any trusted key produce a valid Ed25519 signature over this PAE?
fn signed_by_trusted(att: &SignedAttestation, trusted: &[TrustedKey]) -> bool {
    let msg = attestation_pae(att);
    for sig in &att.signatures {
        let Some(tk) = trusted.iter().find(|k| k.keyid == sig.keyid) else {
            continue;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&tk.key) else {
            continue;
        };
        let Ok(sig_arr) = <[u8; 64]>::try_from(sig.sig.as_slice()) else {
            continue;
        };
        let signature = Signature::from_bytes(&sig_arr);
        if vk.verify_strict(&msg, &signature).is_ok() {
            return true;
        }
    }
    false
}

/// Parse the DSSE payload as an in-toto v1 Statement.
fn parse_statement(att: &SignedAttestation) -> Option<InTotoStatement> {
    let stmt: InTotoStatement = serde_json::from_slice(&att.dsse_payload).ok()?;
    if stmt.statement_type != IN_TOTO_STATEMENT_V1 {
        return None;
    }
    Some(stmt)
}

/// **The fail-closed provenance gate.** Verify that every declared artifact is
/// covered by a trusted, digest-bound, allowed-predicate attestation. Pure: no
/// I/O, no network, no clock. Inputs are already-resolved bytes.
pub fn verify(
    artifacts: &[ArtifactRef],
    attestations: &[SignedAttestation],
    policy: &ProvenancePolicy,
) -> ProvenanceVerdict {
    let (trusted, predicates) = match policy {
        ProvenancePolicy::Unconfigured => {
            // Fail-closed: declared artifacts with no policy ⇒ refuse.
            if let Some(a) = artifacts.first() {
                return ProvenanceVerdict::Refused(ProvenanceError::NotConfigured {
                    artifact: a.name.clone(),
                });
            }
            return ProvenanceVerdict::Admitted;
        }
        ProvenancePolicy::Required {
            trusted_keys,
            required_predicates,
        } => (trusted_keys.as_slice(), required_predicates.as_slice()),
    };

    for art in artifacts {
        // Most-specific error wins: DigestMismatch/PredicateRejected (sig valid)
        // > Untrusted (attestation present, bad sig) > Missing (nothing).
        let mut best: Option<ProvenanceError> = None;
        let bump = |e: ProvenanceError, best: &mut Option<ProvenanceError>| {
            let rank = |e: &ProvenanceError| match e {
                ProvenanceError::Missing { .. } => 0,
                ProvenanceError::Untrusted { .. } => 1,
                ProvenanceError::PredicateRejected { .. }
                | ProvenanceError::DigestMismatch { .. } => 2,
                ProvenanceError::NotConfigured { .. } => 3,
            };
            if best.as_ref().map(|b| rank(&e) >= rank(b)).unwrap_or(true) {
                *best = Some(e);
            }
        };

        let mut admitted = false;
        for att in attestations {
            if !signed_by_trusted(att, trusted) {
                bump(
                    ProvenanceError::Untrusted {
                        artifact: art.name.clone(),
                    },
                    &mut best,
                );
                continue;
            }
            let Some(stmt) = parse_statement(att) else {
                bump(
                    ProvenanceError::Untrusted {
                        artifact: art.name.clone(),
                    },
                    &mut best,
                );
                continue;
            };
            // Signature valid + parses. Now bind digest, then predicate.
            let binds = stmt.subject.iter().any(|s| {
                s.digest
                    .get("sha256")
                    .map(|d| d == &art.digest_hex)
                    .unwrap_or(false)
            });
            if !binds {
                bump(
                    ProvenanceError::DigestMismatch {
                        artifact: art.name.clone(),
                    },
                    &mut best,
                );
                continue;
            }
            if !predicates.iter().any(|p| p == &stmt.predicate_type) {
                bump(
                    ProvenanceError::PredicateRejected {
                        artifact: art.name.clone(),
                    },
                    &mut best,
                );
                continue;
            }
            admitted = true;
            break;
        }

        if !admitted {
            return ProvenanceVerdict::Refused(best.unwrap_or(ProvenanceError::Missing {
                artifact: art.name.clone(),
            }));
        }
    }

    ProvenanceVerdict::Admitted
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn statement_json(subject_digest: &str, predicate: &str) -> Vec<u8> {
        format!(
            r#"{{"_type":"{IN_TOTO_STATEMENT_V1}","subject":[{{"name":"a","digest":{{"sha256":"{subject_digest}"}}}}],"predicateType":"{predicate}"}}"#
        )
        .into_bytes()
    }

    fn sign(payload: Vec<u8>, sk: &SigningKey, keyid: &str) -> SignedAttestation {
        let mut att = SignedAttestation {
            dsse_payload: payload,
            payload_type: IN_TOTO_PAYLOAD_TYPE.to_string(),
            signatures: vec![],
        };
        let sig = sk.sign(&attestation_pae(&att));
        att.signatures.push(DsseSignature {
            keyid: keyid.to_string(),
            sig: sig.to_bytes().to_vec(),
        });
        att
    }

    fn artifact(digest: &str) -> ArtifactRef {
        ArtifactRef {
            kind: ArtifactKind::Package,
            name: "pypi:requests@2.32.0".to_string(),
            digest_algo: DigestAlgo::Sha256,
            digest_hex: digest.to_string(),
        }
    }

    const SLSA: &str = "https://slsa.dev/provenance/v1";
    const DIGEST: &str = "deadbeef00";

    fn required(trusted: Vec<TrustedKey>) -> ProvenancePolicy {
        ProvenancePolicy::Required {
            trusted_keys: trusted,
            required_predicates: vec![SLSA.to_string()],
        }
    }

    #[test]
    fn no_config_with_artifact_is_fail_closed() {
        let v = verify(&[artifact(DIGEST)], &[], &ProvenancePolicy::Unconfigured);
        assert!(matches!(
            v,
            ProvenanceVerdict::Refused(ProvenanceError::NotConfigured { .. })
        ));
    }

    #[test]
    fn no_artifacts_is_admitted() {
        assert_eq!(
            verify(&[], &[], &ProvenancePolicy::Unconfigured),
            ProvenanceVerdict::Admitted
        );
    }

    #[test]
    fn unsigned_artifact_refused() {
        let trusted = vec![TrustedKey {
            keyid: "k1".into(),
            key: key(1).verifying_key().to_bytes(),
        }];
        let v = verify(&[artifact(DIGEST)], &[], &required(trusted));
        assert!(matches!(
            v,
            ProvenanceVerdict::Refused(ProvenanceError::Missing { .. })
        ));
    }

    #[test]
    fn untrusted_key_refused() {
        let trusted = vec![TrustedKey {
            keyid: "k1".into(),
            key: key(1).verifying_key().to_bytes(),
        }];
        // Signed by key(9), not in the trusted set.
        let att = sign(statement_json(DIGEST, SLSA), &key(9), "k1");
        let v = verify(&[artifact(DIGEST)], &[att], &required(trusted));
        assert!(matches!(
            v,
            ProvenanceVerdict::Refused(ProvenanceError::Untrusted { .. })
        ));
    }

    #[test]
    fn digest_mismatch_refused() {
        let trusted = vec![TrustedKey {
            keyid: "k1".into(),
            key: key(1).verifying_key().to_bytes(),
        }];
        // Valid signature by trusted key, but the subject binds a DIFFERENT digest.
        let att = sign(statement_json("00c0ffee11", SLSA), &key(1), "k1");
        let v = verify(&[artifact(DIGEST)], &[att], &required(trusted));
        assert!(matches!(
            v,
            ProvenanceVerdict::Refused(ProvenanceError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn predicate_rejected() {
        let trusted = vec![TrustedKey {
            keyid: "k1".into(),
            key: key(1).verifying_key().to_bytes(),
        }];
        let att = sign(
            statement_json(DIGEST, "https://example.com/other/v1"),
            &key(1),
            "k1",
        );
        let v = verify(&[artifact(DIGEST)], &[att], &required(trusted));
        assert!(matches!(
            v,
            ProvenanceVerdict::Refused(ProvenanceError::PredicateRejected { .. })
        ));
    }

    #[test]
    fn attested_artifact_admitted() {
        let trusted = vec![TrustedKey {
            keyid: "k1".into(),
            key: key(1).verifying_key().to_bytes(),
        }];
        let att = sign(statement_json(DIGEST, SLSA), &key(1), "k1");
        let v = verify(&[artifact(DIGEST)], &[att], &required(trusted));
        assert_eq!(v, ProvenanceVerdict::Admitted);
    }

    #[test]
    fn tampered_payload_breaks_signature() {
        let trusted = vec![TrustedKey {
            keyid: "k1".into(),
            key: key(1).verifying_key().to_bytes(),
        }];
        let mut att = sign(statement_json(DIGEST, SLSA), &key(1), "k1");
        // Tamper the payload after signing.
        att.dsse_payload = statement_json(DIGEST, "https://evil/v1");
        let v = verify(&[artifact(DIGEST)], &[att], &required(trusted));
        assert!(matches!(
            v,
            ProvenanceVerdict::Refused(ProvenanceError::Untrusted { .. })
        ));
    }
}
