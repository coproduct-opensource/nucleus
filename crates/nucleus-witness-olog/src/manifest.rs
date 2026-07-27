//! The accumulation manifest — the signed, transparency-loggable record that
//! binds an admitted witness to the olog fact it became.
//!
//! Each internalised witness emits one manifest binding the full provenance chain
//! so any third party can re-derive it: who did the work, which spec it claims,
//! the evidence digest, the kernel verdict, the assurance rung + tier (carried
//! through, never upgraded), the olog fact, and the reproducibility anchors. Ed25519
//! signed and append-only-log-friendly — the concrete step toward the
//! self-proving-system north star. See `docs/rfcs/witness-olog-functor.md`.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use nucleus_externality::AssuranceRung;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::functor::{AdmissionVerdict, OlogFact, Tier, WitnessDigest, WitnessNode};

/// Domain prefix for the manifest's canonical signing bytes. Bumping invalidates
/// every prior manifest signature (v1 contract).
pub const MANIFEST_DOMAIN: &[u8] = b"nucleus/witness-olog/manifest/v1\0";

/// One signed accumulation record: witness ↦ olog fact, with full provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccumulationManifest {
    /// Who did the work.
    pub agent_id: String,
    /// The olog spec the work claims to satisfy.
    pub task_spec_hash: [u8; 32],
    /// Content-addressed evidence.
    pub witness_digest: WitnessDigest,
    /// The kernel's admission decision.
    pub admission_verdict: AdmissionVerdict,
    /// Assurance rung — carried from the witness, NEVER upgraded.
    pub assurance_rung: AssuranceRung,
    /// Honesty tier — carried from the witness, NEVER upgraded.
    pub tier: Tier,
    /// Digest of the olog fact `Gov` produced.
    pub olog_instance_digest: [u8; 32],
    /// Source-commit anchor.
    pub commit_sha: String,
    /// `#print axioms` footprint of the proof backing this fact (empty if none).
    pub axiom_footprint: String,
    /// CI run that produced + checked this record.
    pub ci_run_id: String,
    /// Ed25519 signature over the canonical bytes, base64.
    pub sig_b64: String,
}

/// Errors constructing / verifying a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ManifestError {
    #[error("signature did not verify: {0}")]
    SignatureInvalid(String),
    #[error("sig_b64 base64 decode failed: {0}")]
    Base64(String),
    #[error("signature is {got} bytes, expected 64")]
    WrongSignatureLength { got: usize },
}

fn push_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Canonical signing bytes: domain-tagged, length-prefixed, integer-only — the
/// same discipline as `nucleus-externality`'s claim bytes. Excludes `sig_b64`
/// (the signature is computed over this).
pub fn canonical_manifest_bytes(m: &AccumulationManifest) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(MANIFEST_DOMAIN);
    push_field(&mut out, m.agent_id.as_bytes());
    push_field(&mut out, &m.task_spec_hash);
    push_field(&mut out, &m.witness_digest.0);
    out.push(match m.admission_verdict {
        AdmissionVerdict::Admitted => 1,
        AdmissionVerdict::Rejected => 0,
    });
    out.push(m.assurance_rung.level());
    out.push(match m.tier {
        Tier::Proven => 2,
        Tier::Modeled => 1,
        Tier::Analogy => 0,
    });
    push_field(&mut out, &m.olog_instance_digest);
    push_field(&mut out, m.commit_sha.as_bytes());
    push_field(&mut out, m.axiom_footprint.as_bytes());
    push_field(&mut out, m.ci_run_id.as_bytes());
    out
}

/// Build the unsigned manifest from a witness node, the fact `Gov` produced, and
/// the provenance anchors. The rung + tier come from the FACT (which `Gov`
/// carried through from the witness) — so the manifest cannot claim more
/// assurance than the witness proved.
#[allow(clippy::too_many_arguments)]
pub fn manifest_from_fact(
    agent_id: impl Into<String>,
    node: &WitnessNode,
    fact: &OlogFact,
    commit_sha: impl Into<String>,
    axiom_footprint: impl Into<String>,
    ci_run_id: impl Into<String>,
) -> AccumulationManifest {
    AccumulationManifest {
        agent_id: agent_id.into(),
        task_spec_hash: fact.task_spec_hash,
        witness_digest: node.digest,
        admission_verdict: node.verdict,
        assurance_rung: fact.rung,
        tier: fact.tier,
        olog_instance_digest: fact.instance_digest,
        commit_sha: commit_sha.into(),
        axiom_footprint: axiom_footprint.into(),
        ci_run_id: ci_run_id.into(),
        sig_b64: String::new(),
    }
}

/// Sign a manifest shell, filling in `sig_b64`.
pub fn sign_manifest(sk: &SigningKey, mut m: AccumulationManifest) -> AccumulationManifest {
    let sig: Signature = sk.sign(&canonical_manifest_bytes(&m));
    m.sig_b64 = STANDARD.encode(sig.to_bytes());
    m
}

/// Verify a manifest's signature under the supplied key.
pub fn verify_manifest(m: &AccumulationManifest, vk: &VerifyingKey) -> Result<(), ManifestError> {
    let sig_bytes = STANDARD
        .decode(&m.sig_b64)
        .map_err(|e| ManifestError::Base64(e.to_string()))?;
    if sig_bytes.len() != 64 {
        return Err(ManifestError::WrongSignatureLength {
            got: sig_bytes.len(),
        });
    }
    let mut buf = [0u8; 64];
    buf.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&buf);
    vk.verify_strict(&canonical_manifest_bytes(m), &sig)
        .map_err(|e| ManifestError::SignatureInvalid(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::functor::{Gov, NoUpgradeGov};

    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }

    fn fixture_node() -> WitnessNode {
        WitnessNode {
            digest: WitnessDigest([42u8; 32]),
            task_spec_hash: [1u8; 32],
            rung: AssuranceRung::TeeAttested,
            tier: Tier::Modeled,
            verdict: AdmissionVerdict::Admitted,
            parent: None,
        }
    }

    fn fixture_manifest() -> AccumulationManifest {
        let node = fixture_node();
        let fact = NoUpgradeGov.map_witness(&node);
        sign_manifest(
            &signer(),
            manifest_from_fact("agent-1", &node, &fact, "abc123", "[propext]", "ci-99"),
        )
    }

    #[test]
    fn sign_verify_round_trip() {
        let m = fixture_manifest();
        verify_manifest(&m, &signer().verifying_key()).expect("fresh manifest must verify");
    }

    #[test]
    fn rung_is_bound_into_the_signature() {
        // Tamper with the rung after signing → signature must fail. This is what
        // makes "lying about the rung is itself a (failed) signed claim" real.
        let mut m = fixture_manifest();
        m.assurance_rung = AssuranceRung::ZkUpperEnvelope; // forge a stronger rung
        let err = verify_manifest(&m, &signer().verifying_key()).unwrap_err();
        assert!(matches!(err, ManifestError::SignatureInvalid(_)));
    }

    #[test]
    fn manifest_cannot_outrank_its_witness() {
        // The no-upgrade invariant at the manifest layer: the signed rung equals
        // the witness's rung (via the fact Gov carried through).
        let node = fixture_node();
        let fact = NoUpgradeGov.map_witness(&node);
        let m = manifest_from_fact("a", &node, &fact, "c", "", "ci");
        assert_eq!(m.assurance_rung, node.rung);
        assert_eq!(m.tier, node.tier);
    }

    #[test]
    fn tampered_agent_id_fails() {
        let mut m = fixture_manifest();
        m.agent_id.push('x');
        assert!(verify_manifest(&m, &signer().verifying_key()).is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let m = fixture_manifest();
        let bogus = SigningKey::from_bytes(&[99u8; 32]).verifying_key();
        assert!(verify_manifest(&m, &bogus).is_err());
    }

    #[test]
    fn canonical_bytes_deterministic_and_domain_tagged() {
        let m = fixture_manifest();
        assert_eq!(canonical_manifest_bytes(&m), canonical_manifest_bytes(&m));
        assert!(canonical_manifest_bytes(&m).starts_with(MANIFEST_DOMAIN));
    }

    #[test]
    fn round_trips_json() {
        let m = fixture_manifest();
        let j = serde_json::to_string(&m).unwrap();
        let back: AccumulationManifest = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
    }
}
