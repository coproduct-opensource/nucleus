//! The accumulation manifest — the signed, transparency-loggable record that
//! binds an admitted witness to the olog fact it became.
//!
//! Each internalised witness emits one manifest binding the full provenance chain
//! so any third party can re-derive it: who did the work, which spec it claims,
//! the evidence digest, the kernel verdict, the digest of the evidence the
//! assurance rung is derived from, the tier (carried through, never upgraded),
//! the olog fact, and the reproducibility anchors. Ed25519 signed and
//! append-only-log-friendly — the concrete step toward the self-proving-system
//! north star. See `docs/rfcs/witness-olog-functor.md`.
//!
//! # The manifest does not state a rung (#2518)
//!
//! v1 carried `assurance_rung` as a signed field, and a reader took it. A
//! signature makes a rung attributable to the signer; it does not make it
//! true. v2 carries [`AccumulationManifest::rung_evidence_digest`] instead, and
//! the rung exists only as the output of [`verify_manifest_rung`], which
//! re-derives it from the committed evidence. The old forgery — overwrite the
//! field, re-sign, and every reader sees the top rung — has nothing to write:
//!
//! ```compile_fail,E0609
//! # fn forge(m: &mut nucleus_witness_olog::AccumulationManifest) {
//! m.assurance_rung = nucleus_externality::AssuranceRung::ZkUpperEnvelope;
//! # }
//! ```

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use nucleus_externality::{EnvelopeVerifier, TeeQuoteVerifier};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::functor::{AdmissionVerdict, OlogFact, Tier, WitnessDigest, WitnessNode};
use crate::rung::{RungError, RungEvidence, VerifiedRung, verify_rung_evidence};

/// Domain prefix for the manifest's canonical signing bytes. Bumping invalidates
/// every prior manifest signature.
///
/// v2 (#2518): the rung byte is gone and the 32-byte `rung_evidence_digest`
/// takes its place. No v1 signature verifies under v2, and none should: a v1
/// signature covers a rung the signer chose.
pub const MANIFEST_DOMAIN: &[u8] = b"nucleus/witness-olog/manifest/v2\0";

/// One signed accumulation record: witness ↦ olog fact, with full provenance.
///
/// `deny_unknown_fields`: a v1 manifest still carrying `assurance_rung` is
/// REFUSED at deserialization rather than accepted with the field dropped. A
/// reader that silently dropped it would hand back a record that looks
/// current but whose signature can never verify; refusing names the problem
/// at the boundary, and no reader can come to rely on the field being there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccumulationManifest {
    /// Who did the work.
    pub agent_id: String,
    /// The olog spec the work claims to satisfy.
    pub task_spec_hash: [u8; 32],
    /// Content-addressed evidence.
    pub witness_digest: WitnessDigest,
    /// The kernel's admission decision.
    pub admission_verdict: AdmissionVerdict,
    /// [`RungEvidence::digest`] of the evidence the witness's rung was derived
    /// from. The manifest COMMITS to evidence; it does not state the rung.
    /// [`verify_manifest_rung`] re-derives the rung from evidence matching this.
    pub rung_evidence_digest: [u8; 32],
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
#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("signature did not verify: {0}")]
    SignatureInvalid(String),
    #[error("sig_b64 base64 decode failed: {0}")]
    Base64(String),
    #[error("signature is {got} bytes, expected 64")]
    WrongSignatureLength { got: usize },
    /// The evidence presented is not the evidence the manifest committed to.
    #[error(
        "rung evidence digest mismatch: manifest commits to {committed}, evidence is {presented}"
    )]
    EvidenceMismatch {
        committed: String,
        presented: String,
    },
    /// The committed evidence did not verify.
    #[error("rung evidence: {0}")]
    Rung(RungError),
}

pub(crate) fn push_field(out: &mut Vec<u8>, bytes: &[u8]) {
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
    push_field(&mut out, &m.rung_evidence_digest);
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
/// the provenance anchors. The evidence digest comes from the FACT's
/// [`VerifiedRung`] (which `Gov` carried through from the witness), so the
/// manifest commits to exactly the evidence that rung was derived from — and
/// states no rung of its own.
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
        rung_evidence_digest: fact.rung.evidence_digest(),
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

/// Verify a manifest AND derive the assurance rung of the witness it records.
///
/// The rung is computed here, from per-layer verifier results; it is never read
/// from the manifest. In order:
///
/// 1. the manifest's own signature under `manifest_vk`;
/// 2. `evidence` must be the evidence the manifest committed to
///    ([`AccumulationManifest::rung_evidence_digest`]);
/// 3. [`verify_rung_evidence`], with the manifest's `agent_id` as the claim's
///    expected subject — the agent the manifest credits is the one the oracle
///    attested about, decided once rather than passed twice.
///
/// With `None` for both layer verifiers (fail closed; no implementation ships)
/// the result is at most `OracleSigned`.
///
/// # Errors
///
/// The signature errors of [`verify_manifest`],
/// [`ManifestError::EvidenceMismatch`], or [`ManifestError::Rung`].
pub fn verify_manifest_rung(
    m: &AccumulationManifest,
    manifest_vk: &VerifyingKey,
    evidence: &RungEvidence,
    oracle_vk: &VerifyingKey,
    now_unix_micros: u64,
    tee_verifier: Option<&dyn TeeQuoteVerifier>,
    envelope_verifier: Option<&dyn EnvelopeVerifier>,
) -> Result<VerifiedRung, ManifestError> {
    verify_manifest(m, manifest_vk)?;
    let presented = evidence.digest();
    if presented != m.rung_evidence_digest {
        return Err(ManifestError::EvidenceMismatch {
            committed: hex::encode(m.rung_evidence_digest),
            presented: hex::encode(presented),
        });
    }
    verify_rung_evidence(
        evidence,
        oracle_vk,
        &m.agent_id,
        now_unix_micros,
        tee_verifier,
        envelope_verifier,
    )
    .map_err(ManifestError::Rung)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::functor::{Gov, NoUpgradeGov};
    use crate::rung::tests::{NOW, SUBJECT, fabricated_evidence, oracle_sk};
    use nucleus_externality::AssuranceRung;

    fn signer() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }

    fn fixture_node() -> WitnessNode {
        WitnessNode {
            digest: WitnessDigest([42u8; 32]),
            task_spec_hash: [1u8; 32],
            rung: VerifiedRung::for_test(AssuranceRung::TeeAttested, [7u8; 32]),
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
    fn evidence_commitment_is_bound_into_the_signature() {
        // Point the manifest at other evidence after signing → signature fails.
        let mut m = fixture_manifest();
        m.rung_evidence_digest = fabricated_evidence().digest();
        let err = verify_manifest(&m, &signer().verifying_key()).unwrap_err();
        assert!(matches!(err, ManifestError::SignatureInvalid(_)));
    }

    #[test]
    fn manifest_commits_to_the_witness_evidence() {
        // The no-upgrade invariant at the manifest layer: the manifest commits
        // to the evidence the witness's rung was derived from (via the fact Gov
        // carried through), and states no rung of its own.
        let node = fixture_node();
        let fact = NoUpgradeGov.map_witness(&node);
        let m = manifest_from_fact("a", &node, &fact, "c", "", "ci");
        assert_eq!(m.rung_evidence_digest, node.rung.evidence_digest());
        assert_eq!(m.tier, node.tier);
    }

    /// A manifest whose node was built with the given rung, committing to the
    /// fabricated evidence, and signed by the accumulator.
    fn manifest_over_fabricated_evidence(signed_as: AssuranceRung) -> AccumulationManifest {
        let ev = fabricated_evidence();
        let mut node = fixture_node();
        node.rung = VerifiedRung::for_test(signed_as, ev.digest());
        let fact = NoUpgradeGov.map_witness(&node);
        sign_manifest(
            &signer(),
            manifest_from_fact(SUBJECT, &node, &fact, "abc", "", "ci"),
        )
    }

    /// #2518 acceptance, at the manifest: the old forgery was "overwrite
    /// `assurance_rung` with `ZkUpperEnvelope`, re-sign" — a signer stating its
    /// own rung. Now the strongest thing a signer controls is which evidence it
    /// commits to, and fabricated layers in that evidence earn nothing: the
    /// rung a relying party derives is `OracleSigned` however the accumulator
    /// labelled the node.
    #[test]
    fn a_signer_cannot_state_the_rung_a_reader_derives() {
        for signed_as in [
            AssuranceRung::TeeAttested,
            AssuranceRung::MultiSourceDisputed,
            AssuranceRung::ZkUpperEnvelope,
        ] {
            let m = manifest_over_fabricated_evidence(signed_as);
            verify_manifest(&m, &signer().verifying_key()).expect("signature is genuine");
            let derived = verify_manifest_rung(
                &m,
                &signer().verifying_key(),
                &fabricated_evidence(),
                &oracle_sk().verifying_key(),
                NOW,
                None,
                None,
            )
            .expect("the claim's signature is genuine");
            assert_eq!(derived.rung(), AssuranceRung::OracleSigned);
        }
    }

    #[test]
    fn evidence_the_manifest_did_not_commit_to_is_refused() {
        let m = manifest_over_fabricated_evidence(AssuranceRung::OracleSigned);
        let mut other = fabricated_evidence();
        other.tee = None;
        assert!(matches!(
            verify_manifest_rung(
                &m,
                &signer().verifying_key(),
                &other,
                &oracle_sk().verifying_key(),
                NOW,
                None,
                None
            ),
            Err(ManifestError::EvidenceMismatch { .. })
        ));
    }

    #[test]
    fn evidence_about_another_agent_is_refused() {
        // The claim's subject is SUBJECT; a manifest crediting another agent
        // cannot borrow it.
        let ev = fabricated_evidence();
        let mut node = fixture_node();
        node.rung = VerifiedRung::for_test(AssuranceRung::OracleSigned, ev.digest());
        let fact = NoUpgradeGov.map_witness(&node);
        let m = sign_manifest(
            &signer(),
            manifest_from_fact(
                "spiffe://nucleus.local/ns/agents/sa/other",
                &node,
                &fact,
                "c",
                "",
                "ci",
            ),
        );
        assert!(matches!(
            verify_manifest_rung(
                &m,
                &signer().verifying_key(),
                &ev,
                &oracle_sk().verifying_key(),
                NOW,
                None,
                None
            ),
            Err(ManifestError::Rung(RungError::Signature(_)))
        ));
    }

    /// Serialization decision: a manifest carrying `assurance_rung` — every v1
    /// manifest, or a v2 one with the field smuggled back in — is refused, not
    /// read with the field ignored.
    #[test]
    fn a_manifest_carrying_a_rung_is_refused() {
        let mut v = serde_json::to_value(fixture_manifest()).unwrap();
        v["assurance_rung"] = serde_json::json!("zk_upper_envelope");
        let err = serde_json::from_value::<AccumulationManifest>(v).unwrap_err();
        assert!(err.to_string().contains("assurance_rung"), "{err}");
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
