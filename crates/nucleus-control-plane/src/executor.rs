//! [`execute_job`] — orchestrate a [`JobSpec`] end-to-end and return a
//! verified provenance [`Bundle`].
//!
//! Flow:
//! 1. Emit `EdgeKind::PodAdmit` for the supplied `session_root`, signed
//!    via the issuer. This anchors the chain.
//! 2. Hand off to the [`JobRunner`] (driver-specific). The runner emits
//!    its own edges through the [`SessionWriter`] and returns a payload.
//! 3. Build a [`Bundle`] via `nucleus-envelope`'s `BundleBuilder` with
//!    `require_signed()` set — every edge in the session must be signed.
//! 4. Self-check the bundle (audit-mode `verify_bundle`) to catch
//!    "your JWKS doesn't cover this kid" at producer time, not consumer
//!    time.
//! 5. Return the bundle. The caller delivers it to the spec's
//!    destination (file write / HTTP POST / in-response) — destination
//!    delivery is OUT of this function's scope so the orchestrator
//!    doesn't have to grow an HTTP client.
//!
//! [`Bundle`]: nucleus_envelope::Bundle

use nucleus_envelope::{verify_bundle, Bundle, BundleBuilder, TrustAnchor, VerifyBundleError};
use nucleus_lineage::{
    CallSpiffeId, EdgeSigner, Jwks, LineageEdge, LineageSink, MerkleProver, SignedTreeHead,
    SinkError,
};
use thiserror::Error;

use crate::runner::{JobRunner, JobRunnerError};
use crate::session_writer::{SessionWriter, SessionWriterError};
use crate::spec::JobSpec;

/// Errors returned by [`execute_job`].
#[derive(Debug, Error)]
pub enum ExecuteJobError {
    /// Underlying sink failure.
    #[error("sink error: {0}")]
    Sink(#[from] SinkError),
    /// Session writer failure (signing or persisting an edge).
    #[error("session writer: {0}")]
    Writer(#[from] SessionWriterError),
    /// The agent driver returned an error.
    #[error("runner: {0}")]
    Runner(#[from] JobRunnerError),
    /// Assembling the bundle failed (e.g. missing required field).
    #[error("bundle build: {0}")]
    Build(#[from] nucleus_envelope::BundleError),
    /// Post-build self-check failed — the produced bundle would not
    /// verify at consumer time. This is the orchestrator's "catch me
    /// early" sanity check.
    #[error("post-build self-check failed: {0}")]
    SelfCheck(#[from] VerifyBundleError),
}

/// Run a job end-to-end. Returns the assembled [`Bundle`].
///
/// `session_root` should be a freshly-derived pod SPIFFE id (no
/// `/call/` suffix). `issuer` signs every edge including the pod-admit.
/// `jwks` is the public JWKS the embedded envelope advertises — the
/// orchestrator does NOT validate this against the issuer; callers are
/// expected to derive `jwks` from `issuer.publish_jwks()` or equivalent.
/// `checkpoints` is the (possibly empty) set of contemporaneous signed
/// tree heads to attach as time attestations.
///
/// If `merkle_prover` is `Some`, a v2 bundle is built with a Merkle
/// anchor (witness-signed root + per-edge inclusion proofs); callers
/// with the witness pubkey can then prove tree-inclusion offline. If
/// `None`, a v1 chain-only bundle is built.
// 8 args is at the threshold; if a future slice adds one more, refactor
// into a builder pattern. Keeping this as a free function for now so
// callers don't have to chain methods just to start a job.
#[allow(clippy::too_many_arguments)]
pub fn execute_job(
    spec: &JobSpec,
    session_root: &CallSpiffeId,
    runner: &dyn JobRunner,
    sink: &dyn LineageSink,
    issuer: &dyn EdgeSigner,
    jwks: Jwks,
    checkpoints: Vec<SignedTreeHead>,
    merkle_prover: Option<&dyn MerkleProver>,
) -> Result<Bundle, ExecuteJobError> {
    let writer = SessionWriter::new(sink, issuer);

    // 1) Pod-admit anchors the chain.
    writer.emit_signed(LineageEdge::pod_admit(session_root.clone()))?;

    // 2) Driver does its work.
    let payload = runner.run(spec, session_root, &writer)?;

    // 3) Assemble.
    let mut builder = BundleBuilder::new(session_root.clone())
        .payload(payload)
        .sink(sink)
        .jwks(jwks)
        .checkpoints(checkpoints)
        .require_signed();
    if let Some(prover) = merkle_prover {
        builder = builder.with_merkle_prover(prover);
    }
    let bundle = builder.build()?;

    // 4) Self-check.
    verify_bundle(&bundle, &TrustAnchor::self_check_only())?;

    Ok(bundle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::MockJobRunner;
    use crate::spec::{AgentDriverRef, Destination, InputRef, JobSpec};
    use nucleus_lineage::{InMemorySink, LocalIssuer};

    fn session_root() -> CallSpiffeId {
        CallSpiffeId::pod("test.nucleus.local", "agents", "summarizer").unwrap()
    }

    fn sample_spec() -> JobSpec {
        JobSpec {
            input_ref: InputRef::Inline {
                content: serde_json::json!({"text": "some input"}),
            },
            task: "extract stats and summarize".to_string(),
            destination: Destination::InResponse,
            policy_profile: "report-extraction".to_string(),
            agent_driver: AgentDriverRef {
                name: "mock".to_string(),
                version: None,
                config: serde_json::json!({}),
            },
        }
    }

    #[test]
    fn execute_mock_job_produces_verifiable_bundle() {
        let sink = InMemorySink::new();
        let issuer = LocalIssuer::random().unwrap();
        let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
        let runner = MockJobRunner;

        let bundle = execute_job(
            &sample_spec(),
            &session_root(),
            &runner,
            &sink,
            &issuer,
            jwks.clone(),
            Vec::new(),
            None,
        )
        .expect("mock job must succeed end-to-end");

        // pod_admit + Read + LlmCall(prompt) + LlmCall(response) + ArtifactProduced = 5.
        assert_eq!(bundle.envelope.edges.len(), 5);
        assert_eq!(
            bundle.envelope.session_root.as_str(),
            session_root().as_str()
        );

        // The payload carries what the runner returned.
        assert_eq!(bundle.payload["task"], "extract stats and summarize");
        assert!(bundle.payload["summary"].as_str().unwrap().contains("mock"));

        // And it verifies against the issuer's real JWKS (trusted anchor path).
        let trusted = nucleus_envelope::TrustAnchor::from_jwks(jwks);
        let report = nucleus_envelope::verify_bundle(&bundle, &trusted)
            .expect("bundle must verify against trusted JWKS");
        assert_eq!(report.edge_count, 5);
        assert!(!report.trust_mode_self_check_only);
    }

    #[test]
    fn execute_propagates_runner_errors() {
        // URL input is unsupported by MockJobRunner — should bubble up as
        // ExecuteJobError::Runner.
        let sink = InMemorySink::new();
        let issuer = LocalIssuer::random().unwrap();
        let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
        let runner = MockJobRunner;
        let spec = JobSpec {
            input_ref: InputRef::Url {
                url: "https://example.com/data.json".to_string(),
            },
            ..sample_spec()
        };

        let err = execute_job(
            &spec,
            &session_root(),
            &runner,
            &sink,
            &issuer,
            jwks,
            Vec::new(),
            None,
        )
        .expect_err("URL input must error");
        assert!(matches!(
            err,
            ExecuteJobError::Runner(JobRunnerError::Unsupported(_))
        ));
    }

    #[test]
    fn execute_rejects_non_pod_session_root() {
        // The self-check should catch this — passing a tool-call id as
        // session_root violates the v1 pod-shape requirement.
        let pod = session_root();
        let not_a_pod = pod.derive_tool("Read", None).unwrap();
        let sink = InMemorySink::new();
        let issuer = LocalIssuer::random().unwrap();
        let jwks: Jwks = serde_json::from_value(issuer.publish_jwks()).unwrap();
        let runner = MockJobRunner;

        let err = execute_job(
            &sample_spec(),
            &not_a_pod,
            &runner,
            &sink,
            &issuer,
            jwks,
            Vec::new(),
            None,
        )
        .expect_err("non-pod session root must be rejected");
        assert!(
            matches!(
                err,
                ExecuteJobError::SelfCheck(VerifyBundleError::SessionRootNotPod { .. })
            ),
            "expected SelfCheck/SessionRootNotPod, got {err:?}"
        );
    }
}
