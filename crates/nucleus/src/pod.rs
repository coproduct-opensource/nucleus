//! Pod runtime for enforced execution.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::approval::Approver;
use crate::budget::AtomicBudget;
use crate::command::{BudgetModel, ContainmentMode, Executor};
use crate::error::Result;
use crate::sandbox::Sandbox;
use crate::time::MonotonicGuard;
use portcullis::PermissionLattice;

/// Specification for a pod (sandboxed instance).
#[derive(Debug, Clone)]
pub struct PodSpec {
    /// Permission policy for this pod.
    pub policy: PermissionLattice,
    /// Working directory for the pod.
    pub work_dir: PathBuf,
    /// Maximum runtime for the pod.
    pub timeout: Duration,
    /// Budget model for command execution.
    pub budget_model: BudgetModel,
    /// How the pod's Executor confines spawned subprocesses (most-paranoid #2).
    ///
    /// Fail-closed default: [`ContainmentMode::Unconfigured`] — the Executor
    /// refuses to spawn until the caller declares a posture (e.g. the tool-proxy
    /// sets [`ContainmentMode::MicroVM`] once its `SandboxProof` is verified, or
    /// a Tier-1 `--local` run opts into [`ContainmentMode::Unsandboxed`]).
    pub containment: ContainmentMode,
    /// Third-party artifacts this pod pulls (images/packages/models/MCP servers).
    /// Each must carry a verified provenance attestation under [`Self::provenance`]
    /// or the pod refuses to spawn (most-paranoid next-bet #3).
    pub artifacts: Vec<nucleus_provenance::ArtifactRef>,
    /// DSSE-signed in-toto attestations covering [`Self::artifacts`].
    pub attestations: Vec<nucleus_provenance::SignedAttestation>,
    /// Provenance policy. Fail-closed default
    /// ([`nucleus_provenance::ProvenancePolicy::Unconfigured`]): declaring an
    /// artifact with no policy refuses the spawn.
    pub provenance: nucleus_provenance::ProvenancePolicy,
}

impl PodSpec {
    /// Create a pod spec with defaults for budget model.
    ///
    /// The containment mode defaults to [`ContainmentMode::Unconfigured`]
    /// (fail-closed); callers must declare a posture via [`Self::with_containment`].
    /// Artifacts default to empty with an `Unconfigured` provenance policy — a
    /// pod that declares no artifacts is admitted; declaring one without a policy
    /// is fail-closed.
    pub fn new(policy: PermissionLattice, work_dir: PathBuf, timeout: Duration) -> Self {
        Self {
            policy: policy.normalize(),
            work_dir,
            timeout,
            budget_model: BudgetModel::default(),
            containment: ContainmentMode::Unconfigured,
            artifacts: Vec::new(),
            attestations: Vec::new(),
            provenance: nucleus_provenance::ProvenancePolicy::Unconfigured,
        }
    }

    /// Declare the containment posture for this pod's subprocess execution.
    #[must_use]
    pub fn with_containment(mut self, mode: ContainmentMode) -> Self {
        self.containment = mode;
        self
    }

    /// Declare the third-party artifacts + their attestations this pod pulls
    /// (most-paranoid next-bet #3). Verified against [`Self::provenance`] at
    /// [`PodRuntime::new`] — fail-closed before any subprocess can spawn.
    #[must_use]
    pub fn with_artifacts(
        mut self,
        artifacts: Vec<nucleus_provenance::ArtifactRef>,
        attestations: Vec<nucleus_provenance::SignedAttestation>,
    ) -> Self {
        self.artifacts = artifacts;
        self.attestations = attestations;
        self
    }

    /// Declare the provenance policy (trusted attestation keys + allowed
    /// predicates). Absent ⇒ `Unconfigured` ⇒ any declared artifact refuses spawn.
    #[must_use]
    pub fn with_provenance(mut self, policy: nucleus_provenance::ProvenancePolicy) -> Self {
        self.provenance = policy;
        self
    }
}

/// Runtime for a pod (kubelet-managed instance).
pub struct PodRuntime {
    spec: PodSpec,
    sandbox: Sandbox,
    budget: AtomicBudget,
    time_guard: MonotonicGuard,
    approver: Option<Arc<dyn Approver>>,
}

impl PodRuntime {
    /// Create a new pod runtime from a spec.
    ///
    /// **Fail-closed artifact-provenance gate (most-paranoid next-bet #3).**
    /// Before constructing any sandbox or executor, verify that every declared
    /// third-party artifact carries a trusted, digest-bound, allowed-predicate
    /// attestation. A refusal returns [`NucleusError::ProvenanceUnverified`] so
    /// no process can ever spawn from an unverified supply chain. (The Executor
    /// re-asserts the resulting verdict at each spawn site as defense-in-depth.)
    pub fn new(spec: PodSpec) -> Result<Self> {
        if let nucleus_provenance::ProvenanceVerdict::Refused(e) =
            nucleus_provenance::verify(&spec.artifacts, &spec.attestations, &spec.provenance)
        {
            let artifact = match &e {
                nucleus_provenance::ProvenanceError::NotConfigured { artifact }
                | nucleus_provenance::ProvenanceError::Missing { artifact }
                | nucleus_provenance::ProvenanceError::Untrusted { artifact }
                | nucleus_provenance::ProvenanceError::DigestMismatch { artifact }
                | nucleus_provenance::ProvenanceError::PredicateRejected { artifact } => {
                    artifact.clone()
                }
            };
            return Err(crate::error::NucleusError::ProvenanceUnverified {
                artifact,
                reason: e.to_string(),
            });
        }

        let sandbox = Sandbox::new(&spec.policy, &spec.work_dir)?;
        let budget = AtomicBudget::new(&spec.policy.budget);
        let time_guard = MonotonicGuard::new(spec.timeout);

        Ok(Self {
            spec,
            sandbox,
            budget,
            time_guard,
            approver: None,
        })
    }

    /// Attach an approver for approval-gated operations.
    pub fn with_approver(mut self, approver: Arc<dyn Approver>) -> Result<Self> {
        let sandbox =
            Sandbox::new(&self.spec.policy, &self.spec.work_dir)?.with_approver(approver.clone());
        self.sandbox = sandbox;
        self.approver = Some(approver);
        Ok(self)
    }

    /// Get the pod policy.
    pub fn policy(&self) -> &PermissionLattice {
        &self.spec.policy
    }

    /// Get the pod sandbox.
    pub fn sandbox(&self) -> &Sandbox {
        &self.sandbox
    }

    /// Get the pod budget.
    pub fn budget(&self) -> &AtomicBudget {
        &self.budget
    }

    /// Get the pod time guard.
    pub fn time_guard(&self) -> &MonotonicGuard {
        &self.time_guard
    }

    /// Build an executor for this pod.
    pub fn executor(&self) -> Executor<'_> {
        let mut executor = Executor::new(&self.spec.policy, &self.sandbox, &self.budget)
            .with_time_guard(&self.time_guard)
            .with_budget_model(self.spec.budget_model)
            .with_containment(self.spec.containment);

        if let Some(ref approver) = self.approver {
            executor = executor.with_approver(approver.clone());
        }

        executor
    }
}

#[cfg(test)]
mod provenance_gate_tests {
    use super::*;
    use nucleus_provenance::{ArtifactKind, ArtifactRef, DigestAlgo, ProvenancePolicy, TrustedKey};

    fn artifact() -> ArtifactRef {
        ArtifactRef {
            kind: ArtifactKind::Package,
            name: "pypi:requests@2.32.0".to_string(),
            digest_algo: DigestAlgo::Sha256,
            digest_hex: "deadbeef00".to_string(),
        }
    }

    fn spec() -> PodSpec {
        PodSpec::new(
            PermissionLattice::default(),
            std::env::temp_dir(),
            Duration::from_secs(60),
        )
    }

    #[test]
    fn declared_artifact_without_provenance_policy_refuses_spawn() {
        // Fail-closed: a declared artifact + Unconfigured (default) policy ⇒ refuse
        // BEFORE any sandbox/executor is built.
        let s = spec().with_artifacts(vec![artifact()], vec![]);
        // (PodRuntime isn't Debug, so match the Result rather than unwrap_err.)
        assert!(matches!(
            PodRuntime::new(s),
            Err(crate::error::NucleusError::ProvenanceUnverified { .. })
        ));
    }

    #[test]
    fn no_artifacts_is_admitted() {
        // A pod that declares no artifacts spawns normally.
        assert!(PodRuntime::new(spec()).is_ok());
    }

    #[test]
    fn unsigned_declared_artifact_refused_under_required_policy() {
        let policy = ProvenancePolicy::Required {
            trusted_keys: vec![TrustedKey {
                keyid: "k1".to_string(),
                key: [1u8; 32],
            }],
            required_predicates: vec!["https://slsa.dev/provenance/v1".to_string()],
        };
        let s = spec()
            .with_artifacts(vec![artifact()], vec![]) // no attestation supplied
            .with_provenance(policy);
        assert!(matches!(
            PodRuntime::new(s),
            Err(crate::error::NucleusError::ProvenanceUnverified { .. })
        ));
    }
}
