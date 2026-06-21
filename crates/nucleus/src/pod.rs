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
}

impl PodSpec {
    /// Create a pod spec with defaults for budget model.
    ///
    /// The containment mode defaults to [`ContainmentMode::Unconfigured`]
    /// (fail-closed); callers must declare a posture via [`Self::with_containment`].
    pub fn new(policy: PermissionLattice, work_dir: PathBuf, timeout: Duration) -> Self {
        Self {
            policy: policy.normalize(),
            work_dir,
            timeout,
            budget_model: BudgetModel::default(),
            containment: ContainmentMode::Unconfigured,
        }
    }

    /// Declare the containment posture for this pod's subprocess execution.
    #[must_use]
    pub fn with_containment(mut self, mode: ContainmentMode) -> Self {
        self.containment = mode;
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
    pub fn new(spec: PodSpec) -> Result<Self> {
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
