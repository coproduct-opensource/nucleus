//! Error types for nucleus enforcement.

use std::path::PathBuf;
use thiserror::Error;

/// Result type for nucleus operations.
pub type Result<T> = std::result::Result<T, NucleusError>;

/// Errors that can occur during policy enforcement.
#[derive(Error, Debug)]
pub enum NucleusError {
    /// Path access denied by policy.
    #[error("access denied: path '{path}' blocked by policy")]
    PathDenied {
        /// The path that was denied.
        path: PathBuf,
        /// Reason for denial.
        reason: String,
    },

    /// Path escapes sandbox.
    #[error("sandbox escape: path '{path}' resolves outside sandbox root")]
    SandboxEscape {
        /// The path that tried to escape.
        path: PathBuf,
    },

    /// Command execution denied by policy.
    #[error("command denied: '{command}' blocked by policy")]
    CommandDenied {
        /// The command that was denied.
        command: String,
        /// Reason for denial.
        reason: String,
    },

    /// Budget exhausted.
    #[error("budget exhausted: requested ${requested:.4}, remaining ${remaining:.4}")]
    BudgetExhausted {
        /// Amount requested.
        requested: f64,
        /// Amount remaining.
        remaining: f64,
    },

    /// Invalid charge amount.
    #[error("invalid charge: {reason}")]
    InvalidCharge {
        /// Reason the charge is invalid.
        reason: String,
    },

    /// Temporal constraint violated.
    #[error("time constraint violated: {reason}")]
    TimeViolation {
        /// Reason for the violation.
        reason: String,
    },

    ///  UninhabitableState detected - operation would complete the uninhabitable_state.
    #[error("uninhabitable_state blocked: operation '{operation}' would enable data exfiltration")]
    StateBlocked {
        /// The operation that was blocked.
        operation: String,
    },

    /// Human approval required but not provided.
    #[error("approval required: '{operation}' requires human approval")]
    ApprovalRequired {
        /// The operation requiring approval.
        operation: String,
    },

    /// Approval token does not match the requested operation.
    #[error("invalid approval token for operation '{operation}'")]
    InvalidApproval {
        /// The operation requiring approval.
        operation: String,
    },

    /// Capability level insufficient.
    #[error(
        "insufficient capability: '{capability}' level is {actual:?}, need at least {required:?}"
    )]
    InsufficientCapability {
        /// The capability that was insufficient.
        capability: String,
        /// The actual level.
        actual: portcullis::CapabilityLevel,
        /// The required level.
        required: portcullis::CapabilityLevel,
    },

    /// Subprocess execution refused because the Executor's containment mode was
    /// never declared. Fail-closed default: the caller must explicitly choose an
    /// isolation posture (`.allow_unsandboxed_local()`, `.with_host_hardening()`,
    /// or `.in_microvm()`) before any subprocess may spawn (most-paranoid #2).
    #[error(
        "isolation not configured: subprocess execution refused — declare a containment mode \
         (allow_unsandboxed_local / with_host_hardening / in_microvm) before spawning"
    )]
    IsolationNotConfigured,

    /// Subprocess execution refused because the achieved isolation is weaker than
    /// the policy's required minimum. Never silently downgrade (most-paranoid #2).
    #[error("isolation insufficient: policy requires [{required}] but the spawn path provides only [{achieved}]")]
    IsolationInsufficient {
        /// The isolation the policy demands (`effective_minimum_isolation`).
        required: String,
        /// The isolation the chosen containment mode can actually attest.
        achieved: String,
    },

    /// Host-level guest hardening (seccomp/rlimits/no-new-privs) was requested but
    /// is unavailable on this platform. Fail-closed: never silently run unhardened
    /// — use a microVM boundary instead (most-paranoid #2).
    #[error("host hardening unavailable on platform '{platform}'; use a microVM boundary instead")]
    HardeningUnavailable {
        /// The OS that lacks the hardening primitives (e.g. "macos").
        platform: String,
    },

    /// IO error from underlying operation.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
