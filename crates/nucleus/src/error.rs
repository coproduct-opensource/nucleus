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

    /// Trifecta detected - operation would complete the lethal trifecta.
    #[error("trifecta blocked: operation '{operation}' would enable data exfiltration")]
    TrifectaBlocked {
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
        actual: lattice_guard::CapabilityLevel,
        /// The required level.
        required: lattice_guard::CapabilityLevel,
    },

    /// IO error from underlying operation.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
