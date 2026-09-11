//! Error types for nucleus enforcement.

use std::path::PathBuf;
use thiserror::Error;

/// Result type for nucleus operations.
pub type Result<T> = std::result::Result<T, NucleusError>;

/// Errors that can occur during policy enforcement.
#[derive(Error, Debug)]
pub enum NucleusError {
    /// Path access denied by policy.
    //
    // `reason` is rendered. It was collected at fifteen sites and displayed at
    // none: every caller built a sentence explaining the refusal and the
    // formatter replaced it with "blocked by policy", which names no rule and
    // sends the reader to a blocklist that may have had nothing to do with it.
    #[error("access denied: path '{path}': {reason}")]
    PathDenied {
        /// The path that was denied.
        path: PathBuf,
        /// Reason for denial.
        reason: String,
    },

    /// The path does not exist.
    ///
    /// Distinct from `PathDenied` on purpose: a caller told "access denied"
    /// reasonably concludes policy refused, and goes looking at a policy that
    /// had nothing to do with it. Linux hit the same taxonomy confusion from
    /// the other side -- apparmor once returned ENOENT for a denial, which read
    /// as "the binary is missing" rather than "apparmor stopped you".
    #[error("path not found: '{path}'")]
    PathNotFound {
        /// The path that does not exist.
        path: PathBuf,
    },

    /// The path exists but cannot be used as asked -- a directory read as a
    /// file, a broken symlink, a bad encoding. Not a policy decision.
    #[error("path '{path}' cannot be used: {reason}")]
    PathUnusable {
        /// The path in question.
        path: PathBuf,
        /// The underlying reason, verbatim from the OS.
        reason: String,
    },

    /// Path escapes sandbox.
    #[error("sandbox escape: path '{path}' resolves outside sandbox root")]
    SandboxEscape {
        /// The path that tried to escape.
        path: PathBuf,
    },

    /// An authority earned for a different action was presented.
    #[error("discharge scope mismatch: {reason}")]
    ScopeMismatch {
        /// Names both the authority held and the action attempted.
        reason: String,
    },

    /// Command execution refused. `reason` says by what.
    ///
    /// The rendering used to be `"command denied: '{command}' blocked by policy"`
    /// -- a constant that named POLICY whatever the cause was, with `reason`
    /// carried in the struct and never printed. Four different reasons reach this
    /// variant and only two of them are policy:
    ///
    ///   blocked by command policy          <- policy
    ///   blocked by the command lattice     <- policy
    ///   malformed command (unbalanced quotes)   <- a PARSE error
    ///   <the argv predicate's own message>      <- a predicate, with detail
    ///
    /// So a command with an unbalanced quote was reported as refused by a policy
    /// that had no part in it. ADR 0007 A-4, and the same shape `15e3530f` fixed
    /// for paths -- `crates/nucleus-perf/src/main.rs:990` still records the cost
    /// of that one: "`EISDIR` ... for a long time was reported as `blocked by
    /// policy`, so it read as a refusal rather than `that is a directory`".
    #[error("command denied: '{command}': {reason}")]
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
    #[error(
        "isolation insufficient: policy requires [{required}] but the spawn path provides only [{achieved}]"
    )]
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

    /// Subprocess execution refused because a declared third-party artifact has
    /// no verified provenance attestation (most-paranoid next-bet #3). Fail-closed:
    /// an unsigned / untrusted-key / digest-mismatched / wrong-predicate artifact,
    /// or any declared artifact under an unconfigured provenance policy, blocks the
    /// spawn before any process exists.
    #[error("artifact provenance unverified for '{artifact}': {reason}")]
    ProvenanceUnverified {
        /// The artifact that failed provenance verification.
        artifact: String,
        /// Why verification refused it.
        reason: String,
    },

    /// IO error from underlying operation.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod command_denied_says_why_tests {
    use super::*;

    fn rendered(reason: &str) -> String {
        NucleusError::CommandDenied {
            command: "grep 'unbalanced".to_string(),
            reason: reason.to_string(),
        }
        .to_string()
    }

    /// THE regression. `Display` was the constant
    /// `"command denied: '{command}' blocked by policy"` and `reason` was never
    /// printed, so a PARSE failure was reported as a policy refusal — sending
    /// the reader to inspect a policy that had no part in it (ADR 0007 A-4).
    #[test]
    fn a_parse_failure_is_not_reported_as_a_policy_refusal() {
        let msg = rendered("malformed command (unbalanced quotes)");
        assert!(
            msg.contains("malformed command"),
            "the cause must reach the reader: {msg}"
        );
        assert!(
            !msg.contains("blocked by policy"),
            "a parse error must not claim policy refused it: {msg}"
        );
    }

    /// The complement, so the test above is not satisfied by a rendering that
    /// simply never mentions policy. A real policy refusal must still say so.
    #[test]
    fn a_policy_refusal_still_says_policy() {
        assert!(rendered("blocked by command policy").contains("policy"));
        assert!(rendered("blocked by the command lattice").contains("lattice"));
    }

    /// Non-vacuity: both tests above would pass against a rendering that
    /// dropped the command and printed only the reason. All four reasons that
    /// reach this variant must render distinctly, and all must carry the
    /// command, or the message is a constant again in a different disguise.
    #[test]
    fn every_reason_renders_distinctly_and_keeps_the_command() {
        let reasons = [
            "blocked by command policy",
            "blocked by the command lattice",
            "malformed command (unbalanced quotes)",
            "argv predicate: NUL byte in argument 2",
        ];
        let mut seen: Vec<String> = reasons.iter().map(|r| rendered(r)).collect();
        for m in &seen {
            assert!(m.contains("grep 'unbalanced"), "the command is lost: {m}");
        }
        let before = seen.len();
        seen.sort();
        seen.dedup();
        assert_eq!(
            before,
            seen.len(),
            "two reasons render identically: {seen:?}"
        );
    }
}
