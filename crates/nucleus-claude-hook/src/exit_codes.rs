//! Well-defined exit code contract for `nucleus-claude-hook`.
//!
//! # Exit Code Protocol
//!
//! The hook communicates its decision to Claude Code via both JSON on stdout
//! **and** its process exit code.  The exit code is the authoritative signal:
//!
//! | Code | Name    | Meaning                                              |
//! |------|---------|------------------------------------------------------|
//! |  0   | Allow   | Operation permitted. JSON on stdout with decision.    |
//! |  1   | Error   | Internal/infrastructure error — no valid decision.    |
//! |  2   | Deny    | Operation blocked. JSON on stdout with deny reason.   |
//!
//! ## Distinguishing "hook didn't run" from "hook allowed"
//!
//! - **Hook not installed / crashed before output**: no JSON on stdout, exit
//!   code depends on OS (likely signal-killed → non-zero, or 0 if the shell
//!   ate it).  Claude Code falls through to its default behavior.
//! - **Hook ran, operation allowed** (exit 0): valid JSON on stdout with
//!   `permissionDecision: "allow"`.
//! - **Hook ran, operation denied** (exit 2): valid JSON on stdout with
//!   `permissionDecision: "deny"` and a `permissionDecisionReason`.
//! - **Hook ran, but hit an internal error** (exit 1): stderr has a diagnostic
//!   message.  No valid decision JSON on stdout (or a deny if `NUCLEUS_FAIL_OPEN=1`).
//!
//! ## `NUCLEUS_FAIL_OPEN=1`
//!
//! When set, infrastructure errors (no stdin, bad JSON, etc.) are promoted
//! from exit 1 to exit 2 with a deny JSON, ensuring the tool call is blocked.

use portcullis::kernel::Verdict;

/// Process exit codes with well-defined semantics.
///
/// These values match the Claude Code hook protocol:
/// - exit 0 → allow / passthrough
/// - exit 2 → deny (block the tool call)
///
/// Exit 1 is reserved for internal errors where no policy decision was made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// Operation permitted — JSON on stdout contains an allow decision.
    Allow = 0,
    /// Internal error — no valid policy decision was made.
    ///
    /// Examples: CLI parse error, stdin read failure (non-fail-closed mode),
    /// JSON deserialization error.
    Error = 1,
    /// Operation denied — JSON on stdout contains a deny with reason.
    ///
    /// This covers both policy denials (capability violations, flow rules,
    /// tamper detection) and infrastructure failures when `NUCLEUS_FAIL_OPEN=1`.
    Deny = 2,
}

impl ExitCode {
    /// Map a kernel [`Verdict`] to the corresponding exit code.
    ///
    /// - `Verdict::Allow` → `ExitCode::Allow`
    /// - `Verdict::RequiresApproval` → `ExitCode::Allow` (the "ask" decision
    ///   is communicated via JSON; the exit code is 0 so Claude Code doesn't
    ///   block outright)
    /// - `Verdict::Deny(_)` → `ExitCode::Deny`
    pub fn from_verdict(verdict: &Verdict) -> Self {
        match verdict {
            Verdict::Allow => Self::Allow,
            Verdict::RequiresApproval => Self::Allow,
            Verdict::Deny(_) => Self::Deny,
        }
    }

    /// Terminate the process with this exit code.
    ///
    /// This is the single point where `std::process::exit()` should be called
    /// from hook logic, making exit behavior auditable and grep-friendly.
    pub fn exit(self) -> ! {
        std::process::exit(self as i32)
    }

    /// The raw integer value (used by tests and diagnostics).
    #[cfg(test)]
    pub fn code(self) -> i32 {
        self as i32
    }

    /// Print the exit code documentation table to stdout.
    ///
    /// Intended for `--exit-codes` flag so integration developers can
    /// programmatically discover the contract.
    pub fn print_docs() {
        println!("nucleus-claude-hook exit codes:");
        println!();
        println!("  EXIT CODE  NAME     MEANING");
        println!("  ---------  -------  ------------------------------------------------");
        println!("  0          Allow    Operation permitted (JSON on stdout)");
        println!("  1          Error    Internal error, no valid decision made");
        println!("  2          Deny     Operation blocked (JSON on stdout with reason)");
        println!();
        println!("When NUCLEUS_FAIL_OPEN=1, infrastructure errors use exit 2 (deny)");
        println!("instead of exit 1, ensuring tool calls are blocked on any failure.");
        println!();
        println!("Integration notes:");
        println!("  - Exit 0 with no stdout JSON = hook passthrough (Claude Code defaults)");
        println!("  - Exit 0 with JSON           = explicit allow decision");
        println!("  - Exit 2 with JSON           = explicit deny with reason");
        println!("  - Exit 1                     = hook error (check stderr)");
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis::kernel::{DenyReason, Verdict};

    #[test]
    fn allow_verdict_maps_to_zero() {
        assert_eq!(ExitCode::from_verdict(&Verdict::Allow), ExitCode::Allow);
        assert_eq!(ExitCode::Allow.code(), 0);
    }

    #[test]
    fn requires_approval_maps_to_zero() {
        assert_eq!(
            ExitCode::from_verdict(&Verdict::RequiresApproval),
            ExitCode::Allow
        );
    }

    #[test]
    fn deny_verdict_maps_to_two() {
        let verdict = Verdict::Deny(DenyReason::InsufficientCapability);
        assert_eq!(ExitCode::from_verdict(&verdict), ExitCode::Deny);
        assert_eq!(ExitCode::Deny.code(), 2);
    }

    #[test]
    fn error_code_is_one() {
        assert_eq!(ExitCode::Error.code(), 1);
    }

    #[test]
    fn repr_values_match_protocol() {
        assert_eq!(ExitCode::Allow as i32, 0);
        assert_eq!(ExitCode::Error as i32, 1);
        assert_eq!(ExitCode::Deny as i32, 2);
    }
}
