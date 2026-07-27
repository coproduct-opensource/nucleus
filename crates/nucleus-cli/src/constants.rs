//! Shared constants for nucleus-cli.
//!
//! This module centralizes constants used across multiple CLI commands
//! to maintain consistency and simplify version/configuration updates.

/// Version of Firecracker to download and validate.
///
/// This version is used by:
/// - `setup` command: Downloads and provisions Firecracker on Lima VM
/// - `doctor` command: Verifies installed Firecracker matches expected version
///
/// Update this constant when upgrading to a new Firecracker version.
pub const FIRECRACKER_VERSION: &str = "1.14.1";

/// The agent's BUILT-IN tools that MUST be disabled when launching the assistant
/// under nucleus enforcement, so the agent can only act through the nucleus MCP
/// tools (each routed through the `PermissionLattice`). Passed verbatim as
/// `--disallowedTools`.
///
/// COMPLETE-MEDIATION INVARIANT: every code path that launches the assistant
/// with `--dangerously-skip-permissions` / `bypassPermissions` (`run`, `shell`)
/// MUST also pass this list. Omitting it lets the built-in Bash/Write/WebFetch/
/// etc. run OUTSIDE the kernel — an in-band path that skips the monitor. The
/// two launch sites referencing this constant keep the boundary identical by
/// construction; do not inline the list.
pub const DISALLOWED_BUILTIN_TOOLS: &str =
    "Bash,Read,Write,Edit,Glob,Grep,WebFetch,WebSearch,NotebookEdit,Agent";

/// Intrinsic interop — the external agent CLI executable that nucleus wraps and
/// launches under enforcement. This is a genuine third-party binary name looked
/// up on the user's `PATH` (NOT a nucleus component), so it is kept verbatim as
/// a real interop identifier rather than neutralized. Centralized here so the
/// single source of truth is explicit; the launch sites (`run`, `shell`)
/// reference this constant instead of hardcoding the name.
pub const AGENT_CLI_BIN: &str = "claude";

/// Intrinsic provenance — the sibling in-repo hook binary/crate name that
/// `nucleus guard` and `nucleus run --hook` resolve and invoke
/// (`crates/nucleus-claude-hook`). Kept verbatim because it is the real
/// crate/binary name on disk; renaming the crate itself is out of scope for
/// this module.
pub const HOOK_BINARY_NAME: &str = "nucleus-claude-hook";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disallowed_builtins_cover_the_dangerous_effects() {
        // Regression guard: the built-in effects that would bypass the lattice
        // must all be in the disallow list. If a new built-in tool appears,
        // add it here and to the constant in the same change.
        for t in [
            "Bash",
            "Write",
            "Edit",
            "WebFetch",
            "WebSearch",
            "Read",
            "Glob",
            "Grep",
        ] {
            assert!(
                DISALLOWED_BUILTIN_TOOLS.split(',').any(|x| x == t),
                "built-in tool {t} must be disallowed (it bypasses the nucleus kernel)"
            );
        }
    }
}
