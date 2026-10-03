//! The unsandboxed host tier, declared on purpose.
//!
//! `nucleus run --local` and `nucleus shell` start a tool-proxy on the host,
//! as the user, with no microVM: the bare host tier
//! (`ContainmentMode::Unsandboxed`). Owner decision 1 (2026-10-02): a
//! non-root runtime runs a pod workload at its own uid only on the explicit
//! `--unsandboxed` opt-in, never because the mode was declared. These two
//! commands ARE the declaration, so they pass the flag deliberately and say so
//! on the terminal; nothing else in the CLI does.

/// The tool-proxy's opt-in flag. One spelling, here, for both commands.
pub(crate) const TOOL_PROXY_OPT_IN: &str = "--unsandboxed";

/// The banner a host-tier command prints before it starts the tool-proxy.
pub(crate) fn banner(command: &str) -> String {
    format!(
        "nucleus {command}: UNSANDBOXED host tier (no microVM). Commands run as your user \
         ({TOOL_PROXY_OPT_IN} passed to the tool-proxy), without namespace or seccomp \
         confinement; a policy that requires stronger isolation is refused. Use a node with \
         microVM isolation for untrusted work."
    )
}

/// Print [`banner`] to stderr, where it cannot be mistaken for the agent's
/// output.
pub(crate) fn announce(command: &str) {
    eprintln!("{}", banner(command));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The banner names the tier and the flag, so what the terminal says is
    /// what the tool-proxy was told.
    #[test]
    fn the_banner_names_the_tier_and_the_opt_in() {
        let b = banner("run --local");
        assert!(b.contains("UNSANDBOXED"), "{b}");
        assert!(b.contains(TOOL_PROXY_OPT_IN), "{b}");
        assert!(b.starts_with("nucleus run --local:"), "{b}");
    }
}
