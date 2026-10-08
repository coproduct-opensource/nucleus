//! What a host directory carries for git to execute, said before the CLI hands
//! it to an agent or turns it into a pod's disk (ADR 0013).
//!
//! The node is the decider for a pod: it refuses an eval cell whose disk
//! carries exec-bearing git config, and records the findings of a standard
//! pod (`nucleus-node`'s `workspace_scan`). The CLI sees two entries the node
//! never does, and warns at each:
//!
//! - the host tiers (`run --local`, `run --hook`, `shell`), where the agent
//!   runs on this machine in the directory itself, and an eval cell is already
//!   refused by name (`run::eval_cell::refuse_host_tier`);
//! - `microvm-host seed`, which builds the disk; a warning there is the
//!   operator's first chance to hear that an eval cell will refuse it.
//!
//! A warning, not a refusal: the standard profile admits these workspaces, and
//! the operator has already declared the host tier with `--unsandboxed`. The
//! list is [`portcullis::git_exec`], the one the node and the consume guard read.

use std::path::Path;

use portcullis::git_exec;

/// The warning for `dir`, or `None` when the scan looked everywhere and found
/// nothing. A scan that could not finish is a warning too (ADR 0007 A-2).
pub(crate) fn warning(dir: &Path, consumer: &str) -> Option<String> {
    let body = match git_exec::scan(dir) {
        Ok(found) if found.is_empty() => return None,
        Ok(found) => found
            .iter()
            .map(|f| format!("  - {f}"))
            .collect::<Vec<_>>()
            .join("\n"),
        Err(e) => format!("  - the workspace could not be scanned: {e}"),
    };
    Some(format!(
        "warning: {} carries configuration git would execute, and {consumer}:\n{body}\nAn \
         eval cell is refused for this workspace (ADR 0013).",
        dir.display()
    ))
}

/// Print [`warning`] for `dir` to stderr, if there is one.
pub(crate) fn warn(dir: &Path, consumer: &str) {
    if let Some(w) = warning(dir, consumer) {
        eprintln!("{w}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hook_is_named_and_a_clean_directory_is_silent() {
        let w = tempfile::tempdir().expect("ws");
        std::fs::create_dir_all(w.path().join(".git/hooks")).expect("hooks");
        std::fs::write(w.path().join(".git/hooks/pre-commit.sample"), "x").expect("sample");
        assert_eq!(warning(w.path(), "the agent runs in it"), None);
        std::fs::write(w.path().join(".git/hooks/pre-commit"), "x").expect("hook");
        let said = warning(w.path(), "the agent runs in it").expect("a warning");
        assert!(said.contains(".git/hooks/pre-commit (git hook)"), "{said}");
    }
}
