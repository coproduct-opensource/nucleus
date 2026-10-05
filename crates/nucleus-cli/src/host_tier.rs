//! The unsandboxed host tier, declared on purpose.
//!
//! `nucleus run --local` and `nucleus shell` start a tool-proxy on the host,
//! as the user, with no microVM: the bare host tier
//! (`ContainmentMode::Unsandboxed`). Owner decision 1 (2026-10-02): a
//! non-root runtime runs a pod workload at its own uid only on the explicit
//! `--unsandboxed` opt-in, never because the mode was declared. These two
//! commands ARE the declaration, so they pass the flag deliberately and say so
//! on the terminal; nothing else in the CLI does.
//!
//! The AGENT on the host is a second, separate declaration ([`HostAgentOptIn`]):
//! `run --local`, `run --hook` and `shell` launch it only with the operator's
//! own `--unsandboxed`, a banner and an audit record (owner decision D9).

use std::path::Path;

use anyhow::{Context, Result, bail};

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

/// The audit log every host agent launch is recorded in, under the nucleus
/// state directory (`crate::config::nucleus_dir`).
pub(crate) const HOST_AGENT_AUDIT_LOG: &str = "audit/host-agent-launches.jsonl";

/// The operator's declaration that the agent runs ON THIS HOST, outside any
/// microVM: the evidence `crate::agent::AgentCommand::launch` requires.
///
/// Owner decision D9 (2026-10-01): a microVM pod runs its agent in the guest,
/// always; the local tiers keep the host launch only behind an explicit
/// `--unsandboxed`. One constructor, [`HostAgentOptIn::declare`], which refuses
/// without the flag and, with it, writes the audit record and prints the
/// banner BEFORE handing the value back -- so a host launch that was not
/// recorded cannot be built (ADR 0007 C-1). Not `Clone`, and `launch` takes it
/// by value: one declaration, one launch (C-4).
#[must_use = "a declaration that launches nothing is an audit record of nothing"]
#[derive(Debug)]
pub(crate) struct HostAgentOptIn {
    _private: (),
}

impl HostAgentOptIn {
    /// Declare a host agent launch for `command` (`"run --local"`, `"shell"`),
    /// recorded in [`HOST_AGENT_AUDIT_LOG`].
    ///
    /// # Errors
    ///
    /// Without `unsandboxed`, the refusal that names the flag and the in-pod
    /// alternative. With it, a failure to write the audit record: a launch the
    /// operator was promised would be recorded is not made unrecorded.
    pub(crate) fn declare(
        unsandboxed: bool,
        command: &str,
        agent: &crate::agent::AgentCommand,
        work_dir: &Path,
    ) -> Result<Self> {
        if !unsandboxed {
            bail!(refusal(command, agent.program()));
        }
        let log = crate::config::nucleus_dir()?.join(HOST_AGENT_AUDIT_LOG);
        Self::declare_to(&log, command, agent, work_dir)
    }

    fn declare_to(
        log: &Path,
        command: &str,
        agent: &crate::agent::AgentCommand,
        work_dir: &Path,
    ) -> Result<Self> {
        let record = serde_json::json!({
            "at": chrono::Utc::now().to_rfc3339(),
            "event": "unsandboxed_host_agent_launch",
            "command": format!("nucleus {command}"),
            // The program only: the agent's arguments and the prompt can carry
            // anything, and an audit log is not where a prompt should land.
            "agent_program": agent.program(),
            "work_dir": work_dir.display().to_string(),
        });
        let line = record.to_string();
        let recorded = nucleus_jsonl::append_line_synced(log, &line).with_context(|| {
            format!(
                "recording the unsandboxed host agent launch in the audit log {}; refusing to \
                 launch unrecorded",
                log.display()
            )
        })?;
        // The declaration is built from the proof that THIS record was kept.
        if !recorded.proves(log, &line) {
            bail!("the audit log did not keep the host agent launch record; refusing to launch");
        }
        eprintln!("{}", agent_banner(command, agent.program(), log));
        Ok(Self { _private: () })
    }

    /// A declaration for a test that builds, and never spawns, a host command.
    #[cfg(test)]
    pub(crate) fn for_test() -> Self {
        Self { _private: () }
    }
}

/// Why a host agent launch is refused without the opt-in.
fn refusal(command: &str, program: &str) -> String {
    format!(
        "nucleus {command} would launch the agent `{program}` on THIS host, as your user, \
         outside any microVM: the unsandboxed host tier, which is never chosen by default. \
         Pass {TOOL_PROXY_OPT_IN} to accept it (a banner is printed and the launch is recorded \
         in ~/.config/nucleus/{HOST_AGENT_AUDIT_LOG}), or use `nucleus run` against a node \
         without --local or --hook, which runs the agent inside the pod."
    )
}

/// The banner a host agent launch prints, on stderr.
fn agent_banner(command: &str, program: &str, log: &Path) -> String {
    format!(
        "nucleus {command}: UNSANDBOXED -- the agent `{program}` runs on THIS host as your user, \
         outside any microVM. Only its nucleus tools are mediated; no pod is its boundary. \
         Recorded in {}.",
        log.display()
    )
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

    fn agent() -> crate::agent::AgentCommand {
        crate::agent::AgentCommand::named(Some("my-agent"), &["--secret-arg".into()])
            .expect("named")
    }

    /// A-19 pair, half one: without `--unsandboxed` there is no declaration,
    /// so no host command can be built, and nothing is recorded. Make
    /// `declare` skip its flag check and this reds.
    #[test]
    fn a_host_agent_launch_without_the_opt_in_is_refused_and_unrecorded() {
        let err = HostAgentOptIn::declare(false, "run --local", &agent(), Path::new("/w"))
            .expect_err("no flag, no host launch");
        let msg = err.to_string();
        assert!(msg.contains("--unsandboxed"), "names the flag: {msg}");
        assert!(msg.contains("my-agent"), "names the agent: {msg}");
        assert!(msg.contains("inside the pod"), "names the default: {msg}");
    }

    /// Half two: with it, one durable JSON line per launch, naming the command,
    /// the program and the directory, and never the agent's arguments.
    #[test]
    fn a_declared_host_agent_launch_is_recorded_before_it_is_allowed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let log = dir.path().join(HOST_AGENT_AUDIT_LOG);
        for _ in 0..2 {
            let _declared =
                HostAgentOptIn::declare_to(&log, "run --local", &agent(), Path::new("/w"))
                    .expect("declared");
        }
        let raw = std::fs::read_to_string(&log).expect("the record exists");
        let lines: Vec<serde_json::Value> = raw
            .lines()
            .map(|l| serde_json::from_str(l).expect("one JSON record per line"))
            .collect();
        assert_eq!(lines.len(), 2, "every launch is its own record: {raw}");
        assert_eq!(lines[0]["event"], "unsandboxed_host_agent_launch");
        assert_eq!(lines[0]["command"], "nucleus run --local");
        assert_eq!(lines[0]["agent_program"], "my-agent");
        assert_eq!(lines[0]["work_dir"], "/w");
        assert!(!raw.contains("--secret-arg"), "arguments stay out: {raw}");
    }

    /// An audit record that cannot be written refuses the launch.
    #[test]
    fn an_unwritable_audit_log_refuses_the_launch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let blocker = dir.path().join("not-a-dir");
        std::fs::write(&blocker, b"").expect("file");
        let err = HostAgentOptIn::declare_to(
            &blocker.join("launches.jsonl"),
            "shell",
            &agent(),
            Path::new("/w"),
        )
        .expect_err("unrecorded is refused");
        assert!(format!("{err:#}").contains("audit"), "{err:#}");
    }

    #[test]
    fn the_agent_banner_says_where_the_agent_runs_and_where_it_was_recorded() {
        let b = agent_banner("shell", "my-agent", Path::new("/log.jsonl"));
        assert!(b.contains("UNSANDBOXED"), "{b}");
        assert!(b.contains("THIS host"), "{b}");
        assert!(b.contains("/log.jsonl"), "{b}");
    }
}
