//! The agent command: the program `run` and `shell` launch, named by the user.
//!
//! Nucleus has no default agent. Which agent CLI runs is the operator's (or the
//! orchestrator's) decision, so `run` and `shell` refuse to start until one is
//! named — with `--agent <PROGRAM> [-- ARGS...]`, the `NUCLEUS_AGENT`
//! environment variable, or `[agent] command = [...]` in the config file.
//!
//! # The launch protocol
//!
//! Nucleus speaks ONE launch protocol to whatever it launches: after the
//! program and the arguments the user gave, it appends its own flags — the
//! confinement flags ([`crate::mediation::confine_to_nucleus_settings`]),
//! `--settings <file>` (the mediation hook registration), `--mcp-config <file>`,
//! `--allowedTools` / `--disallowedTools`, and the prompt. An agent CLI that
//! accepts those flags is launched directly; one that does not is launched
//! through a small adapter that translates them. Per-agent invocations and
//! adapters live in `examples/agents/`, not here: nothing in this crate knows
//! which vendor's CLI is on the other end.
//!
//! # Confinement is part of construction
//!
//! [`AgentCommand::launch`] is the only way the launch sites build the agent's
//! [`Command`], and it applies the confinement flags itself. A launch site
//! cannot forget them, because there is no unconfined agent command to forget
//! them on. They go AFTER the user's arguments, so a flag the user passed
//! cannot be the last word on which settings the agent loads.

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::process::Command;

/// The refusal when no agent was named. Says how to name one and where the
/// examples are, because "required" with no next step is a dead end.
pub const NO_AGENT_NAMED: &str = "\
no agent command named — nucleus launches the agent CLI you choose and has no default.
  Name it with one of:
    --agent <PROGRAM> [-- ARGS...]          e.g. nucleus run --agent my-agent \"fix the bug\"
    NUCLEUS_AGENT=<PROGRAM>                 in the environment
    [agent] command = [\"PROGRAM\", \"ARG\"]    in the nucleus config file
  The agent must accept the nucleus launch protocol; examples/agents/README.md
  shows per-agent invocations and how to adapt one that does not.";

/// `[agent]` in the nucleus config file.
///
/// No `Default` derive with a granting meaning: the empty command names no
/// agent, and an unnamed agent is refused ([`NO_AGENT_NAMED`]).
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AgentConfig {
    /// The agent program followed by its leading arguments. Empty = not set.
    #[serde(default)]
    pub command: Vec<String>,
}

/// Fold the config file's `[agent] command` into the CLI's agent fields when
/// neither `--agent` nor `NUCLEUS_AGENT` named one. The flag wins; arguments
/// given after `--` follow the config's own arguments.
pub fn fold_config_default(
    agent: &mut Option<String>,
    agent_args: &mut Vec<String>,
    config: &AgentConfig,
) {
    if agent.is_some() {
        return;
    }
    let Some((program, args)) = config.command.split_first() else {
        return;
    };
    *agent = Some(program.clone());
    let mut combined = args.to_vec();
    combined.append(agent_args);
    *agent_args = combined;
}

/// A named agent: a non-empty program and the arguments that lead its argv.
///
/// Private fields, one constructor ([`AgentCommand::named`]) that refuses an
/// absent or blank program: holding one is evidence an agent was named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCommand {
    program: String,
    args: Vec<String>,
}

impl AgentCommand {
    /// The agent the user named, or the refusal that says how to name one.
    ///
    /// # Errors
    ///
    /// [`NO_AGENT_NAMED`] when `program` is absent or blank.
    pub fn named(program: Option<&str>, args: &[String]) -> Result<Self> {
        let program = program
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .ok_or_else(|| anyhow!(NO_AGENT_NAMED))?;
        Ok(Self {
            program: program.to_string(),
            args: args.to_vec(),
        })
    }

    /// The program, for messages.
    #[must_use]
    pub fn program(&self) -> &str {
        &self.program
    }

    /// The command line as the user named it, for dry-run and printed advice.
    #[must_use]
    pub fn display(&self) -> String {
        std::iter::once(self.program.as_str())
            .chain(self.args.iter().map(String::as_str))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The agent's command ON THIS HOST, confined: the program, the user's
    /// arguments, then the flags that deny the working directory any say in the
    /// agent's settings. The launch sites append the rest of the launch protocol.
    #[must_use]
    pub fn launch(&self) -> Command {
        let mut cmd = Command::new(&self.program);
        cmd.args(&self.args);
        crate::mediation::confine_to_nucleus_settings(&mut cmd);
        cmd
    }

    /// The agent's argv INSIDE a pod: the program as the guest will resolve it,
    /// then the user's arguments, then the same confinement flags
    /// ([`crate::mediation::CONFINEMENT_FLAGS`]) a host launch gets.
    ///
    /// # Errors
    ///
    /// [`HOST_PATH_IN_POD`] when the program names a file relative to this host
    /// (`./agent`, `bin/agent`, `~/agent`): the agent runs in the guest, which
    /// resolves it against the guest image, and nucleus copies no host binary
    /// into a guest.
    pub fn in_pod(&self) -> Result<(String, Vec<String>)> {
        let program = self.program.as_str();
        let host_relative =
            program.starts_with('~') || (program.contains('/') && !program.starts_with('/'));
        if host_relative {
            return Err(anyhow!("agent program `{program}` {HOST_PATH_IN_POD}"));
        }
        let mut args = self.args.clone();
        args.extend(
            crate::mediation::CONFINEMENT_FLAGS
                .iter()
                .map(|f| (*f).to_string()),
        );
        Ok((program.to_string(), args))
    }
}

/// Why a host-relative agent path is refused for a pod run.
pub const HOST_PATH_IN_POD: &str = "\
names a file relative to this host, but the agent runs inside the pod and the guest resolves \
the program against its own image. Name it by its absolute path in the guest image or by a \
name on the guest's PATH; nucleus does not copy host binaries into the guest. To run the agent \
on this host instead, use --local.";

/// A command line someone will paste: program and arguments, each
/// single-quoted when it is empty or carries a character a shell would read.
pub fn render_for_shell(cmd: &Command) -> String {
    std::iter::once(cmd.get_program())
        .chain(cmd.get_args())
        .map(|a| {
            let a = a.to_string_lossy();
            let plain = !a.is_empty()
                && a.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_./,=:@+".contains(c));
            if plain {
                a.into_owned()
            } else {
                format!("'{}'", a.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(cmd: &Command) -> Vec<String> {
        cmd.get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn no_agent_is_refused_with_directions() {
        for missing in [None, Some(""), Some("   ")] {
            let err = AgentCommand::named(missing, &[]).expect_err("no agent must be refused");
            let msg = err.to_string();
            assert!(msg.contains("--agent"), "names the flag: {msg}");
            assert!(msg.contains("NUCLEUS_AGENT"), "names the env var: {msg}");
            assert!(msg.contains("[agent]"), "names the config key: {msg}");
            assert!(msg.contains("examples/agents"), "points at examples: {msg}");
        }
    }

    #[test]
    fn the_named_program_and_its_args_lead_the_launch() {
        let agent = AgentCommand::named(
            Some("my-agent"),
            &["--profile-dir".to_string(), "/x y".to_string()],
        )
        .expect("named");
        let cmd = agent.launch();
        assert_eq!(cmd.get_program(), "my-agent");
        let args = argv(&cmd);
        assert_eq!(&args[..2], ["--profile-dir", "/x y"], "user args first");
        assert_eq!(agent.display(), "my-agent --profile-dir /x y");
    }

    /// A-19: the confinement is applied by construction. Remove the
    /// `confine_to_nucleus_settings` call from `launch` and this reds.
    #[test]
    fn every_launch_is_confined_after_the_users_args() {
        let agent = AgentCommand::named(
            Some("my-agent"),
            &["--setting-sources".to_string(), "user".to_string()],
        )
        .expect("named");
        let args = argv(&agent.launch());
        assert_eq!(
            args,
            vec![
                "--setting-sources",
                "user",
                "--setting-sources",
                crate::mediation::SETTING_SOURCES,
                "--strict-mcp-config",
            ],
            "nucleus's confinement comes last, so a user flag cannot be the last word"
        );
    }

    #[test]
    fn printed_advice_keeps_the_empty_setting_sources_value() {
        let agent = AgentCommand::named(Some("my agent"), &[]).expect("named");
        assert_eq!(
            render_for_shell(&agent.launch()),
            "'my agent' --setting-sources '' --strict-mcp-config",
            "an unquoted empty value vanishes when pasted, and the flag then \
             swallows the next argument"
        );
    }

    #[test]
    fn the_config_command_is_the_fallback_and_the_flag_wins() {
        let config = AgentConfig {
            command: vec!["cfg-agent".to_string(), "--cfg".to_string()],
        };

        let (mut agent, mut args) = (None, vec!["--extra".to_string()]);
        fold_config_default(&mut agent, &mut args, &config);
        assert_eq!(agent.as_deref(), Some("cfg-agent"));
        assert_eq!(args, ["--cfg", "--extra"]);

        let (mut agent, mut args) = (Some("flag-agent".to_string()), Vec::new());
        fold_config_default(&mut agent, &mut args, &config);
        assert_eq!(agent.as_deref(), Some("flag-agent"));
        assert!(args.is_empty());

        let (mut agent, mut args) = (None, Vec::new());
        fold_config_default(&mut agent, &mut args, &AgentConfig::default());
        assert!(agent.is_none(), "an empty config names no agent");
        assert!(AgentCommand::named(agent.as_deref(), &args).is_err());
    }

    #[test]
    fn the_config_key_parses() {
        let config: crate::config::Config =
            toml::from_str("[agent]\ncommand = [\"my-agent\", \"--flag\"]\n").expect("parses");
        assert_eq!(config.agent.command, ["my-agent", "--flag"]);
    }

    /// A-19: the pod argv is confined exactly as a host launch is. Drop the
    /// `CONFINEMENT_FLAGS` extension from `in_pod` and this reds; so does a
    /// host launch whose flags drift from the pod's.
    #[test]
    fn the_pod_argv_carries_the_same_confinement_as_a_host_launch() {
        let agent = AgentCommand::named(
            Some("/opt/agent/bin/agent"),
            &["--profile-dir".to_string(), "/x y".to_string()],
        )
        .expect("named");
        let (program, args) = agent.in_pod().expect("absolute guest path");
        assert_eq!(program, "/opt/agent/bin/agent");
        assert_eq!(
            args,
            argv(&agent.launch()),
            "the guest invocation and the host invocation confine identically"
        );
        assert_eq!(
            &args[2..],
            ["--setting-sources", "", "--strict-mcp-config"],
            "the user's arguments lead; nucleus's confinement is the last word"
        );

        let on_path = AgentCommand::named(Some("my-agent"), &[]).expect("named");
        assert_eq!(on_path.in_pod().expect("a bare name").0, "my-agent");
    }

    #[test]
    fn a_host_relative_program_is_refused_for_a_pod_by_name() {
        for host_path in ["./agent", "bin/agent", "~/bin/agent", "~agent"] {
            let agent = AgentCommand::named(Some(host_path), &[]).expect("named");
            let err = agent
                .in_pod()
                .expect_err("a host path cannot name a guest file");
            let msg = err.to_string();
            assert!(msg.contains(host_path), "names the program: {msg}");
            assert!(
                msg.contains("does not copy host binaries into the guest"),
                "{msg}"
            );
            assert!(msg.contains("--local"), "names the way out: {msg}");
        }
    }
}
