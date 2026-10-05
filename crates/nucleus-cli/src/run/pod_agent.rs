//! The agent inside the pod: the `WorkloadSpec` a microVM run asks for, and
//! the wait for what it printed (#2696 P5, owner decision D9).
//!
//! # Where the agent runs, and why that is the default
//!
//! A host-launched agent sits outside every structural boundary nucleus has: the
//! microVM fences the tools, and the agent that drives them keeps the operator's
//! files, network and credentials. So a microVM run no longer launches the agent
//! on the host at all. It names the agent as the pod's workload, and the guest's
//! tool-proxy starts it -- after its kernel is live, under
//! `nucleus::ChildConfinement` (a distinct uid, no_new_privs, seccomp without
//! AF_VSOCK or user namespaces), with its tools reached through the in-guest
//! MCP bridge over the workload door. The host only creates the pod, waits for
//! the workload's exit, and prints its output.
//!
//! # What crosses into the guest
//!
//! The program, its arguments, and nothing else. The workload's `env` is EMPTY:
//! everything the agent needs the guest runtime injects itself (the door's URL,
//! `PATH`, `LANG`, `TZ`, a `HOME` on its scratch), and this host's environment,
//! `--env` values and credentials stay here. A model upstream is a declared
//! credentialed egress the host performs (#3031), not a key in the agent's env.
//!
//! # The launch protocol, in a pod
//!
//! The same flags a host launch gets (`crate::run::mcp_launch_protocol`, one
//! builder for both), with two differences that follow from where it runs:
//!
//! - `--mcp-config` carries the configuration DOCUMENT, not a path: no host file
//!   is visible in the guest. It names only the guest's own bridge
//!   (`guest_layout::MCP_BIN`), which finds the door through the
//!   `NUCLEUS_TOOL_PROXY_URL` the runtime gave the workload; it holds no secret.
//! - No `--settings` mediation hook. The hook is this host's binary, which the
//!   guest does not have, and its job -- keeping the agent's built-in tools off
//!   the operator's machine -- is done structurally in a pod: a built-in tool
//!   acts inside the guest, as the workload uid, behind the pod's egress fence.
//!   `--allowedTools` / `--disallowedTools` still apply as defence in depth.
//!   Confining built-in file access WITHIN the guest is Landlock (#2696 P3c).

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use nucleus_spec::WorkloadSpec;
use nucleus_spec::workload_result::WorkloadResult;
use portcullis::PermissionLattice;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::MediationGuard;

/// The MCP configuration an agent in the pod is handed: the guest's own
/// bridge, and nothing else. Built, not written by hand, so it is valid JSON
/// by construction.
pub(super) fn guest_mcp_config() -> String {
    serde_json::json!({
        "mcpServers": {
            "nucleus": {
                "type": "stdio",
                "command": nucleus_spec::guest_layout::MCP_BIN,
            }
        }
    })
    .to_string()
}

/// The pod's workload: the named agent, confined, speaking the launch protocol
/// to the guest's MCP bridge.
///
/// No parameter carries an environment or a credential, so none can reach the
/// workload from here (see the module docs).
///
/// # Errors
///
/// The agent's program names a host-relative file
/// (`crate::agent::HOST_PATH_IN_POD`).
pub(super) fn workload(
    agent: &crate::agent::AgentCommand,
    guard: &MediationGuard,
    policy: &PermissionLattice,
    model: Option<&str>,
    prompt: &str,
) -> Result<WorkloadSpec> {
    let (command, mut args) = agent.in_pod()?;
    let config = guest_mcp_config();
    for arg in super::mcp_launch_protocol(model, config.as_ref(), guard, policy, prompt) {
        args.push(
            arg.into_string()
                .map_err(|a| anyhow!("a launch argument is not UTF-8: {a:?}"))?,
        );
    }
    Ok(WorkloadSpec {
        command,
        args,
        env: BTreeMap::new(),
        artifacts: BTreeMap::new(),
        // The guest's `ChildConfinement` gives an unset uid the unprivileged
        // default, which is never the runtime's.
        uid: None,
    })
}

/// What the agent printed, as the guest's supervisor hashed it.
#[derive(Debug)]
pub(super) struct AgentExit {
    pub(super) exit_code: Option<i32>,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
}

/// How often the node is asked whether the agent has exited.
const POLL: Duration = Duration::from_secs(1);

/// Wait for the pod's workload to exit, then fetch its output.
///
/// # Errors
///
/// The node answers with an error, reports no workload or an incomplete
/// observation, the pod's deadline passes, or a log does not hash to what the
/// supervisor observed. A failed observation is a failed run, never an empty
/// one (ADR 0007 A-1).
pub(super) async fn wait_for_exit(
    client: &reqwest::Client,
    node_url: &str,
    pod: Uuid,
    deadline: Duration,
) -> Result<AgentExit> {
    let base = format!("{}/v1/pods/{pod}", node_url.trim_end_matches('/'));
    let observed = tokio::time::timeout(deadline, async {
        loop {
            let body = get(client, &format!("{base}/workload-result")).await?;
            let result: WorkloadResult =
                serde_json::from_slice(&body).context("decoding the workload result")?;
            match result {
                WorkloadResult::Running => tokio::time::sleep(POLL).await,
                WorkloadResult::Exited {
                    exit_code,
                    stdout_sha256,
                    stderr_sha256,
                    ..
                } => return Ok::<_, anyhow::Error>((exit_code, stdout_sha256, stderr_sha256)),
                WorkloadResult::NotConfigured => {
                    bail!("the pod reports no workload, so the agent was never started in it")
                }
                WorkloadResult::Unavailable { reason } => {
                    bail!("the pod could not observe the agent: {reason}")
                }
            }
        }
    })
    .await
    .map_err(|_| anyhow!("the agent did not exit within the pod's {deadline:?}"))??;
    let (exit_code, stdout_sha256, stderr_sha256) = observed;
    let stdout = get(client, &format!("{base}/workload-logs/stdout")).await?;
    let stderr = get(client, &format!("{base}/workload-logs/stderr")).await?;
    matches_digest("stdout", &stdout, &stdout_sha256)?;
    matches_digest("stderr", &stderr, &stderr_sha256)?;
    Ok(AgentExit {
        exit_code,
        stdout,
        stderr,
    })
}

async fn get(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let response = client
        .get(url)
        .timeout(Duration::from_secs(60))
        .send()
        .await
        .with_context(|| format!("asking the node for {url}"))?;
    let status = response.status().as_u16();
    let body = response.bytes().await?.to_vec();
    crate::node::ensure_ok(status, &body, "reading the in-pod agent's result")?;
    Ok(body)
}

/// The bytes printed are the bytes the supervisor hashed when the agent exited.
fn matches_digest(stream: &str, bytes: &[u8], expected: &str) -> Result<()> {
    let actual = hex::encode(Sha256::digest(bytes));
    if actual == expected {
        Ok(())
    } else {
        bail!(
            "the agent's {stream} does not match the supervisor's digest ({actual} != {expected})"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard(policy: &PermissionLattice) -> MediationGuard {
        MediationGuard::establish(&super::super::build_mcp_allowed_tools(policy))
            .expect("a codegen-like policy grants mediated tools")
    }

    fn agent() -> crate::agent::AgentCommand {
        crate::agent::AgentCommand::named(Some("/opt/agent"), &["--lead".into()]).expect("named")
    }

    /// The program, the argv and the env, exactly. The env is empty: every
    /// variable the agent gets is the guest runtime's to inject.
    #[test]
    fn the_workload_is_the_named_agent_confined_with_an_empty_env() {
        let policy = PermissionLattice::permissive();
        let guard = guard(&policy);
        let w = workload(&agent(), &guard, &policy, Some("m-1"), "fix the bug").expect("built");
        assert_eq!(w.command, "/opt/agent");
        let tools = guard.allowed_tools().join(",");
        let budget = policy.budget.max_cost_usd.to_string();
        let config = guest_mcp_config();
        let expected: Vec<&str> = vec![
            "--lead",
            "--setting-sources",
            "",
            "--strict-mcp-config",
            "--print",
            "--model",
            "m-1",
            "--mcp-config",
            &config,
            "--allowedTools",
            &tools,
            "--disallowedTools",
            crate::constants::DISALLOWED_BUILTIN_TOOLS,
            "--max-budget-usd",
            &budget,
            "fix the bug",
            "--dangerously-skip-permissions",
            "--permission-mode",
            "bypassPermissions",
        ];
        assert_eq!(w.args, expected);
        assert!(w.env.is_empty(), "nothing from this host: {:?}", w.env);
        assert!(w.artifacts.is_empty());
        assert_eq!(w.uid, None, "the guest's confinement picks the uid");
    }

    /// The configuration names only the guest's bridge, and carries no
    /// secret or proxy coordinate of this host's.
    #[test]
    fn the_guest_mcp_config_names_only_the_guest_bridge() {
        let v: serde_json::Value = serde_json::from_str(&guest_mcp_config()).expect("json");
        let servers = v["mcpServers"].as_object().expect("servers");
        assert_eq!(servers.len(), 1);
        assert_eq!(
            servers["nucleus"]["command"],
            nucleus_spec::guest_layout::MCP_BIN
        );
        assert!(servers["nucleus"].get("env").is_none(), "{v}");
    }

    /// A-19 pair: a run carrying `--env` credentials and a pod spec built from
    /// it -- the value appears NOWHERE in what is sent to the node. Wire
    /// `args.envs` into the workload (or the spec's credentials) and this reds.
    #[test]
    fn no_host_secret_reaches_the_pod_spec() {
        use clap::Parser;
        #[derive(Parser)]
        struct Parse {
            #[command(flatten)]
            args: super::super::RunArgs,
        }
        let args = Parse::try_parse_from([
            "run",
            "--agent",
            "/opt/agent",
            "--env",
            "LLM_API_TOKEN=test-token-123",
            "fix the bug",
        ])
        .expect("parses")
        .args;
        let policy = PermissionLattice::permissive();
        let guard = guard(&policy);
        let w = workload(
            &super::super::named_agent(&args).expect("named"),
            &guard,
            &policy,
            None,
            "fix the bug",
        )
        .expect("built");
        let spec = super::super::build_pod_spec(&args, &policy, "/kernel", "/rootfs", Some(w))
            .expect("spec");
        let yaml = serde_yaml::to_string(&spec).expect("yaml");
        assert!(yaml.contains("/opt/agent"), "the agent is the workload");
        assert!(
            !yaml.contains("test-token-123"),
            "a host secret leaked:\n{yaml}"
        );
        assert!(
            !yaml.contains("LLM_API_TOKEN"),
            "a host key leaked:\n{yaml}"
        );
        // And the run refuses the flag outright, rather than dropping it.
        assert!(
            super::super::refuse_host_only_flags(&args)
                .expect_err("--env has no pod meaning")
                .to_string()
                .contains("--env")
        );
    }

    #[test]
    fn a_host_relative_agent_is_refused_before_a_pod_is_asked_for() {
        let policy = PermissionLattice::permissive();
        let agent = crate::agent::AgentCommand::named(Some("./agent"), &[]).expect("named");
        let err = workload(&agent, &guard(&policy), &policy, None, "task")
            .expect_err("a host path names no guest file");
        assert!(err.to_string().contains("./agent"), "{err}");
    }

    #[test]
    fn a_log_that_does_not_match_its_digest_is_refused() {
        let digest = hex::encode(Sha256::digest(b"out"));
        assert!(matches_digest("stdout", b"out", &digest).is_ok());
        let err = matches_digest("stdout", b"other", &digest).expect_err("tampered");
        assert!(err.to_string().contains("stdout"), "{err}");
    }
}
