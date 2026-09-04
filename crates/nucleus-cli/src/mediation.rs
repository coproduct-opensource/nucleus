//! Runtime complete mediation: a default-deny tool gate the agent CLI
//! consults on EVERY tool call.
//!
//! # Why a static denylist is not enough
//!
//! `run` and `shell` launch the agent with its interactive approval bypassed,
//! which is safe only under complete mediation: every tool the agent can reach
//! routes through the nucleus MCP server and therefore the `PermissionLattice`.
//! Until now that rested on [`crate::constants::DISALLOWED_BUILTIN_TOOLS`], a
//! hardcoded list of the agent's built-in tools passed as `--disallowedTools`.
//! A denylist is only as complete as the day it was written: a built-in tool
//! added, renamed, or aliased after that day is reachable, unmediated, with
//! approval already bypassed — and nothing in this repo would notice, because
//! the list is compared against a second copy of itself.
//!
//! # The fix: an allowlist enforced at the call edge
//!
//! The agent CLI runs a `PreToolUse` hook before every tool call and blocks
//! the call when the hook exits with status 2. `nucleus` registers ITSELF as
//! that hook (`nucleus mediation-hook`, hidden), carrying the vetted allowlist
//! in [`ALLOWED_TOOLS_ENV`]. The hook allows a call iff the tool name is
//! EXACTLY one of the allowed nucleus MCP tools and denies everything else —
//! a built-in, a tool the agent CLI grew last week, a nucleus tool the policy
//! did not grant, a malformed event, a missing allowlist. Unknown is denied,
//! not passed through.
//!
//! The static denylist stays as defence in depth (it also keeps the agent
//! from wasting tokens on tool definitions it cannot use); the hook is the
//! boundary. Both launch sites are pinned to install it.
//!
//! # Interop note
//!
//! The hook event shape (`tool_name` on stdin, exit 2 = block) and the
//! `--settings` hook registration are the wrapped agent CLI's own contract,
//! the same intrinsic interop as `--disallowedTools` and `--mcp-config` in the
//! launch sites. No vendor SDK is involved; the gate is a JSON field and an
//! exit code.

use anyhow::{Context, Result};
use std::io::Read;
use std::path::{Path, PathBuf};

/// Environment variable carrying the vetted allowlist (comma-separated tool
/// names) from the launch site to the hook. Set on the agent CLI's process;
/// hooks inherit its environment.
pub const ALLOWED_TOOLS_ENV: &str = "NUCLEUS_MEDIATION_ALLOWED_TOOLS";

/// The hidden subcommand the hook registration invokes.
pub const HOOK_SUBCOMMAND: &str = "mediation-hook";

/// The `PreToolUse` hook exit status that blocks the tool call and feeds
/// stderr back to the model. Chosen over the JSON-decision form because it is
/// the oldest-supported contract: a CLI that does not understand a JSON
/// decision would treat exit 0 + unparsed stdout as ALLOW (fail-open); exit 2
/// blocks on every version that has hooks at all.
const BLOCK_EXIT_CODE: u8 = 2;

/// What the hook decided for one tool call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The tool is one of the allowed, lattice-routed nucleus MCP tools.
    Allow,
    /// Everything else. The reason is fed back to the model.
    Deny { reason: String },
}

/// The pure decision: allow iff `tool_name` is EXACTLY in `allowed` AND is a
/// nucleus MCP tool. An empty allowlist denies everything (the launch site
/// refuses to start with no allowed tools, so this is only reachable if the
/// env var was lost — and losing it must fail closed).
pub fn decide(tool_name: &str, allowed: &[String]) -> Decision {
    let name = tool_name.trim();
    if name.is_empty() {
        return Decision::Deny {
            reason: "tool call carried no tool name".to_string(),
        };
    }
    if !name.starts_with(crate::run::NUCLEUS_MCP_TOOL_PREFIX) {
        return Decision::Deny {
            reason: format!(
                "`{name}` is not a nucleus-mediated tool; only tools routed through the \
                 nucleus permission lattice may run in this session"
            ),
        };
    }
    if !allowed.iter().any(|a| a == name) {
        return Decision::Deny {
            reason: format!("`{name}` is not granted by this session's policy"),
        };
    }
    Decision::Allow
}

/// Parse the allowlist as the launch site serialised it.
pub fn parse_allowlist(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect()
}

/// Pull `tool_name` out of a `PreToolUse` event. Anything unparseable is
/// `None`, which the caller denies.
pub fn tool_name_from_event(event: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(event).ok()?;
    v.get("tool_name")?.as_str().map(str::to_string)
}

/// The settings document that registers this binary as the `PreToolUse`
/// hook for every tool (no matcher = all tools).
pub fn hook_settings(self_exe: &Path) -> serde_json::Value {
    serde_json::json!({
        "hooks": {
            "PreToolUse": [{
                "hooks": [{
                    "type": "command",
                    "command": format!("{} {}", shell_quote(self_exe), HOOK_SUBCOMMAND),
                }]
            }]
        }
    })
}

/// Write the hook settings into `dir` and return the path to pass as
/// `--settings`.
pub fn write_hook_settings(dir: &Path) -> Result<PathBuf> {
    let self_exe = std::env::current_exe().context("resolving own executable for the hook")?;
    let path = dir.join("mediation-hook-settings.json");
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&hook_settings(&self_exe))?,
    )
    .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// Single-quote a path for the hook's shell command line.
fn shell_quote(p: &Path) -> String {
    format!("'{}'", p.display().to_string().replace('\'', "'\\''"))
}

/// The hook entry point: read the event from stdin, decide, and return the
/// process exit status — 0 (allow) or [`BLOCK_EXIT_CODE`] (deny, reason on
/// stderr). Never panics on
/// bad input — a hook that crashes is, on some versions, a hook that allowed.
pub fn run_hook() -> u8 {
    let mut raw = String::new();
    let _ = std::io::stdin().read_to_string(&mut raw);
    let allowed = std::env::var(ALLOWED_TOOLS_ENV)
        .map(|s| parse_allowlist(&s))
        .unwrap_or_default();
    let decision = match tool_name_from_event(&raw) {
        Some(name) => decide(&name, &allowed),
        None => Decision::Deny {
            reason: "unparseable tool-call event".to_string(),
        },
    };
    match decision {
        Decision::Allow => 0,
        Decision::Deny { reason } => {
            eprintln!("nucleus mediation: denied — {reason}");
            BLOCK_EXIT_CODE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed() -> Vec<String> {
        vec![
            "mcp__nucleus__read".to_string(),
            "mcp__nucleus__run".to_string(),
        ]
    }

    #[test]
    fn every_static_denylist_entry_is_denied_by_the_hook() {
        // The hook must subsume the denylist: nothing the list blocks may
        // pass the hook.
        for builtin in crate::constants::DISALLOWED_BUILTIN_TOOLS.split(',') {
            assert!(
                matches!(decide(builtin, &allowed()), Decision::Deny { .. }),
                "{builtin} must be denied"
            );
        }
    }

    #[test]
    fn a_builtin_the_denylist_never_heard_of_is_denied() {
        // The whole point: a tool that did not exist when the denylist was
        // written. Names deliberately absent from DISALLOWED_BUILTIN_TOOLS.
        for novel in [
            "Task",
            "BashOutput",
            "KillShell",
            "Skill",
            "TodoWrite",
            "NewTool",
        ] {
            assert!(
                !crate::constants::DISALLOWED_BUILTIN_TOOLS
                    .split(',')
                    .any(|d| d == novel),
                "test premise: {novel} is not in the static denylist"
            );
            assert!(
                matches!(decide(novel, &allowed()), Decision::Deny { .. }),
                "{novel} must be denied without being listed anywhere"
            );
        }
    }

    #[test]
    fn nucleus_tool_outside_the_policy_grant_is_denied() {
        assert!(matches!(
            decide("mcp__nucleus__web_fetch", &allowed()),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn granted_nucleus_tools_are_allowed_exactly() {
        assert_eq!(decide("mcp__nucleus__read", &allowed()), Decision::Allow);
        assert_eq!(decide("mcp__nucleus__run", &allowed()), Decision::Allow);
        // Exact match: no prefix/suffix tricks.
        assert!(matches!(
            decide("mcp__nucleus__read2", &allowed()),
            Decision::Deny { .. }
        ));
        assert!(matches!(
            decide("mcp__nucleus__rea", &allowed()),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn empty_allowlist_and_empty_name_deny() {
        assert!(matches!(
            decide("mcp__nucleus__read", &[]),
            Decision::Deny { .. }
        ));
        assert!(matches!(decide("", &allowed()), Decision::Deny { .. }));
    }

    #[test]
    fn event_parsing_is_fail_closed() {
        assert_eq!(
            tool_name_from_event(r#"{"tool_name":"mcp__nucleus__read","tool_input":{}}"#)
                .as_deref(),
            Some("mcp__nucleus__read")
        );
        assert_eq!(tool_name_from_event("not json"), None);
        assert_eq!(tool_name_from_event(r#"{"tool_input":{}}"#), None);
        assert_eq!(tool_name_from_event(r#"{"tool_name":7}"#), None);
    }

    #[test]
    fn allowlist_round_trips_through_the_env_encoding() {
        assert_eq!(parse_allowlist(" a , ,b,"), vec!["a", "b"]);
        assert_eq!(
            parse_allowlist(&allowed().join(",")),
            allowed(),
            "the launch site's join and the hook's split must agree"
        );
    }

    #[test]
    fn settings_register_this_binary_for_every_tool() {
        let v = hook_settings(Path::new("/opt/nuc leus/nucleus"));
        let entry = &v["hooks"]["PreToolUse"][0];
        assert!(entry.get("matcher").is_none(), "no matcher = every tool");
        let cmd = entry["hooks"][0]["command"].as_str().unwrap();
        assert_eq!(cmd, "'/opt/nuc leus/nucleus' mediation-hook");
        assert_eq!(entry["hooks"][0]["type"], "command");
    }

    /// Structural pin: BOTH launch sites install the hook and hand it the
    /// allowlist. Mirrors the existing `disallow lists must stay identical`
    /// regression; a site that drops either line reopens the bypass.
    #[test]
    fn both_launch_sites_install_the_hook() {
        for (name, src) in [
            ("run.rs", include_str!("run.rs")),
            ("shell.rs", include_str!("shell.rs")),
        ] {
            let launches = src
                .matches("Command::new(crate::constants::AGENT_CLI_BIN)")
                .count();
            assert!(launches > 0, "{name}: no launch site found (test is stale)");
            assert!(
                src.contains("mediation::write_hook_settings("),
                "{name}: launch site does not install the mediation hook"
            );
            // rustfmt may split the call; compare without whitespace.
            let compact: String = src.split_whitespace().collect();
            assert!(
                compact.contains(".env(crate::mediation::ALLOWED_TOOLS_ENV,"),
                "{name}: launch site does not pass the allowlist to the hook"
            );
        }
    }
}
