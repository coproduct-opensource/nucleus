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
//! # The hook is only the boundary if the subject cannot register one too
//!
//! Both launch sites run the agent CLI on the HOST, in the working directory
//! being examined, and the CLI's own defaults load configuration FROM that
//! directory: `.claude/settings.json`, the hooks registered there, `CLAUDE.md`,
//! and `.mcp.json` servers. Installing nucleus's hook does not displace those —
//! it is merged alongside them. A repository could therefore supply its own
//! tools and its own instructions to the agent sent to examine it, unmediated,
//! with approval already bypassed. [`confine_to_nucleus_settings`] closes that,
//! and every launch site is pinned to call it.
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
use std::process::Command;

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

/// The implicit setting scopes the wrapped agent CLI may load: NONE.
///
/// Empty rather than `user`, because a boundary that reads ambient host state
/// is not a boundary (ADR 0007, family H): a `PreToolUse` hook in
/// `~/.claude/settings.json` is exactly as unmediated as one in the
/// repository's. The only settings that configure a confined agent are the
/// ones nucleus hands it on the command line, which `--setting-sources` does
/// not gate.
pub const SETTING_SOURCES: &str = "";

/// Deny the WORKING DIRECTORY any say in how the confined agent is configured.
///
/// [`crate::run`] and [`crate::shell`] launch the agent CLI on the HOST, in the
/// directory being worked on, with interactive approval bypassed. Left to its
/// defaults the CLI ALSO loads that directory's `.claude/settings.json`, the
/// `PreToolUse` hooks registered there, its `CLAUDE.md`, and its `.mcp.json`
/// servers. So the repository under examination could install hooks and MCP
/// servers of its own alongside the ones nucleus installed to mediate it: the
/// measured thing editing its own measurement, and an unmediated tool reachable
/// with approval already bypassed.
///
/// Every launch site must call this. Verified against the wrapped CLI at
/// 2.1.278, by running it in a directory holding a `.claude/settings.json`
/// hook: without these flags that hook RUNS; with them it does not, while the
/// `--settings` document nucleus passes still does.
///
/// `--strict-mcp-config` is meaningful even where no `--mcp-config` is passed:
/// it then resolves to zero MCP servers rather than to the directory's own.
pub fn confine_to_nucleus_settings(cmd: &mut Command) -> &mut Command {
    cmd.arg("--setting-sources")
        .arg(SETTING_SOURCES)
        .arg("--strict-mcp-config")
}

/// The settings document that registers the mediation hook, as a type.
///
/// Opaque on purpose. The shape is FAIL-OPEN — the nested `hooks` array is
/// load-bearing, and an entry carrying `type` and `command` at the
/// matcher-group level registers NOTHING, with no error and no warning, while
/// every tool call proceeds unhooked (verified against the wrapped CLI at
/// 2.1.278). A launch site that builds this JSON itself can reintroduce that
/// silently, so there is no way to build one except the constructors below and
/// no way to spend one except [`HookSettings::write_to`].
///
/// Before this type the same guarantee was a `grep` in a unit test: the shape
/// lived in one function by convention, and a second author was caught by a
/// structural assertion rather than by the compiler. ADR 0007 C-1 — a type that
/// names evidence has a private constructor — read across to a document whose
/// wrongness is invisible.
#[must_use]
pub struct HookSettings(serde_json::Value);

impl HookSettings {
    /// Register `exe` as the `PreToolUse` hook for every tool (no matcher =
    /// all tools), with `args` appended to the command line.
    pub fn for_exe(exe: &Path, args: &[&str]) -> Self {
        let mut command = shell_quote(exe);
        for arg in args {
            command.push(' ');
            command.push_str(arg);
        }
        Self(serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "hooks": [{
                        "type": "command",
                        "command": command,
                    }]
                }]
            }
        }))
    }

    /// Register THIS binary's hidden hook subcommand.
    ///
    /// # Errors
    ///
    /// If the running executable's path cannot be resolved — without it the
    /// hook command line cannot be written, and a settings file naming no
    /// hook is the fail-open shape this type exists to prevent.
    pub fn for_self() -> Result<Self> {
        let self_exe = std::env::current_exe().context("resolving own executable for the hook")?;
        Ok(Self::for_exe(&self_exe, &[HOOK_SUBCOMMAND]))
    }

    /// Write the document into `dir` and return the path `--settings` takes.
    ///
    /// Consumes `self`: the document is written once, and there is no second
    /// use of a value whose whole purpose is to become that one file.
    ///
    /// # Errors
    ///
    /// If serialization or the write fails.
    pub fn write_to(self, dir: &Path, file_name: &str) -> Result<SettingsPath> {
        let path = dir.join(file_name);
        std::fs::write(&path, serde_json::to_string_pretty(&self.0)?)
            .with_context(|| format!("writing {}", path.display()))?;
        Ok(SettingsPath(path))
    }

    /// The document, for tests that assert its shape. `#[cfg(test)]`, so no
    /// production caller can reach the JSON and hand it somewhere else.
    #[cfg(test)]
    pub(crate) fn as_json(&self) -> &serde_json::Value {
        &self.0
    }
}

/// A path known to hold a [`HookSettings`] document.
///
/// The only thing a launch site may pass to `--settings`. Minted only by
/// [`HookSettings::write_to`], so an arbitrary path — or one holding a
/// hand-rolled document — cannot get there.
pub struct SettingsPath(PathBuf);

impl SettingsPath {
    /// The path, for the command line.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

/// Write the mediation hook's settings into `dir`.
///
/// The ordinary route for a launch site: build the document for this binary
/// and write it under the conventional name.
///
/// # Errors
///
/// As [`HookSettings::for_self`] and [`HookSettings::write_to`].
pub fn write_hook_settings(dir: &Path) -> Result<SettingsPath> {
    HookSettings::for_self()?.write_to(dir, "mediation-hook-settings.json")
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
        let s = HookSettings::for_exe(Path::new("/opt/nuc leus/nucleus"), &[HOOK_SUBCOMMAND]);
        let v = s.as_json();
        let entry = &v["hooks"]["PreToolUse"][0];
        assert!(entry.get("matcher").is_none(), "no matcher = every tool");
        let cmd = entry["hooks"][0]["command"].as_str().unwrap();
        assert_eq!(cmd, "'/opt/nuc leus/nucleus' mediation-hook");
        assert_eq!(entry["hooks"][0]["type"], "command");
    }

    const LAUNCH: &str = "Command::new(crate::constants::AGENT_CLI_BIN)";

    /// Every source region that builds one agent-CLI invocation: from the
    /// `Command::new` that starts it to whatever consumes it.
    ///
    /// Scoped per SITE rather than per file on purpose. The previous version of
    /// this pin asked whether the file mentioned the hook anywhere, which
    /// `run.rs` satisfied from its second launch site while its first one
    /// hand-rolled a settings document that registered nothing.
    fn launch_sites(src: &str) -> Vec<&str> {
        let mut sites = Vec::new();
        let mut rest = src;
        while let Some(start) = rest.find(LAUNCH) {
            let tail = &rest[start..];
            let end = [".output()", ".status()", ".spawn("]
                .iter()
                .filter_map(|t| tail.find(t).map(|i| i + t.len()))
                .min()
                .unwrap_or(tail.len());
            sites.push(&tail[..end]);
            rest = &tail[LAUNCH.len()..];
        }
        sites
    }

    fn all_launch_sites() -> Vec<(&'static str, &'static str)> {
        [
            ("run.rs", include_str!("run.rs")),
            ("shell.rs", include_str!("shell.rs")),
        ]
        .into_iter()
        .flat_map(|(name, src)| launch_sites(src).into_iter().map(move |s| (name, s)))
        .collect()
    }

    /// Structural pin: EVERY launch site confines the agent to the settings
    /// nucleus hands it. A site that omits this lets the working directory
    /// register its own hooks and MCP servers next to the mediating ones.
    ///
    /// No site count is asserted, so a fourth launch site is covered the day it
    /// is written rather than the day someone remembers to update a number.
    #[test]
    fn every_launch_site_confines_the_agent_to_nucleus_settings() {
        let sites = all_launch_sites();
        assert!(
            !sites.is_empty(),
            "no launch site found — this pin has gone stale"
        );
        for (name, site) in sites {
            let compact: String = site.split_whitespace().collect();
            assert!(
                compact.contains("crate::mediation::confine_to_nucleus_settings(&mutcmd)"),
                "{name}: a launch site does not confine the agent to nucleus's own \
                 settings, so the working directory can configure it:\n{site}"
            );
            assert!(
                compact.contains(".arg(\"--settings\")"),
                "{name}: a launch site installs no settings document:\n{site}"
            );
        }
    }

    /// A site that vets an MCP tool set must hand the SAME set to the hook that
    /// enforces it. Conditional because the hook-only mode grants no MCP tools
    /// at all; unconditional, it would read as covering a site it does not.
    #[test]
    fn a_site_that_grants_mcp_tools_tells_the_hook_which_ones() {
        let mut checked = 0;
        for (name, site) in all_launch_sites() {
            let compact: String = site.split_whitespace().collect();
            if !compact.contains(".arg(\"--allowedTools\")") {
                continue;
            }
            checked += 1;
            assert!(
                compact.contains(".env(crate::mediation::ALLOWED_TOOLS_ENV,"),
                "{name}: a launch site auto-approves MCP tools without telling \
                 the hook which ones, so the hook denies all of them:\n{site}"
            );
        }
        assert!(
            checked > 0,
            "no tool-granting launch site found (stale pin)"
        );
    }

    /// The document reaches disk with the nested array intact, and the path
    /// that comes back is the one `--settings` is given. A round trip, because
    /// the failure this type exists to prevent is invisible in the written
    /// file: a flat entry is valid JSON and registers nothing.
    #[test]
    fn the_written_document_keeps_the_nested_hooks_array() {
        let dir =
            std::env::temp_dir().join(format!("nucleus-hook-settings-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let written = HookSettings::for_exe(Path::new("/opt/hook"), &["run"])
            .write_to(&dir, "settings.json")
            .expect("write");
        let raw = std::fs::read_to_string(written.as_path()).expect("read back");
        let v: serde_json::Value = serde_json::from_str(&raw).expect("valid json");
        let group = &v["hooks"]["PreToolUse"][0];
        assert!(
            group.get("hooks").is_some(),
            "the nested array is what registers the hook: {raw}"
        );
        assert!(
            group.get("command").is_none(),
            "a command at the matcher-group level registers nothing"
        );
        assert_eq!(group["hooks"][0]["command"], "'/opt/hook' run");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The fail-open shape has exactly one author.
    ///
    /// A matcher-group entry carrying `type`/`command` without the nested
    /// `hooks` array registers NOTHING — no error, no warning, every tool call
    /// unhooked. A launch site that writes this JSON itself can reintroduce
    /// that silently, so the key may appear in this module only.
    #[test]
    fn no_launch_site_hand_rolls_the_hook_registration() {
        for (name, src) in [
            ("run.rs", include_str!("run.rs")),
            ("shell.rs", include_str!("shell.rs")),
        ] {
            assert!(
                !src.contains("\"PreToolUse\""),
                "{name}: builds a hook registration itself; call \
                 mediation::HookSettings instead"
            );
        }
    }

    #[test]
    fn the_registration_nests_the_hooks_array_and_quotes_the_path() {
        // The nested array is the load-bearing part: without it the CLI
        // registers no hook and does not say so.
        let s = HookSettings::for_exe(Path::new("/opt/nuc leus/hook"), &[]);
        let v = s.as_json();
        let group = &v["hooks"]["PreToolUse"][0];
        assert!(
            group.get("hooks").is_some(),
            "the nested hooks array is what registers the hook"
        );
        assert!(
            group.get("command").is_none(),
            "a command at the matcher-group level registers nothing"
        );
        assert_eq!(group["hooks"][0]["type"], "command");
        assert_eq!(
            group["hooks"][0]["command"].as_str().unwrap(),
            "'/opt/nuc leus/hook'",
            "the path is shell-quoted; the command line is run by a shell"
        );
        // And the self-registering form still agrees with it.
        assert_eq!(
            HookSettings::for_exe(Path::new("/opt/nucleus"), &[HOOK_SUBCOMMAND]).as_json()["hooks"]
                ["PreToolUse"][0]["hooks"][0]["command"]
                .as_str()
                .unwrap(),
            "'/opt/nucleus' mediation-hook"
        );
    }

    #[test]
    fn confinement_loads_no_implicit_settings_and_no_foreign_mcp_servers() {
        let mut cmd = Command::new("agent");
        confine_to_nucleus_settings(&mut cmd);
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            vec!["--setting-sources", "", "--strict-mcp-config"],
            "the confined agent reads no settings scope nucleus did not pass"
        );
        assert!(
            SETTING_SOURCES.is_empty(),
            "an implicit scope is ambient authority, including the operator's own"
        );
    }
}
