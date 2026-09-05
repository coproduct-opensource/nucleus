//! `mcp-guard` — Trifecta Gate CLI. See what your AI agent can exfiltrate.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use nucleus_mcp_guard::{Classifier, ClassifierConfig, SessionMonitor, analyze_session, proxy};
use proxy::{GuardConfig, Mode};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Parser)]
#[command(
    name = "mcp-guard",
    about = "Trifecta Gate: see \u{2014} or stop \u{2014} what your AI agent can exfiltrate."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// Optional classifier-override config (JSON) — extend or replace the defaults.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Emit machine-readable JSON instead of the human report.
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Wrap a live stdio MCP server and observe the session. The server command
    /// and its args follow `--`, e.g. `mcp-guard proxy -- npx my-mcp-server`.
    Proxy {
        /// Report denied calls and forward them anyway instead of blocking.
        /// Blocking is the default (#2429); this is the assessment-mode opt-out.
        #[arg(long, conflicts_with = "enforce")]
        observe: bool,
        /// Accepted for compatibility: blocking is now the default, so this
        /// flag changes nothing. Hidden so new invocations do not learn it.
        #[arg(long, hide = true)]
        enforce: bool,
        /// Persist pinned tool schemas here (JSON). Without it a rug-pull can
        /// only be caught within a single session, which is not the threat:
        /// the attack is to be benign at approval time and mutate later.
        #[arg(long, value_name = "PATH")]
        pin_file: Option<PathBuf>,
        /// Project directory with `.nucleus/manifests/*.toml` (signed tool
        /// manifests, each pinning a descriptor `schema_hash`) and
        /// `.nucleus/trust/*.pub` (publisher keys). Every served tool must match
        /// a signed manifest or it is refused as MCP_TOOL_UNVERIFIED (#1637).
        /// Startup fails if the trust store has no keys.
        #[arg(long, value_name = "DIR")]
        manifests: Option<PathBuf>,
        #[arg(last = true, required = true, num_args = 1..)]
        server: Vec<String>,
    },
    /// Replay a recorded session offline and report. The session file is a JSON
    /// array of tool names (in call order), or `{"tools": [...]}`.
    Analyze { session: PathBuf },
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum SessionFile {
    List(Vec<String>),
    Obj { tools: Vec<String> },
}

/// The whole of what `--observe` gives up (#2434, #2429): presence of the
/// flag, and nothing else, selects [`Mode::Observe`]. Absence always resolves
/// to [`Mode::default`] ([`Mode::Enforce`]) — pinned so this boundary cannot
/// silently flip in either direction. The legacy `--enforce` flag is accepted
/// and ignored: it names the default.
fn mode_for_flag(observe: bool) -> Mode {
    if observe {
        Mode::Observe
    } else {
        Mode::default()
    }
}

fn load_classifier(path: &Option<PathBuf>) -> Result<Classifier> {
    match path {
        Some(p) => {
            let s = std::fs::read_to_string(p)
                .with_context(|| format!("reading classifier config {}", p.display()))?;
            let cfg: ClassifierConfig =
                serde_json::from_str(&s).context("parsing classifier config JSON")?;
            Ok(Classifier::from_config(&cfg))
        }
        None => Ok(Classifier::default()),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let classifier = load_classifier(&cli.config)?;

    let (report, protocol_on_stdout) = match cli.cmd {
        Cmd::Analyze { session } => {
            let s = std::fs::read_to_string(&session)
                .with_context(|| format!("reading session file {}", session.display()))?;
            let sf: SessionFile = serde_json::from_str(&s).context("parsing session file")?;
            let tools = match sf {
                SessionFile::List(v) => v,
                SessionFile::Obj { tools } => tools,
            };
            (analyze_session(&tools, classifier), false)
        }
        Cmd::Proxy {
            observe,
            enforce: _,
            pin_file,
            manifests,
            server,
        } => {
            let (cmd, args) = server.split_first().context("missing MCP server command")?;
            let monitor = Arc::new(Mutex::new(SessionMonitor::new(classifier)));
            let config = GuardConfig {
                mode: mode_for_flag(observe),
                pin_file,
                manifests,
            };
            let report = proxy::run_stdio_proxy_with(monitor, cmd, args, config).await?;
            (report, true) // stdout is the MCP channel — report must go to stderr
        }
    };

    let rendered = if cli.json {
        report.to_json()
    } else {
        report.render()
    };
    if protocol_on_stdout {
        eprintln!("{rendered}");
    } else {
        println!("{rendered}");
    }

    // Non-zero exit when exfiltration is possible, so CI / assessments can gate.
    if report.exfiltration_possible {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── #2434 / #2429: pin the enforce-by-default boundary ───────────────
    //
    // Two links in the chain from argv to blocking behavior, each pinned
    // independently so a regression in either can't hide behind the other:
    // `proxy.rs`'s own `enforce_blocks_where_observe_only_reports` already
    // pins that `Mode::Observe` never blocks and `Mode::Enforce` does; what
    // is pinned here is everything upstream of that — that omitting every
    // flag parses to `observe: false`, and that `false` resolves to `Enforce`.

    /// Link 1: `mode_for_flag` itself. Also verifies `Mode::Observe` is
    /// reachable at all — a test that only checked the false case would pass
    /// just as well if `--observe` did nothing.
    #[test]
    fn mode_for_flag_matches_the_boundary() {
        assert_eq!(mode_for_flag(false), Mode::Enforce);
        assert_eq!(mode_for_flag(true), Mode::Observe);
    }

    /// Link 2: the CLI parser. A bare `proxy` must parse to `observe: false`
    /// — the value `mode_for_flag` is called with. Without this, a clap
    /// default-value regression that flipped the flag's polarity would slip
    /// past `mode_for_flag_matches_the_boundary`, which never touches parsing.
    #[test]
    fn omitting_every_flag_parses_to_enforcing() {
        let cli = Cli::try_parse_from(["mcp-guard", "proxy", "--", "some-server"]).unwrap();
        match cli.cmd {
            Cmd::Proxy { observe, .. } => assert!(!observe, "default must be enforcing"),
            other => panic!("expected Cmd::Proxy, got {other:?}"),
        }
    }

    /// The control for the test above: the opt-out must still work when given.
    #[test]
    fn passing_observe_parses_to_non_enforcing() {
        let cli =
            Cli::try_parse_from(["mcp-guard", "proxy", "--observe", "--", "some-server"]).unwrap();
        match cli.cmd {
            Cmd::Proxy { observe, .. } => assert!(observe),
            other => panic!("expected Cmd::Proxy, got {other:?}"),
        }
    }

    /// Compatibility: the legacy `--enforce` still parses (and resolves to the
    /// default it names), and cannot be combined with `--observe`.
    #[test]
    fn legacy_enforce_flag_is_accepted_and_inert() {
        let cli =
            Cli::try_parse_from(["mcp-guard", "proxy", "--enforce", "--", "some-server"]).unwrap();
        match cli.cmd {
            Cmd::Proxy {
                observe, enforce, ..
            } => {
                assert!(enforce);
                assert!(!observe);
                assert_eq!(mode_for_flag(observe), Mode::Enforce);
            }
            other => panic!("expected Cmd::Proxy, got {other:?}"),
        }
        assert!(
            Cli::try_parse_from([
                "mcp-guard",
                "proxy",
                "--enforce",
                "--observe",
                "--",
                "some-server"
            ])
            .is_err(),
            "contradictory flags must not silently pick one"
        );
    }
}
