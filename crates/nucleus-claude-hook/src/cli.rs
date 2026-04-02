//! Structured CLI argument parsing for `nucleus-claude-hook`.
//!
//! Replaces hand-rolled `args.iter().any(…)` chains in `main()` with a typed
//! enum, enabling proper error messages for unknown flags and testable parsing.
//! No heavy dependencies (no clap) — just pattern matching.

use std::fmt;

/// Parsed CLI command.
#[derive(Debug, PartialEq)]
pub enum CliCommand {
    /// Default mode: read hook JSON from stdin.
    Hook,
    /// `--setup` — configure Claude Code settings.json.
    Setup,
    /// `--status` — show active sessions and configuration.
    /// When `json` is true, output machine-parseable JSON to stdout.
    Status { json: bool },
    /// `--help` / `-h` — print usage information.
    /// When `topic` is `Some`, print detailed help for that topic.
    Help { topic: Option<String> },
    /// `--version` / `-V` — print version string.
    Version,
    /// `--init` — scaffold `.nucleus/` project directory.
    Init,
    /// `--build [DIR] [-o FILE]` — build artifact from `.nucleus/`.
    Build,
    /// `--compartment-path <session-id>` — print compartment file path.
    CompartmentPath { session_id: String },
    /// `--reset-session <session-id>` — clear taint on a session.
    ResetSession { session_id: String },
    /// `--uninstall` — remove hook configuration.
    Uninstall,
    /// `--doctor` — run diagnostic checks.
    Doctor,
    /// `--smoke-test` — run a quick self-test.
    SmokeTest,
    /// `--gc` — garbage-collect stale sessions.
    Gc,
    /// `--show-profile [name]` — display a profile's capabilities.
    ShowProfile { name: Option<String> },
    /// `--receipts [session-id]` — view receipt chain.
    Receipts { session_id: Option<String> },
    /// `--completions <shell>` — print shell completion script.
    Completions { shell: String },
    /// `--exit-codes` — print exit code documentation.
    ExitCodes,
    /// `--benchmark [--iterations N]` — measure hook latency (#522).
    Benchmark { iterations: usize },
    /// `--statusline` — output a short status string for Claude Code's status line.
    StatusLine,
    /// `--compartment <name>` — switch the active compartment for the latest session.
    Compartment { name: String },
}

/// CLI parsing error.
#[derive(Debug, PartialEq)]
pub enum CliError {
    /// A flag that requires an argument was given without one.
    MissingArgument { flag: String, expected: String },
    /// An unrecognized flag was passed.
    UnknownFlag(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::MissingArgument { flag, expected } => {
                write!(f, "missing {expected} for {flag}")
            }
            CliError::UnknownFlag(flag) => {
                write!(
                    f,
                    "unknown flag: {flag}\nRun 'nucleus-claude-hook --help' for usage."
                )
            }
        }
    }
}

/// Parse CLI arguments into a [`CliCommand`].
///
/// `args` should be `std::env::args().collect()` — i.e. args\[0\] is the
/// binary name.  When no flags are present the default is [`CliCommand::Hook`]
/// (stdin mode).
pub fn parse_args(args: &[String]) -> Result<CliCommand, CliError> {
    // Skip argv[0] (the binary name).
    let args = &args[1..];

    if args.is_empty() {
        return Ok(CliCommand::Hook);
    }

    // We only inspect the first flag-like argument.  `--build` is special
    // because `run_build` re-parses the full argv for `-o`/dir arguments,
    // so we just need to recognise it here and let the existing code handle
    // the rest.
    let first = &args[0];

    match first.as_str() {
        "--setup" => Ok(CliCommand::Setup),
        "--status" => {
            let json = args.get(1).map(|a| a == "--json").unwrap_or(false);
            Ok(CliCommand::Status { json })
        }
        "--help" | "-h" => {
            let topic = args.get(1).cloned();
            Ok(CliCommand::Help { topic })
        }
        "--version" | "-V" => Ok(CliCommand::Version),
        "--init" => Ok(CliCommand::Init),
        "--build" => Ok(CliCommand::Build),
        "--uninstall" => Ok(CliCommand::Uninstall),
        "--doctor" => Ok(CliCommand::Doctor),
        "--smoke-test" => Ok(CliCommand::SmokeTest),
        "--gc" => Ok(CliCommand::Gc),
        "--compartment-path" => {
            let session_id = args.get(1).ok_or_else(|| CliError::MissingArgument {
                flag: "--compartment-path".into(),
                expected: "<session-id>".into(),
            })?;
            Ok(CliCommand::CompartmentPath {
                session_id: session_id.clone(),
            })
        }
        "--reset-session" => {
            let session_id = args.get(1).ok_or_else(|| CliError::MissingArgument {
                flag: "--reset-session".into(),
                expected: "<session-id>".into(),
            })?;
            Ok(CliCommand::ResetSession {
                session_id: session_id.clone(),
            })
        }
        "--show-profile" => {
            let name = args.get(1).cloned();
            Ok(CliCommand::ShowProfile { name })
        }
        "--receipts" => {
            let session_id = args.get(1).cloned();
            Ok(CliCommand::Receipts { session_id })
        }
        "--completions" => {
            let shell = args.get(1).ok_or_else(|| CliError::MissingArgument {
                flag: "--completions".into(),
                expected: "<shell> (bash|zsh|fish)".into(),
            })?;
            Ok(CliCommand::Completions {
                shell: shell.clone(),
            })
        }
        "--exit-codes" => Ok(CliCommand::ExitCodes),
        "--benchmark" => {
            let mut iterations = 100usize;
            if args.get(1).map(|a| a.as_str()) == Some("--iterations") {
                if let Some(n) = args.get(2).and_then(|s| s.parse().ok()) {
                    iterations = n;
                }
            }
            Ok(CliCommand::Benchmark { iterations })
        }
        "--statusline" => Ok(CliCommand::StatusLine),
        "--compartment" => {
            let name = args.get(1).ok_or_else(|| CliError::MissingArgument {
                flag: "--compartment".into(),
                expected: "<name> (research|draft|execute|breakglass:<reason>)".into(),
            })?;
            Ok(CliCommand::Compartment { name: name.clone() })
        }
        other if other.starts_with('-') => Err(CliError::UnknownFlag(other.to_string())),
        // No recognised flag — fall through to stdin hook mode.
        _ => Ok(CliCommand::Hook),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn args(slice: &[&str]) -> Vec<String> {
        std::iter::once("nucleus-claude-hook")
            .chain(slice.iter().copied())
            .map(String::from)
            .collect()
    }

    #[test]
    fn no_args_is_hook() {
        assert_eq!(parse_args(&args(&[])).unwrap(), CliCommand::Hook);
    }

    #[test]
    fn simple_flags() {
        assert_eq!(parse_args(&args(&["--setup"])).unwrap(), CliCommand::Setup);
        assert_eq!(
            parse_args(&args(&["--status"])).unwrap(),
            CliCommand::Status { json: false }
        );
        assert_eq!(
            parse_args(&args(&["--help"])).unwrap(),
            CliCommand::Help { topic: None }
        );
        assert_eq!(
            parse_args(&args(&["-h"])).unwrap(),
            CliCommand::Help { topic: None }
        );
        assert_eq!(
            parse_args(&args(&["--version"])).unwrap(),
            CliCommand::Version
        );
        assert_eq!(parse_args(&args(&["-V"])).unwrap(), CliCommand::Version);
        assert_eq!(parse_args(&args(&["--init"])).unwrap(), CliCommand::Init);
        assert_eq!(parse_args(&args(&["--build"])).unwrap(), CliCommand::Build);
        assert_eq!(
            parse_args(&args(&["--uninstall"])).unwrap(),
            CliCommand::Uninstall
        );
        assert_eq!(
            parse_args(&args(&["--doctor"])).unwrap(),
            CliCommand::Doctor
        );
        assert_eq!(
            parse_args(&args(&["--smoke-test"])).unwrap(),
            CliCommand::SmokeTest
        );
        assert_eq!(parse_args(&args(&["--gc"])).unwrap(), CliCommand::Gc);
    }

    #[test]
    fn status_json_flag() {
        assert_eq!(
            parse_args(&args(&["--status", "--json"])).unwrap(),
            CliCommand::Status { json: true }
        );
    }

    #[test]
    fn compartment_path_with_session() {
        assert_eq!(
            parse_args(&args(&["--compartment-path", "sess-42"])).unwrap(),
            CliCommand::CompartmentPath {
                session_id: "sess-42".into()
            }
        );
    }

    #[test]
    fn compartment_path_missing_session() {
        let err = parse_args(&args(&["--compartment-path"])).unwrap_err();
        assert_eq!(
            err,
            CliError::MissingArgument {
                flag: "--compartment-path".into(),
                expected: "<session-id>".into(),
            }
        );
    }

    #[test]
    fn reset_session_with_id() {
        assert_eq!(
            parse_args(&args(&["--reset-session", "abc"])).unwrap(),
            CliCommand::ResetSession {
                session_id: "abc".into()
            }
        );
    }

    #[test]
    fn reset_session_missing_id() {
        let err = parse_args(&args(&["--reset-session"])).unwrap_err();
        assert!(matches!(err, CliError::MissingArgument { .. }));
    }

    #[test]
    fn show_profile_with_name() {
        assert_eq!(
            parse_args(&args(&["--show-profile", "safe_pr_fixer"])).unwrap(),
            CliCommand::ShowProfile {
                name: Some("safe_pr_fixer".into())
            }
        );
    }

    #[test]
    fn show_profile_no_name() {
        assert_eq!(
            parse_args(&args(&["--show-profile"])).unwrap(),
            CliCommand::ShowProfile { name: None }
        );
    }

    #[test]
    fn receipts_with_session() {
        assert_eq!(
            parse_args(&args(&["--receipts", "sess-1"])).unwrap(),
            CliCommand::Receipts {
                session_id: Some("sess-1".into())
            }
        );
    }

    #[test]
    fn receipts_no_session() {
        assert_eq!(
            parse_args(&args(&["--receipts"])).unwrap(),
            CliCommand::Receipts { session_id: None }
        );
    }

    #[test]
    fn completions_with_shell() {
        assert_eq!(
            parse_args(&args(&["--completions", "bash"])).unwrap(),
            CliCommand::Completions {
                shell: "bash".into()
            }
        );
    }

    #[test]
    fn completions_missing_shell() {
        let err = parse_args(&args(&["--completions"])).unwrap_err();
        assert!(matches!(err, CliError::MissingArgument { .. }));
    }

    #[test]
    fn unknown_flag_error() {
        let err = parse_args(&args(&["--staus"])).unwrap_err();
        assert_eq!(err, CliError::UnknownFlag("--staus".into()));
        assert!(err.to_string().contains("unknown flag"));
        assert!(err.to_string().contains("--help"));
    }

    #[test]
    fn build_with_extra_args() {
        // --build passes through to run_build which re-parses for dir/-o
        assert_eq!(
            parse_args(&args(&["--build", ".", "-o", "out.json"])).unwrap(),
            CliCommand::Build
        );
    }

    #[test]
    fn exit_codes_flag() {
        assert_eq!(
            parse_args(&args(&["--exit-codes"])).unwrap(),
            CliCommand::ExitCodes
        );
    }

    #[test]
    fn benchmark_default() {
        assert_eq!(
            parse_args(&args(&["--benchmark"])).unwrap(),
            CliCommand::Benchmark { iterations: 100 }
        );
    }

    #[test]
    fn benchmark_with_iterations() {
        assert_eq!(
            parse_args(&args(&["--benchmark", "--iterations", "500"])).unwrap(),
            CliCommand::Benchmark { iterations: 500 }
        );
    }

    #[test]
    fn statusline_flag() {
        assert_eq!(
            parse_args(&args(&["--statusline"])).unwrap(),
            CliCommand::StatusLine
        );
    }

    #[test]
    fn compartment_with_name() {
        assert_eq!(
            parse_args(&args(&["--compartment", "research"])).unwrap(),
            CliCommand::Compartment {
                name: "research".into()
            }
        );
        assert_eq!(
            parse_args(&args(&["--compartment", "breakglass:prod outage"])).unwrap(),
            CliCommand::Compartment {
                name: "breakglass:prod outage".into()
            }
        );
    }

    #[test]
    fn compartment_missing_name() {
        let err = parse_args(&args(&["--compartment"])).unwrap_err();
        assert!(matches!(err, CliError::MissingArgument { .. }));
    }

    #[test]
    fn non_flag_arg_is_hook_mode() {
        // If someone accidentally passes a non-flag arg, treat as hook mode
        // (stdin will likely fail, but that's the existing behavior).
        assert_eq!(parse_args(&args(&["something"])).unwrap(), CliCommand::Hook);
    }

    #[test]
    fn help_with_topic() {
        assert_eq!(
            parse_args(&args(&["--help", "compartments"])).unwrap(),
            CliCommand::Help {
                topic: Some("compartments".into())
            }
        );
        assert_eq!(
            parse_args(&args(&["-h", "flow"])).unwrap(),
            CliCommand::Help {
                topic: Some("flow".into())
            }
        );
    }
}
