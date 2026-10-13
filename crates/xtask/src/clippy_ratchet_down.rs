//! `cargo xtask clippy-ratchet-down` — lower the clippy ceiling after a push to main.
//!
//! `.clippy-ratchet.toml` holds a ceiling on the ratcheted clippy count. The `check` job of
//! `clippy-ratchet.yml` refuses a PR that goes above it; this command is the other half, run on
//! every push to main, which proposes a LOWER ceiling once the tree measures below it, so the
//! count cannot drift back up into slack that a past cleanup bought.
//!
//! It replaces an inline `run:` block whose branching and arithmetic were shell. Two of that
//! block's defects were shell traps a type refuses:
//!
//! - `$(( ))` reads an empty operand as 0 silently, so a half-written ratchet file rewrote the
//!   ceiling to whatever the tree measured — which retires the ratchet rather than failing it.
//!   Here the file is deserialized into [`Ratchet`], whose fields are `u32` with no default: a
//!   missing, negative or non-integer value is an error.
//! - The ceiling-470 / step-5 / actual-466 case computed 465, a ceiling BELOW the real count.
//!   [`next_ceiling`] clamps to `actual` and its tests pin that case.
//!
//! ## Publishing needs a token, and its absence is not a failure
//!
//! `main` is protected and requires the merge queue, so the new ceiling has to travel as a PR.
//! The repository's default `GITHUB_TOKEN` cannot open one ("GitHub Actions is not permitted to
//! create or approve pull requests"), and a PR it did open would never trigger `pull_request`
//! workflows, so its required checks would never start and auto-merge would wait forever. That
//! is how ten `chore/clippy-ratchet-*` branches were orphaned and this job was red on every
//! drop. So: with `CLIPPY_RATCHET_TOKEN` (a fine-grained PAT or App token with contents +
//! pull-requests write) the command opens and auto-merges the PR; without it the command
//! REPORTS the decision (`::notice::` and the step summary) and touches nothing — not the file,
//! not a branch, not a PR. [`act`] takes the command runner as a parameter so a test can prove
//! the no-token path runs no command at all.
//!
//! Usage: `cargo xtask clippy-ratchet-down [--actual N]`. Without `--actual` the count is
//! measured by `scripts/check-clippy-ratchet.sh --count` — the same measurement the `check` job
//! gates on, so the two cannot disagree about what "the count" is.

use std::fmt;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;

const RATCHET_FILE: &str = ".clippy-ratchet.toml";
const MEASURE_SCRIPT: &str = "scripts/check-clippy-ratchet.sh";
const TOKEN_VAR: &str = "CLIPPY_RATCHET_TOKEN";

/// The three numbers this command decides from. No `Default`, no `#[serde(default)]`: a field
/// that is absent is an error, never 0 (ADR 0007 B-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct Ratchet {
    pub ceiling: u32,
    pub target: u32,
    pub step: u32,
}

pub fn parse_ratchet(text: &str) -> Result<Ratchet> {
    toml::from_str(text).with_context(|| {
        format!(
            "{RATCHET_FILE}: `ceiling`, `target` and `step` must each be a non-negative integer"
        )
    })
}

/// What the ceiling should become.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The tree is not below the ceiling (or the target forbids going lower): nothing to do.
    Unchanged { ceiling: u32, actual: u32 },
    /// The ceiling can drop from `from` to `to`; `to` is never below `actual` or the target.
    Lower { from: u32, to: u32, actual: u32 },
}

/// The ratchet step, with the clamps the shell job had:
///
/// 1. step down: `ceiling - step`, saturating at 0 rather than wrapping;
/// 2. snap to `actual` when the code is already better than the step;
/// 3. never below `actual` — a ceiling below the real count is the configuration the
///    `ratchet-falsifier` job proves goes red, so proposing one breaks every later PR;
/// 4. never below `target`.
///
/// Clamps 2 and 3 together put the proposal at `max(actual, target)` whenever it moves at all,
/// so `step` does not change the result today. That is the shell job's behaviour carried over
/// unchanged (a gate is not altered silently in a port); it is kept as an operand so the
/// file's declared semantics and this function stay one decider.
pub fn next_ceiling(r: Ratchet, actual: u32) -> Decision {
    let stepped = r.ceiling.saturating_sub(r.step);
    let snapped = stepped.min(actual);
    let not_below_actual = snapped.max(actual);
    let proposed = not_below_actual.max(r.target);
    if proposed >= r.ceiling {
        Decision::Unchanged {
            ceiling: r.ceiling,
            actual,
        }
    } else {
        Decision::Lower {
            from: r.ceiling,
            to: proposed,
            actual,
        }
    }
}

/// Rewrite ONLY the `ceiling = N` line, preserving every comment, blank line and line ending.
///
/// Line-precise rather than a TOML re-serialization because the file is mostly prose: a
/// round-trip through a serializer would drop it. Exactly one top-level `ceiling =` line must
/// match (a commented-out `# ceiling = ...` does not), and the result is parsed back and must
/// carry the new ceiling with `target` and `step` untouched — the typed value is the check,
/// not the text edit.
pub fn rewrite_ceiling(text: &str, new: u32) -> Result<String> {
    let before = parse_ratchet(text)?;
    let mut out = String::with_capacity(text.len());
    let mut matched = 0usize;
    for line in text.split_inclusive('\n') {
        let (body, ending) = split_ending(line);
        match ceiling_line_tail(body) {
            Some(tail) => {
                matched += 1;
                out.push_str("ceiling = ");
                out.push_str(&new.to_string());
                out.push_str(tail);
                out.push_str(ending);
            }
            None => out.push_str(line),
        }
    }
    ensure!(
        matched == 1,
        "{RATCHET_FILE}: expected exactly one `ceiling = <n>` line, found {matched}"
    );
    let after = parse_ratchet(&out)?;
    ensure!(
        after
            == Ratchet {
                ceiling: new,
                target: before.target,
                step: before.step,
            },
        "{RATCHET_FILE}: rewriting the ceiling line produced {after:?}, not ceiling {new} \
         with the rest of {before:?} unchanged"
    );
    Ok(out)
}

fn split_ending(line: &str) -> (&str, &str) {
    if let Some(body) = line.strip_suffix("\r\n") {
        (body, "\r\n")
    } else if let Some(body) = line.strip_suffix('\n') {
        (body, "\n")
    } else {
        (line, "")
    }
}

/// For a top-level `ceiling = <digits>[ # comment]` line, the part after the digits (kept
/// verbatim); `None` for every other line.
fn ceiling_line_tail(body: &str) -> Option<&str> {
    let rest = body.strip_prefix("ceiling")?;
    let rest = rest.trim_start_matches([' ', '\t']).strip_prefix('=')?;
    let rest = rest.trim_start_matches([' ', '\t']);
    let digits = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    if digits == 0 {
        return None;
    }
    rest.get(digits..)
}

/// Whether this run may publish. Read once, from the environment, at the edge.
pub enum Publisher {
    Token(Secret),
    NoToken,
}

/// A credential that never prints.
pub struct Secret(String);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl Publisher {
    fn from_env() -> Result<Self> {
        match std::env::var(TOKEN_VAR) {
            Ok(v) if v.is_empty() => Ok(Self::NoToken),
            Ok(v) => Ok(Self::Token(Secret(v))),
            Err(std::env::VarError::NotPresent) => Ok(Self::NoToken),
            Err(e @ std::env::VarError::NotUnicode(_)) => {
                Err(e).with_context(|| format!("{TOKEN_VAR} is set but not valid UTF-8"))
            }
        }
    }
}

/// One external command. `secret`, when set, is replaced by `***` wherever the command is
/// displayed, so an error message cannot leak the token embedded in the remote URL.
pub struct Cmd {
    pub program: &'static str,
    pub args: Vec<String>,
    pub env: Vec<(&'static str, String)>,
    secret: Option<String>,
}

impl Cmd {
    fn new(program: &'static str, args: &[&str]) -> Self {
        Self {
            program,
            args: args.iter().map(|a| (*a).to_string()).collect(),
            env: Vec::new(),
            secret: None,
        }
    }
}

impl fmt::Display for Cmd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = self.program.to_string();
        for a in &self.args {
            s.push(' ');
            s.push_str(a);
        }
        if let Some(secret) = &self.secret {
            s = s.replace(secret.as_str(), "***");
        }
        f.write_str(&s)
    }
}

/// Runs a command in the repository root and returns its stdout; a non-zero exit is an error.
pub trait Runner {
    fn run(&mut self, cmd: &Cmd) -> Result<String>;
}

struct ProcessRunner {
    root: PathBuf,
}

impl Runner for ProcessRunner {
    fn run(&mut self, cmd: &Cmd) -> Result<String> {
        let out = Command::new(cmd.program)
            .args(&cmd.args)
            .envs(cmd.env.iter().map(|(k, v)| (*k, v.as_str())))
            .current_dir(&self.root)
            .stdin(Stdio::null())
            .stderr(Stdio::inherit())
            .output()
            .with_context(|| format!("could not start `{cmd}`"))?;
        if !out.status.success() {
            bail!("`{cmd}` failed: {}", out.status);
        }
        String::from_utf8(out.stdout).with_context(|| format!("`{cmd}` printed non-UTF-8"))
    }
}

/// The measured count, from the same script the `check` job gates on.
fn measure(runner: &mut dyn Runner) -> Result<u32> {
    let out = runner.run(&Cmd::new(MEASURE_SCRIPT, &["--count"]))?;
    let actual: u32 = out
        .trim()
        .parse()
        .with_context(|| format!("`{MEASURE_SCRIPT} --count` printed {out:?}, not a count"))?;
    // The `check` job refuses a 0 for the same reason: this workspace cannot honestly measure
    // it, so a 0 is a clippy run that produced no countable output. Ratcheting to it would
    // set the ceiling to the target and red every later PR.
    ensure!(
        actual != 0,
        "`{MEASURE_SCRIPT} --count` reported 0, which is a broken measurement, not a clean tree"
    );
    Ok(actual)
}

/// What the run did. Every arm is a successful exit; failures are `Err`.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Unchanged {
        ceiling: u32,
        actual: u32,
    },
    /// The ceiling can drop, but no publishing token was supplied: reported, nothing written.
    Reported {
        from: u32,
        to: u32,
        actual: u32,
    },
    /// A PR for this exact ceiling is already open.
    AlreadyOpen {
        from: u32,
        to: u32,
        branch: String,
    },
    Published {
        from: u32,
        to: u32,
        actual: u32,
        branch: String,
    },
}

/// Where the run is: the repository root, the `owner/name` slug (only needed to publish), and
/// the step-summary file (when the runner provides one).
pub struct Site<'a> {
    pub root: &'a Path,
    pub repository: Option<&'a str>,
    pub summary: Option<&'a Path>,
}

pub fn act(
    decision: Decision,
    ratchet_text: &str,
    publisher: Publisher,
    runner: &mut dyn Runner,
    site: &Site<'_>,
) -> Result<Outcome> {
    let outcome = match (decision, publisher) {
        (Decision::Unchanged { ceiling, actual }, Publisher::NoToken | Publisher::Token(_)) => {
            Outcome::Unchanged { ceiling, actual }
        }
        (Decision::Lower { from, to, actual }, Publisher::NoToken) => {
            Outcome::Reported { from, to, actual }
        }
        (Decision::Lower { from, to, actual }, Publisher::Token(token)) => {
            match publish(from, to, actual, ratchet_text, &token, runner, site)? {
                Published::AlreadyOpen { branch } => Outcome::AlreadyOpen { from, to, branch },
                Published::Opened { branch } => Outcome::Published {
                    from,
                    to,
                    actual,
                    branch,
                },
            }
        }
    };
    announce(&outcome, site.summary)?;
    Ok(outcome)
}

/// Say what happened on stdout and, when the runner provides one, in the step summary.
fn announce(outcome: &Outcome, summary: Option<&Path>) -> Result<()> {
    let (stdout, section) = match outcome {
        Outcome::Unchanged { ceiling, actual } => (
            format!("clippy ceiling {ceiling} stays (actual {actual}): nothing to lower"),
            None,
        ),
        Outcome::Reported { from, to, actual } => {
            let msg = format!(
                "clippy ceiling can drop {from} -> {to} (actual {actual}); \
                 no {TOKEN_VAR}, so not publishing"
            );
            let section = format!(
                "{msg}.\n\nTo publish automatically, add a `{TOKEN_VAR}` secret (fine-grained \
                 PAT or App token with contents + pull-requests write). Until then, lower \
                 `ceiling` in `{RATCHET_FILE}` to {to} by hand.\n"
            );
            (format!("::notice::{msg}"), Some(section))
        }
        Outcome::AlreadyOpen { from, to, branch } => {
            let msg = format!("clippy ceiling {from} -> {to}: a PR for `{branch}` is already open");
            (msg.clone(), Some(format!("{msg}.\n")))
        }
        Outcome::Published {
            from,
            to,
            actual,
            branch,
        } => {
            let msg = format!("clippy ceiling {from} -> {to} (actual {actual}): opened `{branch}`");
            (msg.clone(), Some(format!("{msg}.\n")))
        }
    };
    println!("{stdout}");
    match (section, summary) {
        (Some(section), Some(path)) => {
            append_summary(path, &format!("### Clippy ratchet\n\n{section}"))
        }
        (None, _) | (Some(_), None) => Ok(()),
    }
}

/// What [`publish`] did.
enum Published {
    AlreadyOpen { branch: String },
    Opened { branch: String },
}

fn publish(
    from: u32,
    to: u32,
    actual: u32,
    ratchet_text: &str,
    token: &Secret,
    runner: &mut dyn Runner,
    site: &Site<'_>,
) -> Result<Published> {
    let repository = site.repository.with_context(|| {
        format!("{TOKEN_VAR} is set but GITHUB_REPOSITORY is not; cannot name the push target")
    })?;
    let branch = format!("chore/clippy-ratchet-{to}");
    let gh = |args: &[&str]| {
        let mut c = Cmd::new("gh", args);
        c.env.push(("GH_TOKEN", token.0.clone()));
        c.secret = Some(token.0.clone());
        c
    };

    let open = runner.run(&gh(&[
        "pr", "list", "--head", &branch, "--state", "open", "--json", "number", "--jq", "length",
    ]))?;
    let open: u32 = open
        .trim()
        .parse()
        .with_context(|| format!("`gh pr list` printed {open:?}, not a count"))?;
    if open != 0 {
        return Ok(Published::AlreadyOpen { branch });
    }

    // Rewrite before touching git, so an unrewritable file stops the run with nothing pushed.
    let rewritten = rewrite_ceiling(ratchet_text, to)?;
    let path = site.root.join(RATCHET_FILE);
    std::fs::write(&path, rewritten).with_context(|| format!("writing {}", path.display()))?;

    let git = |args: &[&str]| Cmd::new("git", args);
    runner.run(&git(&["config", "user.name", "github-actions[bot]"]))?;
    runner.run(&git(&[
        "config",
        "user.email",
        "41898282+github-actions[bot]@users.noreply.github.com",
    ]))?;
    runner.run(&git(&["checkout", "-B", &branch]))?;
    runner.run(&git(&["add", RATCHET_FILE]))?;
    runner.run(&git(&[
        "commit",
        "-m",
        &format!("chore(clippy-ratchet): ceiling {from} -> {to} (actual {actual})"),
    ]))?;
    // Authenticate the push explicitly instead of relying on the credential actions/checkout
    // left behind. That one is wired with `includeIf.gitdir`, which matches on the PATH the git
    // directory is reached by -- and the runner entrypoint symlinks /home/runner/_work onto the
    // mounted volume, so the workspace has two names and the push resolved the one the
    // credential was not written for: `fatal: could not read Username for
    // 'https://github.com'`, 34 runs in a row. `x-access-token` is the user name GitHub
    // accepts for a token in a URL.
    let mut set_url = git(&[
        "remote",
        "set-url",
        "origin",
        &format!(
            "https://x-access-token:{}@github.com/{repository}.git",
            token.0
        ),
    ]);
    set_url.secret = Some(token.0.clone());
    runner.run(&set_url)?;
    // Force: the branch is bot-owned and single-commit. When an earlier run pushed it but never
    // got its PR open (or the PR was closed), the branch outlives the PR and a plain push is
    // rejected with "fetch first" on EVERY later push to main -- which is how this job was red
    // for a full day with orphaned chore/clippy-ratchet-* branches.
    runner.run(&git(&["push", "-f", "-u", "origin", &branch]))?;

    runner.run(&gh(&[
        "pr",
        "create",
        "--base",
        "main",
        "--head",
        &branch,
        "--title",
        &format!("chore(clippy-ratchet): ceiling {from} -> {to}"),
        "--body",
        &format!(
            "Automated ratchet step. Measured violation count on linux CI is **{actual}**; \
             the ceiling drops {from} -> {to}. The ceiling is never set below actual."
        ),
    ]))?;
    // With a real token the PR runs CI like any other, so a refused auto-merge is a real
    // failure, not the GITHUB_TOKEN limitation the shell job used to warn past.
    runner.run(&gh(&["pr", "merge", "--auto", "--squash", &branch]))?;
    Ok(Published::Opened { branch })
}

fn append_summary(path: &Path, text: &str) -> Result<()> {
    use std::io::Seek as _;
    // Not `OpenOptions::append`: ADR 0007 G-1 reserves that for record logs (clippy.toml), and
    // this is the runner's markdown summary. Seek to the end and write the section in one call.
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(path)
        .with_context(|| format!("opening step summary {}", path.display()))?;
    f.seek(std::io::SeekFrom::End(0))
        .with_context(|| format!("seeking to the end of step summary {}", path.display()))?;
    f.write_all(text.as_bytes())
        .with_context(|| format!("writing step summary {}", path.display()))
}

pub fn run(root: &Path, actual: Option<u32>) -> Result<()> {
    let path = root.join(RATCHET_FILE);
    let text =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let ratchet = parse_ratchet(&text)?;
    let publisher = Publisher::from_env()?;
    let mut runner = ProcessRunner {
        root: root.to_path_buf(),
    };
    let actual = match actual {
        Some(n) => n,
        None => measure(&mut runner)?,
    };
    let decision = next_ceiling(ratchet, actual);
    let repository = std::env::var("GITHUB_REPOSITORY").ok();
    let summary = std::env::var_os("GITHUB_STEP_SUMMARY").map(PathBuf::from);
    let site = Site {
        root,
        repository: repository.as_deref(),
        summary: summary.as_deref(),
    };
    act(decision, &text, publisher, &mut runner, &site).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(ceiling: u32, target: u32, step: u32) -> Ratchet {
        Ratchet {
            ceiling,
            target,
            step,
        }
    }

    const FIXTURE: &str = "# Clippy ratchet: prose.\n\
        #\n\
        # ceiling = 1 in a comment is not the ceiling\n\
        lints = [\n  \"clippy::cast_lossless\",\n]\n\
        \n\
        # More prose.\n\
        ceiling = 345\n\
        target = 0\n\
        step = 5\n";

    // ---- next_ceiling ----

    #[test]
    fn never_below_actual_the_470_case() {
        // The shell job's defect: 470 - 5 = 465, below the real 466.
        assert_eq!(
            next_ceiling(r(470, 0, 5), 466),
            Decision::Lower {
                from: 470,
                to: 466,
                actual: 466
            }
        );
    }

    #[test]
    fn actual_above_ceiling_is_unchanged() {
        assert_eq!(
            next_ceiling(r(345, 0, 5), 350),
            Decision::Unchanged {
                ceiling: 345,
                actual: 350
            }
        );
    }

    #[test]
    fn equal_actual_is_unchanged() {
        assert_eq!(
            next_ceiling(r(345, 0, 5), 345),
            Decision::Unchanged {
                ceiling: 345,
                actual: 345
            }
        );
    }

    #[test]
    fn target_clamps_the_drop() {
        assert_eq!(
            next_ceiling(r(10, 8, 5), 2),
            Decision::Lower {
                from: 10,
                to: 8,
                actual: 2
            }
        );
        // A target at the ceiling forbids any drop.
        assert_eq!(
            next_ceiling(r(10, 10, 5), 2),
            Decision::Unchanged {
                ceiling: 10,
                actual: 2
            }
        );
    }

    #[test]
    fn step_larger_than_ceiling_saturates() {
        assert_eq!(
            next_ceiling(r(3, 0, 10), 1),
            Decision::Lower {
                from: 3,
                to: 1,
                actual: 1
            }
        );
        assert_eq!(
            next_ceiling(r(3, 0, u32::MAX), 3),
            Decision::Unchanged {
                ceiling: 3,
                actual: 3
            }
        );
    }

    #[test]
    fn code_better_than_the_step_snaps_to_actual() {
        assert_eq!(
            next_ceiling(r(345, 0, 5), 343),
            Decision::Lower {
                from: 345,
                to: 343,
                actual: 343
            }
        );
        assert_eq!(
            next_ceiling(r(345, 0, 5), 300),
            Decision::Lower {
                from: 345,
                to: 300,
                actual: 300
            }
        );
    }

    // ---- parsing ----

    #[test]
    fn parses_the_fixture() {
        assert_eq!(parse_ratchet(FIXTURE).unwrap(), r(345, 0, 5));
    }

    #[test]
    fn a_missing_field_is_an_error_not_zero() {
        assert!(parse_ratchet("ceiling = 345\nstep = 5\n").is_err());
        assert!(parse_ratchet("target = 0\nstep = 5\n").is_err());
    }

    #[test]
    fn a_non_integer_or_negative_field_is_an_error() {
        assert!(parse_ratchet("ceiling = \"345\"\ntarget = 0\nstep = 5\n").is_err());
        assert!(parse_ratchet("ceiling = 345.0\ntarget = 0\nstep = 5\n").is_err());
        assert!(parse_ratchet("ceiling = -1\ntarget = 0\nstep = 5\n").is_err());
        assert!(parse_ratchet("ceiling = \ntarget = 0\nstep = 5\n").is_err());
    }

    // ---- rewrite ----

    #[test]
    fn rewrite_changes_exactly_the_ceiling_line() {
        let out = rewrite_ceiling(FIXTURE, 343).unwrap();
        let before: Vec<&str> = FIXTURE.lines().collect();
        let after: Vec<&str> = out.lines().collect();
        assert_eq!(before.len(), after.len());
        let changed: Vec<(usize, &str)> = before
            .iter()
            .zip(&after)
            .enumerate()
            .filter(|(_, (b, a))| b != a)
            .map(|(i, (_, a))| (i, *a))
            .collect();
        assert_eq!(changed, vec![(8, "ceiling = 343")]);
        assert!(out.ends_with('\n'));
        assert_eq!(parse_ratchet(&out).unwrap(), r(343, 0, 5));
    }

    #[test]
    fn rewrite_keeps_a_trailing_comment_and_crlf() {
        let text = "ceiling = 345 # pinned\r\ntarget = 0\r\nstep = 5\r\n";
        assert_eq!(
            rewrite_ceiling(text, 340).unwrap(),
            "ceiling = 340 # pinned\r\ntarget = 0\r\nstep = 5\r\n"
        );
    }

    #[test]
    fn rewrite_refuses_when_no_line_matches() {
        // Valid TOML, ceiling present, but not as a top-level `ceiling = <n>` line the edit
        // can address: refusing is right, guessing is not.
        let text = "\"ceiling\" = 345\ntarget = 0\nstep = 5\n";
        assert!(rewrite_ceiling(text, 340).is_err());
    }

    // ---- act ----

    /// Records every command; answers `gh pr list` with `open_prs`.
    struct Recorder {
        calls: Vec<String>,
        open_prs: &'static str,
    }

    impl Runner for Recorder {
        fn run(&mut self, cmd: &Cmd) -> Result<String> {
            self.calls.push(cmd.to_string());
            if cmd.program == "gh"
                && cmd.args.first().map(String::as_str) == Some("pr")
                && cmd.args.get(1).map(String::as_str) == Some("list")
            {
                return Ok(format!("{}\n", self.open_prs));
            }
            Ok(String::new())
        }
    }

    fn lower() -> Decision {
        Decision::Lower {
            from: 345,
            to: 343,
            actual: 343,
        }
    }

    #[test]
    fn no_token_runs_no_command_and_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(RATCHET_FILE), FIXTURE).unwrap();
        let summary = dir.path().join("summary.md");
        let mut rec = Recorder {
            calls: Vec::new(),
            open_prs: "0",
        };
        let site = Site {
            root: dir.path(),
            repository: Some("owner/repo"),
            summary: Some(summary.as_path()),
        };
        let out = act(lower(), FIXTURE, Publisher::NoToken, &mut rec, &site).unwrap();
        assert_eq!(
            out,
            Outcome::Reported {
                from: 345,
                to: 343,
                actual: 343
            }
        );
        assert!(rec.calls.is_empty(), "ran {:?}", rec.calls);
        assert_eq!(
            std::fs::read_to_string(dir.path().join(RATCHET_FILE)).unwrap(),
            FIXTURE
        );
        let s = std::fs::read_to_string(&summary).unwrap();
        assert!(s.contains("345 -> 343 (actual 343)"), "{s}");
    }

    #[test]
    fn unchanged_runs_no_command_even_with_a_token() {
        let dir = tempfile::tempdir().unwrap();
        let mut rec = Recorder {
            calls: Vec::new(),
            open_prs: "0",
        };
        let site = Site {
            root: dir.path(),
            repository: Some("owner/repo"),
            summary: None,
        };
        let d = Decision::Unchanged {
            ceiling: 345,
            actual: 345,
        };
        let out = act(
            d,
            FIXTURE,
            Publisher::Token(Secret("test-token-123".into())),
            &mut rec,
            &site,
        )
        .unwrap();
        assert_eq!(
            out,
            Outcome::Unchanged {
                ceiling: 345,
                actual: 345
            }
        );
        assert!(rec.calls.is_empty(), "ran {:?}", rec.calls);
    }

    #[test]
    fn token_publishes_in_order_and_never_prints_the_token() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(RATCHET_FILE), FIXTURE).unwrap();
        let mut rec = Recorder {
            calls: Vec::new(),
            open_prs: "0",
        };
        let site = Site {
            root: dir.path(),
            repository: Some("owner/repo"),
            summary: None,
        };
        let out = act(
            lower(),
            FIXTURE,
            Publisher::Token(Secret("test-token-123".into())),
            &mut rec,
            &site,
        )
        .unwrap();
        assert_eq!(
            out,
            Outcome::Published {
                from: 345,
                to: 343,
                actual: 343,
                branch: "chore/clippy-ratchet-343".into()
            }
        );
        let heads: Vec<String> = rec
            .calls
            .iter()
            .map(|c| c.split(' ').take(3).collect::<Vec<_>>().join(" "))
            .collect();
        assert_eq!(
            heads,
            [
                "gh pr list",
                "git config user.name",
                "git config user.email",
                "git checkout -B",
                "git add .clippy-ratchet.toml",
                "git commit -m",
                "git remote set-url",
                "git push -f",
                "gh pr create",
                "gh pr merge",
            ]
        );
        assert!(
            rec.calls.iter().all(|c| !c.contains("test-token-123")),
            "{:?}",
            rec.calls
        );
        assert!(rec.calls[6].contains("https://x-access-token:***@github.com/owner/repo.git"));
        let written = std::fs::read_to_string(dir.path().join(RATCHET_FILE)).unwrap();
        assert_eq!(parse_ratchet(&written).unwrap(), r(343, 0, 5));
    }

    #[test]
    fn an_open_pr_stops_before_any_write() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(RATCHET_FILE), FIXTURE).unwrap();
        let mut rec = Recorder {
            calls: Vec::new(),
            open_prs: "1",
        };
        let site = Site {
            root: dir.path(),
            repository: Some("owner/repo"),
            summary: None,
        };
        let out = act(
            lower(),
            FIXTURE,
            Publisher::Token(Secret("test-token-123".into())),
            &mut rec,
            &site,
        )
        .unwrap();
        assert_eq!(
            out,
            Outcome::AlreadyOpen {
                from: 345,
                to: 343,
                branch: "chore/clippy-ratchet-343".into()
            }
        );
        assert_eq!(rec.calls.len(), 1);
        assert_eq!(
            std::fs::read_to_string(dir.path().join(RATCHET_FILE)).unwrap(),
            FIXTURE
        );
    }

    #[test]
    fn an_unreadable_pr_count_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut rec = Recorder {
            calls: Vec::new(),
            open_prs: "",
        };
        let site = Site {
            root: dir.path(),
            repository: Some("owner/repo"),
            summary: None,
        };
        assert!(
            act(
                lower(),
                FIXTURE,
                Publisher::Token(Secret("test-token-123".into())),
                &mut rec,
                &site,
            )
            .is_err()
        );
    }

    #[test]
    fn a_failing_command_fails_the_run() {
        struct FailPush(Vec<String>);
        impl Runner for FailPush {
            fn run(&mut self, cmd: &Cmd) -> Result<String> {
                self.0.push(cmd.to_string());
                if cmd.args.first().map(String::as_str) == Some("push") {
                    bail!("push rejected");
                }
                Ok("0".into())
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let mut runner = FailPush(Vec::new());
        let site = Site {
            root: dir.path(),
            repository: Some("owner/repo"),
            summary: None,
        };
        assert!(
            act(
                lower(),
                FIXTURE,
                Publisher::Token(Secret("test-token-123".into())),
                &mut runner,
                &site,
            )
            .is_err()
        );
        assert!(
            runner.0.iter().all(|c| !c.starts_with("gh pr create")),
            "no PR after a failed push: {:?}",
            runner.0
        );
    }

    #[test]
    fn measure_refuses_zero_and_garbage() {
        struct Says(&'static str);
        impl Runner for Says {
            fn run(&mut self, _: &Cmd) -> Result<String> {
                Ok(self.0.into())
            }
        }
        assert_eq!(measure(&mut Says("343\n")).unwrap(), 343);
        assert!(measure(&mut Says("0\n")).is_err());
        assert!(measure(&mut Says("")).is_err());
        assert!(measure(&mut Says("warning: x\n343\n")).is_err());
    }
}
