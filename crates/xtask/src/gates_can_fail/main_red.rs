//! "Main is red": a gate already red on this tree, measured on the merge base too.
//!
//! The probe's precondition is a GREEN gate: a gate red before anything is perturbed decides
//! nothing under perturbation, and the script that this replaces said so and FAILED. That is
//! right when the red is this change's. It is wrong when the red is main's: on 2026-10-02 one
//! pull request merged a red in a gate that is not itself required (`xtask scoreboard-ratchet`),
//! and from then on every merge group failed this required context with "already red BEFORE any
//! perturbation" -- the same sentence, charged to every unrelated change, and hiding whatever the
//! probes that did run had to say.
//!
//! So a pre-perturbation red is split, by MEASURING the base rather than assuming it:
//!
//! * red on the merge base too, with the same exit status: [`BaseVerdict::Red`] at the same
//!   code. Main's red. Reported (an annotation, once per gate) and not charged to this change;
//!   every other probe still runs and still fails the run.
//! * green on the merge base: this change turned it red. FAIL, naming the gate.
//! * red on the base with a DIFFERENT exit status: not the same red. FAIL.
//! * the gate does not exist on the base: this change brought it in red. FAIL.
//! * the base could not be evaluated: [`BaseVerdict::CouldNotEvaluate`]. "Could not look" is
//!   never "looked and it was red" (ADR 0007 A). FAIL.
//!
//! What the split cannot see, stated rather than left to be found: a change that adds a SECOND
//! violation to a gate main already has red leaves the exit status where it was and passes
//! here. That gate's own context is red on the change either way -- this harness only declines
//! to re-charge main's red to it -- and the gate's perturbation cannot be asked anything until
//! main is green, on any change.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use super::table::Generated;

/// What a gate concluded on the merge base. Four cases, and only one of them excuses a red.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BaseVerdict {
    Green,
    Red(i32),
    /// The gate is not on the base at all.
    Absent(String),
    /// The base could not be checked out, or the gate could not be run there.
    CouldNotEvaluate(String),
}

/// What a red on THIS tree means, given main's verdict.
#[derive(Debug, PartialEq, Eq)]
pub enum PreRed {
    /// Red on main with the same exit status: main's red, reported and not charged.
    MainIsRed { base_rc: i32 },
    /// Green on main: this change's regression.
    PrRegression,
    /// Red on main, but not the same red.
    DifferentRed { base_rc: i32 },
    /// Not on main: this change brought the gate in red.
    NewGate(String),
    /// Main's verdict is unknown, which is not a verdict.
    Unmeasured(String),
}

pub fn classify(rc: i32, base: &BaseVerdict) -> PreRed {
    match base {
        BaseVerdict::Red(b) if *b == rc => PreRed::MainIsRed { base_rc: *b },
        BaseVerdict::Red(b) => PreRed::DifferentRed { base_rc: *b },
        BaseVerdict::Green => PreRed::PrRegression,
        BaseVerdict::Absent(why) => PreRed::NewGate(why.clone()),
        BaseVerdict::CouldNotEvaluate(why) => PreRed::Unmeasured(why.clone()),
    }
}

/// The merge base, if this run has one to measure.
#[derive(Clone, Debug)]
pub enum MainRef {
    /// A full run (a push to main) or a fixture diff: there is no base. A red is charged, as
    /// it always was -- on a push to main that red IS the "main is red" report.
    NotApplicable,
    /// The resolved commit.
    Known(String),
    /// A base was named and cannot be read. `fetch` is a revision worth one shallow fetch.
    Unreadable { why: String, fetch: Option<String> },
}

/// Which program a gate is.
#[derive(Clone, Debug)]
pub enum Program {
    Script(&'static str),
    Xtask(&'static str),
}

/// One run of a gate: the program, its arguments, where, and with which target dir.
pub fn gate_command(
    program: &Program,
    args: &[String],
    cwd: &Path,
    target: Option<&Path>,
) -> Command {
    let mut cmd = match program {
        Program::Script(gate) => {
            let mut c = Command::new("bash");
            c.arg(format!("scripts/{gate}"));
            c
        }
        Program::Xtask(sub) => {
            let mut c = Command::new("cargo");
            c.args(["run", "-q", "-p", "xtask", "--", sub]);
            c
        }
    };
    cmd.args(args).current_dir(cwd);
    scrub_cargo_env(&mut cmd);
    if let Some(t) = target {
        cmd.env("CARGO_TARGET_DIR", t);
    }
    cmd
}

/// `cargo run` hands this process its own package's environment (`CARGO_MANIFEST_DIR`,
/// `CARGO_PKG_*`, the rustup toolchain it resolved). The script that this replaces ran each gate
/// from a plain shell, and a gate must see what it saw there -- in particular a base tree must
/// resolve its OWN `rust-toolchain.toml`, not inherit this one's.
fn scrub_cargo_env(cmd: &mut Command) {
    for (k, _) in std::env::vars_os() {
        let Some(k) = k.to_str() else { continue };
        let drop = k.starts_with("CARGO_PKG_")
            || matches!(
                k,
                "CARGO_MANIFEST_DIR"
                    | "CARGO_MANIFEST_PATH"
                    | "CARGO_CRATE_NAME"
                    | "CARGO_BIN_NAME"
                    | "CARGO_PRIMARY_PACKAGE"
                    | "RUSTUP_TOOLCHAIN"
            );
        if drop {
            cmd.env_remove(k);
        }
    }
}

/// Run quietly; the exit status as a shell reports it (128+N for a signal, 127 if it would not
/// start).
pub fn status_of(mut cmd: Command) -> i32 {
    match cmd.stdout(Stdio::null()).stderr(Stdio::null()).status() {
        Ok(s) => exit_code(s),
        Err(_) => 127,
    }
}

/// Run and keep the combined output.
pub fn output_of(mut cmd: Command) -> (i32, String) {
    match cmd.output() {
        Ok(o) => {
            let mut text = String::from_utf8_lossy(&o.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&o.stderr));
            (exit_code(o.status), text)
        }
        Err(e) => (127, e.to_string()),
    }
}

fn exit_code(s: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    s.code().unwrap_or_else(|| 128 + s.signal().unwrap_or(0))
}

/// How the base tree is asked whether a gate exists there.
pub enum Presence {
    Script(&'static str),
    Xtask(&'static str),
}

/// One question for the base: run this gate, with these flags (generated inputs written fresh
/// from the BASE tree, since that is what CI would have generated there).
pub struct BaseRequest {
    pub key: String,
    pub presence: Presence,
    pub program: Program,
    pub flags: String,
    pub generated: &'static [Generated],
}

/// A detached worktree of the merge base, outside the repository (a tree nested inside it would
/// be walked as repository content by every gate that walks), removed when dropped. Its builds
/// go to `target/gates-can-fail-base` under THIS tree, so a warm runner reuses the dependency
/// builds from one run to the next.
pub struct BaseTree {
    root: PathBuf,
    pub sha: String,
    tree: PathBuf,
    target: PathBuf,
    _dir: tempfile::TempDir,
}

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let o = Command::new("git")
        .args(args)
        .current_dir(root)
        .stderr(Stdio::null())
        .output()
        .ok()?;
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

/// Resolve a [`MainRef`] to a commit, fetching it once if it was named and is not here (a merge
/// group's base is deeper than the checkout when the group carries more than one change).
pub fn resolve(root: &Path, main: &MainRef) -> Result<String, String> {
    match main {
        MainRef::NotApplicable => Err("this run has no merge base".to_string()),
        MainRef::Known(sha) => Ok(sha.clone()),
        MainRef::Unreadable { why, fetch: None } => Err(why.clone()),
        MainRef::Unreadable {
            why,
            fetch: Some(rev),
        } => {
            let fetched = Command::new("git")
                .args(["fetch", "--no-tags", "--depth=1", "origin", rev])
                .current_dir(root)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
            if !fetched {
                return Err(format!("{why}, and `git fetch origin {rev}` failed"));
            }
            git(
                root,
                &["rev-parse", "--verify", "-q", &format!("{rev}^{{commit}}")],
            )
            .ok_or_else(|| format!("{why}, and {rev} is still not a commit after fetching it"))
        }
    }
}

impl BaseTree {
    pub fn create(root: &Path, sha: &str) -> Result<Self, String> {
        let dir = tempfile::Builder::new()
            .prefix("gates-can-fail-base.")
            .tempdir()
            .map_err(|e| format!("could not make a directory for the base tree: {e}"))?;
        let tree = dir.path().join("tree");
        let ok = Command::new("git")
            .args(["worktree", "add", "--detach", "--quiet"])
            .arg(&tree)
            .arg(sha)
            .current_dir(root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !ok {
            return Err(format!("`git worktree add {sha}` failed"));
        }
        Ok(Self {
            root: root.to_path_buf(),
            sha: sha.to_string(),
            tree,
            target: root.join("target/gates-can-fail-base"),
            _dir: dir,
        })
    }

    pub fn short(&self) -> &str {
        self.sha.get(..9).unwrap_or(&self.sha)
    }

    fn present(&self, presence: &Presence) -> Result<(), String> {
        match presence {
            Presence::Script(gate) => {
                if self.tree.join("scripts").join(gate).is_file() {
                    Ok(())
                } else {
                    Err(format!("scripts/{gate} is not on the merge base"))
                }
            }
            Presence::Xtask(sub) => {
                if super::wiring::xtask_domain(&self.tree).contains(*sub) {
                    Ok(())
                } else {
                    Err(format!("nothing on the merge base invokes xtask {sub}"))
                }
            }
        }
    }

    /// Run the gate on the base. The verdict and how long it took.
    pub fn verdict(&self, req: &BaseRequest) -> (BaseVerdict, f64) {
        let t0 = Instant::now();
        let v = self.verdict_inner(req);
        (v, t0.elapsed().as_secs_f64())
    }

    fn verdict_inner(&self, req: &BaseRequest) -> BaseVerdict {
        if let Err(why) = self.present(&req.presence) {
            return BaseVerdict::Absent(why);
        }
        let mut flags = req.flags.clone();
        let mut keep = Vec::new();
        for g in req.generated {
            let file = match tempfile::Builder::new()
                .prefix(&format!("{}-base.", g.temp.0))
                .suffix(g.temp.1)
                .tempfile()
            {
                Ok(f) => f,
                Err(e) => {
                    return BaseVerdict::CouldNotEvaluate(format!("no temp file: {e}"));
                }
            };
            if !(g.write)(&self.tree, file.path()) {
                return BaseVerdict::CouldNotEvaluate(format!(
                    "{} failed on the merge base",
                    g.gen_name
                ));
            }
            flags = flags.replacen(g.ci_name, &file.path().to_string_lossy(), 1);
            keep.push(file);
        }
        let args: Vec<String> = flags.split_whitespace().map(str::to_string).collect();
        let rc = status_of(gate_command(
            &req.program,
            &args,
            &self.tree,
            Some(&self.target),
        ));
        drop(keep);
        match rc {
            0 => BaseVerdict::Green,
            127 => BaseVerdict::CouldNotEvaluate(
                "the gate could not be started on the merge base (exit 127)".to_string(),
            ),
            rc => BaseVerdict::Red(rc),
        }
    }
}

impl Drop for BaseTree {
    fn drop(&mut self) {
        let _ = Command::new("git")
            .args(["worktree", "remove", "--force"])
            .arg(&self.tree)
            .current_dir(&self.root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_same_red_on_main_is_mains() {
        assert_eq!(
            classify(1, &BaseVerdict::Red(1)),
            PreRed::MainIsRed { base_rc: 1 }
        );
        assert_eq!(
            classify(1, &BaseVerdict::Red(2)),
            PreRed::DifferentRed { base_rc: 2 }
        );
        assert_eq!(classify(1, &BaseVerdict::Green), PreRed::PrRegression);
    }

    #[test]
    fn could_not_look_is_never_main_is_red() {
        // ADR 0007 A: the one case that must not collapse into the excused one.
        let got = classify(1, &BaseVerdict::CouldNotEvaluate("no base".into()));
        assert_eq!(got, PreRed::Unmeasured("no base".into()));
        let got = classify(1, &BaseVerdict::Absent("not there".into()));
        assert_eq!(got, PreRed::NewGate("not there".into()));
    }

    #[test]
    fn an_unreadable_base_with_nothing_to_fetch_is_an_error_not_a_verdict() {
        let r = resolve(
            Path::new("."),
            &MainRef::Unreadable {
                why: "no base revision was given".into(),
                fetch: None,
            },
        );
        assert_eq!(r, Err("no base revision was given".to_string()));
        assert!(resolve(Path::new("."), &MainRef::NotApplicable).is_err());
    }
}
