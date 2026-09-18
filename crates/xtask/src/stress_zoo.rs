//! `cargo xtask stress-zoo` — score `nucleus-perf stress` against injected defects.
//!
//! The manifest is `crates/nucleus-perf/zoo/zoo.toml`, and each defect's patch is
//! `zoo/<name>.patch`. The patch path is derived from the name, so the two cannot
//! disagree. The run happens in a scratch worktree detached at HEAD, so the
//! caller's tree is never patched:
//!
//! 1. Build the proxy and the harness at HEAD. Every mode must HOLD on that build;
//!    a mode red on correct code scores nothing (exit 2).
//! 2. For each defect: `git apply --check` (a failure is zoo rot, exit 2), apply,
//!    rebuild the proxy, copy the binary out, reverse the patch, and require the
//!    tree to be clean again. Then run every mode against the patched binary.
//! 3. A defect is killed when some mode reports a violation. A mismatch with the
//!    manifest's `expect`, in either direction, is exit 1.
//!
//! Only exit 1 from a mode counts as a kill. `nucleus-perf stress` maps its own
//! errors to 2, so a patched proxy that fails to start is "could not look", not a
//! defect caught.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Zoo {
    mode: Vec<Mode>,
    defect: Vec<Defect>,
}

#[derive(Debug, Deserialize)]
struct Mode {
    name: String,
    args: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Defect {
    name: String,
    origin: String,
    expect: Expect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Expect {
    Killed,
    Survives,
}

/// One mode's verdict on one build, from `nucleus-perf`'s exit contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Held,
    Violated,
    CouldNotLook,
}

impl Verdict {
    fn from_exit(code: Option<i32>) -> Self {
        match code {
            Some(0) => Verdict::Held,
            Some(1) => Verdict::Violated,
            // 2, a signal, or anything else: the mode did not produce a verdict.
            _ => Verdict::CouldNotLook,
        }
    }

    fn cell(self) -> &'static str {
        match self {
            Verdict::Held => ".",
            Verdict::Violated => "K",
            Verdict::CouldNotLook => "?",
        }
    }
}

/// What a defect's row amounts to.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// As the manifest says.
    AsExpected,
    /// Expected killed, nothing killed it.
    Survived,
    /// Expected to survive, and a mode killed it: the manifest understates the harness.
    UnexpectedKill,
    /// No mode killed it and at least one could not look, so survival is unproven.
    CouldNotLook,
}

fn judge(expect: Expect, verdicts: &[Verdict]) -> Outcome {
    let killed = verdicts.contains(&Verdict::Violated);
    let blind = verdicts.contains(&Verdict::CouldNotLook);
    match (expect, killed, blind) {
        (Expect::Killed, true, _) | (Expect::Survives, false, false) => Outcome::AsExpected,
        (Expect::Survives, true, _) => Outcome::UnexpectedKill,
        (_, false, true) => Outcome::CouldNotLook,
        (Expect::Killed, false, false) => Outcome::Survived,
    }
}

/// Patches on disk and defects in the manifest must be the same set.
fn parity(zoo: &Zoo, dir: &Path) -> Result<()> {
    let listed: BTreeSet<String> = zoo.defect.iter().map(|d| d.name.clone()).collect();
    if listed.len() != zoo.defect.len() {
        bail!("zoo.toml names a defect twice");
    }
    let mut on_disk = BTreeSet::new();
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "patch")
            && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
        {
            on_disk.insert(stem.to_owned());
        }
    }
    let unlisted: Vec<_> = on_disk.difference(&listed).collect();
    let missing: Vec<_> = listed.difference(&on_disk).collect();
    if !unlisted.is_empty() || !missing.is_empty() {
        bail!(
            "zoo.toml and zoo/*.patch disagree: patches not listed {unlisted:?}, listed without a patch {missing:?}"
        );
    }
    Ok(())
}

fn git(dir: &Path, args: &[&str]) -> Result<std::process::Output> {
    Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .with_context(|| format!("running git {}", args.join(" ")))
}

fn checked(dir: &Path, args: &[&str]) -> Result<()> {
    let out = git(dir, args)?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn build(tree: &Path, target: &Path, packages: &[&str]) -> Result<()> {
    let mut cmd = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cmd.current_dir(tree)
        .env("CARGO_TARGET_DIR", target)
        .arg("build");
    for p in packages {
        cmd.args(["-p", p]);
    }
    let status = cmd.status().context("running cargo build")?;
    if !status.success() {
        bail!("cargo build {packages:?} failed in {}", tree.display());
    }
    Ok(())
}

fn battery(perf: &Path, proxy: &Path, modes: &[Mode]) -> Result<Vec<Verdict>> {
    modes
        .iter()
        .map(|m| {
            let status = Command::new(perf)
                .arg("stress")
                .args(&m.args)
                .arg("--proxy-bin")
                .arg(proxy)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .with_context(|| format!("running mode {}", m.name))?;
            let v = Verdict::from_exit(status.code());
            eprintln!("    {:<22} {v:?}", m.name);
            Ok(v)
        })
        .collect()
}

/// Removes the scratch worktree however the run ends.
struct Scratch<'a> {
    repo: &'a Path,
    tree: PathBuf,
}

impl Drop for Scratch<'_> {
    fn drop(&mut self) {
        let _ = git(
            self.repo,
            &[
                "worktree",
                "remove",
                "--force",
                &self.tree.to_string_lossy(),
            ],
        );
    }
}

pub fn run(only: Option<&str>) -> Result<i32> {
    let top = git(Path::new("."), &["rev-parse", "--show-toplevel"])?;
    let repo = PathBuf::from(String::from_utf8(top.stdout)?.trim());
    let zoo_dir = repo.join("crates/nucleus-perf/zoo");
    let zoo: Zoo = toml::from_str(&std::fs::read_to_string(zoo_dir.join("zoo.toml"))?)
        .context("parsing zoo.toml")?;
    parity(&zoo, &zoo_dir)?;

    let base_target = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo.join("target"));
    let work = base_target.join("stress-zoo");
    let bins = work.join("bin");
    std::fs::create_dir_all(&bins)?;
    let scratch = Scratch {
        repo: &repo,
        tree: work.join("tree"),
    };
    let _ = git(
        &repo,
        &[
            "worktree",
            "remove",
            "--force",
            &scratch.tree.to_string_lossy(),
        ],
    );
    checked(
        &repo,
        &[
            "worktree",
            "add",
            "--detach",
            &scratch.tree.to_string_lossy(),
            "HEAD",
        ],
    )?;
    let tree = &scratch.tree;
    let target = work.join("target");

    eprintln!("baseline: building the proxy and harness at HEAD");
    build(tree, &target, &["nucleus-tool-proxy", "nucleus-perf"])?;
    let perf = bins.join("nucleus-perf");
    std::fs::copy(target.join("debug/nucleus-perf"), &perf)?;
    let baseline_proxy = bins.join("proxy-baseline");
    std::fs::copy(target.join("debug/nucleus-tool-proxy"), &baseline_proxy)?;
    let baseline = battery(&perf, &baseline_proxy, &zoo.mode)?;
    if baseline.iter().any(|v| *v != Verdict::Held) {
        println!("could not look: on correct code, every mode must hold:");
        for (m, v) in zoo.mode.iter().zip(&baseline) {
            println!("  {:<22} {v:?}", m.name);
        }
        return Ok(2);
    }

    let mut rows = Vec::new();
    let mut rot = Vec::new();
    for d in zoo
        .defect
        .iter()
        .filter(|d| only.is_none_or(|o| o == d.name))
    {
        eprintln!("defect {}: {}", d.name, d.origin);
        let patch = zoo_dir.join(format!("{}.patch", d.name));
        let patch = patch.to_string_lossy();
        if !git(tree, &["apply", "--check", &patch])?.status.success() {
            rot.push(d.name.clone());
            continue;
        }
        checked(tree, &["apply", &patch])?;
        let built = build(tree, &target, &["nucleus-tool-proxy"]);
        let proxy = bins.join(format!("proxy-{}", d.name));
        let copied = built.and_then(|()| {
            std::fs::copy(target.join("debug/nucleus-tool-proxy"), &proxy)
                .map(drop)
                .map_err(Into::into)
        });
        checked(tree, &["apply", "-R", &patch])?;
        if !git(tree, &["diff", "--quiet"])?.status.success() {
            bail!("reversing {} left the scratch tree dirty", d.name);
        }
        let verdicts = match copied {
            Ok(()) => battery(&perf, &proxy, &zoo.mode)?,
            Err(e) => {
                eprintln!("    build failed: {e:#}");
                vec![Verdict::CouldNotLook; zoo.mode.len()]
            }
        };
        rows.push((d, verdicts));
    }

    // The score: one column per mode, one row per defect.
    println!("{:<28} {}  outcome", "defect", modes_header(&zoo.mode));
    let mut failed = false;
    let mut blind = !rot.is_empty();
    for (d, verdicts) in &rows {
        let outcome = judge(d.expect, verdicts);
        failed |= matches!(outcome, Outcome::Survived | Outcome::UnexpectedKill);
        blind |= outcome == Outcome::CouldNotLook;
        let cells: Vec<_> = verdicts
            .iter()
            .map(|v| format!("{:^3}", v.cell()))
            .collect();
        println!(
            "{:<28} {}  {outcome:?} (expect {:?})",
            d.name,
            cells.join(""),
            d.expect
        );
    }
    for (i, m) in zoo.mode.iter().enumerate() {
        let kills = rows
            .iter()
            .filter(|(_, v)| v[i] == Verdict::Violated)
            .count();
        println!("  M{i} {:<22} killed {kills} of {}", m.name, rows.len());
    }
    for r in &rot {
        println!("ZOO ROT: {r}.patch no longer applies at HEAD; refresh it");
    }
    Ok(if failed {
        1
    } else if blind {
        2
    } else {
        0
    })
}

fn modes_header(modes: &[Mode]) -> String {
    (0..modes.len()).map(|i| format!("M{i:<2}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use Verdict::{CouldNotLook as Q, Held as H, Violated as V};

    #[test]
    fn only_exit_one_is_a_kill() {
        assert_eq!(Verdict::from_exit(Some(1)), V);
        assert_eq!(Verdict::from_exit(Some(0)), H);
        assert_eq!(Verdict::from_exit(Some(2)), Q);
        assert_eq!(Verdict::from_exit(Some(101)), Q);
        assert_eq!(Verdict::from_exit(None), Q);
    }

    #[test]
    fn a_kill_anywhere_kills() {
        assert_eq!(judge(Expect::Killed, &[H, Q, V]), Outcome::AsExpected);
        assert_eq!(judge(Expect::Survives, &[H, V]), Outcome::UnexpectedKill);
    }

    #[test]
    fn survival_is_only_proven_when_every_mode_looked() {
        assert_eq!(judge(Expect::Survives, &[H, H]), Outcome::AsExpected);
        assert_eq!(judge(Expect::Survives, &[H, Q]), Outcome::CouldNotLook);
        assert_eq!(judge(Expect::Killed, &[H, Q]), Outcome::CouldNotLook);
        assert_eq!(judge(Expect::Killed, &[H, H]), Outcome::Survived);
    }

    #[test]
    fn the_committed_zoo_is_consistent() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../nucleus-perf/zoo");
        let zoo: Zoo = toml::from_str(&std::fs::read_to_string(dir.join("zoo.toml")).unwrap())
            .expect("zoo.toml parses");
        assert!(!zoo.mode.is_empty() && !zoo.defect.is_empty());
        parity(&zoo, &dir).expect("every patch listed, every listed defect has a patch");
    }

    #[test]
    fn an_unlisted_patch_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("stray.patch"), "").unwrap();
        let zoo = Zoo {
            mode: vec![],
            defect: vec![],
        };
        assert!(parity(&zoo, dir.path()).is_err());
    }
}
