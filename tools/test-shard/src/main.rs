//! `nucleus-test-shard` — run one scope shard of the test suite.
//!
//! ```text
//! cargo run --offline --locked --manifest-path tools/test-shard/Cargo.toml --target-dir target/test-shard -- \
//!     [--workspace-features] [--stub <member>:<path>]... [--stub-main <member>:<path>]... -- <argv>...
//! ```
//!
//! A shard gate runs on a MATERIALIZED selection: the pod holds exactly the files its scope
//! names. Every shard's scope names every member's `Cargo.toml`, because cargo loads the whole
//! workspace to resolve one package, but only the sources of the crates its tests can reach. A
//! member with no target file is a member cargo refuses to load, so the shard writes an empty
//! stub at each target path of each member it left out, and then `exec`s the run — one step, so
//! the shard pays one step's overhead, not two.
//!
//! # The stubs are named, not discovered
//!
//! The prototype (nucleus#3138) parsed every manifest at run time to find the target paths. This
//! takes them as arguments, computed by `cargo xtask test-shards` from `cargo metadata`, for two
//! reasons. The plan must declare each stub as a write crate by crate — a wildcard such as
//! `crates/*/src/lib.rs` also names the shard's own crates, so `writesOutsideScope_b` refuses it
//! under a `crates/**` scope (gatehouse F-186) — and a list computed once is the list the plan
//! declares and the list this writes. And a parser here would be a dependency in a crate that
//! must build before the workspace can load.
//!
//! # What it refuses
//!
//! * **Some stubs present and some absent.** A materialized pod has none of them (they are in
//!   the scope's excludes); a full checkout has all of them, and needs none. A mix means the
//!   selection and the generator disagree about which crates this shard holds, and testing
//!   under that disagreement is how a shard passes with fewer tests than it was meant to run.
//! * **A stub outside its member, or a path that climbs.** Every write is one the plan declared.
//!
//! An empty stub is only COMPILED if something in the shard depends on that crate, which the
//! layout says nothing does. If the layout is wrong the build fails: an empty crate exports
//! nothing a dependent could use. Red, never a quiet green.
//!
//! # `--workspace-features`
//!
//! `cargo test -p a -p b` unifies features over a and b alone, so it compiles different units from
//! the whole-workspace gate (gatehouse F-179: 359 of 1,056 and 382 of 1,568 units differ on nucleus
//! 2fc73eda). With cargo's `resolver.feature-unification = "workspace"` (cargo#14774) none do. The
//! setting is unstable in cargo 1.96, so it is enabled for the exec'd process tree only, through
//! cargo's own config environment, with the channel override scoped to the same exec.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitCode};

/// cargo's config environment for workspace feature unification (cargo#14774).
const WORKSPACE_FEATURES: [(&str, &str); 3] = [
    ("__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS", "nightly"),
    ("CARGO_UNSTABLE_FEATURE_UNIFICATION", "true"),
    ("CARGO_RESOLVER_FEATURE_UNIFICATION", "workspace"),
];

/// What a stub holds. A library target compiles from an empty file; a binary, a build script and
/// anything else cargo links as an executable needs a `main`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Body {
    Empty,
    Main,
}

impl Body {
    fn text(self) -> &'static str {
        match self {
            Body::Empty => "",
            Body::Main => "fn main() {}\n",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Stub {
    /// The member's directory, relative to the workspace root.
    member: PathBuf,
    /// The target file, relative to the member.
    path: PathBuf,
    body: Body,
}

impl Stub {
    fn full(&self) -> PathBuf {
        self.member.join(&self.path)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Args {
    workspace_features: bool,
    stubs: Vec<Stub>,
    argv: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    Usage(String),
    /// A path that is absolute or climbs out of where it was declared.
    Escapes(String),
    /// Some stubs present and some absent: the selection and the generator disagree.
    Mixed {
        present: Vec<PathBuf>,
        absent: Vec<PathBuf>,
    },
    Io(String),
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::Usage(why) => write!(
                f,
                "{why}\nusage: nucleus-test-shard [--workspace-features] [--stub <member>:<path>]... \
                 [--stub-main <member>:<path>]... -- <argv>..."
            ),
            Refusal::Escapes(p) => write!(f, "refused: {p} is absolute or leaves its member"),
            Refusal::Mixed { present, absent } => write!(
                f,
                "refused: {} stub path(s) are present and {} absent, so this shard's selection and \
                 `cargo xtask test-shards` disagree about which crates it holds -- regenerate the \
                 shard gates. present: {present:?}; absent: {absent:?}",
                present.len(),
                absent.len()
            ),
            Refusal::Io(e) => write!(f, "refused: {e}"),
        }
    }
}

/// Only plain, relative components: a stub lands where the plan says, or nowhere.
fn plain(p: &Path) -> bool {
    !p.as_os_str().is_empty() && p.components().all(|c| matches!(c, Component::Normal(_)))
}

fn parse_stub(spec: &str, body: Body) -> Result<Stub, Refusal> {
    let Some((member, path)) = spec.split_once(':') else {
        return Err(Refusal::Usage(format!("`{spec}` is not <member>:<path>")));
    };
    let (member, path) = (PathBuf::from(member), PathBuf::from(path));
    if !plain(&member) || !plain(&path) {
        return Err(Refusal::Escapes(spec.to_string()));
    }
    Ok(Stub { member, path, body })
}

fn parse(args: &[String]) -> Result<Args, Refusal> {
    let mut out = Args {
        workspace_features: false,
        stubs: Vec::new(),
        argv: Vec::new(),
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--workspace-features" => out.workspace_features = true,
            "--stub" | "--stub-main" => {
                let body = if a == "--stub" {
                    Body::Empty
                } else {
                    Body::Main
                };
                let spec = it
                    .next()
                    .ok_or_else(|| Refusal::Usage(format!("{a} needs <member>:<path>")))?;
                out.stubs.push(parse_stub(spec, body)?);
            }
            "--" => {
                out.argv = it.cloned().collect();
                break;
            }
            other => return Err(Refusal::Usage(format!("unknown argument `{other}`"))),
        }
    }
    if out.argv.is_empty() {
        return Err(Refusal::Usage("nothing to run after `--`".into()));
    }
    Ok(out)
}

/// Write every stub under `root`, or none. Returns how many were written.
fn write_stubs(root: &Path, stubs: &[Stub]) -> Result<usize, Refusal> {
    let mut present = Vec::new();
    let mut absent = Vec::new();
    for s in stubs {
        let p = s.full();
        // `symlink_metadata`, not `exists`: a dangling link is present, and writing through it
        // would land somewhere no one declared.
        match fs::symlink_metadata(root.join(&p)) {
            Ok(_) => present.push(p),
            Err(e) if e.kind() == io::ErrorKind::NotFound => absent.push(p),
            Err(e) => return Err(Refusal::Io(format!("{}: {e}", p.display()))),
        }
    }
    if absent.is_empty() {
        return Ok(0);
    }
    if !present.is_empty() {
        return Err(Refusal::Mixed { present, absent });
    }
    let mut seen = BTreeSet::new();
    for s in stubs {
        let p = root.join(s.full());
        if !seen.insert(p.clone()) {
            continue;
        }
        if let Some(dir) = p.parent() {
            fs::create_dir_all(dir).map_err(|e| Refusal::Io(format!("{}: {e}", dir.display())))?;
        }
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p)
            .and_then(|mut f| io::Write::write_all(&mut f, s.body.text().as_bytes()))
            .map_err(|e| Refusal::Io(format!("{}: {e}", p.display())))?;
        eprintln!("stub {}", s.full().display());
    }
    Ok(seen.len())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match parse(&args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("nucleus-test-shard: {e}");
            return ExitCode::from(2);
        }
    };
    match write_stubs(Path::new("."), &parsed.stubs) {
        Ok(n) => eprintln!("nucleus-test-shard: {n} stub(s) written"),
        Err(e) => {
            eprintln!("nucleus-test-shard: {e}");
            return ExitCode::from(2);
        }
    }
    let mut cmd = Command::new(&parsed.argv[0]);
    cmd.args(&parsed.argv[1..]);
    if parsed.workspace_features {
        cmd.envs(WORKSPACE_FEATURES.map(|(k, v)| (OsString::from(k), OsString::from(v))));
    }
    // `exec` replaces this process, so the run's exit status IS the step's.
    let err = cmd.exec();
    eprintln!("nucleus-test-shard: cannot exec {}: {err}", parsed.argv[0]);
    ExitCode::from(127)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_string()).collect()
    }

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("test-shard-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn parses_stubs_flags_and_the_run() {
        let a = parse(&s(&[
            "--workspace-features",
            "--stub",
            "crates/a:src/lib.rs",
            "--stub-main",
            "crates/b:src/main.rs",
            "--",
            "cargo",
            "nextest",
            "run",
        ]))
        .unwrap();
        assert!(a.workspace_features);
        assert_eq!(a.stubs.len(), 2);
        assert_eq!(a.stubs[1].body, Body::Main);
        assert_eq!(a.argv, s(&["cargo", "nextest", "run"]));
    }

    #[test]
    fn refuses_a_stub_that_climbs_or_is_absolute_and_a_missing_run() {
        for bad in [
            "crates/a:../b/src/lib.rs",
            "/etc:passwd",
            "crates/a:/x",
            "crates/a:",
            "nocolon",
        ] {
            assert!(parse(&s(&["--stub", bad, "--", "true"])).is_err(), "{bad}");
        }
        assert!(matches!(
            parse(&s(&["--stub", "crates/a:src/lib.rs"])),
            Err(Refusal::Usage(_))
        ));
        assert!(matches!(
            parse(&s(&["--bogus", "--", "true"])),
            Err(Refusal::Usage(_))
        ));
    }

    #[test]
    fn writes_every_stub_into_a_materialized_selection() {
        let root = tmp("materialized");
        fs::create_dir_all(root.join("crates/a")).unwrap();
        fs::write(root.join("crates/a/Cargo.toml"), "").unwrap();
        let stubs = vec![
            parse_stub("crates/a:src/lib.rs", Body::Empty).unwrap(),
            parse_stub("crates/a:src/bin/tool.rs", Body::Main).unwrap(),
        ];
        assert_eq!(write_stubs(&root, &stubs), Ok(2));
        assert_eq!(
            fs::read_to_string(root.join("crates/a/src/lib.rs")).unwrap(),
            ""
        );
        assert_eq!(
            fs::read_to_string(root.join("crates/a/src/bin/tool.rs")).unwrap(),
            "fn main() {}\n"
        );
    }

    #[test]
    fn a_full_checkout_needs_no_stubs_and_is_not_touched() {
        let root = tmp("full");
        fs::create_dir_all(root.join("crates/a/src")).unwrap();
        fs::write(root.join("crates/a/src/lib.rs"), "pub fn real() {}\n").unwrap();
        let stubs = vec![parse_stub("crates/a:src/lib.rs", Body::Empty).unwrap()];
        assert_eq!(write_stubs(&root, &stubs), Ok(0));
        assert_eq!(
            fs::read_to_string(root.join("crates/a/src/lib.rs")).unwrap(),
            "pub fn real() {}\n"
        );
    }

    #[test]
    fn some_present_and_some_absent_is_refused_and_writes_nothing() {
        // The selection holds crate a's sources but not crate b's: the shard's scope and the
        // generator disagree about which crates the shard holds.
        let root = tmp("mixed");
        fs::create_dir_all(root.join("crates/a/src")).unwrap();
        fs::write(root.join("crates/a/src/lib.rs"), "pub fn real() {}\n").unwrap();
        let stubs = vec![
            parse_stub("crates/a:src/lib.rs", Body::Empty).unwrap(),
            parse_stub("crates/b:src/lib.rs", Body::Empty).unwrap(),
        ];
        assert!(matches!(
            write_stubs(&root, &stubs),
            Err(Refusal::Mixed { .. })
        ));
        assert!(
            !root.join("crates/b/src/lib.rs").exists(),
            "nothing is written on a refusal"
        );
    }

    #[test]
    fn a_dangling_link_counts_as_present_and_is_never_written_through() {
        let root = tmp("link");
        fs::create_dir_all(root.join("crates/a/src")).unwrap();
        std::os::unix::fs::symlink(root.join("elsewhere"), root.join("crates/a/src/lib.rs"))
            .unwrap();
        let stubs = vec![
            parse_stub("crates/a:src/lib.rs", Body::Empty).unwrap(),
            parse_stub("crates/b:src/lib.rs", Body::Empty).unwrap(),
        ];
        assert!(matches!(
            write_stubs(&root, &stubs),
            Err(Refusal::Mixed { .. })
        ));
        assert!(!root.join("elsewhere").exists());
    }
}
