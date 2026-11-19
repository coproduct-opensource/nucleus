//! `nucleus-advisory-gate` — the `cargo-deny` gate: advisories, bans, licenses and sources,
//! checked against a PINNED RustSec advisory snapshot with no network.
//!
//! ```text
//! cargo run --offline --locked --quiet --manifest-path tools/advisory-gate/Cargo.toml \
//!     --target-dir target/advisory-gate/build -- check advisories bans licenses sources
//! cargo run --manifest-path tools/advisory-gate/Cargo.toml -- vendor --from <advisory-db checkout>
//! ```
//!
//! # Why a snapshot, and what that costs
//!
//! A gate pod has no network (`net: none`), and cargo-deny normally fetches the advisory database
//! at run time. A verdict computed against "whatever the database said when the pod ran" cannot be
//! re-derived from the change: the same tree would pass today and fail next week. So the database
//! is part of the tree: `.gatehouse/advisory-db/` holds the `crates/`, `rust/` and `LICENSE.txt`
//! of one upstream commit, byte for byte, and `.gatehouse/advisory-db.toml` pins that commit and
//! the git object ids of those three entries.
//!
//! The consequence, stated plainly: **this gate knows only the advisories in the pinned snapshot.**
//! An advisory published after it reaches the gate when the pin moves (`vendor`, in a pull request
//! that this gate itself checks), and not before.
//!
//! # What `check` does, in order
//!
//! 1. Parses the pin (closed key set; anything else refuses).
//! 2. Refuses a snapshot whose top-level entries are not exactly `crates`, `rust`, `LICENSE.txt`,
//!    or that contains anything but directories and regular files.
//! 3. Copies it into a fresh git repository under the work directory, committed at the pinned
//!    upstream commit time. cargo-deny reads its database through `git` (it asks for the HEAD
//!    commit's time), and refuses a directory that is not a repository — measured with cargo-deny
//!    0.20.2.
//! 4. Recomputes the git object id of each entry and refuses unless every one equals the pin. That
//!    is the check that the bytes are upstream's: anyone can run `git rev-parse <commit>:crates` in
//!    a clone of rustsec/advisory-db and compare, with no trust in this repository.
//! 5. Writes a copy of `deny.toml` with `db-path` and `db-urls` pointed at that repository (refusing
//!    a `deny.toml` that already sets either), and runs
//!    `cargo deny --offline --locked --config <copy> check <categories>`.
//!
//! Exit 0 only when cargo-deny exits 0. cargo-deny's own failure code passes through; a snapshot or
//! setup failure exits 2. "Could not look" is never "looked and it was fine" (ADR-0007 A-family).
//!
//! # The database directory name
//!
//! cargo-deny looks for the database for `db-urls = ["https://github.com/rustsec/advisory-db"]` at
//! `<db-path>/advisory-db-3157b0e258782691` (cargo-deny 0.20.2's name for that URL). If a later
//! cargo-deny names it differently, it finds no database, cannot fetch one offline, and fails:
//! measured, exit 1. A wrong name is a red gate, never a green one with no advisories.

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const PIN: &str = ".gatehouse/advisory-db.toml";
const SNAPSHOT: &str = ".gatehouse/advisory-db";
const DENY: &str = "deny.toml";
const WORK: &str = "target/advisory-gate";
const UPSTREAM: &str = "https://github.com/rustsec/advisory-db";
const DB_DIR: &str = "advisory-db-3157b0e258782691";
/// The snapshot's entries, each pinned by its git object id. Closed: a fourth is refused.
const ENTRIES: [&str; 3] = ["crates", "rust", "LICENSE.txt"];
const CATEGORIES: [&str; 4] = ["advisories", "bans", "licenses", "sources"];

#[derive(Debug)]
enum Error {
    Usage(String),
    Pin(String),
    Snapshot(String),
    Config(String),
    Io(String, io::Error),
    Tool(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Usage(m) => write!(f, "usage: {m}"),
            Error::Pin(m) => write!(f, "{PIN}: {m}"),
            Error::Snapshot(m) => write!(f, "{SNAPSHOT}: {m}"),
            Error::Config(m) => write!(f, "{DENY}: {m}"),
            Error::Io(what, e) => write!(f, "{what}: {e}"),
            Error::Tool(m) => write!(f, "{m}"),
        }
    }
}

fn io_err(what: impl Into<String>) -> impl FnOnce(io::Error) -> Error {
    let what = what.into();
    move |e| Error::Io(what, e)
}

/// A 40-hex git object id (SHA-1 object format, which rustsec/advisory-db uses).
#[derive(Debug, Clone, PartialEq, Eq)]
struct ObjectId(String);

impl ObjectId {
    fn parse(s: &str) -> Option<ObjectId> {
        (s.len() == 40
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        .then(|| ObjectId(s.to_string()))
    }
}

/// `.gatehouse/advisory-db.toml`: which upstream commit the snapshot is, and the object id of
/// each entry. Every field is required; there is no default.
#[derive(Debug, PartialEq, Eq)]
struct Pin {
    commit: ObjectId,
    committed: String,
    crates: ObjectId,
    rust: ObjectId,
    license: ObjectId,
}

impl Pin {
    fn entry(&self, name: &str) -> &ObjectId {
        match name {
            "crates" => &self.crates,
            "rust" => &self.rust,
            "LICENSE.txt" => &self.license,
            other => unreachable!("ENTRIES names only three entries, not {other}"),
        }
    }

    /// The pin file's grammar: blank lines, `#` comments, and `key = "value"` for exactly the
    /// five keys below, each once.
    fn parse(text: &str) -> Result<Pin, Error> {
        let mut fields: [(&str, Option<String>); 5] = [
            ("commit", None),
            ("committed", None),
            ("crates", None),
            ("rust", None),
            ("license", None),
        ];
        for (n, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let bad = || Error::Pin(format!("line {}: expected `key = \"value\"`", n + 1));
            let (key, value) = line.split_once('=').ok_or_else(bad)?;
            let (key, value) = (key.trim(), value.trim());
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .filter(|v| !v.contains('"') && !v.contains('\\'))
                .ok_or_else(bad)?;
            let slot = fields
                .iter_mut()
                .find(|(k, _)| *k == key)
                .ok_or_else(|| Error::Pin(format!("line {}: unknown key `{key}`", n + 1)))?;
            if slot.1.replace(value.to_string()).is_some() {
                return Err(Error::Pin(format!("line {}: `{key}` given twice", n + 1)));
            }
        }
        let mut take = |key: &str| -> Result<String, Error> {
            fields
                .iter_mut()
                .find(|(k, _)| *k == key)
                .and_then(|(_, v)| v.take())
                .ok_or_else(|| Error::Pin(format!("`{key}` is missing")))
        };
        let id = |key: &str, v: String| {
            ObjectId::parse(&v)
                .ok_or_else(|| Error::Pin(format!("`{key}` is not a 40-hex object id: {v:?}")))
        };
        let commit = id("commit", take("commit")?)?;
        let committed = take("committed")?;
        if !looks_like_rfc3339(&committed) {
            return Err(Error::Pin(format!(
                "`committed` is not an RFC 3339 time: {committed:?}"
            )));
        }
        Ok(Pin {
            commit,
            committed,
            crates: id("crates", take("crates")?)?,
            rust: id("rust", take("rust")?)?,
            license: id("license", take("license")?)?,
        })
    }

    fn render(&self) -> String {
        format!(
            "# The RustSec advisory snapshot the `cargo-deny` gate checks against. Written by\n\
             # `cargo run --manifest-path tools/advisory-gate/Cargo.toml -- vendor --from <checkout>`;\n\
             # do not edit by hand. Each id is `git rev-parse <commit>:<entry>` in a clone of\n\
             # {UPSTREAM}, recomputed from the vendored bytes on every gate run.\n\
             commit = \"{}\"\n\
             committed = \"{}\"\n\
             crates = \"{}\"\n\
             rust = \"{}\"\n\
             license = \"{}\"\n",
            self.commit.0, self.committed, self.crates.0, self.rust.0, self.license.0
        )
    }
}

/// `YYYY-MM-DDTHH:MM:SS` followed by `Z` or `±HH:MM`, which is what `git log --format=%cI` prints.
fn looks_like_rfc3339(s: &str) -> bool {
    let b = s.as_bytes();
    let digits = |r: std::ops::Range<usize>| r.into_iter().all(|i| b[i].is_ascii_digit());
    let zone = match b.get(19..) {
        Some([b'Z']) => true,
        Some([sign, h1, h2, b':', m1, m2]) => {
            matches!(sign, b'+' | b'-') && [h1, h2, m1, m2].iter().all(|d| d.is_ascii_digit())
        }
        _ => false,
    };
    b.len() >= 20
        && digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && b[10] == b'T'
        && digits(11..13)
        && b[13] == b':'
        && digits(14..16)
        && b[16] == b':'
        && digits(17..19)
        && zone
}

/// `deny.toml` with the database pointed at the verified snapshot. The policy itself (ignores,
/// bans, licenses, sources) is the file's own: one decider per fact (ADR-0007 G), so the gate and
/// any other caller of cargo-deny read one policy.
fn derive_config(deny: &str, db_parent: &Path) -> Result<String, Error> {
    let headers: Vec<usize> = deny
        .lines()
        .enumerate()
        .filter(|(_, l)| l.trim() == "[advisories]")
        .map(|(i, _)| i)
        .collect();
    let [header] = headers[..] else {
        return Err(Error::Config(format!(
            "expected exactly one `[advisories]` table, found {}",
            headers.len()
        )));
    };
    if let Some(l) = deny.lines().map(str::trim).find(|l| {
        ["db-path", "db-urls", "db_path", "db_urls"]
            .iter()
            .any(|k| l.starts_with(k))
    }) {
        return Err(Error::Config(format!(
            "already chooses the advisory database (`{l}`); the gate's database is the pinned snapshot"
        )));
    }
    let path = db_parent
        .to_str()
        .ok_or_else(|| Error::Config(format!("work path is not UTF-8: {}", db_parent.display())))?;
    if path.contains('"') || path.contains('\\') {
        return Err(Error::Config(format!(
            "work path cannot be written as a TOML basic string: {path}"
        )));
    }
    let mut out = String::with_capacity(deny.len() + 256);
    for (i, line) in deny.lines().enumerate() {
        out.push_str(line);
        out.push('\n');
        if i == header {
            out.push_str(&format!(
                "db-path = \"{path}\"\ndb-urls = [\"{UPSTREAM}\"]\n"
            ));
        }
    }
    Ok(out)
}

/// Directories and regular files only: a symlink in the snapshot could point the copy outside it.
fn copy_tree(from: &Path, to: &Path) -> Result<(), Error> {
    let meta = fs::symlink_metadata(from).map_err(io_err(from.display().to_string()))?;
    if meta.is_dir() {
        fs::create_dir_all(to).map_err(io_err(to.display().to_string()))?;
        let mut names: Vec<_> = fs::read_dir(from)
            .map_err(io_err(from.display().to_string()))?
            .map(|e| e.map(|e| e.file_name()))
            .collect::<Result<_, _>>()
            .map_err(io_err(from.display().to_string()))?;
        names.sort();
        for name in names {
            copy_tree(&from.join(&name), &to.join(&name))?;
        }
        Ok(())
    } else if meta.is_file() {
        fs::copy(from, to).map_err(io_err(format!("copying {}", from.display())))?;
        Ok(())
    } else {
        Err(Error::Snapshot(format!(
            "{} is neither a directory nor a regular file",
            from.display()
        )))
    }
}

/// The snapshot's top level is exactly [`ENTRIES`].
fn closed_entries(dir: &Path) -> Result<(), Error> {
    let mut found: Vec<String> = fs::read_dir(dir)
        .map_err(io_err(dir.display().to_string()))?
        .map(|e| e.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<Result<_, _>>()
        .map_err(io_err(dir.display().to_string()))?;
    found.sort();
    let mut want: Vec<String> = ENTRIES.iter().map(|s| s.to_string()).collect();
    want.sort();
    if found == want {
        Ok(())
    } else {
        Err(Error::Snapshot(format!(
            "top-level entries are {found:?}; exactly {want:?} are allowed"
        )))
    }
}

/// `git` with no system or global configuration: a developer's `core.autocrlf`, hooks or
/// excludes must not change the object ids the pin is compared against.
fn git(dir: &Path, args: &[&str], date: Option<&str>) -> Result<String, Error> {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(dir)
        .args([
            "-c",
            "core.autocrlf=false",
            "-c",
            "core.fileMode=true",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "init.defaultBranch=main",
        ])
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "advisory-gate")
        .env("GIT_AUTHOR_EMAIL", "advisory-gate@invalid")
        .env("GIT_COMMITTER_NAME", "advisory-gate")
        .env("GIT_COMMITTER_EMAIL", "advisory-gate@invalid");
    if let Some(d) = date {
        cmd.env("GIT_AUTHOR_DATE", d).env("GIT_COMMITTER_DATE", d);
    }
    let out = cmd
        .output()
        .map_err(|e| Error::Tool(format!("running git {}: {e}", args.join(" "))))?;
    if !out.status.success() {
        return Err(Error::Tool(format!(
            "git {} failed ({}): {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    String::from_utf8(out.stdout)
        .map(|s| s.trim().to_string())
        .map_err(|_| Error::Tool(format!("git {} printed non-UTF-8", args.join(" "))))
}

/// Proof that the materialized database is the pinned upstream snapshot. Only [`materialize`]
/// mints one, after every object id matched (ADR-0007 C: evidence is minted by the checker).
struct Verified {
    repo_parent: PathBuf,
    pin: Pin,
}

fn materialize(root: &Path, work: &Path) -> Result<Verified, Error> {
    let pin_text = fs::read_to_string(root.join(PIN)).map_err(io_err(PIN))?;
    let pin = Pin::parse(&pin_text)?;
    let snapshot = root.join(SNAPSHOT);
    closed_entries(&snapshot)?;

    let parent = work.join("db");
    let repo = parent.join(DB_DIR);
    // A previous run's database is moved aside (one atomic rename) before a fresh one is built,
    // so what cargo-deny reads is always this run's copy. Deleting it in place was measured to
    // fail transiently on macOS (`Directory not empty`, 1 of 5 local runs) while something still
    // held the old tree; the moved-aside copy is never read, so a failed delete of it is reported
    // and does not decide the gate. A gate pod starts with no previous run, so it never gets here.
    if parent.exists() {
        let aside = work.join(format!("db.old-{}", std::process::id()));
        fs::rename(&parent, &aside)
            .map_err(io_err(format!("moving aside {}", parent.display())))?;
        if let Err(e) = fs::remove_dir_all(&aside) {
            eprintln!(
                "advisory-gate: note: could not delete the previous run's copy {}: {e}",
                aside.display()
            );
        }
    }
    fs::create_dir_all(&repo).map_err(io_err(repo.display().to_string()))?;
    for entry in ENTRIES {
        copy_tree(&snapshot.join(entry), &repo.join(entry))?;
    }
    git(&repo, &["init", "-q"], None)?;
    git(&repo, &["add", "-A"], None)?;
    let message = format!("rustsec/advisory-db {}", pin.commit.0);
    git(
        &repo,
        &["commit", "-q", "--no-verify", "-m", &message],
        Some(&pin.committed),
    )?;
    let mut mismatches = Vec::new();
    for entry in ENTRIES {
        let got = git(&repo, &["rev-parse", &format!("HEAD:{entry}")], None)?;
        let want = pin.entry(entry);
        if got != want.0 {
            mismatches.push(format!(
                "{entry}: pinned {} but the bytes hash to {got}",
                want.0
            ));
        }
    }
    if !mismatches.is_empty() {
        return Err(Error::Snapshot(format!(
            "is not rustsec/advisory-db {}: {}",
            pin.commit.0,
            mismatches.join("; ")
        )));
    }
    let repo_parent = fs::canonicalize(&parent).map_err(io_err(parent.display().to_string()))?;
    Ok(Verified { repo_parent, pin })
}

/// What the gate concluded. Three cases, never two (ADR-0007 A).
enum Outcome {
    Held,
    Refused(i32),
    CouldNotRun(Error),
}

fn check(root: &Path, categories: &[String]) -> Outcome {
    if categories.is_empty() {
        return Outcome::CouldNotRun(Error::Usage(format!(
            "check needs one or more of {CATEGORIES:?}"
        )));
    }
    if let Some(c) = categories
        .iter()
        .find(|c| !CATEGORIES.contains(&c.as_str()))
    {
        return Outcome::CouldNotRun(Error::Usage(format!(
            "unknown category `{c}`; one of {CATEGORIES:?}"
        )));
    }
    let work = root.join(WORK);
    let verified = match materialize(root, &work) {
        Ok(v) => v,
        Err(e) => return Outcome::CouldNotRun(e),
    };
    let deny = match fs::read_to_string(root.join(DENY)) {
        Ok(t) => t,
        Err(e) => return Outcome::CouldNotRun(Error::Io(DENY.into(), e)),
    };
    let config = match derive_config(&deny, &verified.repo_parent) {
        Ok(c) => c,
        Err(e) => return Outcome::CouldNotRun(e),
    };
    let config_path = work.join("deny.toml");
    if let Err(e) = fs::write(&config_path, config) {
        return Outcome::CouldNotRun(Error::Io(config_path.display().to_string(), e));
    }
    eprintln!(
        "advisory-gate: rustsec/advisory-db {} (committed {}), verified against {PIN}. \
         Advisories published after that commit are NOT checked until the pin moves.",
        verified.pin.commit.0, verified.pin.committed
    );
    let status = Command::new("cargo")
        .args(["deny", "--offline", "--locked", "--config"])
        .arg(&config_path)
        .arg("check")
        .args(categories)
        .current_dir(root)
        .status();
    match status {
        Ok(s) if s.success() => Outcome::Held,
        Ok(s) => match s.code() {
            Some(code) => Outcome::Refused(code),
            None => Outcome::CouldNotRun(Error::Tool(format!("cargo deny ended by a signal: {s}"))),
        },
        Err(e) => Outcome::CouldNotRun(Error::Tool(format!("running cargo deny: {e}"))),
    }
}

/// Move the pin: copy `crates`, `rust` and `LICENSE.txt` from a clean checkout of
/// rustsec/advisory-db at the commit to pin, and write the pin from that checkout's own object ids.
/// Network access (the clone or fetch) is the caller's; this reads only the local checkout.
fn vendor(root: &Path, from: &Path) -> Result<Pin, Error> {
    let dirty = git(
        from,
        &["status", "--porcelain", "--untracked-files=all"],
        None,
    )?;
    if !dirty.is_empty() {
        return Err(Error::Usage(format!(
            "{} has local changes; vendor only an unmodified checkout",
            from.display()
        )));
    }
    let id = |rev: &str| -> Result<ObjectId, Error> {
        let s = git(from, &["rev-parse", rev], None)?;
        ObjectId::parse(&s).ok_or_else(|| Error::Tool(format!("git rev-parse {rev} gave {s:?}")))
    };
    let pin = Pin {
        commit: id("HEAD")?,
        committed: git(from, &["log", "-1", "--format=%cI", "HEAD"], None)?,
        crates: id("HEAD:crates")?,
        rust: id("HEAD:rust")?,
        license: id("HEAD:LICENSE.txt")?,
    };
    // Round-trip through the parser, so a pin this writes is one the gate accepts.
    let rendered = pin.render();
    Pin::parse(&rendered)?;
    let snapshot = root.join(SNAPSHOT);
    if snapshot.exists() {
        fs::remove_dir_all(&snapshot).map_err(io_err(format!("clearing {SNAPSHOT}")))?;
    }
    for entry in ENTRIES {
        copy_tree(&from.join(entry), &snapshot.join(entry))?;
    }
    fs::write(root.join(PIN), rendered).map_err(io_err(PIN))?;
    Ok(pin)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = match std::env::current_dir() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("advisory-gate: cannot read the working directory: {e}");
            return ExitCode::from(2);
        }
    };
    match args.split_first() {
        Some((cmd, rest)) if cmd == "check" => match check(&root, rest) {
            Outcome::Held => ExitCode::SUCCESS,
            Outcome::Refused(code) => {
                eprintln!("advisory-gate: cargo deny refused this tree (exit {code})");
                ExitCode::from(u8::try_from(code).ok().filter(|c| *c != 0).unwrap_or(1))
            }
            Outcome::CouldNotRun(e) => {
                eprintln!("advisory-gate: could not run: {e}");
                ExitCode::from(2)
            }
        },
        Some((cmd, rest)) if cmd == "vendor" => match rest {
            [flag, from] if flag == "--from" => match vendor(&root, Path::new(from)) {
                Ok(pin) => {
                    eprintln!(
                        "advisory-gate: vendored rustsec/advisory-db {} (committed {}) into {SNAPSHOT}",
                        pin.commit.0, pin.committed
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("advisory-gate: {e}");
                    ExitCode::from(2)
                }
            },
            _ => {
                eprintln!("advisory-gate: usage: vendor --from <advisory-db checkout>");
                ExitCode::from(2)
            }
        },
        _ => {
            eprintln!(
                "advisory-gate: usage: check <{}>... | vendor --from <advisory-db checkout>",
                CATEGORIES.join("|")
            );
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "0123456789abcdef0123456789abcdef01234567";

    fn pin_text() -> String {
        format!(
            "# c\ncommit = \"{A}\"\ncommitted = \"2026-11-18T10:14:42+01:00\"\n\
             crates = \"{A}\"\nrust = \"{A}\"\nlicense = \"{A}\"\n"
        )
    }

    #[test]
    fn a_complete_pin_parses_and_round_trips() {
        let pin = Pin::parse(&pin_text()).expect("parses");
        assert_eq!(pin.committed, "2026-11-18T10:14:42+01:00");
        assert_eq!(Pin::parse(&pin.render()).expect("round trip"), pin);
    }

    #[test]
    fn a_pin_refuses_missing_unknown_duplicate_and_malformed_fields() {
        let cases = [
            pin_text().replace(&format!("license = \"{A}\"\n"), ""),
            pin_text() + "extra = \"x\"\n",
            pin_text() + &format!("rust = \"{A}\"\n"),
            pin_text().replace(&format!("crates = \"{A}\""), "crates = \"ABC\""),
            pin_text().replace(&format!("crates = \"{A}\""), &format!("crates = {A}")),
            pin_text().replace("2026-11-18T10:14:42+01:00", "yesterday"),
        ];
        for text in cases {
            assert!(Pin::parse(&text).is_err(), "accepted:\n{text}");
        }
    }

    #[test]
    fn uppercase_hex_is_not_an_object_id() {
        assert!(ObjectId::parse(&A.to_uppercase()).is_none());
        assert!(ObjectId::parse(&A[..39]).is_none());
        assert!(ObjectId::parse(A).is_some());
    }

    #[test]
    fn rfc3339_as_git_prints_it() {
        assert!(looks_like_rfc3339("2026-11-18T10:14:42+01:00"));
        assert!(looks_like_rfc3339("2026-11-18T09:14:42Z"));
        assert!(!looks_like_rfc3339("2026-11-18 10:14:42"));
        assert!(!looks_like_rfc3339("2026-11-18T10:14:42"));
    }

    #[test]
    fn the_config_points_the_one_advisories_table_at_the_snapshot() {
        let deny = "[graph]\ntargets = []\n\n[advisories]\nversion = 2\nignore = []\n";
        let out = derive_config(deny, Path::new("/w/db")).expect("derives");
        assert_eq!(
            out,
            "[graph]\ntargets = []\n\n[advisories]\ndb-path = \"/w/db\"\n\
             db-urls = [\"https://github.com/rustsec/advisory-db\"]\nversion = 2\nignore = []\n"
        );
    }

    #[test]
    fn the_config_refuses_what_it_cannot_place_or_would_override() {
        let p = Path::new("/w/db");
        assert!(derive_config("[bans]\n", p).is_err(), "no advisories table");
        assert!(
            derive_config("[advisories]\n[advisories]\n", p).is_err(),
            "two tables"
        );
        assert!(derive_config("[advisories]\ndb-path = \"~/x\"\n", p).is_err());
        assert!(derive_config("[advisories]\ndb-urls = []\n", p).is_err());
        assert!(derive_config("[advisories]\n", Path::new("/w/\"db")).is_err());
    }

    #[test]
    fn the_snapshot_entries_are_a_closed_list() {
        let dir = std::env::temp_dir().join(format!("advisory-gate-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        for e in ["crates", "rust"] {
            fs::create_dir_all(dir.join(e)).unwrap();
        }
        fs::write(dir.join("LICENSE.txt"), "cc0").unwrap();
        assert!(closed_entries(&dir).is_ok());
        fs::write(dir.join("README.md"), "extra").unwrap();
        assert!(closed_entries(&dir).is_err(), "a fourth entry");
        fs::remove_file(dir.join("README.md")).unwrap();
        fs::remove_dir_all(dir.join("rust")).unwrap();
        assert!(closed_entries(&dir).is_err(), "a missing entry");
        fs::remove_dir_all(&dir).unwrap();
    }
}
