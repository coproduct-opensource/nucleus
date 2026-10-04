//! The INPUTS of a gate, derived from the gate's own text rather than listed beside it.
//!
//! Ported from `scripts/gate-inputs.sh`, which this replaces, rule for rule. The gate of gates
//! asks, per probe, whether gate G REDs on a violation of its subject and GREENs when it is
//! restored. That answer is a function of G's code and of what G reads, so a change that touches
//! none of those cannot move it -- and this is what says which those are.
//!
//! It is derived, not declared, for the reason the gate of gates gives about its own domain: a
//! hand-kept list is a membership test and cannot say that everything read is listed. Per gate:
//!
//! * code: the gate script, and transitively every script it names; every cargo package it
//!   builds or runs (`-p`, `--package`, `--manifest-path`, `--workspace`, `xtask -- <sub>`) with
//!   that package's path-dependency closure, plus Cargo.lock, the root Cargo.toml,
//!   rust-toolchain.toml and .cargo/. `cargo tree` and `cargo metadata` read only manifests, so
//!   for them only the Cargo.toml files count.
//! * named: every tracked FILE the code names -- by path, or by bare name (every file of that
//!   name, since a bare name may be read after a `cd`) -- in the script or, for an xtask
//!   subcommand, in the string literals of its module and the modules it uses.
//!
//! NOT derived, and not claimed: the set a gate WALKS (a directory or glob it names, or a walk it
//! does not spell at all). That is the gate's subject corpus; `mod.rs` ("SCOPED RUNS") says why
//! skipping on the rest of the corpus is safe and which full run catches what it would miss.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use anyhow::{Context, Result, bail};
use regex::Regex;

/// Paths whose change must re-run EVERY probe: the engine that runs them (this module, and the
/// shim CI calls it through), and the workflow that defines the job they execute in. A change to
/// any of these can move every answer at once, and no per-gate input set would say so. An entry
/// ending in `/` is a directory and matches everything under it.
pub const ENGINE: &[&str] = &[
    "scripts/check-gates-can-fail.sh",
    "crates/xtask/src/gates_can_fail/",
    ".github/workflows/ci.yml",
];

/// What every cargo-built gate depends on besides its packages.
const CARGO_COMMON: &[&str] = &["Cargo.lock", "Cargo.toml", "rust-toolchain.toml", ".cargo/"];

fn re(cell: &'static OnceLock<Regex>, pat: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pat).unwrap_or_else(|e| panic!("bad regex {pat}: {e}")))
}

macro_rules! regex {
    ($pat:expr) => {{
        static CELL: OnceLock<Regex> = OnceLock::new();
        re(&CELL, $pat)
    }};
}

/// The tracked tree, read once: files, their ancestor directories, basenames and packages.
pub struct Index {
    root: PathBuf,
    files: BTreeSet<String>,
    dirs: BTreeSet<String>,
    by_base: BTreeMap<String, Vec<String>>,
    /// `(package name, package dir)`, in tracked-file order.
    pkgs: Vec<(String, String)>,
    pkg_cache: RefCell<HashMap<String, Vec<String>>>,
    xtask_cache: RefCell<HashMap<String, BTreeSet<String>>>,
    script_cache: RefCell<HashMap<String, BTreeSet<String>>>,
}

impl Index {
    pub fn new(root: &Path) -> Result<Self> {
        let out = Command::new("git")
            .arg("ls-files")
            .current_dir(root)
            .output()
            .context("could not run git ls-files")?;
        if !out.status.success() {
            bail!(
                "git ls-files failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let listing = String::from_utf8_lossy(&out.stdout);
        let files: BTreeSet<String> = listing.lines().map(str::to_string).collect();
        let mut dirs = BTreeSet::new();
        let mut by_base: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for f in &files {
            let mut acc = String::new();
            let parts: Vec<&str> = f.split('/').collect();
            if let Some((last, ancestors)) = parts.split_last() {
                for p in ancestors {
                    if !acc.is_empty() {
                        acc.push('/');
                    }
                    acc.push_str(p);
                    dirs.insert(acc.clone());
                }
                by_base
                    .entry((*last).to_string())
                    .or_default()
                    .push(f.clone());
            }
        }
        let mut pkgs = Vec::new();
        for f in &files {
            if f != "Cargo.toml" && !f.ends_with("/Cargo.toml") {
                continue;
            }
            let Ok(text) = fs::read_to_string(root.join(f)) else {
                continue;
            };
            if let Some(name) = package_name(&text) {
                let dir = f.strip_suffix("Cargo.toml").unwrap_or(f);
                let dir = dir.strip_suffix('/').unwrap_or(dir);
                let dir = if dir.is_empty() { "." } else { dir };
                pkgs.push((name, dir.to_string()));
            }
        }
        Ok(Self {
            root: root.to_path_buf(),
            files,
            dirs,
            by_base,
            pkgs,
            pkg_cache: RefCell::default(),
            xtask_cache: RefCell::default(),
            script_cache: RefCell::default(),
        })
    }

    fn is_file(&self, rel: &str) -> bool {
        self.root.join(rel).is_file()
    }

    /// Tokens -> the tracked FILES they name.
    ///
    /// A path names that file. A BARE file name names every tracked file with that name: it may
    /// be a fixed file read after a `cd`, or a `find -name` pattern, and matching every copy is
    /// the only reading that cannot miss the first. A directory or a glob names nothing here --
    /// it is a set the gate WALKS. Code directories arrive by another route (`pkg_dirs`).
    pub fn resolve<'a>(&self, toks: impl IntoIterator<Item = &'a str>) -> BTreeSet<String> {
        let mut want = BTreeSet::new();
        for t in toks {
            let t = t.trim_end_matches('/');
            let t = t.strip_prefix("./").unwrap_or(t);
            if !t.is_empty() {
                want.insert(t.to_string());
            }
        }
        let mut out = BTreeSet::new();
        for t in &want {
            if self.files.contains(t) {
                out.insert(t.clone());
            }
            if !t.contains('/') && !t.contains('*') && !t.contains('?') {
                if let Some(paths) = self.by_base.get(t) {
                    out.extend(paths.iter().cloned());
                }
            }
        }
        out
    }

    /// Tokens that look like a repo path -- they begin with a tracked top-level directory -- and
    /// name nothing tracked. A gate that reads a path this cannot resolve has an input this
    /// cannot see; the self-test fails on them for PROBED gates rather than let the set shrink.
    pub fn unresolved(&self, rel: &str) -> Vec<String> {
        let text = fs::read_to_string(self.root.join(rel)).unwrap_or_default();
        let mut out = Vec::new();
        for t in shell_tokens(&text) {
            let t = t.strip_suffix('/').unwrap_or(&t);
            let Some((top, _)) = t.split_once('/') else {
                continue;
            };
            if !self.dirs.contains(top) {
                continue;
            }
            if t.contains(['*', '?', '{', '}']) {
                continue;
            }
            if self.files.contains(t) || self.dirs.contains(t) {
                continue;
            }
            out.push(t.to_string());
        }
        out
    }

    /// A package and its path-dependency closure, as package directories.
    fn pkg_dirs(&self, name: &str) -> Vec<String> {
        if let Some(hit) = self.pkg_cache.borrow().get(name) {
            return hit.clone();
        }
        let mut out = Vec::new();
        let mut queue: VecDeque<String> = VecDeque::new();
        if let Some((_, d)) = self.pkgs.iter().find(|(n, _)| n == name) {
            queue.push_back(d.clone());
        }
        let mut seen = BTreeSet::new();
        while let Some(d) = queue.pop_front() {
            if !seen.insert(d.clone()) {
                continue;
            }
            out.push(d.clone());
            let manifest = format!("{d}/Cargo.toml");
            let Ok(text) = fs::read_to_string(self.root.join(&manifest)) else {
                continue;
            };
            for cap in regex!(r#"path[[:space:]]*=[[:space:]]*"([^"]+)""#).captures_iter(&text) {
                let p = norm(&format!("{d}/{}", &cap[1]));
                // `[lib] path = "src/lib.rs"` also matches; only a directory with a manifest is
                // a dependency.
                if self.is_file(&format!("{p}/Cargo.toml")) {
                    queue.push_back(p);
                }
            }
        }
        self.pkg_cache
            .borrow_mut()
            .insert(name.to_string(), out.clone());
        out
    }

    /// Every package a line of shell names, with how much of it is read.
    pub fn cargo_inputs(&self, text: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        for line in text.lines() {
            if regex!(r"^[[:space:]]*#").is_match(line) {
                continue;
            }
            if !regex!(r"(^|[^A-Za-z0-9_-])cargo[[:space:]]").is_match(line) {
                continue;
            }
            let manifest_only = regex!(r"cargo[[:space:]]+(tree|metadata)").is_match(line);
            out.extend(CARGO_COMMON.iter().map(|s| (*s).to_string()));
            let mut names = BTreeSet::new();
            for m in regex!(r"(-p|--package)[[:space:]=]+[A-Za-z0-9_-]+").find_iter(line) {
                let s = regex!(r"^(-p|--package)[[:space:]=]+").replace(m.as_str(), "");
                names.insert(s.into_owned());
            }
            for m in regex!(r"--manifest-path[[:space:]=]+[^[:space:]]+").find_iter(line) {
                let s = regex!(r"^--manifest-path[[:space:]=]+").replace(m.as_str(), "");
                let s = s.replace('"', "");
                let s = regex!(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/").replace(&s, "");
                let dir = dirname(&s);
                for (n, d) in &self.pkgs {
                    if *d == dir {
                        names.insert(n.clone());
                    }
                }
            }
            for n in &names {
                for d in self.pkg_dirs(n) {
                    out.insert(if manifest_only {
                        format!("{d}/Cargo.toml")
                    } else {
                        format!("{d}/")
                    });
                }
            }
            // `--workspace` is every package: no closure to walk.
            if line.contains("--workspace") {
                if manifest_only {
                    out.extend(
                        self.files
                            .iter()
                            .filter(|f| *f == "Cargo.toml" || f.ends_with("/Cargo.toml"))
                            .cloned(),
                    );
                } else {
                    out.extend(self.pkgs.iter().map(|(_, d)| format!("{d}/")));
                }
            }
            for cap in regex!(r"xtask -- ([a-z][a-z-]*)").captures_iter(line) {
                out.extend(self.xtask_inputs(&cap[1]));
            }
        }
        out
    }

    /// An xtask subcommand: the xtask package closure, plus the paths its module names.
    ///
    /// The module is `crates/xtask/src/<sub_with_underscores>.rs`, else the longest leading
    /// part of the name that is one (`scoreboard-ratchet` -> scoreboard.rs), else main.rs. Every
    /// module it reaches by `crate::m` / `super::m` is scanned too, since that is code it runs.
    pub fn xtask_inputs(&self, sub: &str) -> BTreeSet<String> {
        if let Some(hit) = self.xtask_cache.borrow().get(sub) {
            return hit.clone();
        }
        let mut out: BTreeSet<String> = CARGO_COMMON.iter().map(|s| (*s).to_string()).collect();
        out.extend(self.pkg_dirs("xtask").into_iter().map(|d| format!("{d}/")));
        let src = "crates/xtask/src";
        let mut name = sub.replace('-', "_");
        let mut module = None;
        while !name.is_empty() {
            let cand = format!("{src}/{name}.rs");
            if self.is_file(&cand) {
                module = Some(cand);
                break;
            }
            match name.rfind('_') {
                Some(i) => name.truncate(i),
                None => break,
            }
        }
        let mut queue = VecDeque::from([module.unwrap_or_else(|| format!("{src}/main.rs"))]);
        let mut seen = BTreeSet::new();
        while let Some(m) = queue.pop_front() {
            if !seen.insert(m.clone()) {
                continue;
            }
            let Ok(text) = fs::read_to_string(self.root.join(&m)) else {
                continue;
            };
            let lits = self.rust_literals(&m, &text);
            out.extend(self.resolve(lits.iter().map(String::as_str)));
            let mods: BTreeSet<String> = regex!(r"(crate|super)::([a-z_]+)")
                .captures_iter(&text)
                .map(|c| c[2].to_string())
                .collect();
            for n in mods {
                let cand = format!("{src}/{n}.rs");
                if self.is_file(&cand) {
                    queue.push_back(cand);
                }
            }
        }
        self.xtask_cache
            .borrow_mut()
            .insert(sub.to_string(), out.clone());
        out
    }

    /// A gate script: itself, what it names, the scripts it names (transitively), its cargo
    /// packages.
    pub fn script_inputs(&self, gate: &str) -> BTreeSet<String> {
        if let Some(hit) = self.script_cache.borrow().get(gate) {
            return hit.clone();
        }
        let mut out = BTreeSet::new();
        let mut queue = VecDeque::from([gate.to_string()]);
        let mut seen = BTreeSet::new();
        while let Some(f) = queue.pop_front() {
            if !seen.insert(f.clone()) {
                continue;
            }
            if !self.is_file(&f) {
                continue;
            }
            out.insert(f.clone());
            let text = fs::read_to_string(self.root.join(&f)).unwrap_or_default();
            let toks = shell_tokens(&text);
            for r in self.resolve(toks.iter().map(String::as_str)) {
                let globby = r.contains('*') || r.contains('?') || r.ends_with('/');
                if !globby && (r.ends_with(".sh") || r.ends_with(".py")) {
                    queue.push_back(r.clone());
                }
                out.insert(r);
            }
            out.extend(self.cargo_inputs(&text));
        }
        self.script_cache
            .borrow_mut()
            .insert(gate.to_string(), out.clone());
        out
    }

    /// Paths a probe's own Rust functions (its perturbation, its generators) name. They live in
    /// the engine, so they also change only with it -- but a generator that READS a file makes
    /// that file an input of its probe, and the engine changing is not the only way that file
    /// changes. Read from the source of `perturb.rs`, the way `declare -f` read the shell.
    pub fn function_inputs(&self, names: &[&str]) -> BTreeSet<String> {
        let src = super::perturb::SOURCE;
        let mut out = BTreeSet::new();
        for n in names {
            let Some(body) = fn_source(src, n) else {
                continue;
            };
            // Both readings: the shell's token scan (a path inside a longer payload, such as a
            // replacement row naming `scripts/check-ci-spec.sh`) and Rust's string literals.
            let mut toks = shell_tokens(body);
            toks.extend(self.rust_literals("crates/xtask/src/gates_can_fail/perturb.rs", body));
            out.extend(self.resolve(toks.iter().map(String::as_str)));
            out.extend(self.cargo_inputs(body));
        }
        out
    }

    /// Rust string literals from one source file, comment lines dropped. `../`-relative literals
    /// (include_str!) are resolved against the file's own directory, and kept only if they name
    /// a tracked file.
    fn rust_literals(&self, src: &str, text: &str) -> BTreeSet<String> {
        let dir = dirname(src);
        let mut out = BTreeSet::new();
        for line in text.lines() {
            if regex!(r"^[[:space:]]*//").is_match(line) {
                continue;
            }
            for m in regex!(r#""([^"\\]|\\.)*""#).find_iter(line) {
                let s = m.as_str();
                let lit = &s[1..s.len() - 1];
                if !regex!(r"^[A-Za-z0-9_./*?-]+$").is_match(lit) {
                    continue;
                }
                if lit.starts_with("../") {
                    let p = norm(&format!("{dir}/{lit}"));
                    if self.files.contains(&p) {
                        out.insert(p);
                    }
                } else {
                    out.insert(lit.strip_prefix("./").unwrap_or(lit).to_string());
                }
            }
        }
        out
    }
}

/// The `[package] name` of a manifest, as the shell's awk read it: the first `name =` line inside
/// the `[package]` table.
fn package_name(text: &str) -> Option<String> {
    let mut in_pkg = false;
    for line in text.lines() {
        if line.starts_with("[package]") {
            in_pkg = true;
            continue;
        }
        if line.starts_with('[') {
            in_pkg = false;
        }
        if in_pkg && regex!(r"^name[[:space:]]*=").is_match(line) {
            let v = line.split_once('"').map_or("", |(_, r)| r);
            let v = v.split_once('"').map_or(v, |(l, _)| l);
            return Some(v.to_string());
        }
    }
    None
}

/// Collapse `a/b/../c` and `./` segments. Paths here are repo-relative.
pub fn norm(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    out.join("/")
}

/// `dirname(1)` for a relative path.
fn dirname(p: &str) -> String {
    let p = p.trim_end_matches('/');
    match p.rfind('/') {
        Some(0) => "/".to_string(),
        Some(i) => p[..i].trim_end_matches('/').to_string(),
        None => ".".to_string(),
    }
}

/// The source of `fn <name>` in `src`, from its signature to the closing brace at column 0.
pub fn fn_source<'a>(src: &'a str, name: &str) -> Option<&'a str> {
    let sig = format!("fn {name}(");
    let start = src.find(&sig)?;
    let rest = &src[start..];
    let end = rest.find("\n}\n").map_or(rest.len(), |i| i + 3);
    Some(&rest[..end])
}

/// Candidate path tokens from one shell file: comment lines and trailing ` # ` comments dropped,
/// and the right-hand side of a pattern match (`[[ "$f" == scripts/*.sh ]]`) dropped too -- a
/// glob a gate COMPARES against is not a set of files it reads.
///
/// `grep -oE` is POSIX leftmost-LONGEST; `regex` is leftmost-first. The two alternatives are
/// therefore tried separately at each position and the longer one kept, which is what makes
/// this token-for-token the shell's (compared over every probed gate when it was ported).
pub fn shell_tokens(text: &str) -> BTreeSet<String> {
    let path_alt = regex!(
        r#"^(\$\(dirname "?\$0"?\)/(\.\./)?|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/)?[A-Za-z0-9_.*?-]*(/[A-Za-z0-9_.*?{}-]+)+/?"#
    );
    let name_alt = regex!(
        r"^\.?[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*\.(sh|py|txt|toml|json|md|lean|yml|yaml|lock|rs|writ)"
    );
    let mut out = BTreeSet::new();
    for line in text.lines() {
        if regex!(r"^[[:space:]]*(#|//)").is_match(line) {
            continue;
        }
        let line = regex!(r"[[:space:]]#[[:space:]].*$").replace(line, "");
        let line = regex!(r#"[=!]=[[:space:]]*"?[^ ]*"#).replace_all(&line, "");
        let mut pos = 0;
        while pos < line.len() {
            if !line.is_char_boundary(pos) {
                pos += 1;
                continue;
            }
            let rest = &line[pos..];
            let a = path_alt.find(rest).map_or(0, |m| m.end());
            let b = name_alt.find(rest).map_or(0, |m| m.end());
            let len = a.max(b);
            if len == 0 {
                pos += 1;
                continue;
            }
            let tok = &rest[..len];
            pos += len;
            let tok = regex!(r#"^\$\(dirname "?\$0"?\)/\.\./"#).replace(tok, "");
            let tok = regex!(r#"^\$\(dirname "?\$0"?\)/"#).replace(&tok, "scripts/");
            let tok = regex!(r"^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/").replace(&tok, "");
            let tok = tok.strip_prefix("./").unwrap_or(&tok);
            let tok = regex!(r"[.]+$").replace(tok, "");
            out.insert(tok.into_owned());
        }
    }
    out
}

/// Does a changed file fall under an input pathspec?
pub fn matches(spec: &str, f: &str) -> bool {
    if spec.ends_with('/') {
        f.starts_with(spec)
    } else if spec.contains('*') || spec.contains('?') {
        glob_match(spec.as_bytes(), f.as_bytes())
    } else {
        spec == f
    }
}

/// A shell `case`/`[[ == ]]` pattern: `*` and `?` match across `/`.
fn glob_match(p: &[u8], s: &[u8]) -> bool {
    match p.split_first() {
        None => s.is_empty(),
        Some((b'*', rest)) => (0..=s.len()).any(|i| glob_match(rest, &s[i..])),
        Some((b'?', rest)) => !s.is_empty() && glob_match(rest, &s[1..]),
        Some((c, rest)) => s.first() == Some(c) && glob_match(rest, &s[1..]),
    }
}

/// The first changed path that falls under an input: `(changed, input)`.
pub fn first_hit(inputs: &BTreeSet<String>, changed: &[String]) -> Option<(String, String)> {
    for f in changed.iter().filter(|f| !f.is_empty()) {
        for p in inputs.iter().filter(|p| !p.is_empty()) {
            if matches(p, f) {
                return Some((f.clone(), p.clone()));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn norm_collapses_dot_and_dotdot() {
        assert_eq!(norm("crates/a/../b/./c"), "crates/b/c");
        assert_eq!(norm("./x"), "x");
    }

    #[test]
    fn dirname_matches_coreutils() {
        assert_eq!(dirname("crates/x/Cargo.toml"), "crates/x");
        assert_eq!(dirname("Cargo.toml"), ".");
    }

    #[test]
    fn a_directory_spec_matches_under_it_and_a_glob_crosses_slashes() {
        assert!(matches("crates/xtask/", "crates/xtask/src/main.rs"));
        assert!(!matches("crates/xtask/", "crates/xtask2/src/main.rs"));
        assert!(matches("crates/*.rs", "crates/a/b.rs"));
        assert!(matches("Cargo.lock", "Cargo.lock"));
        assert!(!matches("Cargo.lock", "x/Cargo.lock"));
    }

    #[test]
    fn tokens_take_the_longer_alternative_like_posix_grep() {
        // `name.sh` alone matches the bare-name alternative; `scripts/name.sh` the path one,
        // which is longer and must win at the same start.
        let t = shell_tokens("bash scripts/name.sh --x\n");
        assert!(t.contains("scripts/name.sh"), "{t:?}");
        assert!(!t.contains("name.sh"), "{t:?}");
    }

    #[test]
    fn tokens_drop_comments_and_compared_globs() {
        let t = shell_tokens("# scripts/a.sh\nx=1 # scripts/b.sh\n[[ \"$f\" == scripts/*.sh ]]\n");
        assert!(t.is_empty(), "{t:?}");
    }

    #[test]
    fn tokens_rewrite_the_dirname_prefix_only_when_a_path_follows_it() {
        // Measured against GNU grep 3.11 and the shell derivation: the prefix needs at least
        // one `/segment` after it, so `$(dirname "$0")/lib.sh` and `$(dirname "$0")/..` match
        // only from their slash.
        let t = shell_tokens("x $(dirname $0)/foo/bar.sh\n");
        assert!(t.contains("scripts/foo/bar.sh"), "{t:?}");
        let t = shell_tokens("source \"$(dirname \"$0\")/lib.sh\"\ncd \"$(dirname \"$0\")/..\"\n");
        assert_eq!(
            t,
            BTreeSet::from(["/lib.sh".to_string(), "/".to_string()]),
            "{t:?}"
        );
    }

    #[test]
    fn fn_source_stops_at_the_closing_brace() {
        let src = "fn a(x: u8) {\n    1\n}\nfn b() {\n}\n";
        assert_eq!(fn_source(src, "a"), Some("fn a(x: u8) {\n    1\n}\n"));
        assert_eq!(fn_source(src, "c"), None);
    }

    #[test]
    fn a_manifest_names_its_package_only_inside_the_package_table() {
        assert_eq!(
            package_name("[workspace]\nname = \"no\"\n[package]\nname = \"yes\"\n"),
            Some("yes".to_string())
        );
        assert_eq!(package_name("[workspace]\nmembers = []\n"), None);
    }
}
