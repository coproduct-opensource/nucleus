//! `cargo xtask line-ratchet` — the line-count ratchet, split by what decides it.
//!
//! The gate this replaces was a shell script, and the two defects it shipped were
//! both parser defects rather than policy defects:
//!
//! 1. It read `grep '^ceiling' | head -1`, so it enforced only the FIRST `[[files]]`
//!    entry while the config declared several. The others drifted far past their
//!    stated ceilings — `nucleus-tool-proxy/src/main.rs` reached 4975 against a
//!    declared 4118 — and nothing said so.
//! 2. Untracked sibling files were invisible until the sweep was added in 2026-09-03,
//!    so a file could be created already over the default ceiling.
//!
//! Neither is a judgement anyone got wrong. Both are what a program has when it has
//! `awk` and `head -1` instead of a parser. A `for` loop over a parsed `Vec` cannot
//! enforce only its head, and one `Deserialize` struct cannot disagree with itself
//! about which fields exist — so this module is the fix for the *class*, not for the
//! two instances.
//!
//! # The split
//!
//! The two halves of this gate are decided by different things, and saying so is the
//! point rather than a comment:
//!
//! * [`check_declaration`] is decided by `.line-ratchet.toml` **alone**. It touches no
//!   source file and would give the same verdict against an empty checkout. It is the
//!   half where both historical defects lived.
//! * [`check_counts`] is decided by the tree: six declared files plus a sweep of every
//!   `crates/*/src/**/*.rs` (661 of them today). It needs a checkout, and therefore a
//!   machine, and no amount of restructuring changes that.
//!
//! Only the second half has to be scheduled. See gatehouse `docs/tiering.md` for why
//! that distinction is worth a type rather than a paragraph.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

const RATCHET_FILE: &str = ".line-ratchet.toml";

/// `.line-ratchet.toml`, in full. `deny_unknown_fields` is load-bearing on both
/// structs: a key nothing reads is how `[ratchet] ceiling` came to shadow a file
/// entry in the first place, so an unread key is a parse error here rather than a
/// silent decoration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RatchetConfig {
    pub ratchet: Defaults,
    #[serde(default)]
    pub files: Vec<FileEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    /// Applied to every swept file with no `[[files]]` entry of its own.
    pub default_ceiling: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    pub path: String,
    pub ceiling: usize,
    pub target: usize,
    /// How far the post-merge job may lower `ceiling` in one step. Read by
    /// `.github/workflows/line-ratchet.yml`, not by the check — which is exactly why
    /// it is declared here: one parser, so the two readers cannot drift apart about
    /// which fields exist.
    pub step: usize,
}

/// A defect in the declaration itself — decidable with no source tree present.
#[derive(Debug, PartialEq, Eq)]
pub enum DeclarationDefect {
    /// Two `[[files]]` entries naming one path. The second silently shadows the
    /// first under any `head`-shaped reader, and under a correct reader it is simply
    /// ambiguous: `path` must be injective over the entry list.
    DuplicatePath { path: String, count: usize },
}

impl std::fmt::Display for DeclarationDefect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DuplicatePath { path, count } => write!(
                f,
                "{path} has {count} [[files]] entries; `path` must name at most one. \
                 Two entries for one file is how a ceiling gets enforced and ignored \
                 at the same time."
            ),
        }
    }
}

pub fn parse(text: &str) -> Result<RatchetConfig> {
    toml::from_str(text).with_context(|| {
        format!("{RATCHET_FILE} did not parse. Both an unknown key and a missing field are \
                 errors here on purpose: a field nothing reads is a field that can silently \
                 stop mattering, and a field that is absent is a default nobody chose.")
    })
}

/// Tier 0: everything decidable from the declaration, with no tree.
pub fn check_declaration(cfg: &RatchetConfig) -> Vec<DeclarationDefect> {
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for e in &cfg.files {
        *seen.entry(e.path.as_str()).or_insert(0) += 1;
    }
    seen.into_iter()
        .filter(|(_, n)| *n > 1)
        .map(|(path, count)| DeclarationDefect::DuplicatePath {
            path: path.to_string(),
            count,
        })
        .collect()
}

/// Lines, counted the way `wc -l` counts them: newline bytes, so a file with no
/// trailing newline reports one fewer than it has visual lines. Matching the old
/// script exactly matters more here than being right in the abstract — a conversion
/// that changes a ceiling's meaning by one is a conversion that moves the goalposts.
fn count_lines(path: &Path) -> Result<usize> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(bytes.iter().filter(|b| **b == b'\n').count())
}

/// Every `crates/*/src/**/*.rs`, excluding any `target/` directory — the same set the
/// shell sweep found via `find crates -path '*/src/*' -name '*.rs' -not -path '*/target/*'`.
fn swept_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let crates = root.join("crates");
    if !crates.is_dir() {
        bail!("no crates/ directory under {}", root.display());
    }
    walk(&crates, &mut out)?;
    out.retain(|p| {
        let s = p.to_string_lossy();
        s.ends_with(".rs") && s.contains("/src/") && !s.contains("/target/")
    });
    out.sort();
    Ok(out)
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            walk(&path, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}

/// 2b: the half that needs a checkout. Returns the number of violations.
pub fn check_counts(root: &Path, cfg: &RatchetConfig, strict: bool) -> Result<usize> {
    let mut violations = 0usize;

    for e in &cfg.files {
        let path = root.join(&e.path);
        if !path.is_file() {
            // A declared file that does not exist is a declaration defect, but it is
            // only detectable with the tree, so it is reported from this half.
            println!("VIOLATION: {} is declared in {RATCHET_FILE} but does not exist", e.path);
            violations += 1;
            continue;
        }
        let actual = count_lines(&path)?;
        if actual > e.ceiling {
            println!("VIOLATION: {} has {actual} lines (ceiling: {})", e.path, e.ceiling);
            println!("  target:  {} lines", e.target);
            println!("  remaining: {} lines to extract", actual.saturating_sub(e.target));
            violations += 1;
        } else if actual <= e.target {
            println!("TARGET REACHED: {} is at or below {} lines!", e.path, e.target);
        } else {
            println!("OK: {} at {actual} lines (ceiling {})", e.path, e.ceiling);
        }
    }

    let declared: Vec<&str> = cfg.files.iter().map(|e| e.path.as_str()).collect();
    let mut swept = 0usize;
    let mut swept_violations = 0usize;
    for path in swept_files(root)? {
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .to_string();
        if declared.iter().any(|d| *d == rel) {
            continue;
        }
        swept += 1;
        let actual = count_lines(&path)?;
        if actual > cfg.ratchet.default_ceiling {
            println!(
                "VIOLATION: {rel} has {actual} lines (default ceiling: {})",
                cfg.ratchet.default_ceiling
            );
            swept_violations += 1;
            violations += 1;
        }
    }
    if swept_violations == 0 {
        println!("OK: {swept} files swept, all <= {} lines", cfg.ratchet.default_ceiling);
    } else {
        println!(
            "{swept_violations} of {swept} swept files exceed the default ceiling ({})",
            cfg.ratchet.default_ceiling
        );
    }

    if violations > 0 && !strict {
        println!("({violations} violation(s); not --strict, so not failing)");
    }
    Ok(violations)
}

/// Emit the parsed `[[files]]` entries as `path ceiling target step`, one per line.
///
/// This exists so `.github/workflows/line-ratchet.yml` — the post-merge job that
/// lowers a ceiling by its `step` — can stop carrying a second, independently
/// hand-rolled awk parser of this file. Two parsers over one declaration is the
/// `head -1` bug with more steps: they read overlapping but different field sets
/// (the check never read `step`; the workflow never read `default_ceiling`) and
/// nothing held them in agreement. nucleus already treats that shape as a defect
/// worth its own gate for workflow path predicates — `ci/merge-group-scope-parity.sh`
/// — and had no analogue here.
pub fn entries_json() -> Result<()> {
    let root = std::env::current_dir()?;
    let text = fs::read_to_string(root.join(RATCHET_FILE))
        .with_context(|| format!("reading {RATCHET_FILE}"))?;
    let cfg = parse(&text)?;
    let defects = check_declaration(&cfg);
    if !defects.is_empty() {
        for d in &defects {
            eprintln!("DECLARATION DEFECT: {d}");
        }
        bail!("refusing to emit entries from a malformed {RATCHET_FILE}");
    }
    // Plain space-separated fields rather than JSON, because the consumer is a
    // `while read -r FILE_PATH CEILING TARGET STEP` loop and the point of this
    // command is to remove a parser, not to add a second one at the other end.
    for e in &cfg.files {
        println!("{} {} {} {}", e.path, e.ceiling, e.target, e.step);
    }
    Ok(())
}

pub fn check(strict: bool) -> Result<()> {
    let root = std::env::current_dir()?;
    let text = fs::read_to_string(root.join(RATCHET_FILE))
        .with_context(|| format!("reading {RATCHET_FILE}"))?;
    let cfg = parse(&text)?;

    // Tier 0 first, and unconditionally fatal. A malformed declaration makes the
    // count half meaningless, and unlike a line count it costs nothing to check, so
    // there is no reason to let it through even in warn-only mode.
    let defects = check_declaration(&cfg);
    if !defects.is_empty() {
        for d in &defects {
            eprintln!("DECLARATION DEFECT: {d}");
        }
        bail!("{} declaration defect(s) in {RATCHET_FILE}", defects.len());
    }
    if cfg.files.is_empty() {
        bail!("no [[files]] entries in {RATCHET_FILE}");
    }
    println!(
        "declaration OK: {} entries, default ceiling {}",
        cfg.files.len(),
        cfg.ratchet.default_ceiling
    );
    // Not a defect, and deliberately not fatal: `line-ratchet.yml` already clamps its
    // proposal to the current ceiling for exactly this case, because the plain
    // max(actual, ceiling - step, target) would propose a RAISE from a job named
    // "ratchet down". Worth naming out loud so the clamp is not mistaken for dead code.
    for e in cfg.files.iter().filter(|e| e.step > 0 && e.ceiling <= e.target) {
        println!(
            "note: {} has already beaten its target ({} <= {}) and still steps by {}; \
             the ratchet-down job's clamp is what keeps that from raising the ceiling",
            e.path, e.ceiling, e.target, e.step
        );
    }

    let violations = check_counts(&root, &cfg, strict)?;
    if violations > 0 && strict {
        bail!("{violations} line-ratchet violation(s)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
[ratchet]
default_ceiling = 2500

[[files]]
path = "a.rs"
ceiling = 10
target = 5
step = 1
"#;

    #[test]
    fn parses_the_real_config() {
        let text = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.line-ratchet.toml"),
        )
        .expect("repo config present");
        let cfg = parse(&text).expect("the shipped config parses");
        assert!(!cfg.files.is_empty());
        assert!(check_declaration(&cfg).is_empty(), "shipped config is well formed");
    }

    #[test]
    fn duplicate_path_is_a_declaration_defect() {
        let text = format!(
            "{GOOD}\n[[files]]\npath = \"a.rs\"\nceiling = 99\ntarget = 5\nstep = 1\n"
        );
        let cfg = parse(&text).unwrap();
        assert_eq!(
            check_declaration(&cfg),
            vec![DeclarationDefect::DuplicatePath { path: "a.rs".into(), count: 2 }]
        );
    }

    #[test]
    fn an_unread_key_does_not_parse() {
        // The `[ratchet] ceiling` that once shadowed a file entry would land here.
        let text = format!("{GOOD}ceiling = 2479\n");
        assert!(parse(&text).is_err(), "an unknown key must not be accepted silently");
    }

    #[test]
    fn a_missing_field_does_not_parse() {
        let text = "[ratchet]\ndefault_ceiling = 1\n\n[[files]]\npath = \"a.rs\"\nceiling = 1\n";
        assert!(parse(text).is_err(), "an incomplete entry must not be accepted");
    }

    #[test]
    fn declaration_check_needs_no_tree() {
        // The whole claim of the Tier 0 half, as a test: same verdict with no files.
        let cfg = parse(GOOD).unwrap();
        assert!(check_declaration(&cfg).is_empty());
    }

    #[test]
    fn line_count_matches_wc_l() {
        let dir = std::env::temp_dir().join("xtask-line-ratchet-test");
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("no-trailing-newline.rs");
        fs::write(&f, b"one\ntwo").unwrap();
        assert_eq!(count_lines(&f).unwrap(), 1, "wc -l counts newlines, not lines");
        fs::write(&f, b"one\ntwo\n").unwrap();
        assert_eq!(count_lines(&f).unwrap(), 2);
        fs::remove_dir_all(&dir).ok();
    }
}
