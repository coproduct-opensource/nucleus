//! Law-mechanism gate — a mechanism declared dead must still be dead.
//!
//! # The defect this was built from (2026-09-09)
//!
//! An architectural audit asked whether several of nucleus's operational
//! concepts are instances of shared algebraic objects. They mostly are. The
//! finding that mattered was different: **most of those unifications are
//! already built, several are machine-proved, and they are not wired to the
//! enforcement path.**
//!
//! `ProductLattice` — the categorical product — had zero uses. `MeetCap` /
//! `Attenuation`, proved in Lean, had zero production call sites; its only
//! lattice instance is over a type whose own doc says *"nothing on a live path
//! constructs or consults this type"*. `PathLattice::with_work_dir` — the
//! filesystem sandbox root — is constructed by eleven callers, all of them
//! tests, three of which are the adversarial suites that prove path-traversal
//! containment holds. They prove it of a configuration production never builds.
//!
//! The repo already knows this class. `docs/north-star.md` demoted clause C9
//! because "the attested-cert producer is dead-code with its result discarded",
//! and `scripts/check-extracted-callsites.sh` (C8) gates it for the Aeneas
//! predicates: *"a predicate proven about a function nobody calls is a proof
//! about dead code."* What was missing is the general case, and a place to
//! record it that a machine reads.
//!
//! # What this gate checks
//!
//! One class today, `D` — *declared, with no live call site*. For each row the
//! gate asserts, over the production region of every tracked Rust file:
//!
//! 1. `decl_anchor` still appears in the file that declares it (a row whose
//!    mechanism was deleted is stale, and stale rows are themselves a finding —
//!    the same rule `ci/gate-integrity-allowlist.txt` applies to itself);
//! 2. `use_anchor` appears **nowhere else**. A row that becomes wired fails,
//!    and the fix is to delete the row and lower the pin.
//!
//! Two anchors, not one: a definition and its call sites never share a literal.
//! A single anchor let check 1 pass on whatever doc comment happened to mention
//! the qualified name — passing by accident, which is the failure mode this
//! whole gate exists to name.
//!
//! So the list may only shrink, by wiring a mechanism or deleting it. It cannot
//! grow silently: `DEAD_COUNT` is exact, and raising it is a deliberate edit
//! with a dated note, the convention `scripts/north-star-ledger-ratchet.txt`
//! and `.clippy-ratchet.toml` already use.
//!
//! # Why this is not C8
//!
//! C8 asserts an anchor **is** present; this asserts it is **absent**. They are
//! duals over the same scanner, and folding them into one manifest is the right
//! end state — but C8 is a required context with its own probe, and rewriting
//! it in the same change that introduces a new class would put a live gate at
//! risk to save a file. The reader here is Rust, so the merge is cheap later.
//!
//! # Domain
//!
//! `git ls-files`, never a filesystem walk. The repo root contains `wt-2630/`,
//! an untracked worktree copy with a full `crates/` tree; a naive walk counts it
//! and over-reports. That is not hypothetical — the first measurement taken for
//! this gate did exactly that and over-counted `#[allow(dead_code)]` by 64%.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

pub const MANIFEST: &str = "scripts/law-mechanisms-manifest.txt";
pub const DEAD_CODE_RATCHET: &str = ".dead-code-ratchet.toml";

// ─────────────────────────────────────────────────────────────────────────────
// The `#[allow(dead_code)]` ratchet
//
// The manifest above names mechanisms that are dead ON PURPOSE and tracked. This
// counts the ones that are dead and merely TOLERATED — the attribute is how dead
// code survives `-D warnings`, and nothing was counting it.
//
// It rides in this command rather than a sixth gate because it has the same
// subject: a thing declared dead. One command, one shim, one workflow step, one
// prepush entry — and two probes, because a gate covering two properties needs a
// perturbation for each.
// ─────────────────────────────────────────────────────────────────────────────

/// `.dead-code-ratchet.toml`. `deny_unknown_fields` on both structs for the
/// reason `.line-ratchet.toml` records: a key nothing reads must not be able to
/// sit there waiting to be mistaken for one that matters.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeadCodeRatchet {
    /// Ceiling on the whole workspace.
    pub total_ceiling: usize,
    /// Per-crate ceilings. A crate with no entry must have ZERO — otherwise a
    /// crate can grow while another shrinks and the total hides it.
    #[serde(default)]
    pub crates: Vec<CrateCeiling>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrateCeiling {
    pub name: String,
    pub ceiling: usize,
}

/// Count `#[allow(...dead_code...)]` occurrences per crate.
///
/// Counts EVERY tracked `crates/**/*.rs`, tests included: an allowance in a test
/// file is still an allowance, and exempting them would make the number look
/// better by moving debt rather than paying it.
pub fn count_dead_code(files: &BTreeMap<String, String>) -> BTreeMap<String, usize> {
    let mut per_crate: BTreeMap<String, usize> = BTreeMap::new();
    for (path, src) in files {
        let Some(krate) = path
            .strip_prefix("crates/")
            .and_then(|r| r.split('/').next())
        else {
            continue;
        };
        let n = src
            .lines()
            // Must START the line (after indentation). An attribute does; a
            // mention inside a string literal does not — which is not
            // hypothetical: this gate's own unit-test fixtures embed the
            // attribute in string literals, and a `contains` counter scored
            // them, inflating xtask from 5 to 9. A gate that counts its own
            // fixtures is measuring the wrong thing.
            .filter(|l| l.trim_start().starts_with("#[allow(") && l.contains("dead_code"))
            .count();
        if n > 0 {
            *per_crate.entry(krate.to_string()).or_default() += n;
        }
    }
    per_crate
}

/// Decide the ratchet. Returns the violation lines; empty means clean.
pub fn decide_dead_code(
    ratchet: &DeadCodeRatchet,
    counts: &BTreeMap<String, usize>,
) -> Vec<String> {
    let mut bad = Vec::new();
    let total: usize = counts.values().sum();
    if total > ratchet.total_ceiling {
        bad.push(format!(
            "total {total} exceeds ceiling {}. This ratchet only shrinks: pay the debt, \
             or lower nothing and explain in the file why the ceiling rose.",
            ratchet.total_ceiling
        ));
    }
    let declared: BTreeMap<&str, usize> = ratchet
        .crates
        .iter()
        .map(|c| (c.name.as_str(), c.ceiling))
        .collect();

    for (krate, n) in counts {
        match declared.get(krate.as_str()) {
            Some(&ceiling) if *n > ceiling => {
                bad.push(format!("{krate}: {n} exceeds its ceiling {ceiling}"))
            }
            None => bad.push(format!(
                "{krate}: {n} allowance(s) but no [[crates]] entry. A crate with none must \
                 stay at none — otherwise debt moves between crates and the total hides it."
            )),
            _ => {}
        }
    }
    // A declared crate that has dropped to zero should lose its entry, so the
    // list shrinks visibly rather than accumulating satisfied ceilings.
    for c in &ratchet.crates {
        if !counts.contains_key(&c.name) {
            bad.push(format!(
                "{}: declared with ceiling {} but has no allowances left — drop the entry",
                c.name, c.ceiling
            ));
        }
    }
    bad
}

/// One manifest row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// Currently always `D`. Kept as a field so folding C8's A/B/C in later is
    /// a parser change and not a format change.
    pub class: char,
    /// The law or property the mechanism is supposed to serve.
    pub law: String,
    /// Human name of the mechanism.
    pub mechanism: String,
    /// Literal that must appear in the DECLARING file — typically the
    /// definition, e.g. `fn with_isolation`. Separate from `use_anchor`
    /// because a method's definition and its call sites never share a literal:
    /// the file says `fn with_isolation`, callers say `Kernel::with_isolation`.
    /// One anchor for both silently made check 1 pass on doc comments.
    pub decl_anchor: String,
    /// Literal that must appear NOWHERE in any other production region — the
    /// call form, e.g. `Kernel::with_isolation`.
    pub use_anchor: String,
    /// The file that declares it.
    pub file: String,
    /// Why it is dead, and what would close it.
    pub note: String,
}

/// The parsed manifest: rows plus the pinned population.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub rows: Vec<Row>,
    pub dead_count: usize,
}

/// Parse the manifest. Declaration-only: decidable against an empty checkout,
/// which is the half of a gate where this repo's ratchet defects have lived.
pub fn parse(text: &str) -> Result<Manifest> {
    let mut rows = Vec::new();
    let mut dead_count = None;

    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("DEAD_COUNT=") {
            let n: usize = rest
                .trim()
                .parse()
                .with_context(|| format!("line {}: DEAD_COUNT is not a number", lineno + 1))?;
            if dead_count.replace(n).is_some() {
                bail!("line {}: DEAD_COUNT declared twice", lineno + 1);
            }
            continue;
        }
        let cols: Vec<&str> = line.split('|').map(str::trim).collect();
        if cols.len() != 7 {
            bail!(
                "line {}: want 7 columns \
                 `CLASS | LAW | mechanism | decl_anchor | use_anchor | file | note`, got {}",
                lineno + 1,
                cols.len()
            );
        }
        let class = match cols[0] {
            "D" => 'D',
            other => bail!("line {}: unknown class {other:?} (want D)", lineno + 1),
        };
        if cols[1..6].iter().any(|c| c.is_empty()) {
            bail!(
                "line {}: LAW, mechanism, decl_anchor, use_anchor and file are required",
                lineno + 1
            );
        }
        rows.push(Row {
            class,
            law: cols[1].to_string(),
            mechanism: cols[2].to_string(),
            decl_anchor: cols[3].to_string(),
            use_anchor: cols[4].to_string(),
            file: cols[5].to_string(),
            note: cols[6].to_string(),
        });
    }

    let dead_count = dead_count.context(
        "manifest must pin DEAD_COUNT=<n>; an unpinned population can shrink by deleting a row",
    )?;
    if dead_count != rows.len() {
        bail!(
            "DEAD_COUNT={dead_count} but {} class-D rows are declared. The pin is exact on \
             purpose: a slack pin lets a row vanish unnoticed, which is the failure this \
             gate exists to catch.",
            rows.len()
        );
    }
    Ok(Manifest { rows, dead_count })
}

/// Strip `#[cfg(test)]` items and comment lines, leaving the production region.
///
/// Brace-balanced, the same shape `scripts/check-mediation.sh` and
/// `scripts/check-extracted-callsites.sh` use — deliberately, so the three
/// gates agree on what "production" means rather than each deciding for itself.
pub fn production_region(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut skipping = false;
    let mut depth: i32 = 0;
    let mut pending = false;

    for line in src.lines() {
        let opens = line.matches('{').count() as i32;
        let closes = line.matches('}').count() as i32;

        if skipping {
            depth += opens - closes;
            if depth <= 0 {
                skipping = false;
                depth = 0;
            }
            continue;
        }
        if line.contains("#[cfg(test)]") {
            pending = true;
            continue;
        }
        if pending {
            if opens > 0 {
                skipping = true;
                depth = opens - closes;
                pending = false;
                if depth <= 0 {
                    skipping = false;
                    depth = 0;
                }
                continue;
            }
            if line.contains(';') {
                pending = false;
            }
            continue;
        }
        if line.trim_start().starts_with("//") {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Is this tracked path part of the production surface?
///
/// Test files are excluded wholesale — a mechanism used only by `tests/` is
/// exactly what this gate is looking for, so counting them would make every row
/// look wired.
pub fn is_production_path(path: &str) -> bool {
    if !path.ends_with(".rs") || !path.starts_with("crates/") {
        return false;
    }
    let excluded = ["/tests/", "/benches/", "/examples/", "/fuzz/"];
    if excluded.iter().any(|seg| path.contains(seg)) {
        return false;
    }
    !Path::new(path)
        .file_name()
        .and_then(|f| f.to_str())
        .is_some_and(|f| f.ends_with("_tests.rs"))
}

/// The verdict for one row: where its anchor was seen, outside its own file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub mechanism: String,
    pub kind: FindingKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingKind {
    /// The anchor is gone from the declaring file — the row is stale.
    Stale { file: String, anchor: String },
    /// The declaring file is not tracked.
    MissingFile { file: String },
    /// The anchor now appears in production elsewhere: it got wired.
    NowWired { sites: Vec<String> },
}

/// Decide the manifest against a corpus of `path -> source` pairs.
///
/// Pure: the caller supplies the corpus, so the whole decision is testable
/// without a checkout.
pub fn decide(manifest: &Manifest, corpus: &BTreeMap<String, String>) -> Vec<Finding> {
    let mut findings = Vec::new();

    for row in &manifest.rows {
        let Some(declaring) = corpus.get(&row.file) else {
            findings.push(Finding {
                mechanism: row.mechanism.clone(),
                kind: FindingKind::MissingFile {
                    file: row.file.clone(),
                },
            });
            continue;
        };
        if !production_region(declaring).contains(&row.decl_anchor) {
            findings.push(Finding {
                mechanism: row.mechanism.clone(),
                kind: FindingKind::Stale {
                    file: row.file.clone(),
                    anchor: row.decl_anchor.clone(),
                },
            });
            continue;
        }

        let mut sites = Vec::new();
        for (path, src) in corpus {
            // The domain rule lives HERE, with the decision, not only in the
            // corpus builder. A caller that hands over a wider corpus — a
            // future refactor, a test — must not be able to widen what counts
            // as production by accident.
            if path == &row.file || !is_production_path(path) {
                continue;
            }
            for (i, line) in production_region(src).lines().enumerate() {
                if line.contains(&row.use_anchor) {
                    sites.push(format!("{path}:{}", i + 1));
                }
            }
        }
        if !sites.is_empty() {
            findings.push(Finding {
                mechanism: row.mechanism.clone(),
                kind: FindingKind::NowWired { sites },
            });
        }
    }
    findings
}

/// Read tracked `crates/**/*.rs` matching `keep`. `git ls-files`, never a
/// filesystem walk — see the module doc for why that distinction is load-bearing.
fn tracked(keep: fn(&str) -> bool) -> Result<BTreeMap<String, String>> {
    let out = std::process::Command::new("git")
        .args(["ls-files", "-z", "crates"])
        .output()
        .context("running `git ls-files`")?;
    if !out.status.success() {
        bail!("`git ls-files` failed; the file domain must come from git, not a directory walk");
    }
    let mut corpus = BTreeMap::new();
    for path in String::from_utf8_lossy(&out.stdout).split('\0') {
        if path.is_empty() || !keep(path) {
            continue;
        }
        if let Ok(src) = std::fs::read_to_string(path) {
            corpus.insert(path.to_string(), src);
        }
    }
    if corpus.is_empty() {
        bail!("no tracked Rust files found; the scan would be vacuous");
    }
    Ok(corpus)
}

/// Every tracked Rust file under `crates/`, tests included.
fn is_any_crate_rs(path: &str) -> bool {
    path.starts_with("crates/") && path.ends_with(".rs")
}

/// Run the gate. Exit code is the caller's (`0` clean, `1` violation).
pub fn run() -> Result<i32> {
    let text = std::fs::read_to_string(MANIFEST).with_context(|| format!("reading {MANIFEST}"))?;
    let manifest = parse(&text)?;
    let corpus = tracked(is_production_path)?;

    let findings = decide(&manifest, &corpus);

    // Second property, same subject: the tolerated dead code, counted.
    let ratchet_text = std::fs::read_to_string(DEAD_CODE_RATCHET)
        .with_context(|| format!("reading {DEAD_CODE_RATCHET}"))?;
    let ratchet: DeadCodeRatchet =
        toml::from_str(&ratchet_text).with_context(|| format!("parsing {DEAD_CODE_RATCHET}"))?;
    let counts = count_dead_code(&tracked(is_any_crate_rs)?);
    let dead_code_violations = decide_dead_code(&ratchet, &counts);

    if findings.is_empty() && dead_code_violations.is_empty() {
        println!(
            "OK: {} declared-dead mechanism(s) are still dead, across {} production files.",
            manifest.dead_count,
            corpus.len()
        );
        println!(
            "     A row leaving this list means the mechanism was wired or deleted — both good."
        );
        println!(
            "OK: {} #[allow(dead_code)] allowance(s) across {} crate(s), all within ceiling.",
            counts.values().sum::<usize>(),
            counts.len()
        );
        return Ok(0);
    }

    if !dead_code_violations.is_empty() {
        println!(
            "FAIL: {} dead-code ratchet violation(s).",
            dead_code_violations.len()
        );
        for v in &dead_code_violations {
            println!("  {v}");
        }
    }
    if findings.is_empty() {
        return Ok(1);
    }

    println!("FAIL: {} law-mechanism finding(s).", findings.len());
    for f in &findings {
        match &f.kind {
            FindingKind::MissingFile { file } => println!(
                "  {}: declaring file {file} is not tracked — fix the row or drop it",
                f.mechanism
            ),
            FindingKind::Stale { file, anchor } => println!(
                "  {}: anchor {anchor:?} no longer appears in {file}. The mechanism was renamed or \
                 deleted; drop the row and lower DEAD_COUNT.",
                f.mechanism
            ),
            FindingKind::NowWired { sites } => {
                println!(
                    "  {}: declared dead but now has {} production call site(s) — drop the row and \
                     lower DEAD_COUNT:",
                    f.mechanism,
                    sites.len()
                );
                for s in sites.iter().take(5) {
                    println!("      {s}");
                }
            }
        }
    }
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus_of(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(p, s)| ((*p).to_string(), (*s).to_string()))
            .collect()
    }

    const ONE_ROW: &str = "D | attenuation | MeetCap | struct MeetCap | MeetCap( | \
         crates/a/src/lib.rs | proved, never called\nDEAD_COUNT=1\n";

    #[test]
    fn parses_a_row_and_its_pin() {
        let m = parse(ONE_ROW).expect("parses");
        assert_eq!(m.dead_count, 1);
        assert_eq!(m.rows[0].law, "attenuation");
        assert_eq!(m.rows[0].class, 'D');
    }

    #[test]
    fn the_pin_is_exact_in_both_directions() {
        // Slack in either direction lets a row vanish or appear unnoticed.
        let high = ONE_ROW.replace("DEAD_COUNT=1", "DEAD_COUNT=2");
        assert!(parse(&high).is_err(), "a pin above the row count must fail");
        let low =
            format!("{ONE_ROW}D | x | Other | struct Other | Other( | crates/a/src/lib.rs | n\n");
        assert!(parse(&low).is_err(), "a pin below the row count must fail");
    }

    #[test]
    fn an_unpinned_manifest_is_refused() {
        let no_pin =
            "D | attenuation | MeetCap | struct MeetCap | MeetCap( | crates/a/src/lib.rs | n\n";
        assert!(parse(no_pin).is_err());
    }

    #[test]
    fn a_dead_mechanism_is_clean() {
        let m = parse(ONE_ROW).unwrap();
        let c = corpus_of(&[
            ("crates/a/src/lib.rs", "pub struct MeetCap;"),
            ("crates/b/src/lib.rs", "fn unrelated() {}"),
        ]);
        assert!(decide(&m, &c).is_empty());
    }

    #[test]
    fn a_wired_mechanism_fails_and_names_the_site() {
        let m = parse(ONE_ROW).unwrap();
        let c = corpus_of(&[
            ("crates/a/src/lib.rs", "pub struct MeetCap;"),
            ("crates/b/src/lib.rs", "fn f() { let _ = MeetCap(x); }"),
        ]);
        let f = decide(&m, &c);
        assert_eq!(f.len(), 1);
        match &f[0].kind {
            FindingKind::NowWired { sites } => assert_eq!(sites, &["crates/b/src/lib.rs:1"]),
            other => panic!("want NowWired, got {other:?}"),
        }
    }

    #[test]
    fn a_renamed_or_deleted_mechanism_is_a_stale_row() {
        let m = parse(ONE_ROW).unwrap();
        let c = corpus_of(&[("crates/a/src/lib.rs", "pub struct Renamed;")]);
        assert!(matches!(decide(&m, &c)[0].kind, FindingKind::Stale { .. }));
    }

    /// The whole point of the class: a mechanism reachable only from tests is
    /// DEAD, and must stay on the list. This is `PathLattice::with_work_dir` —
    /// eleven callers, every one a test, three of them adversarial suites
    /// proving containment of a configuration production never builds.
    #[test]
    fn test_only_use_does_not_count_as_wired() {
        let m = parse(ONE_ROW).unwrap();
        let c = corpus_of(&[
            ("crates/a/src/lib.rs", "pub struct MeetCap;"),
            ("crates/a/tests/it.rs", "fn t() { let _ = MeetCap(x); }"),
            (
                "crates/b/src/lib.rs",
                "#[cfg(test)]\nmod tests {\n    fn t() { let _ = MeetCap; }\n}\n",
            ),
            (
                "crates/b/src/thing_tests.rs",
                "fn t() { let _ = MeetCap(x); }",
            ),
        ]);
        assert!(
            decide(&m, &c).is_empty(),
            "tests/, #[cfg(test)] blocks and *_tests.rs are not production"
        );
    }

    #[test]
    fn a_commented_mention_does_not_count_as_wired() {
        let m = parse(ONE_ROW).unwrap();
        let c = corpus_of(&[
            ("crates/a/src/lib.rs", "pub struct MeetCap;"),
            (
                "crates/b/src/lib.rs",
                "// see MeetCap( for the law\nfn f() {}",
            ),
        ]);
        assert!(decide(&m, &c).is_empty());
    }

    // ── the #[allow(dead_code)] ratchet ─────────────────────────────────

    fn ratchet(total: usize, crates: &[(&str, usize)]) -> DeadCodeRatchet {
        DeadCodeRatchet {
            total_ceiling: total,
            crates: crates
                .iter()
                .map(|(n, c)| CrateCeiling {
                    name: (*n).to_string(),
                    ceiling: *c,
                })
                .collect(),
        }
    }

    #[test]
    fn counts_allowances_per_crate_including_tests() {
        let files = corpus_of(&[
            ("crates/a/src/lib.rs", "#[allow(dead_code)]\nfn x() {}"),
            // A multi-lint allow still allows dead code, and still counts.
            (
                "crates/a/src/other.rs",
                "#[allow(dead_code, unused)]\nfn y() {}",
            ),
            // Tests count: exempting them would make the number look better by
            // moving debt rather than paying it.
            ("crates/a/tests/it.rs", "#[allow(dead_code)]\nfn z() {}"),
            ("crates/b/src/lib.rs", "fn clean() {}"),
        ]);
        let counts = count_dead_code(&files);
        assert_eq!(counts.get("a"), Some(&3));
        assert_eq!(
            counts.get("b"),
            None,
            "a crate with none is absent, not zero"
        );
    }

    #[test]
    fn a_crate_over_its_ceiling_fails() {
        let counts = [("a".to_string(), 4usize)].into_iter().collect();
        let bad = decide_dead_code(&ratchet(10, &[("a", 3)]), &counts);
        assert_eq!(bad.len(), 1);
        assert!(bad[0].contains("exceeds its ceiling 3"), "{}", bad[0]);
    }

    /// The reason per-crate ceilings exist at all. Moving five allowances from
    /// one crate to another leaves the total untouched, so a global-only
    /// ceiling would call this clean.
    #[test]
    fn debt_cannot_be_laundered_between_crates() {
        let declared = ratchet(10, &[("a", 10), ("b", 0)]);
        let counts = [("a".to_string(), 5usize), ("b".to_string(), 5usize)]
            .into_iter()
            .collect();
        let bad = decide_dead_code(&declared, &counts);
        assert!(
            !bad.is_empty(),
            "the total is unchanged at 10; only the per-crate rule can see this"
        );
        assert!(bad.iter().any(|v| v.starts_with("b: 5")), "{bad:?}");
    }

    #[test]
    fn a_crate_with_no_entry_may_not_acquire_allowances() {
        let counts = [("newcomer".to_string(), 1usize)].into_iter().collect();
        let bad = decide_dead_code(&ratchet(10, &[]), &counts);
        assert_eq!(bad.len(), 1);
        assert!(bad[0].contains("no [[crates]] entry"), "{}", bad[0]);
    }

    #[test]
    fn a_crate_that_reached_zero_must_drop_its_entry() {
        // Otherwise the list accumulates satisfied ceilings and stops shrinking
        // visibly, which is how a ratchet quietly stops meaning anything.
        let bad = decide_dead_code(&ratchet(10, &[("done", 3)]), &BTreeMap::new());
        assert_eq!(bad.len(), 1);
        assert!(bad[0].contains("drop the entry"), "{}", bad[0]);
    }

    #[test]
    fn the_total_ceiling_binds_too() {
        let counts = [("a".to_string(), 9usize)].into_iter().collect();
        let bad = decide_dead_code(&ratchet(5, &[("a", 9)]), &counts);
        assert!(
            bad.iter().any(|v| v.contains("total 9 exceeds ceiling 5")),
            "{bad:?}"
        );
    }

    #[test]
    fn the_shipped_ratchet_parses() {
        // The parser rejects unknown keys, so this also pins that the shipped
        // file has no field nothing reads — the trap .line-ratchet.toml records.
        let text = std::fs::read_to_string("../../.dead-code-ratchet.toml")
            .or_else(|_| std::fs::read_to_string(".dead-code-ratchet.toml"))
            .expect("the shipped ratchet is readable from the crate or repo root");
        let r: DeadCodeRatchet = toml::from_str(&text).expect("shipped ratchet parses");
        assert!(r.total_ceiling > 0);
        assert!(!r.crates.is_empty());
    }

    #[test]
    fn the_worktree_copy_is_outside_the_domain() {
        // wt-2630/ is an untracked worktree copy in the repo root with a full
        // crates/ tree. `git ls-files` excludes it; this pins the path filter
        // so a future refactor cannot quietly widen the domain to a walk.
        assert!(!is_production_path("wt-2630/crates/a/src/lib.rs"));
        assert!(is_production_path("crates/a/src/lib.rs"));
        assert!(!is_production_path("crates/a/tests/it.rs"));
        assert!(!is_production_path("crates/a/src/foo_tests.rs"));
        assert!(!is_production_path("crates/a/src/lib.md"));
    }
}
