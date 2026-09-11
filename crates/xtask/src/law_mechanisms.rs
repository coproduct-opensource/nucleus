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
    /// `D` — declared, with no live call site.
    /// `W` — wired: the mechanism IS called, and the row exists because the
    ///       concern in its note is something OTHER than "nobody calls it".
    ///       Its check is the dual of D's: the use-anchor must appear, and a
    ///       W row whose call site disappears is a finding, because a note
    ///       about live code silently becomes a note about dead code.
    ///
    /// Folding C8's A/B/C in later stays a parser change, not a format change.
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
    /// Pinned population of class-D rows.
    pub dead_count: usize,
    /// Pinned population of class-W rows. Pinned for DEAD_COUNT's reason: an
    /// unpinned population can shrink by deleting a row, which is the failure
    /// this gate exists to catch, and it does not become less true for a
    /// different class.
    pub wired_count: usize,
}

/// Parse the manifest. Declaration-only: decidable against an empty checkout,
/// which is the half of a gate where this repo's ratchet defects have lived.
pub fn parse(text: &str) -> Result<Manifest> {
    let mut rows = Vec::new();
    let mut dead_count = None;
    let mut wired_count = None;

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
        if let Some(rest) = line.strip_prefix("WIRED_COUNT=") {
            let n: usize = rest
                .trim()
                .parse()
                .with_context(|| format!("line {}: WIRED_COUNT is not a number", lineno + 1))?;
            if wired_count.replace(n).is_some() {
                bail!("line {}: WIRED_COUNT declared twice", lineno + 1);
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
            "W" => 'W',
            other => bail!("line {}: unknown class {other:?} (want D or W)", lineno + 1),
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
    let wired_count = wired_count.context(
        "manifest must pin WIRED_COUNT=<n>; DEAD_COUNT's reasoning does not stop applying \
         because the class changed",
    )?;
    let declared_dead = rows.iter().filter(|r| r.class == 'D').count();
    let declared_wired = rows.iter().filter(|r| r.class == 'W').count();
    if dead_count != declared_dead {
        bail!(
            "DEAD_COUNT={dead_count} but {declared_dead} class-D rows are declared. The pin is \
             exact on purpose: a slack pin lets a row vanish unnoticed, which is the failure \
             this gate exists to catch."
        );
    }
    if wired_count != declared_wired {
        bail!(
            "WIRED_COUNT={wired_count} but {declared_wired} class-W rows are declared. Exact, \
             for DEAD_COUNT's reason."
        );
    }
    Ok(Manifest {
        rows,
        dead_count,
        wired_count,
    })
}

/// Strip `#[cfg(test)]` items and comment lines, leaving the production region.
///
/// Brace-balanced, the same shape `scripts/check-mediation.sh` and
/// `scripts/check-extracted-callsites.sh` use — deliberately, so the three
/// gates agree on what "production" means rather than each deciding for itself.
///
/// **Stripped lines are BLANKED, not dropped**, so line N of the result is line
/// N of the source. Every consumer tests the result with `contains`, so a blank
/// line changes no verdict — but it does change the line numbers a finding
/// reports, which were previously indices into the stripped region and
/// therefore pointed at the wrong source line. A gate that names the wrong line
/// spends a reader's attention before it spends their judgement.
pub fn production_region(src: &str) -> String {
    let mut out = String::with_capacity(src.len());
    let mut skipping = false;
    let mut depth: usize = 0;
    let mut pending = false;

    for line in src.lines() {
        let opens = line.matches('{').count();
        let closes = line.matches('}').count();

        if skipping {
            depth = depth.saturating_add(opens).saturating_sub(closes);
            if depth == 0 {
                skipping = false;
            }
            out.push('\n');
            continue;
        }
        if line.contains("#[cfg(test)]") {
            pending = true;
            out.push('\n');
            continue;
        }
        if pending {
            if opens > 0 {
                skipping = true;
                depth = opens.saturating_sub(closes);
                pending = false;
                if depth == 0 {
                    skipping = false;
                }
                out.push('\n');
                continue;
            }
            if line.contains(';') {
                pending = false;
            }
            out.push('\n');
            continue;
        }
        if line.trim_start().starts_with("//") {
            out.push('\n');
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
    /// A class-W row whose use-anchor appears nowhere in production. The dual
    /// of `NowWired`: a mechanism recorded as WIRED has lost its only call
    /// site, so whatever the row's note says about it is now about dead code.
    NoLongerWired { anchor: String },
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

        // The declaring file, for the `Self::` spelling only, and only inside
        // an `impl` of the row's own type. See [`self_anchor`] for why this one
        // alternate and nothing else, and [`self_sites`] for why the impl
        // scoping is not optional.
        if let (Some(alt), Some(ty)) = (self_anchor(&row.use_anchor), anchor_type(&row.use_anchor))
        {
            for line_no in self_sites(&production_region(declaring), &ty, &alt) {
                sites.push(format!("{}:{line_no} (as `{alt}`)", row.file));
            }
        }

        match row.class {
            'W' => {
                if sites.is_empty() {
                    findings.push(Finding {
                        mechanism: row.mechanism.clone(),
                        kind: FindingKind::NoLongerWired {
                            anchor: row.use_anchor.clone(),
                        },
                    });
                }
            }
            _ => {
                if !sites.is_empty() {
                    findings.push(Finding {
                        mechanism: row.mechanism.clone(),
                        kind: FindingKind::NowWired { sites },
                    });
                }
            }
        }
    }
    findings
}

/// The `Self::` spelling of a `Type::method(` use-anchor, if it has one.
///
/// # The defect this closes
///
/// `Kernel::with_isolation` was declared class D — *no live call site* — and
/// the gate agreed, for two years of commits. `crates/portcullis/src/kernel.rs`
/// calls it from `Kernel::new` as `Self::with_isolation(..)`, which the anchor
/// `Kernel::with_isolation(` cannot match, in a file the use-anchor scan skips
/// anyway. Two holes stacked, and the row read as true.
///
/// # Why only this one alternate, and only in the declaring file
///
/// The declaring-file skip is RIGHT for the raw anchor and stays: a row whose
/// use-anchor is a bare type name (`ProvenanceDAG`) matches its own `impl
/// ProvenanceDAG` block, so scanning the declaring file for it would report
/// every such row as wired. `Self::method(` has no such ambiguity — inside the
/// declaring file it can only mean that type's method.
///
/// What is deliberately NOT added: the receiver form `.method(`. Resolving
/// `x.with_isolation()` needs the type of `x`, and a grep gate does not have
/// it; matching `.new(` or `.push(` textually would report half the tree as
/// wired. A false "now wired" is a wrong red, which costs more than the hole.
/// That is the question `cargo xtask reach-export` exists to answer, and the
/// answer is not a string search.
fn self_anchor(use_anchor: &str) -> Option<String> {
    let (_ty, method) = use_anchor.rsplit_once("::")?;
    if method.is_empty() {
        // A bare `Type::` anchor names the type, not a method.
        return None;
    }
    Some(format!("Self::{method}"))
}

/// The type named by a `Type::method(` use-anchor.
fn anchor_type(use_anchor: &str) -> Option<String> {
    let (ty, method) = use_anchor.rsplit_once("::")?;
    if method.is_empty() || ty.is_empty() {
        return None;
    }
    Some(ty.to_string())
}

/// Source line numbers (1-based) where `alt` appears INSIDE an `impl` block
/// whose self type is `ty`.
///
/// # Why the impl scoping is not optional
///
/// The first version of this matched `Self::new(` anywhere in the declaring
/// file, and reported `GuardedAction<A>` as wired on the strength of
/// `crates/portcullis/src/guard.rs:333` — which sits inside
/// `impl<A, E> Default for CompositeGuard<A, E>`, where `Self` is
/// `CompositeGuard`. `Self` means whichever impl you are in, and a file
/// declares many types. A false "now wired" is a WRONG RED, which costs more
/// than the hole it was closing.
///
/// Brace counting is naive — a `{` inside a string literal misleads it — which
/// is the same imprecision [`production_region`] already accepts for
/// `#[cfg(test)]`, and for the same reason: a grep gate has no parser. The
/// failure direction is a missed site, not an invented one, because a
/// mis-tracked depth closes an impl early rather than opening one.
fn self_sites(region: &str, ty: &str, alt: &str) -> Vec<usize> {
    let mut out = Vec::new();
    let mut depth: usize = 0;
    // (self type, brace depth the block body sits at)
    let mut open_impls: Vec<(String, usize)> = Vec::new();
    let mut pending: Option<String> = None;

    for (i, line) in region.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed == "impl"
            || trimmed.starts_with("impl ")
            || trimmed.starts_with("impl<")
            || trimmed.starts_with("pub impl ")
        {
            pending = impl_self_type(trimmed);
        }

        let inside = open_impls.last().map(|(t, _)| t == ty).unwrap_or(false);
        if inside && line.contains(alt) {
            out.push(i + 1);
        }

        for c in line.chars() {
            match c {
                '{' => {
                    depth += 1;
                    if let Some(t) = pending.take() {
                        open_impls.push((t, depth));
                    }
                }
                '}' => {
                    if open_impls.last().map(|(_, d)| *d == depth).unwrap_or(false) {
                        open_impls.pop();
                    }
                    depth = depth.saturating_sub(1);
                }
                _ => {}
            }
        }
    }
    out
}

/// The self type of an `impl` header line: the type after `for` when there is
/// one, otherwise the type after the `impl` generics.
///
/// `impl Kernel {` → `Kernel`;
/// `impl<A> GuardedAction<A> {` → `GuardedAction`;
/// `impl<A, E> Default for CompositeGuard<A, E> {` → `CompositeGuard`.
fn impl_self_type(line: &str) -> Option<String> {
    let rest = line.trim_start().strip_prefix("impl")?;
    let rest = skip_balanced_generics(rest.trim_start());
    let target = match rest.find(" for ") {
        Some(i) => &rest[i + 5..],
        None => rest,
    };
    let ident: String = target
        .trim_start()
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    if ident.is_empty() { None } else { Some(ident) }
}

/// Skip a leading `<..>` generic list, honouring nesting.
fn skip_balanced_generics(s: &str) -> &str {
    if !s.starts_with('<') {
        return s;
    }
    let mut depth = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '<' => depth += 1,
            '>' => {
                depth -= 1;
                if depth == 0 {
                    return &s[i + 1..];
                }
            }
            _ => {}
        }
    }
    s
}

/// Read tracked `crates/**/*.rs` matching `keep`. `git ls-files`, never a
/// filesystem walk — see the module doc for why that distinction is load-bearing.
///
/// `pub` so `inert_authority` shares the domain rule rather than restating it;
/// two gates that disagree about which files exist would be two answers to the
/// question this one was built to make singular.
pub fn tracked(keep: fn(&str) -> bool) -> Result<BTreeMap<String, String>> {
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
            "OK: {} declared-WIRED mechanism(s) still have a production call site.",
            manifest.wired_count
        );
        println!(
            "     A W row records a mechanism whose problem is NOT that nobody calls it. \
             Losing its call site is a finding, not a graduation."
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
            FindingKind::NoLongerWired { anchor } => println!(
                "  {}: declared WIRED but {anchor:?} appears in no production region. Its only \
                 call site is gone, so the row's note is now about dead code — re-read it, then \
                 either move the row to class D or drop it and lower WIRED_COUNT.",
                f.mechanism
            ),
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
         crates/a/src/lib.rs | proved, never called\nDEAD_COUNT=1\nWIRED_COUNT=0\n";

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

    // ─── The `Self::` hole, and the hole in closing it ─────────────

    #[test]
    fn self_anchor_is_derived_only_from_a_type_qualified_method() {
        assert_eq!(
            self_anchor("Kernel::with_isolation("),
            Some("Self::with_isolation(".to_string())
        );
        assert_eq!(
            self_anchor("GuardedAction::new("),
            Some("Self::new(".to_string())
        );
        // A bare anchor names no method, so there is no `Self::` spelling.
        assert_eq!(self_anchor("with_work_dir("), None);
        // A trailing `::` names the TYPE (the ConstraintNucleus row's shape),
        // not a method on it.
        assert_eq!(self_anchor("ConstraintNucleus::"), None);
    }

    #[test]
    fn impl_self_type_reads_the_type_the_impl_is_for() {
        assert_eq!(impl_self_type("impl Kernel {").as_deref(), Some("Kernel"));
        assert_eq!(
            impl_self_type("impl<A> GuardedAction<A> {").as_deref(),
            Some("GuardedAction")
        );
        assert_eq!(
            impl_self_type("impl<A, E> Default for CompositeGuard<A, E> {").as_deref(),
            Some("CompositeGuard")
        );
        assert_eq!(
            impl_self_type("impl<'a> From<&'a str> for Wrapper {").as_deref(),
            Some("Wrapper"),
            "the generic list may itself contain `for`-free angle brackets"
        );
        assert_eq!(impl_self_type("fn not_an_impl() {"), None);
    }

    #[test]
    fn a_self_call_in_the_declaring_type_is_a_call_site() {
        // THE DEFECT. `Kernel::with_isolation` was class D — no live call site —
        // and the gate agreed, while kernel.rs called it from `Kernel::new` as
        // `Self::with_isolation(..)`.
        let src = "\
impl Kernel {
    pub fn new(initial: PermissionLattice) -> Self {
        Self::with_isolation(initial, IsolationLattice::localhost())
    }
    pub fn with_isolation(i: PermissionLattice, iso: IsolationLattice) -> Self { todo!() }
}
";
        assert_eq!(
            self_sites(src, "Kernel", "Self::with_isolation("),
            vec![3],
            "the call must be found, at its real line"
        );
    }

    #[test]
    fn a_self_call_in_a_different_impl_is_not_a_call_site() {
        // THE HOLE IN CLOSING THE DEFECT. The first version matched `Self::new(`
        // anywhere in the declaring file and reported `GuardedAction<A>` wired
        // on the strength of guard.rs:333, which is inside
        // `impl<A, E> Default for CompositeGuard<A, E>`. `Self` means whichever
        // impl you are in. A false "now wired" is a wrong red.
        let src = "\
impl<A> GuardedAction<A> {
    pub fn new(inner: A) -> Self { todo!() }
}

impl<A, E> Default for CompositeGuard<A, E> {
    fn default() -> Self {
        Self::new()
    }
}
";
        assert!(
            self_sites(src, "GuardedAction", "Self::new(").is_empty(),
            "`Self::new()` under CompositeGuard is not a GuardedAction call site"
        );
        assert_eq!(
            self_sites(src, "CompositeGuard", "Self::new("),
            vec![7],
            "and it IS one for CompositeGuard, or the scoping is just a mute button"
        );
    }

    #[test]
    fn a_self_call_nested_deeper_in_the_impl_still_counts() {
        // Inner blocks raise the brace depth without opening an impl, so the
        // enclosing impl must stay current.
        let src = "\
impl Kernel {
    pub fn new() -> Self {
        if true {
            return Self::with_isolation();
        }
        todo!()
    }
}
";
        assert_eq!(self_sites(src, "Kernel", "Self::with_isolation("), vec![4]);
    }

    // ─── Class W ───────────────────────────────────────────────────

    const W_ROW: &str = "W | isolation | Kernel::with_isolation | pub fn with_isolation | \
         Kernel::with_isolation( | crates/a/src/lib.rs | wired, but at one constant point\n\
         DEAD_COUNT=0\nWIRED_COUNT=1\n";

    #[test]
    fn a_wired_row_with_a_live_call_site_is_clean() {
        let m = parse(W_ROW).expect("parses");
        assert_eq!(m.wired_count, 1);
        assert_eq!(m.dead_count, 0);
        let corpus = corpus_of(&[(
            "crates/a/src/lib.rs",
            "impl Kernel {\n    pub fn with_isolation() {}\n    pub fn new() { Self::with_isolation(); }\n}\n",
        )]);
        assert!(
            decide(&m, &corpus).is_empty(),
            "a wired W row is the clean case"
        );
    }

    #[test]
    fn a_wired_row_that_lost_its_call_site_is_a_finding() {
        // The dual of NowWired, and the reason W is a class rather than a
        // comment: a note about live code must not quietly become a note about
        // dead code.
        let m = parse(W_ROW).expect("parses");
        let corpus = corpus_of(&[(
            "crates/a/src/lib.rs",
            "impl Kernel {\n    pub fn with_isolation() {}\n}\n",
        )]);
        let f = decide(&m, &corpus);
        assert_eq!(f.len(), 1);
        assert!(
            matches!(f[0].kind, FindingKind::NoLongerWired { .. }),
            "got {:?}",
            f[0]
        );
    }

    #[test]
    fn each_class_is_pinned_by_its_own_count() {
        // A shared pin would let a row change class and vanish from its
        // population without the total moving.
        let mixed = "D | l | M | struct M | M( | crates/a/src/lib.rs | dead\n\
             W | l | K::go | pub fn go | K::go( | crates/a/src/lib.rs | wired\n\
             DEAD_COUNT=1\nWIRED_COUNT=1\n";
        let m = parse(mixed).expect("parses");
        assert_eq!((m.dead_count, m.wired_count), (1, 1));

        let wrong = mixed.replace("DEAD_COUNT=1", "DEAD_COUNT=2");
        assert!(
            parse(&wrong).is_err(),
            "DEAD_COUNT must count class-D rows only"
        );
        let wrong = mixed.replace("WIRED_COUNT=1", "WIRED_COUNT=0");
        assert!(
            parse(&wrong).is_err(),
            "WIRED_COUNT must count class-W rows only"
        );
    }

    #[test]
    fn a_manifest_without_a_wired_pin_is_rejected() {
        let unpinned = "D | l | M | struct M | M( | crates/a/src/lib.rs | dead\nDEAD_COUNT=1\n";
        let err = parse(unpinned).expect_err("an unpinned population can shrink silently");
        assert!(format!("{err}").contains("WIRED_COUNT"), "got {err}");
    }

    #[test]
    fn an_unknown_class_is_rejected() {
        let bad =
            "X | l | M | struct M | M( | crates/a/src/lib.rs | ?\nDEAD_COUNT=0\nWIRED_COUNT=0\n";
        assert!(parse(bad).is_err(), "only D and W are classes");
    }

    // ─── Line positions ────────────────────────────────────────────

    #[test]
    fn the_production_region_preserves_line_numbers() {
        // Findings name a line for a human to open. Before this, the index was
        // into the STRIPPED region, so every finding after a comment pointed at
        // the wrong line — `Self::with_isolation` reported kernel.rs:243 for a
        // call on kernel.rs:590.
        let src = "\
// a comment
fn real() {}
#[cfg(test)]
mod t {
    fn hidden() {}
}
fn also_real() {}
";
        let region = production_region(src);
        let lines: Vec<&str> = region.lines().collect();
        assert_eq!(
            lines.len(),
            src.lines().count(),
            "line count must be preserved"
        );
        assert_eq!(lines[1], "fn real() {}", "source line 2 stays at index 1");
        assert_eq!(
            lines[6], "fn also_real() {}",
            "source line 7 stays at index 6"
        );
        assert!(
            !region.contains("hidden"),
            "test code must still be stripped"
        );
        assert!(
            !region.contains("a comment"),
            "comments must still be stripped"
        );
    }
}
