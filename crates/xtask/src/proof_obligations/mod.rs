//! `cargo xtask proof-obligations` (#2585): which security-kernel function is held to which
//! proof artifact, and whether that artifact can still be what it claims.
//!
//! "Has a proof" was folklore: nothing mapped a function to the artifact that proves it, so a
//! trivial artifact — `theorem f_ok : True := trivial`, or
//! a `kani::proof` harness `fn p() { let _ = f(kani::any()); }` — would satisfy any check that only
//! asks whether something with the right name exists. `proof-obligations.toml` is the map;
//! this is the lint that refuses a row whose artifact is gone, unrun, or vacuous.
//!
//! # What a row must survive
//!
//! Every row:
//! * its `function` resolves, by a `syn` walk of the crate's module tree from its roots (the
//!   library, then each binary), to a function that is not itself test-only code — so a rename
//!   or deletion fails here, naming the row;
//! * a `source_hash`, when present, is the SHA-256 of the function's signature and body
//!   tokens — so a pinned function cannot change without the pin moving in the same diff.
//!
//! By kind:
//! * `kani` — the artifact is a harness (`<file>::<name>`, the `KANI-STATUS.md` key) that
//!   `cargo xtask kani-coverage`'s own lane parse finds run by some workflow (`-p` /
//!   `--harness`); its body names the function; and its LAST statement is `kani::cover!` over
//!   a condition that is not the literal `false`. A harness whose assumptions make its end
//!   unreachable passes every assertion vacuously; a terminal cover is what Kani reports as
//!   UNSATISFIABLE when that happens.
//! * `lean-extracted` — the artifact is a theorem (`<file>.lean::<name>`) in a module some
//!   workflow's Lean-action build elaborates (the tier [`crate::lean_tier`] derives, imports
//!   followed); the function's Aeneas extraction is a `def` in that same tier, found from the
//!   generated doc comment and not from a list; and the theorem's STATEMENT names that
//!   constant. A theorem about `True` names nothing.
//! * `lean-mirror` — as `lean-extracted`, but the constant is a hand-written mirror named by
//!   the row's `constant`, which must be declared in the tier.
//! * `parity`, `typestate-fault-injection` — the artifact is a `#[test]` function
//!   (`<file>::<name>`) whose body names the function.
//! * `missing` — no artifact; the row must be `allowlisted` with a `tracking` issue, and no
//!   other row may cover the same function (an allowlist entry for a covered function is
//!   stale).
//!
//! # The missing ratchet (#2594)
//!
//! A registry that refuses vacuous proofs but accepts any number of `missing` rows would let a
//! gap be registered instead of closed. So the gaps are counted, and the count can only go down:
//!
//! * a **gap** is a function with a row carrying `tracking`: still `missing`, or DISCHARGED — an
//!   artifact row that keeps the `tracking` issue it closed. Discharging a gap therefore turns
//!   its `missing` row into the proof's row and leaves the gap count where it was;
//! * the gap count must EQUAL `MISSING_CEILING` in [`RATCHET`]. One more is a new `missing` row
//!   (red); one fewer is a `missing` row deleted without a proof (red);
//! * so the ceiling on `missing` rows is `MISSING_CEILING` minus the discharged rows — derived
//!   from the registry, never restated beside it. A proof PR does not touch the ratchet file;
//!   the only edit it ever takes is DOWN, in the change that deletes a gap's function outright.
//!
//! What it cannot see, because a stored number has no history: a raise of `MISSING_CEILING`
//! (that is a reviewed one-line diff to a file whose only job is that number), a discharged row
//! turned back into `missing`, and a `tracking` field planted on a row that never was a gap.
//!
//! # What this does not claim
//!
//! It is a static lint. It does not run Kani or Lean: whether the cover is SATISFIED and the
//! theorem elaborates is those tools' verdict in the lanes this lint has checked exist.
//! "The body names the function" is a match on the last path segment, not name resolution, so
//! a same-named function elsewhere would satisfy it. A statement mentioning a constant can
//! still be trivial (`f x = f x`). These are floors, stated so they are not mistaken for more.

mod lean;
mod rust;
#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::{kani_coverage, lean_action_builds, lean_tier};

/// The registry, at the repository root.
pub const REGISTRY: &str = "proof-obligations.toml";

/// The stored half of the missing ratchet: `MISSING_CEILING=<n>`.
pub const RATCHET: &str = "ci/proof-obligations-ratchet.txt";

/// What kind of evidence a row claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    LeanExtracted,
    LeanMirror,
    Kani,
    Parity,
    TypestateFaultInjection,
    Missing,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::LeanExtracted => "lean-extracted",
            Kind::LeanMirror => "lean-mirror",
            Kind::Kani => "kani",
            Kind::Parity => "parity",
            Kind::TypestateFaultInjection => "typestate-fault-injection",
            Kind::Missing => "missing",
        }
    }
}

/// The reviewed decision a row records: the artifact is the function's proof, or the absence
/// of one is accepted for now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Proved,
    Allowlisted,
}

/// One `[[obligation]]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub function: String,
    pub kind: Kind,
    pub artifact: Option<String>,
    pub status: Status,
    pub source_hash: Option<String>,
    /// `lean-mirror` only: the hand-written Lean constant the theorem is about.
    pub constant: Option<String>,
    /// On a `missing` row, the issue that will discharge it; on an artifact row, the gap it
    /// discharged. Kept through the discharge so the gap is still counted (the ratchet).
    pub tracking: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    obligation: Vec<Row>,
}

/// Parse the registry. Rows are keyed by (function, kind, artifact): a duplicate is an error,
/// not a second copy that could later disagree with the first (ADR 0007 G-3).
pub fn parse(text: &str) -> Result<BTreeMap<(String, Kind, Option<String>), Row>> {
    let registry: Registry = toml::from_str(text).context("parsing proof-obligations.toml")?;
    let mut rows = BTreeMap::new();
    for row in registry.obligation {
        let key = (row.function.clone(), row.kind, row.artifact.clone());
        if rows.insert(key, row.clone()).is_some() {
            bail!(
                "duplicate obligation: {} {} {:?}",
                row.function,
                row.kind.name(),
                row.artifact
            );
        }
    }
    if rows.is_empty() {
        bail!("proof-obligations.toml has no rows; a registry of nothing checks nothing");
    }
    Ok(rows)
}

/// One Lean tier, as this lint reads it.
struct Tier {
    /// Every first-party source the tier elaborates, relative to the root.
    files: BTreeSet<PathBuf>,
    /// Rust function → the Lean constants Aeneas extracted it to, in this tier.
    extracted: BTreeMap<String, BTreeSet<String>>,
    /// Every `def`/`abbrev` name the tier declares, as written.
    definitions: BTreeSet<String>,
}

/// `path` relative to `root`, with `.` components dropped (a lakefile's `srcDir := "."`
/// puts one in every path `lean_tier` resolves through it).
fn relative(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .filter(|c| !matches!(c, std::path::Component::CurDir))
        .collect()
}

/// Every tier any workflow's Lean-action step builds, derived by `lean_tier`.
fn tiers(root: &Path) -> Result<Vec<Tier>> {
    let mut workflows: Vec<PathBuf> = std::fs::read_dir(root.join(".github/workflows"))
        .context("reading .github/workflows")?
        .map(|e| e.map(|e| e.path()))
        .collect::<std::io::Result<_>>()?;
    workflows.sort();
    let mut out = Vec::new();
    for path in workflows {
        if !path.extension().is_some_and(|s| s == "yml" || s == "yaml") {
            continue;
        }
        let yaml: serde_yaml::Value = serde_yaml::from_str(&std::fs::read_to_string(&path)?)
            .with_context(|| path.display().to_string())?;
        if lean_action_builds::steps(&yaml)
            .with_context(|| path.display().to_string())?
            .is_empty()
        {
            continue;
        }
        for tier in lean_tier::derive_workflow(root, &relative(root, &path))? {
            let mut t = Tier {
                files: BTreeSet::new(),
                extracted: BTreeMap::new(),
                definitions: BTreeSet::new(),
            };
            for file in tier.closure.values() {
                let text =
                    std::fs::read_to_string(file).with_context(|| file.display().to_string())?;
                for e in lean::extracted(&text).unwrap_or_default() {
                    t.extracted
                        .entry(e.function)
                        .or_default()
                        .insert(e.constant);
                }
                t.definitions.extend(lean::definitions(&text));
                t.files.insert(relative(root, file));
            }
            out.push(t);
        }
    }
    if out.is_empty() {
        bail!("no workflow builds a Lean tier; every lean row would be unreachable by default");
    }
    Ok(out)
}

/// Everything a check reads, gathered once.
struct Tree<'a> {
    root: &'a Path,
    symbols: rust::Symbols<'a>,
    harnesses: Vec<kani_coverage::Harness>,
    lanes: Vec<kani_coverage::Lane>,
    tiers: Vec<Tier>,
}

impl<'a> Tree<'a> {
    fn read(root: &'a Path) -> Result<Self> {
        Ok(Self {
            root,
            symbols: rust::Symbols::new(root)?,
            harnesses: kani_coverage::sources(root)?,
            lanes: kani_coverage::lanes(root)?,
            tiers: tiers(root)?,
        })
    }
}

/// `<file>::<name>`.
fn split_artifact(artifact: &str) -> Option<(PathBuf, &str)> {
    let (file, name) = artifact.rsplit_once("::")?;
    (!file.is_empty() && !name.is_empty()).then(|| (PathBuf::from(file), name))
}

fn check_kani(tree: &Tree, row: &Row, artifact: &str) -> Result<Vec<String>> {
    let mut errors = Vec::new();
    let Some((file, name)) = split_artifact(artifact) else {
        return Ok(vec![format!("`{artifact}` is not <file>::<harness>")]);
    };
    let Some(harness) = tree.harnesses.iter().find(|h| h.key == artifact) else {
        return Ok(vec![format!("no Kani harness `{artifact}`")]);
    };
    if !tree.lanes.iter().any(|l| kani_coverage::covers(l, harness)) {
        errors.push(format!(
            "`{artifact}` is run by no workflow (no Kani lane selects its package and harness)"
        ));
    }
    let bodies = rust::bodies(tree.root, &file, name)?;
    let Some(body) = bodies.iter().find(|b| b.kani) else {
        return Ok(vec![format!(
            "no Kani harness fn `{name}` in {}",
            file.display()
        )]);
    };
    let leaf = rust::leaf(&row.function);
    if !body.idents.contains(leaf) {
        errors.push(format!(
            "`{artifact}` does not reference `{leaf}`: the harness never calls what it is registered as proving"
        ));
    }
    match body.ends_with_cover {
        rust::Cover::Terminal => {}
        rust::Cover::Unsatisfiable => errors.push(format!(
            "`{artifact}` ends with `kani::cover!(false …)`, which no execution satisfies"
        )),
        rust::Cover::Absent => errors.push(format!(
            "`{artifact}` does not end with `kani::cover!`: nothing shows its final state is reachable, so its assertions may hold vacuously"
        )),
    }
    Ok(errors)
}

fn check_lean(tree: &Tree, row: &Row, artifact: &str) -> Result<Vec<String>> {
    let Some((file, name)) = split_artifact(artifact) else {
        return Ok(vec![format!("`{artifact}` is not <file>.lean::<theorem>")]);
    };
    let Some(tier) = tree.tiers.iter().find(|t| t.files.contains(&file)) else {
        return Ok(vec![format!(
            "{} is unreachable: no workflow's Lean-action build elaborates it",
            file.display()
        )]);
    };
    let text = std::fs::read_to_string(tree.root.join(&file))
        .with_context(|| file.display().to_string())?;
    let Some(theorem) = lean::theorems(&text).into_iter().find(|t| t.name == name) else {
        return Ok(vec![format!("no theorem `{name}` in {}", file.display())]);
    };
    let scopes = lean::scopes(&text);
    let constants: Vec<String> = match row.kind {
        Kind::LeanExtracted => match tier.extracted.get(&row.function) {
            Some(c) => c.iter().cloned().collect(),
            None => {
                return Ok(vec![format!(
                    "no Aeneas extraction of `{}` in the tier that builds {}",
                    row.function,
                    file.display()
                )]);
            }
        },
        Kind::LeanMirror => {
            let Some(constant) = &row.constant else {
                return Ok(vec!["a lean-mirror row needs `constant`".into()]);
            };
            if !tier
                .definitions
                .iter()
                .any(|d| d == constant || constant.ends_with(&format!(".{d}")))
            {
                return Ok(vec![format!(
                    "mirror constant `{constant}` is declared nowhere in the tier that builds {}",
                    file.display()
                )]);
            }
            vec![constant.clone()]
        }
        Kind::Kani | Kind::Parity | Kind::TypestateFaultInjection | Kind::Missing => {
            bail!("check_lean called for a {} row", row.kind.name())
        }
    };
    if constants
        .iter()
        .any(|c| lean::mentions(&theorem.statement, c, &scopes))
    {
        Ok(Vec::new())
    } else {
        Ok(vec![format!(
            "theorem `{name}` does not mention {} in its statement: it says nothing about `{}`",
            constants.join(" / "),
            row.function
        )])
    }
}

fn check_test(tree: &Tree, row: &Row, artifact: &str) -> Result<Vec<String>> {
    let Some((file, name)) = split_artifact(artifact) else {
        return Ok(vec![format!("`{artifact}` is not <file>::<test>")]);
    };
    let bodies = rust::bodies(tree.root, &file, name)?;
    let Some(body) = bodies.iter().find(|b| b.test) else {
        return Ok(vec![format!(
            "no #[test] fn `{name}` in {}",
            file.display()
        )]);
    };
    let leaf = rust::leaf(&row.function);
    Ok(if body.idents.contains(leaf) {
        Vec::new()
    } else {
        vec![format!("`{artifact}` does not reference `{leaf}`")]
    })
}

fn check_row(tree: &mut Tree, row: &Row, covered: &BTreeSet<String>) -> Result<Vec<String>> {
    let mut errors = Vec::new();
    match tree.symbols.resolve(&row.function)? {
        None => errors.push(format!(
            "`{}` no longer exists (no such function in the crate's module tree)",
            row.function
        )),
        Some(site) if site.test_only => errors.push(format!(
            "`{}` is test-only code ({}); an obligation is on a function that ships",
            row.function,
            site.file.display()
        )),
        Some(site) => {
            if let Some(pin) = &row.source_hash
                && pin != &site.hash
            {
                errors.push(format!(
                    "`{}` changed since its source_hash was pinned (now {})",
                    row.function, site.hash
                ));
            }
        }
    }
    if row.constant.is_some() && row.kind != Kind::LeanMirror {
        errors.push("`constant` is for lean-mirror rows only".into());
    }
    match (row.kind, row.status, &row.artifact) {
        (Kind::Missing, Status::Allowlisted, None) => {
            if row.tracking.as_deref().is_none_or(|t| t.trim().is_empty()) {
                errors.push("an allowlisted missing row needs a `tracking` issue".into());
            }
            if covered.contains(&row.function) {
                errors.push("stale: the function has an artifact row, so it is not missing".into());
            }
        }
        (Kind::Missing, Status::Proved, _) => errors
            .push("a missing obligation is not allowlisted (status must be `allowlisted`)".into()),
        (Kind::Missing, Status::Allowlisted, Some(_)) => {
            errors.push("a missing row has no artifact".into())
        }
        (_, Status::Allowlisted, _) => errors.push("only a missing row can be allowlisted".into()),
        (_, Status::Proved, None) => errors.push("an artifact row needs `artifact`".into()),
        (kind, Status::Proved, Some(artifact)) => {
            errors.extend(match kind {
                Kind::Kani => check_kani(tree, row, artifact)?,
                Kind::LeanExtracted | Kind::LeanMirror => check_lean(tree, row, artifact)?,
                Kind::Parity | Kind::TypestateFaultInjection => check_test(tree, row, artifact)?,
                Kind::Missing => bail!("a missing row reached the artifact checks"),
            });
        }
    }
    Ok(errors)
}

/// Every violation in `text` against the tree at `root`, one line per row.
pub fn violations(root: &Path, text: &str) -> Result<(usize, BTreeMap<Kind, usize>, Vec<String>)> {
    let rows = parse(text)?;
    let mut tree = Tree::read(root)?;
    let covered: BTreeSet<String> = rows
        .values()
        .filter(|r| r.kind != Kind::Missing)
        .map(|r| r.function.clone())
        .collect();
    let mut counts = BTreeMap::new();
    let mut errors = Vec::new();
    for row in rows.values() {
        *counts.entry(row.kind).or_insert(0usize) += 1;
        for e in check_row(&mut tree, row, &covered)? {
            errors.push(format!(
                "{} [{}{}]: {e}",
                row.function,
                row.kind.name(),
                row.artifact
                    .as_deref()
                    .map(|a| format!(" {a}"))
                    .unwrap_or_default()
            ));
        }
    }
    Ok((rows.len(), counts, errors))
}

/// The registry's gaps, as the ratchet counts them.
#[derive(Debug, PartialEq, Eq)]
pub struct Gaps {
    /// `missing` rows.
    pub missing: usize,
    /// Functions whose gap was closed: an artifact row keeps `tracking`, no `missing` row left.
    pub discharged: usize,
}

/// `MISSING_CEILING` from [`RATCHET`]. Absent or unparsable is an error: a ratchet that could
/// not be read is not a ratchet that passed (ADR 0007 A-2).
pub fn missing_ceiling(root: &Path) -> Result<usize> {
    let text = std::fs::read_to_string(root.join(RATCHET))
        .with_context(|| format!("{RATCHET} is missing: nothing to ratchet against"))?;
    parse_ceiling(&text)
}

fn parse_ceiling(text: &str) -> Result<usize> {
    let mut values = text
        .lines()
        .map(str::trim)
        .filter_map(|l| l.strip_prefix("MISSING_CEILING="));
    let value = values
        .next()
        .with_context(|| format!("{RATCHET} has no MISSING_CEILING= line"))?;
    if values.next().is_some() {
        bail!("{RATCHET} has more than one MISSING_CEILING= line");
    }
    value
        .trim()
        .parse()
        .with_context(|| format!("{RATCHET}: MISSING_CEILING={value} is not a count"))
}

/// The ratchet's verdict on `text` against `ceiling`: the gap count, and why it is red.
pub fn ratchet(text: &str, ceiling: usize) -> Result<(Gaps, Vec<String>)> {
    let rows = parse(text)?;
    let missing: BTreeSet<&str> = rows
        .values()
        .filter(|r| r.kind == Kind::Missing)
        .map(|r| r.function.as_str())
        .collect();
    let tracked: BTreeSet<&str> = rows
        .values()
        .filter(|r| r.tracking.is_some())
        .map(|r| r.function.as_str())
        .collect();
    let gaps = Gaps {
        missing: missing.len(),
        discharged: tracked.difference(&missing).count(),
    };
    let count = tracked.len();
    let mut errors = Vec::new();
    if count > ceiling {
        errors.push(format!(
            "ratchet: {count} proof gaps registered, MISSING_CEILING is {ceiling} ({RATCHET}): \
             a new `missing` row. The count only goes down: give the function its proof, not an \
             allowlist entry"
        ));
    }
    if count < ceiling {
        errors.push(format!(
            "ratchet: {count} proof gaps registered, MISSING_CEILING is {ceiling} ({RATCHET}): \
             a gap left the registry without a proof. Discharge a `missing` row by turning it \
             into the artifact row that proves the function, keeping `tracking`; if the function \
             itself was deleted, lower MISSING_CEILING in that change and say why"
        ));
    }
    Ok((gaps, errors))
}

/// Everything `cargo xtask proof-obligations` checks on the tree at `root`: every row, then the
/// missing ratchet.
pub fn check(root: &Path) -> Result<(usize, BTreeMap<Kind, usize>, Gaps, Vec<String>)> {
    let text = std::fs::read_to_string(root.join(REGISTRY))
        .with_context(|| format!("reading {REGISTRY}"))?;
    let (total, counts, mut errors) = violations(root, &text)?;
    let (gaps, ratchet_errors) = ratchet(&text, missing_ceiling(root)?)?;
    errors.extend(ratchet_errors);
    Ok((total, counts, gaps, errors))
}

/// `cargo xtask proof-obligations`.
pub fn run(root: &Path, derive: bool) -> Result<()> {
    if derive {
        return derive_seed(root);
    }
    let (total, counts, gaps, errors) = check(root)?;
    if !errors.is_empty() {
        for e in &errors {
            println!("::error::{e}");
        }
        bail!(
            "{} proof-obligation violations across {total} rows",
            errors.len()
        );
    }
    let by_kind: Vec<String> = counts
        .iter()
        .map(|(k, n)| format!("{} {n}", k.name()))
        .collect();
    println!(
        "ok: {total} proof obligations hold ({}); {} missing, {} discharged; static: Kani and Lean still decide whether each artifact verifies",
        by_kind.join(", "),
        gaps.missing,
        gaps.discharged
    );
    Ok(())
}

/// `--derive`: the rows the tree already supports, printed as TOML.
///
/// * `lean-extracted`: every Aeneas-extracted function (resolvable, shipping, not a trait
///   impl) of every tier, paired with the first theorem of that tier — by file, then
///   position — whose statement names its constant.
/// * `kani`: every scheduled harness ending in a satisfiable `kani::cover!`, paired with each
///   shipping function of its own crate that its body names. Printed as candidates
///   (commented): a harness names helpers too, and which call is the subject is a reading,
///   not a derivation.
fn derive_seed(root: &Path) -> Result<()> {
    let mut tree = Tree::read(root)?;
    let mut lean_rows: BTreeMap<String, String> = BTreeMap::new();
    for tier in &tree.tiers {
        eprintln!(
            "tier: {} files, {} extracted functions",
            tier.files.len(),
            tier.extracted.len()
        );
        let mut theorems = Vec::new();
        for file in &tier.files {
            let text = std::fs::read_to_string(root.join(file))?;
            if lean::extracted(&text).is_some() {
                continue;
            }
            let scopes = lean::scopes(&text);
            for t in lean::theorems(&text) {
                theorems.push((file.clone(), t, scopes.clone()));
            }
        }
        for (function, constants) in &tier.extracted {
            if lean_rows.contains_key(function) {
                continue;
            }
            match tree.symbols.resolve(function) {
                Ok(Some(site)) if !site.test_only => {}
                Ok(Some(_)) => {
                    eprintln!("skip {function}: test-only");
                    continue;
                }
                Ok(None) => {
                    eprintln!("skip {function}: no such function in the crate");
                    continue;
                }
                Err(e) => {
                    eprintln!("skip {function}: {e:#}");
                    continue;
                }
            }
            if let Some((file, t, _)) = theorems.iter().find(|(_, t, scopes)| {
                constants
                    .iter()
                    .any(|c| lean::mentions(&t.statement, c, scopes))
            }) {
                lean_rows.insert(function.clone(), format!("{}::{}", file.display(), t.name));
            } else {
                eprintln!(
                    "skip {function}: no theorem statement names {}",
                    constants.iter().cloned().collect::<Vec<_>>().join(" / ")
                );
            }
        }
    }
    for (function, artifact) in &lean_rows {
        println!(
            "[[obligation]]\nfunction = \"{function}\"\nkind = \"lean-extracted\"\nartifact = \"{artifact}\"\nstatus = \"proved\"\n"
        );
    }
    let crates = rust::crate_roots(root)?;
    for harness in &tree.harnesses {
        if !tree.lanes.iter().any(|l| kani_coverage::covers(l, harness)) {
            continue;
        }
        let Some((file, name)) = split_artifact(&harness.key) else {
            continue;
        };
        let Some(body) = rust::bodies(root, &file, name)?
            .into_iter()
            .find(|b| b.kani)
        else {
            continue;
        };
        if body.ends_with_cover != rust::Cover::Terminal {
            continue;
        }
        let krate = harness.package.replace('-', "_");
        if !crates.contains_key(&krate) {
            continue;
        }
        let table = tree.symbols.table(&krate)?;
        for (function, site) in table {
            if !site.test_only && body.idents.contains(rust::leaf(function)) {
                println!(
                    "# candidate\n# [[obligation]]\n# function = \"{function}\"\n# kind = \"kani\"\n# artifact = \"{}\"\n# status = \"proved\"\n",
                    harness.key
                );
            }
        }
    }
    eprintln!("derived {} lean-extracted rows", lean_rows.len());
    Ok(())
}
