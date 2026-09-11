//! `cargo xtask convergence` — how far the tree is from ADR 0006's four objects.
//!
//! ADR 0006 measured its own distance once, in prose, on 2026-09-09. That table
//! is an audit. This is the standing version of the two rows whose population
//! can be ENUMERATED FROM A SOURCE, so the distance can be read rather than
//! re-derived, and so it can only shrink.
//!
//! # Why two rows and not four
//!
//! ADR 0006's A-20 draws the line: a population is trustworthy only where
//! something in the tree defines it. `linearity` has one — "`#[must_use]` and
//! not `Clone`" is computable. `act_coverage` has one — the untargeted surface
//! is a closed set of spellings. `attenuation` and `lineage` do not: "every site
//! that narrows authority" is a hand-listed denominator, which is the metric
//! equivalent of a gate that cannot fail. They are excluded, and
//! `.convergence-ratchet.toml` says so rather than quietly averaging them in.
//!
//! # What this does not establish
//!
//! That four objects is the right decomposition. A score falling toward zero is
//! the kind of number that starts substituting for that judgement.
//!
//! Also: this is SYNTACTIC. It reads signatures, not semantics. A type aliased
//! to a watched name is invisible, and a by-reference parameter that is
//! genuinely read-only — `discharge_witness(bundle: &DischargedBundle) ->
//! String` renders one for the audit log — counts against the number anyway.
//! That is the safe direction (it over-counts debt, never under-counts it), but
//! it means the target of 0 may end with a small declared residue rather than a
//! literal zero.

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::collections::BTreeMap;

use crate::law_mechanisms::{is_production_path, production_region, tracked};

pub const RATCHET: &str = ".convergence-ratchet.toml";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ratchet {
    pub linearity: Row,
    pub act_coverage: Row,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub ceiling: usize,
    pub target: usize,
}

/// Parse the ratchet, refusing a shape that could not gate.
///
/// A ceiling BELOW its target is incoherent and would make the row unfailable
/// in one direction; a missing row is a silently dropped measurement. Both bail
/// rather than defaulting, because a default here is a number nobody chose.
pub fn parse(text: &str) -> Result<Ratchet> {
    let r: Ratchet = toml::from_str(text).context("parsing the convergence ratchet")?;
    for (name, row) in [
        ("linearity", &r.linearity),
        ("act_coverage", &r.act_coverage),
    ] {
        if row.ceiling < row.target {
            bail!(
                "{name}: ceiling {} is below target {}",
                row.ceiling,
                row.target
            );
        }
    }
    Ok(r)
}

/// Types whose author declared affine intent: `#[must_use]` and not `Clone`.
///
/// Computed rather than listed, which is the whole reason this row is in the
/// file. Adding `#[must_use]` to a type ENLARGES the population and can raise
/// the number — correct, because it means the tree started making a claim it
/// was not honouring.
pub fn affine_types(corpus: &BTreeMap<String, String>) -> Vec<String> {
    let mut declared: BTreeMap<String, String> = BTreeMap::new();
    for (path, src) in corpus {
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if !line.trim_start().starts_with("#[must_use") {
                continue;
            }
            // The declaration may sit a few attributes below the marker.
            for probe in lines.iter().take((i + 8).min(lines.len())).skip(i + 1) {
                if let Some(name) = struct_or_enum_name(probe) {
                    declared.insert(name, path.clone());
                    break;
                }
            }
        }
    }
    let all: String = corpus.values().cloned().collect::<Vec<_>>().join("\n");
    declared
        .into_keys()
        .filter(|t| !is_clone(&all, corpus, t))
        .collect()
}

fn struct_or_enum_name(line: &str) -> Option<String> {
    let t = line.trim_start();
    let rest = t
        .strip_prefix("pub struct ")
        .or_else(|| t.strip_prefix("pub enum "))?;
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

/// Is `ty` `Clone`, by hand-written impl or by derive above its declaration?
fn is_clone(all: &str, corpus: &BTreeMap<String, String>, ty: &str) -> bool {
    if all.contains(&format!("impl Clone for {ty}")) {
        return true;
    }
    for src in corpus.values() {
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if struct_or_enum_name(line).as_deref() != Some(ty) {
                continue;
            }
            let from = i.saturating_sub(8);
            if lines[from..i]
                .iter()
                .any(|l| l.contains("derive") && l.contains("Clone"))
            {
                return true;
            }
        }
    }
    false
}

/// Count parameters that take an affine type BY REFERENCE.
///
/// Comment lines are skipped: `authority.rs`'s module doc says "Today every
/// effect takes `proof: &DischargedBundle`", and counting prose as a signature
/// would put the defect's own description into the defect count.
pub fn count_linearity(
    corpus: &BTreeMap<String, String>,
    types: &[String],
) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for ty in types {
        let mut n = 0usize;
        for src in corpus.values() {
            for line in src.lines() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                if takes_by_reference(line, ty) {
                    n += 1;
                }
            }
        }
        if n > 0 {
            out.insert(ty.clone(), n);
        }
    }
    out
}

/// `: &Ty` or `: &mut Ty`, with an optional path prefix.
fn takes_by_reference(line: &str, ty: &str) -> bool {
    let mut rest = line;
    while let Some(at) = rest.find(": &") {
        let after = rest[at + 3..].trim_start();
        let after = after.strip_prefix("mut ").unwrap_or(after).trim_start();
        // Skip any `a::b::` qualification before the name.
        let tail = after.rsplit("::").next().unwrap_or(after);
        let name: String = tail
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name == ty {
            return true;
        }
        rest = &rest[at + 3..];
    }
    false
}

/// The untargeted-authority spellings the `Act` collapse replaces.
///
/// A closed set on purpose: each is a call shape that names a verb without its
/// target. `guard.check(Operation::..)` and `GuardedAction<Operation>` are
/// already at zero, which is the evidence this row tracks progress rather than
/// sitting at a constant.
pub fn count_act_coverage(corpus: &BTreeMap<String, String>) -> BTreeMap<String, usize> {
    let shapes: [(&str, fn(&str) -> bool); 4] = [
        ("Authority::spend(Operation::..)", |l| {
            l.contains(".spend(") && l.contains("Operation::")
        }),
        ("guard.check(Operation::..)", |l| {
            l.contains(".check(") && l.contains("Operation::")
        }),
        ("GuardedAction<Operation>", |l| {
            l.contains("GuardedAction<Operation>")
        }),
        ("GuardedAction<String>", |l| {
            l.contains("GuardedAction<String>")
        }),
    ];
    let mut out = BTreeMap::new();
    for (name, pred) in shapes {
        let mut n = 0usize;
        for src in corpus.values() {
            for line in src.lines() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                if pred(line) {
                    n += 1;
                }
            }
        }
        out.insert(name.to_string(), n);
    }
    out
}

/// Is this the gate harness rather than the enforcement path?
///
/// `law_mechanisms::is_production_path` accepts all of `crates/**`, `xtask`
/// included — correct for its own question and wrong for this one twice over.
///
/// First, ADR 0006's four objects are about the runtime that enforces what an
/// agent may do. `xtask` is build tooling; it holds no authority and delegates
/// none, so counting it would put CI plumbing into a number about the
/// enforcement path.
///
/// Second, and this is how it was found: this module NAMES the shapes it counts.
/// `GuardedAction<Operation>` and `.spend(Operation::..)` appear here as pattern
/// definitions, so the gate counted itself and `act_coverage` read 10 instead of
/// 3 — a gate measuring its own source. It stayed invisible until the first
/// commit, because `tracked` reads `git ls-files` and an uncommitted file is not
/// tracked. The gate-of-gates caught it on the next run: "still failing (exit 1)
/// after restore".
fn is_gate_harness(path: &str) -> bool {
    path.starts_with("crates/xtask/")
}

pub struct Finding {
    pub row: &'static str,
    pub found: usize,
    pub ceiling: usize,
}

/// Pure decision: a row fails when it is ABOVE its ceiling.
///
/// Below the ceiling is not a failure — it is a notice to lower it in the same
/// change, the convention `.clippy-ratchet.toml` already uses.
pub fn decide(r: &Ratchet, linearity: usize, act: usize) -> Vec<Finding> {
    let mut f = Vec::new();
    if linearity > r.linearity.ceiling {
        f.push(Finding {
            row: "linearity",
            found: linearity,
            ceiling: r.linearity.ceiling,
        });
    }
    if act > r.act_coverage.ceiling {
        f.push(Finding {
            row: "act_coverage",
            found: act,
            ceiling: r.act_coverage.ceiling,
        });
    }
    f
}

pub fn run() -> Result<i32> {
    let text = std::fs::read_to_string(RATCHET).with_context(|| format!("reading {RATCHET}"))?;
    let ratchet = parse(&text)?;

    // Production region only, and `git ls-files` rather than a filesystem walk —
    // the repo root carries an untracked worktree copy with a full `crates/`
    // tree, and a walk over-counted a sibling gate's number by 64%.
    let corpus: BTreeMap<String, String> = tracked(is_production_path)?
        .into_iter()
        .filter(|(p, _)| !is_gate_harness(p))
        .map(|(p, s)| (p, production_region(&s)))
        .collect();

    let types = affine_types(&corpus);
    let per_type = count_linearity(&corpus, &types);
    let linearity: usize = per_type.values().sum();
    let per_shape = count_act_coverage(&corpus);
    let act: usize = per_shape.values().sum();

    println!("convergence toward ADR 0006's four objects (two measurable arrows):");
    println!(
        "  linearity      {linearity:4} by-reference site(s) on {} affine type(s), ceiling {}, target {}",
        types.len(),
        ratchet.linearity.ceiling,
        ratchet.linearity.target
    );
    for (t, n) in &per_type {
        println!("                      {n:4}  {t}");
    }
    println!(
        "  act_coverage   {act:4} untargeted-authority site(s), ceiling {}, target {}",
        ratchet.act_coverage.ceiling, ratchet.act_coverage.target
    );
    for (s, n) in &per_shape {
        println!("                      {n:4}  {s}");
    }
    println!("  attenuation       -  no enumerable population; excluded (see {RATCHET})");
    println!("  lineage           -  no enumerable population; excluded (see {RATCHET})");

    let findings = decide(&ratchet, linearity, act);
    if findings.is_empty() {
        for (row, found, ceiling) in [
            ("linearity", linearity, ratchet.linearity.ceiling),
            ("act_coverage", act, ratchet.act_coverage.ceiling),
        ] {
            if found < ceiling {
                println!(
                    "::notice::{row} fell to {found}, below the ceiling of {ceiling}. Lower it in \
                     this change to keep the gain."
                );
            }
        }
        println!("OK: every measurable arrow is at or below its ceiling.");
        return Ok(0);
    }
    for f in &findings {
        eprintln!(
            "::error::{} rose to {}, above the ceiling of {}. The tree moved AWAY from the four \
             objects on this arrow.",
            f.row, f.found, f.ceiling
        );
    }
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(p, s)| ((*p).to_string(), (*s).to_string()))
            .collect()
    }

    /// The population is what the TYPES declare. A `#[must_use]` type that is
    /// `Clone` is not affine and must not be counted.
    #[test]
    fn the_population_is_must_use_and_not_clone() {
        let c = corpus(&[(
            "crates/a/src/lib.rs",
            "#[must_use]\npub struct Sealed;\n\
             #[derive(Clone)]\n#[must_use]\npub struct Copied;\n",
        )]);
        let t = affine_types(&c);
        assert!(t.contains(&"Sealed".to_string()), "{t:?}");
        assert!(
            !t.contains(&"Copied".to_string()),
            "a Clone type is not affine: {t:?}"
        );
    }

    /// Prose is not a signature. `authority.rs`'s module doc describes the very
    /// defect this counts, and counting it would put the description into the
    /// count.
    #[test]
    fn a_comment_describing_the_defect_is_not_the_defect() {
        let c = corpus(&[(
            "crates/a/src/lib.rs",
            "//! Today every effect takes `proof: &DischargedBundle`.\n\
             fn real(proof: &DischargedBundle) {}\n",
        )]);
        let n = count_linearity(&c, &["DischargedBundle".to_string()]);
        assert_eq!(
            n.get("DischargedBundle"),
            Some(&1),
            "only the signature counts: {n:?}"
        );
    }

    /// `&mut T` defeats the affine discipline exactly as `&T` does.
    #[test]
    fn a_mutable_reference_counts_too() {
        let c = corpus(&[("crates/a/src/lib.rs", "fn f(r: &mut PreflightResult) {}\n")]);
        let n = count_linearity(&c, &["PreflightResult".to_string()]);
        assert_eq!(n.get("PreflightResult"), Some(&1));
    }

    /// A qualified path is the same type.
    #[test]
    fn a_qualified_path_is_the_same_type() {
        let c = corpus(&[(
            "crates/a/src/lib.rs",
            "fn f(p: &crate::discharge::DischargedBundle) {}\n",
        )]);
        let n = count_linearity(&c, &["DischargedBundle".to_string()]);
        assert_eq!(n.get("DischargedBundle"), Some(&1));
    }

    /// Above the ceiling fails; at or below does not. Below is a notice, not an
    /// error — the same convention `.clippy-ratchet.toml` uses.
    #[test]
    fn only_rising_above_a_ceiling_is_a_finding() {
        let r = parse(
            "[linearity]\nceiling = 3\ntarget = 0\n[act_coverage]\nceiling = 1\ntarget = 0\n",
        )
        .expect("parses");
        assert!(
            decide(&r, 3, 1).is_empty(),
            "at the ceiling is not a finding"
        );
        assert!(
            decide(&r, 1, 0).is_empty(),
            "below the ceiling is not a finding"
        );
        assert_eq!(decide(&r, 4, 1).len(), 1, "above on one row");
        assert_eq!(decide(&r, 4, 2).len(), 2, "above on both");
    }

    /// A ceiling below its target could never be satisfied in one direction and
    /// is a shape nobody chose. Refused rather than defaulted.
    #[test]
    fn an_incoherent_ratchet_is_refused() {
        assert!(
            parse(
                "[linearity]\nceiling = 0\ntarget = 5\n[act_coverage]\nceiling = 1\ntarget = 0\n"
            )
            .is_err()
        );
    }
}
