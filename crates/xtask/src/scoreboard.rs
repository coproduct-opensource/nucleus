//! `cargo xtask scoreboard-ratchet` — the exemplar scoreboard's anti-Goodhart
//! ratchet, ported from the last `python3` heredoc on the gate path
//! (exemplar-scoreboard.yml) per the Rust-only tooling mandate.
//!
//! Every lower-is-better metric has a `_GUARD` partner that may not fall, so
//! a number cannot be improved by deleting the thing it measures: you cannot
//! cut `permissive_verify` by deleting the verifier (`verify_calls_GUARD`
//! would drop), nor `vacuous_lean` by deleting theorems.
//!
//! Exit 0 no regression, 1 a regression or a dropped guard. Improvements are
//! `::notice::`d — the baseline is lowered by a human, never here.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde_json::Value;

const LOWER: [&str; 7] = [
    "permissive_verify",
    "vacuous_lean",
    "sorry_admit",
    "mediation_drift",
    "effect_stubs",
    "unsafe_blocks",
    "stale_verus_dirs",
];
const HIGHER: [&str; 4] = [
    "extracted_proofs",
    "crates_lints_workspace",
    "extraction_ratio_pct",
    "lints_adoption_pct",
];

/// Flatten nested objects to dotted keys; numbers only (booleans excluded).
fn flatten(v: &Value, prefix: &str, out: &mut BTreeMap<String, f64>) {
    if let Value::Object(m) = v {
        for (k, x) in m {
            let key = format!("{prefix}{k}");
            match x {
                Value::Object(_) => flatten(x, &format!("{key}."), out),
                Value::Number(n) => {
                    if let Some(f) = n.as_f64() {
                        out.insert(key, f);
                    }
                }
                _ => {}
            }
        }
    }
}

/// The decision, pure: `(failures, improvements)`.
#[must_use]
pub fn ratchet(current: &Value, baseline: &Value) -> (Vec<String>, Vec<String>) {
    let (mut c, mut b) = (BTreeMap::new(), BTreeMap::new());
    flatten(current, "", &mut c);
    flatten(baseline, "", &mut b);
    let mut fail = Vec::new();
    let mut improved = Vec::new();
    for (k, cv) in &c {
        let name = k.rsplit('.').next().unwrap_or(k);
        let Some(bv) = b.get(k) else { continue };
        if LOWER.contains(&name) {
            if cv > bv {
                fail.push(format!("{name} regressed {bv}->{cv} (lower is better)"));
            } else if cv < bv {
                improved.push(format!("{name} {bv}->{cv}"));
            }
        } else if HIGHER.contains(&name) {
            if cv < bv {
                fail.push(format!("{name} regressed {bv}->{cv} (higher is better)"));
            } else if cv > bv {
                improved.push(format!("{name} {bv}->{cv}"));
            }
        } else if name.ends_with("_GUARD") && cv < bv {
            fail.push(format!(
                "anti-gaming GUARD {name} dropped {bv}->{cv} (verifier/theorems deleted?)"
            ));
        }
    }
    (fail, improved)
}

pub fn scoreboard_ratchet(current: &str, baseline: &str) -> Result<()> {
    let cur: Value = serde_json::from_str(
        &std::fs::read_to_string(current).with_context(|| format!("reading {current}"))?,
    )
    .with_context(|| format!("parsing {current}"))?;
    let base: Value = serde_json::from_str(
        &std::fs::read_to_string(baseline).with_context(|| format!("reading {baseline}"))?,
    )
    .with_context(|| format!("parsing {baseline}"))?;
    // Non-vacuity: a scoreboard with no numeric metric compared to the
    // baseline "has no regressions" having compared nothing.
    let (mut c, mut b) = (BTreeMap::new(), BTreeMap::new());
    flatten(&cur, "", &mut c);
    flatten(&base, "", &mut b);
    let compared = c.keys().filter(|k| b.contains_key(*k)).count();
    if compared < 3 {
        eprintln!("::error::only {compared} metric(s) shared between {current} and {baseline} — the ratchet compared nothing");
        std::process::exit(1);
    }
    let (fail, improved) = ratchet(&cur, &base);
    for i in &improved {
        println!("::notice::improved {i} — lower {baseline} to ratchet it in");
    }
    if !fail.is_empty() {
        for f in &fail {
            println!("::error::{f}");
        }
        std::process::exit(1);
    }
    println!("exemplar scoreboard: no regressions vs baseline ({compared} metrics compared)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn lower_is_better_regresses_upward_and_improves_downward() {
        let base = json!({"a": {"sorry_admit": 5, "extracted_proofs": 4}});
        let (f, i) = ratchet(&json!({"a": {"sorry_admit": 6, "extracted_proofs": 4}}), &base);
        assert_eq!(f.len(), 1);
        assert!(i.is_empty());
        let (f, i) = ratchet(&json!({"a": {"sorry_admit": 3, "extracted_proofs": 6}}), &base);
        assert!(f.is_empty());
        assert_eq!(i.len(), 2);
    }

    #[test]
    fn a_dropped_guard_is_a_failure_even_when_the_metric_improves() {
        // The anti-Goodhart pairing: deleting theorems lowers vacuous_lean AND
        // drops lean_theorems_GUARD; the guard must fail.
        let base = json!({"vacuous_lean": 10, "lean_theorems_GUARD": 900});
        let (f, _) = ratchet(&json!({"vacuous_lean": 0, "lean_theorems_GUARD": 100}), &base);
        assert_eq!(f.len(), 1);
        assert!(f[0].contains("GUARD"));
    }

    #[test]
    fn booleans_and_unknown_keys_are_ignored() {
        let base = json!({"flag": true, "note": "x", "other": 1});
        let (f, i) = ratchet(&json!({"flag": false, "note": "y", "other": 2}), &base);
        assert!(f.is_empty() && i.is_empty());
    }
}
