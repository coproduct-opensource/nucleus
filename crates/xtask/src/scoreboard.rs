//! `cargo xtask scoreboard-ratchet` — the exemplar scoreboard's anti-Goodhart
//! ratchet, ported from the last `python3` heredoc on the gate path
//! (exemplar-scoreboard.yml) per the Rust-only tooling mandate.
//!
//! Every lower-is-better metric has a `_GUARD` partner that may not fall, so
//! a number cannot be improved by deleting the thing it measures: you cannot
//! cut `permissive_verify` by deleting the verifier (`verify_calls_GUARD`
//! would drop), nor `vacuous_lean` by deleting theorems.
//!
//! Exit 0 no regression, 1 a regression, a dropped guard, a metric that
//! vanished from the current scoreboard, or an UNPINNED improvement. The
//! baseline is edited by a human, never here — and it is edited in the SAME
//! change that moves the number (the North Star ledger's convention): a
//! `::notice::` improvement used to be advisory, so baselines were lowered
//! months after the fact and the slack in between (sorry 26 vs pin 38,
//! theorems 1466 vs guard 891) made the ratchet advisory too.

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
const HIGHER: [&str; 6] = [
    "extracted_proofs",
    "extracted_lean_files",
    "crates_lints_workspace",
    "extraction_ratio_pct",
    "lints_adoption_pct",
    // The frontier: the share of the replay corpus a canonical profile's own
    // lattice lets through (`frontier.<profile>.allowed_share_permille`). It
    // rides beside `corpus_steps_GUARD` and each profile's
    // `denied_at_exfil_vector_GUARD`, which may not fall — so it cannot be
    // raised by shrinking the corpus or by opening an exfiltration sink.
    "allowed_share_permille",
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
    // A metric the baseline pins but the current scoreboard no longer
    // reports is not "no regression": it is the ratchet comparing nothing
    // for that key. Deleting the measurement must be as visible as failing it.
    for k in b.keys() {
        if !c.contains_key(k) {
            let name = k.rsplit('.').next().unwrap_or(k);
            if LOWER.contains(&name) || HIGHER.contains(&name) || name.ends_with("_GUARD") {
                fail.push(format!(
                    "{k} vanished from the current scoreboard (pinned in the baseline)"
                ));
            }
        }
    }
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
        eprintln!(
            "::error::only {compared} metric(s) shared between {current} and {baseline} — the ratchet compared nothing"
        );
        std::process::exit(1);
    }
    let (fail, improved) = ratchet(&cur, &base);
    if !fail.is_empty() {
        for f in &fail {
            println!("::error::{f}");
        }
        std::process::exit(1);
    }
    // Same-change pinning. An improvement that is not pinned in this change
    // is slack the next regression can spend; it is an error, with the fix
    // named, not a notice.
    if !improved.is_empty() {
        for i in &improved {
            println!(
                "::error::improved {i} but {baseline} was not moved in the same change — re-pin it so the gain is a ratchet, not slack"
            );
        }
        std::process::exit(1);
    }
    println!(
        "exemplar scoreboard: no regressions vs baseline ({compared} metrics compared, every pin exact)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn lower_is_better_regresses_upward_and_improves_downward() {
        let base = json!({"a": {"sorry_admit": 5, "extracted_proofs": 4}});
        let (f, i) = ratchet(
            &json!({"a": {"sorry_admit": 6, "extracted_proofs": 4}}),
            &base,
        );
        assert_eq!(f.len(), 1);
        assert!(i.is_empty());
        let (f, i) = ratchet(
            &json!({"a": {"sorry_admit": 3, "extracted_proofs": 6}}),
            &base,
        );
        assert!(f.is_empty());
        assert_eq!(i.len(), 2);
    }

    #[test]
    fn a_dropped_guard_is_a_failure_even_when_the_metric_improves() {
        // The anti-Goodhart pairing: deleting theorems lowers vacuous_lean AND
        // drops lean_theorems_GUARD; the guard must fail.
        let base = json!({"vacuous_lean": 10, "lean_theorems_GUARD": 900});
        let (f, _) = ratchet(
            &json!({"vacuous_lean": 0, "lean_theorems_GUARD": 100}),
            &base,
        );
        assert_eq!(f.len(), 1);
        assert!(f[0].contains("GUARD"));
    }

    /// Deleting a pinned measurement is as loud as failing it.
    #[test]
    fn a_pinned_metric_that_vanishes_is_a_failure() {
        let base = json!({"frontier": {"codegen": {"allowed_share_permille": 400, "denied_at_exfil_vector_GUARD": 3}}, "corpus_steps_GUARD": 155});
        let (f, _) = ratchet(&json!({"frontier": {}}), &base);
        assert_eq!(f.len(), 3, "{f:?}");
        assert!(f.iter().all(|m| m.contains("vanished")));
    }

    /// The frontier's two directions: the share may not fall (HIGHER), and
    /// its guards may not fall either, so it cannot be bought.
    #[test]
    fn the_frontier_share_and_its_guards_ratchet_in_opposite_directions() {
        let base = json!({"frontier": {"codegen": {"allowed_share_permille": 400, "denied_at_exfil_vector_GUARD": 3}}, "corpus_steps_GUARD": 155});
        // Share up, guards flat: an improvement, not a failure.
        let (f, i) = ratchet(
            &json!({"frontier": {"codegen": {"allowed_share_permille": 450, "denied_at_exfil_vector_GUARD": 3}}, "corpus_steps_GUARD": 155}),
            &base,
        );
        assert!(f.is_empty(), "{f:?}");
        assert_eq!(i.len(), 1);
        // Share up BY shrinking the corpus or opening the exfil sink: refused.
        let (f, _) = ratchet(
            &json!({"frontier": {"codegen": {"allowed_share_permille": 900, "denied_at_exfil_vector_GUARD": 0}}, "corpus_steps_GUARD": 20}),
            &base,
        );
        assert_eq!(f.len(), 2, "{f:?}");
        // Share down: a regression.
        let (f, _) = ratchet(
            &json!({"frontier": {"codegen": {"allowed_share_permille": 300, "denied_at_exfil_vector_GUARD": 3}}, "corpus_steps_GUARD": 155}),
            &base,
        );
        assert_eq!(f.len(), 1, "{f:?}");
    }

    #[test]
    fn booleans_and_unknown_keys_are_ignored() {
        let base = json!({"flag": true, "note": "x", "other": 1});
        let (f, i) = ratchet(&json!({"flag": false, "note": "y", "other": 2}), &base);
        assert!(f.is_empty() && i.is_empty());
    }
}
