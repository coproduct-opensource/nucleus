//! `nucleus-delivery-conformance` — the boot gate's trace-conformance step: the
//! in-guest probe's OBSERVED environment inventory, replayed through the
//! production classifier and the extracted delivery oracle.
//!
//! The FM-5 chain so far: the delivery relation is PROVED (Lean, over the
//! Aeneas-extracted `ident_may_deliver`), the launch construction is
//! host-unit-TESTED against it pointwise, and the in-guest probe OBSERVES the
//! real child's posture per boot (asserting a fixed list of identity variables
//! is absent). This binary closes the remaining gap between the probe and the
//! oracle: the probe's list is a hand-enumerated sample, while the oracle is
//! categorical. Here, every name the probe actually SAW in the workload's
//! environment (`NUCLEUS_WORKLOAD_ENV: <name>` inventory lines in the guest
//! log) is classified with the SAME `env_key_material` the launch builder uses
//! and checked against the SAME `ident_may_deliver(kind, Workload)` the Lean
//! theorems are about — so a leaked variable is refused by classification, not
//! by membership in a list someone remembered to extend.
//!
//! Fail-closed on silence: an empty inventory (or one missing the proxy-URL
//! anchor the probe itself requires) FAILS. A checker that passes when the
//! thing it checks never ran is the false-green shape this repo has removed
//! several times; absence of evidence here is a red verdict, not a green one.
//!
//! Exit codes: 0 conformant; 1 violation or missing/empty inventory; 2 usage.

use nucleus_ifc_kernel::env_classifier::env_key_material;
use nucleus_ifc_kernel::extracted::identity::{Principal, ident_may_deliver};

/// The inventory needle the workload probe emits, one line per observed
/// environment name (names only — values never leave the guest).
const INVENTORY_NEEDLE: &str = "NUCLEUS_WORKLOAD_ENV: ";

/// The non-vacuity anchor: the probe requires this to be present in the
/// workload environment, so a real inventory always contains it.
const ANCHOR: &str = "NUCLEUS_TOOL_PROXY_URL";

/// Extract the observed inventory (deduplicated, order-preserving) from log text.
fn parse_inventory(log: &str) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut names = Vec::new();
    for line in log.lines() {
        if let Some(idx) = line.find(INVENTORY_NEEDLE) {
            let name = line[idx + INVENTORY_NEEDLE.len()..].trim();
            // Guest consoles interleave; keep only plausible env names so a
            // corrupted line cannot smuggle an unparseable entry past review.
            if !name.is_empty()
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && seen.insert(name.to_string())
            {
                names.push(name.to_string());
            }
        }
    }
    names
}

/// One verdict line per name; returns the violations.
fn check_inventory(names: &[String]) -> Vec<String> {
    let mut violations = Vec::new();
    for name in names {
        let kind = env_key_material(name);
        let licensed = ident_may_deliver(kind, Principal::Workload);
        println!(
            "conformance: {name} -> {kind:?} -> {}",
            if licensed { "licensed" } else { "REFUSED" }
        );
        if !licensed {
            violations.push(format!(
                "{name} classifies as {kind:?}, which ident_may_deliver refuses for the workload"
            ));
        }
    }
    violations
}

fn main() {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        eprintln!("usage: nucleus-delivery-conformance <guest-log>...");
        std::process::exit(2);
    }

    let mut inventory: Vec<String> = Vec::new();
    for path in &paths {
        match std::fs::read_to_string(path) {
            Ok(text) => inventory.extend(parse_inventory(&text)),
            Err(err) => {
                // A named log that cannot be read is a broken harness, not a pass.
                eprintln!("conformance: cannot read {path}: {err}");
                std::process::exit(1);
            }
        }
    }

    if inventory.is_empty() {
        eprintln!(
            "conformance: no {INVENTORY_NEEDLE:?} lines found in {} log(s) — the probe's \
             inventory never reached the collected logs, so there is nothing to certify. \
             Failing closed.",
            paths.len()
        );
        std::process::exit(1);
    }
    if !inventory.iter().any(|n| n == ANCHOR) {
        eprintln!(
            "conformance: inventory ({} names) is missing the {ANCHOR} anchor the probe \
             requires — the inventory is not from a mediated workload run. Failing closed.",
            inventory.len()
        );
        std::process::exit(1);
    }

    let violations = check_inventory(&inventory);
    if violations.is_empty() {
        println!(
            "conformance: OK — {} observed name(s), every one licensed by \
             ident_may_deliver(_, Workload)",
            inventory.len()
        );
    } else {
        for v in &violations {
            eprintln!("conformance: VIOLATION — {v}");
        }
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The observed-shape fixture: what a real green boot's inventory looks like
    /// (names from the probe's own contract plus ordinary runtime vars). The
    /// middle rung does real work here: the AUTH secret is Internal and
    /// LICENSED, while everything Secret is refused — so a green verdict is not
    /// "nothing NUCLEUS_-prefixed crossed".
    const GREEN_LOG: &str = "\
[    7.1] NUCLEUS_WORKLOAD_ENV: PATH\n\
[    7.1] NUCLEUS_WORKLOAD_ENV: HOME\n\
[    7.1] NUCLEUS_WORKLOAD_ENV: NUCLEUS_TOOL_PROXY_URL\n\
[    7.1] NUCLEUS_WORKLOAD_ENV: NUCLEUS_TOOL_PROXY_AUTH_SECRET\n\
[    7.1] NUCLEUS_WORKLOAD_ENV: NUCLEUS_EGRESS_GITHUB_URL\n";

    #[test]
    fn green_inventory_is_licensed() {
        let inv = parse_inventory(GREEN_LOG);
        assert_eq!(inv.len(), 5);
        assert!(inv.iter().any(|n| n == ANCHOR));
        assert!(check_inventory(&inv).is_empty());
    }

    #[test]
    fn the_internal_rung_is_licensed_not_merely_absent() {
        // ProxyAuthSecret is Internal — deliverable to the workload BY THE
        // ORACLE, not by fallthrough. If this ever flips, the green fixture
        // above goes red for the right reason.
        let v = check_inventory(&["NUCLEUS_TOOL_PROXY_AUTH_SECRET".into()]);
        assert!(v.is_empty());
    }

    #[test]
    fn a_leaked_identity_cert_is_refused_by_the_oracle() {
        let log = format!("{GREEN_LOG}[    7.2] NUCLEUS_WORKLOAD_ENV: NUCLEUS_IDENTITY_CERT\n");
        let inv = parse_inventory(&log);
        let violations = check_inventory(&inv);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("NUCLEUS_IDENTITY_CERT"));
        assert!(violations[0].contains("SvidCert"));
    }

    #[test]
    fn a_leaked_task_token_is_refused_by_the_oracle() {
        let violations = check_inventory(&["NUCLEUS_TASK_TOKEN".into()]);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn a_novel_dlc_variable_is_refused_by_the_prefix_rule_not_a_list() {
        // The probe's hand-enumerated list could not know this name; the
        // classifier's prefix rule + the oracle refuse it anyway. This is the
        // categorical-beats-remembered-attack case the harness exists for.
        let violations = check_inventory(&["NUCLEUS_DLC_SOMETHING_NEW".into()]);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn inventory_parse_ignores_corrupt_and_duplicate_lines() {
        let log = "\
noise NUCLEUS_WORKLOAD_ENV: GOOD_NAME\n\
NUCLEUS_WORKLOAD_ENV: bad name with spaces\n\
NUCLEUS_WORKLOAD_ENV: GOOD_NAME\n";
        let inv = parse_inventory(log);
        assert_eq!(inv, vec!["GOOD_NAME".to_string()]);
    }
}
