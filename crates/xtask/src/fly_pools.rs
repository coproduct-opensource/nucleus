//! `cargo xtask fly-pools` — the committed runner-pool default must be one the manager accepts.
//!
//! `ci/fly-runner/manager.toml` carries a `POOLS` default that a fresh deployment uses
//! until `fly secrets set POOLS=...` replaces it with the real volume ids. The manager
//! validates that JSON at startup (`ci_fly_runner::parse_pools`), and nothing validated
//! the committed copy — so the tracked default could be, and was, a configuration the
//! manager refuses:
//!
//! ```text
//! "size":8,"standby":8,"requires_volume":true      and no "volumes" key
//! ```
//!
//! `requires_volume` with zero volumes for eight machines is rejected by
//! `crates/ci-fly-runner/src/lib.rs`, whose message explains why it must be:
//! machines past the end of the volume list "would compile onto the root filesystem and
//! run out of disk". That failure is not hypothetical — `requires_volume`'s own doc
//! records it costing four required checks, ejected from the merge queue while looking
//! clean, after `ld terminated with signal 7 [Bus error]` and then ENOSPC.
//!
//! The comment two lines above the value asserted the opposite: "this tracked default
//! has none, so a fresh deployment works without them (cold caches)." It could not.
//!
//! This calls **the manager's own validator**. A second implementation of the rule would
//! be a second thing to drift, which is the failure this whole family of gates exists to
//! refuse.
//!
//! # What decides this
//!
//! One committed TOML file. No source tree, no Fly API, no network.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

const MANAGER_TOML: &str = "ci/fly-runner/manager.toml";
/// The prose table that documents the same pools, and disagreed with them.
const README: &str = "ci/fly-runner/README.md";
/// How many `(pool, field)` pairs the README and the TOML may still disagree on. Shrink-only.
const DRIFT: &str = "ci/fly-pools-drift.txt";
/// The other config the same README restates numbers from.
const QUEUE_TOML: &str = "ci/merge-queue.toml";

/// The `POOLS = '...'` value, as the manager would receive it.
pub fn pools_json(manager_toml: &str) -> Result<String> {
    for line in manager_toml.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("POOLS") {
            let rest = rest.trim_start();
            let Some(rest) = rest.strip_prefix('=') else {
                continue;
            };
            let rest = rest.trim();
            // Single-quoted TOML literal string: no escapes, so the value is what is between.
            if let Some(inner) = rest.strip_prefix('\'').and_then(|r| r.rsplit_once('\'')) {
                return Ok(inner.0.to_string());
            }
            if let Some(inner) = rest.strip_prefix('"').and_then(|r| r.rsplit_once('"')) {
                return Ok(inner.0.to_string());
            }
            bail!("{MANAGER_TOML}: POOLS is not a quoted string");
        }
    }
    bail!("{MANAGER_TOML}: no POOLS assignment")
}

pub fn check(root: &Path) -> Result<()> {
    let text = fs::read_to_string(root.join(MANAGER_TOML))
        .with_context(|| format!("reading {MANAGER_TOML}"))?;
    let json = pools_json(&text)?;

    match ci_fly_runner::parse_pools(&json) {
        Ok(pools) => {
            for p in &pools {
                println!(
                    "ok: {} — size {} standby {} volumes {} requires_volume {}",
                    p.label,
                    p.size,
                    p.standby,
                    p.volumes.len(),
                    p.requires_volume
                );
            }
            if pools.is_empty() {
                bail!("{MANAGER_TOML}: POOLS parsed to no pools at all");
            }
            readme_agrees(root, &pools)
        }
        Err(e) => bail!(
            "{MANAGER_TOML}'s POOLS default is a configuration the manager REFUSES:\n  {e}\n\
             This is the value a fresh deployment uses until `fly secrets set POOLS=...`\n\
             replaces it, so a default the manager rejects is a deployment that does not start."
        ),
    }
}

/// `ci/fly-runner/README.md`'s pool table must agree with the value the manager receives.
///
/// The README is how anyone learns what the pools ARE — it is the first thing a reader opens, and
/// `fly-pools` referenced it zero times, checking only that the TOML parses. So the two could drift
/// silently, and had: measured 2026-09-11, **all four numbers disagreed** — the README said the
/// build pool is size 16 standby 16 where the TOML says 8 and 8, and the gate pool size 40 standby
/// 40 where the TOML says 16 and 16.
///
/// RATCHETED rather than driven to zero, and the reason is that neither side is obviously right.
/// `manager.toml`'s POOLS is the default a fresh deployment uses until `fly secrets set POOLS=...`
/// replaces it, so the README may be describing the deployed secret truthfully while the tracked
/// default describes a bootstrap. Live runner counts settle nothing — `FINDINGS.md` F-75 measured
/// one to two build machines, which matches neither 8 nor 16. Deciding that needs the secret, which
/// is not readable from a checkout; making the disagreement visible and un-growable does not.
fn readme_agrees(root: &Path, pools: &[ci_fly_runner::PoolSpec]) -> Result<()> {
    let text =
        fs::read_to_string(root.join(README)).with_context(|| format!("reading {README}"))?;
    let pin: usize = fs::read_to_string(root.join(DRIFT))
        .with_context(|| format!("{DRIFT} is missing — nothing to ratchet the drift against"))?
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("DRIFT="))
        .and_then(|v| v.trim().parse().ok())
        .with_context(|| format!("{DRIFT} has no DRIFT= line"))?;

    let mut drift = Vec::new();
    let mut rows = 0usize;
    for p in pools {
        // The row naming this pool's label, and the `size N, standby M` it claims.
        let Some(row) = text
            .lines()
            .find(|l| l.starts_with('|') && l.contains(&format!("`{}`", p.label)))
        else {
            bail!(
                "{README} has no table row for pool {:?} — the table is the documentation of record",
                p.label
            );
        };
        rows += 1;
        for (field, declared) in [("size", p.size), ("standby", p.standby)] {
            let claimed = row
                .split(&format!("{field} "))
                .nth(1)
                .and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next())
                .and_then(|n| n.parse::<usize>().ok());
            match claimed {
                None => bail!("{README}'s row for {:?} states no {field}", p.label),
                Some(c) if c != declared => {
                    drift.push(format!(
                        "{} {field}: README {c}, {MANAGER_TOML} {declared}",
                        p.label
                    ));
                }
                Some(_) => {}
            }
        }
    }
    if rows == 0 {
        bail!("{README} matched no pool rows — the comparison examined nothing");
    }
    for d in &drift {
        println!("  drift  {d}");
    }
    if drift.len() > pin {
        bail!(
            "{} README/TOML disagreement(s), pin {pin} — the file a reader opens to learn the pool \
             sizes does not agree with the value the manager receives. Fix one side, or raise the \
             pin with the reason they differ",
            drift.len()
        );
    }
    if drift.len() < pin {
        bail!(
            "{} disagreement(s), pin {pin} — lower the pin in the same change that fixed one",
            drift.len()
        );
    }
    println!(
        "OK: {rows} pool(s) compared against {README}; {} still disagree (pin {pin})",
        drift.len()
    );
    readme_queue_constants(root, &text)
}

/// The same README also restates merge-queue constants, and nothing compared those either.
///
/// `ci/fly-runner/README.md` explains the queue's throughput by quoting `max_entries_to_build = 1`
/// from `ci/merge-queue.toml`. `ci-spec live-parity` compares that TOML against the LIVE ruleset; no
/// gate reads this README at all. So raising the constant — which was tried and reverted earlier,
/// per merge-queue.toml's own note — would leave the prose saying 1 with nothing to notice.
///
/// **This half is preventive, and that is worth saying plainly.** The pool comparison above found
/// four live disagreements; these two values agree today. A gate half that has never been red on a
/// real defect is a weaker thing than one that has, and the honest place to record which is which is
/// here rather than in a commit message nobody re-reads.
///
/// The value is quoted across a LINE WRAP — `max_entries_to_build` ending one line and `= 1`
/// starting the next — which is why a naive grep misses it and why this class of drift survives.
/// The scan normalises whitespace before matching, deliberately.
fn readme_queue_constants(root: &Path, readme: &str) -> Result<()> {
    let toml = fs::read_to_string(root.join(QUEUE_TOML))
        .with_context(|| format!("reading {QUEUE_TOML}"))?;
    let joined: String = readme.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut checked = 0usize;
    for key in ["max_entries_to_build"] {
        let Some(declared) = toml
            .lines()
            .map(str::trim)
            .find_map(|l| l.strip_prefix(key))
            .and_then(|r| r.trim_start().strip_prefix('='))
            .and_then(|r| r.trim().parse::<usize>().ok())
        else {
            bail!("{QUEUE_TOML} states no {key} — the constant this README quotes is gone");
        };
        let Some(after) = joined.split(key).nth(1) else {
            bail!("{README} no longer quotes {key}; drop this check or restore the sentence");
        };
        let claimed = after
            .trim_start()
            .strip_prefix('=')
            .map(str::trim_start)
            .and_then(|r| r.split(|c: char| !c.is_ascii_digit()).next())
            .and_then(|n| n.parse::<usize>().ok());
        match claimed {
            None => bail!("{README} quotes {key} without a value"),
            Some(c) if c != declared => bail!(
                "{README} says {key} = {c}, {QUEUE_TOML} says {declared} — the prose explaining the \
                 queue's throughput disagrees with the queue's configuration"
            ),
            Some(_) => checked += 1,
        }
    }
    if checked == 0 {
        bail!("no merge-queue constant was compared — the check examined nothing");
    }
    println!("OK: {checked} merge-queue constant(s) in {README} agree with {QUEUE_TOML}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn the_committed_default_is_one_the_manager_accepts() {
        check(&root()).expect("the tracked POOLS default must validate");
    }

    #[test]
    fn extracts_the_single_quoted_value() {
        let t = "FLY_REGION = \"iad\"\nPOOLS = '[{\"label\":\"a\"}]'\n";
        assert_eq!(pools_json(t).unwrap(), "[{\"label\":\"a\"}]");
    }

    #[test]
    fn a_missing_pools_assignment_is_an_error() {
        assert!(pools_json("FLY_REGION = \"iad\"\n").is_err());
    }

    #[test]
    fn the_defect_this_gate_was_written_for_is_refused() {
        // requires_volume with no volumes: what the tracked default actually held.
        let bad = r#"[{"label":"b","guest":{"cpu_kind":"performance","cpus":8,"memory_mb":32768},"size":8,"standby":8,"requires_volume":true}]"#;
        let e = ci_fly_runner::parse_pools(bad).expect_err("must be refused");
        assert!(e.contains("requires_volume"), "message names the rule: {e}");
    }
}
