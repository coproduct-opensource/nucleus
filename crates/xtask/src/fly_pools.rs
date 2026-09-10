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
            Ok(())
        }
        Err(e) => bail!(
            "{MANAGER_TOML}'s POOLS default is a configuration the manager REFUSES:\n  {e}\n\
             This is the value a fresh deployment uses until `fly secrets set POOLS=...`\n\
             replaces it, so a default the manager rejects is a deployment that does not start."
        ),
    }
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
