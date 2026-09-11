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
//! # And the table that describes the pool must not contradict it
//!
//! `ci/fly-runner/README.md`'s table says the build pool is *size 16, standby 16* and the gate
//! pool *size 40, standby 40*; `POOLS` here says 8/8 and 16/16. Nothing compared them, and
//! gatehouse's F-82 took its headline — *"sixteen warm build machines are delivering two or
//! three concurrent jobs"* — from the table.
//!
//! **The first version of this gate demanded they be EQUAL, and that was wrong.** The two
//! numbers answer different questions, and noticing that is the finding rather than the
//! mismatch:
//!
//!   * `POOLS` here is the FRESH-DEPLOYMENT FALLBACK, and it declares `requires_volume: false`
//!     because a tracked default cannot carry volume ids that do not exist yet.
//!   * The README's table describes the DEPLOYED pool, whose `POOLS` secret carries
//!     `requires_volume: true` and the real ids — and whose size is capped by the volume count.
//!
//! So raising this default to 16 to "make them agree" would put sixteen volume-less build
//! machines into a fresh deployment, which is precisely the failure the comment above `POOLS`
//! describes: a compile pool without a volume fills its 8 GB rootfs, `ld terminated with signal
//! 7`, then ENOSPC, then four ejected required checks.
//!
//! What is left is checkable and true: every pool the manager is configured with is DESCRIBED,
//! and the fallback never claims more machines than the deployment it falls back from. That
//! catches the hazard (a default bigger than the volumes behind it) and does not pretend to know
//! the live value, which is whatever `fly secrets set POOLS=...` last wrote and is not in this
//! tree at all.
//!
//! **What it does NOT catch, said plainly: a reader taking the wrong number out of the README.**
//! No gate over two committed files can, because neither is the deployment. The compensating
//! control is the table saying which number it is, which is a sentence and not a check.
//!
//! # What decides this
//!
//! Two committed files. No source tree, no Fly API, no network.

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

const README: &str = "ci/fly-runner/README.md";

/// `(label, size, standby)` for every row of the README's pool table.
///
/// The table's cells read `… size 16, standby 16 …` and name the app in backticks, so the parse
/// is: a `|`-delimited line that mentions a `` `nucleus-fly-*` `` app, then `size N` and
/// `standby N` anywhere in it. Deliberately forgiving about everything else in the cell — the
/// guest shape, the volumes, the prose — because this gate is about two numbers and a stricter
/// parser would turn an editorial change into a red build.
pub fn readme_pools(readme: &str) -> Vec<(String, usize, usize)> {
    let number_after = |line: &str, key: &str| -> Option<usize> {
        let at = line.find(key)? + key.len();
        let rest = line[at..].trim_start();
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().ok()
    };
    readme
        .lines()
        .filter(|l| l.trim_start().starts_with('|'))
        .filter_map(|l| {
            let label = l
                .split('`')
                .find(|t| t.starts_with("nucleus-fly-"))?
                .to_string();
            Some((
                label,
                number_after(l, "size ")?,
                number_after(l, "standby ")?,
            ))
        })
        .collect()
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
            let readme = fs::read_to_string(root.join(README))
                .with_context(|| format!("reading {README}"))?;
            let described = readme_pools(&readme);
            if described.is_empty() {
                bail!(
                    "{README}: no pool table row names a `nucleus-fly-*` app with a size and a \
                     standby. A gate that cannot find what it compares is not a passing gate — \
                     if the table moved, move this parser with it."
                );
            }
            let mut wrong = Vec::new();
            for p in &pools {
                match described.iter().find(|(l, _, _)| l == &p.label) {
                    None => wrong.push(format!(
                        "POOLS configures `{}` and {README}'s table does not describe it, so \
                         nothing tells a reader what that pool is for",
                        p.label
                    )),
                    // The fallback may be SMALLER than the deployment — it is volume-less and
                    // has to be. It may never be larger: every machine past the volume count
                    // compiles onto an 8 GB rootfs and fills it.
                    Some((_, size, standby)) if p.size > *size || p.standby > *standby => wrong
                        .push(format!(
                            "{}: the volume-less fallback in {MANAGER_TOML} is size {} standby \
                             {}, LARGER than the size {size} standby {standby} pool {README} \
                             describes — a fresh deployment would start machines with no volume \
                             behind them",
                            p.label, p.size, p.standby
                        )),
                    Some(_) => {}
                }
            }
            if !wrong.is_empty() {
                bail!(
                    "the runner-pool default and the table describing it disagree:\n  {}",
                    wrong.join("\n  ")
                );
            }
            println!(
                "ok: {README} describes all {} configured pool(s), and the volume-less fallback \
                 is no larger than any of them",
                pools.len()
            );
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

    /// The README's table, parsed. Forgiving about everything but the two numbers and the app
    /// name, so an editorial change to a cell is not a red build.
    #[test]
    fn the_readme_table_yields_a_label_a_size_and_a_standby() {
        let t = "| pool | label | Machine | jobs |\n\
                 |---|---|---|---|\n\
                 | build | `nucleus-fly-build` | performance-8x, 32 GB, one volume each; size 16, standby 16 | things |\n\
                 | gate | `nucleus-fly-gate` | shared-cpu-8x, no volume; size 40, standby 40 | other things |\n";
        assert_eq!(
            readme_pools(t),
            vec![
                ("nucleus-fly-build".to_string(), 16, 16),
                ("nucleus-fly-gate".to_string(), 40, 40)
            ]
        );
    }

    /// **A gate that cannot find what it compares is not a passing gate.** If the table moves or
    /// is reformatted past this parser, that must be a red build and not a silent "all zero rows
    /// agree" — the vacuity failure F-78's small scopes and F-52's unread pin are both instances
    /// of.
    ///
    /// Written at the `check` level and not only over `readme_pools`, because that is where the
    /// guard has to hold. The first version asserted only that the parser returns nothing, which
    /// left the bail untested: deleting `if described.is_empty()` kept every test green and the
    /// real gate passing, which is F-88 exactly, one commit after recording it.
    #[test]
    fn a_readme_the_parser_cannot_read_is_a_red_build_and_not_a_vacuous_pass() {
        assert!(readme_pools("# a readme with prose and no table\n").is_empty());

        let dir = tempfile::tempdir().unwrap();
        let fly = dir.path().join("ci/fly-runner");
        std::fs::create_dir_all(&fly).unwrap();
        std::fs::write(
            fly.join("manager.toml"),
            "[env]\n  POOLS = '[{\"label\":\"nucleus-fly-build\",\"guest\":{\"cpu_kind\":\"shared\",\"cpus\":1,\"memory_mb\":256},\"size\":1,\"standby\":1}]'\n",
        )
        .unwrap();
        std::fs::write(fly.join("README.md"), "# prose, and the table has moved\n").unwrap();
        let e = check(dir.path()).expect_err("a table this cannot read must not pass");
        assert!(format!("{e}").contains("move this parser with it"), "{e}");
    }

    /// **The hazard this half of the gate exists for.** The fallback is volume-less. A default
    /// LARGER than the deployed pool starts build machines with no volume behind them, which
    /// fills an 8 GB rootfs: `ld terminated with signal 7`, then ENOSPC, then four ejected
    /// required checks. Smaller is fine and is the normal case.
    #[test]
    fn a_fallback_larger_than_the_pool_it_falls_back_from_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let fly = dir.path().join("ci/fly-runner");
        std::fs::create_dir_all(&fly).unwrap();
        let write = |size: usize| {
            std::fs::write(
                fly.join("manager.toml"),
                format!(
                    "[env]\n  POOLS = '[{{\"label\":\"nucleus-fly-build\",\"guest\":{{\"cpu_kind\":\"performance\",\"cpus\":8,\"memory_mb\":32768}},\"size\":{size},\"standby\":{size},\"requires_volume\":false}}]'\n"
                ),
            )
            .unwrap();
            std::fs::write(
                fly.join("README.md"),
                "| build | `nucleus-fly-build` | one volume each; size 16, standby 16 | things |\n",
            )
            .unwrap();
            check(dir.path())
        };
        write(8).expect("a smaller fallback is the normal case");
        let e = write(17).expect_err("a fallback past the volume count must be refused");
        assert!(format!("{e}").contains("no volume behind them"), "{e}");
    }

    /// A pool the manager is configured with and the table does not mention: nothing tells a
    /// reader what it is for, which is how a number gets taken out of the wrong row.
    #[test]
    fn a_configured_pool_the_table_does_not_describe_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let fly = dir.path().join("ci/fly-runner");
        std::fs::create_dir_all(&fly).unwrap();
        std::fs::write(
            fly.join("manager.toml"),
            "[env]\n  POOLS = '[{\"label\":\"nucleus-fly-mystery\",\"guest\":{\"cpu_kind\":\"shared\",\"cpus\":1,\"memory_mb\":256},\"size\":1,\"standby\":1}]'\n",
        )
        .unwrap();
        std::fs::write(
            fly.join("README.md"),
            "| build | `nucleus-fly-build` | size 16, standby 16 | things |\n",
        )
        .unwrap();
        let e = check(dir.path()).expect_err("an undescribed pool must be refused");
        assert!(format!("{e}").contains("does not describe it"), "{e}");
    }

    #[test]
    fn the_defect_this_gate_was_written_for_is_refused() {
        // requires_volume with no volumes: what the tracked default actually held.
        let bad = r#"[{"label":"b","guest":{"cpu_kind":"performance","cpus":8,"memory_mb":32768},"size":8,"standby":8,"requires_volume":true}]"#;
        let e = ci_fly_runner::parse_pools(bad).expect_err("must be refused");
        assert!(e.contains("requires_volume"), "message names the rule: {e}");
    }
}
