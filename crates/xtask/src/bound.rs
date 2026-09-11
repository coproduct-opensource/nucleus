//! Bound-enforcement gate — how much of the enforcement the repo declares is
//! actually reachable on the live path.
//!
//! # The defect this was built from
//!
//! A census of nucleus's 868 issues (2026-09-11) classified the 120 that are
//! `bug`-labelled or carry an audit prefix. **72 of them — 60%, of which 64 are
//! security-labelled — are one defect: a mechanism that exists and that nothing
//! binds to the live path.** `Kernel` flow control was opt-in, so `decide()`
//! without `enable_flow_control()` skipped every IFC check (#750). `FieldEnvelope`
//! and `WitnessBundle` were never compiled into portcullis (#781). Egress policy
//! sat behind a feature flag, off by default (#738). `FlowReceipt::verify_signature`
//! was a permanent stub (#732). `DischargedBundle`'s witness was discarded at
//! every callsite (#1360). `CapToken::authorize()` and
//! `SessionCleanseToken::authorize()` were `pub` with no authorization check
//! (#1348, #1358).
//!
//! They close in a median of **0.1 days** against 0.4 for everything else — the
//! fix is one call, one flag, one `&` removed. They survive for months because
//! nothing was looking: **45 of the 72 were found by a human reading code**, and
//! none by a gate.
//!
//! Both ADRs name this class and neither counts it. ADR 0006's Consequences ask
//! for exactly this: *"The audit found a category it does not cover: PROVEN but
//! not on the path. A `wired?` column, mechanically checked, would have caught
//! most of items 17–30."* ADR 0007 is the same defect from the other end — a
//! lint that exists in `tools/` and is never reached for enforces nothing.
//!
//! # What this gate measures
//!
//! One class, exactly: **witness discipline**. For the closed vocabulary of
//! witness types `scripts/inert-authority-manifest.txt` declares — `Authority`,
//! `CheckProof`, `DecisionToken`, `SessionCleanseToken`, and eleven more — every
//! production parameter that accepts one is a *declared* enforcement point:
//!
//! * **D** — sites that accept a witness.
//! * **B** — sites that accept it under a name the body can consult.
//! * **D − B** — sites that accept it as `_name` and drop it: the signature says
//!   a caller must hold the witness to get here, the body says the witness
//!   decides nothing.
//!
//! `B / D` is the number. It is the same scan `inert-authority` runs, with the
//! denominator that gate never computed.
//!
//! # Two ratios, and why the gate pins the second
//!
//! The raw census is **D=204, B=171, dropped=33**. But 32 of those 33 are class
//! `N` in the manifest — `DenyAllEffects::run(&self, _cmd, _authority)` refuses
//! unconditionally, so it performs no act and consults nothing correctly. Gating
//! the raw ratio would push toward binding a witness in a double that has no use
//! for one: pressure toward a worse tree, which is not what a gate is for.
//!
//! So the gate excludes the manifest's class-`N` sites from **both** terms:
//!
//! ```text
//!   raw    171 / 204  = 83.82%    (pure computation, nothing curated)
//!   net    171 / 172  = 99.41%    (class-N sites removed from D and from D−B)
//! ```
//!
//! The net ratio depends on a hand-adjudicated classification, which is the
//! obvious way to game it — reclassify a `D` row as `N` and the badge rises. Two
//! things bound that: the classification lives in a manifest whose per-`(file,
//! scope)` counts are already pinned exactly and probed by
//! `scripts/check-inert-authority.sh`, so a reclassification is a reviewed diff
//! with a reason string; and this gate asserts `dropped_raw == INERT_TOTAL`, so
//! the two independent scans must keep agreeing. They agree exactly today, which
//! also means no single line drops two witnesses — the first-match-wins bool
//! `inert_site` uses and this all-matches census are measuring one population.
//!
//! # What the measurement found, and what it means for the badge
//!
//! **Net debt is 1.** One site — `trait CaClient` in
//! `crates/nucleus-identity/src/ca/mod.rs` — performs an act while dropping its
//! witness. Witness discipline in nucleus is, for practical purposes, already
//! paid off.
//!
//! That refutes the obvious reading of the issue census. The 72 class-L6 defects
//! are *not* mostly witness drops; they are feature gates (#738, #781), opt-in
//! enforcement (#750, #1361), stubs (#732) and unconstructed types (#1348).
//! A badge showing 99.41% for one nearly-discharged class is honest and not yet
//! useful. It becomes useful when the classes that are *not* discharged join the
//! same denominator, one at a time, each with its own exact census — which is
//! the only way to add one without turning `B / D` into a number whose meaning
//! nobody can state.
//!
//! Until then the badge reads `authority bound`, naming its class. ADR 0007 I-1:
//! *a gate whose green is indistinguishable from vacuity*. A badge that said
//! `secure` off this number would be exactly that.
//!
//! # Why a floor, and why D is pinned too
//!
//! `.bound-ratchet.toml` pins a **floor on net B/D** in basis points. Pinning the
//! debt `D − B` instead would let the ratio fall while the debt held constant —
//! add ten dropped witnesses and ten bound ones and a debt pin sees nothing. But
//! a floor alone rewards deleting enforcement points: remove a witness parameter
//! and D and B fall together while the ratio rises. So `declared_floor` pins D as
//! well, and a shrinking surface has to be a deliberate edit with a dated note —
//! the trap `the-cci-counts-prose` records next door, where documenting a known
//! gap lowered the score.

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;

use crate::inert_authority::{Binding, witness_params};
use crate::law_mechanisms::{is_production_path, production_region, tracked};

pub const RATCHET: &str = ".bound-ratchet.toml";

/// A census of witness-accepting parameter sites over the production region.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Census {
    /// Sites that accept a witness under a consultable name.
    pub bound: usize,
    /// Sites that accept a witness and drop it.
    pub dropped: usize,
}

impl Census {
    /// Declared enforcement points: every site that accepts a witness at all.
    pub const fn declared(self) -> usize {
        self.bound + self.dropped
    }

    /// `B / D` in basis points, so the pin is an integer. An empty surface is
    /// zero, never 100%: nothing declared is nothing bound, and rounding it up
    /// would let deleting the last witness paint the badge green.
    pub const fn basis_points(self) -> u32 {
        if self.declared() == 0 {
            return 0;
        }
        ((self.bound * 10_000) / self.declared()) as u32
    }
}

/// Count witness-accepting sites per file over the production region of `corpus`.
pub fn census(corpus: &BTreeMap<String, String>, witness: &[String]) -> BTreeMap<String, Census> {
    let mut out: BTreeMap<String, Census> = BTreeMap::new();
    for (path, src) in corpus {
        for line in production_region(src).lines() {
            for binding in witness_params(line, witness) {
                let e = out.entry(path.clone()).or_default();
                match binding {
                    Binding::Bound => e.bound += 1,
                    Binding::Dropped => e.dropped += 1,
                }
            }
        }
    }
    out
}

pub fn total(per_file: &BTreeMap<String, Census>) -> Census {
    per_file.values().fold(Census::default(), |a, c| Census {
        bound: a.bound + c.bound,
        dropped: a.dropped + c.dropped,
    })
}

/// The pinned floor, read from `.bound-ratchet.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pin {
    /// Minimum `B / D`, in basis points. May only rise.
    pub floor_bp: u32,
    /// Minimum `D`. A shrinking surface is a decision, not a win.
    pub declared_floor: usize,
}

pub fn parse_pin(text: &str) -> Result<Pin> {
    let mut floor_bp = None;
    let mut declared_floor = None;
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('[') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            bail!("line {}: not `key = value`: {raw}", lineno + 1);
        };
        let value = value.trim();
        match key.trim() {
            "floor_bp" => floor_bp = Some(value.parse().context("floor_bp is not a number")?),
            "declared_floor" => {
                declared_floor = Some(value.parse().context("declared_floor is not a number")?);
            }
            other => bail!("line {}: unknown key `{other}`", lineno + 1),
        }
    }
    let floor_bp: u32 =
        floor_bp.context("floor_bp= is missing; an unpinned floor gates nothing")?;
    let declared_floor: usize =
        declared_floor.context("declared_floor= is missing; the surface must be pinned too")?;
    if floor_bp == 0 {
        bail!("floor_bp=0 passes for every tree, including one with no enforcement at all");
    }
    if floor_bp > 10_000 {
        bail!("floor_bp={floor_bp} exceeds 10000bp; the gate could never pass");
    }
    if declared_floor == 0 {
        bail!("declared_floor=0 passes for a tree with no witness-accepting site");
    }
    Ok(Pin {
        floor_bp,
        declared_floor,
    })
}

/// One disagreement between the pin and the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// The ratio fell below its floor.
    Fell { found_bp: u32, floor_bp: u32 },
    /// The declared surface shrank.
    Shrank { found: usize, floor: usize },
    /// The ratio rose and the pin was not raised with it.
    Slack { found_bp: u32, floor_bp: u32 },
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fell { found_bp, floor_bp } => write!(
                f,
                "B/D fell to {}.{:02}% against a floor of {}.{:02}%: a witness-accepting site \
                 stopped being able to consult its witness.",
                found_bp / 100,
                found_bp % 100,
                floor_bp / 100,
                floor_bp % 100
            ),
            Self::Shrank { found, floor } => write!(
                f,
                "the declared surface fell to {found} sites from a floor of {floor}. Deleting an \
                 enforcement point raises B/D without binding anything; if the deletion is \
                 intended, lower declared_floor in the same edit with a dated note."
            ),
            Self::Slack { found_bp, floor_bp } => write!(
                f,
                "B/D is {}.{:02}% but the floor is pinned at {}.{:02}%. Raise floor_bp to the \
                 measured value: a floor with slack under it is a gate that has already stopped \
                 gating (ADR 0007 I-1).",
                found_bp / 100,
                found_bp % 100,
                floor_bp / 100,
                floor_bp % 100
            ),
        }
    }
}

pub fn decide(pin: Pin, found: Census) -> Vec<Finding> {
    let mut out = Vec::new();
    let found_bp = found.basis_points();
    if found_bp < pin.floor_bp {
        out.push(Finding::Fell {
            found_bp,
            floor_bp: pin.floor_bp,
        });
    } else if found_bp > pin.floor_bp {
        out.push(Finding::Slack {
            found_bp,
            floor_bp: pin.floor_bp,
        });
    }
    if found.declared() < pin.declared_floor {
        out.push(Finding::Shrank {
            found: found.declared(),
            floor: pin.declared_floor,
        });
    }
    out
}

/// The raw census, the manifest's class-`N` exclusions, and the net.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    pub raw: Census,
    /// Sites the manifest adjudicates as `N` — accepted and dropped, but no act
    /// is performed, so nothing was owed. Removed from D and from D − B alike.
    pub excused: usize,
}

impl Report {
    /// The gated ratio: class-`N` sites out of both terms.
    pub const fn net(self) -> Census {
        Census {
            bound: self.raw.bound,
            dropped: self.raw.dropped - self.excused,
        }
    }
}

pub fn report(
    corpus: &BTreeMap<String, String>,
    manifest: &crate::inert_authority::Manifest,
) -> Result<(Report, BTreeMap<String, Census>)> {
    let per_file = census(corpus, &manifest.witness);
    let raw = total(&per_file);
    if raw.dropped != manifest.inert_total {
        bail!(
            "this census counts {} dropped witness(es); INERT_TOTAL pins {}. Most likely a \
             parameter started accepting a witness as `_name` and no row was added for it — a \
             gate that is now present and decides nothing. Failing that, two scans over one \
             population disagree and at least one is wrong, so the ratio below would come from \
             the wrong denominator either way. Record the site in {} and raise INERT_TOTAL, or \
             bind the witness.",
            raw.dropped,
            manifest.inert_total,
            crate::inert_authority::MANIFEST
        );
    }
    let excused: usize = manifest
        .rows
        .iter()
        .filter(|r| r.class == 'N')
        .map(|r| r.count)
        .sum();
    Ok((Report { raw, excused }, per_file))
}

pub fn run(measure: bool, badge: bool) -> Result<i32> {
    let text = std::fs::read_to_string(crate::inert_authority::MANIFEST)
        .with_context(|| format!("reading {}", crate::inert_authority::MANIFEST))?;
    let manifest = crate::inert_authority::parse(&text)?;
    let corpus = tracked(is_production_path)?;
    let (rep, per_file) = report(&corpus, &manifest)?;
    let net = rep.net();

    if measure {
        println!(
            "raw  D={} B={} dropped={}  B/D={}",
            rep.raw.declared(),
            rep.raw.bound,
            rep.raw.dropped,
            pct(rep.raw.basis_points())
        );
        println!(
            "net  D={} B={} dropped={}  B/D={}   ({} class-N site(s) excused)",
            net.declared(),
            net.bound,
            net.dropped,
            pct(net.basis_points()),
            rep.excused
        );
        for (path, c) in &per_file {
            if c.dropped > 0 {
                println!(
                    "  {:3} dropped / {:3} sites  {path}",
                    c.dropped,
                    c.declared()
                );
            }
        }
        return Ok(0);
    }

    if badge {
        println!(
            r#"{{"schemaVersion":1,"label":"authority bound","message":"{}/{}","color":"{}"}}"#,
            net.bound,
            net.declared(),
            if net.basis_points() >= 9_900 {
                "brightgreen"
            } else if net.basis_points() >= 9_000 {
                "yellow"
            } else {
                "orange"
            }
        );
        return Ok(0);
    }

    let pin = parse_pin(
        &std::fs::read_to_string(RATCHET).with_context(|| format!("reading {RATCHET}"))?,
    )?;
    let findings = decide(pin, net);
    if findings.is_empty() {
        println!(
            "OK: {} of {} witness-accepting sites bind their witness under a consultable name \
             ({}, floor {}).",
            net.bound,
            net.declared(),
            pct(net.basis_points()),
            pct(pin.floor_bp)
        );
        println!(
            "     raw census D={} B={} dropped={}; {} class-N site(s) excused by \
             {}, and dropped == INERT_TOTAL.",
            rep.raw.declared(),
            rep.raw.bound,
            rep.raw.dropped,
            rep.excused,
            crate::inert_authority::MANIFEST
        );
        println!(
            "     {} site(s) perform an act while dropping the witness. Witness discipline is \
             one class of ADR 0006's `wired?` column; the classes that are not discharged \
             (feature-gated, opt-in, stubbed enforcement) are not counted here.",
            net.dropped
        );
        return Ok(0);
    }
    println!("FAIL: {} bound-enforcement finding(s).", findings.len());
    for f in &findings {
        println!("  {f}");
    }
    Ok(1)
}

/// Basis points as a percentage, for messages a human reads.
fn pct(bp: u32) -> String {
    format!("{}.{:02}%", bp / 100, bp % 100)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inert_authority::{Binding, witness_params};

    fn witness() -> Vec<String> {
        vec!["Authority".to_string(), "CheckProof".to_string()]
    }

    #[test]
    fn a_bound_witness_is_a_declared_site() {
        assert_eq!(
            witness_params(
                "    fn run(&self, cmd: &str, authority: Authority) {",
                &witness()
            ),
            vec![Binding::Bound]
        );
    }

    #[test]
    fn a_dropped_witness_is_a_declared_site_too() {
        // The denominator's whole point: an ignored witness still counts as a
        // place the design says enforcement happens.
        assert_eq!(
            witness_params("    fn run(&self, _authority: Authority) {", &witness()),
            vec![Binding::Dropped]
        );
    }

    #[test]
    fn two_witnesses_on_one_line_are_two_sites() {
        // `inert_site` counts such a line once, which is how INERT_TOTAL was
        // measured; the census counts both. They agree today only because no
        // such line exists, and `report` asserts that rather than assuming it.
        assert_eq!(
            witness_params("    fn f(a: Authority, _p: CheckProof) {", &witness()),
            vec![Binding::Bound, Binding::Dropped]
        );
    }

    #[test]
    fn an_underscore_inside_a_name_does_not_split_the_identifier() {
        // `some_authority` is one bound site, not a bound one plus a dropped one.
        assert_eq!(
            witness_params("    fn f(some_authority: Authority) {", &witness()),
            vec![Binding::Bound]
        );
    }

    #[test]
    fn a_non_witness_type_is_not_a_site() {
        assert!(witness_params("    fn f(authority: String) {", &witness()).is_empty());
    }

    #[test]
    fn an_empty_surface_is_zero_not_a_hundred_percent() {
        // Deleting the last witness parameter must not paint the badge green.
        assert_eq!(Census::default().basis_points(), 0);
    }

    #[test]
    fn the_net_removes_excused_sites_from_both_terms() {
        let rep = Report {
            raw: Census {
                bound: 171,
                dropped: 33,
            },
            excused: 32,
        };
        assert_eq!(rep.raw.declared(), 204);
        assert_eq!(rep.net().declared(), 172);
        assert_eq!(rep.net().dropped, 1);
        assert_eq!(rep.net().basis_points(), 9941);
    }

    #[test]
    fn a_ratio_below_the_floor_fails() {
        let pin = Pin {
            floor_bp: 9941,
            declared_floor: 172,
        };
        let found = Census {
            bound: 170,
            dropped: 2,
        };
        assert!(matches!(
            decide(pin, found).as_slice(),
            [Finding::Fell { .. }]
        ));
    }

    #[test]
    fn a_ratio_above_the_floor_also_fails_so_the_pin_cannot_go_slack() {
        let pin = Pin {
            floor_bp: 9000,
            declared_floor: 172,
        };
        let found = Census {
            bound: 171,
            dropped: 1,
        };
        assert!(matches!(
            decide(pin, found).as_slice(),
            [Finding::Slack { .. }]
        ));
    }

    #[test]
    fn deleting_enforcement_points_does_not_pass_by_raising_the_ratio() {
        // 100% of a smaller surface. The ratio is perfect and the gate refuses.
        let pin = Pin {
            floor_bp: 9941,
            declared_floor: 172,
        };
        let found = Census {
            bound: 100,
            dropped: 0,
        };
        let findings = decide(pin, found);
        assert!(findings.iter().any(|f| matches!(f, Finding::Shrank { .. })));
    }

    #[test]
    fn a_zero_floor_is_rejected_rather_than_passing_vacuously() {
        let err = parse_pin("floor_bp = 0\ndeclared_floor = 1\n").unwrap_err();
        assert!(err.to_string().contains("no enforcement at all"));
    }

    #[test]
    fn a_zero_declared_floor_is_rejected() {
        let err = parse_pin("floor_bp = 1\ndeclared_floor = 0\n").unwrap_err();
        assert!(err.to_string().contains("no witness-accepting site"));
    }

    #[test]
    fn a_missing_pin_is_rejected() {
        assert!(
            parse_pin("floor_bp = 9941\n")
                .unwrap_err()
                .to_string()
                .contains("declared_floor")
        );
        assert!(
            parse_pin("declared_floor = 172\n")
                .unwrap_err()
                .to_string()
                .contains("floor_bp")
        );
    }

    #[test]
    fn the_committed_ratchet_parses_and_pins_both_terms() {
        // The gate's own configuration is a subject, not an assumption: a
        // ratchet that stopped parsing would be discovered in CI, not here.
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../",
            ".bound-ratchet.toml"
        ))
        .expect("the committed ratchet is readable");
        let pin = parse_pin(&text).expect("the committed ratchet parses");
        assert!(pin.floor_bp > 0 && pin.declared_floor > 0);
    }
}
