//! The census, held to a pin.
//!
//! # Why the census needed binding at all
//!
//! `census.rs` is, in its own words, "the audit the design rests on": which
//! required contexts have a key and which do not, by name, with `Unmeasured`
//! kept separate from `Refused` so that "could not look" never reads as
//! "looked and it has none".
//!
//! Nothing ran it. Measured 2026-09-21 by grepping every workflow, script and
//! required-check entry: no caller. A mechanism that exists and is not bound to
//! the live path is the defect family the scorecard header puts at 60% of this
//! repository's classified bugs, and an audit nobody runs is its purest form —
//! the answer is correct and nobody asked.
//!
//! What it says today is worth the wiring on its own: **47 required contexts,
//! 11 keyed, 36 refused**, and every refusal for one reason — the workflow
//! declares no `paths:` filter, so its read-set is the whole tree and a key
//! over it would never hit.
//!
//! # What the pin holds
//!
//! Two numbers and a direction each:
//!
//! * `keyed_floor` may only RISE. A context that gains a declared read-set
//!   becomes cacheable, and losing that is a regression this refuses.
//! * `unmeasured_ceiling` may only FALL. `Unmeasured` is "could not look", and
//!   a growing count of contexts the census cannot judge is the vacuity the
//!   three-valued `Outcome` exists to prevent.
//!
//! The POPULATION is deliberately not pinned here. `ci/required-checks.txt`
//! already carries `# PINNED = n`, and a second copy is the shape ADR 0007 G
//! forbids: if a fact is written twice, one of them goes stale. This module
//! reads the ledger's own pin and holds the census to it, so a census that
//! scanned three contexts and found three keyed cannot pass a floor of eleven.

use anyhow::{Context, Result, bail};

/// The pinned floors for the census.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pins {
    /// Contexts with a derivable key. May only rise.
    pub keyed_floor: usize,
    /// Contexts the census could not judge. May only fall.
    pub unmeasured_ceiling: usize,
}

/// What holding the census to its pin decided.
///
/// Three-valued for the same reason `Outcome` is: a census that could not run
/// is not a census that found nothing, and reporting the first as the second is
/// how a gate goes quietly green (ADR 0007 A-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The census ran over the whole ledger and met both pins.
    Held {
        keyed: usize,
        refused: usize,
        population: usize,
    },
    /// The census ran and a pin was missed.
    Regressed(String),
    /// The census did not see what it claims to have seen. Never `Regressed`:
    /// a scan over the wrong population says nothing about the pins.
    CouldNotLook(String),
}

/// Parse the pin file: `key = value` lines, `#` comments.
///
/// # Errors
///
/// If a key is missing, repeated, or not a number.
pub fn parse_pins(text: &str) -> Result<Pins> {
    let mut keyed_floor: Option<usize> = None;
    let mut unmeasured_ceiling: Option<usize> = None;
    // `(1..).zip(...)` rather than `enumerate()` + 1: this crate denies
    // `arithmetic_side_effects` for the shipped build, and a line number is not
    // worth an exception.
    for (lineno, raw) in (1usize..).zip(text.lines()) {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            bail!("line {}: not `key = value`: {raw}", lineno);
        };
        let value = value.trim();
        let slot = match key.trim() {
            "keyed_floor" => &mut keyed_floor,
            "unmeasured_ceiling" => &mut unmeasured_ceiling,
            other => bail!("line {}: unknown key `{other}`", lineno),
        };
        if slot.is_some() {
            bail!("line {}: `{}` declared twice", lineno, key.trim());
        }
        *slot = Some(
            value
                .parse()
                .with_context(|| format!("line {}: `{value}` is not a number", lineno))?,
        );
    }
    Ok(Pins {
        keyed_floor: keyed_floor.context("no `keyed_floor`; an unpinned census gates nothing")?,
        unmeasured_ceiling: unmeasured_ceiling
            .context("no `unmeasured_ceiling`; the count of contexts nobody could judge would be free to grow")?,
    })
}

/// The population `ci/required-checks.txt` pins for itself.
///
/// Read rather than restated: the ledger already carries this number, and a
/// second copy would drift (ADR 0007 G).
///
/// # Errors
///
/// If the ledger carries no `# PINNED = n` line.
pub fn ledger_population(ledger: &str) -> Result<usize> {
    for line in ledger.lines() {
        if let Some(rest) = line.trim().strip_prefix("# PINNED = ") {
            return rest
                .trim()
                .parse()
                .with_context(|| format!("`{rest}` is not a number"));
        }
    }
    bail!(
        "ci/required-checks.txt carries no `# PINNED = n`. Without it the census has no \
         population to be held to, and a scan of three contexts could satisfy a floor of eleven."
    )
}

/// Hold a census to its pins.
#[must_use]
pub fn judge(
    pins: &Pins,
    ledger_population: usize,
    keyed: usize,
    refused: usize,
    unmeasured: usize,
) -> Verdict {
    let population = keyed.saturating_add(refused).saturating_add(unmeasured);
    if population != ledger_population {
        return Verdict::CouldNotLook(format!(
            "the census saw {population} context(s) and ci/required-checks.txt pins \
             {ledger_population}. Until those agree the counts below say nothing — a scan over \
             the wrong population cannot be compared to a floor."
        ));
    }
    if unmeasured > pins.unmeasured_ceiling {
        return Verdict::Regressed(format!(
            "{unmeasured} context(s) could not be judged, ceiling {}. `Unmeasured` is \"could not \
             look\": it may fall and may not grow, or the census starts reporting silence as \
             absence.",
            pins.unmeasured_ceiling
        ));
    }
    if keyed < pins.keyed_floor {
        return Verdict::Regressed(format!(
            "{keyed} context(s) are keyed, floor {}. A context loses its key when its workflow \
             stops declaring what it reads, which makes its result uncacheable — and the reason \
             36 of 47 are refused today.",
            pins.keyed_floor
        ));
    }
    Verdict::Held {
        keyed,
        refused,
        population,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pins() -> Pins {
        Pins {
            keyed_floor: 11,
            unmeasured_ceiling: 0,
        }
    }

    #[test]
    fn the_shipped_shape_holds() {
        assert_eq!(
            judge(&pins(), 47, 11, 36, 0),
            Verdict::Held {
                keyed: 11,
                refused: 36,
                population: 47
            }
        );
    }

    /// A context that stops declaring what it reads loses its key, and the
    /// floor catches it. This is the regression the pin exists for.
    #[test]
    fn losing_a_key_is_refused() {
        let Verdict::Regressed(why) = judge(&pins(), 47, 10, 37, 0) else {
            panic!("a fallen keyed count must regress");
        };
        assert!(why.contains("floor 11"), "{why}");
    }

    /// More keys is progress, not a finding.
    #[test]
    fn gaining_a_key_is_fine() {
        assert!(matches!(
            judge(&pins(), 47, 12, 35, 0),
            Verdict::Held { keyed: 12, .. }
        ));
    }

    /// "Could not look" may not grow, and it is its own verdict rather than a
    /// regression of the keyed count.
    #[test]
    fn a_context_the_census_cannot_judge_is_refused_on_its_own_terms() {
        let Verdict::Regressed(why) = judge(&pins(), 47, 11, 35, 1) else {
            panic!("a growing unmeasured count must regress");
        };
        assert!(why.contains("could not look"), "{why}");
    }

    /// NON-VACUITY. A census over the wrong population cannot be compared to a
    /// floor at all — and it is `CouldNotLook`, not `Regressed`, because the
    /// pins were never evaluated.
    #[test]
    fn a_short_census_says_nothing_rather_than_passing() {
        let Verdict::CouldNotLook(why) = judge(&pins(), 47, 3, 0, 0) else {
            panic!("a census over 3 of 47 must not be judged against the pins");
        };
        assert!(why.contains("say nothing"), "{why}");

        // And the same shape cannot sneak past by being large enough: a floor
        // of 11 with 11 keyed still fails when the population is wrong.
        assert!(matches!(
            judge(&pins(), 47, 11, 0, 0),
            Verdict::CouldNotLook(_)
        ));
    }

    #[test]
    fn pins_parse_and_refuse_what_they_should() {
        let p =
            parse_pins("# a comment\nkeyed_floor = 11\nunmeasured_ceiling = 0\n").expect("parses");
        assert_eq!(p, pins());
        assert!(parse_pins("keyed_floor = 11\n").is_err(), "missing ceiling");
        assert!(
            parse_pins("unmeasured_ceiling = 0\n").is_err(),
            "missing floor"
        );
        assert!(
            parse_pins("keyed_floor = 11\nkeyed_floor = 12\nunmeasured_ceiling = 0\n").is_err(),
            "a repeated key must not silently take the last value"
        );
        assert!(parse_pins("keyed_floor = many\nunmeasured_ceiling = 0\n").is_err());
    }

    #[test]
    fn the_ledger_population_is_read_not_restated() {
        assert_eq!(
            ledger_population("# some prose\n# PINNED = 47\nTests\n").expect("reads the pin"),
            47
        );
        assert!(
            ledger_population("Tests\nDoctests\n").is_err(),
            "a ledger with no pin leaves the census with no population to be held to"
        );
    }
}
