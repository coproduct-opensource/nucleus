//! Scorecard — one card, one row per defect family, and a badge naming the weakest.
//!
//! # The measurement this was built from
//!
//! A census of all 868 nucleus issues (2026-09-11) classified the 120 that are
//! `bug`-labelled or carry an audit prefix (`audit:`, `[CRIT-n]`, `[HIGH-n]`).
//! Four families account for about 90% of them:
//!
//! | family | defects | the defect |
//! |---|---|---|
//! | `bound` | 72 (60%) | a mechanism exists and nothing binds it to the live path |
//! | `alg`   | 15 (13%) | a law of a structure the code already claims to be |
//! | `life`  | 14 (12%) | unbounded carrier, no durable state, no validity interval |
//! | `tot`   |  7 (6%)  | a function whose type says total, that panics |
//!
//! The remaining 10% is genuinely novel — DX, release infra, an SDK format
//! mismatch — and no census here will find it.
//!
//! 64 of the 72 `bound` defects are security-labelled, **45 of them were found
//! by a human reading code and none by a gate**, and they close in a median of
//! 0.1 days against 0.4 for everything else. The fix is one call, one flag, one
//! `&` removed. They survive for months because nothing is looking.
//!
//! The three families beside `bound` are the answer to an objection worth
//! stating: that a gate cannot find a property nobody thought of. For these,
//! **nobody has to think of the property** — it is generated from a
//! declaration. `AnyOf : JoinSemilattice<Verdict>` obliges commutativity, and
//! #1222 ("AnyOf combinator is order-dependent — violates join commutativity")
//! is an audit finding that would have been a failing generated test on day one.
//!
//! # What a family is
//!
//! Every family reports the same three numbers, and the shape is gatehouse's
//! `trusted-base.txt` principle: *"THE POPULATION IS ENUMERATED, NOT LISTED …
//! the assumptions are then the COMPLEMENT of what is pinned, over a closed
//! population — there is no third state and no list to drift."*
//!
//! * **population** — obligations the tree declares.
//! * **discharged** — of those, the ones a mechanism that can fail covers.
//! * **undeclared** — sites with the family's *shape* that are not declared
//!   into it, so they sit outside the population entirely.
//!
//! The third number is the lesson of `bound`. 32 of its 33 dropped witnesses are
//! class-`N` legitimate doubles — `DenyAllEffects::run` refuses unconditionally,
//! so it performs no act and correctly consults nothing — and a census without
//! that column reads 83.82% where the truth is 99.41%. A number that silently
//! omits its undeclared surface is the `scripts/law-mechanisms-manifest.txt`
//! failure: a numerator with no denominator.
//!
//! # Why the badge names the weakest family
//!
//! Pooling the numerators over the pooled denominators gives one percentage that
//! is dominated by whichever family has the largest population, and `tot` alone
//! measures in the thousands. A family at 0% would disappear into that average.
//! An unweighted mean has the same defect more slowly. Counting families at
//! target is ungameable but cannot tell 14% from 84%.
//!
//! So the badge reads `alg 22%` — the lowest-scoring family **and** its number.
//! It moves whenever the weakest improves, it cannot hide a bad family behind a
//! good one, and it says where the next hour of work goes. ADR 0007 I-1: a gate
//! whose green is indistinguishable from vacuity. An average would be one.
//!
//! # Why two pins per family
//!
//! `.scorecard-ratchet.toml` carries `floor_bp` and `population_floor` for each
//! family, the discipline `.bound-ratchet.toml` established. A floor on the ratio
//! alone rewards deleting enforcement points — remove an obligation and
//! numerator and denominator fall together while the ratio rises. A pin on the
//! debt alone misses a ratio falling at constant debt. Neither is sufficient and
//! together they are, which is why both are required and a missing one is an
//! error rather than a default.

use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;

pub const RATCHET: &str = ".scorecard-ratchet.toml";

/// What one family found in the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Census {
    /// Obligations the tree declares.
    pub population: usize,
    /// Of those, the ones a mechanism that can fail actually covers.
    pub discharged: usize,
    /// Sites carrying the family's shape that are not declared into it, and so
    /// are outside `population`. Not a failure — a statement of how much surface
    /// the denominator does not reach.
    pub undeclared: usize,
}

impl Census {
    /// `discharged / population` in basis points, so a pin is an integer.
    ///
    /// An empty population is zero, never 100%: nothing declared is nothing
    /// discharged, and rounding it up would let deleting the last obligation
    /// paint the card green.
    pub const fn basis_points(self) -> u32 {
        if self.population == 0 {
            return 0;
        }
        ((self.discharged * 10_000) / self.population) as u32
    }

    /// Obligations declared and not discharged.
    pub const fn outstanding(self) -> usize {
        self.population.saturating_sub(self.discharged)
    }
}

/// One defect family, and how to count it.
pub trait Family {
    /// The family's name on the card and in the ratchet. Lowercase, stable.
    fn name(&self) -> &'static str;

    /// What one unit of population is, printed on the card so a reader never has
    /// to guess what the denominator counts.
    fn unit(&self) -> &'static str;

    /// Enumerate the family over the production region of `corpus`.
    fn census(&self, corpus: &BTreeMap<String, String>) -> Result<Census>;
}

// ─────────────────────────────────────────────────────────────────────────────
// The `bound` family — declared enforcement that reaches the live path.
//
// A thin adapter over `crate::bound`, which owns the measurement, the
// cross-check against `INERT_TOTAL`, and the class-`N` excusal. The scorecard
// deliberately does not re-implement any of it: two censuses of one population
// that could disagree is the defect `bound` itself bails on.

pub struct Bound;

impl Family for Bound {
    fn name(&self) -> &'static str {
        "bound"
    }

    fn unit(&self) -> &'static str {
        "witness-accepting parameter site"
    }

    fn census(&self, corpus: &BTreeMap<String, String>) -> Result<Census> {
        let text = std::fs::read_to_string(crate::inert_authority::MANIFEST)
            .with_context(|| format!("reading {}", crate::inert_authority::MANIFEST))?;
        let manifest = crate::inert_authority::parse(&text)?;
        let (report, _) = crate::bound::report(corpus, &manifest)?;
        let net = report.net();
        Ok(Census {
            population: net.declared(),
            discharged: net.bound,
            // The class-`N` sites: a witness accepted and dropped where no act is
            // performed, so nothing was owed. Shape without obligation.
            undeclared: report.excused,
        })
    }
}

/// Every family on the card, in the order they are printed.
pub fn families() -> Vec<Box<dyn Family>> {
    vec![Box::new(Bound), Box::new(crate::alg::Alg)]
}

// ─────────────────────────────────────────────────────────────────────────────
// The ratchet

/// The pinned floors for one family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pin {
    /// Minimum `discharged / population`, in basis points. May only rise.
    pub floor_bp: u32,
    /// Minimum `population`. A shrinking surface is a decision, not a win.
    pub population_floor: usize,
}

/// Parse `.scorecard-ratchet.toml`: `[family.<name>]` sections, two keys each.
///
/// Declaration-only, so it is decidable against an empty checkout — the half of
/// a gate where this repo's ratchet defects have lived.
pub fn parse_ratchet(text: &str) -> Result<BTreeMap<String, Pin>> {
    let mut out: BTreeMap<String, Pin> = BTreeMap::new();
    let mut current: Option<String> = None;
    let mut floor_bp: Option<u32> = None;
    let mut population_floor: Option<usize> = None;

    // Close the section under construction, if any.
    fn close(
        out: &mut BTreeMap<String, Pin>,
        name: &Option<String>,
        floor_bp: Option<u32>,
        population_floor: Option<usize>,
    ) -> Result<()> {
        let Some(name) = name else { return Ok(()) };
        let floor_bp = floor_bp.with_context(|| {
            format!("[family.{name}] has no floor_bp; an unpinned ratio gates nothing")
        })?;
        let population_floor = population_floor.with_context(|| {
            format!(
                "[family.{name}] has no population_floor. A floor on the ratio alone rewards \
                 deleting obligations: remove one and numerator and denominator fall together \
                 while the ratio rises."
            )
        })?;
        if floor_bp == 0 {
            bail!("[family.{name}] floor_bp=0 passes for every tree, including an empty one");
        }
        if floor_bp > 10_000 {
            bail!("[family.{name}] floor_bp={floor_bp} exceeds 10000bp; the gate could never pass");
        }
        if population_floor == 0 {
            bail!("[family.{name}] population_floor=0 passes for a tree with no obligations");
        }
        if out
            .insert(
                name.clone(),
                Pin {
                    floor_bp,
                    population_floor,
                },
            )
            .is_some()
        {
            bail!("[family.{name}] declared twice");
        }
        Ok(())
    }

    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(header) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            close(&mut out, &current, floor_bp, population_floor)?;
            floor_bp = None;
            population_floor = None;
            let name = header.strip_prefix("family.").with_context(|| {
                format!(
                    "line {}: only [family.<name>] sections are allowed",
                    lineno + 1
                )
            })?;
            if name.is_empty() {
                bail!("line {}: [family.] has no name", lineno + 1);
            }
            current = Some(name.to_string());
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            bail!("line {}: not `key = value`: {raw}", lineno + 1);
        };
        if current.is_none() {
            bail!(
                "line {}: `{}` appears before any [family.<name>] section",
                lineno + 1,
                key.trim()
            );
        }
        let value = value.trim();
        match key.trim() {
            "floor_bp" => {
                floor_bp =
                    Some(value.parse().with_context(|| {
                        format!("line {}: floor_bp is not a number", lineno + 1)
                    })?);
            }
            "population_floor" => {
                population_floor = Some(value.parse().with_context(|| {
                    format!("line {}: population_floor is not a number", lineno + 1)
                })?);
            }
            other => bail!("line {}: unknown key `{other}`", lineno + 1),
        }
    }
    close(&mut out, &current, floor_bp, population_floor)?;

    if out.is_empty() {
        bail!("{RATCHET} declares no families; the card would be empty and the gate vacuous");
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// The decision

/// One disagreement between the ratchet and the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// A family's ratio fell below its floor.
    Fell {
        family: String,
        found_bp: u32,
        floor_bp: u32,
    },
    /// A family's declared surface shrank.
    Shrank {
        family: String,
        found: usize,
        floor: usize,
    },
    /// A family's ratio rose and the pin was not raised with it.
    Slack {
        family: String,
        found_bp: u32,
        floor_bp: u32,
    },
    /// A family is on the card with no pin.
    Unpinned { family: String },
    /// A pin names a family that is not on the card.
    Stale { family: String },
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fell {
                family,
                found_bp,
                floor_bp,
            } => write!(
                f,
                "{family} fell to {} against a floor of {}: an obligation the tree declares \
                 stopped being discharged.",
                pct(*found_bp),
                pct(*floor_bp)
            ),
            Self::Shrank {
                family,
                found,
                floor,
            } => write!(
                f,
                "{family}'s population fell to {found} from a floor of {floor}. Deleting an \
                 obligation raises the ratio without discharging anything; if the deletion is \
                 intended, lower population_floor in the same edit with a dated note."
            ),
            Self::Slack {
                family,
                found_bp,
                floor_bp,
            } => write!(
                f,
                "{family} is at {} but the floor is pinned at {}. Raise floor_bp to the measured \
                 value: a floor with slack under it has already stopped gating (ADR 0007 I-1).",
                pct(*found_bp),
                pct(*floor_bp)
            ),
            Self::Unpinned { family } => write!(
                f,
                "{family} is on the card and has no [family.{family}] section in {RATCHET}. A \
                 family nothing pins can fall to zero silently."
            ),
            Self::Stale { family } => write!(
                f,
                "{RATCHET} pins [family.{family}] and no family by that name is on the card. A \
                 stale pin is a gate ranging over nothing."
            ),
        }
    }
}

/// Compare the measured card against the ratchet. Pure and total.
pub fn decide(pins: &BTreeMap<String, Pin>, card: &[(String, Census)]) -> Vec<Finding> {
    let mut out = Vec::new();
    for (family, census) in card {
        let Some(pin) = pins.get(family) else {
            out.push(Finding::Unpinned {
                family: family.clone(),
            });
            continue;
        };
        let found_bp = census.basis_points();
        if found_bp < pin.floor_bp {
            out.push(Finding::Fell {
                family: family.clone(),
                found_bp,
                floor_bp: pin.floor_bp,
            });
        } else if found_bp > pin.floor_bp {
            out.push(Finding::Slack {
                family: family.clone(),
                found_bp,
                floor_bp: pin.floor_bp,
            });
        }
        if census.population < pin.population_floor {
            out.push(Finding::Shrank {
                family: family.clone(),
                found: census.population,
                floor: pin.population_floor,
            });
        }
    }
    for family in pins.keys() {
        if !card.iter().any(|(name, _)| name == family) {
            out.push(Finding::Stale {
                family: family.clone(),
            });
        }
    }
    out
}

/// The family the badge names: lowest ratio, ties broken by name so the badge is
/// stable across runs rather than following map iteration order.
pub fn weakest(card: &[(String, Census)]) -> Option<(&str, Census)> {
    card.iter()
        .min_by_key(|(name, c)| (c.basis_points(), name.as_str()))
        .map(|(name, c)| (name.as_str(), *c))
}

// ─────────────────────────────────────────────────────────────────────────────

/// Basis points as a percentage, for messages a human reads.
fn pct(bp: u32) -> String {
    format!("{}.{:02}%", bp / 100, bp % 100)
}

fn render(card: &[(String, Census)], families: &[Box<dyn Family>]) -> String {
    let unit_of = |name: &str| {
        families
            .iter()
            .find(|f| f.name() == name)
            .map_or("", |f| f.unit())
    };
    let unit_w = card
        .iter()
        .map(|(n, _)| unit_of(n).len())
        .chain(std::iter::once(4))
        .max()
        .unwrap_or(4);
    let name_w = card
        .iter()
        .map(|(n, _)| n.len())
        .chain(std::iter::once(6))
        .max()
        .unwrap_or(6);

    let mut out = format!(
        "  {:name_w$}  {:unit_w$}  {:>10}  {:>10}  {:>8}  {:>10}\n",
        "family", "unit", "population", "discharged", "%", "undeclared"
    );
    for (name, c) in card {
        out.push_str(&format!(
            "  {:name_w$}  {:unit_w$}  {:>10}  {:>10}  {:>8}  {:>10}\n",
            name,
            unit_of(name),
            c.population,
            c.discharged,
            pct(c.basis_points()),
            c.undeclared
        ));
    }
    out
}

/// Build the card by asking every family to count itself.
///
/// Pure over the corpus, so the whole of it is reachable from a test with a
/// synthetic tree — the same reason `decide` is pure. `run` below is the I/O
/// shell: read the tree, call this, print.
///
/// # Errors
///
/// If a family's census fails, or reports more discharged than its population.
/// The second is not a formality: a census that discharges more than it declares
/// is counting two different things, and the ratio would be meaningless rather
/// than merely wrong.
pub fn card_of(
    families: &[Box<dyn Family>],
    corpus: &BTreeMap<String, String>,
) -> Result<Vec<(String, Census)>> {
    let mut card: Vec<(String, Census)> = Vec::new();
    for family in families {
        let census = family
            .census(corpus)
            .with_context(|| format!("counting the `{}` family", family.name()))?;
        if census.discharged > census.population {
            bail!(
                "the `{}` family reports {} discharged of a population of {}. A census that \
                 discharges more than it declares is measuring two different things, and the \
                 ratio below would be meaningless.",
                family.name(),
                census.discharged,
                census.population
            );
        }
        card.push((family.name().to_string(), census));
    }
    Ok(card)
}

/// The shields.io endpoint object for a card, naming its weakest family.
///
/// Thresholds are deliberately far apart: a family under three quarters is
/// orange, because the badge's job is to be uncomfortable while a family is
/// genuinely undischarged.
pub fn badge_json(card: &[(String, Census)]) -> Result<String> {
    let Some((name, weak)) = weakest(card) else {
        bail!("no families on the card; the badge would name nothing");
    };
    let colour = if weak.basis_points() >= 9_900 {
        "brightgreen"
    } else if weak.basis_points() >= 7_500 {
        "yellow"
    } else {
        "orange"
    };
    Ok(format!(
        r#"{{"schemaVersion":1,"label":"scorecard","message":"{name} {}","color":"{colour}"}}"#,
        pct(weak.basis_points())
    ))
}

pub fn run(measure: bool, badge: bool) -> Result<i32> {
    let corpus = crate::law_mechanisms::tracked(crate::law_mechanisms::is_production_path)?;
    let families = families();
    let card = card_of(&families, &corpus)?;

    let Some((weak_name, weak)) = weakest(&card) else {
        bail!("no families on the card; the gate would pass vacuously");
    };

    if badge {
        println!("{}", badge_json(&card)?);
        return Ok(0);
    }

    if measure {
        println!("  scorecard | {weak_name} {}\n", pct(weak.basis_points()));
        print!("{}", render(&card, &families));
        for (name, c) in &card {
            if c.outstanding() > 0 {
                println!(
                    "\n  {name}: {} of {} obligation(s) undischarged",
                    c.outstanding(),
                    c.population
                );
            }
        }
        return Ok(0);
    }

    let pins = parse_ratchet(
        &std::fs::read_to_string(RATCHET).with_context(|| format!("reading {RATCHET}"))?,
    )?;
    let findings = decide(&pins, &card);
    if findings.is_empty() {
        println!(
            "OK: {} {} on the card, weakest is {weak_name} at {}.",
            card.len(),
            if card.len() == 1 {
                "family"
            } else {
                "families"
            },
            pct(weak.basis_points())
        );
        print!("{}", render(&card, &families));
        println!(
            "     The badge names the weakest family rather than an average, so a family at zero \
             cannot hide behind one at a hundred (ADR 0007 I-1)."
        );
        return Ok(0);
    }
    println!("FAIL: {} scorecard finding(s).", findings.len());
    for f in &findings {
        println!("  {f}");
    }
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(population: usize, discharged: usize) -> Census {
        Census {
            population,
            discharged,
            undeclared: 0,
        }
    }

    #[test]
    fn an_empty_population_is_zero_not_a_hundred_percent() {
        // Deleting the last obligation must not paint the card green.
        assert_eq!(Census::default().basis_points(), 0);
    }

    #[test]
    fn the_badge_names_the_weakest_family_not_the_average() {
        let card = vec![
            ("bound".to_string(), c(172, 171)),
            ("alg".to_string(), c(250, 55)),
        ];
        // Pooled, this reads (171+55)/(172+250) = 53%; the weakest is 22%.
        let (name, census) = weakest(&card).expect("a card with rows has a weakest");
        assert_eq!(name, "alg");
        assert_eq!(census.basis_points(), 2_200);
    }

    #[test]
    fn ties_break_by_name_so_the_badge_does_not_flicker() {
        let card = vec![
            ("zeta".to_string(), c(10, 5)),
            ("alpha".to_string(), c(100, 50)),
        ];
        assert_eq!(weakest(&card).map(|(n, _)| n), Some("alpha"));
    }

    #[test]
    fn a_ratio_below_the_floor_fails() {
        let pins = BTreeMap::from([(
            "bound".to_string(),
            Pin {
                floor_bp: 9_941,
                population_floor: 172,
            },
        )]);
        let card = vec![("bound".to_string(), c(172, 170))];
        assert!(matches!(
            decide(&pins, &card).as_slice(),
            [Finding::Fell { .. }]
        ));
    }

    #[test]
    fn a_ratio_above_the_floor_also_fails_so_the_pin_cannot_go_slack() {
        let pins = BTreeMap::from([(
            "bound".to_string(),
            Pin {
                floor_bp: 5_000,
                population_floor: 172,
            },
        )]);
        let card = vec![("bound".to_string(), c(172, 171))];
        assert!(matches!(
            decide(&pins, &card).as_slice(),
            [Finding::Slack { .. }]
        ));
    }

    #[test]
    fn deleting_obligations_does_not_pass_by_raising_the_ratio() {
        // 100% of a smaller population. The ratio is perfect and the gate refuses.
        let pins = BTreeMap::from([(
            "bound".to_string(),
            Pin {
                floor_bp: 9_941,
                population_floor: 172,
            },
        )]);
        let card = vec![("bound".to_string(), c(100, 100))];
        let findings = decide(&pins, &card);
        assert!(findings.iter().any(|f| matches!(f, Finding::Shrank { .. })));
    }

    #[test]
    fn a_family_with_no_pin_is_a_finding_not_a_default() {
        let card = vec![("bound".to_string(), c(172, 171))];
        assert!(matches!(
            decide(&BTreeMap::new(), &card).as_slice(),
            [Finding::Unpinned { .. }]
        ));
    }

    #[test]
    fn a_pin_for_a_family_that_is_not_on_the_card_is_a_finding() {
        let pins = BTreeMap::from([(
            "ghost".to_string(),
            Pin {
                floor_bp: 1,
                population_floor: 1,
            },
        )]);
        assert!(matches!(
            decide(&pins, &[]).as_slice(),
            [Finding::Stale { .. }]
        ));
    }

    #[test]
    fn both_pins_are_required() {
        let only_ratio = "[family.bound]\nfloor_bp = 9941\n";
        assert!(
            parse_ratchet(only_ratio)
                .unwrap_err()
                .to_string()
                .contains("population_floor")
        );
        let only_population = "[family.bound]\npopulation_floor = 172\n";
        assert!(
            parse_ratchet(only_population)
                .unwrap_err()
                .to_string()
                .contains("floor_bp")
        );
    }

    #[test]
    fn a_zero_floor_is_rejected_rather_than_passing_vacuously() {
        let text = "[family.bound]\nfloor_bp = 0\npopulation_floor = 1\n";
        assert!(
            parse_ratchet(text)
                .unwrap_err()
                .to_string()
                .contains("every tree")
        );
    }

    #[test]
    fn an_empty_ratchet_is_rejected() {
        assert!(
            parse_ratchet("# just a comment\n")
                .unwrap_err()
                .to_string()
                .contains("no families")
        );
    }

    #[test]
    fn two_families_parse_independently() {
        let text = "\
[family.bound]
floor_bp = 9941
population_floor = 172

[family.alg]
floor_bp = 2200
population_floor = 250
";
        let pins = parse_ratchet(text).expect("two sections parse");
        assert_eq!(pins.len(), 2);
        assert_eq!(pins["alg"].floor_bp, 2_200);
        assert_eq!(pins["bound"].population_floor, 172);
    }

    #[test]
    fn a_key_before_any_section_is_rejected() {
        assert!(
            parse_ratchet("floor_bp = 1\n[family.bound]\n")
                .unwrap_err()
                .to_string()
                .contains("before any")
        );
    }

    // ── The card a human reads ────────────────────────────────────────
    //
    // `render` is the gate's only output on a green tree, so an unreadable or
    // silently-truncated card is a defect that no other test would catch.

    struct Fake(&'static str, &'static str);
    impl Family for Fake {
        fn name(&self) -> &'static str {
            self.0
        }
        fn unit(&self) -> &'static str {
            self.1
        }
        fn census(&self, _: &BTreeMap<String, String>) -> Result<Census> {
            Ok(Census::default())
        }
    }

    #[test]
    fn the_card_names_every_family_its_unit_and_its_numbers() {
        let families: Vec<Box<dyn Family>> = vec![
            Box::new(Fake("bound", "witness-accepting parameter site")),
            Box::new(Fake("alg", "(lattice type, law) obligation")),
        ];
        let card = vec![
            ("bound".to_string(), c(172, 171)),
            (
                "alg".to_string(),
                Census {
                    population: 278,
                    discharged: 110,
                    undeclared: 9,
                },
            ),
        ];
        let out = render(&card, &families);
        assert!(out.contains("witness-accepting parameter site"));
        assert!(out.contains("(lattice type, law) obligation"));
        assert!(out.contains("99.41%"), "bound's ratio: {out}");
        assert!(out.contains("39.56%"), "alg's ratio: {out}");
        assert!(out.contains("278") && out.contains("110") && out.contains('9'));
        assert_eq!(out.lines().count(), 3, "a header and one line per family");
    }

    #[test]
    fn a_family_with_no_matching_unit_still_renders_its_row() {
        // The card must not drop a row because the unit lookup missed: a
        // silently shorter card is the shape of a gate that stopped looking.
        let out = render(&[("ghost".to_string(), c(4, 2))], &[]);
        assert!(out.contains("ghost"));
        assert!(out.contains("50.00%"));
    }

    // ── Every finding says what to do about it ────────────────────────

    #[test]
    fn fell_names_both_numbers() {
        let m = Finding::Fell {
            family: "alg".into(),
            found_bp: 3_928,
            floor_bp: 3_956,
        }
        .to_string();
        assert!(
            m.contains("alg") && m.contains("39.28%") && m.contains("39.56%"),
            "{m}"
        );
    }

    #[test]
    fn shrank_says_the_deletion_may_be_intended() {
        let m = Finding::Shrank {
            family: "bound".into(),
            found: 171,
            floor: 172,
        }
        .to_string();
        assert!(
            m.contains("population_floor"),
            "names the pin to lower: {m}"
        );
        assert!(m.contains("dated note"), "{m}");
    }

    #[test]
    fn slack_cites_the_rule_it_enforces() {
        let m = Finding::Slack {
            family: "bound".into(),
            found_bp: 9_942,
            floor_bp: 9_941,
        }
        .to_string();
        assert!(
            m.contains("I-1"),
            "a pin with slack has stopped gating: {m}"
        );
    }

    #[test]
    fn unpinned_and_stale_each_name_the_family_and_the_file() {
        let u = Finding::Unpinned {
            family: "alg".into(),
        }
        .to_string();
        assert!(u.contains("alg") && u.contains(RATCHET), "{u}");
        let s = Finding::Stale {
            family: "ghost".into(),
        }
        .to_string();
        assert!(s.contains("ghost") && s.contains(RATCHET), "{s}");
    }

    #[test]
    fn outstanding_is_the_undischarged_remainder() {
        assert_eq!(c(278, 110).outstanding(), 168);
        // Saturating, so a clamped census never underflows into a huge number.
        assert_eq!(c(5, 9).outstanding(), 0);
    }

    // ── The card, built from families ─────────────────────────────────

    struct Counting(&'static str, Census);
    impl Family for Counting {
        fn name(&self) -> &'static str {
            self.0
        }
        fn unit(&self) -> &'static str {
            "unit"
        }
        fn census(&self, _: &BTreeMap<String, String>) -> Result<Census> {
            Ok(self.1)
        }
    }

    #[test]
    fn every_family_contributes_one_row_in_order() {
        let families: Vec<Box<dyn Family>> = vec![
            Box::new(Counting("bound", c(172, 171))),
            Box::new(Counting("alg", c(278, 110))),
        ];
        let card = card_of(&families, &BTreeMap::new()).expect("both families count");
        assert_eq!(
            card,
            vec![
                ("bound".to_string(), c(172, 171)),
                ("alg".to_string(), c(278, 110))
            ]
        );
    }

    #[test]
    fn a_census_discharging_more_than_it_declares_is_refused() {
        // Not a formality: the ratio would exceed 100% and mean nothing.
        let families: Vec<Box<dyn Family>> = vec![Box::new(Counting("bad", c(10, 11)))];
        let err = card_of(&families, &BTreeMap::new())
            .expect_err("11 of 10 is not a ratio")
            .to_string();
        assert!(err.contains("two different things"), "{err}");
    }

    #[test]
    fn an_empty_card_has_no_badge_rather_than_a_green_one() {
        let err = badge_json(&[]).expect_err("nothing to name").to_string();
        assert!(err.contains("name nothing"), "{err}");
    }

    #[test]
    fn the_badge_names_the_weakest_and_colours_by_it() {
        let orange = badge_json(&[
            ("bound".to_string(), c(172, 171)),
            ("alg".to_string(), c(278, 110)),
        ])
        .expect("a card with rows has a badge");
        assert!(orange.contains(r#""message":"alg 39.56%""#), "{orange}");
        assert!(orange.contains("orange"), "under three quarters: {orange}");

        let green = badge_json(&[("bound".to_string(), c(172, 171))]).expect("one row");
        assert!(green.contains("brightgreen"), "{green}");

        let yellow = badge_json(&[("x".to_string(), c(100, 80))]).expect("one row");
        assert!(yellow.contains("yellow"), "{yellow}");
    }

    #[test]
    fn the_badge_is_well_formed_json() {
        let b = badge_json(&[("alg".to_string(), c(278, 110))]).expect("one row");
        assert!(b.starts_with('{') && b.ends_with('}'), "{b}");
        assert_eq!(b.matches('"').count() % 2, 0, "balanced quotes: {b}");
        assert!(b.contains(r#""schemaVersion":1"#), "{b}");
    }

    #[test]
    fn the_committed_ratchet_parses_and_pins_every_family_on_the_card() {
        // The gate's own configuration is a subject, not an assumption.
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../",
            ".scorecard-ratchet.toml"
        ))
        .expect("the committed ratchet is readable");
        let pins = parse_ratchet(&text).expect("the committed ratchet parses");
        for family in families() {
            assert!(
                pins.contains_key(family.name()),
                "family `{}` is on the card with no pin",
                family.name()
            );
        }
    }
}
