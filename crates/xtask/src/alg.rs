//! The `alg` family — laws a declaration already claims.
//!
//! # The defect
//!
//! Of the 120 audit-and-bug issues the 2026-09-11 census classified, 15 are a
//! law of a structure the code already says it is. #1222: *"AnyOf combinator is
//! order-dependent for RequiresApproval — violates join commutativity."* #735:
//! *"DelegationScope subset check uses string equality — glob subsumption not
//! evaluated"*, which is an ordering implemented as syntactic equality, the same
//! bug gatehouse's `writ` fixed by making `globSubsumes` the rule. #747 and #740:
//! a receipt hash over `format!("{:?}")` and a canonical encoding that admits a
//! length-extension collision — injectivity and stability.
//!
//! None of these needed inventing. They are the laws of the structure the type
//! declares itself to be, and they arrive with the declaration.
//!
//! # Population is (type, law), not (type, trait)
//!
//! "Does type `T` have a law check?" scores this tree far too well.
//! `crates/portcullis/tests/proptest_lattice.rs` covers six types, and not to the
//! same depth: `CapabilityLattice` has nine laws checked, `BudgetLattice` six,
//! `CommandLattice`/`PathLattice`/`TimeLattice` four each — commutativity and
//! idempotence only, no associativity, no absorption, no order laws — and
//! `PermissionLattice` has one, `normalize_is_idempotent`, against the fifteen
//! its three traits oblige. A per-type census calls all six covered.
//!
//! So the unit is one law of one type, and the obligation table is fixed:
//!
//! | trait | laws | which |
//! |---|---|---|
//! | `Lattice` | 9 | commutativity, associativity, idempotence for meet and join; two absorption; `leq`/meet consistency |
//! | `BoundedLattice` | 4 | top and bottom identity, top and bottom annihilator |
//! | `DistributiveLattice` | 2 | meet-over-join and its dual |
//!
//! Those are exactly what [`verify_lattice_laws`], [`verify_bounded_lattice_laws`]
//! and [`verify_distributive_laws`] check, counted by reading them. A type
//! implementing all three owes 15.
//!
//! [`verify_lattice_laws`]: https://docs.rs/portcullis-core
//! [`verify_bounded_lattice_laws`]: https://docs.rs/portcullis-core
//! [`verify_distributive_laws`]: https://docs.rs/portcullis-core
//!
//! # Why only these three traits
//!
//! `MeetSemilattice` and `JoinSemilattice` are implemented in this tree and have
//! **no verifier at all**, so counting their obligations would mix "a checker
//! exists and is not wired" with "no checker exists" — two different debts with
//! two different fixes. `convergence` made the same call and said so: its two
//! unmeasurable arrows are *"excluded because a hand-listed denominator is the
//! metric equivalent of a gate that cannot fail."* When a semilattice verifier
//! lands, its traits join the table here and the population rises, which is a
//! number going up because the measurement got honest.
//!
//! # Discharged is declared, not inferred
//!
//! Asking "is there a law check for `T`?" needs the check's type argument
//! resolved — a `typeck` question. A grep for it attributed `CapabilityLevel`
//! correctly, missed `ConfLevel`, `IFCLabel`, `Verdict` and `FlowState`, and
//! picked up a bare generic parameter `L` as though it were a type. So the
//! numerator reads `lattice_laws!` invocations, which name their type and their
//! families on one line, and both sides of the ratio are syntax without a
//! resolver.
//!
//! A consequence to state plainly: **the six types covered by
//! `proptest_lattice.rs` count as undischarged today.** They are checked, by
//! hand, with generated samples — but not declared, so this gate cannot see
//! them. Converting them is a strengthening (four laws to nine) that may turn
//! something red, which is why it is its own commit rather than folded in here.
//! Until it lands, the `alg` number understates real coverage for a stated
//! reason, and it rises when the conversion happens.
//!
//! # Undeclared
//!
//! Types with `meet`, `join` or `leq` and no lattice trait impl are outside the
//! population entirely: no generic suite can reach them. `WasiGrant`,
//! `WasiWorld`, the two CRDT joins and `RiskCost`/`WeakeningCost` — the only
//! hand-written `PartialOrd`/`Ord` in the workspace, antisymmetry and
//! transitivity unverified — are the shape without the declaration. They are
//! reported, not counted against the ratio, for the reason `bound`'s class-`N`
//! sites are: a number that silently omits its own surface is a numerator with
//! no denominator.

use anyhow::Result;
use std::collections::{BTreeMap, BTreeSet};

use crate::inert_authority::scope_of;
use crate::law_mechanisms::production_region;
use crate::scorecard::{Census, Family};

/// Laws `verify_lattice_laws` checks: commutativity, associativity and
/// idempotence for meet and join (6), two absorption laws, and the
/// `a ≤ b ⟺ a ∧ b = a` consistency check.
const LATTICE_LAWS: usize = 9;

/// Laws `verify_bounded_lattice_laws` adds: `a ∧ ⊤ = a`, `a ∨ ⊥ = a`,
/// `a ∧ ⊥ = ⊥`, `a ∨ ⊤ = ⊤`.
const BOUNDED_LAWS: usize = 4;

/// Laws `verify_distributive_laws` checks: `a ∧ (b ∨ c) = (a ∧ b) ∨ (a ∧ c)`
/// and its dual.
const DISTRIBUTIVE_LAWS: usize = 2;

/// The traits whose laws a verifier exists for, and what each obliges.
///
/// `BoundedLattice: Lattice`, so a bounded type also carries a `Lattice` impl
/// and the nine arrive once from that row rather than twice.
const OBLIGATIONS: [(&str, usize); 3] = [
    ("Lattice", LATTICE_LAWS),
    ("BoundedLattice", BOUNDED_LAWS),
    ("DistributiveLattice", DISTRIBUTIVE_LAWS),
];

/// What one `lattice_laws!` family keyword discharges.
///
/// `bounded` discharges thirteen, not four: `verify_bounded_lattice_laws` calls
/// `verify_lattice_laws` first, so declaring it covers the base lattice laws too.
fn discharged_by(family: &str) -> usize {
    match family {
        "lattice" => LATTICE_LAWS,
        "bounded" => LATTICE_LAWS + BOUNDED_LAWS,
        "distributive" => DISTRIBUTIVE_LAWS,
        _ => 0,
    }
}

/// A trait impl found in the tree: which trait, for which type.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Impl {
    pub trait_name: String,
    pub type_name: String,
}

/// Find `impl [<generics>] [path::]Trait for Type` over one source region.
///
/// A grep, not a resolver — the trait vocabulary is a closed list for the same
/// reason `inert_authority`'s witness vocabulary is. The spellings in this tree
/// are `impl Lattice for X`, `impl crate::frame::Lattice for X` and
/// `impl crate::category::BoundedLattice for X`, all of which this accepts, and
/// the type is taken as the head identifier so `ProductLattice<A, B>` is
/// `ProductLattice`.
pub fn impls_in(region: &str) -> Vec<Impl> {
    let mut out = Vec::new();
    for line in region.lines() {
        let t = line.trim_start();
        let Some(rest) = t.strip_prefix("impl") else {
            continue;
        };
        if !rest.starts_with(|c: char| c.is_whitespace() || c == '<') {
            continue;
        }
        let Some(head) = rest.split('{').next() else {
            continue;
        };
        let Some((before, after)) = head.rsplit_once(" for ") else {
            continue;
        };
        // The trait is the last path segment before ` for `.
        let trait_name = before
            .rsplit(|c: char| c == ':' || c.is_whitespace())
            .find(|s| !s.is_empty())
            .unwrap_or("")
            .trim_end_matches('>');
        // Longest match first: `BoundedLattice` must not read as `Lattice`.
        let Some((matched, _)) = OBLIGATIONS.iter().find(|(name, _)| *name == trait_name) else {
            continue;
        };
        let type_name: String = after
            .trim()
            .trim_start_matches('&')
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if type_name.is_empty() {
            continue;
        }
        out.push(Impl {
            trait_name: (*matched).to_string(),
            type_name,
        });
    }
    out
}

/// A `lattice_laws!` invocation: the type it names and the families it lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declaration {
    pub type_name: String,
    pub families: Vec<String>,
}

/// Find `lattice_laws!(name, Type, samples, [families])` over one source region.
///
/// Invocations span several lines once rustfmt has had them, so this walks to the
/// matching `)` rather than reading a line. The type is the head identifier after
/// the first comma, which is why `ProductLattice<ConfLevel, IntegLevel>` does not
/// need comma-in-generics handling. The families are the bracketed list of
/// lowercase identifiers immediately before the closing paren — unambiguous
/// against the `vec![…]` in the samples argument, whose contents are not all
/// lowercase.
pub fn declarations_in(region: &str) -> Vec<Declaration> {
    const NEEDLE: &str = "lattice_laws!(";
    let mut out = Vec::new();
    let mut search = 0usize;
    while let Some(found) = region[search..].find(NEEDLE) {
        let open = search + found + NEEDLE.len() - 1;
        // `lattice_law_case!` and the `macro_rules!` definition do not contain
        // this needle, but a qualified call `$crate::lattice_laws!(` would; the
        // head check keeps the needle anchored to an identifier boundary.
        let prev = region[..search + found].chars().next_back();
        if matches!(prev, Some(c) if c.is_ascii_alphanumeric() || c == '_') {
            search = open + 1;
            continue;
        }
        let mut depth = 0usize;
        let mut close = None;
        for (i, c) in region[open..].char_indices() {
            match c {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = close else { break };
        let span = &region[open + 1..close];
        search = close + 1;

        let Some((_, after_first_comma)) = span.split_once(',') else {
            continue;
        };
        let type_name: String = after_first_comma
            .trim_start()
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if type_name.is_empty() {
            continue;
        }
        // The family list: the last bracketed run of lowercase identifiers.
        let families = span
            .rmatch_indices('[')
            .find_map(|(i, _)| {
                let rest = &span[i + 1..];
                let end = rest.find(']')?;
                let inner = &rest[..end];
                let ok = !inner.is_empty()
                    && inner.chars().all(|c| {
                        c.is_ascii_lowercase() || c == '_' || c == ',' || c.is_whitespace()
                    });
                ok.then(|| {
                    inner
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect::<Vec<_>>()
                })
            })
            .unwrap_or_default();
        if families.is_empty() {
            continue;
        }
        out.push(Declaration {
            type_name,
            families,
        });
    }
    out
}

/// Types carrying a lattice-shaped method, by the impl block they live in.
///
/// Reuses `inert_authority::scope_of`, which attributes `impl Trait for Type` to
/// `Type` — the same reason a type whose `meet` lives inside its trait impl is
/// found here too, and then cancels out against the declared set.
pub fn lattice_shaped(region: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut scope = String::from("<free>");
    for line in region.lines() {
        if let Some(s) = scope_of(line) {
            scope = s;
        }
        let t = line.trim_start();
        if (t.starts_with("fn meet") || t.starts_with("fn join") || t.starts_with("fn leq"))
            && scope != "<free>"
        {
            out.insert(scope.clone());
        }
    }
    out
}

/// The measured state of the family.
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// Obligations per type, summed over its law-bearing trait impls.
    pub obliged: BTreeMap<String, usize>,
    /// Obligations per type that a `lattice_laws!` invocation discharges,
    /// clamped so a declaration can never claim more than the type owes.
    pub declared: BTreeMap<String, usize>,
    /// Types with a lattice-shaped method and no law-bearing trait impl.
    pub undeclared: BTreeSet<String>,
}

/// The crate a tracked path belongs to, used to key types.
///
/// Two distinct types share the name `CapabilityLattice` — one at
/// `nucleus-ifc-kernel/src/capability_lattice.rs:21` whose impls live in
/// `portcullis-core`, one at `portcullis/src/capability.rs:115` whose impls live
/// in `portcullis`. Both implement all three traits, so a bare-name key sums
/// their obligations to 30 **and lets one declaration discharge both**. That is
/// unsound in the numerator, which is the half that must never over-report.
///
/// Keying by the crate the `impl` or the declaration is written in separates
/// them. The cost is that a declaration written in a different crate from the
/// impl reads as undischarged; that direction understates coverage rather than
/// inventing it, which is the error worth having.
fn crate_of(path: &str) -> &str {
    path.strip_prefix("crates/")
        .and_then(|r| r.split('/').next())
        .unwrap_or("<unknown>")
}

fn key(path: &str, type_name: &str) -> String {
    format!("{}::{type_name}", crate_of(path))
}

pub fn report(corpus: &BTreeMap<String, String>) -> Report {
    let mut obliged: BTreeMap<String, usize> = BTreeMap::new();
    let mut declared: BTreeMap<String, usize> = BTreeMap::new();
    let mut shaped: BTreeSet<String> = BTreeSet::new();

    for (path, src) in corpus {
        let region = production_region(src);
        for i in impls_in(&region) {
            let laws = OBLIGATIONS
                .iter()
                .find(|(n, _)| *n == i.trait_name)
                .map_or(0, |(_, l)| *l);
            *obliged.entry(key(path, &i.type_name)).or_insert(0) += laws;
        }
        for d in declarations_in(&region) {
            let sum: usize = d.families.iter().map(|f| discharged_by(f)).sum();
            *declared.entry(key(path, &d.type_name)).or_insert(0) += sum;
        }
        shaped.extend(lattice_shaped(&region).into_iter().map(|t| key(path, &t)));
    }

    // A declaration cannot discharge more than the type owes. Listing `bounded`
    // on a type that only implements `Lattice` does not compile, so this clamp
    // never fires in practice — but a census that could report more discharged
    // than declared is measuring two different things, and the ratio would be
    // meaningless rather than merely wrong.
    for (ty, d) in &mut declared {
        let cap = obliged.get(ty).copied().unwrap_or(0);
        *d = (*d).min(cap);
    }

    let undeclared = shaped
        .into_iter()
        .filter(|t| !obliged.contains_key(t))
        .collect();

    Report {
        obliged,
        declared,
        undeclared,
    }
}

pub struct Alg;

impl Family for Alg {
    fn name(&self) -> &'static str {
        "alg"
    }

    fn unit(&self) -> &'static str {
        "(lattice type, law) obligation"
    }

    fn census(&self, corpus: &BTreeMap<String, String>) -> Result<Census> {
        let r = report(corpus);
        Ok(Census {
            population: r.obliged.values().sum(),
            discharged: r.declared.values().sum(),
            undeclared: r.undeclared.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_impl_is_found() {
        let v = impls_in("impl Lattice for ConfLevel {\n");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].trait_name, "Lattice");
        assert_eq!(v[0].type_name, "ConfLevel");
    }

    #[test]
    fn a_qualified_impl_is_found() {
        let v = impls_in("impl crate::frame::Lattice for CommandLattice {\n");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].type_name, "CommandLattice");
    }

    #[test]
    fn bounded_does_not_read_as_lattice() {
        // The whole obligation table turns on this: `BoundedLattice` owes 4, not
        // 9, because the 9 arrive from the `Lattice` impl beside it.
        let v = impls_in("impl BoundedLattice for CapabilityLevel {\n");
        assert_eq!(v[0].trait_name, "BoundedLattice");
    }

    #[test]
    fn generics_do_not_hide_the_trait_or_the_type() {
        let v = impls_in("impl<A: Lattice, B: Lattice> Lattice for ProductLattice<A, B> {\n");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].trait_name, "Lattice");
        assert_eq!(v[0].type_name, "ProductLattice");
    }

    #[test]
    fn an_unrelated_trait_is_not_an_obligation() {
        assert!(impls_in("impl Display for ConfLevel {\n").is_empty());
        assert!(impls_in("impl LatticeOperation for Foo {\n").is_empty());
    }

    #[test]
    fn an_inherent_impl_is_not_a_trait_impl() {
        assert!(impls_in("impl ConfLevel {\n").is_empty());
    }

    #[test]
    fn a_single_line_declaration_parses() {
        let d = declarations_in("lattice_laws!(conf_laws, ConfLevel, s(), [bounded]);\n");
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].type_name, "ConfLevel");
        assert_eq!(d[0].families, vec!["bounded"]);
    }

    #[test]
    fn a_multi_line_declaration_parses() {
        let src = "\
lattice_laws!(
    conf_level_laws,
    ConfLevel,
    vec![ConfLevel::Public, ConfLevel::Internal, ConfLevel::Secret],
    [bounded, distributive]
);
";
        let d = declarations_in(src);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].type_name, "ConfLevel");
        assert_eq!(d[0].families, vec!["bounded", "distributive"]);
    }

    #[test]
    fn a_generic_type_argument_does_not_break_the_comma_split() {
        // `ProductLattice<ConfLevel, IntegLevel>` carries a comma inside its
        // generics; taking the head identifier sidesteps it entirely.
        let src = "lattice_laws!(p, ProductLattice<ConfLevel, IntegLevel>, v(), [bounded]);\n";
        let d = declarations_in(src);
        assert_eq!(d[0].type_name, "ProductLattice");
        assert_eq!(d[0].families, vec!["bounded"]);
    }

    #[test]
    fn the_samples_vec_is_not_mistaken_for_the_family_list() {
        let src = "lattice_laws!(n, T, vec![T::A, T::B, T::C], [lattice]);\n";
        let d = declarations_in(src);
        assert_eq!(d[0].families, vec!["lattice"]);
    }

    #[test]
    fn bounded_discharges_the_base_laws_too() {
        // verify_bounded_lattice_laws calls verify_lattice_laws first.
        assert_eq!(discharged_by("bounded"), LATTICE_LAWS + BOUNDED_LAWS);
        assert_eq!(discharged_by("lattice"), LATTICE_LAWS);
        assert_eq!(discharged_by("distributive"), DISTRIBUTIVE_LAWS);
        assert_eq!(discharged_by("nonsense"), 0);
    }

    #[test]
    fn two_types_sharing_a_name_in_different_crates_are_not_one_type() {
        // `CapabilityLattice` exists twice — nucleus-ifc-kernel and portcullis —
        // and both implement all three traits. Under a bare-name key their
        // obligations sum to 30 and ONE declaration discharges both, which
        // over-reports the numerator. The crate keeps them apart.
        let corpus = BTreeMap::from([
            (
                "crates/alpha/src/lib.rs".to_string(),
                "impl Lattice for Shared {}\nlattice_laws!(s, Shared, v(), [lattice]);\n"
                    .to_string(),
            ),
            (
                "crates/beta/src/lib.rs".to_string(),
                "impl Lattice for Shared {}\n".to_string(),
            ),
        ]);
        let r = report(&corpus);
        assert_eq!(r.obliged["alpha::Shared"], LATTICE_LAWS);
        assert_eq!(r.obliged["beta::Shared"], LATTICE_LAWS);
        assert_eq!(r.declared.get("alpha::Shared"), Some(&LATTICE_LAWS));
        assert_eq!(
            r.declared.get("beta::Shared"),
            None,
            "alpha's declaration must not discharge beta's obligations"
        );
    }

    #[test]
    fn a_type_with_meet_and_no_trait_impl_is_undeclared() {
        let corpus = BTreeMap::from([(
            "crates/demo/src/lib.rs".to_string(),
            "impl WasiGrant {\n    fn meet(&self, o: &Self) -> Self { todo!() }\n}\n".to_string(),
        )]);
        let r = report(&corpus);
        assert!(r.undeclared.contains("demo::WasiGrant"));
        assert!(r.obliged.is_empty());
    }

    #[test]
    fn a_declared_type_is_not_also_counted_as_undeclared() {
        let corpus = BTreeMap::from([(
            "crates/demo/src/lib.rs".to_string(),
            "impl Lattice for ConfLevel {\n    fn meet(&self, o: &Self) -> Self { todo!() }\n}\n"
                .to_string(),
        )]);
        let r = report(&corpus);
        assert!(r.undeclared.is_empty());
        assert_eq!(r.obliged["demo::ConfLevel"], LATTICE_LAWS);
    }

    #[test]
    fn a_declaration_cannot_discharge_more_than_the_type_owes() {
        let corpus = BTreeMap::from([(
            "crates/demo/src/lib.rs".to_string(),
            "impl Lattice for T {}\nlattice_laws!(t, T, s(), [bounded, distributive]);\n"
                .to_string(),
        )]);
        let r = report(&corpus);
        assert_eq!(r.obliged["demo::T"], LATTICE_LAWS);
        assert_eq!(
            r.declared["demo::T"], LATTICE_LAWS,
            "clamped to what is owed"
        );
    }

    #[test]
    fn obligations_sum_across_the_traits_a_type_implements() {
        let corpus = BTreeMap::from([(
            "crates/demo/src/lib.rs".to_string(),
            "impl Lattice for T {}\nimpl BoundedLattice for T {}\nimpl DistributiveLattice for T {}\n"
                .to_string(),
        )]);
        let r = report(&corpus);
        assert_eq!(
            r.obliged["demo::T"],
            LATTICE_LAWS + BOUNDED_LAWS + DISTRIBUTIVE_LAWS,
            "a type implementing all three owes 15"
        );
    }
}
