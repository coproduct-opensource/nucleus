//! The `life` family — a right that never expires.
//!
//! # The defect
//!
//! Of the 120 audit-and-bug issues the 2026-09-11 census classified, 14 are a
//! lifecycle: an unbounded carrier, state that does not survive a restart, or a
//! missing validity interval. This family counts the third, because it is the
//! one whose population can be enumerated from a source.
//!
//! Every one-shot right in nucleus is affine and enforced as such.
//! `Authority` carries `#[must_use = "an Authority that is never spent is an
//! action that was authorised and not taken"]`, is consumed by value in
//! `spend_on`, and has two `compile_fail` doctests proving replay (E0382) and
//! clone (E0599) are rejected. `DecisionToken`, `CheckProof`, `DischargedBundle`
//! and `SessionCleanseToken` are the same shape.
//!
//! **Not one of them expires.** A token minted at t=0 authorises at t=∞, so the
//! window between time-of-check and time-of-use is unbounded on every right in
//! the system. The affine half of the discipline is done and the temporal half
//! was never started.
//!
//! # Why this population and not the other two
//!
//! *Unbounded carriers* have a real defect behind them — `Kernel.trace` is a
//! `Vec<Decision>` appended once per allowed operation with no cap, and
//! `FlowTracker` never compacts while its capped mirror `FlowGraph` carries four
//! named ceilings. But the population is "a collection in a long-lived struct",
//! and long-lived is a judgement about the struct's role. The measurement that
//! exists — 902 collection fields, 328 grown and never bounded, 69 in structs
//! whose *names* suggest they persist — rests on that name heuristic, and a
//! denominator decided by a regex over struct names is the metric equivalent of
//! a gate that cannot fail.
//!
//! *Transition totality* has almost no population: the entire repo contains
//! three transition functions — `MockMachineDriver::transition` (on the mock;
//! the `MachineDriver` trait declares no transition law, so a real backend
//! inherits nothing), `Compartment::can_transition_to` (returns `bool`, so
//! nothing forces a caller to consult it) and `ProgressLevel::advance`. There is
//! no `next_state`, no transition table, no `valid_transition` anywhere.
//! `JobState` is written by direct variant construction at five sites, so
//! `Completed → Queued` is writable. That is an ADR, not a ratchet.
//!
//! `convergence` made the same call and said so: two of its four arrows are
//! *"excluded because a hand-listed denominator is the metric equivalent of a
//! gate that cannot fail."* Both exclusions here are named rather than averaged
//! in, and both become countable once their design question is answered.
//!
//! # The number is zero, and that is the finding
//!
//! 14 affine rights, 0 with a validity interval. `.scorecard-ratchet.toml`
//! records it with `measured_zero = true` rather than leaving the ratio
//! unpinned, because a zero is still gated from both sides here:
//! `population_floor` keeps the denominator from shrinking, and the slack check
//! fires the moment the first right gains an interval — turning the gate red and
//! demanding the pin be raised to meet it.
//!
//! Giving a right an expiry is a behaviour change on a security boundary: it
//! needs a clock at the mint site, a check at the consume site, and a decision
//! about what expiry *means* for an operation already in flight. This gate
//! states the debt exactly; it does not pay it.

use anyhow::Result;
use std::collections::BTreeMap;

use crate::convergence::{affine_corpus, affine_types};
use crate::scorecard::{Census, Family};

/// Field names that bound a right's validity by TIME.
///
/// A closed vocabulary, like `inert_authority`'s witness list, and for the same
/// reason: this is a grep, not a resolver, so the alternative is matching
/// anything that looks temporal and crediting a `created_at` that nothing reads.
/// A bound must say when the right STOPS being valid — `issued_at` alone does
/// not, and is deliberately absent.
pub const INTERVAL_FIELDS: [&str; 7] = [
    "not_after",
    "expires_at",
    "expires_at_unix",
    "expires_in",
    "expiry",
    "valid_until",
    "valid_until_unix",
];

/// Field names that bound a right's validity by the STATE it was decided
/// against.
///
/// A wall-clock TTL asks *how long has it been?* The invariant a one-shot right
/// actually needs is *has anything it depended on changed?* Those diverge in
/// both directions: a thirty-second token is stale at one millisecond if the
/// policy was amended, and sound an hour later if nothing moved. A TTL also
/// imports a trusted clock and host/guest skew across the vsock boundary.
///
/// So a right carrying the fingerprint of the state it was decided against is
/// bounded **more tightly** than one carrying a duration, not less — it expires
/// the instant that state changes rather than on a timer someone guessed. This
/// list exists so the family measures the property rather than the spelling.
///
/// It is deliberately narrow. A field must name the state the decision DEPENDED
/// on; a `session_id` or a `sequence` identifies the right, and identifying is
/// not bounding.
pub const DEPENDENCY_FIELDS: [&str; 5] = [
    "permissions",
    "policy_hash",
    "generation",
    "epoch",
    "state_hash",
];

/// The body of `pub struct`/`pub enum` `ty`, if this source declares it.
///
/// Brace-counted from the declaration, so a nested type inside the body does not
/// end it early and a field of a *later* struct is never read as this one's.
pub fn declaration_body<'a>(src: &'a str, ty: &str) -> Option<&'a str> {
    let needles = [format!("pub struct {ty}"), format!("pub enum {ty}")];
    let start = needles.iter().find_map(|n| {
        src.find(n.as_str()).filter(|i| {
            // The name must end here: `pub struct Authority` must not match
            // `pub struct AuthorityLevel`.
            src[i + n.len()..]
                .chars()
                .next()
                .is_none_or(|c| !c.is_alphanumeric() && c != '_')
        })
    })?;
    let rest = &src[start..];
    // A unit or tuple struct ends at the `;` before any `{`.
    let brace = rest.find('{');
    let semi = rest.find(';');
    match (brace, semi) {
        (None, _) => Some(rest.split(';').next().unwrap_or(rest)),
        (Some(_), Some(s)) if s < brace? => Some(&rest[..s]),
        (Some(b), _) => {
            let mut depth = 0usize;
            for (i, c) in rest[b..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some(&rest[..b + i + 1]);
                        }
                    }
                    _ => {}
                }
            }
            Some(rest)
        }
    }
}

/// Does this type's declaration carry a field saying when it stops being valid?
///
/// Either form counts: a time after which it is stale, or a fingerprint of the
/// state it was decided against. See [`DEPENDENCY_FIELDS`] for why the second is
/// the stronger bound.
pub fn has_validity_interval(body: &str) -> bool {
    body.lines()
        .map(str::trim_start)
        .filter(|l| !l.starts_with("//"))
        .any(|l| {
            INTERVAL_FIELDS
                .iter()
                .chain(DEPENDENCY_FIELDS.iter())
                .any(|f| {
                    // A field, not a mention: `expires_at: u64`, never a doc line or
                    // a method called `expires_at()`.
                    strip_visibility(l)
                        .strip_prefix(*f)
                        .is_some_and(|r| r.trim_start().starts_with(':'))
                })
        })
}

/// Drop a leading visibility modifier: `pub`, `pub(crate)`, `pub(super)`,
/// `pub(in path)`.
///
/// Only `pub ` was stripped before, so every `pub(crate)` field was invisible to
/// this family — and the first right to gain a validity bound carried exactly
/// that: `pub(crate) permissions: String` on `DecisionToken`. The gate reported
/// the work as not done.
fn strip_visibility(line: &str) -> &str {
    let Some(rest) = line.strip_prefix("pub") else {
        return line;
    };
    match rest.strip_prefix('(') {
        Some(after) => after
            .split_once(')')
            .map_or(line, |(_, tail)| tail.trim_start()),
        None => rest.trim_start(),
    }
}

/// Per affine type, whether it carries a validity interval.
pub fn report(corpus: &BTreeMap<String, String>) -> BTreeMap<String, bool> {
    // The SAME shaping `convergence` applies, through the same function. Passing
    // raw sources here counted 6 affine rights against convergence's 7, because
    // a `#[cfg(test)]` region carried a `Clone` impl that rejected a type which
    // is affine in the shipped build. Two gates disagreeing about one population
    // is what `bound` bails on rather than reports.
    let shaped = affine_corpus(corpus);
    affine_types(&shaped)
        .into_iter()
        .map(|ty| {
            let carries = shaped
                .values()
                .filter_map(|src| declaration_body(src, &ty))
                .any(has_validity_interval);
            (ty, carries)
        })
        .collect()
}

pub struct Life;

impl Family for Life {
    fn name(&self) -> &'static str {
        "life"
    }

    fn unit(&self) -> &'static str {
        "affine right"
    }

    fn census(&self, corpus: &BTreeMap<String, String>) -> Result<Census> {
        let r = report(corpus);
        Ok(Census {
            population: r.len(),
            discharged: r.values().filter(|carries| **carries).count(),
            // The other two sub-censuses are excluded by name, not silently, and
            // neither has a population this gate can enumerate — so there is no
            // honest count of surface the denominator misses. Reporting a guess
            // here would be worse than reporting none.
            undeclared: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_struct_body_ends_at_its_own_closing_brace() {
        let src = "pub struct A {\n    x: u8,\n}\npub struct B {\n    expires_at: u64,\n}\n";
        let a = declaration_body(src, "A").expect("A is declared");
        assert!(!has_validity_interval(a), "B's field must not leak into A");
        let b = declaration_body(src, "B").expect("B is declared");
        assert!(has_validity_interval(b));
    }

    #[test]
    fn a_nested_type_does_not_end_the_body_early() {
        let src = "pub struct A {\n    inner: Inner,\n    // struct Nested { }\n    expires_at: u64,\n}\n";
        let a = declaration_body(src, "A").expect("A is declared");
        assert!(has_validity_interval(a));
    }

    #[test]
    fn a_prefix_of_a_longer_name_is_not_the_type() {
        // `pub struct Authority` must not match `pub struct AuthorityLevel`.
        let src = "pub struct AuthorityLevel {\n    expires_at: u64,\n}\n";
        assert!(declaration_body(src, "Authority").is_none());
    }

    #[test]
    fn a_tuple_struct_has_a_body_and_no_interval() {
        let src = "pub struct Token(u64);\n";
        let b = declaration_body(src, "Token").expect("declared");
        assert!(!has_validity_interval(b));
    }

    #[test]
    fn a_doc_comment_mentioning_expiry_is_not_a_field() {
        let src = "pub struct A {\n    /// expires_at: when this stops working\n    x: u8,\n}\n";
        let b = declaration_body(src, "A").expect("declared");
        assert!(!has_validity_interval(b), "a mention is not an interval");
    }

    #[test]
    fn a_method_named_like_a_field_is_not_a_field() {
        let src = "pub struct A {\n    x: u8,\n}\nimpl A {\n    pub fn expires_at(&self) -> u64 { 0 }\n}\n";
        let b = declaration_body(src, "A").expect("declared");
        assert!(!has_validity_interval(b));
    }

    #[test]
    fn issued_at_alone_is_not_a_validity_interval() {
        // An interval must say when the right STOPS being valid.
        let src = "pub struct A {\n    issued_at: u64,\n}\n";
        let b = declaration_body(src, "A").expect("declared");
        assert!(!has_validity_interval(b));
    }

    #[test]
    fn a_restricted_visibility_field_is_still_a_field() {
        // Only `pub ` was stripped before, so every `pub(crate)` field was
        // invisible — including the first right in the tree to gain a bound.
        for vis in ["pub", "pub(crate)", "pub(super)", "pub(in crate::a)", ""] {
            let src = format!("pub struct A {{\n    {vis} expires_at: u64,\n}}\n");
            let b = declaration_body(&src, "A").expect("declared");
            assert!(
                has_validity_interval(b),
                "visibility `{vis}` should not hide the field"
            );
        }
    }

    #[test]
    fn a_state_fingerprint_bounds_validity_as_much_as_a_clock_does() {
        // A right carrying the state it was decided against expires the instant
        // that state changes — a tighter bound than a duration someone guessed.
        let src = "pub struct Token {\n    pub(crate) permissions: String,\n}\n";
        let b = declaration_body(src, "Token").expect("declared");
        assert!(has_validity_interval(b));
    }

    #[test]
    fn identifying_a_right_is_not_bounding_it() {
        for f in ["session_id", "sequence", "issued_at", "id"] {
            let src = format!("pub struct A {{\n    {f}: u64,\n}}\n");
            let b = declaration_body(&src, "A").expect("declared");
            assert!(
                !has_validity_interval(b),
                "{f} identifies, it does not bound"
            );
        }
    }

    #[test]
    fn every_spelling_in_the_vocabulary_counts() {
        for f in INTERVAL_FIELDS.iter().chain(DEPENDENCY_FIELDS.iter()) {
            let src = format!("pub struct A {{\n    {f}: u64,\n}}\n");
            let b = declaration_body(&src, "A").expect("declared");
            assert!(has_validity_interval(b), "{f} should count");
        }
    }

    #[test]
    fn the_census_counts_affine_rights_and_their_intervals() {
        let corpus = BTreeMap::from([(
            "crates/demo/src/lib.rs".to_string(),
            "#[must_use]\npub struct Timed {\n    expires_at: u64,\n}\n\
             #[must_use]\npub struct Forever {\n    x: u8,\n}\n"
                .to_string(),
        )]);
        let c = Life.census(&corpus).expect("the census succeeds");
        assert_eq!(c.population, 2);
        assert_eq!(c.discharged, 1);
        assert_eq!(c.basis_points(), 5_000);
    }

    #[test]
    fn a_clone_impl_written_for_tests_does_not_disqualify_a_production_right() {
        // This is the bug that made `life` report 6 where `convergence` reported
        // 7: passing raw sources let a `#[cfg(test)]` Clone impl reject a type
        // that is affine in the shipped build. Both now shape the corpus through
        // `affine_corpus`, so both ask the same question.
        let corpus = BTreeMap::from([(
            "crates/demo/src/lib.rs".to_string(),
            "#[must_use]\npub struct Right {\n    x: u8,\n}\n\
             #[cfg(test)]\nmod tests {\n    impl Clone for Right {\n        fn clone(&self) -> Self { todo!() }\n    }\n}\n"
                .to_string(),
        )]);
        assert_eq!(
            Life.census(&corpus).expect("succeeds").population,
            1,
            "a test-only Clone impl is not a production escape hatch"
        );
    }

    #[test]
    fn the_gate_harness_is_not_its_own_subject() {
        // `convergence` excludes crates/xtask for the reason it learned the hard
        // way: the module that names the shapes it counts would count itself.
        let corpus = BTreeMap::from([(
            "crates/xtask/src/demo.rs".to_string(),
            "#[must_use]\npub struct Right {\n    x: u8,\n}\n".to_string(),
        )]);
        assert_eq!(Life.census(&corpus).expect("succeeds").population, 0);
    }

    #[test]
    fn a_clonable_must_use_type_is_not_an_affine_right() {
        // Replay is the thing an interval bounds; a type you can clone was never
        // one-shot, so it is not this family's subject.
        let corpus = BTreeMap::from([(
            "crates/demo/src/lib.rs".to_string(),
            "#[must_use]\n#[derive(Clone)]\npub struct Copyable {\n    x: u8,\n}\n".to_string(),
        )]);
        assert_eq!(Life.census(&corpus).expect("succeeds").population, 0);
    }
}
