//! **Model ↔ production parity for the policy kernel.**
//!
//! This proptest module transcribes the *reference-monitor semantics* the shipped
//! kernel is pinned to — as an **independent Rust oracle** written to mirror,
//! declaration-for-declaration, the mathlib-free Lean model in
//! `crates/portcullis-core/lean/GovernanceCompletenessSpike.lean` — then asserts
//! (over random `Policy`/`Request` values) that the shipped [`decide`] /
//! [`governance_monotone`] agree with that oracle on every case.
//!
//! # The parity contract (Rust oracle ↔ Lean model ↔ shipped kernel)
//!
//! The Lean model proves `governance_monotone_iff` (axioms `[propext,
//! Quot.sound]`, zero `sorry`): checking `allowed(new) ⊆ allowed(old)` over the
//! finite `representativeReqs` domain DECIDES anti-self-weakening over the entire
//! (infinite) request space. That proof is *about the Lean model*, so the
//! guarantee only transfers to the shipped Rust to the extent the two agree.
//! This module is the pin. The oracle in [`model`] mirrors the Lean definitions
//! one-to-one:
//!
//!   | Lean (`GovernanceCompletenessSpike`) | oracle (`model`)        |
//!   |--------------------------------------|-------------------------|
//!   | `matchM` / `ruleMatches`             | `matcher_matches` / `rule_matches` |
//!   | `decideAux` (default-deny fold)      | `decide_aux`            |
//!   | `decideP p q = decideAux p false q`  | `decide_p`              |
//!   | `escalates old new q`                | `escalates`             |
//!   | `fieldExacts` / `fieldReps`          | `field_exacts` / `field_reps` |
//!   | `representativeReqs`                 | `representative_reqs`   |
//!   | `monotoneOver old new reqs`          | `monotone_over`         |
//!
//! `decide_aux` is a *structural transcription of the Lean fold* — recursion over
//! the rule list threading the `permitted` accumulator, with Forbid short-
//! circuiting to `Deny` — not the shipped imperative early-return loop. So a bug
//! in the shipped loop surfaces as a `decide != decide_p` disagreement.
//!
//! # The differential angle
//!
//! [`model::decide_declarative`] is a *third, deliberately divergent*
//! formulation of the same monitor: `Allow` iff *some* matching `Permit` exists
//! AND *no* matching `Forbid` exists (two independent existential scans, vs. the
//! Lean fold's single accumulator pass). It is asserted equal to `decide_p` on
//! every request — an internal cross-check that neither the fold transcription
//! nor the declarative reading has drifted, independent of the shipped kernel.
//! Likewise `field_reps`' fresh value is built by a *different* method than the
//! shipped `fresh_not_in` (a run of `\u{1}` strictly longer than every named
//! exact, hence outside the set by length, vs. the shipped `\0fresh`-extension),
//! keeping the two representative-domain constructions independent.
//!
//! # The parity claims
//!
//!   (a)  `decide == decide_p` (the Lean fold) for every request — both random
//!        requests and every representative request.
//!   (a′) `decide_p == decide_declarative` — the fold and the existential
//!        reading of the semantics agree (model-internal differential).
//!   (b)  `governance_monotone(old,new).is_ok() == monotone_over(old, new,
//!        representative_reqs(old,new))` — the shipped verdict matches the Lean
//!        `monotoneOver … (representativeReqs …)`, the exact term
//!        `governance_monotone_iff` decides — and whenever production returns a
//!        witness, that witness `escalates` under BOTH the shipped and the model
//!        semantics.
//!
//! # Caveat
//!
//! Like every proptest, this NARROWS the model↔production gap probabilistically
//! (random sampling over a bounded generator); it is not a formal extraction. The
//! oracle is a hand-written mirror of the Lean semantics, asserted equal to the
//! shipped functions — not the shipped functions themselves, nor the Lean model
//! itself.

use nucleus_policy_kernel::{
    Decision, Effect, Matcher, Policy, Request, Rule, decide, governance_monotone,
};
use proptest::prelude::*;

/// The independent oracle: the Lean `GovernanceCompletenessSpike` model,
/// transcribed declaration-for-declaration into Rust.
mod model {
    use super::*;
    use std::collections::BTreeSet;

    /// `matchM`: `Any` matches anything; `Exact e` matches iff the field equals
    /// `e`.
    fn matcher_matches(m: &Matcher, value: &str) -> bool {
        match m {
            Matcher::Any => true,
            Matcher::Exact(s) => s == value,
        }
    }

    /// `ruleMatches`: all three field matchers match the request.
    fn rule_matches(rule: &Rule, r: &Request) -> bool {
        matcher_matches(&rule.principal, &r.principal)
            && matcher_matches(&rule.action, &r.action)
            && matcher_matches(&rule.resource, &r.resource)
    }

    /// `decideAux`: the default-deny fold with Forbid-overrides-Permit — a
    /// structural transcription of the Lean recursion over the rule list
    /// threading the `permitted` accumulator (a matching `Forbid` short-circuits
    /// to `Deny`). NOT the shipped imperative early-return loop.
    fn decide_aux(rules: &[Rule], permitted: bool, r: &Request) -> Decision {
        match rules.split_first() {
            None => {
                if permitted {
                    Decision::Allow
                } else {
                    Decision::Deny
                }
            }
            Some((rule, rest)) => {
                if rule_matches(rule, r) {
                    match rule.effect {
                        Effect::Forbid => Decision::Deny,
                        Effect::Permit => decide_aux(rest, true, r),
                    }
                } else {
                    decide_aux(rest, permitted, r)
                }
            }
        }
    }

    /// `decideP p q = decideAux p false q`: the entry point, decision from the
    /// empty-permit accumulator.
    pub fn decide_p(policy: &Policy, r: &Request) -> Decision {
        decide_aux(&policy.rules, false, r)
    }

    /// The **differential** reading of the same monitor (NOT a Lean declaration):
    /// `Allow` iff some `Permit` matches and no `Forbid` matches. Two independent
    /// existential scans vs. the fold's single accumulator pass — asserted equal
    /// to [`decide_p`] to cross-check the transcription.
    pub fn decide_declarative(policy: &Policy, r: &Request) -> Decision {
        let any_forbid = policy
            .rules
            .iter()
            .any(|rule| rule.effect == Effect::Forbid && rule_matches(rule, r));
        let any_permit = policy
            .rules
            .iter()
            .any(|rule| rule.effect == Effect::Permit && rule_matches(rule, r));
        if any_permit && !any_forbid {
            Decision::Allow
        } else {
            Decision::Deny
        }
    }

    /// `escalates old new q`: `decideP new q = Allow ∧ decideP old q = Deny` —
    /// the update newly grants `q`.
    pub fn escalates(old: &Policy, new: &Policy, q: &Request) -> bool {
        decide_p(new, q) == Decision::Allow && decide_p(old, q) == Decision::Deny
    }

    /// `fieldExacts sel (old ++ new)`: every exact string a field takes across
    /// both policies' rules (deduplicated; the Lean list carries duplicates but
    /// `fieldReps` is used only through membership, so the set is faithful).
    fn field_exacts(old: &Policy, new: &Policy, sel: impl Fn(&Rule) -> &Matcher) -> Vec<String> {
        let set: BTreeSet<String> = old
            .rules
            .iter()
            .chain(new.rules.iter())
            .filter_map(|r| match sel(r) {
                Matcher::Exact(s) => Some(s.clone()),
                Matcher::Any => None,
            })
            .collect();
        set.into_iter().collect()
    }

    /// A **`Fresh`** value equal to none of `exacts` — the honest witness of the
    /// Lean `Fresh α` class (`fresh_not_mem`). Built by a *different* method than
    /// the shipped `fresh_not_in`: a run of `\u{1}` strictly longer than the
    /// longest exact, hence outside the set by length. Keeps the two fresh-value
    /// constructions independent.
    fn fresh_outside(exacts: &[String]) -> String {
        let max_len = exacts.iter().map(|s| s.chars().count()).max().unwrap_or(0);
        "\u{1}".repeat(max_len + 1)
    }

    /// `fieldReps sel (old ++ new) = Fresh.fresh (fieldExacts …) :: fieldExacts …`
    /// — one fresh value plus every named exact.
    fn field_reps(old: &Policy, new: &Policy, sel: impl Fn(&Rule) -> &Matcher) -> Vec<String> {
        let exacts = field_exacts(old, new, sel);
        let fresh = fresh_outside(&exacts);
        let mut out = vec![fresh];
        out.extend(exacts);
        out
    }

    /// `representativeReqs old new`: the Cartesian product of the per-field
    /// representatives (`flatMap`/`map` in Lean).
    pub fn representative_reqs(old: &Policy, new: &Policy) -> Vec<Request> {
        let principals = field_reps(old, new, |r| &r.principal);
        let actions = field_reps(old, new, |r| &r.action);
        let resources = field_reps(old, new, |r| &r.resource);
        let mut out = Vec::new();
        for p in &principals {
            for a in &actions {
                for res in &resources {
                    out.push(Request {
                        principal: p.clone(),
                        action: a.clone(),
                        resource: res.clone(),
                    });
                }
            }
        }
        out
    }

    /// `monotoneOver old new reqs = reqs.all (fun q => ¬ escalates old new q)`:
    /// the finite check over an explicit request list. `true` = non-weakening.
    pub fn monotone_over(old: &Policy, new: &Policy, reqs: &[Request]) -> bool {
        reqs.iter().all(|q| !escalates(old, new, q))
    }
}

// ── Generators ───────────────────────────────────────────────────────────────
//
// A small shared alphabet for both matcher exacts and request fields, so random
// requests actually collide with `Exact` matchers (exercising the interesting
// classes rather than almost-always hitting the `Any`-only bucket).

fn small_string() -> impl Strategy<Value = String> {
    prop::sample::select(vec!["", "x", "y", "z", "alice", "read", "doc"])
        .prop_map(|s| s.to_string())
}

fn matcher_strat() -> impl Strategy<Value = Matcher> {
    prop_oneof![Just(Matcher::Any), small_string().prop_map(Matcher::Exact),]
}

fn effect_strat() -> impl Strategy<Value = Effect> {
    prop_oneof![Just(Effect::Permit), Just(Effect::Forbid)]
}

fn rule_strat() -> impl Strategy<Value = Rule> {
    (
        effect_strat(),
        matcher_strat(),
        matcher_strat(),
        matcher_strat(),
    )
        .prop_map(|(effect, principal, action, resource)| Rule {
            effect,
            principal,
            action,
            resource,
        })
}

fn policy_strat() -> impl Strategy<Value = Policy> {
    prop::collection::vec(rule_strat(), 0..6).prop_map(|rules| Policy { rules })
}

fn request_strat() -> impl Strategy<Value = Request> {
    (small_string(), small_string(), small_string()).prop_map(|(principal, action, resource)| {
        Request {
            principal,
            action,
            resource,
        }
    })
}

proptest! {
    /// (a) The shipped imperative `decide` agrees with the model's `decideP`
    /// fold on random requests.
    #[test]
    fn decide_matches_model(policy in policy_strat(), req in request_strat()) {
        prop_assert_eq!(decide(&policy, &req), model::decide_p(&policy, &req));
    }

    /// (a′) Model-internal differential: the `decideAux` fold and the
    /// existential declarative reading agree on random requests — a cross-check
    /// of the transcription that does not touch the shipped kernel.
    #[test]
    fn model_fold_matches_declarative(policy in policy_strat(), req in request_strat()) {
        prop_assert_eq!(model::decide_p(&policy, &req), model::decide_declarative(&policy, &req));
    }

    /// (a″) `decide`, `decideP`, and the declarative reading all agree on every
    /// representative request — the classes that actually drive the
    /// monotonicity verdict.
    #[test]
    fn decide_matches_model_on_representatives(old in policy_strat(), new in policy_strat()) {
        for req in model::representative_reqs(&old, &new) {
            prop_assert_eq!(decide(&old, &req), model::decide_p(&old, &req));
            prop_assert_eq!(decide(&new, &req), model::decide_p(&new, &req));
            prop_assert_eq!(model::decide_p(&old, &req), model::decide_declarative(&old, &req));
            prop_assert_eq!(model::decide_p(&new, &req), model::decide_declarative(&new, &req));
        }
    }

    /// (b) The shipped `governance_monotone` verdict (Ok vs Err) matches the
    /// Lean `monotoneOver old new (representativeReqs old new)` — the exact term
    /// `governance_monotone_iff` decides — and any production witness genuinely
    /// `escalates` under the model.
    #[test]
    fn governance_monotone_matches_model(old in policy_strat(), new in policy_strat()) {
        let prod = governance_monotone(&old, &new);
        let reps = model::representative_reqs(&old, &new);
        prop_assert_eq!(prod.is_ok(), model::monotone_over(&old, &new, &reps));

        if let Err(witness) = prod {
            // Production's witness is newly granted under the shipped semantics …
            prop_assert_eq!(decide(&new, &witness), Decision::Allow);
            prop_assert_eq!(decide(&old, &witness), Decision::Deny);
            // … and is a genuine `escalates` under the independent model.
            prop_assert!(model::escalates(&old, &new, &witness));
        }
    }
}
