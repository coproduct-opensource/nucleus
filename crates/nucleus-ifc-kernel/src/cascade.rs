//! User-authored cascades over the derivation lattice.
//!
//! A [`Cascade`] is an ordered sequence of [`CascadeStep`]s a user declares to
//! compose a multi-step policy pipeline (observe → transform → observe …) on the
//! session exposure ceiling. Every step is a **monotone endomap** on the
//! [`DerivationClass`] lattice, and non-monotone steps are **unrepresentable** —
//! the enum has no constructor for one. So admissibility is by construction, and
//! the whole cascade inherits the anti-laundering ratchet proven ONCE in Lean:
//!
//!   `crates/portcullis-core/lean/DerivationCascadeAdmissible.lean`
//!     · `raiseTo_mono` / `sealAbove_mono` — each step is a monotone endomap
//!     · `user_cascade_ratchets` — a cascade of monotone steps inherits the
//!       ratchet (fixpoint / unrollings-below / denial-persists) with NO
//!       per-cascade proof.
//!
//! The Lean proof is over a faithful model of this lattice; the `#[cfg(test)]`
//! parity block below binds that model to production `DerivationClass` the same
//! way #2299 bound the newtype to the lattice: exhaustively, over every element.
//! In particular `every_step_is_monotone_on_production` re-establishes the Lean
//! monotonicity hypotheses directly on the shipped `join`/`leq`, so the guarantee
//! holds on production regardless of model fidelity.

use crate::DerivationClass;

/// A single user-authored cascade step: a monotone endomap on the
/// [`DerivationClass`] exposure lattice.
///
/// The set of constructors is deliberately closed to monotone maps — a
/// non-monotone step (which would break the ratchet, see the Lean
/// `badLoop_breaks_ratchet`) cannot be expressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CascadeStep {
    /// RAISE: join the running exposure up to at least `level` (an observation).
    /// Lean: `DerivationCascade.raiseTo` (`raiseTo_mono`).
    RaiseTo(DerivationClass),
    /// SEAL: a monotone tripwire — once the running exposure reaches `threshold`,
    /// seal it to [`DerivationClass::OpaqueExternal`] (fully unreproducible);
    /// otherwise pass through unchanged. A monotone closure, not a join with a
    /// constant. Lean: `DerivationCascade.sealAbove` (`sealAbove_mono`).
    SealAbove(DerivationClass),
}

impl CascadeStep {
    /// Apply the step to a running exposure value. Matches the Lean endomap
    /// arm-for-arm (bound exhaustively by the parity tests below).
    pub fn apply(self, x: DerivationClass) -> DerivationClass {
        match self {
            CascadeStep::RaiseTo(level) => x.join(level),
            CascadeStep::SealAbove(threshold) => {
                if threshold.leq(x) {
                    DerivationClass::OpaqueExternal
                } else {
                    x
                }
            }
        }
    }
}

/// A user-authored cascade: an ordered sequence of monotone steps.
///
/// Because every step is monotone, the cascade is a monotone endomap on the
/// exposure lattice, so it inherits the anti-laundering ratchet
/// (`DerivationCascadeAdmissible.user_cascade_ratchets`): no ordering of steps
/// can launder accumulated taint below a denied threshold.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cascade(pub Vec<CascadeStep>);

impl Cascade {
    /// One pass of the cascade from a starting exposure — composes the steps
    /// left-to-right (mirrors Lean `runCascade`).
    pub fn run(&self, start: DerivationClass) -> DerivationClass {
        self.0.iter().fold(start, |acc, step| step.apply(acc))
    }

    /// The cascade's least fixpoint reached from ⊥ (`Deterministic`) — iterate the
    /// pass to stability. A monotone endomap on this finite lattice stabilizes
    /// within its height (4); the bound here is a safety net, not unbounded
    /// recursion. Mirrors Lean `lfp` (iterate-from-⊥ to a fixpoint).
    pub fn fixpoint(&self) -> DerivationClass {
        let mut cur = DerivationClass::Deterministic;
        // height(DerivationClass) = 4; +1 headroom, +1 to confirm stability.
        for _ in 0..=(4 + 1) {
            let next = self.run(cur);
            if next == cur {
                return cur;
            }
            cur = next;
        }
        debug_assert!(
            false,
            "cascade fixpoint did not stabilize within lattice height — a step is non-monotone"
        );
        cur
    }

    /// Anti-laundering query: does the cascade's fixpoint DENY an action requiring
    /// cleanliness `threshold` (i.e. `threshold ⊑ fixpoint`)? Denial persists — no
    /// step ordering launders it away (Lean `user_cascade_ratchets.denial_persists`).
    pub fn denies(&self, threshold: DerivationClass) -> bool {
        threshold.leq(self.fixpoint())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use DerivationClass::*;

    /// Every element of the production derivation lattice (the diamond).
    const ALL: [DerivationClass; 5] = [
        Deterministic,
        AIDerived,
        HumanPromoted,
        Mixed,
        OpaqueExternal,
    ];

    /// `RaiseTo` is exactly the production join — binds `CascadeStep::RaiseTo` to
    /// Lean `raiseTo` over the shipped `DerivationClass::join`.
    #[test]
    fn raise_to_matches_production_join() {
        for &level in &ALL {
            for &x in &ALL {
                assert_eq!(
                    CascadeStep::RaiseTo(level).apply(x),
                    x.join(level),
                    "RaiseTo({level:?}).apply({x:?}) must equal x.join(level)"
                );
            }
        }
    }

    /// `SealAbove` matches its intended closure semantics over every element.
    #[test]
    fn seal_above_matches_semantics() {
        for &t in &ALL {
            for &x in &ALL {
                let expected = if t.leq(x) { OpaqueExternal } else { x };
                assert_eq!(CascadeStep::SealAbove(t).apply(x), expected);
            }
        }
    }

    /// THE load-bearing binding: every step kind is a **monotone endomap on
    /// production** `join`/`leq`. This re-establishes the Lean monotonicity
    /// hypotheses (`raiseTo_mono`, `sealAbove_mono`) directly on the shipped
    /// lattice, so `user_cascade_ratchets` applies to real cascades. Exhaustive
    /// over the parameter and both lattice elements (5³ per step kind).
    #[test]
    fn every_step_is_monotone_on_production() {
        let step_kinds = |p: DerivationClass| [CascadeStep::RaiseTo(p), CascadeStep::SealAbove(p)];
        for &param in &ALL {
            for step in step_kinds(param) {
                for &a in &ALL {
                    for &b in &ALL {
                        if a.leq(b) {
                            assert!(
                                step.apply(a).leq(step.apply(b)),
                                "step {step:?} not monotone at {a:?} ⊑ {b:?}: \
                                 {:?} ⋢ {:?}",
                                step.apply(a),
                                step.apply(b)
                            );
                        }
                    }
                }
            }
        }
    }

    /// A sample multi-step cascade using BOTH step kinds (the `SealAbove` step is
    /// the one only `loop_admissible` covers).
    fn sample() -> Cascade {
        Cascade(vec![
            CascadeStep::RaiseTo(AIDerived),
            CascadeStep::SealAbove(Mixed),
        ])
    }

    /// Every finite unrolling stays ⊑ the fixpoint (binds
    /// `user_cascade_ratchets.unrolls_below`). Iterating the pass from ⊥ ascends
    /// and never overshoots the fixpoint.
    #[test]
    fn fixpoint_dominates_every_unrolling() {
        let c = sample();
        let fp = c.fixpoint();
        let mut cur = Deterministic;
        for _ in 0..8 {
            assert!(cur.leq(fp), "unrolling {cur:?} exceeded fixpoint {fp:?}");
            cur = c.run(cur);
        }
    }

    /// **Anti-laundering.** If any unrolling denies an action requiring
    /// cleanliness `threshold`, the fixpoint denies it too — no ordering launders
    /// it away (binds `user_cascade_ratchets.denial_persists`). Exhaustive over
    /// thresholds.
    #[test]
    fn denial_persists_across_unrollings() {
        let c = sample();
        let fp = c.fixpoint();
        for &threshold in &ALL {
            // Walk the unrollings; if any denies, the fixpoint must deny.
            let mut cur = Deterministic;
            for _ in 0..8 {
                if threshold.leq(cur) {
                    assert!(
                        c.denies(threshold),
                        "unrolling {cur:?} denied threshold {threshold:?} but fixpoint {fp:?} did not"
                    );
                }
                cur = c.run(cur);
            }
        }
    }

    /// The "no silent cleansing" guarantee, inherited by a user cascade: once the
    /// cascade has observed AI-derived provenance, a sink requiring `Deterministic`
    /// (reproducible) provenance stays denied — mirrors Lean
    /// `ai_derived_never_reaches_deterministic`.
    #[test]
    fn ai_derived_cascade_denies_deterministic_sink() {
        let c = Cascade(vec![CascadeStep::RaiseTo(AIDerived)]);
        assert_eq!(c.fixpoint(), AIDerived);
        // A Deterministic-requiring sink: threshold = Deterministic is the
        // *cleanest* requirement, always ⊑ everything, so it is denied once the
        // ceiling has risen. The meaningful check: the ceiling never returns to
        // Deterministic (no cleansing) — fixpoint is strictly above ⊥.
        assert_ne!(c.fixpoint(), Deterministic);
    }
}
