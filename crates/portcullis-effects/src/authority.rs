//! `Authority` — a spent-on-use wrapper over [`DischargedBundle`].
//!
//! ## What this is for
//!
//! Today every effect takes `proof: &DischargedBundle`. In the vocabulary of
//! effect systems that is `ReaderT Capability`: authority that is **ambient and
//! readable at every bind**. [`require_scope`](crate::require_scope) rejects a
//! bundle earned for a *different* action — real, and worth having — but nothing
//! stops a *matching* bundle being replayed arbitrarily often. The one-shot
//! property the Lean side proves has no counterpart in the Rust types.
//!
//! The fix is not a type-system fight. `DischargedBundle` is **already affine**:
//! it is `!Clone`, `!Copy` and `#[must_use]`. The only reason it can be replayed
//! is that it is passed by reference rather than moved. `Authority` is that
//! move, made explicit and given a name.
//!
//! ## Affine, not linear — and affine is the one we want
//!
//! Rust gives *use at most once*, not *use exactly once*. At-most-once is
//! precisely what one-shot declassification needs, so the weaker guarantee is
//! the correct one. (A widely repeated claim that Rust 1.95 shipped linear types
//! via `std::marker::MustMove` is false — checked against 1.96.1, which is
//! newer; the trait does not exist.)
//!
//! ## The spend is the witness point
//!
//! An `Authority` can carry the [`ReceiptLog`] it should record against, and
//! [`spend`](Authority::spend) appends the receipt itself. That placement is the
//! point of the design, not an implementation detail.
//!
//! The surveyed alternative is to log at the **policy decision point** and let
//! each enforcement site annotate the record afterwards; the five-plane runtime
//! governance architecture calls the result "complete by construction … a
//! property of the architecture, not of developer diligence". It is a real
//! improvement over ad-hoc logging, but the completeness is still architectural:
//! some human wires every decision point, and a site that is added later and not
//! wired is silently uncovered. That is exactly how the three most dangerous
//! effects here — `run_argv`, `run_argv_async` and `NetEffect::fetch` — ended up
//! outside the log while every safer effect was inside it.
//!
//! Because `Authority` is affine, this crate can do better than architectural
//! completeness. `spend` is the *only* way to consume one, and after the #2090
//! cutover an effect cannot run without consuming one. So "the authority was
//! exercised" and "a receipt exists" are the same event, and the compiler is what
//! keeps them the same event. Etas — the closest effect-typed agent language —
//! keeps audit as a separate trace abstraction alongside the effect type and
//! explicitly does *not* use linear or affine capabilities, so the coupling here
//! is not what the current literature does.
//!
//! **What this does not claim.** A receipt says an authority was spent for a
//! scope, which is upstream of the syscall: it is not proof the effect completed,
//! and a spend followed by a crash still logs `Allowed`. Distinguishing
//! *committed* from *authorised* needs a second event after the effect returns —
//! Etas splits `request`/`handled`/`commit`/`denied` for exactly this reason —
//! and that is not implemented here. Attaching the witness is also still a call
//! the mediation layer has to make; forgetting it loses the record but never the
//! enforcement, and `every_effect_is_witnessed` is what stops it drifting.

use std::sync::Arc;

use portcullis_core::discharge::DischargedBundle;
use portcullis_core::{Operation, SinkClass};

use crate::receipt::{EffectOutcome, ReceiptLog};

/// One authorised action, **spent when used**.
///
/// Holding an `Authority` is the right to perform exactly one operation. The
/// scope check consumes it, so a second use is a compile error rather than a
/// policy someone has to remember.
///
/// ## A single authority authorises a single action
///
/// A `compile_fail` doctest passes when the snippet fails to compile FOR ANY
/// REASON — a typo would satisfy it just as well as the moved value. The error
/// code below looks like it pins the reason. **It does not:** rustdoc on this
/// toolchain does not enforce it (measured — swapping `E0382` for an unrelated
/// `E0433` left the suite green). It is kept as documentation of intent only.
///
/// What actually establishes the reason is perturbation: delete the second
/// `spend` and this snippet COMPILES, so the failure does depend on the replay
/// and on nothing else. That was checked, not assumed.
///
/// ```compile_fail,E0382
/// use portcullis_effects::authority::Authority;
/// use portcullis_core::discharge::test_helpers::bundle_for;
/// use portcullis_core::{Operation, SinkClass};
///
/// let authority = Authority::new(bundle_for(Operation::RunBash, SinkClass::BashExec));
/// let _first = authority.spend(Operation::RunBash, SinkClass::BashExec);
/// // Replay: `authority` was moved by the first `spend`.
/// let _second = authority.spend(Operation::RunBash, SinkClass::BashExec);
/// ```
///
/// ## …and it cannot be duplicated to get around that
///
/// ```compile_fail,E0599
/// use portcullis_effects::authority::Authority;
/// use portcullis_core::discharge::test_helpers::bundle_for;
/// use portcullis_core::{Operation, SinkClass};
///
/// let authority = Authority::new(bundle_for(Operation::RunBash, SinkClass::BashExec));
/// // `DischargedBundle` is deliberately not `Clone`, so neither is this.
/// let copy = authority.clone();
/// ```
#[must_use = "an Authority that is never spent is an action that was authorised and not taken"]
pub struct Authority {
    bundle: DischargedBundle,
    /// Where to record the spend. `None` leaves the spend unwitnessed — the
    /// enforcement is identical either way, so a missing witness degrades to
    /// silence, never to permission.
    witness: Option<Arc<ReceiptLog>>,
}

/// Why an authority could not be spent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendError {
    /// The authority was earned for a different (operation, sink) pair.
    ScopeMismatch(String),
}

impl std::fmt::Display for SpendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpendError::ScopeMismatch(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for SpendError {}

impl Authority {
    /// Wrap a discharged bundle as a single-use authority.
    ///
    /// Takes the bundle **by value**: the caller gives up the ability to use it
    /// again, which is the entire point.
    pub fn new(bundle: DischargedBundle) -> Self {
        Authority {
            bundle,
            witness: None,
        }
    }

    /// Attach the log that should record this authority's spend.
    ///
    /// The mediation layer owns the log, so it attaches the witness on the way
    /// past; the authority then carries it down to wherever it is actually
    /// spent. That is the whole trick — see the type docs.
    pub fn witnessed_by(mut self, log: Arc<ReceiptLog>) -> Self {
        self.witness = Some(log);
        self
    }

    /// The operation and sink this authority was earned for, without spending it.
    pub fn scope(&self) -> (Operation, SinkClass) {
        (self.bundle.operation(), self.bundle.sink_class())
    }

    /// Spend this authority on exactly one `(operation, sink)` pair.
    ///
    /// Consumes `self`. On success the bundle is handed back so the caller can
    /// pass it to today's `&DischargedBundle` effect surface — this is the
    /// transitional seam, and it is worth being precise about what it does and
    /// does not buy:
    ///
    /// * **Bought:** one `Authority` authorises one scope check. Holding it
    ///   twice, or checking two different scopes with it, will not compile.
    /// * **Not bought:** once the bundle is handed back, the old ambient
    ///   surface applies to it again. Closing that is the signature change
    ///   through the effect traits, which this type exists to inform rather
    ///   than to pre-empt.
    pub fn spend(self, op: Operation, sink: SinkClass) -> Result<DischargedBundle, SpendError> {
        // Record against the scope ATTEMPTED, not the scope held. A refused
        // spend is evidence about what was reached for, and the pair held is
        // already implied by whichever authority was issued.
        match crate::require_scope(&self.bundle, op, sink) {
            Ok(()) => {
                if let Some(log) = &self.witness {
                    log.append(op, sink, EffectOutcome::Allowed);
                }
                Ok(self.bundle)
            }
            Err(why) => {
                if let Some(log) = &self.witness {
                    log.append(op, sink, EffectOutcome::DeniedByScope);
                }
                Err(SpendError::ScopeMismatch(why))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis_core::discharge::test_helpers::bundle_for;

    #[test]
    fn an_authority_spends_on_the_scope_it_was_earned_for() {
        let a = Authority::new(bundle_for(Operation::RunBash, SinkClass::BashExec));
        assert_eq!(a.scope(), (Operation::RunBash, SinkClass::BashExec));
        assert!(a.spend(Operation::RunBash, SinkClass::BashExec).is_ok());
    }

    /// The confused deputy, at the authority layer: a right earned for writing
    /// files does not become a right to run a shell just because both are
    /// "allowed". Same property `require_scope` enforces, restated where the
    /// caller actually holds the thing.
    #[test]
    fn an_authority_earned_for_one_action_will_not_spend_on_another() {
        let a = Authority::new(bundle_for(Operation::WriteFiles, SinkClass::WorkspaceWrite));
        let err = a
            .spend(Operation::RunBash, SinkClass::BashExec)
            .expect_err("a write authority must not buy a shell execution");
        let SpendError::ScopeMismatch(why) = err;
        assert!(
            why.contains("WriteFiles") && why.contains("RunBash"),
            "the refusal should name both the authority held and the action attempted: {why}"
        );
    }

    /// The affine property is INHERITED, not invented here: it holds because
    /// `DischargedBundle` is `!Clone`, and if that ever changed every guarantee
    /// above would quietly become advisory.
    ///
    /// There is no runtime assertion for this. Rust cannot state a negative
    /// bound, and the trick that looks like it can — a generic `is_clone::<T>()`
    /// helper — asserts nothing about the type it names and is rejected by
    /// clippy as an unused parameter. It was written, and deleted, rather than
    /// left in place looking like evidence.
    ///
    /// The property is carried by the `compile_fail` doctest on `Authority`,
    /// whose dependence on the replay was established by perturbation.
    #[test]
    fn spending_returns_the_bundle_for_the_transitional_surface() {
        let a = Authority::new(bundle_for(Operation::RunBash, SinkClass::BashExec));
        let bundle = a
            .spend(Operation::RunBash, SinkClass::BashExec)
            .expect("in-scope spend succeeds");
        // The seam, stated: the bundle comes back, so today's `&`-taking effect
        // surface still applies to it. One Authority buys one scope check, not
        // one effect invocation.
        assert_eq!(bundle.operation(), Operation::RunBash);
    }
}
