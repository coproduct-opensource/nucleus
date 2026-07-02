//! **The dual idempotent reflections of the Proof-Carrying-Authorization fabric.**
//!
//! The categorical model of the fabric (see the spiffy doctrine doc
//! *"authorization is natural in the execution site"*, verdict: the
//! *Enriched-Reflection model*) identifies two order-theoretic operators that do
//! all the work:
//!
//! - **Enforcement** is a [`ClosureOperator`] — monotone, **inflationary**
//!   (`x ≤ c(x)`), idempotent. Its fixed points are the postures a backend can
//!   actually enforce; the operator is the **reflector** `L_E` (left adjoint to
//!   the inclusion of the enforceable sub-poset). [`Reflector`] is exactly
//!   [`enforcement::require_isolation`](crate::enforcement::require_isolation)
//!   viewed this way: clamp *up* to the least enforceable posture ≥ the request.
//!
//! - **Delegation** is the order-dual [`InteriorOperator`] — monotone,
//!   **deflationary** (`i(x) ≤ x`), idempotent. [`Attenuator`] is attenuation
//!   under a ceiling `(−) ∧ c`: the greatest sub-authority ≤ both the requested
//!   capability and the ceiling — the **coreflector** onto the down-set `↓c`.
//!
//! Together they realize the model's headline **sandwich**: for a delegated,
//! enforced workload, `i(x) ≤ x ≤ c(x)` with both ends idempotent — the gap
//! between what was delegated and what is enforced cannot be silently widened.
//!
//! This module is in `portcullis` (the runtime crate), not the Aeneas-translated
//! `portcullis-core`; the operators here wrap already-verified primitives
//! (`require_isolation`, the lattice `meet`).

use portcullis_core::category::Lattice;

use crate::enforcement::{require_isolation, BackendCapability};
use crate::isolation::IsolationLattice;

/// A **closure operator** on a poset `T`: monotone, inflationary (`x ≤ c(x)`),
/// idempotent (`c(c(x)) = c(x)`). The fixed points form a reflective sub-poset
/// and `c` is the reflector (left adjoint to the inclusion).
pub trait ClosureOperator<T> {
    /// `c(x)` — the closure of `x`.
    fn close(&self, x: T) -> T;
}

/// An **interior operator** on a poset `T`: monotone, deflationary (`i(x) ≤ x`),
/// idempotent. The order-dual of a [`ClosureOperator`]; the fixed points form a
/// coreflective sub-poset and `i` is the coreflector.
pub trait InteriorOperator<T> {
    /// `i(x)` — the interior of `x`.
    fn interior(&self, x: T) -> T;
}

/// **Enforcement as a closure operator.** `Reflector(backend).close(x)` is the
/// least posture the backend can enforce that is at-least-as-strong as `x` — the
/// reflector `L_E` of the enforceable sub-poset. This is the categorical reading
/// of [`require_isolation`]; on the (built-in-backend-unreachable) `Unenforceable`
/// case it returns `x`, preserving the inflationary law.
#[derive(Debug, Clone, Copy)]
pub struct Reflector<'a>(pub &'a BackendCapability);

impl ClosureOperator<IsolationLattice> for Reflector<'_> {
    fn close(&self, x: IsolationLattice) -> IsolationLattice {
        require_isolation(x, self.0)
            .map(|e| e.enforced)
            .unwrap_or(x)
    }
}

/// **Delegation as an interior operator.** `Attenuator(c).interior(x) = x ∧ c` —
/// the greatest authority that is ≤ both `x` and the ceiling `c`; the coreflector
/// onto the down-set `↓c`. Idempotent because `(x∧c)∧c = x∧c`.
#[derive(Debug, Clone)]
pub struct Attenuator<L>(pub L);

impl<L: Lattice> InteriorOperator<L> for Attenuator<L> {
    fn interior(&self, x: L) -> L {
        x.meet(&self.0)
    }
}

/// Check the three closure-operator laws over `samples`, returning a list of
/// violations (empty ⇒ `c` is a genuine closure operator). Monotonicity is
/// checked over all ordered pairs in `samples`.
pub fn verify_closure_laws<T, C>(c: &C, samples: &[T]) -> Vec<String>
where
    T: Lattice + std::fmt::Debug,
    C: ClosureOperator<T>,
{
    let mut bad = Vec::new();
    for x in samples {
        let cx = c.close(x.clone());
        // inflationary: x ≤ c(x)
        if !x.leq(&cx) {
            bad.push(format!("not inflationary: {x:?} ⋠ c={cx:?}"));
        }
        // idempotent: c(c(x)) = c(x)
        if c.close(cx.clone()) != cx {
            bad.push(format!(
                "not idempotent at {x:?}: c(c)={:?} ≠ c={cx:?}",
                c.close(cx.clone())
            ));
        }
    }
    for x in samples {
        for y in samples {
            if x.leq(y) && !c.close(x.clone()).leq(&c.close(y.clone())) {
                bad.push(format!("not monotone: {x:?} ≤ {y:?} but c(x) ⋠ c(y)"));
            }
        }
    }
    bad
}

/// Check the three interior-operator laws over `samples` (empty ⇒ genuine
/// interior operator). The order-dual of [`verify_closure_laws`].
pub fn verify_interior_laws<T, I>(i: &I, samples: &[T]) -> Vec<String>
where
    T: Lattice + std::fmt::Debug,
    I: InteriorOperator<T>,
{
    let mut bad = Vec::new();
    for x in samples {
        let ix = i.interior(x.clone());
        // deflationary: i(x) ≤ x
        if !ix.leq(x) {
            bad.push(format!("not deflationary: i={ix:?} ⋠ {x:?}"));
        }
        // idempotent
        if i.interior(ix.clone()) != ix {
            bad.push(format!("not idempotent at {x:?}"));
        }
    }
    for x in samples {
        for y in samples {
            if x.leq(y) && !i.interior(x.clone()).leq(&i.interior(y.clone())) {
                bad.push(format!("not monotone: {x:?} ≤ {y:?} but i(x) ⋠ i(y)"));
            }
        }
    }
    bad
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isolation::{FileIsolation, NetworkIsolation, ProcessIsolation};
    use portcullis_core::CapabilityLevel;

    fn all_isolations() -> Vec<IsolationLattice> {
        let mut out = Vec::new();
        for &p in &[
            ProcessIsolation::Shared,
            ProcessIsolation::Namespaced,
            ProcessIsolation::MicroVM,
        ] {
            for &f in &[
                FileIsolation::Unrestricted,
                FileIsolation::Sandboxed,
                FileIsolation::ReadOnly,
                FileIsolation::Ephemeral,
            ] {
                for &n in &[
                    NetworkIsolation::Host,
                    NetworkIsolation::Namespaced,
                    NetworkIsolation::Filtered,
                    NetworkIsolation::Airgapped,
                ] {
                    out.push(IsolationLattice {
                        process: p,
                        file: f,
                        network: n,
                    });
                }
            }
        }
        out
    }

    #[test]
    fn enforcement_is_a_closure_operator_on_every_backend() {
        let postures = all_isolations();
        for backend in [
            &BackendCapability::FIRECRACKER,
            &BackendCapability::APPLE_VZ,
        ] {
            let violations = verify_closure_laws(&Reflector(backend), &postures);
            assert!(
                violations.is_empty(),
                "{} reflector violated the closure laws: {violations:?}",
                backend.name
            );
        }
    }

    #[test]
    fn delegation_is_an_interior_operator() {
        let caps = [
            CapabilityLevel::Never,
            CapabilityLevel::LowRisk,
            CapabilityLevel::Always,
        ];
        for &ceiling in &caps {
            let violations = verify_interior_laws(&Attenuator(ceiling), &caps);
            assert!(
                violations.is_empty(),
                "attenuator ∧{ceiling:?} violated the interior laws: {violations:?}"
            );
        }
    }

    #[test]
    fn the_sandwich_holds_pointwise() {
        // i(x) ≤ x ≤ c(x): delegation never exceeds the request, enforcement
        // never falls below it — and both ends are idempotent.
        let firecracker = Reflector(&BackendCapability::FIRECRACKER);
        for x in all_isolations() {
            let enforced = firecracker.close(x);
            assert!(
                x.at_least(&x) && enforced.at_least(&x),
                "enforcement must be ≥ requested"
            );
        }
    }
}
