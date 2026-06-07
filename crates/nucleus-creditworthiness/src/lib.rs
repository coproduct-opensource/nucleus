//! Agent creditworthiness — the credit file that turns recompute-verified
//! history into bond-substituting reputation.
//!
//! The proven kernel [`nucleus_witness_olog::required_bond`] says verifiable
//! clean history substitutes for posted collateral down to a floor (a fresh
//! identity gets no discount — `sybil_no_discount`). But that kernel takes
//! `reputation_micro` as a bare number. **This crate is what _derives_ that
//! number**: it folds an identity's recompute-verified [`CreditEvent`]s into a
//! [`CreditFile`] — a multi-dimensional, deterministic, recompute-stable vector
//! — and composes the proven kernel to price the bond. It re-derives the bond
//! with the EXACT proven function the enforcement path uses; it never
//! re-implements the math.
//!
//! # The dimension vector (regenerative by default)
//!
//! Creditworthiness is behaviour over time priced into a number, over TWO active
//! dimensions:
//! * [`CreditDimension::FinancialDefault`] — honest settlement vs. caught
//!   defection (recompute-verified Settlement/VCG receipts);
//! * [`CreditDimension::Externality`] — Pigouvian: did the agent pay its
//!   true-cost dues to the commons, or dump them? (recompute-verified `Commons` /
//!   `route_to_commons` receipts).
//!
//! Both are load-bearing on the bond-substituting reputation
//! ([`CreditDimension::is_active`]) — the substrate is **regenerative by
//! default**: routing true-cost dues to the commons builds standing exactly as
//! honest settlement does, and only ever from a receipt that already recomputed.
//! Greed ignites; conscience compounds.
//!
//! # What is PROVEN here (property tests, not prose)
//!
//! * **Commutative monoid.** [`CreditFile::default`] is the identity and
//!   [`CreditFile::merge`] is associative + commutative ⇒ the credit file is
//!   independent of event order ⇒ any verifier recomputes the SAME file from the
//!   same receipts (recompute-stable).
//! * **Monotone flywheel.** An honest settlement never lowers reputation (never
//!   RAISES the required bond); a caught defection never raises it. For an honest
//!   agent the wheel only ever turns one way.
//! * **Sybil-no-discount.** An empty file yields reputation `0` ⇒ the full bond
//!   — minting fresh identities buys no discount (inherited from the composed
//!   kernel's `requiredBond` floor).
//! * **Provenance-gated, both dimensions.** An externality credit moves
//!   reputation only when minted from a recompute-verified `Commons` receipt
//!   (same discipline as the financial dimension) — activating externality does
//!   not let an unverified claim move money-gating standing.
//!
//! # Honesty boundary
//!
//! A [`CreditEvent`] is only as good as the recompute that justifies it: each
//! carries the `receipt_hash` of the verified receipt it was derived from, so a
//! relying party can re-verify provenance. This crate does the *aggregation +
//! pricing*; it does not itself verify receipts (that is `nucleus-recompute` /
//! `nucleus-envelope`). Garbage events in, garbage file out — feed it only
//! events minted from receipts that already recomputed.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use nucleus_witness_olog::{deters, required_bond, AmountMicro};
use serde::{Deserialize, Serialize};

#[cfg(feature = "recompute")]
pub mod mint;

/// WASM-pure, append-only hash chain over an identity's [`CreditEvent`]s
/// (always compiled — needs only `sha2`). The storage-independent core the
/// durable [`store`] commits to and any client can re-verify.
pub mod ledger;

/// Durable, append-only, per-identity credit ledger backed by redb. Behind the
/// off-by-default `persist` feature so the default + wasm32 builds never compile
/// redb; the verifier service enables it.
#[cfg(feature = "persist")]
pub mod store;

/// A dimension of creditworthiness. Each dimension is scored independently from
/// recompute-verified events.
///
/// Both [`CreditDimension::FinancialDefault`] and
/// [`CreditDimension::Externality`] are active (see [`CreditDimension::is_active`])
/// — the substrate is regenerative by default. Each contributes to the
/// bond-substituting reputation only from recompute-verified events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CreditDimension {
    /// Financial-default risk: honest, recompute-matched settlement (credit) vs.
    /// a caught defection / recompute mismatch (debit). **Active.**
    FinancialDefault,
    /// Externality internalization (Pigouvian): paying true-cost dues to the
    /// commons (credit) vs. dumping uncompensated externalities (debit).
    /// **Active** — fed by recompute-verified `Commons` (`route_to_commons`)
    /// receipts; regenerative by default.
    Externality,
}

impl CreditDimension {
    /// Every defined dimension, in canonical (sorted) order.
    pub const ALL: [CreditDimension; 2] = [
        CreditDimension::FinancialDefault,
        CreditDimension::Externality,
    ];

    /// Whether this dimension contributes to the bond-substituting reputation.
    ///
    /// **Both dimensions are active: the substrate is regenerative by default.**
    /// `FinancialDefault` is fed by recompute-verified settlement/VCG receipts;
    /// `Externality` is fed by recompute-verified `Commons` (`route_to_commons`)
    /// receipts — paying true-cost dues to the commons builds standing exactly as
    /// honest settlement does. Both move reputation ONLY from events minted off a
    /// receipt that already recomputed (see [`crate::mint`]), so activating
    /// externality does not let an unverified claim move money-gating standing.
    ///
    /// Note: this lights up commons-routing *accounting* (did the dues actually
    /// reach the commons, verified). The Pigouvian *rate-setting* — what the dues
    /// should be — remains a governed, contestable frontier (see
    /// `docs/rfcs/regenerative-default-substrate.md` and `externality-oracle.md`).
    pub const fn is_active(self) -> bool {
        matches!(
            self,
            CreditDimension::FinancialDefault | CreditDimension::Externality
        )
    }
}

/// Whether an event builds (`Credit`) or destroys (`Debit`) standing on its
/// dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Polarity {
    /// Builds standing (e.g. an honest settlement, externality dues paid).
    Credit,
    /// Destroys standing (e.g. a caught defection, externality dumped).
    Debit,
}

/// One recompute-verified outcome attributable to an identity, scoring a single
/// dimension.
///
/// `weight_micro` is the (already recompute-verified) economic magnitude in
/// micro-USD; `receipt_hash` binds the event to the verified receipt that
/// justifies it, so provenance is re-checkable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreditEvent {
    /// Which creditworthiness dimension this event scores.
    pub dimension: CreditDimension,
    /// Whether it builds or destroys standing.
    pub polarity: Polarity,
    /// Recompute-verified economic magnitude, micro-USD.
    pub weight_micro: u64,
    /// Content hash of the verified receipt this event was derived from.
    pub receipt_hash: [u8; 32],
}

impl CreditEvent {
    /// An honest, recompute-matched settlement worth `weight_micro` — builds
    /// financial standing.
    pub fn honest_settlement(weight_micro: u64, receipt_hash: [u8; 32]) -> Self {
        Self {
            dimension: CreditDimension::FinancialDefault,
            polarity: Polarity::Credit,
            weight_micro,
            receipt_hash,
        }
    }

    /// A caught defection (recompute mismatch / fraud proof) worth
    /// `weight_micro` — destroys financial standing.
    pub fn caught_defection(weight_micro: u64, receipt_hash: [u8; 32]) -> Self {
        Self {
            dimension: CreditDimension::FinancialDefault,
            polarity: Polarity::Debit,
            weight_micro,
            receipt_hash,
        }
    }

    /// Externality dues paid to the commons worth `weight_micro` — builds
    /// standing on the **active** externality dimension (regenerative by default).
    pub fn externality_internalized(weight_micro: u64, receipt_hash: [u8; 32]) -> Self {
        Self {
            dimension: CreditDimension::Externality,
            polarity: Polarity::Credit,
            weight_micro,
            receipt_hash,
        }
    }

    /// An uncompensated externality dumped on the commons worth `weight_micro` —
    /// destroys standing on the **active** externality dimension.
    pub fn externality_dumped(weight_micro: u64, receipt_hash: [u8; 32]) -> Self {
        Self {
            dimension: CreditDimension::Externality,
            polarity: Polarity::Debit,
            weight_micro,
            receipt_hash,
        }
    }
}

/// Per-dimension accumulator. Credits and debits are kept separate (not pre-
/// netted) so the fold is a clean, saturating, commutative monoid.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
struct DimAcc {
    credit_micro: u128,
    debit_micro: u128,
}

impl DimAcc {
    /// Net standing on this dimension, floored at 0 and clamped into `u64`
    /// (the input type the proven `required_bond` kernel expects). Standing can
    /// never go negative: a deeply-defected agent simply has zero reputation,
    /// not "anti-reputation" that would absurdly *increase* someone else's bond.
    fn net_micro(self) -> u64 {
        let net = self.credit_micro.saturating_sub(self.debit_micro);
        net.min(u128::from(u64::MAX)) as u64
    }

    fn merge(self, other: Self) -> Self {
        Self {
            credit_micro: self.credit_micro.saturating_add(other.credit_micro),
            debit_micro: self.debit_micro.saturating_add(other.debit_micro),
        }
    }
}

/// An identity's credit file: a deterministic, multi-dimensional aggregation of
/// recompute-verified [`CreditEvent`]s.
///
/// [`CreditFile::default`] (empty) is the monoid identity; [`CreditFile::merge`]
/// combines two files associatively + commutatively. Build one with
/// [`CreditFile::from_events`] or by folding with [`CreditFile::observe`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreditFile {
    /// Per-dimension accumulators. Absent dimension == zero (the empty file is
    /// the empty map), so equality is canonical regardless of insertion order.
    dims: BTreeMap<CreditDimension, DimAcc>,
    /// Number of events folded in (provenance/audit; sums under merge).
    event_count: u64,
}

impl CreditFile {
    /// An empty credit file — the monoid identity and a brand-new identity's
    /// starting point (reputation 0 ⇒ full bond).
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold a single recompute-verified event into the file.
    pub fn observe(&mut self, event: &CreditEvent) {
        let acc = self.dims.entry(event.dimension).or_default();
        match event.polarity {
            Polarity::Credit => {
                acc.credit_micro = acc
                    .credit_micro
                    .saturating_add(u128::from(event.weight_micro));
            }
            Polarity::Debit => {
                acc.debit_micro = acc
                    .debit_micro
                    .saturating_add(u128::from(event.weight_micro));
            }
        }
        self.event_count = self.event_count.saturating_add(1);
    }

    /// Build a credit file from a slice of events. Order-independent: any
    /// permutation of `events` yields an equal file (see the `order_independent`
    /// property test).
    pub fn from_events(events: &[CreditEvent]) -> Self {
        let mut file = Self::new();
        for e in events {
            file.observe(e);
        }
        file
    }

    /// Combine two credit files — the commutative-monoid operation. Used to
    /// merge histories accrued in different shards/sessions without caring about
    /// order.
    pub fn merge(mut self, other: Self) -> Self {
        for (dim, acc) in other.dims {
            let entry = self.dims.entry(dim).or_default();
            *entry = entry.merge(acc);
        }
        self.event_count = self.event_count.saturating_add(other.event_count);
        self
    }

    /// Number of events folded into this file.
    pub fn event_count(&self) -> u64 {
        self.event_count
    }

    /// Net standing on a single dimension (floored at 0) — for per-dimension
    /// inspection. The bond is priced by the sum over ACTIVE dimensions; see
    /// [`CreditFile::reputation_micro`].
    pub fn dimension_micro(&self, dim: CreditDimension) -> u64 {
        self.dims.get(&dim).copied().unwrap_or_default().net_micro()
    }

    /// The bond-substituting reputation: the sum of net standing across the
    /// **active** dimensions only (v1: financial). Dormant dimensions
    /// ([`CreditDimension::Externality`]) are excluded until activated.
    /// Saturating into `u64`, the type the proven kernel consumes.
    pub fn reputation_micro(&self) -> u64 {
        self.dims
            .iter()
            .filter(|(dim, _)| dim.is_active())
            .fold(0u128, |acc, (_, dacc)| {
                acc.saturating_add(u128::from(dacc.net_micro()))
            })
            .min(u128::from(u64::MAX)) as u64
    }

    /// The **minimum bond** this identity must post to deter a one-shot
    /// defection worth `max_defection_gain_micro`, given the reputation it has
    /// accrued. Composes the proven [`nucleus_witness_olog::required_bond`]
    /// (reputation substitutes for capital down to a Sybil-proof floor) — the
    /// money path runs the exact proven function.
    pub fn required_bond(&self, max_defection_gain_micro: u64) -> AmountMicro {
        required_bond(max_defection_gain_micro, self.reputation_micro())
    }

    /// Whether posting `bond` on top of this identity's accrued reputation
    /// deters a one-shot defection worth `max_defection_gain_micro`. Composes
    /// the proven [`nucleus_witness_olog::deters`].
    pub fn deters(&self, bond: AmountMicro, max_defection_gain_micro: u64) -> bool {
        deters(bond, self.reputation_micro(), max_defection_gain_micro)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn h(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    // ── Worked examples ─────────────────────────────────────────────────────

    #[test]
    fn empty_file_is_sybil_priced() {
        let f = CreditFile::new();
        assert_eq!(f.reputation_micro(), 0);
        // A fresh identity pays the full bond — no discount for splitting.
        assert_eq!(f.required_bond(1_000_000), AmountMicro(1_000_000));
    }

    #[test]
    fn honest_history_substitutes_for_capital() {
        let f = CreditFile::from_events(&[
            CreditEvent::honest_settlement(400_000, h(1)),
            CreditEvent::honest_settlement(300_000, h(2)),
        ]);
        assert_eq!(f.reputation_micro(), 700_000);
        // 700k of clean history covers 700k of a 1M defection gain → 300k bond.
        assert_eq!(f.required_bond(1_000_000), AmountMicro(300_000));
        // Once reputation alone covers the gain, the bond floors at zero.
        assert_eq!(f.required_bond(700_000), AmountMicro::ZERO);
    }

    #[test]
    fn a_caught_defection_burns_standing() {
        let mut f = CreditFile::from_events(&[CreditEvent::honest_settlement(500_000, h(1))]);
        assert_eq!(f.reputation_micro(), 500_000);
        f.observe(&CreditEvent::caught_defection(200_000, h(9)));
        assert_eq!(f.reputation_micro(), 300_000);
    }

    #[test]
    fn standing_floors_at_zero_never_negative() {
        // More defection than credit ⇒ reputation 0, NOT a negative that would
        // perversely raise the required bond above the bare gain.
        let f = CreditFile::from_events(&[
            CreditEvent::honest_settlement(100_000, h(1)),
            CreditEvent::caught_defection(900_000, h(2)),
        ]);
        assert_eq!(f.reputation_micro(), 0);
        assert_eq!(f.required_bond(1_000_000), AmountMicro(1_000_000));
    }

    #[test]
    fn externality_dimension_is_active_regenerative_by_default() {
        // Externality events accumulate on their dimension...
        let f = CreditFile::from_events(&[
            CreditEvent::externality_internalized(1_000_000, h(1)),
            CreditEvent::externality_dumped(250_000, h(2)),
        ]);
        assert_eq!(f.dimension_micro(CreditDimension::Externality), 750_000);
        // ...and now CONTRIBUTE to the bond-substituting reputation: routing
        // true-cost dues to the commons prices a discount, exactly as honest
        // settlement does. Regenerative by default.
        assert_eq!(f.reputation_micro(), 750_000);
        assert_eq!(f.required_bond(1_000_000), AmountMicro(250_000));
        assert!(CreditDimension::Externality.is_active());
        assert!(CreditDimension::FinancialDefault.is_active());
    }

    #[test]
    fn both_dimensions_sum_into_reputation() {
        // Financial + externality standing compose into one bond-substituting
        // reputation — conscience and commerce pulling the same direction.
        let f = CreditFile::from_events(&[
            CreditEvent::honest_settlement(400_000, h(1)),
            CreditEvent::externality_internalized(300_000, h(2)),
        ]);
        assert_eq!(f.reputation_micro(), 700_000);
    }

    #[test]
    fn serde_round_trips() {
        let f = CreditFile::from_events(&[
            CreditEvent::honest_settlement(123, h(1)),
            CreditEvent::caught_defection(45, h(2)),
            CreditEvent::externality_internalized(9, h(3)),
        ]);
        let json = serde_json::to_string(&f).unwrap();
        let back: CreditFile = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    // ── Property tests: the credit file is a commutative monoid ──────────────
    //
    // Order-independence is the load-bearing property: a verifier who replays
    // the same receipts in ANY order must recompute the SAME file (and thus the
    // same bond). That is exactly the commutative-monoid laws on `merge` + the
    // empty-file identity.

    prop_compose! {
        fn any_event()(
            dim_sel in 0usize..2,
            pol in any::<bool>(),
            weight in 0u64..2_000_000,
            seed in any::<u8>(),
        ) -> CreditEvent {
            CreditEvent {
                dimension: CreditDimension::ALL[dim_sel],
                polarity: if pol { Polarity::Credit } else { Polarity::Debit },
                weight_micro: weight,
                receipt_hash: [seed; 32],
            }
        }
    }

    fn events() -> impl Strategy<Value = Vec<CreditEvent>> {
        proptest::collection::vec(any_event(), 0..24)
    }

    proptest! {
        /// Identity: merging with the empty file changes nothing (both sides).
        #[test]
        fn monoid_identity(evs in events()) {
            let f = CreditFile::from_events(&evs);
            prop_assert_eq!(f.clone().merge(CreditFile::new()), f.clone());
            prop_assert_eq!(CreditFile::new().merge(f.clone()), f);
        }

        /// Commutativity: merge order of two files does not matter.
        #[test]
        fn monoid_commutative(a in events(), b in events()) {
            let fa = CreditFile::from_events(&a);
            let fb = CreditFile::from_events(&b);
            prop_assert_eq!(fa.clone().merge(fb.clone()), fb.merge(fa));
        }

        /// Associativity: regrouping three merges does not matter.
        #[test]
        fn monoid_associative(a in events(), b in events(), c in events()) {
            let fa = CreditFile::from_events(&a);
            let fb = CreditFile::from_events(&b);
            let fc = CreditFile::from_events(&c);
            let left = fa.clone().merge(fb.clone()).merge(fc.clone());
            let right = fa.merge(fb.merge(fc));
            prop_assert_eq!(left, right);
        }

        /// Recompute-stability: any permutation of the events yields an equal
        /// file. (Follows from the monoid laws; proved directly because it is
        /// the property a third-party verifier actually relies on.)
        #[test]
        fn order_independent(evs in events(), seed in any::<u64>()) {
            let forward = CreditFile::from_events(&evs);
            // A cheap deterministic shuffle: rotate by a seed-derived offset.
            let mut shuffled = evs.clone();
            if !shuffled.is_empty() {
                let k = (seed as usize) % shuffled.len();
                shuffled.rotate_left(k);
                // plus a reversal so it isn't merely a rotation
                shuffled.reverse();
            }
            prop_assert_eq!(forward, CreditFile::from_events(&shuffled));
        }

        /// Monotone flywheel (up): an honest settlement never RAISES the bond.
        #[test]
        fn honest_settlement_never_raises_bond(
            evs in events(),
            extra in 0u64..2_000_000,
            gain in 0u64..4_000_000,
            seed in any::<u8>(),
        ) {
            let before = CreditFile::from_events(&evs);
            let mut after = before.clone();
            after.observe(&CreditEvent::honest_settlement(extra, [seed; 32]));
            prop_assert!(after.reputation_micro() >= before.reputation_micro());
            prop_assert!(after.required_bond(gain).0 <= before.required_bond(gain).0);
        }

        /// Monotone flywheel (down): a caught defection never LOWERS the bond.
        #[test]
        fn caught_defection_never_lowers_bond(
            evs in events(),
            extra in 0u64..2_000_000,
            gain in 0u64..4_000_000,
            seed in any::<u8>(),
        ) {
            let before = CreditFile::from_events(&evs);
            let mut after = before.clone();
            after.observe(&CreditEvent::caught_defection(extra, [seed; 32]));
            prop_assert!(after.reputation_micro() <= before.reputation_micro());
            prop_assert!(after.required_bond(gain).0 >= before.required_bond(gain).0);
        }

        /// Regenerative monotonicity: an externality CREDIT (true-cost dues routed
        /// to the commons) never LOWERS reputation; an externality DEBIT (dumped)
        /// never RAISES it — the same one-way flywheel as the financial dimension,
        /// now that externality is active.
        #[test]
        fn externality_credit_builds_debit_burns(
            evs in events(),
            ext_weight in 0u64..2_000_000,
            ext_pol in any::<bool>(),
            gain in 0u64..4_000_000,
            seed in any::<u8>(),
        ) {
            let before = CreditFile::from_events(&evs);
            let mut after = before.clone();
            if ext_pol {
                after.observe(&CreditEvent::externality_internalized(ext_weight, [seed; 32]));
                prop_assert!(after.reputation_micro() >= before.reputation_micro());
                prop_assert!(after.required_bond(gain).0 <= before.required_bond(gain).0);
            } else {
                after.observe(&CreditEvent::externality_dumped(ext_weight, [seed; 32]));
                prop_assert!(after.reputation_micro() <= before.reputation_micro());
                prop_assert!(after.required_bond(gain).0 >= before.required_bond(gain).0);
            }
        }

        /// Sybil-no-discount: a fresh (empty) identity always pays the full bond.
        #[test]
        fn fresh_identity_pays_full_bond(gain in 0u64..4_000_000) {
            prop_assert_eq!(CreditFile::new().required_bond(gain), AmountMicro(gain));
        }
    }
}
