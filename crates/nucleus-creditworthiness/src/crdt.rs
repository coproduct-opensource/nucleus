//! A conflict-free replicated set of recompute-verified [`CreditEvent`]s —
//! the join-semilattice that lets the credit ledger survive multi-writer,
//! out-of-order, duplicating gossip replication with **strong eventual
//! consistency**.
//!
//! # Why [`CreditFile`] alone is not enough under replication
//!
//! [`CreditFile`] is a beautiful commutative *monoid*: order-independent, so a
//! single writer who replays the same receipts in any order recomputes the same
//! file. But monoid merge is **not idempotent** — it folds already-summed
//! totals. Under gossip the SAME [`CreditEvent`] arrives via multiple paths, and
//! [`CreditFile::merge`] would DOUBLE-COUNT it. The financial-default flywheel
//! would spin twice for one honest settlement.
//!
//! # The fix: a set keyed by `receipt_hash`
//!
//! [`ReputationSet`] keys events by their `receipt_hash` — the 32-byte content
//! hash of the verified receipt the event was minted from. A receipt has exactly
//! one content hash, and the same receipt deterministically mints the same
//! event, so set membership by `receipt_hash` is **idempotent**: seeing the same
//! receipt twice is seeing it once. [`ReputationSet::join`] is then a true
//! join-semilattice — commutative, associative, **idempotent** — and reputation
//! is a deterministic fold over the set, reusing [`CreditFile`]'s proven monoid
//! VERBATIM. Any two replicas that have observed the same event multiset compute
//! the same `reputation_micro`, regardless of order or duplication.
//!
//! # Fail-closed admission — trust the recompute, never set membership
//!
//! An event joins the set ONLY through a recompute gate
//! ([`ReputationSet::verified_insert`] / [`ReputationSet::verified_admit`]),
//! which re-mints the event from its receipt via [`crate::mint`]. A forged event
//! — one that claims credit with no recomputing receipt, or whose claimed value
//! does not match what the receipt actually recomputes to — NEVER joins. The set
//! is a write-conflict resolver; it is **not** a source of truth. Truth is the
//! recompute.
//!
//! # Honest scope: a CRDT resolves WRITE CONFLICTS, not TRUTHFULNESS
//!
//! [`ReputationSet`] guarantees that replicas converge on the same *set of
//! admitted evidence* and therefore the same reputation. It does NOT decide
//! whether any given event is honest — that is settled, upstream and
//! independently, by the recompute in [`crate::mint`]. Reputation stays a
//! deterministic function of recompute-verified evidence; the CRDT only makes
//! that function survive replication.
//!
//! # No transport here
//!
//! This module is pure: it builds on [`crate::mint`] / [`CreditFile`] and adds
//! no transport. The eventual iroh-docs carrier that gossips these sets across
//! the wire is a separate, later, feature-gated slice — deliberately absent so
//! the join-semilattice can be reasoned about and property-tested in isolation.

use std::collections::BTreeMap;

use crate::{CreditDimension, CreditEvent, CreditFile};

/// A conflict-free replicated set of recompute-verified [`CreditEvent`]s, keyed
/// by `receipt_hash`.
///
/// Provides strong eventual consistency: any replica that has admitted the same
/// recompute-verified events converges to the same [`ReputationSet::reputation_micro`]
/// regardless of the order they arrived or how many times they were duplicated.
///
/// The merge ([`ReputationSet::join`]) is a join-semilattice:
/// * **idempotent** — `receipt_hash` uniquely identifies a receipt's content;
/// * **commutative** — `join(a, b) == join(b, a)`;
/// * **associative** — `join(join(a, b), c) == join(a, join(b, c))`.
///
/// Reputation is a deterministic fold over the set values, reusing the proven
/// [`CreditFile`] monoid — so two replicas with identical membership compute
/// identical reputation.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReputationSet {
    /// Events keyed by `receipt_hash`. A [`BTreeMap`] gives a canonical,
    /// insertion-order-independent layout (so structural equality is order-free)
    /// and a stable fold order. Absent key == event never observed.
    events: BTreeMap<[u8; 32], CreditEvent>,
}

/// Lowercase-hex a 32-byte hash without depending on the (feature-gated) `hex`
/// crate — used only to make a fail-closed panic message legible.
fn hex32(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap());
        s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap());
    }
    s
}

impl ReputationSet {
    /// The empty set — the join-semilattice's identity element (reputation 0 ⇒
    /// full bond, exactly like an empty [`CreditFile`]).
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of distinct recompute-verified events in the set.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Iterate the set's events in canonical (`receipt_hash`-sorted) order.
    pub fn iter(&self) -> impl Iterator<Item = &CreditEvent> {
        self.events.values()
    }

    /// Whether the set already holds the event for this `receipt_hash`.
    pub fn contains(&self, receipt_hash: &[u8; 32]) -> bool {
        self.events.contains_key(receipt_hash)
    }

    /// Merge two reputation sets: the **join-semilattice** operation. Returns a
    /// new set holding the union of both sets' `receipt_hash`-keyed events.
    ///
    /// On a shared key, the two events MUST be identical — the same receipt
    /// recomputes to the same event, so a divergence here is not a normal merge
    /// conflict but evidence of a CRDT-invariant violation (a tampered/forged
    /// event injected into a gossip). We fail closed and panic: replication must
    /// halt and be diagnosed rather than silently converge on a lie.
    ///
    /// # Panics
    /// If a `receipt_hash` appears in both sets bound to differing events.
    pub fn join(&self, other: &Self) -> Self {
        let mut merged = self.events.clone();
        for (hash, other_event) in &other.events {
            match merged.get(hash) {
                Some(existing) if existing == other_event => { /* idempotent: no-op */ }
                Some(existing) => {
                    panic!(
                        "CRDT invariant violation: receipt_hash {} is bound to two \
                         different CreditEvents across replicas ({existing:?} vs \
                         {other_event:?}). The same receipt must recompute to the same \
                         event; this indicates a forged/tampered event in gossip. \
                         Failing closed.",
                        hex32(hash)
                    );
                }
                None => {
                    merged.insert(*hash, *other_event);
                }
            }
        }
        Self { events: merged }
    }

    /// Fold the set into a [`CreditFile`] using the proven [`CreditFile`] monoid
    /// VERBATIM. Deterministic: identical membership ⇒ identical file.
    pub fn credit_file(&self) -> CreditFile {
        let events: Vec<CreditEvent> = self.events.values().copied().collect();
        CreditFile::from_events(&events)
    }

    /// The bond-substituting reputation — a deterministic fold over the set's
    /// verified evidence. Because the set is deduped by `receipt_hash`, this is
    /// idempotent and convergent: any replica with the same membership computes
    /// the same value.
    pub fn reputation_micro(&self) -> u64 {
        self.credit_file().reputation_micro()
    }

    /// Net standing on a single dimension (floored at 0), folded over the set.
    pub fn dimension_micro(&self, dim: CreditDimension) -> u64 {
        self.credit_file().dimension_micro(dim)
    }

    /// Number of distinct events in the set (exact dedup count). Equal to
    /// [`ReputationSet::len`]; distinct from [`CreditFile::event_count`], which
    /// counts every observation (and would over-count duplicates).
    pub fn event_count(&self) -> u64 {
        self.events.len() as u64
    }

    /// Insert an event already known to be recompute-verified, keyed by its
    /// `receipt_hash`. Internal: the public admission gates
    /// ([`Self::verified_insert`] / [`Self::verified_admit`]) call this only
    /// AFTER re-minting from a receipt. Idempotent; fails closed (panics) if the
    /// same key arrives bound to a different event.
    #[cfg(feature = "recompute")]
    fn admit(&mut self, event: CreditEvent) -> bool {
        match self.events.get(&event.receipt_hash) {
            Some(existing) if *existing == event => true, // idempotent
            Some(existing) => panic!(
                "CRDT invariant violation: receipt_hash {} re-admitted with a different \
                 event ({existing:?} vs {event:?}); deterministic mint broken. Failing closed.",
                hex32(&event.receipt_hash)
            ),
            None => {
                self.events.insert(event.receipt_hash, event);
                true
            }
        }
    }

    /// **Fail-closed admission gate.** Admit an event by RE-MINTING it from its
    /// receipt via [`crate::mint::mint_event`] (which recomputes the receipt). The
    /// caller supplies only the receipt — the event is derived here, never
    /// trusted from the wire — so trust is the recompute, never set membership.
    ///
    /// Returns `true` if the event was newly admitted or confirmed as an
    /// idempotent duplicate; `false` if the receipt is
    /// [`nucleus_recompute::RecomputeOutcome::Invalid`] (no baseline to attribute,
    /// nothing minted, set unchanged).
    ///
    /// Note a recompute **Mismatch** is still admitted — it mints a *debit*
    /// (caught defection / externality dumped), which correctly burns standing.
    #[cfg(feature = "recompute")]
    pub fn verified_insert(&mut self, receipt: &nucleus_recompute::ClearingReceipt) -> bool {
        match crate::mint::mint_event(receipt) {
            Some(event) => self.admit(event),
            None => false, // Invalid receipt: not admitted.
        }
    }

    /// **Fail-closed admission gate for gossiped (event, receipt) pairs.** A
    /// replica receives a *claimed* [`CreditEvent`] alongside the receipt it
    /// purports to come from. We RE-MINT from the receipt and admit ONLY if the
    /// freshly-minted event equals the claim. A forged event — one that claims
    /// credit with no recomputing receipt (Invalid ⇒ no mint), or whose claimed
    /// dimension/polarity/weight/hash does not match what the receipt actually
    /// recomputes to — NEVER joins.
    ///
    /// Returns `true` iff the claim was verified against its receipt and admitted
    /// (or was an idempotent duplicate); `false` otherwise (set unchanged).
    #[cfg(feature = "recompute")]
    pub fn verified_admit(
        &mut self,
        claimed: &CreditEvent,
        receipt: &nucleus_recompute::ClearingReceipt,
    ) -> bool {
        match crate::mint::mint_event(receipt) {
            // The recompute IS the authority: the claim must match it exactly.
            Some(minted) if &minted == claimed => self.admit(minted),
            // Either the receipt recomputes to a DIFFERENT event than claimed, or
            // it is Invalid (no mint). Forged ⇒ refused.
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Polarity;
    use proptest::prelude::*;

    /// Insert raw events (test-only) bypassing the recompute gate, to exercise
    /// the pure join-semilattice laws on arbitrary membership. The admission gate
    /// itself is tested separately under `#[cfg(feature = "recompute")]`.
    fn set_from(events: &[CreditEvent]) -> ReputationSet {
        let mut s = ReputationSet::new();
        for e in events {
            s.events.insert(e.receipt_hash, *e);
        }
        s
    }

    // ── Strategies ───────────────────────────────────────────────────────────

    prop_compose! {
        /// Generate an event whose `receipt_hash` is a CONTENT-DERIVED, injective
        /// function of its (dimension, polarity, weight). This models the real
        /// invariant — a receipt's content hash determines the event it mints —
        /// so equal keys always carry equal events (no spurious fail-closed
        /// panic) and distinct events get distinct keys.
        fn any_event()(
            dim_sel in 0usize..2,
            pol in any::<bool>(),
            weight in 0u64..2_000_000,
        ) -> CreditEvent {
            let mut hash = [0u8; 32];
            hash[0..8].copy_from_slice(&weight.to_le_bytes());
            hash[8] = dim_sel as u8;
            hash[9] = pol as u8;
            CreditEvent {
                dimension: CreditDimension::ALL[dim_sel],
                polarity: if pol { Polarity::Credit } else { Polarity::Debit },
                weight_micro: weight,
                receipt_hash: hash,
            }
        }
    }

    fn any_set() -> impl Strategy<Value = ReputationSet> {
        proptest::collection::vec(any_event(), 0..24).prop_map(|evs| set_from(&evs))
    }

    // ── CRDT laws: join is a join-semilattice ────────────────────────────────

    proptest! {
        /// Commutative: join(a, b) == join(b, a).
        #[test]
        fn crdt_commutative(a in any_set(), b in any_set()) {
            prop_assert_eq!(a.join(&b), b.join(&a));
        }

        /// Associative: join(join(a, b), c) == join(a, join(b, c)).
        #[test]
        fn crdt_associative(a in any_set(), b in any_set(), c in any_set()) {
            let left = a.join(&b).join(&c);
            let right = a.join(&b.join(&c));
            prop_assert_eq!(left, right);
        }

        /// Idempotent: join(a, a) == a. This is what [`CreditFile::merge`] is NOT,
        /// and the whole reason the set exists.
        #[test]
        fn crdt_idempotent(a in any_set()) {
            prop_assert_eq!(a.join(&a), a);
        }

        /// Identity: join(a, ∅) == a == join(∅, a).
        #[test]
        fn crdt_identity(a in any_set()) {
            prop_assert_eq!(a.join(&ReputationSet::new()), a.clone());
            prop_assert_eq!(ReputationSet::new().join(&a), a);
        }
    }

    // ── Convergence / determinism (strong eventual consistency) ───────────────

    proptest! {
        /// The load-bearing property: reputation is invariant under permutation
        /// AND duplication of the same event multiset. Gossip reorders and
        /// re-delivers; the answer must not move.
        #[test]
        fn reputation_invariant_under_permutation_and_duplication(
            evs in proptest::collection::vec(any_event(), 0..24),
            seed in any::<u64>(),
        ) {
            let baseline = set_from(&evs).reputation_micro();

            // Permute (rotate + reverse) and re-deliver every event twice.
            let mut gossip = evs.clone();
            if !gossip.is_empty() {
                let k = (seed as usize) % gossip.len();
                gossip.rotate_left(k);
                gossip.reverse();
            }
            gossip.extend(evs.clone()); // duplicates

            prop_assert_eq!(baseline, set_from(&gossip).reputation_micro());
        }

        /// Three replicas receive the same events in different orders (and one
        /// with duplicates), then pairwise-join. All converge to one set and one
        /// reputation — strong eventual consistency.
        #[test]
        fn replicas_converge(evs in proptest::collection::vec(any_event(), 0..16)) {
            let r1 = set_from(&evs);

            let mut rev = evs.clone();
            rev.reverse();
            let r2 = set_from(&rev);

            let mut dup = evs.clone();
            dup.extend(evs.clone()); // a replica that saw everything twice
            let r3 = set_from(&dup);

            // Same membership ⇒ same set ⇒ same reputation, before any join.
            prop_assert_eq!(&r1, &r2);
            prop_assert_eq!(&r1, &r3);
            prop_assert_eq!(r1.reputation_micro(), r2.reputation_micro());
            prop_assert_eq!(r2.reputation_micro(), r3.reputation_micro());

            // And joining in any grouping is the same fixed point.
            prop_assert_eq!(r1.join(&r2).join(&r3), r1.clone());
        }

        /// Monotone flywheel survives into the set: admitting an honest
        /// settlement never lowers reputation; a caught defection never raises it.
        #[test]
        fn monotone_flywheel(a in any_set(), weight in 0u64..2_000_000) {
            let before = a.reputation_micro();

            // Use keys `any_event` can never produce (bytes 8/9 ∈ {0,1} there),
            // so these are guaranteed-fresh additions, not overwrites.
            let up_key = [0xFFu8; 32];
            let down_key = [0xFEu8; 32];

            let mut up = a.clone();
            up.events.insert(up_key, CreditEvent::honest_settlement(weight, up_key));
            prop_assert!(up.reputation_micro() >= before);

            let mut down = a.clone();
            down.events.insert(down_key, CreditEvent::caught_defection(weight, down_key));
            prop_assert!(down.reputation_micro() <= before);
        }
    }

    // ── Worked examples + fail-closed join ────────────────────────────────────

    #[test]
    fn empty_set_is_identity_and_zero() {
        let a = ReputationSet::new();
        assert_eq!(a.join(&ReputationSet::new()), ReputationSet::new());
        assert_eq!(a.reputation_micro(), 0);
        assert!(a.is_empty());
        assert_eq!(a.event_count(), 0);
    }

    #[test]
    fn join_unions_distinct_events() {
        let e1 = CreditEvent::honest_settlement(100_000, [1u8; 32]);
        let e2 = CreditEvent::caught_defection(50_000, [2u8; 32]);
        let merged = set_from(&[e1]).join(&set_from(&[e2]));
        assert_eq!(merged.len(), 2);
        // 100k credit − 50k debit on the financial dimension.
        assert_eq!(merged.reputation_micro(), 50_000);
    }

    #[test]
    fn duplicate_key_equal_value_is_silent() {
        let e = CreditEvent::honest_settlement(100_000, [1u8; 32]);
        let merged = set_from(&[e]).join(&set_from(&[e]));
        assert_eq!(merged.len(), 1);
        assert_eq!(merged.reputation_micro(), 100_000);
    }

    #[test]
    #[should_panic(expected = "CRDT invariant violation")]
    fn duplicate_key_unequal_value_fails_closed() {
        // Same receipt_hash, different weight — a forged/tampered event in gossip.
        let honest = CreditEvent::honest_settlement(100_000, [7u8; 32]);
        let forged = CreditEvent::honest_settlement(200_000, [7u8; 32]);
        let _ = set_from(&[honest]).join(&set_from(&[forged]));
    }

    #[test]
    fn credit_file_reconstruction_is_deterministic() {
        let evs = [
            CreditEvent::honest_settlement(400_000, [1u8; 32]),
            CreditEvent::caught_defection(100_000, [2u8; 32]),
            CreditEvent::externality_internalized(300_000, [3u8; 32]),
        ];
        let file = set_from(&evs).credit_file();
        // (400k − 100k) financial + 300k externality = 600k.
        assert_eq!(file.reputation_micro(), 600_000);
        assert_eq!(file.event_count(), 3);
    }

    // ── Exhaustive small CRDT-law check (belt-and-braces, deterministic) ──────

    /// A tiny fixed alphabet of events over three receipt_hashes (two of which
    /// share a hash with differing values, to keep the universe consistent we
    /// pick distinct hashes per distinct value). Exhaustively checks the three
    /// semilattice laws over all subsets — a deterministic complement to the
    /// randomized proptests.
    #[test]
    fn exhaustive_small_semilattice_laws() {
        let universe = [
            CreditEvent::honest_settlement(10, [1u8; 32]),
            CreditEvent::caught_defection(20, [2u8; 32]),
            CreditEvent::externality_internalized(30, [3u8; 32]),
            CreditEvent::externality_dumped(40, [4u8; 32]),
        ];
        // All 16 subsets as sets.
        let subsets: Vec<ReputationSet> = (0u8..16)
            .map(|mask| {
                let chosen: Vec<CreditEvent> = universe
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| mask & (1 << i) != 0)
                    .map(|(_, e)| *e)
                    .collect();
                set_from(&chosen)
            })
            .collect();

        for a in &subsets {
            // Idempotent.
            assert_eq!(&a.join(a), a);
            // Identity.
            assert_eq!(&a.join(&ReputationSet::new()), a);
            for b in &subsets {
                // Commutative.
                assert_eq!(a.join(b), b.join(a));
                for c in &subsets {
                    // Associative.
                    assert_eq!(a.join(b).join(c), a.join(&b.join(c)));
                }
            }
        }
    }
}

// ── Recompute-gated admission tests ──────────────────────────────────────────

#[cfg(all(test, feature = "recompute"))]
mod recompute_tests {
    use super::*;
    use nucleus_econ_kernels::{classify, refund, route_to_commons, seller_gross, CommonsShare};
    use nucleus_recompute::{ClearingReceipt, CommonsClaim, SettlementClaim};

    /// A genuinely-honest settlement receipt (outputs computed by the same proven
    /// kernels recompute checks against, so the Match is real).
    fn honest_settlement(price_micro: u64, delivered_bps: u64) -> ClearingReceipt {
        ClearingReceipt::Settlement(SettlementClaim {
            price_micro,
            delivered_bps,
            verdict: classify(delivered_bps),
            seller_gross: seller_gross(price_micro, delivered_bps),
            refund: refund(price_micro, delivered_bps),
        })
    }

    fn honest_commons(pool_micro: u64) -> ClearingReceipt {
        let shares = vec![CommonsShare {
            destination: "commons".into(),
            bps: 10_000,
        }];
        let allocations = route_to_commons(pool_micro, &shares).unwrap();
        ClearingReceipt::Commons(CommonsClaim {
            pool_micro,
            shares,
            allocations,
        })
    }

    #[test]
    fn verified_insert_admits_honest_settlement() {
        let r = honest_settlement(500_000, 10_000);
        let mut set = ReputationSet::new();
        assert!(set.verified_insert(&r));
        assert_eq!(set.len(), 1);
        assert_eq!(set.reputation_micro(), 500_000);
    }

    #[test]
    fn verified_insert_admits_caught_defection_as_debit() {
        let mut r = honest_settlement(500_000, 10_000);
        if let ClearingReceipt::Settlement(ref mut c) = r {
            c.seller_gross += 1; // tamper ⇒ recompute Mismatch
        }
        let mut set = ReputationSet::new();
        // A defection is still admitted — it mints a debit that burns standing.
        assert!(set.verified_insert(&r));
        assert_eq!(set.len(), 1);
        // 500k debit, no credit ⇒ floored at 0.
        assert_eq!(set.reputation_micro(), 0);
    }

    #[test]
    fn verified_insert_rejects_invalid_receipt() {
        // Commons shares not summing to 10_000 ⇒ Invalid ⇒ nothing minted.
        let invalid = ClearingReceipt::Commons(CommonsClaim {
            pool_micro: 1_000,
            shares: vec![CommonsShare {
                destination: "x".into(),
                bps: 9_999,
            }],
            allocations: vec![],
        });
        let mut set = ReputationSet::new();
        assert!(!set.verified_insert(&invalid));
        assert!(set.is_empty());
        assert_eq!(set.reputation_micro(), 0);
    }

    #[test]
    fn verified_insert_is_idempotent() {
        let r = honest_settlement(500_000, 10_000);
        let mut set = ReputationSet::new();
        assert!(set.verified_insert(&r));
        let rep1 = set.reputation_micro();
        assert!(set.verified_insert(&r)); // same receipt again
        assert_eq!(set.reputation_micro(), rep1);
        assert_eq!(set.len(), 1); // still one event
    }

    #[test]
    fn verified_admit_accepts_a_matching_claim() {
        let r = honest_settlement(500_000, 10_000);
        let honest_claim = crate::mint::mint_event(&r).unwrap();
        let mut set = ReputationSet::new();
        assert!(set.verified_admit(&honest_claim, &r));
        assert_eq!(set.len(), 1);
        assert_eq!(set.reputation_micro(), 500_000);
    }

    #[test]
    fn verified_admit_rejects_a_forged_claim() {
        // The receipt is a caught defection (recomputes to a DEBIT), but the
        // gossiped claim lies that it was an honest settlement CREDIT.
        let mut r = honest_settlement(500_000, 10_000);
        if let ClearingReceipt::Settlement(ref mut c) = r {
            c.seller_gross += 1;
        }
        let forged_claim = CreditEvent::honest_settlement(500_000, crate::mint::receipt_hash(&r));
        let mut set = ReputationSet::new();
        // The recompute mints a debit, not the claimed credit ⇒ refused.
        assert!(!set.verified_admit(&forged_claim, &r));
        assert!(set.is_empty());
    }

    #[test]
    fn verified_admit_rejects_claim_backed_by_invalid_receipt() {
        // A claim with no recomputing receipt (Invalid ⇒ no mint) never joins.
        let invalid = ClearingReceipt::Commons(CommonsClaim {
            pool_micro: 1_000,
            shares: vec![CommonsShare {
                destination: "x".into(),
                bps: 9_999,
            }],
            allocations: vec![],
        });
        let forged_claim =
            CreditEvent::externality_internalized(1_000, crate::mint::receipt_hash(&invalid));
        let mut set = ReputationSet::new();
        assert!(!set.verified_admit(&forged_claim, &invalid));
        assert!(set.is_empty());
    }

    #[test]
    fn multi_replica_verified_inserts_converge() {
        let r1 = honest_settlement(400_000, 10_000);
        let r2 = honest_commons(300_000);

        let mut a = ReputationSet::new();
        a.verified_insert(&r1);
        a.verified_insert(&r2);

        let mut b = ReputationSet::new();
        b.verified_insert(&r2); // different order
        b.verified_insert(&r1);
        b.verified_insert(&r1); // and a duplicate delivery

        assert_eq!(a, b);
        assert_eq!(a.reputation_micro(), b.reputation_micro());
        assert_eq!(a.reputation_micro(), 700_000); // 400k financial + 300k externality

        // Joining the two replicas is the same fixed point.
        let merged = a.join(&b);
        assert_eq!(merged.reputation_micro(), 700_000);
        assert_eq!(merged.len(), 2);
    }
}
