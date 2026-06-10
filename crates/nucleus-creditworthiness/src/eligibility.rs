//! Airdrop **optionality** math — a pure, deterministic, recomputable projection
//! of an identity's recompute-verified track record into a HYPOTHETICAL
//! basis-point [`Allocation`].
//!
//! # What this IS
//!
//! A pure function ([`eligibility_snapshot`]) over the EXISTING recompute-gated
//! credit hash chain ([`crate::ledger::LedgerEntry`]). For each identity it folds
//! the [`CreditEvent`](crate::CreditEvent)s already sealed on the append-only
//! chain into a single net **eligibility weight** (credits minus debits, floored
//! at zero, optionally per-dimension-weighted, and time-rooted so earlier
//! verified contribution roots a larger share). Eligible identities' weights are
//! then normalized to integer basis points (summing to at most `10_000`) by exact
//! largest-remainder apportionment — the same deterministic integer discipline as
//! the Shapley split elsewhere in the substrate. Anyone can recompute the
//! identical [`Allocation`] in the browser over the public chain (this module is
//! WASM-pure: integer-only, no `std`-only or native dependencies beyond what
//! `ledger.rs` already pulls in).
//!
//! It makes the statement *"early verifiable contribution MAY be recognized
//! later"* **credible via recomputable math** — nothing more.
//!
//! # What this IS NOT — read this before reasoning about it as value
//!
//! This is **NOT a token**. It is **NOT a transferable balance**. It is **NOT a
//! security**. It is **NOT for sale**. It is **NOT a promise, right, or claim** to
//! any future distribution of anything. An [`Allocation`] **confers nothing**: it
//! is identity-bound, **non-transferable**, consumptive / reputational standing
//! only. There is deliberately **no transfer / move / mint API** on
//! [`Allocation`] — it is a plain, read-only data structure (`identity -> bps`).
//!
//! The basis points are **abstract units** (math, not money). No price, no
//! appreciation, no profit, no distribution is promised or implied anywhere. The
//! *exercise* of any optionality — any actual distribution of value, any
//! transferable token, any on-chain mint, any sale — is an explicit,
//! securities-counsel-gated **one-way door that is OUT OF SCOPE here and is NOT
//! built**. This module builds ONLY the optionality math.
//!
//! # Why the math is the anti-farming guarantee
//!
//! Eligibility derives ONLY from recompute-gated [`CreditEvent`]s already on the
//! append-only chain — there is **no new accrual path**. The economic magnitude
//! (`weight_micro`) of every event was already recompute-verified from DECLARED
//! inputs (so it cannot be inflated by the very lie that the recompute catches),
//! and a [`SnapshotParams::min_distinct_receipts`] **Sybil-floor** requires an
//! identity to carry at least that many *distinct* receipt hashes before it is
//! eligible at all — one replayed receipt cannot farm standing. Greed is therefore
//! satisfiable ONLY by doing real, recompute-verified work: greed pulls agents in,
//! proof keeps them honest.
//!
//! # Honesty boundary (TCB / do NOT overclaim)
//!
//! This is a **recomputable projection** over already-verified events, not a
//! guarantee of anything. Garbage events in, garbage projection out — feed it only
//! chains whose entries were minted from receipts that already recomputed (see
//! [`crate::mint`]) and verified with [`crate::ledger::verify_chain`]. This module
//! does the *projection*; it does not itself verify receipts or chains. The chain
//! is tamper-EVIDENT, not a non-equivocating transparency log (see the
//! [`crate::ledger`] honesty boundary). The time-rooting curve and per-dimension
//! weights are governed parameters, not theorems: they shape *which* recomputable
//! projection is taken, and the projection is reproducible byte-for-byte given the
//! same chain and the same [`SnapshotParams`].

use crate::{CreditDimension, Polarity};

use crate::ledger::LedgerEntry;
use std::collections::{BTreeMap, BTreeSet};

/// The number of basis points in a whole (100% = `10_000` bps). An
/// [`Allocation`] sums to at most this value.
pub const BPS_DENOMINATOR: u32 = 10_000;

/// Per-dimension multiplier applied to an event's `weight_micro` before it is
/// summed into the eligibility weight. Fixed-point: the multiplier is
/// `numer / DIM_WEIGHT_DENOM`, so `DIM_WEIGHT_DENOM` itself means "×1".
///
/// Integer fixed-point keeps the whole computation deterministic and WASM-pure;
/// there is no floating point anywhere in this module.
pub const DIM_WEIGHT_DENOM: u64 = 1_000;

/// Parameters that pin down *which* recomputable projection [`eligibility_snapshot`]
/// takes. The snapshot is a pure function of `(chains, params)`: the same inputs
/// always yield the identical [`Allocation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotParams {
    /// Sybil-floor: an identity is eligible only if its chain carries at least
    /// this many **distinct** recompute receipt hashes. `1` admits any identity
    /// with a single verified receipt; raising it makes one-replayed-receipt
    /// farming impossible. A value of `0` is treated as `1` (a non-empty,
    /// recompute-verified history is always required — empty never qualifies).
    pub min_distinct_receipts: u32,

    /// Per-dimension fixed-point multiplier (`numer / DIM_WEIGHT_DENOM`) applied
    /// to each event's `weight_micro`. A dimension absent from this map defaults
    /// to `DIM_WEIGHT_DENOM` (×1). Lets governance weight, e.g., externality
    /// internalization differently from financial settlement when projecting
    /// standing — without changing how the events themselves were verified.
    pub dimension_weight: BTreeMap<CreditDimension, u64>,

    /// Time-rooting half-life, in chain positions (`seq`). The event at the head
    /// of the curve (the earliest *eligible-relative* position, see below) gets
    /// full weight; an event `half_life` positions later gets ~half; `2 *
    /// half_life` later ~a quarter; and so on. `0` disables time-rooting (every
    /// position weighted equally). Earlier verified contribution — the
    /// time-scarce, backdated-unforgeable track record — therefore roots a
    /// larger share.
    pub time_root_half_life: u64,
}

impl Default for SnapshotParams {
    /// A conservative default: require 2 distinct receipts (kills the cheapest
    /// single-receipt-replay Sybil), weight every dimension ×1, and root time at
    /// a 64-position half-life.
    fn default() -> Self {
        Self {
            min_distinct_receipts: 2,
            dimension_weight: BTreeMap::new(),
            time_root_half_life: 64,
        }
    }
}

impl SnapshotParams {
    /// The effective Sybil-floor (`min_distinct_receipts`, but never below 1: an
    /// empty / zero-receipt identity is never eligible).
    fn effective_floor(&self) -> u32 {
        self.min_distinct_receipts.max(1)
    }

    /// The fixed-point dimension multiplier for `dim` (defaults to ×1).
    fn dim_mult(&self, dim: CreditDimension) -> u64 {
        self.dimension_weight
            .get(&dim)
            .copied()
            .unwrap_or(DIM_WEIGHT_DENOM)
    }
}

/// A HYPOTHETICAL, NON-TRANSFERABLE allocation of abstract basis points across
/// identities.
///
/// # NOT a token — read [the module docs](self)
///
/// This is a plain, read-only mapping `identity -> bps`. It is **not** a token,
/// **not** a transferable balance, **not** a security, **not** for sale, and
/// confers **no right, claim, or promise** to any distribution of value. There is
/// deliberately no transfer / move / mint method. The basis points are abstract
/// math (sum ≤ [`BPS_DENOMINATOR`]); they are a recomputable projection of
/// recompute-verified standing, nothing more.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allocation {
    /// Eligible identity → basis points. Identities below the Sybil-floor, or
    /// with zero net eligibility weight, are absent (not present with `0`), so
    /// the structure is canonical regardless of input order. `BTreeMap` keeps the
    /// iteration order deterministic for any consumer.
    bps: BTreeMap<String, u32>,
}

impl Allocation {
    /// Basis points apportioned to `identity` (`0` if absent / ineligible).
    pub fn bps_of(&self, identity: &str) -> u32 {
        self.bps.get(identity).copied().unwrap_or(0)
    }

    /// Iterate `(identity, bps)` in deterministic (sorted-by-identity) order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, u32)> {
        self.bps.iter().map(|(k, v)| (k.as_str(), *v))
    }

    /// Number of eligible identities (those with non-zero bps).
    pub fn len(&self) -> usize {
        self.bps.len()
    }

    /// Whether no identity is eligible (e.g. empty / all-debit / all below the
    /// Sybil-floor input).
    pub fn is_empty(&self) -> bool {
        self.bps.is_empty()
    }

    /// Total apportioned basis points (≤ [`BPS_DENOMINATOR`]). Less than the full
    /// denominator only when there are zero eligible identities (then it is `0`).
    pub fn total_bps(&self) -> u32 {
        self.bps.values().copied().sum()
    }
}

/// Saturating fixed-point product `weight_micro * (mult / DIM_WEIGHT_DENOM)`,
/// in `u128` to keep headroom; saturates rather than wrapping.
fn apply_dim_weight(weight_micro: u64, mult: u64) -> u128 {
    (u128::from(weight_micro)).saturating_mul(u128::from(mult)) / u128::from(DIM_WEIGHT_DENOM)
}

/// The integer time-rooting factor for an event at relative position `rel`
/// (0 = earliest eligible position) given `half_life`, as a fixed-point value
/// over [`DIM_WEIGHT_DENOM`].
///
/// Non-increasing in `rel`: `factor(0) = DIM_WEIGHT_DENOM` (×1) and it halves
/// every `half_life` positions via integer right-shifts plus a linear
/// interpolation within a half-life window. `half_life == 0` returns
/// `DIM_WEIGHT_DENOM` for every position (time-rooting disabled). Pure integer
/// math — identical on every platform, including wasm32.
fn time_root_factor(rel: u64, half_life: u64) -> u128 {
    if half_life == 0 {
        return u128::from(DIM_WEIGHT_DENOM);
    }
    let full_halvings = rel / half_life;
    let within = rel % half_life;
    // Base after `full_halvings` halvings: DENOM >> full_halvings (saturates to 0
    // once we've shifted past the integer precision — deep-history events
    // contribute a vanishing, non-negative share, never a larger one).
    let base = if full_halvings >= 64 {
        0u128
    } else {
        u128::from(DIM_WEIGHT_DENOM) >> full_halvings
    };
    if base == 0 {
        return 0;
    }
    // Linearly interpolate down toward base/2 across the current half-life
    // window, so the factor is monotone non-increasing *within* a window too
    // (not a step function). step = (base - base/2) * within / half_life.
    let next = base >> 1;
    let span = base - next;
    let dec = span.saturating_mul(u128::from(within)) / u128::from(half_life);
    base - dec
}

/// One identity's raw, pre-normalization eligibility computation.
struct RawStanding {
    /// Net eligibility weight (credits − debits, floored at 0), after
    /// per-dimension and time-rooting weighting.
    weight: u128,
    /// Count of DISTINCT recompute receipt hashes seen on the chain.
    distinct_receipts: usize,
}

/// Fold one identity's contiguous, `seq`-ordered chain into its raw standing.
///
/// `entries` MUST be that identity's chain in `seq` order (as produced and
/// verified by [`crate::ledger`]); the relative position used for time-rooting is
/// the index within the supplied slice, so the **earliest** entry is rooted
/// strongest. Distinct receipt hashes are counted for the Sybil-floor.
fn fold_identity(entries: &[LedgerEntry], params: &SnapshotParams) -> RawStanding {
    let mut receipts: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut credit: u128 = 0;
    let mut debit: u128 = 0;
    for (rel, entry) in entries.iter().enumerate() {
        let ev = &entry.event;
        receipts.insert(ev.receipt_hash);
        let dim_weighted = apply_dim_weight(ev.weight_micro, params.dim_mult(ev.dimension));
        let factor = time_root_factor(rel as u64, params.time_root_half_life);
        // weighted = dim_weighted * factor / DENOM (fixed-point), saturating.
        let weighted = dim_weighted.saturating_mul(factor) / u128::from(DIM_WEIGHT_DENOM);
        match ev.polarity {
            Polarity::Credit => credit = credit.saturating_add(weighted),
            Polarity::Debit => debit = debit.saturating_add(weighted),
        }
    }
    RawStanding {
        weight: credit.saturating_sub(debit),
        distinct_receipts: receipts.len(),
    }
}

/// Compute the HYPOTHETICAL, non-transferable basis-point [`Allocation`] over a
/// set of identities' recompute-verified credit chains.
///
/// `identities` pairs each identity key with **its own** contiguous, `seq`-ordered
/// [`crate::ledger::LedgerEntry`] chain (the same chains [`crate::ledger::verify_chain`]
/// validates). For each identity this:
///
/// 1. counts DISTINCT receipt hashes and drops the identity if it carries fewer
///    than the [`SnapshotParams`] Sybil-floor (one replayed receipt can't farm
///    standing);
/// 2. folds its events into a net eligibility weight = Σ(credit) − Σ(debit),
///    floored at 0, with each event scaled by its per-dimension multiplier and a
///    non-increasing time-rooting factor (earlier verified contribution roots a
///    larger share);
/// 3. drops identities whose net weight is 0 (all-debit / empty);
/// 4. normalizes the surviving weights to exact integer basis points
///    (sum ≤ [`BPS_DENOMINATOR`]) via largest-remainder apportionment.
///
/// The result is a **pure function** of `(identities, params)` and is invariant to
/// the order in which identities are supplied — any verifier recomputes the
/// identical [`Allocation`] from the same public chains.
///
/// # This is NOT a token / not a security / not for sale
///
/// See [the module docs](self): the returned [`Allocation`] confers no right,
/// claim, or promise; it is non-transferable, abstract-unit standing only.
pub fn eligibility_snapshot(
    identities: &[(&str, &[LedgerEntry])],
    params: &SnapshotParams,
) -> Allocation {
    let floor = params.effective_floor() as usize;

    // Collect eligible (identity, raw weight) in deterministic key order so the
    // apportionment tie-breaking is itself order-independent. Dedup by identity
    // key: if the same key appears twice, the later slice replaces the earlier
    // (callers should pass one chain per identity; this keeps the fn total).
    let mut eligible: BTreeMap<String, u128> = BTreeMap::new();
    for (id, entries) in identities {
        let raw = fold_identity(entries, params);
        if raw.distinct_receipts < floor {
            continue; // below Sybil-floor
        }
        if raw.weight == 0 {
            continue; // all-debit / empty net standing
        }
        eligible.insert((*id).to_string(), raw.weight);
    }

    apportion_bps(&eligible)
}

/// Largest-remainder (Hamilton) apportionment of `weights` into integer basis
/// points summing to exactly [`BPS_DENOMINATOR`] (or `0` when there are no
/// eligible identities / total weight is 0). Deterministic: remainders tie-break
/// by descending remainder then ascending identity key, so the result is a pure
/// function of the `(identity -> weight)` map.
fn apportion_bps(weights: &BTreeMap<String, u128>) -> Allocation {
    let total: u128 = weights
        .values()
        .copied()
        .fold(0u128, |a, w| a.saturating_add(w));
    if total == 0 || weights.is_empty() {
        return Allocation::default();
    }

    let denom = u128::from(BPS_DENOMINATOR);

    // Floor share + fractional remainder for each identity.
    struct Share {
        id: String,
        floor_bps: u32,
        // remainder numerator = (weight * denom) mod total, in [0, total).
        rem: u128,
    }
    let mut shares: Vec<Share> = Vec::with_capacity(weights.len());
    let mut allocated: u32 = 0;
    for (id, &w) in weights {
        let scaled = w.saturating_mul(denom);
        let floor_bps = (scaled / total) as u32;
        let rem = scaled % total;
        allocated = allocated.saturating_add(floor_bps);
        shares.push(Share {
            id: id.clone(),
            floor_bps,
            rem,
        });
    }

    // Distribute the leftover bps (denominator − allocated) one each to the
    // largest remainders. Tie-break: larger remainder first, then smaller
    // identity key (BTreeMap already gave us ascending key order; a stable sort
    // by descending remainder preserves that as the secondary key).
    let mut leftover = BPS_DENOMINATOR.saturating_sub(allocated);
    let mut order: Vec<usize> = (0..shares.len()).collect();
    order.sort_by(|&a, &b| {
        shares[b]
            .rem
            .cmp(&shares[a].rem)
            .then_with(|| shares[a].id.cmp(&shares[b].id))
    });
    for &i in &order {
        if leftover == 0 {
            break;
        }
        shares[i].floor_bps = shares[i].floor_bps.saturating_add(1);
        leftover -= 1;
    }

    let mut bps = BTreeMap::new();
    for s in shares {
        if s.floor_bps > 0 {
            bps.insert(s.id, s.floor_bps);
        }
    }
    Allocation { bps }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CreditEvent;
    use proptest::prelude::*;

    fn rh(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    /// Build a well-formed `seq`-ordered chain for `id` from `(event)` list,
    /// linking each entry to its predecessor exactly as the ledger does.
    fn chain(id: &str, events: &[CreditEvent]) -> Vec<LedgerEntry> {
        let mut out: Vec<LedgerEntry> = Vec::new();
        for (seq, ev) in events.iter().enumerate() {
            let prev = out.last().map(|e| e.this_hash);
            out.push(LedgerEntry::new(
                id.to_string(),
                seq as u64,
                *ev,
                100 + seq as i64,
                prev,
            ));
        }
        out
    }

    /// Params with time-rooting disabled (so raw weights are easy to reason
    /// about) and a Sybil-floor of 1.
    fn flat_params(min_distinct: u32) -> SnapshotParams {
        SnapshotParams {
            min_distinct_receipts: min_distinct,
            dimension_weight: BTreeMap::new(),
            time_root_half_life: 0,
        }
    }

    // ── Worked examples ─────────────────────────────────────────────────────

    #[test]
    fn empty_input_is_empty_allocation() {
        let alloc = eligibility_snapshot(&[], &SnapshotParams::default());
        assert!(alloc.is_empty());
        assert_eq!(alloc.total_bps(), 0);
    }

    #[test]
    fn all_debit_identity_is_not_eligible() {
        let a = chain(
            "a",
            &[
                CreditEvent::caught_defection(500, rh(1)),
                CreditEvent::caught_defection(500, rh(2)),
            ],
        );
        let alloc = eligibility_snapshot(&[("a", &a)], &flat_params(1));
        assert!(alloc.is_empty());
        assert_eq!(alloc.bps_of("a"), 0);
    }

    #[test]
    fn single_eligible_identity_gets_full_allocation() {
        let a = chain(
            "a",
            &[
                CreditEvent::honest_settlement(1000, rh(1)),
                CreditEvent::honest_settlement(1000, rh(2)),
            ],
        );
        let alloc = eligibility_snapshot(&[("a", &a)], &flat_params(1));
        assert_eq!(alloc.bps_of("a"), BPS_DENOMINATOR);
        assert_eq!(alloc.total_bps(), BPS_DENOMINATOR);
    }

    #[test]
    fn two_equal_identities_split_evenly() {
        let a = chain(
            "a",
            &[
                CreditEvent::honest_settlement(1000, rh(1)),
                CreditEvent::honest_settlement(1000, rh(2)),
            ],
        );
        let b = chain(
            "b",
            &[
                CreditEvent::honest_settlement(1000, rh(3)),
                CreditEvent::honest_settlement(1000, rh(4)),
            ],
        );
        let alloc = eligibility_snapshot(&[("a", &a), ("b", &b)], &flat_params(1));
        assert_eq!(alloc.bps_of("a"), 5000);
        assert_eq!(alloc.bps_of("b"), 5000);
        assert_eq!(alloc.total_bps(), BPS_DENOMINATOR);
    }

    #[test]
    fn sybil_floor_excludes_single_distinct_receipt() {
        // Two events but the SAME receipt hash replayed → 1 distinct receipt.
        let a = chain(
            "a",
            &[
                CreditEvent::honest_settlement(1000, rh(7)),
                CreditEvent::honest_settlement(1000, rh(7)),
            ],
        );
        // floor=2 excludes it; floor=1 admits it.
        let excluded = eligibility_snapshot(&[("a", &a)], &flat_params(2));
        assert!(excluded.is_empty());
        let admitted = eligibility_snapshot(&[("a", &a)], &flat_params(1));
        assert_eq!(admitted.bps_of("a"), BPS_DENOMINATOR);
    }

    #[test]
    fn debit_reduces_eligibility_share() {
        // a has a debit eating into its credit; b is clean. b should get more.
        let a = chain(
            "a",
            &[
                CreditEvent::honest_settlement(1000, rh(1)),
                CreditEvent::caught_defection(800, rh(2)),
            ],
        );
        let b = chain(
            "b",
            &[
                CreditEvent::honest_settlement(1000, rh(3)),
                CreditEvent::honest_settlement(0, rh(4)),
            ],
        );
        let alloc = eligibility_snapshot(&[("a", &a), ("b", &b)], &flat_params(1));
        // a net = 200, b net = 1000 → b > a.
        assert!(alloc.bps_of("b") > alloc.bps_of("a"));
        assert_eq!(alloc.total_bps(), BPS_DENOMINATOR);
    }

    #[test]
    fn time_rooting_favors_earlier_contribution() {
        // Same total credit, but identity `early` did its work at the head of the
        // chain (positions 0..) and `late` padded the head with tiny events so its
        // big credit lands at a later position. With time-rooting on, `early`'s
        // big early credit should root a strictly larger share.
        let early = chain(
            "early",
            &[
                CreditEvent::honest_settlement(1_000_000, rh(1)),
                CreditEvent::honest_settlement(1, rh(2)),
            ],
        );
        let late = chain(
            "late",
            &[
                CreditEvent::honest_settlement(1, rh(3)),
                CreditEvent::honest_settlement(1_000_000, rh(4)),
            ],
        );
        let params = SnapshotParams {
            min_distinct_receipts: 1,
            dimension_weight: BTreeMap::new(),
            time_root_half_life: 1, // aggressive decay so position matters a lot
        };
        let alloc = eligibility_snapshot(&[("early", &early), ("late", &late)], &params);
        assert!(
            alloc.bps_of("early") > alloc.bps_of("late"),
            "early={} late={}",
            alloc.bps_of("early"),
            alloc.bps_of("late")
        );
    }

    #[test]
    fn dimension_weight_scales_contribution() {
        // Weight externality at 2x; an externality-credit identity then outranks
        // an otherwise-equal financial-credit identity.
        let fin = chain(
            "fin",
            &[
                CreditEvent::honest_settlement(1000, rh(1)),
                CreditEvent::honest_settlement(1000, rh(2)),
            ],
        );
        let ext = chain(
            "ext",
            &[
                CreditEvent::externality_internalized(1000, rh(3)),
                CreditEvent::externality_internalized(1000, rh(4)),
            ],
        );
        let mut dim = BTreeMap::new();
        dim.insert(CreditDimension::Externality, 2 * DIM_WEIGHT_DENOM); // 2x
        let params = SnapshotParams {
            min_distinct_receipts: 1,
            dimension_weight: dim,
            time_root_half_life: 0,
        };
        let alloc = eligibility_snapshot(&[("fin", &fin), ("ext", &ext)], &params);
        assert!(alloc.bps_of("ext") > alloc.bps_of("fin"));
    }

    #[test]
    fn allocation_has_no_transfer_api() {
        // Compile-time documentation: Allocation exposes only read accessors.
        // (If a transfer/move/mint method were ever added, this test's intent —
        // and the module's Howey-clean contract — would be violated.)
        let a = chain(
            "a",
            &[
                CreditEvent::honest_settlement(1, rh(1)),
                CreditEvent::honest_settlement(1, rh(2)),
            ],
        );
        let alloc = eligibility_snapshot(&[("a", &a)], &flat_params(1));
        let _ = alloc.bps_of("a");
        let _ = alloc.iter().count();
        let _ = alloc.total_bps();
        let _ = alloc.len();
        let _ = alloc.is_empty();
    }

    // ── Property tests ───────────────────────────────────────────────────────

    prop_compose! {
        fn any_event()(
            dim_sel in 0usize..2,
            pol in any::<bool>(),
            weight in 0u64..1_000_000,
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
        proptest::collection::vec(any_event(), 0..16)
    }

    /// A small set of identities, each with its own event list.
    fn identity_events() -> impl Strategy<Value = Vec<(String, Vec<CreditEvent>)>> {
        proptest::collection::vec(("[a-e]{1,3}", events()), 0..6)
    }

    proptest! {
        /// Determinism: same input → byte-identical Allocation.
        #[test]
        fn deterministic(ids in identity_events()) {
            let chains: Vec<(String, Vec<LedgerEntry>)> =
                ids.iter().map(|(id, evs)| (id.clone(), chain(id, evs))).collect();
            let refs: Vec<(&str, &[LedgerEntry])> =
                chains.iter().map(|(id, c)| (id.as_str(), c.as_slice())).collect();
            let p = SnapshotParams::default();
            let a1 = eligibility_snapshot(&refs, &p);
            let a2 = eligibility_snapshot(&refs, &p);
            prop_assert_eq!(a1, a2);
        }

        /// Permutation-invariance: shuffling the identity order yields an equal
        /// Allocation. (Dedup by key, so we use distinct identity keys.)
        #[test]
        fn permutation_invariant(n in 0usize..6, seed in any::<u64>()) {
            // Build n identities with distinct keys and fixed deterministic chains.
            let mut chains: Vec<(String, Vec<LedgerEntry>)> = Vec::new();
            for i in 0..n {
                let id = format!("id{i}");
                let evs = vec![
                    CreditEvent::honest_settlement(100 * (i as u64 + 1), rh(i as u8)),
                    CreditEvent::honest_settlement(50, rh((i as u8).wrapping_add(100))),
                ];
                chains.push((id.clone(), chain(&id, &evs)));
            }
            let refs: Vec<(&str, &[LedgerEntry])> =
                chains.iter().map(|(id, c)| (id.as_str(), c.as_slice())).collect();
            let p = SnapshotParams::default();
            let base = eligibility_snapshot(&refs, &p);

            // Deterministic shuffle: rotate + reverse.
            let mut shuffled = refs.clone();
            if !shuffled.is_empty() {
                let k = (seed as usize) % shuffled.len();
                shuffled.rotate_left(k);
                shuffled.reverse();
            }
            let shuf = eligibility_snapshot(&shuffled, &p);
            prop_assert_eq!(base, shuf);
        }

        /// Normalization: total bps is always ≤ BPS_DENOMINATOR, and equals it
        /// whenever at least one identity is eligible.
        #[test]
        fn normalization_sums_to_denominator_or_zero(ids in identity_events()) {
            let chains: Vec<(String, Vec<LedgerEntry>)> =
                ids.iter().map(|(id, evs)| (id.clone(), chain(id, evs))).collect();
            let refs: Vec<(&str, &[LedgerEntry])> =
                chains.iter().map(|(id, c)| (id.as_str(), c.as_slice())).collect();
            let alloc = eligibility_snapshot(&refs, &SnapshotParams::default());
            prop_assert!(alloc.total_bps() <= BPS_DENOMINATOR);
            if !alloc.is_empty() {
                prop_assert_eq!(alloc.total_bps(), BPS_DENOMINATOR);
            } else {
                prop_assert_eq!(alloc.total_bps(), 0);
            }
        }

        /// Sybil-floor: any identity with fewer than `floor` distinct receipts is
        /// never present in the Allocation.
        #[test]
        fn sybil_floor_excludes_below_threshold(
            evs in events(),
            floor in 1u32..6,
        ) {
            let c = chain("solo", &evs);
            let p = SnapshotParams {
                min_distinct_receipts: floor,
                dimension_weight: BTreeMap::new(),
                time_root_half_life: 0,
            };
            let distinct: std::collections::BTreeSet<[u8;32]> =
                evs.iter().map(|e| e.receipt_hash).collect();
            let alloc = eligibility_snapshot(&[("solo", c.as_slice())], &p);
            if distinct.len() < floor as usize {
                prop_assert!(alloc.is_empty());
            }
        }

        /// Monotonicity (raw weight): appending a CREDIT event to an identity's
        /// chain never DECREASES its raw eligibility weight, ceteris paribus.
        /// (Measured on raw fold weight — normalization is relative, so we test
        /// the pre-normalization quantity the spec names.)
        #[test]
        fn adding_credit_never_decreases_raw_weight(
            evs in events(),
            extra in 0u64..1_000_000,
            seed in any::<u8>(),
        ) {
            let p = SnapshotParams::default();
            let before = fold_identity(&chain("x", &evs), &p).weight;
            let mut evs2 = evs.clone();
            evs2.push(CreditEvent::honest_settlement(extra, [seed; 32]));
            let after = fold_identity(&chain("x", &evs2), &p).weight;
            prop_assert!(after >= before);
        }

        /// Debit-reduces: appending a DEBIT event never INCREASES raw weight.
        #[test]
        fn adding_debit_never_increases_raw_weight(
            evs in events(),
            extra in 0u64..1_000_000,
            seed in any::<u8>(),
        ) {
            let p = SnapshotParams::default();
            let before = fold_identity(&chain("x", &evs), &p).weight;
            let mut evs2 = evs.clone();
            evs2.push(CreditEvent::caught_defection(extra, [seed; 32]));
            let after = fold_identity(&chain("x", &evs2), &p).weight;
            prop_assert!(after <= before);
        }

        /// Time-root factor is non-increasing in position (the early-mover
        /// guarantee at the curve level).
        #[test]
        fn time_root_factor_non_increasing(a in 0u64..256, b in 0u64..256, hl in 0u64..64) {
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            prop_assert!(time_root_factor(lo, hl) >= time_root_factor(hi, hl));
        }

        /// All-debit / empty chains yield zero net weight (and thus no
        /// allocation).
        #[test]
        fn all_debit_yields_zero_weight(weights in proptest::collection::vec(0u64..1_000_000, 0..12)) {
            let evs: Vec<CreditEvent> = weights
                .iter()
                .enumerate()
                .map(|(i, w)| CreditEvent::caught_defection(*w, rh(i as u8)))
                .collect();
            let p = SnapshotParams::default();
            let raw = fold_identity(&chain("x", &evs), &p);
            prop_assert_eq!(raw.weight, 0);
        }
    }
}
