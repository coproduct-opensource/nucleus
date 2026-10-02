//! Egress volume: a byte ceiling and an optional pace, per pod (#2905).
//!
//! # The seam
//!
//! Every other egress control in the tree bounds **where** a pod may send
//! (netns default-deny, the DNS pin, `url_allow`, the boot-time probe) or
//! **whether** a tainted session may reach a sink (IFC floors). Nothing
//! bounded **how many** bytes leave. A host on the allowlist was unbounded,
//! so a workload that reached one permitted host could move weights-scale
//! volume through it at line rate. RAND's *Securing AI Model Weights* names
//! the missing primitive: rate-limited outputs, "so that exfiltration of a
//! significant portion of the weights would take too long to be practical".
//!
//! # Why this is a [`LedgerCore`], not a new counter
//!
//! Egress bytes are a conserved quantity exactly like money: every path that
//! sends must draw from one balance, a draw that was never made must be
//! refundable, and the sum of what is in flight plus what has been spent may
//! never pass the ceiling. That is the invariant [`LedgerCore`] already states
//! and the `kani-fast` lane already proves over the shipped type at `u64`
//! (`proof_budget_ledger_conserves`, `proof_budget_ledger_release_conserves`).
//! [`EgressBytes`] is `u64`, so those proofs are about this ledger too. One
//! unit, one law (ADR 0006 C1) — not a twenty-first linear quantity with its
//! own arithmetic.
//!
//! The mapping onto the core:
//!
//! * a send the host is ABOUT to perform is a child allocation
//!   ([`EgressLedger::reserve`] → [`EgressHold`]), so concurrent sends cannot
//!   jointly overdraw — the same reason the budget ledger reserves before a
//!   spawn rather than charging after it;
//! * settling a hold folds what was actually sent into consumption, or refunds
//!   it when nothing left the host ([`EgressSettlement`]);
//! * bytes a counter OBSERVED after the fact (a kernel counter on the pod's
//!   link) are parent consumption ([`EgressLedger::record_observed`]).
//!
//! # Which direction is counted
//!
//! Upload only — bytes from the pod toward the network. Exfiltration is the
//! threat this bounds, and a download cannot carry the pod's data out. Counting
//! responses too would spend the budget on package downloads and model replies,
//! which would force operators to set the ceiling high enough to be useless
//! against the upload it exists for.
//!
//! # Exhaustion latches
//!
//! The first time a reservation would pass the ceiling, the ledger refuses it
//! AND every later reservation, however small. The issue's wording is that the
//! pod's egress "drops to the default-deny state", and a non-latching ceiling
//! has a second defect: the remaining budget becomes an oracle a workload can
//! binary-search by trying sizes, and then spend to the last byte in chunks
//! sized to fit. A pace refusal does NOT latch — it is a rate, and the next
//! window is a fresh allowance by definition.
//!
//! # What this does not claim
//!
//! It bounds volume, not existence: a pod with a 1 MiB ceiling can still leak
//! 1 MiB. And a counter sees what it is shown — on the tap that is ciphertext
//! size, which is sufficient for a byte budget and deliberately not a DLP claim.

use core::num::NonZeroU32;

use crate::budget_ledger::{ChildId, LedgerCore, LedgerError};

/// The quantity an [`EgressLedger`] conserves: bytes sent toward the network.
///
/// `u64` on purpose — the unit the conservation proofs are stated at.
pub type EgressBytes = u64;

/// Concurrent holds one pod may have outstanding.
///
/// Above the credential broker's per-pod connection cap (16), so every
/// connection it can serve can hold a reservation at once. Exceeding it is a
/// refusal ([`EgressRefusal::TooManyInFlight`]), never an overwrite.
pub const EGRESS_SLOTS: usize = 32;

/// The ceiling a pod gets when its spec declares none: **1 GiB**.
///
/// # Why finite, and why this number
///
/// ADR 0007 B-2: `None` may not mean unrestricted. A spec written before this
/// field existed did not choose "unbounded"; it chose nothing, and the runtime
/// may not read silence as a grant.
///
/// The number is chosen to break no ordinary workload and every weights-scale
/// one. 1 GiB of UPLOAD is far above what a codegen, review or research pod
/// sends — prompts, patches, a pushed branch, a published package — while a
/// single open-weights checkpoint of a mid-sized model is tens of GiB and a
/// frontier one is hundreds. A pod that needs more says so in its spec
/// (`network.egress.max_bytes`), which is the named override: a deliberate,
/// reviewable number rather than an absence.
pub const DEFAULT_EGRESS_MAX_BYTES: EgressBytes = 1 << 30;

/// How fast egress may proceed, on top of the total ceiling.
///
/// An enum rather than `Option<Rate>` so that "no pace" is a value someone
/// wrote down, not the shape a missing field happens to have (ADR 0007 B-2).
/// [`EgressPace::Unpaced`] does not mean unbounded: the total ceiling still
/// applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressPace {
    /// Only the total ceiling applies.
    Unpaced,
    /// At most `bytes` per fixed window of `window_secs` seconds.
    ///
    /// `NonZeroU32` because a zero-length window has no meaning and every
    /// reading of one (divide by zero, or "every instant is a new window",
    /// which is unpaced) is a defect; the type makes it unwritable.
    PerWindow {
        /// Bytes admitted per window.
        bytes: EgressBytes,
        /// Window length.
        window_secs: NonZeroU32,
    },
}

/// A pod's egress authority: a total byte ceiling and a pace.
///
/// Fields are private so the only ways to get one are a declared value
/// ([`EgressCeiling::new`]) or the named default
/// ([`EgressCeiling::undeclared`]) — never `Default::default()`, which this
/// type deliberately does not implement (ADR 0007 B-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressCeiling {
    max_bytes: EgressBytes,
    pace: EgressPace,
}

impl EgressCeiling {
    /// A declared ceiling.
    #[must_use]
    pub const fn new(max_bytes: EgressBytes, pace: EgressPace) -> Self {
        Self { max_bytes, pace }
    }

    /// What a pod gets when it declared nothing:
    /// [`DEFAULT_EGRESS_MAX_BYTES`], unpaced. Finite on purpose.
    #[must_use]
    pub const fn undeclared() -> Self {
        Self::new(DEFAULT_EGRESS_MAX_BYTES, EgressPace::Unpaced)
    }

    /// Total bytes this authority permits.
    #[must_use]
    pub const fn max_bytes(&self) -> EgressBytes {
        self.max_bytes
    }

    /// The pace, if any.
    #[must_use]
    pub const fn pace(&self) -> EgressPace {
        self.pace
    }
}

/// Why an egress reservation was refused. Every variant names the dimension
/// and carries the counts a person needs to act on it (#2762).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressRefusal {
    /// The total ceiling is spent, or this send would pass it. Latching: every
    /// later reservation on the same ledger is refused with this variant.
    CeilingExhausted {
        /// The pod's ceiling.
        ceiling: EgressBytes,
        /// Bytes already sent or in flight when the refusal was decided.
        counted: EgressBytes,
        /// Bytes this send asked for.
        requested: EgressBytes,
    },
    /// This window's pace allowance would be passed. Not latching.
    RateExceeded {
        /// Bytes allowed per window.
        bytes_per_window: EgressBytes,
        /// Window length, seconds.
        window_secs: u32,
        /// Bytes already admitted in the current window.
        counted_in_window: EgressBytes,
        /// Bytes this send asked for.
        requested: EgressBytes,
    },
    /// Every reservation slot is held by a send still in flight.
    TooManyInFlight {
        /// Slot capacity.
        max: usize,
    },
    /// The ledger could not decide — a duplicate or unknown hold, or (for the
    /// host wrapper) a poisoned lock. "Could not look" is a refusal, never a
    /// grant (ADR 0007 A-1).
    LedgerFault,
}

impl EgressRefusal {
    /// The policy dimension this refusal is about, as the spec spells it.
    #[must_use]
    pub const fn dimension(&self) -> &'static str {
        match self {
            Self::CeilingExhausted { .. } => "egress.max_bytes",
            Self::RateExceeded { .. } => "egress.rate",
            Self::TooManyInFlight { .. } => "egress.in_flight",
            Self::LedgerFault => "egress.ledger",
        }
    }
}

impl core::fmt::Display for EgressRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CeilingExhausted {
                ceiling,
                counted,
                requested,
            } => write!(
                f,
                "egress budget exhausted (egress.max_bytes): {counted} of {ceiling} bytes \
                 already sent, {requested} more requested; egress is refused for the rest \
                 of this pod's life"
            ),
            Self::RateExceeded {
                bytes_per_window,
                window_secs,
                counted_in_window,
                requested,
            } => write!(
                f,
                "egress rate exceeded (egress.rate): {counted_in_window} of {bytes_per_window} \
                 bytes sent in this {window_secs}s window, {requested} more requested"
            ),
            Self::TooManyInFlight { max } => write!(
                f,
                "egress refused (egress.in_flight): {max} sends already in flight"
            ),
            Self::LedgerFault => write!(f, "egress refused (egress.ledger): ledger fault"),
        }
    }
}

impl std::error::Error for EgressRefusal {}

/// Whether a refusal is the first of its kind, which is what decides whether
/// it earns an audit record. Exhaustion is an effect (FM-3: no effect without
/// a receipt), but a workload hammering a latched ledger must not be able to
/// turn that into unbounded log growth on the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressNovelty {
    /// The ceiling latched on this call, or the first pace refusal this window.
    First,
    /// The same state was already reported.
    Repeat,
}

/// A reservation of egress bytes for one send the host is about to perform.
///
/// Affine: not `Clone`, `#[must_use]`, and settled BY VALUE
/// ([`EgressLedger::settle`]) so one hold cannot be refunded twice (ADR 0007
/// C-4). Only [`EgressLedger::reserve`] constructs one. A hold that is dropped
/// unsettled stays allocated — the bytes remain unavailable, which is the
/// fail-closed reading of "we do not know whether they were sent".
#[must_use = "an unsettled hold keeps its bytes reserved for the life of the ledger"]
#[derive(Debug, PartialEq, Eq)]
pub struct EgressHold {
    id: ChildId,
    bytes: EgressBytes,
}

impl EgressHold {
    /// Bytes this hold reserved.
    #[must_use]
    pub const fn bytes(&self) -> EgressBytes {
        self.bytes
    }
}

/// What happened to a held send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressSettlement {
    /// The bytes left the host, or may have (an ambiguous transport failure is
    /// this, not [`EgressSettlement::NotSent`]).
    Sent,
    /// Provably nothing left the host; the hold is refunded.
    NotSent,
}

/// The outcome of [`EgressLedger::reserve`]. A sum type, not a `bool`
/// (ADR 0007 A-2): the refusal carries its dimension and counts.
#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub enum EgressDecision {
    /// Admitted; the bytes are reserved until the hold is settled.
    Admitted(EgressHold),
    /// Refused, with why and whether it is the first such refusal.
    Refused(EgressRefusal, EgressNovelty),
}

/// The outcome of [`EgressLedger::record_observed`].
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressObservation {
    /// Still under the ceiling.
    WithinCeiling {
        /// Bytes still available.
        remaining: EgressBytes,
    },
    /// The observed bytes reached or passed the ceiling. The ledger is latched
    /// and the observer must close the path it counted.
    Exhausted(EgressRefusal, EgressNovelty),
}

/// The current pace window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Window {
    started_at: u64,
    counted: EgressBytes,
    refused: bool,
}

/// Whether the ceiling has latched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Latch {
    Open,
    Exhausted,
}

/// One pod's egress balance, shared by every path that sends on its behalf.
///
/// Hold exactly one per pod and hand the SAME one to every egress path (ADR
/// 0007 G: one decider per fact). Two ledgers for one pod would each admit up
/// to the ceiling, which is the fan-out defect the budget ledger exists to
/// close, in a new unit.
#[derive(Debug)]
pub struct EgressLedger {
    ceiling: EgressCeiling,
    core: LedgerCore<EgressBytes, EGRESS_SLOTS>,
    window: Window,
    latch: Latch,
    next_id: ChildId,
}

impl EgressLedger {
    /// A fresh ledger with nothing sent.
    #[must_use]
    pub fn new(ceiling: EgressCeiling) -> Self {
        Self {
            ceiling,
            core: LedgerCore::new(ceiling.max_bytes, 0),
            window: Window {
                started_at: 0,
                counted: 0,
                refused: false,
            },
            latch: Latch::Open,
            next_id: 0,
        }
    }

    /// The authority this ledger enforces.
    #[must_use]
    pub const fn ceiling(&self) -> EgressCeiling {
        self.ceiling
    }

    /// Bytes sent or in flight.
    #[must_use]
    pub fn counted(&self) -> EgressBytes {
        self.core
            .parent_consumed_units()
            .saturating_add(self.core.allocated_units())
    }

    /// Bytes still available to reserve. Zero once latched.
    #[must_use]
    pub fn remaining(&self) -> EgressBytes {
        match self.latch {
            Latch::Open => self.core.available_units(),
            Latch::Exhausted => 0,
        }
    }

    /// The underlying proof subject.
    #[must_use]
    pub fn core(&self) -> &LedgerCore<EgressBytes, EGRESS_SLOTS> {
        &self.core
    }

    fn exhausted(&self, requested: EgressBytes) -> EgressRefusal {
        EgressRefusal::CeilingExhausted {
            ceiling: self.ceiling.max_bytes,
            counted: self.counted(),
            requested,
        }
    }

    /// Latch, reporting whether this call is the one that latched.
    fn latch(&mut self) -> EgressNovelty {
        match self.latch {
            Latch::Open => {
                self.latch = Latch::Exhausted;
                EgressNovelty::First
            }
            Latch::Exhausted => EgressNovelty::Repeat,
        }
    }

    /// Reserve `bytes` for a send about to happen at `now_unix`.
    ///
    /// Order: the latch, then the pace, then the ceiling. The pace is checked
    /// before the ceiling so a send that would fail both reports the
    /// NON-latching reason and does not latch — waiting is the remedy, and
    /// latching would deny the pod a send the ceiling could still afford in a
    /// later window. On any refusal nothing is reserved.
    pub fn reserve(&mut self, bytes: EgressBytes, now_unix: u64) -> EgressDecision {
        if self.latch == Latch::Exhausted {
            return EgressDecision::Refused(self.exhausted(bytes), EgressNovelty::Repeat);
        }

        if let EgressPace::PerWindow {
            bytes: per_window,
            window_secs,
        } = self.ceiling.pace
        {
            let len = u64::from(window_secs.get());
            if now_unix.saturating_sub(self.window.started_at) >= len
                || now_unix < self.window.started_at
            {
                self.window = Window {
                    started_at: now_unix,
                    counted: 0,
                    refused: false,
                };
            }
            if self.window.counted.saturating_add(bytes) > per_window {
                let novelty = if self.window.refused {
                    EgressNovelty::Repeat
                } else {
                    self.window.refused = true;
                    EgressNovelty::First
                };
                return EgressDecision::Refused(
                    EgressRefusal::RateExceeded {
                        bytes_per_window: per_window,
                        window_secs: window_secs.get(),
                        counted_in_window: self.window.counted,
                        requested: bytes,
                    },
                    novelty,
                );
            }
        }

        let id = self.next_id;
        match self.core.try_allocate(id, bytes) {
            Ok(()) => {
                self.next_id = self.next_id.saturating_add(1);
                if let EgressPace::PerWindow { .. } = self.ceiling.pace {
                    self.window.counted = self.window.counted.saturating_add(bytes);
                }
                EgressDecision::Admitted(EgressHold { id, bytes })
            }
            Err(LedgerError::InsufficientBudget { .. }) => {
                let refusal = self.exhausted(bytes);
                let novelty = self.latch();
                EgressDecision::Refused(refusal, novelty)
            }
            Err(LedgerError::TooManyChildren { max }) => EgressDecision::Refused(
                EgressRefusal::TooManyInFlight { max },
                EgressNovelty::Repeat,
            ),
            Err(LedgerError::DuplicateChild | LedgerError::UnknownChild) => {
                EgressDecision::Refused(EgressRefusal::LedgerFault, EgressNovelty::Repeat)
            }
        }
    }

    /// Settle a hold. [`EgressSettlement::Sent`] folds its bytes into what
    /// this pod has spent; [`EgressSettlement::NotSent`] refunds them.
    ///
    /// Takes the hold by value: settling is the hold's end.
    pub fn settle(&mut self, hold: EgressHold, outcome: EgressSettlement) {
        let spent = match outcome {
            EgressSettlement::Sent => hold.bytes,
            EgressSettlement::NotSent => 0,
        };
        // `UnknownChild` is the only error `release` has, and it means a hold
        // minted by a DIFFERENT ledger. Nothing of this ledger's changes, which
        // is the conservative answer — a foreign hold cannot refund bytes here.
        let _ = self.core.release(hold.id, spent);
    }

    /// Fold in bytes a counter observed AFTER they were sent — a kernel byte
    /// counter on the pod's link, which cannot ask first.
    ///
    /// Clamped at the ceiling (the core's `record_parent_consumed`), and
    /// latching when the ceiling is reached: the observer is then obliged to
    /// close the path it counted. The pace is not applied — it cannot refuse
    /// bytes that already left.
    pub fn record_observed(&mut self, bytes: EgressBytes) -> EgressObservation {
        let available = self.core.available_units();
        let _ = self.core.record_parent_consumed(bytes);
        if self.latch == Latch::Exhausted || bytes >= available {
            let refusal = EgressRefusal::CeilingExhausted {
                ceiling: self.ceiling.max_bytes,
                counted: self.counted(),
                requested: bytes,
            };
            let novelty = self.latch();
            return EgressObservation::Exhausted(refusal, novelty);
        }
        EgressObservation::WithinCeiling {
            remaining: self.core.available_units(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admitted(d: EgressDecision) -> EgressHold {
        match d {
            EgressDecision::Admitted(h) => h,
            EgressDecision::Refused(r, _) => panic!("expected admission, got {r}"),
        }
    }

    fn refused(d: EgressDecision) -> (EgressRefusal, EgressNovelty) {
        match d {
            EgressDecision::Admitted(h) => panic!("expected refusal, got a hold of {}", h.bytes),
            EgressDecision::Refused(r, n) => (r, n),
        }
    }

    fn paced(max: u64, per: u64, secs: u32) -> EgressCeiling {
        EgressCeiling::new(
            max,
            EgressPace::PerWindow {
                bytes: per,
                window_secs: NonZeroU32::new(secs).expect("non-zero"),
            },
        )
    }

    /// The defect #2905 names: a send that would pass the ceiling is refused,
    /// with the dimension and the counts.
    #[test]
    fn a_send_past_the_ceiling_is_refused_and_names_the_dimension() {
        let mut ledger = EgressLedger::new(EgressCeiling::new(1_000, EgressPace::Unpaced));
        let first = admitted(ledger.reserve(600, 0));
        ledger.settle(first, EgressSettlement::Sent);

        let (refusal, novelty) = refused(ledger.reserve(500, 0));
        assert_eq!(
            refusal,
            EgressRefusal::CeilingExhausted {
                ceiling: 1_000,
                counted: 600,
                requested: 500
            }
        );
        assert_eq!(novelty, EgressNovelty::First);
        assert_eq!(refusal.dimension(), "egress.max_bytes");
        assert!(refusal.to_string().contains("600 of 1000 bytes"));
        assert!(ledger.core().conserves());
    }

    /// Latching: after exhaustion even a send that WOULD fit is refused, so the
    /// remaining budget is not an oracle to binary-search.
    #[test]
    fn exhaustion_latches_even_for_a_send_that_would_fit() {
        let mut ledger = EgressLedger::new(EgressCeiling::new(1_000, EgressPace::Unpaced));
        let _ = refused(ledger.reserve(2_000, 0));
        let (refusal, novelty) = refused(ledger.reserve(1, 0));
        assert!(matches!(refusal, EgressRefusal::CeilingExhausted { .. }));
        assert_eq!(
            novelty,
            EgressNovelty::Repeat,
            "only the latching call is First"
        );
        assert_eq!(ledger.remaining(), 0);
    }

    /// Two sends in flight at once cannot jointly overdraw: the second is
    /// decided against what the first has RESERVED, not what it has spent.
    #[test]
    fn concurrent_holds_cannot_jointly_pass_the_ceiling() {
        let mut ledger = EgressLedger::new(EgressCeiling::new(1_000, EgressPace::Unpaced));
        let a = admitted(ledger.reserve(700, 0));
        let (refusal, _) = refused(ledger.reserve(700, 0));
        assert!(matches!(
            refusal,
            EgressRefusal::CeilingExhausted { counted: 700, .. }
        ));
        ledger.settle(a, EgressSettlement::Sent);
        assert!(ledger.core().conserves());
    }

    /// One balance for every path: bytes a kernel counter observed and bytes a
    /// userspace path reserved draw from the same ceiling.
    #[test]
    fn observed_and_reserved_bytes_share_one_ceiling() {
        let mut ledger = EgressLedger::new(EgressCeiling::new(1_000, EgressPace::Unpaced));
        assert_eq!(
            ledger.record_observed(600),
            EgressObservation::WithinCeiling { remaining: 400 }
        );
        let (refusal, _) = refused(ledger.reserve(500, 0));
        assert_eq!(
            refusal,
            EgressRefusal::CeilingExhausted {
                ceiling: 1_000,
                counted: 600,
                requested: 500
            }
        );

        // And the other way round: a reservation in flight leaves less for the
        // observed path, which latches when it reaches the ceiling.
        let mut ledger = EgressLedger::new(EgressCeiling::new(1_000, EgressPace::Unpaced));
        let hold = admitted(ledger.reserve(900, 0));
        assert!(matches!(
            ledger.record_observed(200),
            EgressObservation::Exhausted(
                EgressRefusal::CeilingExhausted { .. },
                EgressNovelty::First
            )
        ));
        ledger.settle(hold, EgressSettlement::Sent);
        assert!(ledger.core().conserves());
    }

    #[test]
    fn a_send_that_never_left_is_refunded() {
        let mut ledger = EgressLedger::new(EgressCeiling::new(1_000, EgressPace::Unpaced));
        let hold = admitted(ledger.reserve(1_000, 0));
        assert_eq!(ledger.remaining(), 0);
        ledger.settle(hold, EgressSettlement::NotSent);
        assert_eq!(ledger.remaining(), 1_000);
        assert_eq!(ledger.counted(), 0);
    }

    /// ADR 0007 B: a pod that declared nothing gets a FINITE ceiling.
    #[test]
    fn an_undeclared_ceiling_is_finite() {
        let ceiling = EgressCeiling::undeclared();
        assert_eq!(ceiling.max_bytes(), DEFAULT_EGRESS_MAX_BYTES);
        assert!(ceiling.max_bytes() < u64::MAX);

        let mut ledger = EgressLedger::new(ceiling);
        let hold = admitted(ledger.reserve(DEFAULT_EGRESS_MAX_BYTES, 0));
        ledger.settle(hold, EgressSettlement::Sent);
        let (refusal, _) = refused(ledger.reserve(1, 0));
        assert!(matches!(refusal, EgressRefusal::CeilingExhausted { .. }));
    }

    #[test]
    fn the_pace_refuses_within_a_window_and_resets_after_it() {
        let mut ledger = EgressLedger::new(paced(10_000, 100, 60));
        let h = admitted(ledger.reserve(80, 1_000));
        ledger.settle(h, EgressSettlement::Sent);

        let (refusal, novelty) = refused(ledger.reserve(30, 1_010));
        assert_eq!(
            refusal,
            EgressRefusal::RateExceeded {
                bytes_per_window: 100,
                window_secs: 60,
                counted_in_window: 80,
                requested: 30
            }
        );
        assert_eq!(novelty, EgressNovelty::First);
        assert_eq!(refusal.dimension(), "egress.rate");
        assert_eq!(refused(ledger.reserve(30, 1_020)).1, EgressNovelty::Repeat);

        // A pace refusal does not latch: the next window admits.
        let h = admitted(ledger.reserve(30, 1_060));
        ledger.settle(h, EgressSettlement::Sent);
        assert_eq!(ledger.counted(), 110);
    }

    /// A send that fails both the pace and the ceiling reports the pace and
    /// does not latch the ceiling.
    #[test]
    fn the_pace_is_decided_before_the_ceiling_and_does_not_latch() {
        let mut ledger = EgressLedger::new(paced(100, 50, 60));
        let (refusal, _) = refused(ledger.reserve(200, 0));
        assert!(matches!(refusal, EgressRefusal::RateExceeded { .. }));
        assert_eq!(ledger.remaining(), 100);
    }

    #[test]
    fn every_slot_held_is_a_refusal_not_an_overwrite() {
        let mut ledger = EgressLedger::new(EgressCeiling::new(1_000, EgressPace::Unpaced));
        let holds: Vec<_> = (0..EGRESS_SLOTS)
            .map(|_| admitted(ledger.reserve(1, 0)))
            .collect();
        let (refusal, _) = refused(ledger.reserve(1, 0));
        assert_eq!(
            refusal,
            EgressRefusal::TooManyInFlight { max: EGRESS_SLOTS }
        );
        for h in holds {
            ledger.settle(h, EgressSettlement::Sent);
        }
        assert_eq!(ledger.counted(), u64::try_from(EGRESS_SLOTS).expect("fits"));
    }
}
