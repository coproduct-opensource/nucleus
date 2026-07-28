//! Effect receipts — evidence that an authority was spent, and on what.
//!
//! # What this is for
//!
//! After the B1/B2 cutover every effect is *enforced*: reaching one requires
//! surrendering a scoped, single-use [`Authority`](crate::authority::Authority).
//! Enforcement without evidence is still only as good as the operator's word,
//! though — which is exactly the gap the 2026 sandbox-escape results exposed in
//! other runtimes. A receipt is what lets a third party check the claim instead
//! of believing it.
//!
//! Receipts are emitted at the mediation choke point, so a receipt cannot be
//! forgotten separately from the check: the same call site that spends the
//! authority appends the entry.
//!
//! # What a receipt asserts, precisely
//!
//! **That an authorization decision was made for this `(Operation, SinkClass)`,
//! and what it was.** It does NOT assert that the underlying I/O succeeded: an
//! `Allowed` receipt followed by a disk error is a correct pair of facts. The
//! flagship claim is about side effects being *mediated and authorized*, and the
//! authorization is the part a receipt can witness.
//!
//! # What this is not, yet
//!
//! * **Not signed.** Signing binds a chain to a key; binding it to a *measured
//!   binary* is the attestation work, and neither is done here. An unsigned
//!   chain detects accidental truncation and reordering, not a motivated
//!   operator.
//! * **Not persisted.** The log lives with the effect handler.
//! * **Not complete across the crate.** `PolicyEnforced` is the choke point for
//!   the ten methods it gates. `ShellEffect::run_argv`,
//!   `AsyncShellSpawnEffect::run_argv_async` and `NetEffect::fetch` spend their
//!   authority inside `RealEffects`, below this layer, so they are not witnessed
//!   here.

use std::sync::Mutex;

use portcullis_core::{Operation, SinkClass};
use sha2::{Digest, Sha256};

/// What the mediation layer decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectOutcome {
    /// The authority was in scope and the capability permitted it. The effect
    /// was invoked (it may still have failed for non-policy reasons).
    Allowed,
    /// The coarse capability lattice denied it (`… == Never`).
    DeniedByPolicy,
    /// The authority was earned for a different `(Operation, SinkClass)`.
    DeniedByScope,
}

impl EffectOutcome {
    fn code(self) -> u8 {
        match self {
            EffectOutcome::Allowed => 0,
            EffectOutcome::DeniedByPolicy => 1,
            EffectOutcome::DeniedByScope => 2,
        }
    }
}

/// One entry in the effect chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectReceipt {
    /// Position in the chain, from 0.
    pub seq: u64,
    /// The operation the effect was attempted under.
    pub operation: Operation,
    /// The sink the effect targeted.
    pub sink_class: SinkClass,
    /// What the mediation layer decided.
    pub outcome: EffectOutcome,
    /// Hash of the previous entry; all-zero for the first.
    pub prev_hash: [u8; 32],
    /// `SHA-256` over this entry's canonical bytes, including `prev_hash`.
    pub hash: [u8; 32],
}

/// The bytes that get hashed. Fixed-width and order-fixed, so two chains agree
/// on a digest iff they agree on the facts — no serializer in the trusted path.
fn canonical_bytes(
    seq: u64,
    operation: Operation,
    sink_class: SinkClass,
    outcome: EffectOutcome,
    prev_hash: &[u8; 32],
) -> [u8; 43] {
    let mut buf = [0u8; 43];
    buf[0..8].copy_from_slice(&seq.to_be_bytes());
    buf[8..40].copy_from_slice(prev_hash);
    buf[40] = operation as u8;
    buf[41] = sink_class as u8;
    buf[42] = outcome.code();
    buf
}

/// Why a chain failed verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// `seq` is not the entry's index — an entry was inserted or removed.
    SequenceBroken {
        /// Index in the log where the break was found.
        at: usize,
    },
    /// `prev_hash` does not match the previous entry's `hash`.
    LinkBroken {
        /// Index in the log where the break was found.
        at: usize,
    },
    /// The stored `hash` is not the hash of the entry's own contents.
    ContentAltered {
        /// Index in the log where the break was found.
        at: usize,
    },
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::SequenceBroken { at } => write!(f, "sequence broken at entry {at}"),
            ChainError::LinkBroken { at } => write!(f, "hash link broken at entry {at}"),
            ChainError::ContentAltered { at } => write!(f, "entry {at} was altered"),
        }
    }
}

impl std::error::Error for ChainError {}

/// An append-only, hash-chained log of mediation decisions.
///
/// Interior-mutable so the effect traits can append through `&self` — they take
/// `&self` because an effect handler is shared, and threading `&mut` through
/// them would change every signature for no security gain.
#[derive(Debug, Default)]
pub struct ReceiptLog {
    entries: Mutex<Vec<EffectReceipt>>,
}

impl ReceiptLog {
    /// An empty chain.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a decision and return the new chain head.
    ///
    /// Appending is the only mutation this type offers: there is no `remove`,
    /// no `truncate`, and no way to reach the inner `Vec`. That makes the log
    /// append-only *by construction* rather than by convention — which is the
    /// property `verify_chain` then makes checkable by a third party.
    pub fn append(
        &self,
        operation: Operation,
        sink_class: SinkClass,
        outcome: EffectOutcome,
    ) -> [u8; 32] {
        let mut entries = self.entries.lock().expect("receipt log poisoned");
        let seq = entries.len() as u64;
        let prev_hash = entries.last().map_or([0u8; 32], |e| e.hash);
        let hash: [u8; 32] = Sha256::digest(canonical_bytes(
            seq, operation, sink_class, outcome, &prev_hash,
        ))
        .into();
        entries.push(EffectReceipt {
            seq,
            operation,
            sink_class,
            outcome,
            prev_hash,
            hash,
        });
        hash
    }

    /// A snapshot of the chain.
    pub fn entries(&self) -> Vec<EffectReceipt> {
        self.entries.lock().expect("receipt log poisoned").clone()
    }

    /// The current head, or all-zero when empty.
    pub fn head(&self) -> [u8; 32] {
        self.entries
            .lock()
            .expect("receipt log poisoned")
            .last()
            .map_or([0u8; 32], |e| e.hash)
    }

    /// How many decisions have been recorded.
    pub fn len(&self) -> usize {
        self.entries.lock().expect("receipt log poisoned").len()
    }

    /// Whether the chain is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Re-derive every hash and link.
    ///
    /// This is the check a third party runs: it needs only the entries, no
    /// access to the runtime that produced them. It detects truncation from the
    /// middle, reordering, and any edit to a recorded fact.
    ///
    /// It does NOT detect an operator who discards the tail and recomputes — for
    /// that the head must be published or signed, which is the attestation work
    /// this module deliberately does not claim.
    pub fn verify_chain(&self) -> Result<(), ChainError> {
        let entries = self.entries.lock().expect("receipt log poisoned");
        let mut expected_prev = [0u8; 32];
        for (i, e) in entries.iter().enumerate() {
            if e.seq != i as u64 {
                return Err(ChainError::SequenceBroken { at: i });
            }
            if e.prev_hash != expected_prev {
                return Err(ChainError::LinkBroken { at: i });
            }
            let recomputed: [u8; 32] = Sha256::digest(canonical_bytes(
                e.seq,
                e.operation,
                e.sink_class,
                e.outcome,
                &e.prev_hash,
            ))
            .into();
            if recomputed != e.hash {
                return Err(ChainError::ContentAltered { at: i });
            }
            expected_prev = e.hash;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_log_is_empty_and_has_a_zero_head() {
        let log = ReceiptLog::new();
        assert!(log.is_empty());
        assert_eq!(log.head(), [0u8; 32]);
        assert_eq!(log.verify_chain(), Ok(()));
    }

    #[test]
    fn appending_links_each_entry_to_the_last() {
        let log = ReceiptLog::new();
        log.append(
            Operation::ReadFiles,
            SinkClass::AuditLogAppend,
            EffectOutcome::Allowed,
        );
        log.append(
            Operation::GitPush,
            SinkClass::GitPush,
            EffectOutcome::DeniedByScope,
        );
        let entries = log.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].prev_hash, [0u8; 32]);
        assert_eq!(entries[1].prev_hash, entries[0].hash);
        assert_eq!(log.head(), entries[1].hash);
        assert_eq!(log.verify_chain(), Ok(()));
    }

    /// Denials are evidence too. A chain that recorded only successes would let
    /// a refused push disappear from the record.
    #[test]
    fn denials_are_recorded_not_dropped() {
        let log = ReceiptLog::new();
        log.append(
            Operation::GitPush,
            SinkClass::GitPush,
            EffectOutcome::DeniedByPolicy,
        );
        assert_eq!(log.entries()[0].outcome, EffectOutcome::DeniedByPolicy);
    }

    /// The same facts in the same order must hash identically, or a third party
    /// cannot compare two copies of a chain.
    #[test]
    fn the_chain_is_deterministic() {
        let build = || {
            let log = ReceiptLog::new();
            log.append(
                Operation::WriteFiles,
                SinkClass::WorkspaceWrite,
                EffectOutcome::Allowed,
            );
            log.append(
                Operation::WebFetch,
                SinkClass::HTTPEgress,
                EffectOutcome::Allowed,
            );
            log.head()
        };
        assert_eq!(build(), build());
    }

    /// Reordering two entries breaks the chain — the property that makes the
    /// log worth keeping.
    #[test]
    fn reordering_is_detected() {
        let log = ReceiptLog::new();
        log.append(
            Operation::ReadFiles,
            SinkClass::AuditLogAppend,
            EffectOutcome::Allowed,
        );
        log.append(
            Operation::GitPush,
            SinkClass::GitPush,
            EffectOutcome::Allowed,
        );
        let mut tampered = log.entries();
        tampered.swap(0, 1);
        let replayed = ReceiptLog {
            entries: Mutex::new(tampered),
        };
        assert!(matches!(
            replayed.verify_chain(),
            Err(ChainError::SequenceBroken { .. } | ChainError::LinkBroken { .. })
        ));
    }

    /// Editing a recorded fact is detected even when the links are left intact —
    /// this is what `hash` covering the contents buys over a bare linked list.
    #[test]
    fn editing_an_entry_is_detected() {
        let log = ReceiptLog::new();
        log.append(
            Operation::GitPush,
            SinkClass::GitPush,
            EffectOutcome::DeniedByScope,
        );
        let mut tampered = log.entries();
        // Rewrite history: the refused push becomes an allowed one.
        tampered[0].outcome = EffectOutcome::Allowed;
        let forged = ReceiptLog {
            entries: Mutex::new(tampered),
        };
        assert_eq!(
            forged.verify_chain(),
            Err(ChainError::ContentAltered { at: 0 })
        );
    }

    /// Truncating from the middle is detected by the sequence check.
    #[test]
    fn removing_a_middle_entry_is_detected() {
        let log = ReceiptLog::new();
        for _ in 0..3 {
            log.append(
                Operation::ReadFiles,
                SinkClass::AuditLogAppend,
                EffectOutcome::Allowed,
            );
        }
        let mut tampered = log.entries();
        tampered.remove(1);
        let truncated = ReceiptLog {
            entries: Mutex::new(tampered),
        };
        assert!(matches!(
            truncated.verify_chain(),
            Err(ChainError::SequenceBroken { .. })
        ));
    }
}
