//! WASM-pure, append-only hash chain over an identity's [`CreditEvent`]s.
//!
//! This module is **always compiled** (it needs only `sha2`, which is already in
//! the default dependency closure) so the same chain verification that the
//! durable [`crate::store`] performs server-side is also runnable in the browser
//! verify SDK. The durable, redb-backed store lives behind the off-by-default
//! `persist` feature; this module is the storage-independent core it commits to.
//!
//! # What a chain is
//!
//! For one identity, the ledger is a sequence of [`LedgerEntry`]s with
//! `seq = 0, 1, 2, …`. Each entry commits, via a SHA-256 [`entry_hash`] over
//! domain-separated canonical bytes, to:
//!
//! * the identity it belongs to,
//! * its `seq`,
//! * the underlying [`CreditEvent`] (dimension, polarity, weight, receipt hash),
//! * the entry timestamp, and
//! * the **previous** entry's `this_hash` (`None`/32 zero bytes for genesis).
//!
//! Because each `this_hash` folds in the predecessor's `this_hash`, the chain is
//! tamper-evident: editing any field of any entry, reordering, dropping, or
//! re-pointing a link changes a hash and [`verify_chain`] rejects it
//! ([`ChainError`]).
//!
//! # Honesty boundary (do NOT overclaim)
//!
//! This is tamper-EVIDENCE relative to a head a consumer previously retained
//! (see [`crate::store::CreditLedgerStore::head`]) plus intra-ledger
//! immutability + ordering + per-identity gap detection. It is **NOT** a
//! transparency log: there is no non-equivocation (an operator who controls the
//! store can present two divergent internally-consistent chains, or regenerate +
//! re-hash a fresh history for a verifier who never saw a prior head), no
//! sublinear inclusion/consistency proofs, and no third-party append-only
//! guarantee. Closing the equivocation gap is a documented follow-on: make each
//! entry a leaf in `nucleus-lineage` `MerkleSink`, seal a `SignedTreeHead`, and
//! submit it to the `nucleus-witness` C2SP tlog-witness server for a
//! cosignature (k-of-n witnesses across failure domains).

use crate::{CreditDimension, CreditEvent, Polarity};
use sha2::{Digest, Sha256};

/// Domain separator for ledger-entry canonical bytes (versioned). Mirrors
/// `nucleus-recompute`'s `RECEIPT_DOMAIN` discipline: domain-tagged,
/// NUL-delimited variable-length fields, fixed-width big-endian integers, raw
/// 32-byte hashes.
const LEDGER_DOMAIN: &[u8] = b"nucleus-credit-ledger/entry/v1\0";

/// The 32 zero bytes that stand in for an absent (`None`) predecessor hash in
/// the canonical bytes of a genesis entry.
const ABSENT_PREV: [u8; 32] = [0u8; 32];

/// Canonical, stable snake_case tag for a credit dimension.
///
/// The match is **exhaustive** (no wildcard) and this module lives in the same
/// crate as [`CreditDimension`], so adding a new `#[non_exhaustive]` variant is a
/// compile error here — a new dimension MUST be given a tag deliberately rather
/// than silently hashing to an unstable / colliding value.
fn dim_tag(dim: CreditDimension) -> &'static str {
    match dim {
        CreditDimension::FinancialDefault => "financial_default",
        CreditDimension::Externality => "externality",
    }
}

/// Canonical, stable snake_case tag for a polarity.
fn pol_tag(pol: Polarity) -> &'static str {
    match pol {
        Polarity::Credit => "credit",
        Polarity::Debit => "debit",
    }
}

/// One link in an identity's credit chain: a [`CreditEvent`] sealed at position
/// `seq`, linked to its predecessor by hash.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LedgerEntry {
    /// The identity this entry accrues to (the store key; supplied by the
    /// caller, never read from the event/receipt — see crate docs).
    pub identity: String,
    /// Position in this identity's chain, starting at 0.
    pub seq: u64,
    /// The recompute-verified outcome this entry records.
    pub event: CreditEvent,
    /// Entry timestamp, seconds since the Unix epoch.
    pub ts_unix_secs: i64,
    /// The predecessor's [`LedgerEntry::this_hash`]; `None` for the genesis
    /// entry (`seq == 0`).
    pub prev_hash: Option<[u8; 32]>,
    /// SHA-256 over this entry's canonical bytes (which fold in `prev_hash`).
    pub this_hash: [u8; 32],
}

impl LedgerEntry {
    /// Build an entry, computing its [`LedgerEntry::this_hash`] from the other
    /// fields. The only constructor — `this_hash` is never set by hand, so a
    /// well-formed [`LedgerEntry`] always carries a self-consistent hash.
    pub fn new(
        identity: String,
        seq: u64,
        event: CreditEvent,
        ts_unix_secs: i64,
        prev_hash: Option<[u8; 32]>,
    ) -> Self {
        let this_hash = entry_hash(&identity, seq, &event, ts_unix_secs, prev_hash);
        Self {
            identity,
            seq,
            event,
            ts_unix_secs,
            prev_hash,
            this_hash,
        }
    }
}

/// The exact preimage [`entry_hash`] digests. Deterministic and total: every
/// field is encoded unambiguously (length-delimited or fixed-width), so distinct
/// logical entries never share a preimage.
pub fn canonical_entry_bytes(
    identity: &str,
    seq: u64,
    event: &CreditEvent,
    ts_unix_secs: i64,
    prev_hash: Option<[u8; 32]>,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(LEDGER_DOMAIN.len() + identity.len() + 96);
    b.extend_from_slice(LEDGER_DOMAIN);
    b.extend_from_slice(identity.as_bytes());
    b.push(0x00);
    b.extend_from_slice(&seq.to_be_bytes());
    b.extend_from_slice(dim_tag(event.dimension).as_bytes());
    b.push(0x00);
    b.extend_from_slice(pol_tag(event.polarity).as_bytes());
    b.push(0x00);
    b.extend_from_slice(&event.weight_micro.to_be_bytes());
    b.extend_from_slice(&event.receipt_hash);
    b.extend_from_slice(&ts_unix_secs.to_be_bytes());
    b.extend_from_slice(&prev_hash.unwrap_or(ABSENT_PREV));
    b
}

/// SHA-256 over [`canonical_entry_bytes`] — a pure function of its inputs.
pub fn entry_hash(
    identity: &str,
    seq: u64,
    event: &CreditEvent,
    ts_unix_secs: i64,
    prev_hash: Option<[u8; 32]>,
) -> [u8; 32] {
    let bytes = canonical_entry_bytes(identity, seq, event, ts_unix_secs, prev_hash);
    let mut h = Sha256::new();
    h.update(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Why a chain failed [`verify_chain`].
///
/// Hand-rolled `Display`/`Error` (no `thiserror`) so this WASM-pure module adds
/// nothing but `sha2` to the default/browser dependency closure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// The genesis entry (`seq == 0`) carried a non-`None` `prev_hash`.
    GenesisNotNone,
    /// `seq` did not start at 0 and increase by exactly 1 (a dropped or
    /// reordered entry).
    SeqGap {
        /// The `seq` the chain expected next.
        expected: u64,
        /// The `seq` actually found.
        found: u64,
    },
    /// The recomputed [`entry_hash`] did not match the stored `this_hash` (a
    /// mutated field).
    BadHash {
        /// The `seq` whose hash failed to recompute.
        seq: u64,
    },
    /// An entry's `prev_hash` did not equal its predecessor's `this_hash` (a
    /// re-pointed link).
    BrokenLink {
        /// The `seq` whose back-link was broken.
        seq: u64,
    },
    /// Two entries in the same slice belonged to different identities.
    IdentityMismatch,
}

impl core::fmt::Display for ChainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChainError::GenesisNotNone => {
                write!(f, "genesis entry (seq 0) must have no prev_hash")
            }
            ChainError::SeqGap { expected, found } => {
                write!(f, "sequence gap: expected seq {expected}, found {found}")
            }
            ChainError::BadHash { seq } => write!(f, "hash mismatch at seq {seq}"),
            ChainError::BrokenLink { seq } => write!(f, "broken back-link at seq {seq}"),
            ChainError::IdentityMismatch => write!(f, "entries belong to different identities"),
        }
    }
}

impl std::error::Error for ChainError {}

/// Verify that `entries` is a single identity's contiguous, hash-linked chain in
/// `seq` order. Pure — runnable in the browser SDK. An empty slice is a valid
/// (fresh-identity) chain.
///
/// Checks, per entry: identity is constant ([`ChainError::IdentityMismatch`]);
/// `seq` starts at 0 and increments by 1 ([`ChainError::SeqGap`]); the back-link
/// matches the predecessor's `this_hash`, and genesis has no predecessor
/// ([`ChainError::BrokenLink`] / [`ChainError::GenesisNotNone`]); and the stored
/// `this_hash` recomputes ([`ChainError::BadHash`]). Link/structure is checked
/// before hash so a re-pointed link surfaces as `BrokenLink` rather than the
/// downstream `BadHash`.
pub fn verify_chain(entries: &[LedgerEntry]) -> Result<(), ChainError> {
    let mut prev: Option<&LedgerEntry> = None;
    let mut expected_seq: u64 = 0;
    for e in entries {
        if let Some(p) = prev {
            if p.identity != e.identity {
                return Err(ChainError::IdentityMismatch);
            }
        }
        if e.seq != expected_seq {
            return Err(ChainError::SeqGap {
                expected: expected_seq,
                found: e.seq,
            });
        }
        match prev {
            None => {
                if e.prev_hash.is_some() {
                    return Err(ChainError::GenesisNotNone);
                }
            }
            Some(p) => {
                if e.prev_hash != Some(p.this_hash) {
                    return Err(ChainError::BrokenLink { seq: e.seq });
                }
            }
        }
        let recomputed = entry_hash(&e.identity, e.seq, &e.event, e.ts_unix_secs, e.prev_hash);
        if recomputed != e.this_hash {
            return Err(ChainError::BadHash { seq: e.seq });
        }
        prev = Some(e);
        expected_seq = expected_seq.saturating_add(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rh(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    /// Build a well-formed chain of `n` honest-settlement entries for `id`,
    /// linking each to its predecessor (exactly what the store does).
    fn build_chain(id: &str, n: u64) -> Vec<LedgerEntry> {
        let mut out: Vec<LedgerEntry> = Vec::new();
        for seq in 0..n {
            let prev = out.last().map(|e| e.this_hash);
            let event = CreditEvent::honest_settlement(1_000 * (seq + 1), rh(seq as u8));
            out.push(LedgerEntry::new(
                id.to_string(),
                seq,
                event,
                100 + seq as i64,
                prev,
            ));
        }
        out
    }

    #[test]
    fn happy_chain_verifies_and_is_well_linked() {
        let chain = build_chain("agent-a", 4);
        assert_eq!(chain[0].prev_hash, None);
        assert_eq!(chain[0].seq, 0);
        for i in 1..chain.len() {
            assert_eq!(chain[i].seq, i as u64);
            assert_eq!(chain[i].prev_hash, Some(chain[i - 1].this_hash));
        }
        assert_eq!(verify_chain(&chain), Ok(()));
    }

    #[test]
    fn empty_chain_is_valid() {
        assert_eq!(verify_chain(&[]), Ok(()));
    }

    #[test]
    fn entry_hash_is_deterministic_and_field_sensitive() {
        let id = "agent-a";
        let ev = CreditEvent::honest_settlement(1_000, rh(1));
        let h = entry_hash(id, 0, &ev, 100, None);
        // Identical inputs → identical hash.
        assert_eq!(h, entry_hash(id, 0, &ev, 100, None));
        // Each field independently changes the hash.
        assert_ne!(h, entry_hash("agent-b", 0, &ev, 100, None)); // identity
        assert_ne!(h, entry_hash(id, 1, &ev, 100, None)); // seq
        assert_ne!(h, entry_hash(id, 0, &ev, 101, None)); // ts
        assert_ne!(h, entry_hash(id, 0, &ev, 100, Some(rh(7)))); // prev
        let ev_w = CreditEvent::honest_settlement(1_001, rh(1));
        assert_ne!(h, entry_hash(id, 0, &ev_w, 100, None)); // weight
        let ev_p = CreditEvent::caught_defection(1_000, rh(1));
        assert_ne!(h, entry_hash(id, 0, &ev_p, 100, None)); // polarity/dimension
        let ev_r = CreditEvent::honest_settlement(1_000, rh(2));
        assert_ne!(h, entry_hash(id, 0, &ev_r, 100, None)); // receipt_hash
    }

    #[test]
    fn absent_prev_uses_32_zero_bytes() {
        let id = "agent-a";
        let ev = CreditEvent::honest_settlement(1_000, rh(1));
        let absent = canonical_entry_bytes(id, 0, &ev, 100, None);
        let zeroed = canonical_entry_bytes(id, 0, &ev, 100, Some([0u8; 32]));
        // A genesis (None prev) hashes identically to an explicit all-zero prev:
        // the canonical encoding substitutes 32 zero bytes for an absent prev.
        assert_eq!(absent, zeroed);
        assert_eq!(&absent[absent.len() - 32..], &[0u8; 32]);
    }

    #[test]
    fn tamper_mutated_field_without_rehash_is_bad_hash() {
        let mut chain = build_chain("agent-a", 3);
        // Mutate the event weight on entry 1 but DO NOT recompute this_hash.
        chain[1].event.weight_micro += 1;
        assert_eq!(verify_chain(&chain), Err(ChainError::BadHash { seq: 1 }));
    }

    #[test]
    fn tamper_repointed_link_is_broken_link() {
        let mut chain = build_chain("agent-a", 3);
        // Re-point entry 2's back-link to entry 0 (a real prior hash) — the link
        // no longer matches its actual predecessor (entry 1).
        chain[2].prev_hash = Some(chain[0].this_hash);
        assert_eq!(verify_chain(&chain), Err(ChainError::BrokenLink { seq: 2 }));
    }

    #[test]
    fn tamper_dropped_entry_is_detected() {
        let mut chain = build_chain("agent-a", 4);
        // Drop the middle entry: seq jumps 1 -> 3, a gap.
        chain.remove(2);
        assert_eq!(
            verify_chain(&chain),
            Err(ChainError::SeqGap {
                expected: 2,
                found: 3
            })
        );
    }

    #[test]
    fn tamper_reordered_entries_is_detected() {
        let mut chain = build_chain("agent-a", 4);
        chain.swap(1, 2); // now seqs go 0,2,1,3
        assert_eq!(
            verify_chain(&chain),
            Err(ChainError::SeqGap {
                expected: 1,
                found: 2
            })
        );
    }

    #[test]
    fn tamper_genesis_prev_set_is_detected() {
        let mut chain = build_chain("agent-a", 2);
        chain[0].prev_hash = Some(rh(9)); // genesis must have None
        assert_eq!(verify_chain(&chain), Err(ChainError::GenesisNotNone));
    }

    #[test]
    fn tamper_mixed_identities_is_detected() {
        let mut a = build_chain("agent-a", 2);
        let b = build_chain("agent-b", 1);
        a.push(b.into_iter().next().unwrap()); // a foreign entry spliced in
                                               // Identity is the most fundamental invariant, so it is checked first:
                                               // a foreign-identity entry is caught as IdentityMismatch.
        assert_eq!(verify_chain(&a), Err(ChainError::IdentityMismatch));
    }

    #[test]
    fn identity_mismatch_when_seq_aligned() {
        // Two entries with consecutive seqs but different identities: the
        // identity guard fires even when ordering/linkage would otherwise line
        // up.
        let a0 = LedgerEntry::new(
            "agent-a".into(),
            0,
            CreditEvent::honest_settlement(1, rh(0)),
            100,
            None,
        );
        // seq 1, validly linked to a0, but a DIFFERENT identity.
        let b1 = LedgerEntry::new(
            "agent-b".into(),
            1,
            CreditEvent::honest_settlement(1, rh(1)),
            101,
            Some(a0.this_hash),
        );
        assert_eq!(verify_chain(&[a0, b1]), Err(ChainError::IdentityMismatch));
    }
}
