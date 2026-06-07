//! Durable, append-only, per-identity credit ledger backed by an embedded redb
//! database. Gated behind the off-by-default `persist` feature so the default
//! build and the wasm32 verify SDK never compile redb.
//!
//! # Design
//!
//! Two typed tables (composite keys, NOT the O(n) read-modify-write JSON-`Vec`
//! blob pattern, and NOT a `MultimapTable` which would sort + dedup values and
//! destroy log order):
//!
//! * `credit_entries: (identity, seq) -> JSON(LedgerEntry)`. redb sorts tuple
//!   keys lexicographically, so a range over `(id, 0)..=(id, u64::MAX)` yields
//!   exactly one identity's entries in `seq` order; each append is an
//!   `O(log n)` single-row insert.
//! * `credit_seen: (identity, receipt_hash) -> first seq`. `O(log n)`
//!   per-identity dedup, because [`crate::CreditFile::observe`] is NOT
//!   idempotent — a re-submitted receipt would otherwise double-count.
//!
//! # Atomic append (the compare-and-swap)
//!
//! The whole read-compute-write — read the last `seq`, check the dedup table,
//! compute the back-link, insert both rows — happens inside ONE
//! `begin_write` transaction. redb serializes write transactions (single
//! writer), so this single txn IS the compare-and-swap that stops two
//! concurrent appends from forking the chain; no separate CAS primitive is
//! needed.
//!
//! # Durability
//!
//! [`Database::create`] then one write txn materializes both tables (so the
//! first read never hits a missing table). Each append commits with redb's
//! `Durability::Immediate` default (fsync per commit) — fine at the expected
//! sub-1-QPS accrual rate. Reopening the file rebuilds full state from disk;
//! nothing is held only in memory.
//!
//! # Honesty boundary (do NOT overclaim)
//!
//! See [`crate::ledger`]: this is intra-ledger immutability + ordering +
//! per-identity gap detection + append-extension verification against a head the
//! consumer previously retained ([`CreditLedgerStore::head`]), and
//! [`CreditLedgerStore::credit_file`] refuses to price a chain that fails
//! [`verify_chain`]. It is NOT a transparency log (no non-equivocation, no
//! sublinear proofs, no third-party append-only guarantee) until each head is
//! Merkle-anchored (`nucleus-lineage` `MerkleSink` / `SignedTreeHead`) and
//! witness-cosigned (`nucleus-witness` C2SP server).
//!
//! The store key (`identity`) is a caller-supplied `&str` — none of
//! [`CreditEvent`] / [`CreditFile`] / `ClearingReceipt` carries one. This crate
//! stays identity-agnostic on purpose; binding the key to an authenticated
//! principal is the caller's job. The HTTP front-end
//! (`nucleus-verifier-service`) now does exactly that: `POST
//! /v1/credit/{agent_id}/accrue` requires a detached Ed25519 signature over the
//! request body and passes the DERIVED `hex(verifying_key)` as `identity`, so
//! standing is no longer self-asserted and cross-identity double-claim of a
//! receipt is prevented (an attacker can mint keys but cannot accrue under an
//! identity it does not control). A different front-end MUST apply the same
//! discipline before its standing can price real bonds.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use thiserror::Error;

use crate::ledger::{verify_chain, LedgerEntry};
use crate::{CreditEvent, CreditFile};

/// `(identity, seq) -> JSON(LedgerEntry)`. Tuple keys sort lexicographically, so
/// a range scan over one identity is contiguous and `seq`-ordered.
const ENTRIES: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("credit_entries");
/// `(identity, receipt_hash) -> first seq seen`. Per-identity dedup.
const SEEN: TableDefinition<(&str, &[u8]), u64> = TableDefinition::new("credit_seen");

/// Errors the credit ledger store surfaces. Mirrors the house redb
/// error-mapping (`nucleus-auction-hub-server` / `nucleus-oauth`) so the
/// `#[from]` conversions are identical.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Opening / creating the database failed.
    #[error("storage open: {0}")]
    StorageOpen(#[from] redb::DatabaseError),
    /// Beginning a read or write transaction failed.
    #[error("storage transaction: {0}")]
    StorageTransaction(#[from] redb::TransactionError),
    /// Opening a table failed.
    #[error("storage table: {0}")]
    StorageTable(#[from] redb::TableError),
    /// A read/write/iteration storage operation failed.
    #[error("storage io: {0}")]
    StorageIo(#[from] redb::StorageError),
    /// Committing the write transaction failed.
    #[error("storage commit: {0}")]
    StorageCommit(#[from] redb::CommitError),
    /// (De)serializing a [`LedgerEntry`] failed.
    #[error("encode: {0}")]
    Encode(#[from] serde_json::Error),
    /// The persisted chain failed [`verify_chain`] — the store refuses to price
    /// a tampered ledger.
    #[error("corrupt chain: {0}")]
    CorruptChain(#[from] crate::ledger::ChainError),
}

/// A durable, append-only, per-identity credit ledger.
///
/// `redb::Database` is `Send + Sync` (single-writer / multiple-reader) but not
/// `Clone`, so share it as `Arc<CreditLedgerStore>` when embedding in a
/// `Clone` application state.
pub struct CreditLedgerStore {
    db: Database,
}

impl CreditLedgerStore {
    /// Open (or create) the ledger at `path`, materializing both tables in one
    /// write txn so the first read never errors on a missing table.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let db = Database::create(path)?;
        let w = db.begin_write()?;
        {
            let _ = w.open_table(ENTRIES)?;
            let _ = w.open_table(SEEN)?;
        }
        w.commit()?;
        Ok(Self { db })
    }

    /// Append `event` to `identity`'s chain at timestamp `ts_unix_secs`,
    /// returning the new [`LedgerEntry`] — or `Ok(None)` if the event's
    /// `receipt_hash` was already recorded for this identity (dedup; a no-op).
    ///
    /// The read-compute-write is one write transaction (see module docs: the
    /// CAS that prevents a forked chain).
    pub fn append_at(
        &self,
        identity: &str,
        event: CreditEvent,
        ts_unix_secs: i64,
    ) -> Result<Option<LedgerEntry>, StoreError> {
        let w = self.db.begin_write()?;
        let appended;
        {
            let mut entries = w.open_table(ENTRIES)?;
            let mut seen = w.open_table(SEEN)?;

            if seen
                .get((identity, event.receipt_hash.as_slice()))?
                .is_some()
            {
                // Already counted this receipt for this identity — skip.
                appended = None;
            } else {
                // Last seq for this identity. Scope the range iterator so its
                // immutable borrow of `entries` is released before the insert.
                let last: Option<u64> = {
                    let mut it = entries.range((identity, 0u64)..=(identity, u64::MAX))?;
                    match it.next_back() {
                        Some(row) => Some(row?.0.value().1),
                        None => None,
                    }
                };
                // Back-link to the predecessor's this_hash. Scope the read guard
                // so it drops before the insert.
                let prev: Option<[u8; 32]> = match last {
                    Some(s) => {
                        let guard = entries
                            .get((identity, s))?
                            .expect("entry at the last recorded seq must exist");
                        Some(serde_json::from_slice::<LedgerEntry>(guard.value())?.this_hash)
                    }
                    None => None,
                };
                let seq = last.map_or(0, |s| s.saturating_add(1));
                let entry = LedgerEntry::new(identity.to_string(), seq, event, ts_unix_secs, prev);
                let bytes = serde_json::to_vec(&entry)?;
                entries.insert((identity, seq), bytes.as_slice())?;
                seen.insert((identity, event.receipt_hash.as_slice()), seq)?;
                appended = Some(entry);
            }
        }
        w.commit()?;
        Ok(appended)
    }

    /// [`CreditLedgerStore::append_at`] with the current wall-clock time
    /// (`SystemTime::now`; no `chrono` dependency).
    pub fn append(
        &self,
        identity: &str,
        event: CreditEvent,
    ) -> Result<Option<LedgerEntry>, StoreError> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.append_at(identity, event, ts)
    }

    /// All of `identity`'s entries, in `seq` order (range scan over one
    /// identity's contiguous key range). Empty for an unknown identity.
    pub fn entries(&self, identity: &str) -> Result<Vec<LedgerEntry>, StoreError> {
        let r = self.db.begin_read()?;
        let table = r.open_table(ENTRIES)?;
        let mut out = Vec::new();
        for row in table.range((identity, 0u64)..=(identity, u64::MAX))? {
            let (_, value) = row?;
            out.push(serde_json::from_slice::<LedgerEntry>(value.value())?);
        }
        Ok(out)
    }

    /// `identity`'s current head: the last `(seq, this_hash)`, or `None` if the
    /// identity has no entries. The `this_hash` is the portable commitment a
    /// consumer retains to detect a later prefix rewrite (append-extension
    /// check).
    pub fn head(&self, identity: &str) -> Result<Option<(u64, [u8; 32])>, StoreError> {
        let r = self.db.begin_read()?;
        let table = r.open_table(ENTRIES)?;
        let mut it = table.range((identity, 0u64)..=(identity, u64::MAX))?;
        match it.next_back() {
            Some(row) => {
                let (_, value) = row?;
                let entry: LedgerEntry = serde_json::from_slice(value.value())?;
                Ok(Some((entry.seq, entry.this_hash)))
            }
            None => Ok(None),
        }
    }

    /// `identity`'s [`CreditFile`], re-folded from its persisted raw events
    /// after [`verify_chain`] passes. Returns [`StoreError::CorruptChain`] if
    /// the persisted chain is tampered — the store refuses to price it.
    ///
    /// The fold is the crate's proven commutative monoid, so re-folding the
    /// persisted events is value-identical to the stateless
    /// [`crate::mint::credit_file_from_receipts`] path.
    pub fn credit_file(&self, identity: &str) -> Result<CreditFile, StoreError> {
        let entries = self.entries(identity)?;
        verify_chain(&entries)?;
        let events: Vec<CreditEvent> = entries.iter().map(|e| e.event).collect();
        Ok(CreditFile::from_events(&events))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::ChainError;

    fn rh(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn durable_across_drop_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credit.redb");
        let head_a;
        {
            let store = CreditLedgerStore::open(&path).unwrap();
            store
                .append("agent-a", CreditEvent::honest_settlement(400_000, rh(1)))
                .unwrap();
            store
                .append("agent-a", CreditEvent::honest_settlement(300_000, rh(2)))
                .unwrap();
            store
                .append("agent-b", CreditEvent::honest_settlement(50_000, rh(3)))
                .unwrap();
            assert_eq!(
                store.credit_file("agent-a").unwrap().reputation_micro(),
                700_000
            );
            head_a = store.head("agent-a").unwrap();
            // store dropped here — DB handle closed, nothing kept in memory.
        }

        // Reopen the SAME file: state survives.
        let store = CreditLedgerStore::open(&path).unwrap();
        let a = store.entries("agent-a").unwrap();
        let b = store.entries("agent-b").unwrap();
        assert_eq!(a.len(), 2);
        assert_eq!(b.len(), 1);
        assert_eq!((a[0].seq, a[1].seq), (0, 1));
        assert_eq!(
            store.credit_file("agent-a").unwrap().reputation_micro(),
            700_000
        );
        assert_eq!(store.head("agent-a").unwrap(), head_a);
        // The persisted chain still verifies.
        assert!(verify_chain(&a).is_ok());
    }

    #[test]
    fn dedup_is_per_identity_and_append_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credit.redb");
        let store = CreditLedgerStore::open(&path).unwrap();
        let ev = CreditEvent::honest_settlement(500_000, rh(7));

        let first = store.append("agent-a", ev).unwrap();
        assert!(first.is_some());
        // Re-submitting the same receipt_hash is a no-op (observe() is NOT
        // idempotent, so this guards against double-counting).
        let second = store.append("agent-a", ev).unwrap();
        assert!(second.is_none());
        assert_eq!(store.entries("agent-a").unwrap().len(), 1);
        assert_eq!(
            store.credit_file("agent-a").unwrap().reputation_micro(),
            500_000
        );

        // The SAME receipt_hash under a DIFFERENT identity is NOT deduped:
        // dedup is per-identity BY DESIGN (this crate is identity-agnostic; the
        // store key is an opaque `&str`). Driving the store with a second
        // identity is the caller's privilege — and the HTTP front-end now gates
        // it behind a detached Ed25519 signature whose key IS the identity, so
        // an attacker cannot reach this line under an id it does not control.
        let other = store.append("agent-b", ev).unwrap();
        assert!(other.is_some());
        assert_eq!(store.entries("agent-b").unwrap().len(), 1);
    }

    #[test]
    fn identities_are_isolated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credit.redb");
        let store = CreditLedgerStore::open(&path).unwrap();
        store
            .append("agent-a", CreditEvent::honest_settlement(100_000, rh(1)))
            .unwrap();

        // agent-b has no rows, no standing, no head.
        assert!(store.entries("agent-b").unwrap().is_empty());
        assert_eq!(store.credit_file("agent-b").unwrap().reputation_micro(), 0);
        assert_eq!(store.head("agent-b").unwrap(), None);

        // agent-a's row never leaks into another identity's scan.
        let a = store.entries("agent-a").unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].identity, "agent-a");
    }

    #[test]
    fn head_advances_and_commits_to_the_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credit.redb");
        let store = CreditLedgerStore::open(&path).unwrap();
        assert_eq!(store.head("agent-a").unwrap(), None);
        let e0 = store
            .append("agent-a", CreditEvent::honest_settlement(1, rh(1)))
            .unwrap()
            .unwrap();
        assert_eq!(store.head("agent-a").unwrap(), Some((0, e0.this_hash)));
        let e1 = store
            .append("agent-a", CreditEvent::honest_settlement(2, rh(2)))
            .unwrap()
            .unwrap();
        assert_eq!(store.head("agent-a").unwrap(), Some((1, e1.this_hash)));
        assert_eq!(e1.prev_hash, Some(e0.this_hash));
    }

    #[test]
    fn credit_file_refuses_a_tampered_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credit.redb");
        {
            let store = CreditLedgerStore::open(&path).unwrap();
            store
                .append("agent-a", CreditEvent::honest_settlement(100_000, rh(1)))
                .unwrap();
        }
        // Hand-corrupt entry seq 0: flip the event weight but keep the STALE
        // this_hash, so verify_chain must reject it as BadHash.
        {
            let db = Database::create(&path).unwrap();
            let w = db.begin_write().unwrap();
            {
                let mut t = w.open_table(ENTRIES).unwrap();
                let raw = {
                    let g = t.get(("agent-a", 0u64)).unwrap().unwrap();
                    g.value().to_vec()
                };
                let mut entry: LedgerEntry = serde_json::from_slice(&raw).unwrap();
                entry.event.weight_micro += 1; // tamper; do NOT recompute this_hash
                let bytes = serde_json::to_vec(&entry).unwrap();
                t.insert(("agent-a", 0u64), bytes.as_slice()).unwrap();
            }
            w.commit().unwrap();
        }

        let store = CreditLedgerStore::open(&path).unwrap();
        let err = store.credit_file("agent-a").unwrap_err();
        assert!(matches!(
            err,
            StoreError::CorruptChain(ChainError::BadHash { seq: 0 })
        ));
    }

    // ── Mint correctness through the store (reuse, not reimplement) ───────────
    // Needs the `recompute` feature for the mint bridge + receipt types; on by
    // default, so present under the usual `cargo test --features persist`.

    #[cfg(feature = "recompute")]
    fn honest_settlement(
        price_micro: u64,
        delivered_bps: u64,
    ) -> nucleus_recompute::ClearingReceipt {
        use nucleus_econ_kernels::{classify, refund, seller_gross};
        nucleus_recompute::ClearingReceipt::Settlement(nucleus_recompute::SettlementClaim {
            price_micro,
            delivered_bps,
            verdict: classify(delivered_bps),
            seller_gross: seller_gross(price_micro, delivered_bps),
            refund: refund(price_micro, delivered_bps),
        })
    }

    #[cfg(feature = "recompute")]
    #[test]
    fn mint_through_store_credits_honest_debits_caught_skips_invalid() {
        use crate::mint::mint_event;
        use nucleus_econ_kernels::CommonsShare;
        use nucleus_recompute::{ClearingReceipt, CommonsClaim};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credit.redb");
        let store = CreditLedgerStore::open(&path).unwrap();

        // Honest settlement → financial credit; standing rises.
        let good = honest_settlement(1_000_000, 10_000);
        store
            .append("agent-a", mint_event(&good).expect("honest mints an event"))
            .unwrap();
        assert_eq!(
            store.credit_file("agent-a").unwrap().reputation_micro(),
            1_000_000
        );

        // Tampered settlement (seller_gross + 1, caught by recompute) → caught
        // defection; standing falls. Weight is the declared price (400k), not
        // the inflated claim.
        let mut tampered = honest_settlement(400_000, 10_000);
        if let ClearingReceipt::Settlement(ref mut c) = tampered {
            c.seller_gross += 1;
        }
        store
            .append(
                "agent-a",
                mint_event(&tampered).expect("a caught lie still mints a debit"),
            )
            .unwrap();
        assert_eq!(
            store.credit_file("agent-a").unwrap().reputation_micro(),
            600_000 // 1,000,000 credit − 400,000 debit
        );

        // Invalid commons receipt (bps != 10_000) mints nothing → no entry.
        let invalid = ClearingReceipt::Commons(CommonsClaim {
            pool_micro: 1_000,
            shares: vec![CommonsShare {
                destination: "x".into(),
                bps: 9_999,
            }],
            allocations: vec![],
        });
        assert!(mint_event(&invalid).is_none());
        assert_eq!(store.entries("agent-a").unwrap().len(), 2);
    }

    #[cfg(feature = "recompute")]
    #[test]
    fn durable_refold_matches_stateless_mint() {
        use crate::mint::{credit_file_from_receipts, mint_events};

        let receipts = vec![
            honest_settlement(400_000, 10_000),
            honest_settlement(300_000, 10_000),
        ];
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credit.redb");
        let store = CreditLedgerStore::open(&path).unwrap();
        for e in mint_events(&receipts) {
            store.append("agent-a", e).unwrap();
        }

        let durable = store.credit_file("agent-a").unwrap();
        let stateless = credit_file_from_receipts(&receipts);
        // Persisting + re-folding introduces NO divergence from the stateless,
        // recompute-only path — the durable money path runs the exact proven
        // required_bond.
        assert_eq!(durable.reputation_micro(), stateless.reputation_micro());
        assert_eq!(
            durable.required_bond(1_000_000),
            stateless.required_bond(1_000_000)
        );
        assert_eq!(durable.event_count(), stateless.event_count());
    }
}
