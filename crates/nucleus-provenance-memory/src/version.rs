//! Versioned publication over content-addressed records.
//!
//! A memory space's published history is **linear and hash-chained**: each
//! [`Commit`] names its version `n = parent + 1`, the head hash of its parent and
//! the records it adds. The head hash is a domain-tagged SHA-256 over
//! `(parent head, version, the commit's records in content-hash order, publisher
//! binding, epoch)`. Records keep their own [`ContentHash`]; commit metadata lives
//! in the envelope, so no record hash changes when it is published.
//!
//! A [`Pin`] is `(version, head)`: what a reader observed, and what a publisher
//! expects the head to still be (compare-and-swap). A [`Patch`] is a branch's
//! additions over the pin it was taken from. Publishing validates the **whole
//! candidate** — the current head plus the patch — through a
//! [`CandidateValidator`]; [`StoreInvariants`] is the store's own validator
//! (label monotonicity, keyed conflicts, record and byte caps). Validating each
//! patch alone is not enough: two disjoint six-record patches over a ten-record
//! cap are each fine and together are not.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crdt::{ProvenanceMemorySet, label_not_lower};
use crate::hash::ContentHash;
use crate::record::MemoryRecord;

/// Domain tag for the head of version 0 of a space (no commits yet).
const GENESIS_DOMAIN: &[u8] = b"nucleus-provenance-memory/genesis/v2\0";
/// Domain tag for a commit's head hash.
const COMMIT_DOMAIN: &[u8] = b"nucleus-provenance-memory/commit/v2\0";
/// Domain tag for the publisher identity of the v1 -> v2 migration commit.
const MIGRATION_PUBLISHER_DOMAIN: &[u8] = b"nucleus-provenance-memory/publisher/v1-migration\0";
/// Domain tag for the publisher identity of an operator-direct write.
const OPERATOR_PUBLISHER_DOMAIN: &[u8] = b"nucleus-provenance-memory/publisher/operator-direct\0";

fn tagged(domain: &[u8], body: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(body);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn parse_hex32(s: &str, what: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(s).map_err(|e| format!("{what} hex decode: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{what} must be 32 bytes"))
}

/// The head of a published history: the genesis hash of an empty space, or the
/// hash of its latest [`Commit`]. Minted only by hashing; the wire form is hex
/// and is a claim until a commit chain recomputes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct HeadHash([u8; 32]);

impl HeadHash {
    /// The head of version 0 of `space`. Binding the space name means one
    /// space's history cannot be replayed as another's.
    pub fn genesis(space: &str) -> Self {
        Self(tagged(GENESIS_DOMAIN, space.as_bytes()))
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex (64 characters).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl TryFrom<String> for HeadHash {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        parse_hex32(&s, "head hash").map(Self)
    }
}

impl From<HeadHash> for String {
    fn from(h: HeadHash) -> String {
        h.to_hex()
    }
}

/// The opaque identity of whoever published a commit. The node mints binding
/// identities; this crate only carries and hashes them. No `Default`: an absent
/// publisher is not a publisher (ADR 0007 B-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PublisherBinding([u8; 32]);

impl PublisherBinding {
    /// A binding identity minted elsewhere (the node, per run).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The fixed identity of the commit that carries a v1 journal's records into v2.
    pub fn v1_migration() -> Self {
        Self(tagged(MIGRATION_PUBLISHER_DOMAIN, &[]))
    }

    /// The fixed identity of a write the operator-configured proxy made directly,
    /// not under a node-minted binding.
    pub fn operator_direct() -> Self {
        Self(tagged(OPERATOR_PUBLISHER_DOMAIN, &[]))
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl TryFrom<String> for PublisherBinding {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        parse_hex32(&s, "publisher binding").map(Self)
    }
}

impl From<PublisherBinding> for String {
    fn from(p: PublisherBinding) -> String {
        hex::encode(p.0)
    }
}

/// The policy epoch a commit was published under. Opaque here; the node bumps it
/// to revoke. No `Default` (ADR 0007 B-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Epoch(u64);

impl Epoch {
    /// The epoch of writes that no node-minted binding governs: the v1 migration
    /// and operator-direct writes.
    pub const PRE_BINDING: Epoch = Epoch(0);

    /// An epoch value minted elsewhere.
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// The raw value.
    pub fn get(&self) -> u64 {
        self.0
    }
}

/// A position in a published history: version `n` and the head hash at `n`.
/// What a pinned reader observed, and what a publisher expects (CAS).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    version: u64,
    head: HeadHash,
}

impl Pin {
    /// A claimed position; checked against the history before it is relied on.
    pub fn new(version: u64, head: HeadHash) -> Self {
        Self { version, head }
    }

    /// Version 0 of `space`.
    pub fn genesis(space: &str) -> Self {
        Self {
            version: 0,
            head: HeadHash::genesis(space),
        }
    }

    /// The version number.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The head hash at that version.
    pub fn head(&self) -> HeadHash {
        self.head
    }
}

/// Why a commit could not be sealed or does not follow its parent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommitError {
    /// A commit adds at least one record.
    #[error("a commit must add at least one record")]
    Empty,
    /// One record appears twice in one commit.
    #[error("record {} appears twice in one commit", .0.to_hex())]
    DuplicateRecord(ContentHash),
    /// The version counter cannot advance.
    #[error("version counter overflow")]
    VersionOverflow,
    /// The commit is not the parent's successor.
    #[error("commit version {found} does not follow version {parent}")]
    NotNext {
        /// The parent's version.
        parent: u64,
        /// The version the commit claims.
        found: u64,
    },
    /// The commit names a different parent head.
    #[error("commit names a different parent head")]
    ParentMismatch,
    /// The stored head hash is not the hash of the commit's contents.
    #[error("commit hash does not match its contents")]
    HashMismatch,
    /// A record label could not be encoded for hashing.
    #[error("record label encoding failed: {0}")]
    Encoding(String),
}

/// One published version: the records it adds over its parent, and the
/// head hash that chains it. The wire form is a claim; [`Commit::verify`]
/// recomputes it against the parent the reader already holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commit {
    version: u64,
    parent_head: HeadHash,
    /// Admission order: a derived record follows the records it cites.
    records: Vec<MemoryRecord>,
    publisher: PublisherBinding,
    epoch: Epoch,
    commit_hash: HeadHash,
}

impl Commit {
    /// Seal the successor of `parent` adding `records` (in admission order).
    pub fn seal(
        parent: Pin,
        records: Vec<MemoryRecord>,
        publisher: PublisherBinding,
        epoch: Epoch,
    ) -> Result<Self, CommitError> {
        let version = parent
            .version
            .checked_add(1)
            .ok_or(CommitError::VersionOverflow)?;
        let commit_hash = head_hash(parent.head, version, &records, publisher, epoch)?;
        Ok(Self {
            version,
            parent_head: parent.head,
            records,
            publisher,
            epoch,
            commit_hash,
        })
    }

    /// Check this commit is `parent`'s successor and that its head hash is the
    /// hash of its contents. Returns the new position.
    pub fn verify(&self, parent: &Pin) -> Result<Pin, CommitError> {
        let next = parent
            .version
            .checked_add(1)
            .ok_or(CommitError::VersionOverflow)?;
        if self.version != next {
            return Err(CommitError::NotNext {
                parent: parent.version,
                found: self.version,
            });
        }
        if self.parent_head != parent.head {
            return Err(CommitError::ParentMismatch);
        }
        let recomputed = head_hash(
            self.parent_head,
            self.version,
            &self.records,
            self.publisher,
            self.epoch,
        )?;
        if recomputed != self.commit_hash {
            return Err(CommitError::HashMismatch);
        }
        Ok(self.head())
    }

    /// The position this commit creates.
    pub fn head(&self) -> Pin {
        Pin {
            version: self.version,
            head: self.commit_hash,
        }
    }

    /// The records it adds, in admission order.
    pub fn records(&self) -> &[MemoryRecord] {
        &self.records
    }

    /// Who published it.
    pub fn publisher(&self) -> PublisherBinding {
        self.publisher
    }

    /// The epoch it was published under.
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }
}

/// The head hash: parent, version, each record's content hash and label in
/// content-hash order, publisher, epoch. The label is bound even though the
/// content hash excludes it, so a relabelled line breaks the chain as well as
/// failing replay.
fn head_hash(
    parent: HeadHash,
    version: u64,
    records: &[MemoryRecord],
    publisher: PublisherBinding,
    epoch: Epoch,
) -> Result<HeadHash, CommitError> {
    if records.is_empty() {
        return Err(CommitError::Empty);
    }
    let mut entries = std::collections::BTreeMap::new();
    for record in records {
        let hash = record.content_hash();
        let label =
            serde_json::to_vec(&record.label).map_err(|e| CommitError::Encoding(e.to_string()))?;
        if entries.insert(hash, label).is_some() {
            return Err(CommitError::DuplicateRecord(hash));
        }
    }
    let count = u64::try_from(entries.len()).map_err(|_| CommitError::VersionOverflow)?;
    let mut h = Sha256::new();
    h.update(COMMIT_DOMAIN);
    h.update(parent.0);
    h.update(version.to_be_bytes());
    h.update(count.to_be_bytes());
    for (hash, label) in &entries {
        let len = u64::try_from(label.len()).map_err(|_| CommitError::VersionOverflow)?;
        h.update(hash.as_bytes());
        h.update(len.to_be_bytes());
        h.update(label);
    }
    h.update(publisher.0);
    h.update(epoch.0.to_be_bytes());
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(HeadHash(out))
}

/// A branch's additions over the pin it was taken from, plus the keys the
/// proposer explicitly resolves against concurrent publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Patch {
    base: Pin,
    records: Vec<MemoryRecord>,
    resolved: BTreeSet<ContentHash>,
}

impl Patch {
    /// Additions (admission order) over `base`.
    pub fn new(base: Pin, records: Vec<MemoryRecord>) -> Self {
        Self {
            base,
            records,
            resolved: BTreeSet::new(),
        }
    }

    /// Explicitly supersede a key that was also published after `base`. Without
    /// it, such an overlap is a keyed conflict.
    pub fn resolve(mut self, key: ContentHash) -> Self {
        self.resolved.insert(key);
        self
    }

    /// The pin the patch was taken from.
    pub fn base(&self) -> Pin {
        self.base
    }

    /// The additions, in admission order.
    pub fn records(&self) -> &[MemoryRecord] {
        &self.records
    }

    /// Whether `key` was explicitly resolved.
    pub fn is_resolved(&self, key: &ContentHash) -> bool {
        self.resolved.contains(key)
    }
}

/// The whole candidate a publish would produce: the current head's records, the
/// keys published after the patch's base, the patch's additions that differ from
/// the head, and the journal's size once the commit is appended.
#[derive(Debug, Clone, Copy)]
pub struct Candidate<'a> {
    /// Records at the current head.
    pub head: &'a ProvenanceMemorySet,
    /// Content hashes published after the patch's base (the concurrent writes).
    pub concurrent: &'a BTreeSet<ContentHash>,
    /// The patch being published.
    pub patch: &'a Patch,
    /// The patch's records not already present, identically, at the head.
    pub additions: &'a [MemoryRecord],
    /// Journal size in bytes after the commit is appended.
    pub journal_bytes: u64,
}

/// Why a candidate is not a valid next state.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CandidateRefusal {
    /// A record would replace an existing one with a lower label.
    #[error("record {} would lower its label", .hash.to_hex())]
    LabelLowered {
        /// The record's content hash.
        hash: ContentHash,
    },
    /// A key was published concurrently and the patch did not resolve it.
    #[error("record {} was published concurrently and is not resolved", .hash.to_hex())]
    KeyedConflict {
        /// The record's content hash.
        hash: ContentHash,
    },
    /// The candidate holds more records than the space allows.
    #[error("candidate holds {records} records; the cap is {cap}")]
    RecordCap {
        /// Records in the candidate.
        records: usize,
        /// The cap.
        cap: usize,
    },
    /// The journal would exceed its byte cap.
    #[error("journal would hold {bytes} bytes; the cap is {cap}")]
    ByteCap {
        /// Journal bytes after the commit.
        bytes: u64,
        /// The cap.
        cap: u64,
    },
    /// A record lies outside what the publisher's binding may write: a schema
    /// outside its view's scope. Decided by a caller's validator over the
    /// publisher's own additions.
    #[error("record {} is outside the publisher's view", .hash.to_hex())]
    OutsideView {
        /// The record's content hash.
        hash: ContentHash,
    },
    /// The commit would spend more than the publisher's own allocation. Decided by
    /// a caller's validator from the publisher's allocation alone, so the verdict
    /// does not depend on what anyone else holds (a budget split, not a global
    /// count).
    #[error("the commit spends {spend} bytes; the publisher has {allocation} left")]
    AllocationExceeded {
        /// Bytes this commit adds to the journal.
        spend: u64,
        /// What remains of the publisher's allocation.
        allocation: u64,
    },
}

/// Validates a whole candidate before it is committed. The pure memory-context
/// kernel's `validate_candidate` plugs in here; [`StoreInvariants`] is the
/// store's own.
pub trait CandidateValidator {
    /// `Ok` only if the candidate is a valid next state.
    fn validate(&self, candidate: &Candidate<'_>) -> Result<(), CandidateRefusal>;
}

/// The store's invariants: no label lowers, no unresolved keyed conflict, and
/// the record and byte caps hold for the whole candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreInvariants {
    max_records: usize,
    max_journal_bytes: u64,
}

impl StoreInvariants {
    /// Caps on the candidate's record count and the journal's size.
    pub fn new(max_records: usize, max_journal_bytes: u64) -> Self {
        Self {
            max_records,
            max_journal_bytes,
        }
    }
}

impl CandidateValidator for StoreInvariants {
    fn validate(&self, candidate: &Candidate<'_>) -> Result<(), CandidateRefusal> {
        let mut fresh = 0usize;
        for record in candidate.additions {
            let hash = record.content_hash();
            match candidate.head.get(&hash) {
                Some(existing) => {
                    if candidate.concurrent.contains(&hash) && !candidate.patch.is_resolved(&hash) {
                        return Err(CandidateRefusal::KeyedConflict { hash });
                    }
                    if !label_not_lower(&existing.label, &record.label) {
                        return Err(CandidateRefusal::LabelLowered { hash });
                    }
                }
                None => fresh = fresh.saturating_add(1),
            }
        }
        let records = candidate.head.len().saturating_add(fresh);
        if records > self.max_records {
            return Err(CandidateRefusal::RecordCap {
                records,
                cap: self.max_records,
            });
        }
        if candidate.journal_bytes > self.max_journal_bytes {
            return Err(CandidateRefusal::ByteCap {
                bytes: candidate.journal_bytes,
                cap: self.max_journal_bytes,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "version_tests.rs"]
mod tests;
