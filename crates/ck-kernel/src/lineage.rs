//! Lineage store — append-only record of admitted descendants.
//!
//! Every accepted amendment appends a record linking parent → child
//! with the witness bundle digest. The lineage is the replayable
//! audit trail of the system's self-amendment history.

use std::collections::HashSet;

use chrono::Utc;

use ck_types::witness::LineageRecord;
use ck_types::{ArtifactDigest, PatchClass};

/// Append-only lineage store.
///
/// Maintains an ordered list of admitted descendants and a set
/// for O(1) membership checks.
pub struct LineageStore {
    records: Vec<LineageRecord>,
    admitted: HashSet<String>,
    next_sequence: u64,
}

impl Default for LineageStore {
    fn default() -> Self {
        Self::new()
    }
}

impl LineageStore {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            admitted: HashSet::new(),
            next_sequence: 0,
        }
    }

    /// Admit the genesis artifact (root of the lineage).
    pub fn admit_genesis(&mut self, digest: ArtifactDigest) {
        let record = LineageRecord {
            sequence: self.next_sequence,
            parent_digest: digest.clone(),
            candidate_digest: digest.clone(),
            witness_digest: ArtifactDigest::from_bytes(b"genesis"),
            patch_class: PatchClass::Config,
            timestamp_utc: Utc::now(),
            admitted: true,
        };
        self.admitted.insert(digest.as_str().to_string());
        self.records.push(record);
        self.next_sequence += 1;
    }

    /// Append an admitted amendment to the lineage.
    pub fn append(
        &mut self,
        parent: ArtifactDigest,
        candidate: ArtifactDigest,
        witness_digest: ArtifactDigest,
        patch_class: PatchClass,
    ) -> LineageRecord {
        let record = LineageRecord {
            sequence: self.next_sequence,
            parent_digest: parent,
            candidate_digest: candidate.clone(),
            witness_digest,
            patch_class,
            timestamp_utc: Utc::now(),
            admitted: true,
        };
        self.admitted.insert(candidate.as_str().to_string());
        self.records.push(record.clone());
        self.next_sequence += 1;
        record
    }

    /// Check if a digest is in the admitted lineage.
    pub fn is_admitted(&self, digest: &ArtifactDigest) -> bool {
        self.admitted.contains(digest.as_str())
    }

    /// Number of records (including genesis).
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Get all lineage records.
    pub fn records(&self) -> &[LineageRecord] {
        &self.records
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_admitted() {
        let mut store = LineageStore::new();
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        store.admit_genesis(genesis.clone());
        assert!(store.is_admitted(&genesis));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_append_and_lookup() {
        let mut store = LineageStore::new();
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        store.admit_genesis(genesis.clone());

        let v1 = ArtifactDigest::from_bytes(b"v1");
        let witness = ArtifactDigest::from_bytes(b"w1");
        store.append(genesis.clone(), v1.clone(), witness, PatchClass::Config);

        assert!(store.is_admitted(&v1));
        assert_eq!(store.len(), 2);
        assert_eq!(store.records()[1].sequence, 1);
    }

    #[test]
    fn test_unknown_digest_not_admitted() {
        let mut store = LineageStore::new();
        store.admit_genesis(ArtifactDigest::from_bytes(b"genesis"));
        let unknown = ArtifactDigest::from_bytes(b"unknown");
        assert!(!store.is_admitted(&unknown));
    }

    #[test]
    fn test_sequence_monotonic() {
        let mut store = LineageStore::new();
        let g = ArtifactDigest::from_bytes(b"g");
        store.admit_genesis(g.clone());

        for i in 1..5 {
            let d = ArtifactDigest::from_bytes(format!("v{}", i).as_bytes());
            let w = ArtifactDigest::from_bytes(format!("w{}", i).as_bytes());
            store.append(g.clone(), d, w, PatchClass::Config);
        }

        for (i, rec) in store.records().iter().enumerate() {
            assert_eq!(rec.sequence, i as u64);
        }
    }
}
