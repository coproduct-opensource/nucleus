//! Lineage store — append-only record of admitted descendants.
//!
//! Every accepted amendment appends a record linking parent → child
//! with the witness bundle digest. The lineage is the replayable
//! audit trail of the system's self-amendment history.

use std::collections::HashSet;

use chrono::Utc;

use ck_types::witness::{AdmissionMode, LineageRecord};
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

    /// Restore from persisted records.
    ///
    /// Accepts a list of lineage records (genesis + descendants) and
    /// rebuilds the in-memory state. Records must be ordered by sequence
    /// number and have monotonically increasing sequences.
    pub fn restore(records: Vec<LineageRecord>) -> Result<Self, String> {
        if records.is_empty() {
            return Err("Cannot restore from empty records".into());
        }

        let mut admitted = HashSet::new();
        let mut max_seq = 0u64;

        for (i, record) in records.iter().enumerate() {
            if i > 0 && record.sequence <= max_seq {
                return Err(format!(
                    "Sequence numbers must be monotonically increasing: {} <= {}",
                    record.sequence, max_seq
                ));
            }
            max_seq = record.sequence;
            admitted.insert(record.candidate_digest.as_str().to_string());
        }

        Ok(Self {
            next_sequence: max_seq + 1,
            admitted,
            records,
        })
    }

    /// Admit the genesis artifact (root of the lineage).
    pub fn admit_genesis(&mut self, digest: ArtifactDigest, git_commit_sha: Option<String>) {
        let record = LineageRecord {
            sequence: self.next_sequence,
            parent_digest: digest.clone(),
            candidate_digest: digest.clone(),
            witness_digest: ArtifactDigest::from_bytes(b"genesis"),
            patch_class: PatchClass::Config,
            timestamp_utc: Utc::now(),
            admitted: true,
            admission_mode: AdmissionMode::Genesis,
            git_commit_sha,
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
            admission_mode: AdmissionMode::OrdinarySelfAmendment,
            git_commit_sha: None,
        };
        self.admitted.insert(candidate.as_str().to_string());
        self.records.push(record.clone());
        self.next_sequence += 1;
        record
    }

    /// Append a constitutional amendment to the lineage.
    ///
    /// Constitutional amendments change TCB files and require human authorization.
    /// They are recorded with `AdmissionMode::ConstitutionalAmendment`.
    pub fn append_constitutional(
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
            admission_mode: AdmissionMode::ConstitutionalAmendment,
            git_commit_sha: None,
        };
        self.admitted.insert(candidate.as_str().to_string());
        self.records.push(record.clone());
        self.next_sequence += 1;
        record
    }

    /// Import an external commit as a trusted base into the lineage.
    ///
    /// Same as `append` but with `AdmissionMode::Imported` and an associated
    /// git commit SHA. Used when `main` advances out-of-band and the new HEAD
    /// must be explicitly adopted rather than silently auto-admitted.
    pub fn import(
        &mut self,
        parent: ArtifactDigest,
        candidate: ArtifactDigest,
        git_sha: String,
    ) -> LineageRecord {
        let record = LineageRecord {
            sequence: self.next_sequence,
            parent_digest: parent,
            candidate_digest: candidate.clone(),
            witness_digest: ArtifactDigest::from_bytes(b"imported"),
            patch_class: PatchClass::Config,
            timestamp_utc: Utc::now(),
            admitted: true,
            admission_mode: AdmissionMode::Imported,
            git_commit_sha: Some(git_sha),
        };
        self.admitted.insert(candidate.as_str().to_string());
        self.records.push(record.clone());
        self.next_sequence += 1;
        record
    }

    /// Get the most recent lineage record.
    pub fn latest_record(&self) -> Option<&LineageRecord> {
        self.records.last()
    }

    /// Get the digest of the latest admitted node.
    ///
    /// In the dual-DAG model, ordinary amendments MUST parent from this
    /// digest. This prevents out-of-band commits from silently becoming
    /// constitutional lineage ancestors.
    pub fn latest_admitted_digest(&self) -> Option<ArtifactDigest> {
        self.records.last().map(|r| r.candidate_digest.clone())
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
        store.admit_genesis(genesis.clone(), None);
        assert!(store.is_admitted(&genesis));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_append_and_lookup() {
        let mut store = LineageStore::new();
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        store.admit_genesis(genesis.clone(), None);

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
        store.admit_genesis(ArtifactDigest::from_bytes(b"genesis"), None);
        let unknown = ArtifactDigest::from_bytes(b"unknown");
        assert!(!store.is_admitted(&unknown));
    }

    #[test]
    fn test_restore_from_records() {
        let mut store = LineageStore::new();
        let g = ArtifactDigest::from_bytes(b"genesis");
        store.admit_genesis(g.clone(), None);

        let v1 = ArtifactDigest::from_bytes(b"v1");
        let w1 = ArtifactDigest::from_bytes(b"w1");
        store.append(g.clone(), v1.clone(), w1, PatchClass::Config);

        let v2 = ArtifactDigest::from_bytes(b"v2");
        let w2 = ArtifactDigest::from_bytes(b"w2");
        store.append(v1.clone(), v2.clone(), w2, PatchClass::Controller);

        // Restore from the records
        let records = store.records().to_vec();
        let restored = LineageStore::restore(records).unwrap();

        assert_eq!(restored.len(), 3);
        assert!(restored.is_admitted(&g));
        assert!(restored.is_admitted(&v1));
        assert!(restored.is_admitted(&v2));
        assert!(!restored.is_admitted(&ArtifactDigest::from_bytes(b"unknown")));

        // New appends should continue from the correct sequence
        let mut restored = restored;
        let v3 = ArtifactDigest::from_bytes(b"v3");
        let w3 = ArtifactDigest::from_bytes(b"w3");
        let record = restored.append(v2, v3.clone(), w3, PatchClass::Config);
        assert_eq!(record.sequence, 3);
        assert!(restored.is_admitted(&v3));
    }

    #[test]
    fn test_restore_empty_fails() {
        let result = LineageStore::restore(vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_sequence_monotonic() {
        let mut store = LineageStore::new();
        let g = ArtifactDigest::from_bytes(b"g");
        store.admit_genesis(g.clone(), None);

        for i in 1..5 {
            let d = ArtifactDigest::from_bytes(format!("v{}", i).as_bytes());
            let w = ArtifactDigest::from_bytes(format!("w{}", i).as_bytes());
            store.append(g.clone(), d, w, PatchClass::Config);
        }

        for (i, rec) in store.records().iter().enumerate() {
            assert_eq!(rec.sequence, i as u64);
        }
    }

    #[test]
    fn test_genesis_with_git_sha() {
        let mut store = LineageStore::new();
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        store.admit_genesis(genesis.clone(), Some("abc123".into()));

        let record = store.latest_record().unwrap();
        assert_eq!(record.admission_mode, AdmissionMode::Genesis);
        assert_eq!(record.git_commit_sha.as_deref(), Some("abc123"));
    }

    #[test]
    fn test_import_creates_imported_record() {
        let mut store = LineageStore::new();
        let genesis = ArtifactDigest::from_bytes(b"genesis");
        store.admit_genesis(genesis.clone(), None);

        let imported = ArtifactDigest::from_bytes(b"imported-commit");
        let record = store.import(genesis, imported.clone(), "def456".into());

        assert_eq!(record.admission_mode, AdmissionMode::Imported);
        assert_eq!(record.git_commit_sha.as_deref(), Some("def456"));
        assert!(store.is_admitted(&imported));
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_latest_admitted_digest() {
        let mut store = LineageStore::new();
        let g = ArtifactDigest::from_bytes(b"g");
        store.admit_genesis(g.clone(), None);
        assert_eq!(store.latest_admitted_digest(), Some(g.clone()));

        let v1 = ArtifactDigest::from_bytes(b"v1");
        store.append(
            g,
            v1.clone(),
            ArtifactDigest::from_bytes(b"w1"),
            PatchClass::Config,
        );
        assert_eq!(store.latest_admitted_digest(), Some(v1));
    }

    #[test]
    fn test_latest_record() {
        let mut store = LineageStore::new();
        let g = ArtifactDigest::from_bytes(b"g");
        store.admit_genesis(g.clone(), None);

        assert_eq!(store.latest_record().unwrap().sequence, 0);

        let v1 = ArtifactDigest::from_bytes(b"v1");
        let w1 = ArtifactDigest::from_bytes(b"w1");
        store.append(g, v1, w1, PatchClass::Config);

        assert_eq!(store.latest_record().unwrap().sequence, 1);
        assert_eq!(
            store.latest_record().unwrap().admission_mode,
            AdmissionMode::OrdinarySelfAmendment
        );
    }
}
