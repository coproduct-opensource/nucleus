//! RFC 9162 Merkle tree over the verification log (#95).
//!
//! Sits alongside the chain-hash log from [`crate::log`]: every
//! `log_entries` row is also a leaf in a `MemoryBackedTree<Sha256>`.
//! At a given log size both representations commit to the same
//! ordering, but the Merkle tree is what unlocks inclusion +
//! consistency proofs — the canonical RFC 9162 / RFC 6962 primitives.
//!
//! # Iter status
//!
//! - iter-1 (#69): chain-hash only, descriptive — auditor replays
//!   the chain.
//! - iter-2 (#94): signed STH over the chain head, JWKS publication.
//! - iter-3 (#95, this module): RFC 9162 Merkle root + inclusion +
//!   consistency proofs, both surfaced on the STH endpoint AND on
//!   dedicated proof endpoints. The chain-hash STH stays in
//!   `root_hash_hex` for backward compatibility; new clients should
//!   prefer `merkle_root_hex`.
//!
//! # Cost note
//!
//! `MemoryBackedTree` is rebuilt from scratch at process startup by
//! replaying every `log_entries` row. For the v1 hosted service this
//! is fine — the log only grows by the verify rate (a few per second
//! at most) and a million-leaf rebuild takes well under a second on
//! the Fly shared CPU. Persistent on-disk Merkle state is a
//! follow-up if log size becomes a problem.

use std::sync::Arc;

use anyhow::{Context, Result};
use ct_merkle::mem_backed_tree::MemoryBackedTree;
use sha2::Sha256;
use sqlx::{Row, SqlitePool};
use tokio::sync::RwLock;

/// One Merkle log instance. Wrapped in `Arc<RwLock<_>>` inside
/// [`crate::app::AppState`] so handlers can read proofs concurrently
/// while only the verify path takes the writer lock to append.
pub struct MerkleLog {
    tree: MemoryBackedTree<Sha256, Vec<u8>>,
}

impl MerkleLog {
    /// Construct a fresh empty log.
    pub fn empty() -> Self {
        Self {
            tree: MemoryBackedTree::default(),
        }
    }

    /// Replay every `log_entries` row in seq order into a fresh
    /// Merkle tree. Called once at process startup so the in-memory
    /// tree is consistent with the persisted chain.
    pub async fn from_persisted_entries(pool: &SqlitePool) -> Result<Self> {
        let mut tree = MerkleLog::empty();
        let rows = sqlx::query("SELECT entry_hash FROM log_entries ORDER BY seq ASC")
            .fetch_all(pool)
            .await
            .context("loading log_entries for merkle rebuild")?;
        for row in rows {
            let entry_hash: Vec<u8> = row.get(0);
            tree.tree.push(entry_hash);
        }
        Ok(tree)
    }

    /// Append a leaf. The verify handler calls this AFTER the
    /// `log_entries` INSERT commits so the in-memory tree and the
    /// persisted chain agree.
    pub fn push(&mut self, entry_hash: &[u8; 32]) {
        self.tree.push(entry_hash.to_vec());
    }

    /// Current leaf count.
    pub fn size(&self) -> usize {
        // ct-merkle's MemoryBackedTree exposes `len()` via the
        // underlying leaves; root().num_leaves() is the spec-stable
        // accessor.
        self.tree.root().num_leaves() as usize
    }

    /// Current root, hex-encoded SHA-256.
    pub fn root_hex(&self) -> String {
        hex::encode(self.tree.root().as_bytes())
    }

    /// Inclusion proof for the leaf at `idx`. Returns the
    /// RFC 9162 / RFC 6962 audit path bytes (concatenated 32-byte
    /// SHA-256 nodes, leaf-to-root). Returns `None` when `idx`
    /// is out of range — the route layer maps that to 404.
    pub fn inclusion_proof(&self, idx: usize) -> Option<Vec<u8>> {
        if idx >= self.size() {
            return None;
        }
        Some(self.tree.prove_inclusion(idx).as_bytes().to_vec())
    }

    /// Consistency proof between `from_size` and the current size.
    /// Returns `None` when `from_size` is in the future (> current)
    /// or zero (no prior commitment to prove from).
    pub fn consistency_proof(&self, from_size: usize) -> Option<Vec<u8>> {
        let current = self.size();
        if from_size == 0 || from_size > current {
            return None;
        }
        let num_additions = current - from_size;
        Some(
            self.tree
                .prove_consistency(num_additions)
                .as_bytes()
                .to_vec(),
        )
    }
}

/// Convenience type for AppState — handlers share a single tree.
pub type SharedMerkleLog = Arc<RwLock<MerkleLog>>;

#[cfg(test)]
mod tests {
    use super::*;

    fn h(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn empty_log_has_zero_size() {
        let log = MerkleLog::empty();
        assert_eq!(log.size(), 0);
    }

    #[test]
    fn push_increases_size() {
        let mut log = MerkleLog::empty();
        log.push(&h(1));
        log.push(&h(2));
        log.push(&h(3));
        assert_eq!(log.size(), 3);
    }

    #[test]
    fn root_changes_on_each_push() {
        let mut log = MerkleLog::empty();
        let r0 = log.root_hex();
        log.push(&h(1));
        let r1 = log.root_hex();
        log.push(&h(2));
        let r2 = log.root_hex();
        assert_ne!(r0, r1);
        assert_ne!(r1, r2);
    }

    #[test]
    fn inclusion_proof_for_in_range_index_is_some() {
        let mut log = MerkleLog::empty();
        log.push(&h(1));
        log.push(&h(2));
        log.push(&h(3));
        assert!(log.inclusion_proof(0).is_some());
        assert!(log.inclusion_proof(2).is_some());
    }

    #[test]
    fn inclusion_proof_for_out_of_range_is_none() {
        let mut log = MerkleLog::empty();
        log.push(&h(1));
        assert!(log.inclusion_proof(99).is_none());
    }

    #[test]
    fn consistency_proof_zero_from_is_none() {
        let mut log = MerkleLog::empty();
        log.push(&h(1));
        log.push(&h(2));
        assert!(log.consistency_proof(0).is_none());
    }

    #[test]
    fn consistency_proof_future_from_is_none() {
        let mut log = MerkleLog::empty();
        log.push(&h(1));
        assert!(log.consistency_proof(99).is_none());
    }

    #[test]
    fn consistency_proof_between_valid_sizes_is_some() {
        let mut log = MerkleLog::empty();
        for i in 1u8..=5 {
            log.push(&h(i));
        }
        // current = 5, from=3 → 2 additions, valid proof.
        assert!(log.consistency_proof(3).is_some());
        // from=5 → 0 additions, also valid (proves "same size")
        assert!(log.consistency_proof(5).is_some());
    }
}
