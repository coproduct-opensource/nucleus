//! Verification of `Envelope::checkpoints` — the contemporaneous signed tree
//! heads a bundle carries.
//!
//! Until this module, `verify_bundle` counted checkpoints into the report and
//! looked at nothing else: a checkpoint's root, size, timestamp, kid and
//! signature could all be rewritten and the bundle still verified. A reader of
//! `checkpoint_count` had no way to know the count was of unverified claims.
//!
//! Each checkpoint is now:
//!
//! 1. **signed** by the trust anchor's witness key — the same key the Merkle
//!    anchor's tree head is checked against, obtained out of band. A bundle that
//!    carries checkpoints under an anchor with no witness key is refused: the
//!    verifier could not look, and that is not "looked and it was fine" (A-1);
//! 2. **free of cosignatures**, which nothing here verifies — a cosignature the
//!    verifier ignores is a claim it would be passing on unchecked;
//! 3. **not an equivocation**: two checkpoints of one size with two roots are
//!    evidence of a split view and refuse the bundle;
//! 4. **consistent with the Merkle anchor**, when there is one: no larger than
//!    the anchored tree, and at the anchored size, the anchored root;
//! 5. **recomputed from the edges** when the bundle carries the whole log — the
//!    anchor's inclusion proofs put the session's edges at leaves `0..n` of an
//!    `n`-leaf tree — so every checkpoint's root is the RFC 6962 root of a prefix
//!    of edges the bundle itself holds.
//!
//! Self-check trust mode verifies none of this, for the reason it skips the
//! Merkle anchor: the witness key would be the producer's own claim. The report
//! says [`CheckpointVerification::NotChecked`] rather than a count.

use nucleus_lineage::{Ed25519Witness, LineageEdge, SignedTreeHead, edge_content_hash};
use sha2::{Digest, Sha256};

use super::{TrustAnchor, VerifyBundleError};
use crate::bundle::MerkleAnchor;

/// What happened to a bundle's checkpoints. Three cases, not a `bool` (A-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointVerification {
    /// The bundle carries no checkpoints.
    NonePresent,
    /// Every checkpoint verified. `recomputed_from_edges` of them also had their
    /// root recomputed from the bundle's own edges (see module docs, step 5).
    Verified {
        count: usize,
        recomputed_from_edges: usize,
    },
    /// Self-check trust mode: the checkpoints were carried, not checked.
    NotChecked { count: usize },
}

pub(super) fn verify_checkpoints(
    edges: &[LineageEdge],
    checkpoints: &[SignedTreeHead],
    anchor: Option<&MerkleAnchor>,
    trust: &TrustAnchor,
) -> Result<CheckpointVerification, VerifyBundleError> {
    if checkpoints.is_empty() {
        return Ok(CheckpointVerification::NonePresent);
    }
    if trust.is_self_check_only() {
        return Ok(CheckpointVerification::NotChecked {
            count: checkpoints.len(),
        });
    }
    let witness_bytes =
        trust
            .witness_pubkey
            .ok_or(VerifyBundleError::CheckpointWithoutWitnessKey {
                count: checkpoints.len(),
            })?;
    let witness = Ed25519Witness::verify_only(witness_bytes).map_err(|e| {
        VerifyBundleError::CheckpointBadSignature {
            index: 0,
            detail: format!("trust anchor witness key: {e}"),
        }
    })?;

    for (index, cp) in checkpoints.iter().enumerate() {
        if !cp.cosignatures.is_empty() {
            return Err(VerifyBundleError::CheckpointCosignaturesUnsupported { index });
        }
        cp.verify(&witness)
            .map_err(|e| VerifyBundleError::CheckpointBadSignature {
                index,
                detail: e.to_string(),
            })?;
    }

    for (index, cp) in checkpoints.iter().enumerate() {
        if let Some(other) = checkpoints[..index].iter().position(|earlier| {
            earlier.tree_size == cp.tree_size && earlier.root_hash_hex != cp.root_hash_hex
        }) {
            return Err(VerifyBundleError::CheckpointEquivocation {
                index,
                other,
                tree_size: cp.tree_size,
            });
        }
    }

    let mut recomputed_from_edges = 0;
    if let Some(anchor) = anchor {
        for (index, cp) in checkpoints.iter().enumerate() {
            if cp.tree_size > anchor.sth.tree_size {
                return Err(VerifyBundleError::CheckpointBeyondAnchor {
                    index,
                    tree_size: cp.tree_size,
                    anchor_tree_size: anchor.sth.tree_size,
                });
            }
            if cp.tree_size == anchor.sth.tree_size && cp.root_hash_hex != anchor.sth.root_hash_hex
            {
                return Err(VerifyBundleError::CheckpointRootMismatch {
                    index,
                    tree_size: cp.tree_size,
                    expected_root_hex: anchor.sth.root_hash_hex.clone(),
                });
            }
        }

        if carries_whole_log(edges, anchor) {
            let leaves: Vec<[u8; 32]> = edges.iter().map(|e| edge_content_hash(e, None)).collect();
            for (index, cp) in checkpoints.iter().enumerate() {
                // `tree_size <= anchor size == leaves.len()`, checked above.
                let prefix = usize::try_from(cp.tree_size)
                    .ok()
                    .and_then(|n| leaves.get(..n))
                    .filter(|p| !p.is_empty())
                    .ok_or(VerifyBundleError::CheckpointRootMismatch {
                        index,
                        tree_size: cp.tree_size,
                        expected_root_hex: String::from("<no prefix of that size>"),
                    })?;
                let expected = hex::encode(merkle_tree_hash(prefix));
                if cp.root_hash_hex != expected {
                    return Err(VerifyBundleError::CheckpointRootMismatch {
                        index,
                        tree_size: cp.tree_size,
                        expected_root_hex: expected,
                    });
                }
                recomputed_from_edges += 1;
            }
        }
    }

    Ok(CheckpointVerification::Verified {
        count: checkpoints.len(),
        recomputed_from_edges,
    })
}

/// The anchor's (already verified) inclusion proofs put `edges[i]` at leaf `i`
/// of a tree with exactly `edges.len()` leaves: the bundle holds the whole log.
fn carries_whole_log(edges: &[LineageEdge], anchor: &MerkleAnchor) -> bool {
    !edges.is_empty()
        && u64::try_from(edges.len()).is_ok_and(|n| n == anchor.sth.tree_size)
        && anchor.inclusion_proofs.len() == edges.len()
        && anchor
            .inclusion_proofs
            .iter()
            .enumerate()
            .all(|(i, p)| u64::try_from(i).is_ok_and(|i| i == p.leaf_index))
}

/// The largest power of two strictly less than `n`, for `n >= 2`.
fn split_point(n: usize) -> usize {
    let k = (n - 1).next_power_of_two();
    if k >= n { k / 2 } else { k }
}

/// RFC 6962 §2.1 Merkle Tree Hash over leaf data `d[0..n]`, `n >= 1`.
fn merkle_tree_hash(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves {
        [] => Sha256::digest([]).into(),
        [leaf] => Sha256::new_with_prefix([0x00])
            .chain_update(leaf)
            .finalize()
            .into(),
        _ => {
            let (left, right) = leaves.split_at(split_point(leaves.len()));
            Sha256::new_with_prefix([0x01])
                .chain_update(merkle_tree_hash(left))
                .chain_update(merkle_tree_hash(right))
                .finalize()
                .into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6962 split: `k` is the largest power of two strictly below `n`.
    #[test]
    fn split_is_the_largest_power_of_two_below_n() {
        for (n, k) in [(2, 1), (3, 2), (4, 2), (5, 4), (8, 4), (9, 8), (17, 16)] {
            assert_eq!(split_point(n), k, "n = {n}");
        }
    }
}
