//! [`MerkleProver`] — trait the envelope builder uses to ask any
//! Merkle-backed sink for inclusion proofs by leaf-hash.
//!
//! Decouples [`crate::nucleus_envelope::BundleBuilder`]-equivalent
//! callers from the concrete `MerkleSink<S, W>` type so they don't
//! need to know which witness or inner sink backs the proofs.

use ct_merkle::{ConsistencyProof, InclusionProof, RootHash};
use sha2::Sha256;

use crate::checkpoint::{SignedTreeHead, TreeWitness, WitnessError};
use crate::merkle::{MerkleError, MerkleSink};
use crate::sink::LineageSink;

/// Anything that can produce a Merkle inclusion proof for a leaf hash.
///
/// All methods take `&self` so a single prover can serve many readers
/// concurrently. Implementations hold their own synchronization
/// (typically a `Mutex` around the underlying tree).
pub trait MerkleProver: Send + Sync {
    /// Locate the leaf whose content-hash matches `leaf_hash` and
    /// return its `(leaf_index, inclusion_proof)`. Returns `Ok(None)`
    /// if the leaf is not in this tree.
    ///
    /// **Concurrency caveat:** this method acquires and releases the
    /// implementation's internal lock. Callers that need a *consistent
    /// view* of (proofs, signed root) MUST use
    /// [`Self::prove_for_hashes_and_seal`] instead, which performs both
    /// operations under one lock. Mixing this method with
    /// [`Self::seal_current_root`] under concurrent emit can produce
    /// proofs that don't verify against the sealed root.
    fn prove_for_hash(
        &self,
        leaf_hash: &[u8; 32],
    ) -> Result<Option<(u64, InclusionProof<Sha256>)>, MerkleError>;

    /// Cut a fresh signed tree head that the inclusion proofs from
    /// this prover will anchor to. See concurrency caveat on
    /// [`Self::prove_for_hash`].
    fn seal_current_root(&self) -> Result<SignedTreeHead, MerkleError>;

    /// **Atomic alternative to `prove_for_hash` + `seal_current_root`.**
    ///
    /// Look up each leaf hash, gather inclusion proofs, and sign the
    /// root — all under ONE acquisition of the prover's internal lock.
    /// Concurrent emit cannot advance the tree between the proofs and
    /// the seal. This is what envelope builders MUST use to produce
    /// soundly verifiable v2 bundles under any production load.
    ///
    /// Returns `(sth, proofs)` where `proofs[i]` is the
    /// `(leaf_index, InclusionProof)` for `leaf_hashes[i]`. Returns
    /// `Err(MerkleError::Backend(...))` (or analogous) if any leaf
    /// hash is not present.
    fn prove_for_hashes_and_seal(
        &self,
        leaf_hashes: &[[u8; 32]],
    ) -> Result<(SignedTreeHead, Vec<(u64, InclusionProof<Sha256>)>), MerkleError>;

    /// Current `RootHash` (for tests / debug). Most callers should
    /// use [`Self::seal_current_root`] to bind a witness signature.
    fn current_root(&self) -> Result<RootHash<Sha256>, MerkleError>;

    /// **v2.3c.** Compute an RFC 6962 §2.1.2 Merkle consistency proof
    /// from `old_size` to the current tree size. Required by C2SP
    /// `tlog-witness` `POST /add-checkpoint` when the producer has
    /// previously cosigned with a witness — the request body carries
    /// `old <prev_size>` followed by the consistency proof lines.
    ///
    /// Default impl returns `Err(MerkleError::ConsistencyOutOfRange)`
    /// (with `reason: "prover does not implement consistency proofs"`)
    /// — single-purpose provers can opt out, but [`MerkleSink`] supplies
    /// a real implementation.
    fn prove_consistency_from(
        &self,
        old_size: u64,
    ) -> Result<ConsistencyProof<Sha256>, MerkleError> {
        Err(MerkleError::ConsistencyOutOfRange {
            old_size,
            current_size: 0,
            reason: "prover does not implement consistency proofs",
        })
    }
}

impl<S, W> MerkleProver for MerkleSink<S, W>
where
    S: LineageSink,
    W: TreeWitness,
{
    fn prove_for_hash(
        &self,
        leaf_hash: &[u8; 32],
    ) -> Result<Option<(u64, InclusionProof<Sha256>)>, MerkleError> {
        self.prove_inclusion_by_hash(leaf_hash)
    }

    fn seal_current_root(&self) -> Result<SignedTreeHead, MerkleError> {
        // Sign the current root via the witness. We DON'T write the
        // STH to disk here — that's `force_checkpoint`'s job. This is
        // a "give me a signed snapshot for an envelope" primitive.
        let root = self.current_root()?;
        let tree_size = root.num_leaves();
        let mut root_bytes = [0u8; 32];
        root_bytes.copy_from_slice(root.as_bytes().as_slice());
        self.witness()
            .sign_sth(tree_size, &root_bytes)
            .map_err(MerkleError::Witness)
    }

    fn prove_for_hashes_and_seal(
        &self,
        leaf_hashes: &[[u8; 32]],
    ) -> Result<(SignedTreeHead, Vec<(u64, InclusionProof<Sha256>)>), MerkleError> {
        // Delegate to the MerkleSink's atomic implementation, which
        // holds the tree mutex across the proof-gather + sign phases.
        self.atomic_prove_and_seal(leaf_hashes)
    }

    fn current_root(&self) -> Result<RootHash<Sha256>, MerkleError> {
        Self::current_root(self)
    }

    fn prove_consistency_from(
        &self,
        old_size: u64,
    ) -> Result<ConsistencyProof<Sha256>, MerkleError> {
        Self::prove_consistency_from(self, old_size)
    }
}

/// Re-exported error variant used by callers that don't pull in
/// `crate::checkpoint::WitnessError` directly.
pub type ProverWitnessError = WitnessError;
