//! [`MerkleSink`] — a [`LineageSink`] wrapper that maintains an append-only
//! RFC 6962 / RFC 9162-style Merkle tree over edge content hashes and
//! emits signed checkpoints ([`SignedTreeHead`]) at a configured interval.
//!
//! # Threat model
//!
//! `MerkleSink` defends against post-hoc log tampering: once a checkpoint
//! is signed by a [`TreeWitness`] and published, any later mutation of
//! the underlying log (edit, reorder, splice, truncate) is detectable
//! because the Merkle root recomputed from the persisted edges no longer
//! matches the signed STH.
//!
//! It does NOT defend against an attacker who controls the witness key
//! at the moment of signing — that's the broader transparency-log
//! problem and requires either (a) an external witness with adversarial
//! interests (e.g., a customer-run Rekor mirror) or (b) gossip protocols
//! between auditors. The [`TreeWitness`] trait is the integration point
//! for both options.
//!
//! # Wire compatibility
//!
//! `MerkleSink<S>` is a transparent wrapper: edges still flow through
//! the inner sink (`S`) in the same JSONL format, so consumers that
//! don't care about Merkle integrity see no change. The checkpoint
//! files live in a separate directory and are opt-in for verification.
//!
//! # Leaf encoding
//!
//! Each edge contributes one leaf to the Merkle tree. The leaf bytes are
//! the 32-byte [`edge_content_hash`] of the edge (with `prev_hash = None`,
//! so the Merkle structure is orthogonal to the linear chain — auditors
//! can produce inclusion proofs without knowing the linear order). The
//! ct-merkle crate then prepends the RFC 6962 leaf-prefix `0x00` and
//! hashes again to produce the leaf-node value in the tree.

use std::collections::HashMap;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use ct_merkle::mem_backed_tree::MemoryBackedTree;
use ct_merkle::{InclusionProof, RootHash};
use sha2::Sha256;
use thiserror::Error;

use crate::checkpoint::{SignedTreeHead, TreeWitness, WitnessError};
use crate::edge::LineageEdge;
use crate::id::CallSpiffeId;
use crate::proof::edge_content_hash;
use crate::sink::{LineageSink, SinkError};

/// Errors specific to the Merkle layer.
#[derive(Debug, Error)]
pub enum MerkleError {
    /// The inner sink returned an error.
    #[error("inner sink failure: {0}")]
    Sink(#[from] SinkError),
    /// I/O error writing or reading a checkpoint file.
    #[error("checkpoint io: {0}")]
    Io(#[from] std::io::Error),
    /// JSON serialization/deserialization error on a checkpoint.
    #[error("checkpoint json: {0}")]
    Json(#[from] serde_json::Error),
    /// The witness backend rejected an STH signing or verification request.
    #[error("witness error: {0}")]
    Witness(#[from] WitnessError),
    /// The Merkle state lock was poisoned by a previous panic.
    #[error("merkle state lock poisoned")]
    Poisoned,
    /// `verify_log` was given a checkpoint that does not match the
    /// recomputed root for that tree_size.
    #[error("checkpoint #{seq} mismatch: signed root {signed} vs recomputed {recomputed}")]
    RootMismatch {
        seq: u64,
        signed: String,
        recomputed: String,
    },
    /// A checkpoint references a tree_size that exceeds the number of
    /// edges actually persisted to the underlying sink.
    #[error("checkpoint references tree_size {tree_size} but log only has {edges} edges")]
    CheckpointAheadOfLog { tree_size: u64, edges: u64 },
}

/// Knobs for [`MerkleSink`]. Defaults: every 16 edges, dir `./checkpoints`.
#[derive(Debug, Clone)]
pub struct MerkleConfig {
    /// Emit a signed checkpoint after every `checkpoint_interval` edges.
    /// `1` emits one per edge (test-friendly, expensive); production
    /// deployments typically pick something between 100 and 10_000.
    pub checkpoint_interval: u64,
    /// Directory to write checkpoint files into. Created on first emit.
    /// Each checkpoint is a separate file named `sth-<tree_size>.json`
    /// so concurrent readers can pick the latest atomically.
    pub checkpoint_dir: PathBuf,
}

impl MerkleConfig {
    pub fn new(checkpoint_dir: impl Into<PathBuf>) -> Self {
        Self {
            checkpoint_interval: 16,
            checkpoint_dir: checkpoint_dir.into(),
        }
    }

    pub fn with_interval(mut self, interval: u64) -> Self {
        // Interval 0 makes no progress; clamp to 1.
        self.checkpoint_interval = interval.max(1);
        self
    }
}

/// Internal state — kept behind a [`Mutex`] so [`LineageSink::emit`] can
/// remain `&self`.
struct State {
    tree: MemoryBackedTree<Sha256, Vec<u8>>,
    next_checkpoint_at: u64,
    /// Map from each leaf's 32-byte content hash to its leaf index in
    /// the tree. Populated on every emit (and during replay in `new()`)
    /// so [`MerkleSink::prove_inclusion_by_hash`] can locate a leaf
    /// without a linear scan. Since each leaf is `edge_content_hash`
    /// of a unique [`LineageEdge`] and content hashes are
    /// collision-resistant, two distinct edges cannot share an index.
    leaf_index_by_hash: HashMap<[u8; 32], u64>,
}

/// A [`LineageSink`] wrapper that maintains a Merkle tree of edges and
/// emits signed [`SignedTreeHead`]s at configured intervals.
///
/// Type parameters:
///
/// - `S` — the underlying [`LineageSink`] (typically [`crate::JsonlSink`]).
/// - `W` — the [`TreeWitness`] used to sign STHs.
pub struct MerkleSink<S, W>
where
    S: LineageSink,
    W: TreeWitness,
{
    inner: S,
    witness: W,
    config: MerkleConfig,
    state: Mutex<State>,
}

impl<S, W> MerkleSink<S, W>
where
    S: LineageSink,
    W: TreeWitness,
{
    /// Construct a new MerkleSink. If `replay_from` is `Some`, the tree
    /// is pre-populated by replaying every edge currently in the inner
    /// sink — useful when re-opening an existing log so subsequent
    /// emits extend the same Merkle history.
    pub fn new(inner: S, witness: W, config: MerkleConfig) -> Result<Self, MerkleError> {
        let mut tree = MemoryBackedTree::<Sha256, Vec<u8>>::new();
        let mut leaf_index_by_hash = HashMap::new();
        let existing = inner.iter()?;
        let initial_size = existing.len() as u64;
        for (i, edge) in existing.into_iter().enumerate() {
            let h = edge_content_hash(&edge, None);
            tree.push(h.to_vec());
            leaf_index_by_hash.insert(h, i as u64);
        }
        // First checkpoint is emitted once we've added `checkpoint_interval`
        // new edges, regardless of where we started.
        let next_checkpoint_at = initial_size + config.checkpoint_interval;
        create_dir_all(&config.checkpoint_dir)?;
        Ok(Self {
            inner,
            witness,
            config,
            state: Mutex::new(State {
                tree,
                next_checkpoint_at,
                leaf_index_by_hash,
            }),
        })
    }

    /// The current tree size (number of leaves committed).
    pub fn tree_size(&self) -> Result<u64, MerkleError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| MerkleError::Poisoned)?
            .tree
            .len())
    }

    /// The witness used to sign checkpoints.
    pub fn witness(&self) -> &W {
        &self.witness
    }

    /// Produce a Merkle inclusion proof for the leaf whose content
    /// hash is `leaf_hash`. Returns `Ok(None)` if no such leaf has been
    /// emitted into this tree.
    ///
    /// Companion to [`SignedTreeHead::root_hash_hex`]: the returned
    /// proof verifies against the root of the tree AT THE CURRENT
    /// `tree_size`. If a downstream consumer wants the proof anchored
    /// to a specific STH, they must call [`Self::force_checkpoint`]
    /// just before, so the STH's tree_size equals the tree state used
    /// to generate the proof.
    pub fn prove_inclusion_by_hash(
        &self,
        leaf_hash: &[u8; 32],
    ) -> Result<Option<(u64, InclusionProof<Sha256>)>, MerkleError> {
        let st = self.state.lock().map_err(|_| MerkleError::Poisoned)?;
        let Some(&leaf_index) = st.leaf_index_by_hash.get(leaf_hash) else {
            return Ok(None);
        };
        // `prove_inclusion` panics if the index is out of range; we
        // just inserted it so the invariant holds.
        let proof = st.tree.prove_inclusion(leaf_index as usize);
        Ok(Some((leaf_index, proof)))
    }

    /// Current Merkle root + leaf count. Useful for callers that want
    /// to anchor inclusion proofs to a freshly-cut STH without
    /// emitting a checkpoint file.
    pub fn current_root(&self) -> Result<RootHash<Sha256>, MerkleError> {
        let st = self.state.lock().map_err(|_| MerkleError::Poisoned)?;
        Ok(st.tree.root())
    }

    /// Force a checkpoint to be written immediately, regardless of
    /// `checkpoint_interval` progress. Useful at shutdown to seal the
    /// log.
    pub fn force_checkpoint(&self) -> Result<SignedTreeHead, MerkleError> {
        let mut st = self.state.lock().map_err(|_| MerkleError::Poisoned)?;
        let sth = sign_current(&self.witness, &st.tree)?;
        write_checkpoint(&self.config.checkpoint_dir, &sth)?;
        // Realign the next scheduled checkpoint so we don't double-emit
        // immediately after a forced one.
        st.next_checkpoint_at = sth.tree_size + self.config.checkpoint_interval;
        Ok(sth)
    }
}

impl<S, W> LineageSink for MerkleSink<S, W>
where
    S: LineageSink,
    W: TreeWitness,
{
    fn emit(&self, edge: LineageEdge) -> Result<(), SinkError> {
        // 1) Persist to the inner sink first — even if the Merkle update
        // fails, the durable log of edges is intact and recoverable.
        self.inner.emit(edge.clone())?;

        // 2) Append the leaf hash to our in-memory Merkle tree and
        // record the leaf-index → hash map so inclusion proofs can be
        // generated later by content hash without a linear scan.
        let leaf = edge_content_hash(&edge, None);
        let mut st = self.state.lock().map_err(|_| SinkError::Poisoned)?;
        let leaf_index = st.tree.len();
        st.tree.push(leaf.to_vec());
        st.leaf_index_by_hash.insert(leaf, leaf_index);

        // 3) Cut a checkpoint if we've crossed the interval.
        if st.tree.len() >= st.next_checkpoint_at {
            // Signing failures are surfaced via the operator log path
            // rather than failing the emit — the durable edge is already
            // committed. We record the next attempt at the current size
            // + interval so we don't tight-loop on a broken witness.
            match sign_current(&self.witness, &st.tree) {
                Ok(sth) => match write_checkpoint(&self.config.checkpoint_dir, &sth) {
                    Ok(()) => {
                        st.next_checkpoint_at = sth.tree_size + self.config.checkpoint_interval;
                    }
                    Err(e) => {
                        tracing::error!(
                            target: "nucleus_lineage::merkle",
                            "failed to write checkpoint at tree_size {}: {e}",
                            sth.tree_size,
                        );
                        st.next_checkpoint_at = st.tree.len() + self.config.checkpoint_interval;
                    }
                },
                Err(e) => {
                    tracing::error!(
                        target: "nucleus_lineage::merkle",
                        "failed to sign checkpoint at tree_size {}: {e}",
                        st.tree.len(),
                    );
                    st.next_checkpoint_at = st.tree.len() + self.config.checkpoint_interval;
                }
            }
        }
        Ok(())
    }

    fn iter(&self) -> Result<Vec<LineageEdge>, SinkError> {
        self.inner.iter()
    }

    fn edges_for_child(&self, id: &CallSpiffeId) -> Result<Vec<LineageEdge>, SinkError> {
        self.inner.edges_for_child(id)
    }
}

/// Read every `sth-*.json` file in `dir`, parse, and return sorted by
/// `tree_size`.
pub fn read_checkpoints(dir: &Path) -> Result<Vec<SignedTreeHead>, MerkleError> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(MerkleError::Io(e)),
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if !name.starts_with("sth-") || !name.ends_with(".json") {
            continue;
        }
        let bytes = std::fs::read(&path)?;
        let sth: SignedTreeHead = serde_json::from_slice(&bytes)?;
        out.push(sth);
    }
    out.sort_by_key(|s| s.tree_size);
    Ok(out)
}

/// Replay all edges from `sink` into a fresh Merkle tree, then validate
/// every checkpoint in `checkpoints` against:
///
/// 1. The witness's signature over the canonical STH bytes.
/// 2. The recomputed root hash at that `tree_size`.
///
/// Returns `Ok(())` if all checkpoints validate; returns the first
/// failure otherwise.
pub fn verify_log<S, W>(
    sink: &S,
    checkpoints: &[SignedTreeHead],
    witness: &W,
) -> Result<(), MerkleError>
where
    S: LineageSink,
    W: TreeWitness,
{
    // Build a parallel tree by replaying the inner-sink edges.
    let edges = sink.iter()?;
    let total = edges.len() as u64;
    let mut tree = MemoryBackedTree::<Sha256, Vec<u8>>::new();
    let mut roots_at: Vec<(u64, [u8; 32])> = Vec::with_capacity(checkpoints.len());

    // Sort checkpoints by tree_size so we can compute roots in one pass.
    let mut by_size: Vec<&SignedTreeHead> = checkpoints.iter().collect();
    by_size.sort_by_key(|c| c.tree_size);
    let mut cursor = 0usize;

    for (idx, edge) in edges.iter().enumerate() {
        let h = edge_content_hash(edge, None);
        tree.push(h.to_vec());
        let size = (idx + 1) as u64;
        // Record roots for any checkpoints at this size.
        while cursor < by_size.len() && by_size[cursor].tree_size == size {
            let root = tree_root_bytes(&tree);
            roots_at.push((size, root));
            cursor += 1;
        }
    }

    // Any checkpoint past the actual log length is a structural error.
    if let Some(sth) = by_size.get(cursor) {
        return Err(MerkleError::CheckpointAheadOfLog {
            tree_size: sth.tree_size,
            edges: total,
        });
    }

    // Now validate each checkpoint.
    for (i, sth) in by_size.iter().enumerate() {
        // Signature validation: this also enforces kid match.
        sth.verify(witness)?;

        let (size, root) = roots_at[i];
        debug_assert_eq!(size, sth.tree_size);
        let signed_root = hex::decode(&sth.root_hash_hex)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
            .ok_or_else(|| {
                MerkleError::Witness(WitnessError::Backend(
                    "malformed root_hash_hex in STH".into(),
                ))
            })?;
        if signed_root != root {
            return Err(MerkleError::RootMismatch {
                seq: sth.tree_size,
                signed: sth.root_hash_hex.clone(),
                recomputed: hex::encode(root),
            });
        }
    }
    Ok(())
}

/// Sign an STH for the tree's current state.
fn sign_current<W: TreeWitness>(
    witness: &W,
    tree: &MemoryBackedTree<Sha256, Vec<u8>>,
) -> Result<SignedTreeHead, WitnessError> {
    let root = tree_root_bytes(tree);
    witness.sign_sth(tree.len(), &root)
}

/// Extract the raw root hash bytes from a `MemoryBackedTree<Sha256, _>`.
fn tree_root_bytes(tree: &MemoryBackedTree<Sha256, Vec<u8>>) -> [u8; 32] {
    use ct_merkle::digest::Output;
    let root = tree.root();
    // RootHash::as_bytes() returns the digest::Output<H>; SHA-256 is 32 bytes.
    let bytes: &Output<Sha256> = root.as_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes.as_slice());
    out
}

/// Write `sth` to `dir/sth-<tree_size>.json` atomically.
fn write_checkpoint(dir: &Path, sth: &SignedTreeHead) -> Result<(), MerkleError> {
    create_dir_all(dir)?;
    let final_path = dir.join(format!("sth-{:020}.json", sth.tree_size));
    // Use a stable, lexicographically-sortable filename (zero-padded tree_size)
    // plus a temp-then-rename for atomic visibility.
    let tmp_path = final_path.with_extension("json.tmp");
    {
        let f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp_path)?;
        let mut w = BufWriter::new(f);
        serde_json::to_writer(&mut w, sth)?;
        w.flush()?;
    }
    std::fs::rename(&tmp_path, &final_path)?;
    Ok(())
}

// Suppress unused-import warnings when test-only items aren't reached.
#[allow(dead_code)]
fn _now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[allow(dead_code)]
fn _read_lines(path: &Path) -> Result<Vec<String>, std::io::Error> {
    let f = File::open(path)?;
    let reader = BufReader::new(f);
    reader.lines().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::Ed25519Witness;
    use crate::edge::{EdgeKind, LineageEdge};
    use crate::id::CallSpiffeId;
    use crate::sink::InMemorySink;

    fn pod() -> CallSpiffeId {
        CallSpiffeId::pod("prod.example.com", "agents", "coder").unwrap()
    }

    fn tool_edge(p: &CallSpiffeId, payload: &[u8]) -> LineageEdge {
        let child = p.derive_tool("Bash", Some(payload)).unwrap();
        LineageEdge::from_parent(
            child,
            p.clone(),
            EdgeKind::ToolCall {
                tool: "Bash".to_string(),
            },
        )
    }

    #[test]
    fn merkle_sink_emits_checkpoint_at_interval() {
        let dir = tempfile::tempdir().unwrap();
        let inner = InMemorySink::new();
        let witness = Ed25519Witness::from_seed([1u8; 32]);
        let cfg = MerkleConfig::new(dir.path()).with_interval(3);
        let sink = MerkleSink::new(inner, witness, cfg).unwrap();
        let p = pod();
        // 5 edges → expect one checkpoint at size 3, no checkpoint yet at size 5.
        for i in 0..5 {
            sink.emit(tool_edge(&p, format!("payload-{i}").as_bytes()))
                .unwrap();
        }
        let cps = read_checkpoints(dir.path()).unwrap();
        assert_eq!(cps.len(), 1, "expected one STH at the interval boundary");
        assert_eq!(cps[0].tree_size, 3);
    }

    #[test]
    fn merkle_sink_force_checkpoint_seals_current_state() {
        let dir = tempfile::tempdir().unwrap();
        let inner = InMemorySink::new();
        let witness = Ed25519Witness::from_seed([2u8; 32]);
        let cfg = MerkleConfig::new(dir.path()).with_interval(1_000);
        let sink = MerkleSink::new(inner, witness, cfg).unwrap();
        let p = pod();
        for i in 0..2 {
            sink.emit(tool_edge(&p, format!("p-{i}").as_bytes()))
                .unwrap();
        }
        let sth = sink.force_checkpoint().unwrap();
        assert_eq!(sth.tree_size, 2);

        let cps = read_checkpoints(dir.path()).unwrap();
        assert_eq!(cps.len(), 1);
        assert_eq!(cps[0], sth);
    }

    #[test]
    fn verify_log_accepts_intact_chain() {
        let dir = tempfile::tempdir().unwrap();
        let inner = InMemorySink::new();
        let witness = Ed25519Witness::from_seed([3u8; 32]);
        let cfg = MerkleConfig::new(dir.path()).with_interval(2);
        let sink = MerkleSink::new(inner, witness, cfg).unwrap();
        let p = pod();
        for i in 0..6 {
            sink.emit(tool_edge(&p, format!("payload-{i}").as_bytes()))
                .unwrap();
        }
        // 6 edges, interval 2 → STHs at 2, 4, 6.
        let cps = read_checkpoints(dir.path()).unwrap();
        assert_eq!(cps.len(), 3);

        // Verify with the verify-only witness (auditor scenario).
        let signer_bytes = sink.witness().verifying_key_bytes();
        let auditor = Ed25519Witness::verify_only(signer_bytes).unwrap();
        verify_log(&sink, &cps, &auditor).unwrap();
    }

    #[test]
    fn verify_log_detects_tampered_edge() {
        let dir = tempfile::tempdir().unwrap();
        let inner = InMemorySink::new();
        let witness = Ed25519Witness::from_seed([4u8; 32]);
        let cfg = MerkleConfig::new(dir.path()).with_interval(2);
        let sink = MerkleSink::new(inner, witness, cfg).unwrap();
        let p = pod();
        for i in 0..4 {
            sink.emit(tool_edge(&p, format!("payload-{i}").as_bytes()))
                .unwrap();
        }
        let cps = read_checkpoints(dir.path()).unwrap();
        assert!(!cps.is_empty());

        // Now construct a tampered "sink" that returns a modified edge list,
        // and verify against the original checkpoints.
        let tampered = InMemorySink::new();
        // Emit different payloads — same count, same kind, different content.
        for i in 0..4 {
            tampered
                .emit(tool_edge(&p, format!("ATTACK-{i}").as_bytes()))
                .unwrap();
        }
        let auditor = Ed25519Witness::verify_only(sink.witness().verifying_key_bytes()).unwrap();
        let err = verify_log(&tampered, &cps, &auditor).unwrap_err();
        assert!(matches!(err, MerkleError::RootMismatch { .. }));
    }

    #[test]
    fn verify_log_detects_truncated_log() {
        let dir = tempfile::tempdir().unwrap();
        let inner = InMemorySink::new();
        let witness = Ed25519Witness::from_seed([5u8; 32]);
        let cfg = MerkleConfig::new(dir.path()).with_interval(2);
        let sink = MerkleSink::new(inner, witness, cfg).unwrap();
        let p = pod();
        for i in 0..6 {
            sink.emit(tool_edge(&p, format!("payload-{i}").as_bytes()))
                .unwrap();
        }
        let cps = read_checkpoints(dir.path()).unwrap();
        // Build a shorter log — only 3 edges — and verify against checkpoints
        // that reach tree_size 6.
        let truncated = InMemorySink::new();
        for i in 0..3 {
            truncated
                .emit(tool_edge(&p, format!("payload-{i}").as_bytes()))
                .unwrap();
        }
        let auditor = Ed25519Witness::verify_only(sink.witness().verifying_key_bytes()).unwrap();
        let err = verify_log(&truncated, &cps, &auditor).unwrap_err();
        assert!(matches!(err, MerkleError::CheckpointAheadOfLog { .. }));
    }

    #[test]
    fn merkle_sink_replays_existing_inner_sink() {
        let dir = tempfile::tempdir().unwrap();
        let inner = InMemorySink::new();
        let p = pod();
        // Pre-populate inner sink with 2 edges (no Merkle yet).
        for i in 0..2 {
            inner
                .emit(tool_edge(&p, format!("pre-{i}").as_bytes()))
                .unwrap();
        }
        let witness = Ed25519Witness::from_seed([6u8; 32]);
        let cfg = MerkleConfig::new(dir.path()).with_interval(2);
        let sink = MerkleSink::new(inner, witness, cfg).unwrap();
        // Tree starts at size 2 from replay.
        assert_eq!(sink.tree_size().unwrap(), 2);

        // Emitting 2 more should hit interval boundary at total=4.
        for i in 0..2 {
            sink.emit(tool_edge(&p, format!("post-{i}").as_bytes()))
                .unwrap();
        }
        let cps = read_checkpoints(dir.path()).unwrap();
        assert_eq!(cps.len(), 1);
        assert_eq!(cps[0].tree_size, 4);
    }

    #[test]
    fn verify_log_rejects_swapped_witness() {
        let dir = tempfile::tempdir().unwrap();
        let inner = InMemorySink::new();
        let witness = Ed25519Witness::from_seed([7u8; 32]);
        let cfg = MerkleConfig::new(dir.path()).with_interval(1);
        let sink = MerkleSink::new(inner, witness, cfg).unwrap();
        let p = pod();
        sink.emit(tool_edge(&p, b"first")).unwrap();
        let cps = read_checkpoints(dir.path()).unwrap();
        assert_eq!(cps.len(), 1);

        // Use a different witness for verification.
        let wrong = Ed25519Witness::from_seed([99u8; 32]);
        let err = verify_log(&sink, &cps, &wrong).unwrap_err();
        assert!(matches!(
            err,
            MerkleError::Witness(WitnessError::KidMismatch { .. })
        ));
    }
}
