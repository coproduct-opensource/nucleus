//! Effect receipts — a transparency log of mediation decisions.
//!
//! # What this is for
//!
//! After the B1/B2 cutover every effect is *enforced*: reaching one requires
//! surrendering a scoped, single-use [`Authority`](crate::authority::Authority).
//! Enforcement without evidence is still only as good as the operator's word,
//! which is exactly the gap the 2026 sandbox-escape results exposed elsewhere. A
//! receipt lets a third party *check* the claim instead of believing it.
//!
//! Receipts are emitted at the mediation choke point, so a receipt cannot be
//! forgotten separately from the check: the same call site that spends the
//! authority appends the entry.
//!
//! # Why a Merkle log rather than a hash chain
//!
//! The first version was a linear `prev_hash` chain. That detects reordering and
//! edits, but supports neither of the two proofs a transparency log exists to
//! provide, and both matter here:
//!
//! * **Inclusion** — *"this effect is in the log"*, in `O(log n)` rather than by
//!   shipping the whole log. Without it, an auditor checking one action has to
//!   receive every action.
//! * **Consistency** — *"the log I see now only grew from the log I saw before;
//!   nothing was rewritten behind me"*. A linear chain cannot express this at
//!   all: an operator who discards a suffix and recomputes produces a chain that
//!   verifies perfectly.
//!
//! This is the Certificate Transparency structure (RFC 6962), as used by
//! Trillian and Rekor. The tree hashing below follows that spec exactly:
//!
//! ```text
//! MTH({})      = SHA256()
//! MTH({d0})    = SHA256(0x00 || d0)
//! MTH(D[n])    = SHA256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
//!                where k is the largest power of two < n
//! ```
//!
//! The `0x00`/`0x01` prefixes are load-bearing: without them a leaf and an
//! internal node could hash identically, which is the classic second-preimage
//! attack on Merkle trees.
//!
//! # What a receipt asserts, precisely
//!
//! **That an authorization decision was made for this `(Operation, SinkClass)`,
//! and what it was.** It does NOT assert that the underlying I/O succeeded: an
//! `Allowed` receipt followed by a disk error is a correct pair of facts. The
//! flagship claim is about side effects being *mediated and authorized*, and the
//! authorization is the part a receipt can witness.
//!
//! # What this still does NOT establish
//!
//! * **Nothing is published.** A signed checkpoint proves the operator asserted
//!   a root, not that anyone else saw it. [`Witness`] closes the *split-view*
//!   half of that — a log cannot get two conflicting views cosigned — but a
//!   witness only helps clients who demand a cosignature, and this crate ships
//!   the verification core, not a running witness service. Anchoring to a public
//!   log (Rekor) is the further escalation and is not done.
//! * **The signing key is whatever the caller supplies.** Binding it to a
//!   *measured binary* is the attestation work, and is not done here.
//! * **Coverage is the ten methods `PolicyEnforced` gates.**
//!   `ShellEffect::run_argv`, `AsyncShellSpawnEffect::run_argv_async` and
//!   `NetEffect::fetch` spend their authority inside `RealEffects`, below this
//!   layer, so they are not witnessed.

use std::sync::Mutex;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use portcullis_core::{Operation, SinkClass};
use sha2::{Digest, Sha256};

/// What the mediation layer decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectOutcome {
    /// The authority was in scope and the capability permitted it.
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

/// One decision, one leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectReceipt {
    /// Position in the log, from 0.
    pub seq: u64,
    /// The operation the effect was attempted under.
    pub operation: Operation,
    /// The sink the effect targeted.
    pub sink_class: SinkClass,
    /// What the mediation layer decided.
    pub outcome: EffectOutcome,
}

impl EffectReceipt {
    /// The bytes that get hashed. Fixed-width and order-fixed, so two logs agree
    /// on a root iff they agree on the facts — no serializer in the trusted path.
    fn canonical_bytes(&self) -> [u8; 11] {
        let mut buf = [0u8; 11];
        buf[0..8].copy_from_slice(&self.seq.to_be_bytes());
        buf[8] = self.operation as u8;
        buf[9] = self.sink_class as u8;
        buf[10] = self.outcome.code();
        buf
    }

    /// RFC 6962 leaf hash: `SHA256(0x00 || entry)`.
    pub fn leaf_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([0x00]);
        h.update(self.canonical_bytes());
        h.finalize().into()
    }
}

/// RFC 6962 internal node hash: `SHA256(0x01 || left || right)`.
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The largest power of two strictly less than `n`. Only called with `n > 1`.
fn split_point(n: usize) -> usize {
    debug_assert!(n > 1);
    let mut k = 1usize;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// Merkle Tree Hash over `leaves`.
fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => Sha256::new().finalize().into(),
        1 => leaves[0],
        n => {
            let k = split_point(n);
            node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
        }
    }
}

/// RFC 6962 `PATH(m, D[n])` — the inclusion proof for leaf `m`.
fn path(m: usize, leaves: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if n <= 1 {
        return Vec::new();
    }
    let k = split_point(n);
    if m < k {
        let mut p = path(m, &leaves[..k]);
        p.push(mth(&leaves[k..]));
        p
    } else {
        let mut p = path(m - k, &leaves[k..]);
        p.push(mth(&leaves[..k]));
        p
    }
}

/// RFC 6962 `SUBPROOF(m, D[n], b)`.
fn subproof(m: usize, leaves: &[[u8; 32]], b: bool) -> Vec<[u8; 32]> {
    let n = leaves.len();
    if m == n {
        return if b { Vec::new() } else { vec![mth(leaves)] };
    }
    let k = split_point(n);
    if m <= k {
        let mut p = subproof(m, &leaves[..k], b);
        p.push(mth(&leaves[k..]));
        p
    } else {
        let mut p = subproof(m - k, &leaves[k..], false);
        p.push(mth(&leaves[..k]));
        p
    }
}

/// A claim about the log at one point in time: *this many entries, this root*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    /// Number of entries the root covers.
    pub size: u64,
    /// Merkle Tree Hash over those entries.
    pub root: [u8; 32],
}

impl Checkpoint {
    /// Fixed-width bytes over which the signature is computed.
    fn signing_bytes(&self) -> [u8; 40] {
        let mut buf = [0u8; 40];
        buf[0..8].copy_from_slice(&self.size.to_be_bytes());
        buf[8..40].copy_from_slice(&self.root);
        buf
    }
}

/// A checkpoint plus the operator's signature over it.
#[derive(Debug, Clone, Copy)]
pub struct SignedCheckpoint {
    /// The claim.
    pub checkpoint: Checkpoint,
    /// Ed25519 over [`Checkpoint::signing_bytes`].
    pub signature: [u8; 64],
}

impl SignedCheckpoint {
    /// Check the signature against a known verifying key.
    ///
    /// This establishes that the holder of the key asserted this `(size, root)`.
    /// It does NOT establish that the log was not forked: two validly signed
    /// checkpoints of the same size with different roots is exactly what forking
    /// looks like, and catching it requires comparing against a witness.
    pub fn verify_signature(&self, key: &VerifyingKey) -> bool {
        let sig = Signature::from_bytes(&self.signature);
        // `verify_strict`, not `verify`: the strict form rejects small-order and
        // torsion-component public keys, under which one signature can verify
        // against several keys. For a log whose whole point is "WHICH operator
        // asserted this root", that malleability would undo the claim. Enforced
        // repo-wide by scripts/check-verify-strict.sh (M-3), which caught this.
        key.verify_strict(&self.checkpoint.signing_bytes(), &sig)
            .is_ok()
    }
}

/// An append-only, Merkle-backed log of mediation decisions.
///
/// Interior-mutable so the effect traits can append through `&self` — they take
/// `&self` because an effect handler is shared, and threading `&mut` through
/// them would change every signature for no security gain.
#[derive(Debug, Default)]
pub struct ReceiptLog {
    entries: Mutex<Vec<EffectReceipt>>,
}

impl ReceiptLog {
    /// An empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a decision; returns its leaf index.
    ///
    /// Appending is the only mutation this type offers: there is no `remove`, no
    /// `truncate`, and no way to reach the inner `Vec`. That makes the log
    /// append-only *by construction* rather than by convention.
    pub fn append(
        &self,
        operation: Operation,
        sink_class: SinkClass,
        outcome: EffectOutcome,
    ) -> u64 {
        let mut entries = self.entries.lock().expect("receipt log poisoned");
        let seq = entries.len() as u64;
        entries.push(EffectReceipt {
            seq,
            operation,
            sink_class,
            outcome,
        });
        seq
    }

    /// A snapshot of the entries.
    pub fn entries(&self) -> Vec<EffectReceipt> {
        self.entries.lock().expect("receipt log poisoned").clone()
    }

    fn leaves(&self) -> Vec<[u8; 32]> {
        self.entries
            .lock()
            .expect("receipt log poisoned")
            .iter()
            .map(|e| e.leaf_hash())
            .collect()
    }

    /// Merkle Tree Hash over the whole log.
    pub fn root(&self) -> [u8; 32] {
        mth(&self.leaves())
    }

    /// How many decisions have been recorded.
    pub fn len(&self) -> usize {
        self.entries.lock().expect("receipt log poisoned").len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The current `(size, root)` claim.
    pub fn checkpoint(&self) -> Checkpoint {
        let leaves = self.leaves();
        Checkpoint {
            size: leaves.len() as u64,
            root: mth(&leaves),
        }
    }

    /// Sign the current checkpoint.
    pub fn sign_checkpoint(&self, key: &SigningKey) -> SignedCheckpoint {
        let checkpoint = self.checkpoint();
        let sig = key.sign(&checkpoint.signing_bytes());
        SignedCheckpoint {
            checkpoint,
            signature: sig.to_bytes(),
        }
    }

    /// Inclusion proof for leaf `index`, or `None` if out of range.
    pub fn inclusion_proof(&self, index: u64) -> Option<Vec<[u8; 32]>> {
        let leaves = self.leaves();
        if (index as usize) >= leaves.len() {
            return None;
        }
        Some(path(index as usize, &leaves))
    }

    /// Consistency proof from an earlier size `m` to the current log.
    ///
    /// `None` when `m` is 0 or larger than the current size — there is nothing
    /// to be consistent with.
    pub fn consistency_proof(&self, m: u64) -> Option<Vec<[u8; 32]>> {
        let leaves = self.leaves();
        let m = m as usize;
        if m == 0 || m > leaves.len() {
            return None;
        }
        Some(subproof(m, &leaves, true))
    }
}

/// Verify that `leaf` really is entry `index` of a log of `size` with `root`.
///
/// The auditor's side: needs the leaf, its index, the tree size, the `O(log n)`
/// proof, and the root — never the log itself.
pub fn verify_inclusion(
    leaf: &[u8; 32],
    index: u64,
    size: u64,
    proof: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    if index >= size {
        return false;
    }
    let mut fn_ = index;
    let mut sn = size - 1;
    let mut r = *leaf;
    for p in proof {
        if sn == 0 {
            return false;
        }
        if !fn_.is_multiple_of(2) || fn_ == sn {
            r = node_hash(p, &r);
            while fn_.is_multiple_of(2) && fn_ != 0 {
                fn_ /= 2;
                sn /= 2;
            }
        } else {
            r = node_hash(&r, p);
        }
        fn_ /= 2;
        sn /= 2;
    }
    sn == 0 && r == *root
}

/// Verify that a log of size `n` with root `root_n` is an append-only extension
/// of the log of size `m` with root `root_m`.
///
/// **This is the property a hash chain cannot express.** An operator who
/// discards a suffix and recomputes produces a chain that verifies internally;
/// they cannot produce a consistency proof against a checkpoint an auditor
/// already holds.
pub fn verify_consistency(
    m: u64,
    root_m: &[u8; 32],
    n: u64,
    root_n: &[u8; 32],
    proof: &[[u8; 32]],
) -> bool {
    if m > n {
        return false;
    }
    if m == n {
        return proof.is_empty() && root_m == root_n;
    }
    if m == 0 {
        // The empty tree is a prefix of everything, and needs no proof.
        return proof.is_empty();
    }

    // Walk up while the first tree's last leaf is a RIGHT child: those levels
    // are shared by both trees and contribute nothing to the proof.
    let (mut fn_, mut sn) = (m - 1, n - 1);
    while fn_ & 1 == 1 {
        fn_ >>= 1;
        sn >>= 1;
    }

    let mut it = proof.iter();
    // When `fn_` reached 0 the first tree is a complete subtree, so its root is
    // `root_m` and the proof omits it. Otherwise the proof supplies the seed.
    let (mut fr, mut sr) = if fn_ != 0 {
        match it.next() {
            Some(seed) => (*seed, *seed),
            None => return false,
        }
    } else {
        (*root_m, *root_m)
    };

    for c in it {
        if sn == 0 {
            return false; // proof longer than the tree can justify
        }
        if fn_ & 1 == 1 || fn_ == sn {
            // A node on the first tree's right border: it contributes to BOTH
            // roots. Hashing only `sr` here was the bug in the first version —
            // every prefix then failed to reproduce `root_m`.
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            while fn_ != 0 && fn_ & 1 == 0 {
                fn_ >>= 1;
                sn >>= 1;
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fn_ >>= 1;
        sn >>= 1;
    }

    sn == 0 && fr == *root_m && sr == *root_n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log_of(n: u64) -> ReceiptLog {
        let log = ReceiptLog::new();
        for i in 0..n {
            log.append(
                Operation::ReadFiles,
                SinkClass::AuditLogAppend,
                if i % 3 == 0 {
                    EffectOutcome::Allowed
                } else {
                    EffectOutcome::DeniedByScope
                },
            );
        }
        log
    }

    #[test]
    fn an_empty_log_has_the_empty_hash() {
        let log = ReceiptLog::new();
        assert!(log.is_empty());
        let expected: [u8; 32] = Sha256::new().finalize().into();
        assert_eq!(log.root(), expected);
    }

    /// Denials are evidence too. A log recording only successes would let a
    /// refused push disappear from the record.
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

    /// The same facts in the same order must produce the same root, or two
    /// copies of a log cannot be compared.
    #[test]
    fn the_root_is_deterministic() {
        assert_eq!(log_of(7).root(), log_of(7).root());
    }

    /// A leaf and an internal node must not hash alike — the RFC 6962 domain
    /// separation. Without the `0x00`/`0x01` prefixes an attacker could present
    /// an internal node as a leaf (second-preimage).
    #[test]
    fn leaves_and_nodes_are_domain_separated() {
        let e = EffectReceipt {
            seq: 0,
            operation: Operation::ReadFiles,
            sink_class: SinkClass::AuditLogAppend,
            outcome: EffectOutcome::Allowed,
        };
        let leaf = e.leaf_hash();
        let as_node = node_hash(&leaf, &leaf);
        assert_ne!(leaf, as_node);
    }

    /// Every entry proves its own membership, at every log size — including the
    /// non-power-of-two sizes where the tree is unbalanced and the proof lengths
    /// differ per leaf.
    #[test]
    fn every_entry_has_a_verifying_inclusion_proof() {
        for n in 1u64..=33 {
            let log = log_of(n);
            let root = log.root();
            let entries = log.entries();
            for i in 0..n {
                let proof = log.inclusion_proof(i).expect("in range");
                assert!(
                    verify_inclusion(&entries[i as usize].leaf_hash(), i, n, &proof, &root),
                    "inclusion failed for leaf {i} of {n}"
                );
            }
        }
    }

    /// An inclusion proof must not verify a leaf that is not there. This is the
    /// direction that matters: a proof that accepts anything proves nothing.
    #[test]
    fn a_forged_leaf_has_no_inclusion_proof() {
        let log = log_of(9);
        let root = log.root();
        let proof = log.inclusion_proof(4).expect("in range");
        let forged = EffectReceipt {
            seq: 4,
            operation: Operation::GitPush,
            sink_class: SinkClass::GitPush,
            outcome: EffectOutcome::Allowed,
        };
        assert!(
            !verify_inclusion(&forged.leaf_hash(), 4, 9, &proof, &root),
            "a leaf that was never appended verified"
        );
    }

    /// Growth is provable: every earlier size is consistent with every later one.
    #[test]
    fn every_prefix_is_consistent_with_the_whole() {
        for n in 1u64..=17 {
            let full = log_of(n);
            let root_n = full.root();
            for m in 1..=n {
                let root_m = log_of(m).root();
                let proof = full.consistency_proof(m).expect("m in range");
                assert!(
                    verify_consistency(m, &root_m, n, &root_n, &proof),
                    "consistency failed for {m} -> {n}"
                );
            }
        }
    }

    /// **The property a hash chain cannot express.**
    ///
    /// An operator who drops the tail and recomputes produces a log that is
    /// internally perfect — every hash correct, every link intact. What they
    /// cannot do is prove that log consistent with a checkpoint the auditor
    /// already holds.
    #[test]
    fn a_rewritten_log_cannot_prove_consistency_with_an_earlier_checkpoint() {
        // Auditor saw 8 entries and kept the checkpoint.
        let seen = log_of(8).checkpoint();

        // Operator rewrites: keeps 5, appends 3 different ones.
        let rewritten = log_of(5);
        for _ in 0..3 {
            rewritten.append(
                Operation::GitPush,
                SinkClass::GitPush,
                EffectOutcome::Allowed,
            );
        }
        let now = rewritten.checkpoint();
        assert_eq!(
            now.size, seen.size,
            "same size — the sizes cannot betray it"
        );
        assert_ne!(now.root, seen.root);

        // Whatever proof they offer, at any size, it cannot bridge the two.
        for m in 1..=8u64 {
            if let Some(p) = rewritten.consistency_proof(m) {
                assert!(
                    !verify_consistency(seen.size, &seen.root, now.size, &now.root, &p),
                    "a rewritten log bridged an earlier checkpoint with the size-{m} proof"
                );
            }
        }
    }

    #[test]
    fn a_signed_checkpoint_verifies_and_a_tampered_one_does_not() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let vk = key.verifying_key();
        let log = log_of(6);
        let signed = log.sign_checkpoint(&key);
        assert!(signed.verify_signature(&vk));

        // Same signature, different claimed root.
        let mut forged = signed;
        forged.checkpoint.root[0] ^= 0xff;
        assert!(
            !forged.verify_signature(&vk),
            "a rewritten root kept its signature"
        );

        // Same signature, different claimed size.
        let mut resized = signed;
        resized.checkpoint.size += 1;
        assert!(
            !resized.verify_signature(&vk),
            "a rewritten size kept its signature"
        );
    }

    #[test]
    fn a_checkpoint_from_another_key_does_not_verify() {
        let log = log_of(4);
        let signed = log.sign_checkpoint(&SigningKey::from_bytes(&[1u8; 32]));
        let other = SigningKey::from_bytes(&[2u8; 32]).verifying_key();
        assert!(!signed.verify_signature(&other));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Witness — split-view detection
// ═══════════════════════════════════════════════════════════════════════════

/// Why a witness refused to cosign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessError {
    /// The checkpoint's signature did not verify against the log's key.
    BadLogSignature,
    /// The submitted `old_size` exceeds the checkpoint size — a log cannot
    /// shrink.
    OldSizeExceedsCheckpoint,
    /// The submitted `old_size` is not the size this witness last cosigned.
    ///
    /// The log is either behind, or is presenting a view that skips over what
    /// the witness already saw.
    StaleOrForkedOldSize {
        /// What this witness last cosigned for the origin.
        expected: u64,
        /// What the log submitted.
        submitted: u64,
    },
    /// The consistency proof did not verify: the new log is NOT an append-only
    /// extension of what this witness last saw. **This is a detected fork.**
    NotConsistent,
    /// Sizes were equal but the roots differed — a split view at the same size.
    SameSizeDifferentRoot,
    /// A zero-size checkpoint must carry the empty tree's root.
    BadEmptyRoot,
}

impl std::fmt::Display for WitnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WitnessError::BadLogSignature => write!(f, "checkpoint signature did not verify"),
            WitnessError::OldSizeExceedsCheckpoint => {
                write!(
                    f,
                    "old size exceeds the checkpoint size — a log cannot shrink"
                )
            }
            WitnessError::StaleOrForkedOldSize {
                expected,
                submitted,
            } => write!(
                f,
                "old size {submitted} is not the {expected} this witness last cosigned"
            ),
            WitnessError::NotConsistent => write!(
                f,
                "consistency proof failed — the log is not an append-only extension (FORK)"
            ),
            WitnessError::SameSizeDifferentRoot => {
                write!(f, "same size, different root — split view")
            }
            WitnessError::BadEmptyRoot => write!(f, "size-0 checkpoint with a non-empty root"),
        }
    }
}

impl std::error::Error for WitnessError {}

/// A witness's signature over a checkpoint it has verified.
#[derive(Debug, Clone, Copy)]
pub struct Cosignature {
    /// The checkpoint being attested.
    pub checkpoint: Checkpoint,
    /// Ed25519 by the witness key.
    pub signature: [u8; 64],
}

impl Cosignature {
    /// Check a cosignature against a known witness key.
    pub fn verify_signature(&self, witness_key: &VerifyingKey) -> bool {
        let sig = Signature::from_bytes(&self.signature);
        // Strict for the same reason as `SignedCheckpoint::verify`: a client
        // relying on "a witness cosigned this" needs the witness identity to be
        // unambiguous.
        witness_key
            .verify_strict(&self.checkpoint.signing_bytes(), &sig)
            .is_ok()
    }
}

/// A transparency-log witness for ONE log.
///
/// # What this is for
///
/// A signed checkpoint proves the operator *asserted* a root. It does not stop
/// them asserting a **different** root of the same size to somebody else — the
/// split-view attack, and the gap this module previously documented as open.
///
/// A witness closes it by remembering. It stores only the latest checkpoint it
/// has cosigned, and refuses to cosign anything that is not a provable
/// append-only extension of that. A forking log cannot get both views cosigned,
/// so a client that requires a cosignature cannot be shown a private view.
///
/// Per the C2SP `tlog-witness` protocol: *"only a single witness is required to
/// prove a log is append-only"* — more witnesses defend against collusion, not
/// against the basic attack.
///
/// # Scope
///
/// This is the **verification core**, not the service. There is no HTTP, no
/// persistence, and no origin multiplexing: those are deployment concerns, and
/// putting them here would mean shipping a network service that cannot be tested
/// in a unit test. What is here is the part that decides.
#[derive(Debug, Default)]
pub struct Witness {
    latest: Option<Checkpoint>,
}

impl Witness {
    /// A witness that has seen nothing yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// The latest checkpoint this witness has cosigned.
    pub fn latest(&self) -> Option<Checkpoint> {
        self.latest
    }

    /// Verify a checkpoint against everything this witness has seen, and cosign
    /// it if it is a sound append-only extension.
    ///
    /// The checks follow C2SP `tlog-witness` in order: log signature, size
    /// sanity, that `old_size` is exactly what this witness last cosigned, the
    /// RFC 6962 consistency proof, and the equal-size root match.
    ///
    /// On success the witness advances its stored state — which is what makes
    /// the *next* call able to detect a fork.
    pub fn witness(
        &mut self,
        submitted: &SignedCheckpoint,
        log_key: &VerifyingKey,
        old_size: u64,
        consistency_proof: &[[u8; 32]],
        witness_key: &SigningKey,
    ) -> Result<Cosignature, WitnessError> {
        if !submitted.verify_signature(log_key) {
            return Err(WitnessError::BadLogSignature);
        }
        let cp = submitted.checkpoint;

        if cp.size == 0 {
            let empty: [u8; 32] = Sha256::new().finalize().into();
            if cp.root != empty {
                return Err(WitnessError::BadEmptyRoot);
            }
        }
        if old_size > cp.size {
            return Err(WitnessError::OldSizeExceedsCheckpoint);
        }

        let expected = self.latest.map(|c| c.size).unwrap_or(0);
        if old_size != expected {
            return Err(WitnessError::StaleOrForkedOldSize {
                expected,
                submitted: old_size,
            });
        }

        match self.latest {
            None => {
                // Nothing seen yet: any checkpoint is acceptable, and the proof
                // must be empty because there is nothing to be consistent with.
                if !consistency_proof.is_empty() {
                    return Err(WitnessError::NotConsistent);
                }
            }
            Some(prev) => {
                if prev.size == cp.size {
                    // The split view, at its sharpest: same size, and the only
                    // question is whether the root moved.
                    if prev.root != cp.root {
                        return Err(WitnessError::SameSizeDifferentRoot);
                    }
                } else if !verify_consistency(
                    prev.size,
                    &prev.root,
                    cp.size,
                    &cp.root,
                    consistency_proof,
                ) {
                    return Err(WitnessError::NotConsistent);
                }
            }
        }

        self.latest = Some(cp);
        let sig = witness_key.sign(&cp.signing_bytes());
        Ok(Cosignature {
            checkpoint: cp,
            signature: sig.to_bytes(),
        })
    }
}

#[cfg(test)]
mod witness_tests {
    use super::*;

    fn log_of(n: u64) -> ReceiptLog {
        let log = ReceiptLog::new();
        for _ in 0..n {
            log.append(
                Operation::ReadFiles,
                SinkClass::AuditLogAppend,
                EffectOutcome::Allowed,
            );
        }
        log
    }

    fn keys() -> (SigningKey, VerifyingKey, SigningKey, VerifyingKey) {
        let log_key = SigningKey::from_bytes(&[3u8; 32]);
        let wit_key = SigningKey::from_bytes(&[4u8; 32]);
        let lvk = log_key.verifying_key();
        let wvk = wit_key.verifying_key();
        (log_key, lvk, wit_key, wvk)
    }

    /// Honest growth is cosigned at every step, and the cosignature verifies.
    #[test]
    fn a_growing_log_is_cosigned_at_every_step() {
        let (lk, lvk, wk, wvk) = keys();
        let mut w = Witness::new();
        let mut prev = 0u64;
        for n in 1u64..=12 {
            let log = log_of(n);
            let signed = log.sign_checkpoint(&lk);
            let proof = if prev == 0 {
                Vec::new()
            } else {
                log.consistency_proof(prev).expect("prev in range")
            };
            let co = w
                .witness(&signed, &lvk, prev, &proof, &wk)
                .unwrap_or_else(|e| panic!("honest growth {prev}->{n} refused: {e}"));
            assert!(co.verify_signature(&wvk));
            assert_eq!(w.latest().unwrap().size, n);
            prev = n;
        }
    }

    /// **The attack this exists to stop.**
    ///
    /// The log cosigns 8 entries with the witness, then rewrites history — keeps
    /// 5, appends 3 different ones — and presents the result at the SAME size, so
    /// the size cannot give it away. The signature is valid; the log's own
    /// internal structure is perfect. The witness refuses because it remembers.
    #[test]
    fn a_split_view_at_the_same_size_is_refused() {
        let (lk, lvk, wk, _wvk) = keys();
        let mut w = Witness::new();

        let honest = log_of(8);
        let first = honest.sign_checkpoint(&lk);
        w.witness(&first, &lvk, 0, &[], &wk).expect("first is fine");

        let rewritten = log_of(5);
        for _ in 0..3 {
            rewritten.append(
                Operation::GitPush,
                SinkClass::GitPush,
                EffectOutcome::Allowed,
            );
        }
        let forked = rewritten.sign_checkpoint(&lk);
        assert_eq!(forked.checkpoint.size, first.checkpoint.size);
        assert_ne!(forked.checkpoint.root, first.checkpoint.root);
        assert!(
            forked.verify_signature(&lvk),
            "the fork is validly signed — that is the point"
        );

        let err = w
            .witness(&forked, &lvk, 8, &[], &wk)
            .expect_err("a split view must not be cosigned");
        assert_eq!(err, WitnessError::SameSizeDifferentRoot);
    }

    /// A fork that also GROWS cannot buy its way past the witness either: no
    /// consistency proof exists from the witnessed root to a rewritten one.
    #[test]
    fn a_forked_log_that_grows_still_cannot_be_cosigned() {
        let (lk, lvk, wk, _wvk) = keys();
        let mut w = Witness::new();

        let honest = log_of(6);
        w.witness(&honest.sign_checkpoint(&lk), &lvk, 0, &[], &wk)
            .expect("first is fine");

        let rewritten = log_of(3);
        for _ in 0..7 {
            rewritten.append(
                Operation::GitPush,
                SinkClass::GitPush,
                EffectOutcome::Allowed,
            );
        }
        let forked = rewritten.sign_checkpoint(&lk);
        assert!(forked.checkpoint.size > 6);

        // Try every proof the forked log can produce.
        for m in 1..=forked.checkpoint.size {
            if let Some(p) = rewritten.consistency_proof(m) {
                assert!(
                    w.witness(&forked, &lvk, 6, &p, &wk).is_err(),
                    "a forked log was cosigned using the size-{m} proof"
                );
            }
        }
    }

    /// A log that lies about where the witness is gets caught before any proof
    /// is even checked — the witness knows what it last signed.
    #[test]
    fn a_wrong_old_size_is_refused() {
        let (lk, lvk, wk, _wvk) = keys();
        let mut w = Witness::new();
        let l6 = log_of(6);
        w.witness(&l6.sign_checkpoint(&lk), &lvk, 0, &[], &wk)
            .expect("first");

        let l9 = log_of(9);
        let proof = l9.consistency_proof(4).expect("in range");
        let err = w
            .witness(&l9.sign_checkpoint(&lk), &lvk, 4, &proof, &wk)
            .expect_err("old_size 4 is not the 6 the witness holds");
        assert_eq!(
            err,
            WitnessError::StaleOrForkedOldSize {
                expected: 6,
                submitted: 4
            }
        );
    }

    /// An unsigned or wrongly-signed checkpoint is refused before anything else.
    #[test]
    fn a_checkpoint_from_the_wrong_key_is_refused() {
        let (_lk, lvk, wk, _wvk) = keys();
        let impostor = SigningKey::from_bytes(&[9u8; 32]);
        let mut w = Witness::new();
        let err = w
            .witness(&log_of(3).sign_checkpoint(&impostor), &lvk, 0, &[], &wk)
            .expect_err("wrong key");
        assert_eq!(err, WitnessError::BadLogSignature);
    }

    /// A refused checkpoint must NOT advance the witness. If it did, one rejected
    /// fork would poison the witness's state and lock out the honest log.
    #[test]
    fn a_refusal_does_not_advance_the_witness() {
        let (lk, lvk, wk, _wvk) = keys();
        let mut w = Witness::new();
        let l4 = log_of(4);
        w.witness(&l4.sign_checkpoint(&lk), &lvk, 0, &[], &wk)
            .expect("first");
        assert_eq!(w.latest().unwrap().size, 4);

        let rewritten = log_of(2);
        for _ in 0..2 {
            rewritten.append(
                Operation::GitPush,
                SinkClass::GitPush,
                EffectOutcome::Allowed,
            );
        }
        let _ = w.witness(&rewritten.sign_checkpoint(&lk), &lvk, 4, &[], &wk);
        assert_eq!(
            w.latest().unwrap(),
            l4.checkpoint(),
            "a refusal must leave the witness on the last good checkpoint"
        );

        // And the honest log can still make progress afterwards.
        let l7 = log_of(7);
        let proof = l7.consistency_proof(4).expect("in range");
        w.witness(&l7.sign_checkpoint(&lk), &lvk, 4, &proof, &wk)
            .expect("the honest log is not locked out by a rejected fork");
    }
}
