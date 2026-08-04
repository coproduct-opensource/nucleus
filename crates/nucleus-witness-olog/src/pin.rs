//! `pin.rs` — relying-party trust **pinning** (Phase 2 economic layer "B").
//!
//! The deep-research verdict put this first: for a neutral verification fabric the
//! strongest, most regulation-clean moat is the **transparency-logged history
//! itself + relying parties who pin trust to *our* log specifically**. Its one
//! failure mode is the leak: if relying parties treat our log as one of many
//! interchangeable logs, a fork can copy the public history, re-anchor it in its
//! own log, and claim equivalence — the data moat evaporates.
//!
//! This module is the fix. A relying party holds a [`PinnedLog`] — the canonical
//! log's **origin + public key + a known checkpoint (root, size)** — and
//! [`accept_fact`] admits a fact **only** if:
//!
//! 1. the presented checkpoint's **origin** matches the pin, and
//! 2. it is signed by the **pinned key** (a checkpoint from any *other* log key is
//!    rejected — this is the anti-re-anchor moat: a fork's checkpoint is signed by
//!    a different key, so its "copy" of our history is not accepted), and
//! 3. the presented checkpoint is **append-only-consistent** with the pinned
//!    checkpoint (RFC 6962 consistency proof — the log cannot rewrite history),
//!    and never older than the pin, and
//! 4. the fact's leaf is **included** under the presented checkpoint (RFC 6962
//!    inclusion proof).
//!
//! The Merkle inclusion/consistency math is the audited `ct-merkle` crate; the
//! checkpoint signature uses the same Ed25519 + domain-tagged discipline as the
//! rest of this crate. The novel part — and the moat — is the **pinning policy +
//! foreign-log rejection**.
//!
//! ## Honesty boundary
//!
//! Pinning makes the data/history moat *not leak* to a fork; it does not, by
//! itself, force adoption (relying parties must actually pin). And it secures
//! "this fact is in the log I pinned, append-only" — not the truthfulness of the
//! fact's content (that is the witness/recompute layer). It is the relying-party
//! half of the CT/Sigstore model, stated without overclaim.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ct_merkle::{ConsistencyProof, InclusionProof, RootHash};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::digest::Output;
use sha2::Sha256;
use thiserror::Error;

/// Domain tag for a checkpoint's canonical signing bytes (versioned).
pub const CHECKPOINT_DOMAIN: &[u8] = b"nucleus/witness-olog/checkpoint/v1\0";

fn push_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The identity of the canonical proof-ledger a relying party pins: the log's
/// `origin` string and its Ed25519 public key bytes. A checkpoint that is not
/// signed by THIS key (even if internally consistent) is a *foreign log*.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogIdentity {
    pub origin: String,
    pub log_pubkey: [u8; 32],
}

/// A signed checkpoint (signed tree head): the log asserts `root` at `tree_size`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedCheckpoint {
    pub origin: String,
    pub tree_size: u64,
    pub root: [u8; 32],
    pub kid: String,
    pub sig_b64: String,
}

pub fn canonical_checkpoint_bytes(c: &SignedCheckpoint) -> Vec<u8> {
    let mut out = Vec::with_capacity(96);
    out.extend_from_slice(CHECKPOINT_DOMAIN);
    push_field(&mut out, c.origin.as_bytes());
    out.extend_from_slice(&c.tree_size.to_be_bytes());
    push_field(&mut out, &c.root);
    push_field(&mut out, c.kid.as_bytes());
    out
}

pub fn sign_checkpoint(sk: &SigningKey, mut c: SignedCheckpoint) -> SignedCheckpoint {
    c.sig_b64 = STANDARD.encode(sk.sign(&canonical_checkpoint_bytes(&c)).to_bytes());
    c
}

/// The relying party's pin: the canonical log identity + a checkpoint it trusts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinnedLog {
    pub identity: LogIdentity,
    pub pinned_tree_size: u64,
    pub pinned_root: [u8; 32],
}

/// Why a fact was rejected. Each variant is a distinct moat property.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TrustRejection {
    /// The checkpoint's origin differs from the pinned log.
    #[error("foreign log origin: {got:?} != pinned {pinned:?}")]
    ForeignLogOrigin { got: String, pinned: String },
    /// The presenter's key is not the pinned log key (the anti-re-anchor moat:
    /// a fork's copy is signed by a different key).
    #[error("foreign log key (not the pinned key)")]
    ForeignLogKey,
    /// The checkpoint signature did not verify under the pinned key.
    #[error("checkpoint signature invalid: {0}")]
    BadCheckpointSig(String),
    /// Signature bytes were malformed.
    #[error("checkpoint signature malformed: {0}")]
    MalformedSig(String),
    /// The presented checkpoint is older than the pin.
    #[error("stale checkpoint: size {got} < pinned {pinned}")]
    Stale { got: u64, pinned: u64 },
    /// The presented checkpoint is not an append-only extension of the pin.
    #[error("not append-only: consistency proof failed: {0}")]
    NotAppendOnly(String),
    /// The fact's leaf is not included under the presented checkpoint.
    #[error("fact not included: {0}")]
    NotIncluded(String),
}

fn to_root(bytes: [u8; 32], size: u64) -> RootHash<Sha256> {
    let digest = Output::<Sha256>::try_from(&bytes[..]).expect("root hash is exactly 32 bytes");
    RootHash::new(digest, size)
}

fn verify_checkpoint_sig(c: &SignedCheckpoint, vk: &VerifyingKey) -> Result<(), TrustRejection> {
    let sig_bytes = STANDARD
        .decode(&c.sig_b64)
        .map_err(|e| TrustRejection::MalformedSig(e.to_string()))?;
    if sig_bytes.len() != 64 {
        return Err(TrustRejection::MalformedSig(format!(
            "{} bytes, expected 64",
            sig_bytes.len()
        )));
    }
    let mut buf = [0u8; 64];
    buf.copy_from_slice(&sig_bytes);
    vk.verify_strict(&canonical_checkpoint_bytes(c), &Signature::from_bytes(&buf))
        .map_err(|e| TrustRejection::BadCheckpointSig(e.to_string()))
}

/// Admit a fact only if it is included, under a checkpoint signed by the **pinned
/// log key**, that is append-only-consistent with the pinned checkpoint. `leaf` is
/// the fact's leaf value (e.g. an `AccumulationManifest`'s canonical bytes); it is
/// hashed by `ct-merkle` with the RFC 6962 leaf prefix, the same way the log built
/// the tree.
#[allow(clippy::too_many_arguments)]
pub fn accept_fact(
    pinned: &PinnedLog,
    presented: &SignedCheckpoint,
    presented_vk: &VerifyingKey,
    consistency_proof: &ConsistencyProof<Sha256>,
    leaf: &[u8],
    leaf_index: u64,
    inclusion_proof: &InclusionProof<Sha256>,
) -> Result<(), TrustRejection> {
    // 1. Same log (origin).
    if presented.origin != pinned.identity.origin {
        return Err(TrustRejection::ForeignLogOrigin {
            got: presented.origin.clone(),
            pinned: pinned.identity.origin.clone(),
        });
    }
    // 2. The presenter's key MUST be the pinned key — a fork that re-anchors our
    //    history into its own log signs with a different key and is rejected here,
    //    even if its checkpoint is internally valid.
    if presented_vk.to_bytes() != pinned.identity.log_pubkey {
        return Err(TrustRejection::ForeignLogKey);
    }
    // 3. The checkpoint is signed by that pinned key.
    verify_checkpoint_sig(presented, presented_vk)?;
    // 4. Never older than the pin.
    if presented.tree_size < pinned.pinned_tree_size {
        return Err(TrustRejection::Stale {
            got: presented.tree_size,
            pinned: pinned.pinned_tree_size,
        });
    }
    let pinned_root = to_root(pinned.pinned_root, pinned.pinned_tree_size);
    let presented_root = to_root(presented.root, presented.tree_size);
    // 5. Append-only: the presented root extends the pinned root.
    presented_root
        .verify_consistency(&pinned_root, consistency_proof)
        .map_err(|e| TrustRejection::NotAppendOnly(format!("{e:?}")))?;
    // 6. Inclusion of the fact's leaf under the presented checkpoint.
    presented_root
        .verify_inclusion(&leaf.to_vec(), leaf_index, inclusion_proof)
        .map_err(|e| TrustRejection::NotIncluded(format!("{e:?}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_merkle::mem_backed_tree::MemoryBackedTree;

    const ORIGIN: &str = "nucleus.witness-olog/v1";

    fn log_sk() -> SigningKey {
        SigningKey::from_bytes(&[11u8; 32])
    }

    fn checkpoint(tree: &MemoryBackedTree<Sha256, Vec<u8>>, sk: &SigningKey) -> SignedCheckpoint {
        let root = tree.root();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(root.as_bytes().as_slice());
        sign_checkpoint(
            sk,
            SignedCheckpoint {
                origin: ORIGIN.into(),
                tree_size: root.num_leaves(),
                root: bytes,
                kid: "log-k".into(),
                sig_b64: String::new(),
            },
        )
    }

    /// Build a tree of `n` leaves, return (tree, pinned checkpoint at `pin_size`).
    fn setup(
        n: usize,
        pin_size: usize,
    ) -> (
        MemoryBackedTree<Sha256, Vec<u8>>,
        PinnedLog,
        SignedCheckpoint,
    ) {
        let sk = log_sk();
        // Build the tree at the pinned size first to capture its checkpoint.
        let mut tree = MemoryBackedTree::<Sha256, Vec<u8>>::new();
        for i in 0..pin_size {
            tree.push(vec![i as u8; 4]);
        }
        let pinned_cp = checkpoint(&tree, &sk);
        let pinned = PinnedLog {
            identity: LogIdentity {
                origin: ORIGIN.into(),
                log_pubkey: sk.verifying_key().to_bytes(),
            },
            pinned_tree_size: pinned_cp.tree_size,
            pinned_root: pinned_cp.root,
        };
        for i in pin_size..n {
            tree.push(vec![i as u8; 4]);
        }
        (tree, pinned, pinned_cp)
    }

    #[test]
    fn accepts_included_fact_under_pinned_consistent_log() {
        let sk = log_sk();
        let (tree, pinned, _) = setup(8, 4);
        let presented = checkpoint(&tree, &sk);
        let consistency = tree.prove_consistency(pinned.pinned_tree_size as usize);
        let idx = 5u64; // a leaf added after the pin
        let leaf = vec![idx as u8; 4];
        let inclusion = tree.prove_inclusion(idx as usize);
        accept_fact(
            &pinned,
            &presented,
            &sk.verifying_key(),
            &consistency,
            &leaf,
            idx,
            &inclusion,
        )
        .expect("honest included fact must be accepted");
    }

    #[test]
    fn rejects_foreign_log_key_even_if_internally_valid() {
        // A "fork" copies the history into its OWN log signed by a different key.
        let fork_sk = SigningKey::from_bytes(&[99u8; 32]);
        let (tree, pinned, _) = setup(8, 4);
        let presented = checkpoint(&tree, &fork_sk); // signed by the fork's key
        let consistency = tree.prove_consistency(pinned.pinned_tree_size as usize);
        let idx = 5u64;
        let leaf = vec![idx as u8; 4];
        let inclusion = tree.prove_inclusion(idx as usize);
        let err = accept_fact(
            &pinned,
            &presented,
            &fork_sk.verifying_key(),
            &consistency,
            &leaf,
            idx,
            &inclusion,
        )
        .unwrap_err();
        assert_eq!(
            err,
            TrustRejection::ForeignLogKey,
            "the anti-re-anchor moat"
        );
    }

    #[test]
    fn rejects_foreign_origin() {
        let sk = log_sk();
        let (tree, pinned, _) = setup(8, 4);
        let mut presented = checkpoint(&tree, &sk);
        presented.origin = "evil.fork/v1".into();
        let presented = sign_checkpoint(&sk, presented); // re-sign so only origin differs
        let consistency = tree.prove_consistency(pinned.pinned_tree_size as usize);
        let inclusion = tree.prove_inclusion(5);
        let err = accept_fact(
            &pinned,
            &presented,
            &sk.verifying_key(),
            &consistency,
            &[5u8; 4],
            5,
            &inclusion,
        )
        .unwrap_err();
        assert!(matches!(err, TrustRejection::ForeignLogOrigin { .. }));
    }

    #[test]
    fn rejects_tampered_checkpoint_signature() {
        let sk = log_sk();
        let (tree, pinned, _) = setup(8, 4);
        let mut presented = checkpoint(&tree, &sk);
        presented.root[0] ^= 0xFF; // tamper after signing
        let consistency = tree.prove_consistency(pinned.pinned_tree_size as usize);
        let inclusion = tree.prove_inclusion(5);
        let err = accept_fact(
            &pinned,
            &presented,
            &sk.verifying_key(),
            &consistency,
            &[5u8; 4],
            5,
            &inclusion,
        )
        .unwrap_err();
        assert!(matches!(err, TrustRejection::BadCheckpointSig(_)));
    }

    #[test]
    fn rejects_non_included_leaf() {
        let sk = log_sk();
        let (tree, pinned, _) = setup(8, 4);
        let presented = checkpoint(&tree, &sk);
        let consistency = tree.prove_consistency(pinned.pinned_tree_size as usize);
        let inclusion = tree.prove_inclusion(5);
        // Present a DIFFERENT leaf value than the one the proof is for.
        let err = accept_fact(
            &pinned,
            &presented,
            &sk.verifying_key(),
            &consistency,
            &[0xAAu8; 4],
            5,
            &inclusion,
        )
        .unwrap_err();
        assert!(matches!(err, TrustRejection::NotIncluded(_)));
    }
}
