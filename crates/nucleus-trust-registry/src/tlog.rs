// SPDX-License-Identifier: MIT
//
//! Transparency log of trust roots.
//!
//! Every merged binding is appended as a leaf into an RFC 6962 Merkle log
//! (`ct_merkle`, the SAME crate + pin the lineage log uses). After
//! appending, we cut a Signed Tree Head (reusing
//! [`nucleus_lineage::Ed25519Witness`]) and **cosign** it with an
//! independent witness (reusing [`nucleus_witness::WitnessKey`]'s C2SP
//! `tlog-cosignature` path). The cosigned STH + per-leaf inclusion proofs
//! are persisted.
//!
//! # The trust rule the verifier enforces
//!
//! A binding is "trusted" by [`verify_binding_in_log`] ONLY if:
//!
//! 1. its leaf hash is `H(trust_domain ‖ canonical_json(bundle) ‖
//!    owner_id ‖ ts)`, AND
//! 2. an inclusion proof places that leaf in the STH's tree at the
//!    STH's root, AND
//! 3. the STH carries a valid witness cosignature.
//!
//! Consequences (the security properties):
//! - A rogue/backdated binding inserted into a copy of the log but NOT
//!   present in the cosigned STH has no inclusion proof against the
//!   cosigned root → rejected.
//! - Tampering with the bundle changes `canonical_json(bundle)` → the
//!   leaf hash changes → the stored inclusion proof no longer verifies
//!   → rejected.
//!
//! # Single witness — honest scope
//!
//! MVP is one registry maintainer + one witness. This is "auditable, not
//! un-backdoorable": the cosignature makes a maintainer who serves a
//! split view DETECTABLE to anyone holding the witness key, but a single
//! witness colluding with the maintainer is not defended against. We do
//! NOT borrow Sigstore threshold/ceremony language; adding more witnesses
//! is a drop-in (the cosign primitive is per-witness).

use ct_merkle::mem_backed_tree::MemoryBackedTree;
use ct_merkle::{InclusionProof, RootHash};
use nucleus_lineage::checkpoint::{Ed25519Witness, SignedTreeHead, TreeWitness};
use nucleus_lineage::signed_note::format_checkpoint_body;
use nucleus_witness::cosign::{verify_cosign_line, WitnessKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::RegistryError;

/// The C2SP "origin" string for this transparency log. Schema-less,
/// printable-ASCII (validated by `format_checkpoint_body`).
pub const LOG_ORIGIN: &str = "nucleus.trust-registry/v1";

/// Compute the canonical leaf bytes for a binding:
/// `SHA-256(len-prefixed(trust_domain) ‖ canonical_json(bundle) ‖
/// owner_id(8, big-endian) ‖ ts(8, big-endian))`.
///
/// Length-prefixing the trust-domain string makes the concatenation
/// unambiguous (no field can bleed into the next). `canonical_json` is the
/// `serde_json` re-serialization of the parsed bundle, so a byte-reordered
/// but semantically-identical bundle hashes the same, while ANY change to
/// the key material changes the leaf.
pub fn binding_leaf(
    trust_domain: &str,
    bundle_bytes: &[u8],
    owner_id: u64,
    ts: u64,
) -> Result<[u8; 32], RegistryError> {
    let canonical = canonical_json(bundle_bytes)?;
    let mut h = Sha256::new();
    h.update((trust_domain.len() as u64).to_be_bytes());
    h.update(trust_domain.as_bytes());
    h.update((canonical.len() as u64).to_be_bytes());
    h.update(&canonical);
    h.update(owner_id.to_be_bytes());
    h.update(ts.to_be_bytes());
    Ok(h.finalize().into())
}

/// Canonicalize bundle JSON by parsing to a `serde_json::Value` and
/// re-serializing. `serde_json` sorts object keys only with the
/// `preserve_order` feature OFF (default `BTreeMap`-backed map), giving a
/// deterministic byte string for semantically-equal inputs.
fn canonical_json(bundle_bytes: &[u8]) -> Result<Vec<u8>, RegistryError> {
    let value: serde_json::Value = serde_json::from_slice(bundle_bytes)
        .map_err(|e| RegistryError::Bundle(format!("bundle is not valid json: {e}")))?;
    // RFC 8785 JCS: lexicographic key sort applied during serialization,
    // independent of serde_json's Map type — so the binding leaf is stable even
    // when the `preserve_order` feature is unified on across the workspace
    // (serde_json's default Map ordering is NOT a canonicalization guarantee).
    serde_jcs::to_vec(&value).map_err(|e| RegistryError::Bundle(format!("canonicalize (JCS): {e}")))
}

/// One appended binding's record: its leaf index + the leaf hash. Used to
/// look up inclusion proofs after the tree is sealed.
#[derive(Debug, Clone)]
pub struct AppendedLeaf {
    /// 0-based leaf index in the Merkle tree.
    pub index: u64,
    /// The 32-byte leaf hash (`binding_leaf`).
    pub leaf_hash: [u8; 32],
}

/// An append-only transparency log of trust-root bindings.
///
/// Wraps a `ct_merkle` memory-backed tree. Append bindings, then
/// [`Self::seal`] to produce a cosigned STH + inclusion proofs.
#[derive(Default)]
pub struct TrustLog {
    tree: MemoryBackedTree<Sha256, Vec<u8>>,
    leaves: Vec<AppendedLeaf>,
}

impl TrustLog {
    /// A fresh, empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a binding leaf. Returns the [`AppendedLeaf`] record.
    pub fn append_binding(
        &mut self,
        trust_domain: &str,
        bundle_bytes: &[u8],
        owner_id: u64,
        ts: u64,
    ) -> Result<AppendedLeaf, RegistryError> {
        let leaf_hash = binding_leaf(trust_domain, bundle_bytes, owner_id, ts)?;
        let index = self.tree.len();
        self.tree.push(leaf_hash.to_vec());
        let rec = AppendedLeaf { index, leaf_hash };
        self.leaves.push(rec.clone());
        Ok(rec)
    }

    /// Current tree size (leaf count).
    pub fn len(&self) -> u64 {
        self.tree.len()
    }

    /// Whether the log is empty.
    pub fn is_empty(&self) -> bool {
        self.tree.len() == 0
    }

    /// Seal the current tree: sign an STH with `witness`, cosign its C2SP
    /// checkpoint body with `cosigner`, and gather inclusion proofs for
    /// every appended leaf.
    ///
    /// Returns a [`SealedLog`] holding the cosigned STH + per-leaf
    /// inclusion proofs — exactly the artifacts a verifier needs.
    pub fn seal(
        &self,
        witness: &Ed25519Witness,
        cosigner: &WitnessKey,
        cosign_timestamp: u64,
    ) -> Result<SealedLog, RegistryError> {
        let root = self.tree.root();
        let tree_size = root.num_leaves();
        let mut root_bytes = [0u8; 32];
        root_bytes.copy_from_slice(root.as_bytes().as_slice());

        let sth = witness
            .sign_sth(tree_size, &root_bytes)
            .map_err(|e| RegistryError::Cosignature(format!("STH sign: {e}")))?;

        // Cosign the C2SP checkpoint body over (origin, size, root). The
        // cosignature commits the witness to THIS (size, root) tuple.
        let note_body = format_checkpoint_body(LOG_ORIGIN, tree_size, &root_bytes)
            .map_err(|e| RegistryError::Cosignature(format!("checkpoint body: {e}")))?;
        let cosign_line = cosigner.cosign_line(note_body.as_bytes(), cosign_timestamp);

        let mut proofs = Vec::with_capacity(self.leaves.len());
        for leaf in &self.leaves {
            let proof = self.tree.prove_inclusion(leaf.index as usize);
            proofs.push(StoredInclusion {
                trust_domain_index: leaf.index,
                leaf_hash_hex: hex::encode(leaf.leaf_hash),
                proof_hex: hex::encode(proof.as_bytes()),
            });
        }

        Ok(SealedLog {
            sth,
            origin: LOG_ORIGIN.to_string(),
            cosign_line,
            cosigner_pubkey_hex: hex::encode(cosigner.verifying_key_bytes()),
            inclusions: proofs,
        })
    }
}

/// A stored inclusion proof for one leaf (serializable to disk / PR
/// artifact).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredInclusion {
    /// Leaf index in the tree.
    pub trust_domain_index: u64,
    /// Hex of the 32-byte leaf hash.
    pub leaf_hash_hex: String,
    /// Hex of the inclusion proof bytes (`InclusionProof::as_bytes`).
    pub proof_hex: String,
}

/// The persisted output of sealing the log: the cosigned STH + inclusion
/// proofs. This is the artifact a verifier loads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedLog {
    /// The witness-signed tree head.
    pub sth: SignedTreeHead,
    /// The C2SP log origin string (binds the cosignature body).
    pub origin: String,
    /// The witness cosignature line (C2SP `tlog-cosignature`).
    pub cosign_line: String,
    /// Hex of the cosigner's Ed25519 verifying key (published
    /// out-of-band; a verifier pins this).
    pub cosigner_pubkey_hex: String,
    /// One inclusion proof per appended binding.
    pub inclusions: Vec<StoredInclusion>,
}

impl SealedLog {
    /// Reconstruct the `ct_merkle` [`RootHash`] from the STH's signed
    /// root + tree size, so a verifier can check inclusion proofs without
    /// the original tree.
    fn root_hash(&self) -> Result<RootHash<Sha256>, RegistryError> {
        let bytes = hex::decode(&self.sth.root_hash_hex)
            .map_err(|e| RegistryError::NotInLog(format!("bad STH root hex: {e}")))?;
        let digest: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| RegistryError::NotInLog("STH root is not 32 bytes".to_string()))?;
        Ok(RootHash::new(digest.into(), self.sth.tree_size))
    }
}

/// Verify that a binding is trusted: its leaf is in the cosigned STH AND
/// the witness cosignature over the STH is valid.
///
/// `expected_cosigner_pubkey` is the out-of-band-pinned witness public
/// key (32 bytes). The verifier MUST supply it — trusting the pubkey
/// embedded in the artifact alone would let a forger ship their own
/// cosignature. (Here we both pin it and cross-check it against the
/// embedded one.)
///
/// Steps:
/// 1. Recompute the binding leaf hash from `(trust_domain, bundle_bytes,
///    owner_id, ts)`. Tampering with the bundle changes this hash.
/// 2. Find the stored inclusion proof for that leaf hash; verify it
///    against the STH root. A leaf not in the cosigned STH has no
///    verifying proof → reject.
/// 3. Verify the witness cosignature over the STH's C2SP body against
///    the pinned cosigner key.
pub fn verify_binding_in_log(
    sealed: &SealedLog,
    trust_domain: &str,
    bundle_bytes: &[u8],
    owner_id: u64,
    ts: u64,
    expected_cosigner_pubkey: &[u8; 32],
) -> Result<(), RegistryError> {
    // (1) recompute the leaf hash.
    let leaf_hash = binding_leaf(trust_domain, bundle_bytes, owner_id, ts)?;
    let leaf_hash_hex = hex::encode(leaf_hash);

    // (2) inclusion against the cosigned STH root.
    let stored = sealed
        .inclusions
        .iter()
        .find(|s| s.leaf_hash_hex == leaf_hash_hex)
        .ok_or_else(|| {
            RegistryError::NotInLog(format!(
                "no inclusion proof for binding leaf {leaf_hash_hex} (not in cosigned log, or bundle tampered)"
            ))
        })?;
    let root = sealed.root_hash()?;
    let proof_bytes = hex::decode(&stored.proof_hex)
        .map_err(|e| RegistryError::NotInLog(format!("bad inclusion proof hex: {e}")))?;
    // `InclusionProof::from_bytes` panics on a non-multiple-of-32 length;
    // guard it so a malformed artifact is a clean reject, not a panic.
    if proof_bytes.len() % 32 != 0 {
        return Err(RegistryError::NotInLog(
            "inclusion proof length is not a multiple of the digest size".to_string(),
        ));
    }
    let proof = InclusionProof::<Sha256>::from_bytes(proof_bytes);
    root.verify_inclusion(&leaf_hash.to_vec(), stored.trust_domain_index, &proof)
        .map_err(|e| {
            RegistryError::NotInLog(format!(
                "inclusion proof does not verify against cosigned STH root: {e:?}"
            ))
        })?;

    // (3) cosignature over the C2SP body for THIS (size, root).
    let mut root_bytes = [0u8; 32];
    let root_decoded = hex::decode(&sealed.sth.root_hash_hex)
        .map_err(|e| RegistryError::Cosignature(format!("bad STH root hex: {e}")))?;
    if root_decoded.len() != 32 {
        return Err(RegistryError::Cosignature(
            "STH root not 32 bytes".to_string(),
        ));
    }
    root_bytes.copy_from_slice(&root_decoded);
    let note_body = format_checkpoint_body(&sealed.origin, sealed.sth.tree_size, &root_bytes)
        .map_err(|e| RegistryError::Cosignature(format!("checkpoint body: {e}")))?;
    // Defense in depth: the embedded cosigner pubkey must match the pin.
    let embedded = hex::decode(&sealed.cosigner_pubkey_hex)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        .ok_or_else(|| RegistryError::Cosignature("bad embedded cosigner pubkey".to_string()))?;
    if &embedded != expected_cosigner_pubkey {
        return Err(RegistryError::Cosignature(
            "embedded cosigner pubkey does not match the pinned witness key".to_string(),
        ));
    }
    verify_cosign_line(
        &sealed.cosign_line,
        note_body.as_bytes(),
        expected_cosigner_pubkey,
    )
    .map_err(|e| RegistryError::Cosignature(format!("witness cosignature invalid: {e}")))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUNDLE: &[u8] = br#"{"keys":[{"kty":"EC","crv":"P-256","use":"jwt-svid","kid":"k1","x":"AA","y":"BB"}],"spiffe_sequence":1}"#;

    fn witness() -> Ed25519Witness {
        Ed25519Witness::from_seed([3u8; 32])
    }
    fn cosigner() -> WitnessKey {
        WitnessKey::from_seed([9u8; 32], "nucleus.trust-registry/witness-1")
    }

    #[test]
    fn append_seal_verify_round_trip() {
        let mut log = TrustLog::new();
        log.append_binding("ci.example.org", BUNDLE, 12345, 1000)
            .unwrap();
        let sealed = log.seal(&witness(), &cosigner(), 1_700_000_000).unwrap();
        verify_binding_in_log(
            &sealed,
            "ci.example.org",
            BUNDLE,
            12345,
            1000,
            &cosigner().verifying_key_bytes(),
        )
        .unwrap();
    }

    #[test]
    fn tampered_bundle_fails_inclusion() {
        let mut log = TrustLog::new();
        log.append_binding("ci.example.org", BUNDLE, 12345, 1000)
            .unwrap();
        let sealed = log.seal(&witness(), &cosigner(), 1_700_000_000).unwrap();
        let tampered = br#"{"keys":[{"kty":"EC","crv":"P-256","use":"jwt-svid","kid":"ATTACKER","x":"AA","y":"BB"}],"spiffe_sequence":1}"#;
        let err = verify_binding_in_log(
            &sealed,
            "ci.example.org",
            tampered,
            12345,
            1000,
            &cosigner().verifying_key_bytes(),
        )
        .unwrap_err();
        assert!(matches!(err, RegistryError::NotInLog(_)));
    }

    #[test]
    fn binding_not_in_log_rejected() {
        let mut log = TrustLog::new();
        log.append_binding("ci.example.org", BUNDLE, 12345, 1000)
            .unwrap();
        let sealed = log.seal(&witness(), &cosigner(), 1_700_000_000).unwrap();
        // A different domain never appended → no inclusion proof.
        let err = verify_binding_in_log(
            &sealed,
            "rogue.example.org",
            BUNDLE,
            999,
            1000,
            &cosigner().verifying_key_bytes(),
        )
        .unwrap_err();
        assert!(matches!(err, RegistryError::NotInLog(_)));
    }

    #[test]
    fn wrong_cosigner_key_rejected() {
        let mut log = TrustLog::new();
        log.append_binding("ci.example.org", BUNDLE, 12345, 1000)
            .unwrap();
        let sealed = log.seal(&witness(), &cosigner(), 1_700_000_000).unwrap();
        let other = WitnessKey::from_seed([42u8; 32], "other");
        let err = verify_binding_in_log(
            &sealed,
            "ci.example.org",
            BUNDLE,
            12345,
            1000,
            &other.verifying_key_bytes(),
        )
        .unwrap_err();
        assert!(matches!(err, RegistryError::Cosignature(_)));
    }

    #[test]
    fn canonical_json_is_key_order_invariant() {
        let a = br#"{"spiffe_sequence":1,"keys":[]}"#;
        let b = br#"{"keys":[],"spiffe_sequence":1}"#;
        assert_eq!(
            binding_leaf("d", a, 1, 1).unwrap(),
            binding_leaf("d", b, 1, 1).unwrap()
        );
    }

    #[test]
    fn multiple_bindings_each_verify() {
        let mut log = TrustLog::new();
        log.append_binding("a.example.org", BUNDLE, 1, 100).unwrap();
        log.append_binding("b.example.org", BUNDLE, 2, 200).unwrap();
        log.append_binding("c.example.org", BUNDLE, 3, 300).unwrap();
        let sealed = log.seal(&witness(), &cosigner(), 1_700_000_000).unwrap();
        let pk = cosigner().verifying_key_bytes();
        verify_binding_in_log(&sealed, "a.example.org", BUNDLE, 1, 100, &pk).unwrap();
        verify_binding_in_log(&sealed, "b.example.org", BUNDLE, 2, 200, &pk).unwrap();
        verify_binding_in_log(&sealed, "c.example.org", BUNDLE, 3, 300, &pk).unwrap();
    }
}
