//! BLAKE3 transport hashing for bundles.
//!
//! # ⚠️  THIS IS A TRANSPORT ID, NOT THE CANONICAL HASH ⚠️
//!
//! [`blake3_bundle_hash`] computes a **BLAKE3-256 digest over the FULL
//! `serde_json::to_vec(&bundle)` bytes**. Its sole purpose is to address
//! the bundle for content-addressed transfer over iroh-blobs.
//!
//! This is **DISTINCT** from [`nucleus_envelope::canonical_bundle_hash`],
//! which is:
//!   - a **SHA-256** digest (not BLAKE3),
//!   - over **selected canonical fields** (session_root, chain head, payload
//!     hash) — NOT the full serialized bytes,
//!   - deliberately **excludes** the `attestation` field so an attestation
//!     can be attached/stripped without changing identity.
//!
//! Consequences you must not forget:
//!   - The two hashes will NEVER be equal and serve different roles. Use the
//!     canonical hash for attestation/identity; use THIS one only for
//!     transport addressing.
//!   - Because this hashes the FULL bytes, attaching an attestation, or any
//!     other byte-level change, produces a DIFFERENT [`BundleHash`]. That is
//!     correct for a transport id (it addresses exact bytes) and is exactly
//!     why it must not be conflated with the canonical identity.
//!   - The resulting 32 bytes are a **bare BLAKE3 digest — NOT a CID**.

use nucleus_envelope::Bundle;

use crate::BundleHash;

/// Compute the content-addressed transport id of `bundle`: the BLAKE3-256
/// root of `serde_json::to_vec(&bundle)`.
///
/// Deterministic: serde_json serializes struct fields in declaration order,
/// so the same `Bundle` value always yields the same bytes and therefore the
/// same hash. A single-byte change anywhere in the serialized form changes
/// the hash.
///
/// See the module docs: this is a TRANSPORT id, NOT
/// [`nucleus_envelope::canonical_bundle_hash`], and NOT a CID.
///
/// # Panics
///
/// Never in practice. `Bundle` is a plain `Serialize` tree of JSON-safe
/// types, so `serde_json::to_vec` cannot fail; we surface the impossible
/// case as an empty input rather than panicking.
pub fn blake3_bundle_hash(bundle: &Bundle) -> BundleHash {
    let bytes = serde_json::to_vec(bundle).unwrap_or_default();
    // Delegate to the generic byte hasher: the bundle path is just one caller
    // of the generic artifact CAS. No algorithm change.
    blake3_hash(&bytes)
}

/// Compute the BLAKE3-256 digest of arbitrary bytes (transport addressing only).
///
/// This is the low-level hash shared by [`blake3_bundle_hash`] and the generic
/// [`crate::publish::publish_bytes`]. Deterministic: the same bytes always
/// yield the same hash, and a single-byte change changes the hash.
///
/// Like [`blake3_bundle_hash`], the result is a bare BLAKE3-256 digest — a
/// TRANSPORT id, **NOT** [`nucleus_envelope::canonical_bundle_hash`] (SHA-256
/// over selected fields) and **NOT** a CID.
pub fn blake3_hash(data: &[u8]) -> BundleHash {
    let digest = blake3::hash(data);
    BundleHash(*digest.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_lineage::{CallSpiffeId, EdgeKind, InMemorySink, Jwks, LineageEdge, LineageSink};

    fn fixture_bundle(summary: &str) -> Bundle {
        let sink = InMemorySink::new();
        let p = CallSpiffeId::pod("prod.example.com", "agents", "summarizer").unwrap();
        sink.emit(LineageEdge::pod_admit(p.clone())).unwrap();
        sink.emit(LineageEdge::from_parent(
            p.derive_tool("Read", Some(b"hello")).unwrap(),
            p.clone(),
            EdgeKind::ToolCall {
                tool: "Read".to_string(),
            },
        ))
        .unwrap();
        nucleus_envelope::BundleBuilder::new(p)
            .payload(serde_json::json!({ "summary": summary }))
            .sink(&sink)
            .jwks(Jwks { keys: vec![] })
            .build()
            .unwrap()
    }

    #[test]
    fn blake3_bundle_hash_is_deterministic() {
        let b = fixture_bundle("hi");
        let h1 = blake3_bundle_hash(&b);
        let h2 = blake3_bundle_hash(&b);
        assert_eq!(h1, h2);
        assert_eq!(h1.as_bytes().len(), 32);
    }

    #[test]
    fn one_byte_payload_mutation_changes_the_hash() {
        let b = fixture_bundle("hi");
        let h1 = blake3_bundle_hash(&b);

        // Mutate exactly one payload byte ('hi' -> 'hj').
        let mut b2 = b.clone();
        b2.payload = serde_json::json!({ "summary": "hj" });
        let h2 = blake3_bundle_hash(&b2);

        assert_ne!(
            h1, h2,
            "a 1-byte payload change must change the BLAKE3 hash"
        );
    }

    #[test]
    fn distinct_from_canonical_sha256_hash() {
        // Documented invariant: the BLAKE3 transport id is not the SHA-256
        // canonical hash. Their byte values differ.
        let b = fixture_bundle("hi");
        let transport = blake3_bundle_hash(&b);
        let canonical = nucleus_envelope::canonical_bundle_hash(&b);
        assert_ne!(transport.as_bytes(), &canonical);
    }

    #[test]
    fn three_distinct_ids_invariant_blake3_vs_sha256() {
        // Load-bearing invariant: BLAKE3-256 (transport) and SHA-256
        // (canonical) are computed independently via distinct algorithms and
        // never conflated. This encodes the "three distinct ids" discipline:
        //   1. BLAKE3-256 transport hash (over the FULL serialized bytes, here)
        //   2. SHA-256 canonical hash (over selected fields, nucleus-envelope)
        //   3. No CID (no multihash/multicodec/multibase framing)
        //
        // Consequence: if either algorithm is mutated or wrongly shared, this
        // test catches the divergence. Byte-integrity != provenance.
        let bundle = fixture_bundle("three_ids");

        // (1) BLAKE3 transport hash over the full serialized bytes.
        let transport_blake3 = blake3_bundle_hash(&bundle);

        // (2) SHA-256 canonical hash over selected fields (excludes attestation).
        let canonical_sha256 = nucleus_envelope::canonical_bundle_hash(&bundle);

        // Independently computed => the byte sequences differ.
        assert_ne!(
            transport_blake3.as_bytes().as_slice(),
            canonical_sha256.as_slice(),
            "BLAKE3 transport hash (full bytes) must differ from \
             SHA-256 canonical hash (selected fields)"
        );

        // Both are 32 bytes, but from different algorithms over different inputs.
        assert_eq!(transport_blake3.as_bytes().len(), 32);
        assert_eq!(canonical_sha256.len(), 32);

        // (3) BundleHash is NOT a CID — no multihash, multicodec, or multibase.
        let hex = transport_blake3.to_hex();
        assert_eq!(hex.len(), 64, "raw 32-byte BLAKE3 -> 64 hex chars");
        assert!(
            !hex.starts_with('z'),
            "BundleHash must not be multibase-encoded"
        );
    }

    #[test]
    fn blake3_hash_matches_bundle_hash_over_same_bytes() {
        // The generic byte hasher and the bundle hasher agree byte-for-byte
        // (the bundle path is a thin caller). No algorithm divergence.
        let b = fixture_bundle("hi");
        let bytes = serde_json::to_vec(&b).unwrap();
        assert_eq!(blake3_hash(&bytes), blake3_bundle_hash(&b));
    }
}
