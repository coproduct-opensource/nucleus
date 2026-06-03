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
    let digest = blake3::hash(&bytes);
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
}
