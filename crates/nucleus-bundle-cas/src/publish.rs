//! Publish a [`Bundle`] into an iroh-blobs store under its BLAKE3 root.
//!
//! "Publish" here means LOCAL availability: the bytes are added to a store so
//! that a [`crate::fetch::fetch_bundle`] caller (who has the node ticket
//! out-of-band) can pull them. There is NO advertisement, NO DHT, NO
//! discovery — see the crate-level trust-model docs.

use iroh_blobs::store::mem::MemStore;
use nucleus_envelope::Bundle;

use crate::{blake3_bundle_hash, BundleHash};

/// Errors from [`publish_bytes`] (generic artifact publishing).
#[derive(Debug, thiserror::Error)]
pub enum PublishBytesError {
    /// The iroh-blobs store rejected the add.
    #[error("iroh-blobs add_bytes failed: {0}")]
    Store(#[source] anyhow::Error),
    /// The store hashed the bytes with a different BLAKE3 root than we computed
    /// locally. This should be impossible (both use BLAKE3-256 over the same
    /// bytes) — surfaced loudly so a future hashing divergence fails closed
    /// instead of silently shipping a wrong id.
    #[error("store hash {store} != locally-computed blake3 hash {local}")]
    HashMismatch {
        /// Hash reported by iroh-blobs.
        store: BundleHash,
        /// Hash we computed via [`crate::blake3_hash`].
        local: BundleHash,
    },
}

/// Errors from [`publish_bundle`].
#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    /// Serializing the bundle to JSON failed.
    #[error("serializing bundle to JSON: {0}")]
    Serialize(#[source] serde_json::Error),
    /// The iroh-blobs store rejected the add.
    #[error("iroh-blobs add_bytes failed: {0}")]
    Store(#[source] anyhow::Error),
    /// The store hashed the bytes with a different BLAKE3 root than we
    /// computed locally. This should be impossible (both use BLAKE3-256 over
    /// the same bytes) — surfaced loudly so a future hashing divergence in
    /// either side fails closed instead of silently shipping a wrong id.
    #[error("store hash {store} != locally-computed bundle hash {local}")]
    HashMismatch {
        /// Hash reported by iroh-blobs.
        store: BundleHash,
        /// Hash we computed via [`blake3_bundle_hash`].
        local: BundleHash,
    },
}

/// Publish arbitrary bytes to `store`, returning their BLAKE3-256 transport
/// hash.
///
/// The bytes are hashed locally via [`crate::blake3_hash`], added to the store,
/// and the store's returned hash is validated against the local hash to fail
/// closed on divergence. The returned hash satisfies [`crate::blake3_hash`] of
/// the same bytes.
///
/// This is the generic artifact layer; [`publish_bundle`] is a thin caller that
/// serializes a [`Bundle`] then calls this. Like the bundle path, this is
/// transport addressing only — byte-integrity, NOT provenance.
pub async fn publish_bytes(
    store: &MemStore,
    bytes: &[u8],
) -> Result<BundleHash, PublishBytesError> {
    let local = crate::hash::blake3_hash(bytes);

    let tag = store
        .add_bytes(bytes.to_vec())
        .await
        .map_err(|e| PublishBytesError::Store(e.into()))?;
    let store_hash: BundleHash = tag.hash.into();

    if store_hash != local {
        return Err(PublishBytesError::HashMismatch {
            store: store_hash,
            local,
        });
    }
    Ok(local)
}

/// Serialize `bundle` to JSON, add it to `store`, and return its
/// [`BundleHash`] (BLAKE3-256 root).
///
/// The returned hash equals [`blake3_bundle_hash`] of the same bundle; we
/// assert this against the store's own computed hash to fail closed on any
/// divergence.
///
/// Internally calls [`publish_bytes`] and maps its errors back to
/// [`PublishError`] for backward compatibility.
pub async fn publish_bundle(store: &MemStore, bundle: &Bundle) -> Result<BundleHash, PublishError> {
    let bytes = serde_json::to_vec(bundle).map_err(PublishError::Serialize)?;

    // Defensive consistency check: the bundle hasher and the generic byte
    // hasher must agree over the same bytes (they share `blake3_hash`).
    debug_assert_eq!(crate::hash::blake3_hash(&bytes), blake3_bundle_hash(bundle));

    publish_bytes(store, &bytes).await.map_err(|e| match e {
        PublishBytesError::Store(err) => PublishError::Store(err),
        PublishBytesError::HashMismatch { store, local } => {
            PublishError::HashMismatch { store, local }
        }
    })
}
