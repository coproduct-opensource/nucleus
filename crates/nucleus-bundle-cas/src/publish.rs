//! Publish a [`Bundle`] into an iroh-blobs store under its BLAKE3 root.
//!
//! "Publish" here means LOCAL availability: the bytes are added to a store so
//! that a [`crate::fetch::fetch_bundle`] caller (who has the node ticket
//! out-of-band) can pull them. There is NO advertisement, NO DHT, NO
//! discovery — see the crate-level trust-model docs.

use iroh_blobs::store::mem::MemStore;
use nucleus_envelope::Bundle;

use crate::{blake3_bundle_hash, BundleHash};

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

/// Serialize `bundle` to JSON, add it to `store`, and return its
/// [`BundleHash`] (BLAKE3-256 root).
///
/// The returned hash equals [`blake3_bundle_hash`] of the same bundle; we
/// assert this against the store's own computed hash to fail closed on any
/// divergence.
pub async fn publish_bundle(store: &MemStore, bundle: &Bundle) -> Result<BundleHash, PublishError> {
    let bytes = serde_json::to_vec(bundle).map_err(PublishError::Serialize)?;
    let local = blake3_bundle_hash(bundle);

    let tag = store
        .add_bytes(bytes)
        .await
        .map_err(|e| PublishError::Store(e.into()))?;
    let store_hash: BundleHash = tag.hash.into();

    if store_hash != local {
        return Err(PublishError::HashMismatch {
            store: store_hash,
            local,
        });
    }
    Ok(local)
}
