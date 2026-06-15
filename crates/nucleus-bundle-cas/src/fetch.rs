//! Fetch a [`Bundle`] from an untrusted peer by its BLAKE3 root.
//!
//! The transfer rides iroh-blobs' **bao-verified** get stream: the requested
//! [`BundleHash`] is the verification root, so a peer that serves any bytes
//! whose BLAKE3 root is not exactly that hash causes the fetch to FAIL. A
//! peer cannot substitute content.
//!
//! What this does NOT do (see crate trust-model docs):
//!   - no discovery — `node_addr` is supplied out-of-band;
//!   - no availability guarantee — a peer can be offline or refuse to serve;
//!   - no provenance — the returned bytes deserialize to a [`Bundle`], but
//!     you MUST still run [`nucleus_envelope::verify_bundle`] with an
//!     out-of-band trust anchor. fetched != trusted.

use iroh::{Endpoint, EndpointAddr};
use iroh_blobs::store::mem::MemStore;
use nucleus_envelope::Bundle;

use crate::BundleHash;

/// Errors from [`fetch_bytes`] (generic artifact fetching).
#[derive(Debug, thiserror::Error)]
pub enum FetchBytesError {
    /// Could not open a QUIC connection to the peer (offline, wrong addr,
    /// ALPN refused, …). An availability failure, NOT a content failure.
    #[error("connecting to peer over iroh: {0}")]
    Connect(#[source] anyhow::Error),
    /// The bao-verified get stream failed. The load-bearing case: the peer
    /// served bytes that do NOT hash to the requested [`BundleHash`], so
    /// verification rejected them. Also covers truncated/corrupted streams.
    /// A peer CANNOT substitute content under this error.
    #[error("bao-verified fetch failed (content mismatch, truncation, or transport error): {0}")]
    Get(#[source] anyhow::Error),
    /// The verified bytes were retrieved but are not present locally after the
    /// get (should not happen on success).
    #[error("reading fetched bytes from store: {0}")]
    Read(#[source] anyhow::Error),
}

/// Errors from [`fetch_bundle`].
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// Could not open a QUIC connection to the peer (offline, wrong addr,
    /// ALPN refused, …). An availability failure, NOT a content failure.
    #[error("connecting to peer over iroh: {0}")]
    Connect(#[source] anyhow::Error),
    /// The bao-verified get stream failed. The load-bearing case: the peer
    /// served bytes that do NOT hash to the requested [`BundleHash`], so
    /// verification rejected them. Also covers truncated/corrupted streams.
    /// A peer CANNOT substitute content under this error.
    #[error("bao-verified fetch failed (content mismatch, truncation, or transport error): {0}")]
    Get(#[source] anyhow::Error),
    /// The verified bytes were retrieved but are not present locally after
    /// the get (should not happen on success).
    #[error("reading fetched bytes from store: {0}")]
    Read(#[source] anyhow::Error),
    /// The (hash-verified) bytes did not deserialize to a [`Bundle`]. The
    /// bytes are byte-for-byte what the producer published, but they are not
    /// a valid bundle — a producer-side bug, not a transport substitution.
    #[error("fetched bytes are not a valid bundle JSON: {0}")]
    Deserialize(#[source] serde_json::Error),
}

/// Fetch a blob identified by `hash` from `node_addr` over a bao-verified
/// iroh-blobs stream into `store`, returning the verified bytes.
///
/// The transfer rides iroh-blobs' bao-verified get stream: the requested
/// [`BundleHash`] is the verification root, so a peer serving bytes whose
/// BLAKE3 root is not exactly that hash causes the fetch to FAIL. A peer
/// cannot substitute content.
///
/// On success the returned bytes are guaranteed to BLAKE3-hash to exactly
/// `hash` (the bao stream enforces it). This is byte-integrity ONLY — the
/// caller must validate the contents (e.g., deserialize and verify provenance).
/// fetched != trusted.
///
/// This is the generic artifact layer; [`fetch_bundle`] is a thin caller that
/// calls this and deserializes to a [`Bundle`].
pub async fn fetch_bytes(
    endpoint: &Endpoint,
    store: &MemStore,
    node_addr: EndpointAddr,
    hash: BundleHash,
) -> Result<Vec<u8>, FetchBytesError> {
    let iroh_hash: iroh_blobs::Hash = hash.into();

    // Out-of-band addressing: connect directly using the supplied NodeAddr
    // over the blobs ALPN. No discovery is consulted.
    let conn = endpoint
        .connect(node_addr, iroh_blobs::ALPN)
        .await
        .map_err(|e| FetchBytesError::Connect(e.into()))?;

    // Bao-verified get: `hash` is the verification root. Anything that does
    // not reproduce this BLAKE3 root is rejected before it reaches us.
    store
        .remote()
        .fetch(conn, iroh_hash)
        .await
        .map_err(|e| FetchBytesError::Get(e.into()))?;

    // The verified bytes now live in `store`; read them back.
    let bytes = store
        .get_bytes(iroh_hash)
        .await
        .map_err(|e| FetchBytesError::Read(e.into()))?;

    Ok(bytes.to_vec())
}

/// Connect to `node_addr` (an [`EndpointAddr`] obtained out-of-band — iroh's
/// "node ticket"), fetch the blob identified by `hash` over a bao-verified
/// iroh-blobs stream into `store`, and deserialize it to a [`Bundle`].
///
/// On success the returned bytes are guaranteed to BLAKE3-hash to exactly
/// `hash` (the bao stream enforces it). This is byte-integrity ONLY — run
/// [`nucleus_envelope::verify_bundle`] afterwards for provenance.
///
/// Internally calls [`fetch_bytes`] and maps its errors back to [`FetchError`]
/// for backward compatibility.
pub async fn fetch_bundle(
    endpoint: &Endpoint,
    store: &MemStore,
    node_addr: EndpointAddr,
    hash: BundleHash,
) -> Result<Bundle, FetchError> {
    let bytes = fetch_bytes(endpoint, store, node_addr, hash)
        .await
        .map_err(|e| match e {
            FetchBytesError::Connect(err) => FetchError::Connect(err),
            FetchBytesError::Get(err) => FetchError::Get(err),
            FetchBytesError::Read(err) => FetchError::Read(err),
        })?;

    serde_json::from_slice(&bytes).map_err(FetchError::Deserialize)
}
