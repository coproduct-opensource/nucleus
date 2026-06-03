//! Content-addressed transport for nucleus provenance [`Bundle`]s.
//!
//! This crate addresses a serialized [`Bundle`] by the BLAKE3 hash of its
//! JSON bytes ([`BundleHash`]) and fetches+verifies it from an untrusted
//! peer over [`iroh-blobs`](iroh_blobs) (a bao-verified blob stream). The
//! delivered bytes are then piped into the EXISTING
//! [`nucleus_envelope::verify_bundle`] — content-addressing is a transport
//! concern and is deliberately ORTHOGONAL to provenance.
//!
//! # Trust model — read this before pitching to anyone
//!
//! This is the SMALLEST shippable slice of "topology #4": fetch a bundle by
//! its BLAKE3 root from a peer whose node ticket you already have. The
//! guarantees are intentionally narrow:
//!
//! - **No content DISCOVERY.** The node ticket (a [`iroh::NodeAddr`]) is
//!   passed OUT-OF-BAND. There is NO DHT, NO content routing, NO provider
//!   advertisement. "DHT" / discovery is deferred and aspirational — do not
//!   claim it exists.
//!
//! - **No NAT traversal in this slice.** Relays/holepunching are iroh's job
//!   but are not exercised or guaranteed here; addresses are supplied
//!   directly.
//!
//! - **No availability guarantee.** A peer can be offline, or can lie about
//!   *having* the bytes (refuse to serve, stall, serve nothing). The only
//!   thing this crate guarantees is the **CORRECTNESS of delivered bytes**:
//!   if a peer returns bytes, the bao-verified stream rejects anything whose
//!   BLAKE3 root is not exactly the requested [`BundleHash`]. A peer cannot
//!   SUBSTITUTE content.
//!
//! - **fetched != trusted.** BLAKE3 byte-integrity is ORTHOGONAL to envelope
//!   provenance. A perfect-hash fetch can STILL FAIL
//!   [`nucleus_envelope::verify_bundle`] (e.g. forged/unknown issuer JWKS).
//!   You MUST run `verify_bundle` with an out-of-band [`TrustAnchor`] after
//!   fetching. Receiving the exact bytes you asked for says NOTHING about
//!   who produced them.
//!
//! - **A raw 32-byte BLAKE3 hash is NOT a CID.** [`BundleHash`] is a bare
//!   BLAKE3-256 digest of the bundle's JSON bytes. It carries no multihash
//!   prefix, no multicodec, no multibase. Do **not** call it a CID, and do
//!   not interoperate with IPLD/IPFS tooling as if it were one.
//!
//! - **This [`BundleHash`] is a TRANSPORT id, DISTINCT from the SHA-256
//!   [`nucleus_envelope::canonical_bundle_hash`].** The canonical hash is a
//!   stable, attestation-bearing identity over selected canonical fields
//!   (and excludes the `attestation` field). This BLAKE3 hash is over the
//!   FULL `serde_json::to_vec(&bundle)` bytes — any byte change (including
//!   the attestation field) changes it. They serve different purposes; never
//!   conflate them.
//!
//! - **Not wired into the WASM/browser verifier.** iroh-blobs is a native
//!   (tokio + QUIC) transport; this crate is server/CLI-side only.
//!
//! # Single-tenant value (split-trust across failure domains)
//!
//! This is useful to ONE operator with zero counterparties: content-addressed,
//! bao-verified replication of your own provenance bundles across your own
//! machines/regions/clouds — resilient, dedup-friendly, tamper-evident archival
//! and disaster-recovery where any replica's bytes self-validate against the
//! [`BundleHash`]. The "mesh" value is *failure-domain diversity*, not other
//! organizations; peer fan-out is additive, not a prerequisite. (Remember:
//! fetched != trusted — replication integrity is orthogonal to provenance.)
//!
//! # Metering seam (dormant; do NOT wire payment here yet)
//!
//! [`fetch_bundle`] verifies bytes against the BLAKE3 root — i.e. bytes a peer
//! *provably* served. That is the natural future metering point for a
//! pay-per-PROVEN-byte tier (priced by nucleus's verified VCG/Pigou clearing,
//! settled over x402/L402). It is deliberately NOT implemented: no payment, no
//! accounting, no token — the seam is documented so the paid tier is additive,
//! not a rewrite. Meter only proven work (verified bytes), never self-reported.
//!
//! [`Bundle`]: nucleus_envelope::Bundle
//! [`TrustAnchor`]: nucleus_envelope::TrustAnchor

use std::fmt;
use std::str::FromStr;

pub mod fetch;
pub mod hash;
pub mod publish;

pub use fetch::{fetch_bundle, FetchError};
pub use hash::blake3_bundle_hash;
pub use publish::{publish_bundle, PublishError};

/// Length, in bytes, of a [`BundleHash`] (BLAKE3-256 digest).
pub const BUNDLE_HASH_LEN: usize = 32;

/// A content-addressed transport identifier for a serialized
/// [`nucleus_envelope::Bundle`]: the **BLAKE3-256 root** of its JSON bytes.
///
/// # NOT a CID, NOT the canonical hash
///
/// - This is a bare 32-byte BLAKE3 digest. It is **NOT a CID** (no
///   multihash/multicodec/multibase framing).
/// - It is **DISTINCT** from [`nucleus_envelope::canonical_bundle_hash`]
///   (SHA-256, over selected canonical fields). This BLAKE3 hash is a
///   pure transport id over the full serialized bytes.
///
/// On the wire to iroh-blobs it maps 1:1 to an [`iroh_blobs::Hash`].
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BundleHash(pub [u8; BUNDLE_HASH_LEN]);

impl BundleHash {
    /// Construct from raw bytes.
    pub const fn from_bytes(bytes: [u8; BUNDLE_HASH_LEN]) -> Self {
        Self(bytes)
    }

    /// The raw 32 bytes of the digest.
    pub const fn as_bytes(&self) -> &[u8; BUNDLE_HASH_LEN] {
        &self.0
    }

    /// Lowercase hex encoding (64 chars).
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(BUNDLE_HASH_LEN * 2);
        for b in self.0 {
            // Two lowercase hex nibbles per byte.
            s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
            s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
        }
        s
    }
}

/// Hex (lowercase, 64 chars).
impl fmt::Display for BundleHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Same as [`Display`](fmt::Display) — show the hex so logs are copy-pasteable.
impl fmt::Debug for BundleHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BundleHash({})", self.to_hex())
    }
}

/// Error parsing a [`BundleHash`] from a hex string.
#[derive(Debug, thiserror::Error)]
pub enum BundleHashParseError {
    /// The string was not exactly 64 hex characters (32 bytes).
    #[error("expected 64 hex chars (32-byte BLAKE3 digest), got {0} chars")]
    BadLength(usize),
    /// A non-hex character was encountered.
    #[error("invalid hex digit at position {0}")]
    BadHexDigit(usize),
}

impl FromStr for BundleHash {
    type Err = BundleHashParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.len() != BUNDLE_HASH_LEN * 2 {
            return Err(BundleHashParseError::BadLength(s.len()));
        }
        let mut out = [0u8; BUNDLE_HASH_LEN];
        let bytes = s.as_bytes();
        for (i, byte) in out.iter_mut().enumerate() {
            let hi = (bytes[2 * i] as char)
                .to_digit(16)
                .ok_or(BundleHashParseError::BadHexDigit(2 * i))?;
            let lo = (bytes[2 * i + 1] as char)
                .to_digit(16)
                .ok_or(BundleHashParseError::BadHexDigit(2 * i + 1))?;
            *byte = ((hi << 4) | lo) as u8;
        }
        Ok(BundleHash(out))
    }
}

/// Map our transport id onto iroh-blobs' [`iroh_blobs::Hash`] (also a raw
/// BLAKE3-256 digest), so the two are byte-identical on the wire.
impl From<BundleHash> for iroh_blobs::Hash {
    fn from(h: BundleHash) -> Self {
        iroh_blobs::Hash::from_bytes(h.0)
    }
}

impl From<iroh_blobs::Hash> for BundleHash {
    fn from(h: iroh_blobs::Hash) -> Self {
        BundleHash(*h.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let h = BundleHash([0xABu8; 32]);
        let s = h.to_hex();
        assert_eq!(s.len(), 64);
        assert_eq!(s, "ab".repeat(32));
        let back: BundleHash = s.parse().unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn from_str_rejects_bad_length() {
        let err = BundleHash::from_str("abcd").unwrap_err();
        assert!(matches!(err, BundleHashParseError::BadLength(4)));
    }

    #[test]
    fn from_str_rejects_non_hex() {
        let bad = "z".repeat(64);
        let err = BundleHash::from_str(&bad).unwrap_err();
        assert!(matches!(err, BundleHashParseError::BadHexDigit(0)));
    }

    #[test]
    fn iroh_hash_round_trips_bytewise() {
        let h = BundleHash([7u8; 32]);
        let iroh: iroh_blobs::Hash = h.into();
        assert_eq!(iroh.as_bytes(), h.as_bytes());
        let back: BundleHash = iroh.into();
        assert_eq!(back, h);
    }
}
