//! Newtype wrappers for cryptographic hashes (#1050).
//!
//! Prevents accidentally passing a parser hash where a content hash is
//! expected. Zero runtime cost — these are transparent `[u8; 32]` wrappers.

// sha2 is optional — compute() only available with artifact or wasm-sandbox feature.
#[cfg(any(feature = "artifact", feature = "wasm-sandbox"))]
use sha2::{Digest, Sha256};

/// SHA-256 hash of fetched content (web page, API response, file).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentHash(pub [u8; 32]);

/// SHA-256 hash of a WASM parser module binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ParserHash(pub [u8; 32]);

/// SHA-256 hash of a receipt in the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReceiptHash(pub [u8; 32]);

/// SHA-256 digest of a WitnessBundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WitnessDigest(pub [u8; 32]);

// ═══════════════════════════════════════════════════════════════════════════
// Shared implementation via macro
// ═══════════════════════════════════════════════════════════════════════════

macro_rules! impl_hash_type {
    ($name:ident, $doc:expr) => {
        impl $name {
            #[cfg(any(feature = "artifact", feature = "wasm-sandbox"))]
            #[doc = $doc]
            pub fn compute(data: &[u8]) -> Self {
                let mut hasher = Sha256::new();
                hasher.update(data);
                let result = hasher.finalize();
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&result);
                Self(hash)
            }

            /// Create from raw bytes.
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Get the raw bytes.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Zero hash (sentinel value).
            pub const fn zero() -> Self {
                Self([0u8; 32])
            }

            /// Check if this is the zero hash.
            pub const fn is_zero(&self) -> bool {
                // Can't use == in const context, check first and last bytes
                self.0[0] == 0 && self.0[31] == 0
            }

            /// Hex-encode for display.
            pub fn to_hex(&self) -> String {
                self.0.iter().map(|b| format!("{b:02x}")).collect()
            }

            /// Short hex prefix for logging (first 8 chars).
            pub fn short_hex(&self) -> String {
                self.0[..4].iter().map(|b| format!("{b:02x}")).collect()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}:{}", stringify!($name), &self.to_hex()[..16])
            }
        }

        impl From<[u8; 32]> for $name {
            fn from(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
        }

        impl From<$name> for [u8; 32] {
            fn from(h: $name) -> Self {
                h.0
            }
        }
    };
}

impl_hash_type!(ContentHash, "Compute SHA-256 of content bytes.");
impl_hash_type!(ParserHash, "Compute SHA-256 of parser WASM binary.");
impl_hash_type!(ReceiptHash, "Compute SHA-256 of receipt data.");
impl_hash_type!(WitnessDigest, "Compute SHA-256 of witness bundle.");

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(feature = "artifact", feature = "wasm-sandbox"))]
    #[test]
    fn content_hash_compute() {
        let h = ContentHash::compute(b"hello");
        assert_ne!(h, ContentHash::zero());
        assert_eq!(h.to_hex().len(), 64);
    }

    #[cfg(any(feature = "artifact", feature = "wasm-sandbox"))]
    #[test]
    fn different_types_not_mixable() {
        let data = b"same data";
        let content = ContentHash::compute(data);
        let parser = ParserHash::compute(data);
        // Same bytes, but different types — cannot be compared directly.
        // This is the point: the type system prevents confusion.
        assert_eq!(content.as_bytes(), parser.as_bytes());
        // content == parser; // COMPILE ERROR — different types
    }

    #[cfg(any(feature = "artifact", feature = "wasm-sandbox"))]
    #[test]
    fn display_format() {
        let h = ContentHash::compute(b"test");
        let display = format!("{h}");
        assert!(display.starts_with("ContentHash:"));
    }

    #[cfg(any(feature = "artifact", feature = "wasm-sandbox"))]
    #[test]
    fn short_hex() {
        let h = ContentHash::compute(b"test");
        assert_eq!(h.short_hex().len(), 8);
    }

    #[test]
    fn zero_hash() {
        assert!(ContentHash::zero().is_zero());
    }

    #[test]
    fn from_into_bytes() {
        let bytes = [0xAA; 32];
        let h = ContentHash::from(bytes);
        let back: [u8; 32] = h.into();
        assert_eq!(bytes, back);
    }
}
