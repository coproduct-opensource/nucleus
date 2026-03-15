//! Content-addressed artifact digests.

use std::fmt;

/// A content-addressed digest of an artifact (BLAKE3).
#[derive(Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ArtifactDigest(String);

impl ArtifactDigest {
    /// Create a digest from raw bytes.
    pub fn from_bytes(data: &[u8]) -> Self {
        let hash = blake3::hash(data);
        Self(format!("blake3:{}", hash.to_hex()))
    }

    /// Create a digest from a pre-computed hex string (e.g., from storage).
    pub fn from_hex(hex: impl Into<String>) -> Self {
        let s = hex.into();
        if s.starts_with("blake3:") {
            Self(s)
        } else {
            Self(format!("blake3:{}", s))
        }
    }

    /// The raw hex portion (without the `blake3:` prefix).
    pub fn hex(&self) -> &str {
        self.0.strip_prefix("blake3:").unwrap_or(&self.0)
    }

    /// The full prefixed form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ArtifactDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ArtifactDigest({}..)",
            &self.hex()[..12.min(self.hex().len())]
        )
    }
}

impl fmt::Display for ArtifactDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_digest_from_bytes() {
        let d = ArtifactDigest::from_bytes(b"hello world");
        assert!(d.as_str().starts_with("blake3:"));
        assert_eq!(d.hex().len(), 64); // BLAKE3 = 256-bit = 64 hex chars
    }

    #[test]
    fn test_digest_deterministic() {
        let a = ArtifactDigest::from_bytes(b"same input");
        let b = ArtifactDigest::from_bytes(b"same input");
        assert_eq!(a, b);
    }

    #[test]
    fn test_digest_different_inputs() {
        let a = ArtifactDigest::from_bytes(b"input a");
        let b = ArtifactDigest::from_bytes(b"input b");
        assert_ne!(a, b);
    }

    #[test]
    fn test_from_hex_with_prefix() {
        let d = ArtifactDigest::from_hex("blake3:abcd1234");
        assert_eq!(d.as_str(), "blake3:abcd1234");
        assert_eq!(d.hex(), "abcd1234");
    }

    #[test]
    fn test_from_hex_without_prefix() {
        let d = ArtifactDigest::from_hex("abcd1234");
        assert_eq!(d.as_str(), "blake3:abcd1234");
    }
}
