//! [`ContentHash`] — a 32-byte content address over a record's canonical bytes.
//!
//! Same discipline as `nucleus_recompute::content_hash_hex` and a
//! `nucleus_lineage` edge's `content_hash_hex`: a domain-tagged `sha256` over a
//! deterministic serialization. Keying a [`crate::MemoryRecord`] by this hash
//! makes set membership idempotent and makes any tampering invalidate the key.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

/// Domain separation tag, so a memory-record hash can never collide with a hash
/// computed over the same bytes in another nucleus context.
pub(crate) const MEMORY_RECORD_DOMAIN: &[u8] = b"nucleus-provenance-memory/record/v1\0";

/// A 32-byte content address. Serialized as lowercase hex for legible,
/// stable wire/JSON form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentHash(pub [u8; 32]);

impl ContentHash {
    /// Compute the content hash of already-canonicalized bytes (domain-tagged).
    pub fn of_canonical_bytes(canonical: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(MEMORY_RECORD_DOMAIN);
        h.update(canonical);
        let digest = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Self(out)
    }

    /// Lowercase-hex rendering (64 chars).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from lowercase/uppercase hex; errors on wrong length / non-hex.
    pub fn from_hex(s: &str) -> Result<Self, String> {
        let bytes = hex::decode(s).map_err(|e| format!("content hash hex decode: {e}"))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "content hash must be 32 bytes".to_string())?;
        Ok(Self(arr))
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Serialize for ContentHash {
    fn serialize<S: Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ContentHash {
    fn deserialize<D: Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        ContentHash::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip() {
        let h = ContentHash::of_canonical_bytes(b"hello");
        let s = h.to_hex();
        assert_eq!(s.len(), 64);
        assert_eq!(ContentHash::from_hex(&s).unwrap(), h);
    }

    #[test]
    fn domain_tag_changes_hash() {
        // The same payload under a raw sha256 must differ from our domain-tagged
        // hash, proving the tag is actually applied.
        let ours = ContentHash::of_canonical_bytes(b"x");
        let mut plain = Sha256::new();
        plain.update(b"x");
        let plain: [u8; 32] = plain.finalize().into();
        assert_ne!(ours.0, plain);
    }

    #[test]
    fn distinct_inputs_distinct_hashes() {
        assert_ne!(
            ContentHash::of_canonical_bytes(b"a"),
            ContentHash::of_canonical_bytes(b"b")
        );
    }

    #[test]
    fn from_hex_rejects_bad_length() {
        assert!(ContentHash::from_hex("deadbeef").is_err());
    }

    #[test]
    fn serde_is_hex_string() {
        let h = ContentHash::of_canonical_bytes(b"z");
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(json, format!("\"{}\"", h.to_hex()));
        let back: ContentHash = serde_json::from_str(&json).unwrap();
        assert_eq!(back, h);
    }
}
