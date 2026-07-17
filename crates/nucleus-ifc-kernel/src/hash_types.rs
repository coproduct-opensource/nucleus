//! Content-address newtype for the IFC kernel (InputsAuthorized, brick 1).
//!
//! [`ContentHash`] is a transparent 32-byte SHA-256 wrapper used to tag a
//! [`crate::ifc_api::FlowTracker`] node with the digest of the bytes it
//! observed. The newtype (vs a bare `[u8; 32]`) prevents mixing a content
//! digest up with an unrelated 32-byte value.
//!
//! ## Why the kernel defines its own `ContentHash`
//!
//! `portcullis-core` also has a `ContentHash` (with a `sha2`-backed
//! `compute()`), but this kernel crate is the **dependency-free bottom** of the
//! graph (`portcullis-core` depends on *it*, not the reverse), so it cannot name
//! that type without a dependency cycle. It also must not pull in `sha2` — its
//! reason to exist is Aeneas's dependency-free requirement. So the kernel owns a
//! pure, hashing-free `ContentHash` here: callers that already hold a digest
//! wrap it with [`ContentHash::from_bytes`]. (A later brick may unify the two by
//! re-exporting this type from `portcullis-core`, the established layering
//! pattern for kernel types — out of scope for this additive change.)

/// SHA-256 content address of the bytes a flow node observed.
///
/// Transparent `[u8; 32]` newtype — zero runtime cost. The kernel never hashes
/// (it stays `sha2`-free); construct one from an already-computed digest with
/// [`Self::from_bytes`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentHash([u8; 32]);

impl ContentHash {
    /// Wrap an already-computed 32-byte digest.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw 32-byte digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for ContentHash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<ContentHash> for [u8; 32] {
    fn from(h: ContentHash) -> Self {
        h.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_round_trips() {
        let bytes = [7u8; 32];
        let h = ContentHash::from_bytes(bytes);
        assert_eq!(h.as_bytes(), &bytes);
        let back: [u8; 32] = h.into();
        assert_eq!(back, bytes);
    }

    #[test]
    fn distinct_digests_are_unequal() {
        assert_ne!(
            ContentHash::from_bytes([1u8; 32]),
            ContentHash::from_bytes([2u8; 32])
        );
    }
}
