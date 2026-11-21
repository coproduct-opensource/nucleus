//! Digests: one per tensor, one per checkpoint, one per patch program.
//!
//! A tensor digest commits to the tensor's name, element type, shape and
//! bytes. A checkpoint digest commits to the sorted list of (name, tensor
//! digest). Nothing about file layout enters either, so one set of tensors has
//! one digest however it is split across files, and the tensors that differ
//! between two checkpoints are a set difference over two indexes.
//!
//! A file's free-form metadata block is not part of any digest: it does not
//! change what the model computes, and binding it would make two files holding
//! the same weights two different checkpoints.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::container::Dtype;

const TENSOR_DOMAIN: &[u8] = b"nucleus/weight-patch/tensor/v1\0";
const CHECKPOINT_DOMAIN: &[u8] = b"nucleus/weight-patch/checkpoint/v1\0";

// Lengths are hashed as 64-bit values so a digest does not depend on the
// platform's pointer width. This is what makes the conversion below total.
const _: () = assert!(usize::BITS <= u64::BITS);

fn len_u64(n: usize) -> u64 {
    // Total by the assertion above; the fallback arm is not reachable on any
    // target this crate compiles for.
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// A digest string that is not 64 lowercase hexadecimal characters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("a digest is 64 lowercase hexadecimal characters; got {got:?}")]
pub struct DigestParseError {
    got: String,
}

macro_rules! digest_newtype {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name([u8; 32]);

        impl $name {
            pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// The 32 digest bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Lowercase hexadecimal, the one spelling this digest has.
            #[must_use]
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.to_hex())
            }
        }

        impl FromStr for $name {
            type Err = DigestParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let mut bytes = [0u8; 32];
                let refuse = || DigestParseError { got: s.to_owned() };
                hex::decode_to_slice(s, &mut bytes).map_err(|_| refuse())?;
                // `decode_to_slice` accepts upper case. One digest, one
                // spelling: two strings that compare unequal must not name the
                // same checkpoint.
                if hex::encode(bytes) != s {
                    return Err(refuse());
                }
                Ok(Self(bytes))
            }
        }

        impl TryFrom<String> for $name {
            type Error = DigestParseError;

            fn try_from(s: String) -> Result<Self, Self::Error> {
                s.parse()
            }
        }

        impl From<$name> for String {
            fn from(d: $name) -> Self {
                d.to_hex()
            }
        }
    };
}

digest_newtype!(
    /// Commits to one tensor: its name, element type, shape and bytes.
    TensorDigest
);
digest_newtype!(
    /// Commits to a whole checkpoint: the sorted list of tensor names and
    /// their digests.
    CheckpointDigest
);
digest_newtype!(
    /// Commits to a patch program's canonical bytes.
    ProgramDigest
);

/// Streams one tensor's bytes into its digest.
pub(crate) struct TensorHasher(Sha256);

impl TensorHasher {
    pub(crate) fn new(name: &str, dtype: Dtype, shape: &[u64], byte_len: u64) -> Self {
        let mut h = Sha256::new();
        h.update(TENSOR_DOMAIN);
        h.update(len_u64(name.len()).to_le_bytes());
        h.update(name.as_bytes());
        let tag = dtype.tag();
        h.update(len_u64(tag.len()).to_le_bytes());
        h.update(tag.as_bytes());
        h.update(len_u64(shape.len()).to_le_bytes());
        for dim in shape {
            h.update(dim.to_le_bytes());
        }
        h.update(byte_len.to_le_bytes());
        Self(h)
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    pub(crate) fn finish(self) -> TensorDigest {
        TensorDigest::from_bytes(self.0.finalize().into())
    }
}

/// Every tensor of a checkpoint by name, with its digest.
///
/// Built only by reading tensor bytes ([`crate::Applier`]); there is no way to
/// assemble one from claimed digests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointIndex {
    tensors: BTreeMap<String, TensorDigest>,
}

impl CheckpointIndex {
    pub(crate) const fn empty() -> Self {
        Self {
            tensors: BTreeMap::new(),
        }
    }

    /// Adds a tensor. Returns the name back if it is already present: one name
    /// in two files is two candidates for the same tensor, and choosing one
    /// silently is how two readers come to disagree about a checkpoint.
    pub(crate) fn insert(&mut self, name: String, digest: TensorDigest) -> Result<(), String> {
        if self.tensors.contains_key(&name) {
            return Err(name);
        }
        self.tensors.insert(name, digest);
        Ok(())
    }

    /// The digest of the named tensor, if the checkpoint has it.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<TensorDigest> {
        self.tensors.get(name).copied()
    }

    /// Every tensor, in name order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, TensorDigest)> {
        self.tensors.iter().map(|(n, d)| (n.as_str(), *d))
    }

    /// How many tensors the checkpoint has.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tensors.len()
    }

    /// Whether the checkpoint has no tensors.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tensors.is_empty()
    }

    /// The checkpoint digest.
    #[must_use]
    pub fn digest(&self) -> CheckpointDigest {
        let mut h = Sha256::new();
        h.update(CHECKPOINT_DOMAIN);
        h.update(len_u64(self.tensors.len()).to_le_bytes());
        for (name, digest) in &self.tensors {
            h.update(len_u64(name.len()).to_le_bytes());
            h.update(name.as_bytes());
            h.update(digest.as_bytes());
        }
        CheckpointDigest::from_bytes(h.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_digest_has_one_spelling() {
        let lower = "ab".repeat(32);
        let parsed: TensorDigest = lower.parse().unwrap();
        assert_eq!(parsed.to_hex(), lower);
        assert!("AB".repeat(32).parse::<TensorDigest>().is_err());
        assert!("ab".repeat(31).parse::<TensorDigest>().is_err());
        assert!("zz".repeat(32).parse::<TensorDigest>().is_err());
    }

    #[test]
    fn a_digest_round_trips_through_json() {
        let d: CheckpointDigest = "0f".repeat(32).parse().unwrap();
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, format!("\"{}\"", "0f".repeat(32)));
        assert_eq!(serde_json::from_str::<CheckpointDigest>(&json).unwrap(), d);
        assert!(serde_json::from_str::<CheckpointDigest>("\"0F\"").is_err());
    }

    fn tensor(name: &str, dtype: Dtype, shape: &[u64], bytes: &[u8]) -> TensorDigest {
        let mut h = TensorHasher::new(name, dtype, shape, len_u64(bytes.len()));
        h.update(bytes);
        h.finish()
    }

    #[test]
    fn a_tensor_digest_binds_name_type_shape_and_bytes() {
        let base = tensor("a", Dtype::F32, &[2], &[0; 8]);
        assert_ne!(base, tensor("b", Dtype::F32, &[2], &[0; 8]));
        assert_ne!(base, tensor("a", Dtype::I32, &[2], &[0; 8]));
        assert_ne!(base, tensor("a", Dtype::F32, &[1, 2], &[0; 8]));
        assert_ne!(
            base,
            tensor("a", Dtype::F32, &[2], &[0, 0, 0, 0, 0, 0, 0, 1])
        );
        assert_eq!(base, tensor("a", Dtype::F32, &[2], &[0; 8]));
    }

    #[test]
    fn a_tensor_digest_does_not_depend_on_how_the_bytes_arrive() {
        let whole = tensor("a", Dtype::U8, &[4], &[1, 2, 3, 4]);
        let mut h = TensorHasher::new("a", Dtype::U8, &[4], 4);
        h.update(&[1]);
        h.update(&[2, 3]);
        h.update(&[4]);
        assert_eq!(h.finish(), whole);
    }

    #[test]
    fn a_checkpoint_digest_does_not_depend_on_insertion_order() {
        let a = tensor("a", Dtype::U8, &[1], &[1]);
        let b = tensor("b", Dtype::U8, &[1], &[2]);
        let mut one = CheckpointIndex::empty();
        one.insert("a".into(), a).unwrap();
        one.insert("b".into(), b).unwrap();
        let mut two = CheckpointIndex::empty();
        two.insert("b".into(), b).unwrap();
        two.insert("a".into(), a).unwrap();
        assert_eq!(one.digest(), two.digest());
        assert_ne!(one.digest(), CheckpointIndex::empty().digest());
    }

    #[test]
    fn a_name_present_twice_is_refused() {
        let a = tensor("a", Dtype::U8, &[1], &[1]);
        let mut index = CheckpointIndex::empty();
        index.insert("a".into(), a).unwrap();
        assert_eq!(index.insert("a".into(), a), Err("a".to_owned()));
    }
}
