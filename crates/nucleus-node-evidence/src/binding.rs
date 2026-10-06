//! What the quote's qualifying data commits to: the node's executor key, its
//! federation key set, and a freshness value.
//!
//! This is the binding that lets a stranger tie a receipt's signer to the boot
//! the quote measured. The TPM signs `extraData = qualifying_data(..)`, so a
//! quote taken for one executor key cannot be presented for another, and one
//! taken for one challenge or epoch cannot be presented for another.
//!
//! # Encoding
//!
//! `SHA-256` over a domain tag and three length-prefixed fields, each a
//! big-endian `u32` length followed by its bytes:
//!
//! ```text
//! "nucleus-node-evidence/v1/qualifying-data"
//! executor-key  = 0x01 || ed25519 public key (32 bytes)
//! federation    = 0x00                       (not federated)
//!               | 0x01 || SHA-256(JWKS)      (32 bytes)
//! freshness     = 0x01 || nonce               (challenge, 16..=64 bytes)
//!               | 0x02 || counter u64 BE || iat i64 BE   (epoch)
//! ```
//!
//! Every field is length-prefixed and every alternative is tagged, so the
//! encoding is injective: no two distinct bindings hash the same preimage.

use serde::{Deserialize, Serialize};

use crate::crypto::sha256;

const DOMAIN: &[u8] = b"nucleus-node-evidence/v1/qualifying-data";

/// The node's executor public key — the key that signs its receipts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutorKey {
    /// An Ed25519 public key, hex.
    Ed25519(#[serde(with = "hex32")] [u8; 32]),
}

/// Whether the node's identity is federated, and if so the digest of the
/// JWKS it federates with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Federation {
    /// The node publishes no federation key set.
    NotFederated,
    /// SHA-256 of the node's federation JWKS document bytes, hex.
    JwksSha256(#[serde(with = "hex32")] [u8; 32]),
}

/// The public half of the binding: which keys this evidence speaks for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyBinding {
    /// The executor key whose receipts this evidence covers.
    pub executor_key: ExecutorKey,
    /// The federation key set, if any.
    pub federation: Federation,
}

/// A verifier-chosen challenge. 16 to 64 bytes: long enough not to repeat,
/// short enough that a challenge endpoint cannot be made to hash megabytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Nonce(Vec<u8>);

/// The bounds on a [`Nonce`], in bytes.
pub const NONCE_LEN: std::ops::RangeInclusive<usize> = 16..=64;

impl Nonce {
    /// A nonce from raw bytes, refused outside [`NONCE_LEN`].
    pub fn new(bytes: Vec<u8>) -> Result<Self, String> {
        if NONCE_LEN.contains(&bytes.len()) {
            Ok(Self(bytes))
        } else {
            Err(format!(
                "nonce is {} bytes; must be {}..={}",
                bytes.len(),
                NONCE_LEN.start(),
                NONCE_LEN.end()
            ))
        }
    }

    /// The nonce bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl TryFrom<String> for Nonce {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        Self::new(hex::decode(&s).map_err(|e| format!("nonce is not hex: {e}"))?)
    }
}

impl From<Nonce> for String {
    fn from(n: Nonce) -> String {
        hex::encode(n.0)
    }
}

/// How this evidence claims to be fresh.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Freshness {
    /// Quoted over a nonce a verifier sent (challenge-response). Fresh only
    /// to the verifier that sent this nonce.
    Challenge {
        /// The verifier's nonce (EAT `eat_nonce`), hex.
        eat_nonce: Nonce,
    },
    /// Re-quoted on an interval by the node itself, for offline checking.
    /// Fresh relative to a receipt only within a verifier's maximum age.
    Epoch {
        /// The node's epoch counter, incremented per re-quote.
        counter: u64,
        /// The node's wall-clock time of the quote, Unix seconds (EAT `iat`).
        iat: i64,
    },
}

fn put(out: &mut Vec<u8>, field: &[u8]) {
    // Every field here is at most 1 + 8 + 8 or 1 + 64 bytes; the length fits.
    let len = u32::try_from(field.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
}

/// The 32 bytes the node passes as the quote's qualifying data, and the
/// verifier recomputes and compares with the quote's `extraData`.
pub fn qualifying_data(binding: &KeyBinding, freshness: &Freshness) -> [u8; 32] {
    let mut pre = Vec::with_capacity(160);
    put(&mut pre, DOMAIN);
    let mut f = Vec::new();
    match &binding.executor_key {
        ExecutorKey::Ed25519(k) => {
            f.push(0x01);
            f.extend_from_slice(k);
        }
    }
    put(&mut pre, &f);
    f.clear();
    match &binding.federation {
        Federation::NotFederated => f.push(0x00),
        Federation::JwksSha256(d) => {
            f.push(0x01);
            f.extend_from_slice(d);
        }
    }
    put(&mut pre, &f);
    f.clear();
    match freshness {
        Freshness::Challenge { eat_nonce } => {
            f.push(0x01);
            f.extend_from_slice(eat_nonce.as_bytes());
        }
        Freshness::Epoch { counter, iat } => {
            f.push(0x02);
            f.extend_from_slice(&counter.to_be_bytes());
            f.extend_from_slice(&iat.to_be_bytes());
        }
    }
    put(&mut pre, &f);
    sha256(&pre)
}

pub(crate) mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes of hex"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> KeyBinding {
        KeyBinding {
            executor_key: ExecutorKey::Ed25519([1; 32]),
            federation: Federation::NotFederated,
        }
    }

    #[test]
    fn nonce_bounds() {
        assert!(Nonce::new(vec![0; 15]).is_err());
        assert!(Nonce::new(vec![0; 16]).is_ok());
        assert!(Nonce::new(vec![0; 64]).is_ok());
        assert!(Nonce::new(vec![0; 65]).is_err());
    }

    #[test]
    fn every_component_moves_the_digest() {
        let n = Freshness::Challenge {
            eat_nonce: Nonce::new(vec![7; 32]).unwrap(),
        };
        let base = qualifying_data(&binding(), &n);
        let mut b = binding();
        b.executor_key = ExecutorKey::Ed25519([2; 32]);
        assert_ne!(qualifying_data(&b, &n), base);
        let mut b = binding();
        b.federation = Federation::JwksSha256([0; 32]);
        assert_ne!(qualifying_data(&b, &n), base);
        let n2 = Freshness::Challenge {
            eat_nonce: Nonce::new(vec![8; 32]).unwrap(),
        };
        assert_ne!(qualifying_data(&binding(), &n2), base);
        let e1 = Freshness::Epoch {
            counter: 1,
            iat: 10,
        };
        let e2 = Freshness::Epoch {
            counter: 2,
            iat: 10,
        };
        let e3 = Freshness::Epoch {
            counter: 1,
            iat: 11,
        };
        let d1 = qualifying_data(&binding(), &e1);
        assert_ne!(d1, qualifying_data(&binding(), &e2));
        assert_ne!(d1, qualifying_data(&binding(), &e3));
        assert_ne!(d1, base);
    }

    #[test]
    fn freshness_json_shape() {
        let e = Freshness::Epoch { counter: 3, iat: 9 };
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"epoch":{"counter":3,"iat":9}}"#
        );
        let bad = r#"{"challenge":{"eat_nonce":"00"}}"#;
        assert!(
            serde_json::from_str::<Freshness>(bad).is_err(),
            "short nonce refused at parse"
        );
    }

    #[test]
    fn golden_vector() {
        // Pinned so an accidental change to the encoding is a test failure:
        // nodes and verifiers built from different commits must agree.
        let d = qualifying_data(&binding(), &Freshness::Epoch { counter: 1, iat: 2 });
        assert_eq!(hex::encode(d), GOLDEN);
    }

    /// Computed independently of this crate from the encoding in the module
    /// docs (a 10-line script over SHA-256 and big-endian length prefixes).
    const GOLDEN: &str = "d27067409861814336c3f36bcecd06eec961dd20df8978897d2d47a4f083b96a";
}
