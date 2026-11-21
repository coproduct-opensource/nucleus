//! Thirty-two-byte values with one spelling each: a role's public key, a
//! receipt's root hash, a policy's digest, and the digest of content this
//! crate does not interpret.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A value that is not 64 lowercase hexadecimal characters.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("expected 64 lowercase hexadecimal characters; got {got:?}")]
pub struct HexError {
    got: String,
}

macro_rules! hex32 {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name([u8; 32]);

        impl $name {
            /// From the 32 bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// The 32 bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Lowercase hexadecimal, the one spelling this value has.
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
            type Err = HexError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let mut bytes = [0u8; 32];
                let refuse = || HexError { got: s.to_owned() };
                hex::decode_to_slice(s, &mut bytes).map_err(|_| refuse())?;
                // Upper case decodes too; two strings that compare unequal
                // must not name the same key or receipt.
                if hex::encode(bytes) != s {
                    return Err(refuse());
                }
                Ok(Self(bytes))
            }
        }

        impl TryFrom<String> for $name {
            type Error = HexError;

            fn try_from(s: String) -> Result<Self, Self::Error> {
                s.parse()
            }
        }

        impl From<$name> for String {
            fn from(v: $name) -> Self {
                v.to_hex()
            }
        }
    };
}

hex32!(
    /// An Ed25519 public key. A role is whoever can sign with it; a name in a
    /// receipt is never evidence of who signed.
    RoleKey
);
hex32!(
    /// A receipt's root hash: what the next receipt in a chain cites.
    ReceiptHash
);
hex32!(
    /// A release policy's digest.
    PolicyDigest
);
hex32!(
    /// The SHA-256 of content this crate binds but does not interpret: an
    /// evaluation suite, a seed list, a harness image, a transcript.
    ContentDigest
);

impl RoleKey {
    /// The public half of `signer`.
    #[must_use]
    pub fn of(signer: &ed25519_dalek::SigningKey) -> Self {
        Self(signer.verifying_key().to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_value_one_spelling() {
        let lower = "0a".repeat(32);
        assert_eq!(lower.parse::<RoleKey>().unwrap().to_hex(), lower);
        assert!("0A".repeat(32).parse::<RoleKey>().is_err());
        assert!("0a".repeat(31).parse::<ReceiptHash>().is_err());
        let json = format!("\"{lower}\"");
        let key: PolicyDigest = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&key).unwrap(), json);
    }
}
