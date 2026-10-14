//! Trust roots: the operator-pinned keys whose signatures make a decision an owner's.
//!
//! The file is the control plane's approvers shape, a JSON array of `{kid, public_key, who}`
//! with `public_key` an SPKI PEM. Roots are operator configuration and never workload input:
//! the caller loads them from a node-provisioned path, and nothing here reads a file.
//!
//! The kid is DERIVED, not trusted: [`kid_for`] is the first 16 hex of SHA-256 over the trimmed
//! PEM (the control plane's `kid_for`), and a file whose `kid` disagrees with its key is refused
//! rather than believed (ADR 0007 G-1: one decider per fact).

use std::collections::BTreeSet;

use base64::Engine as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Most roots one file may pin. A verifier tries each in turn, so this bounds its work.
pub const MAX_ROOTS: usize = 16;

/// Why a signature did not check, before it is mapped to a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SigRefusal {
    /// Not a well-formed signature for the key's algorithm, or not its one encoding.
    Encoding,
    /// Well formed, and not by this key over these bytes.
    DoesNotVerify,
}

/// A pinned key, by algorithm. The algorithm is read from the SPKI, never from a field.
#[derive(Debug)]
pub(crate) enum RootKey {
    P256(Box<p256::ecdsa::VerifyingKey>),
    Ed25519(Box<ed25519_dalek::VerifyingKey>),
}

impl RootKey {
    fn from_spki(der: &[u8]) -> Option<Self> {
        if let Some(k) = crate::key_p256::key_from_spki(der) {
            return Some(Self::P256(Box::new(k)));
        }
        crate::key_ed25519::key_from_spki(der).map(|k| Self::Ed25519(Box::new(k)))
    }

    pub(crate) fn check(&self, message: &[u8], signature: &[u8]) -> Result<(), SigRefusal> {
        match self {
            Self::P256(k) => crate::key_p256::check(k, message, signature),
            Self::Ed25519(k) => crate::key_ed25519::check(k, message, signature),
        }
    }
}

/// One pinned key.
#[derive(Debug)]
pub(crate) struct TrustRoot {
    pub(crate) kid: String,
    pub(crate) who: String,
    pub(crate) key: RootKey,
}

/// The keys a decision may be signed by. Never empty: a pod with no roots has no decision tools,
/// not a verifier that refuses everything.
#[derive(Debug)]
pub struct TrustRoots {
    roots: Vec<TrustRoot>,
}

/// Why a trust-roots file was refused. Every arm is fatal at load: verifying against fewer keys
/// than were configured would surface as unexplained refusals far from the cause.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RootsError {
    /// Not a JSON array of `{kid, public_key, who}` with no other fields.
    #[error("trust roots are not a JSON array of {{kid, public_key, who}}: {0}")]
    Malformed(String),
    /// The array is empty.
    #[error("trust roots are empty")]
    Empty,
    /// More than [`MAX_ROOTS`] entries.
    #[error("more than {MAX_ROOTS} trust roots")]
    TooMany,
    /// Two entries share a kid.
    #[error("kid {0} appears twice")]
    DuplicateKid(String),
    /// The key is not an SPKI PEM of a P-256 or Ed25519 public key.
    #[error("kid {0}: public_key is not an SPKI PEM of a P-256 or Ed25519 key")]
    BadKey(String),
    /// The entry's kid is not the one its key derives.
    #[error("kid {claimed} does not match its key, whose kid is {derived}")]
    KidMismatch {
        /// What the file says.
        claimed: String,
        /// What [`kid_for`] computes from the key.
        derived: String,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Approver {
    kid: String,
    public_key: String,
    who: String,
}

/// The kid of an SPKI PEM: the first 16 lowercase hex of SHA-256 over the trimmed PEM text.
pub fn kid_for(public_key_pem: &str) -> String {
    let mut h = hex::encode(Sha256::digest(public_key_pem.trim().as_bytes()));
    h.truncate(16);
    h
}

/// The DER inside a `PUBLIC KEY` PEM block, or `None`.
fn pem_to_der(pem: &str) -> Option<Vec<u8>> {
    let mut lines = pem.trim().lines().map(str::trim);
    if lines.next()? != "-----BEGIN PUBLIC KEY-----" {
        return None;
    }
    let mut body = String::new();
    for line in lines {
        if line == "-----END PUBLIC KEY-----" {
            return base64::engine::general_purpose::STANDARD
                .decode(body.as_bytes())
                .ok();
        }
        body.push_str(line);
    }
    None
}

impl TrustRoots {
    /// Parse a trust-roots file. Every entry must parse and derive its own kid.
    pub fn from_json(text: &str) -> Result<Self, RootsError> {
        let list: Vec<Approver> =
            serde_json::from_str(text).map_err(|e| RootsError::Malformed(e.to_string()))?;
        if list.is_empty() {
            return Err(RootsError::Empty);
        }
        if list.len() > MAX_ROOTS {
            return Err(RootsError::TooMany);
        }
        let mut kids = BTreeSet::new();
        let mut roots = Vec::with_capacity(list.len());
        for Approver {
            kid,
            public_key,
            who,
        } in list
        {
            let derived = kid_for(&public_key);
            if derived != kid {
                return Err(RootsError::KidMismatch {
                    claimed: kid,
                    derived,
                });
            }
            if !kids.insert(kid.clone()) {
                return Err(RootsError::DuplicateKid(kid));
            }
            let key = pem_to_der(&public_key)
                .and_then(|der| RootKey::from_spki(&der))
                .ok_or_else(|| RootsError::BadKey(kid.clone()))?;
            roots.push(TrustRoot { kid, who, key });
        }
        Ok(Self { roots })
    }

    /// How many keys are pinned.
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    /// Always `false`: an empty file is refused at load.
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// The pinned kids, in file order.
    pub fn kids(&self) -> impl Iterator<Item = &str> {
        self.roots.iter().map(|r| r.kid.as_str())
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &TrustRoot> {
        self.roots.iter()
    }

    pub(crate) fn has_kid(&self, kid: &str) -> bool {
        self.roots.iter().any(|r| r.kid == kid)
    }
}
