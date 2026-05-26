//! Witness federation: countersignatures on signed tree heads.
//!
//! A [`Cosignature`] is an additional Ed25519 signature on a
//! [`SignedTreeHead`]'s canonical bytes produced by an *external*
//! witness — a party other than the log producer. Federation defends
//! against split-view attacks (RFC 9162 §8.2): a producer who tries
//! to show different roots to different verifiers gets caught when
//! cosignatures don't accumulate.
//!
//! This module ships:
//! - The [`Cosignature`] wire type.
//! - The [`WitnessClient`] trait every external witness backend
//!   implements (HTTP, file, in-process).
//! - [`InProcessWitness`] — wraps an existing [`Ed25519Witness`] for
//!   tests and local federation experiments.
//!
//! # v2.1 scope limit
//!
//! The C2SP `tlog-witness` spec binds the witness's *own* timestamp
//! into the signed bytes (so a cosignature can't be replayed against
//! a later timestamp). This crate signs the producer's canonical
//! [`canonical_sth_bytes`] unmodified — the cosignature still proves
//! "this witness saw and approved THIS specific (tree_size, producer
//! timestamp, root)," which is enough for cross-witness split-view
//! defense at the per-STH level. Cross-time consistency-proof binding
//! and the C2SP request envelope (`POST /add-checkpoint` with `old`
//! line + consistency proof) land in v2.2.
//!
//! [`canonical_sth_bytes`]: crate::canonical_sth_bytes

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::checkpoint::{
    canonical_sth_bytes, Ed25519Witness, SignedTreeHead, TreeWitness, WitnessError,
};

/// An additional signature on a [`SignedTreeHead`] from an external
/// witness. `signature` is Ed25519 over the same
/// [`canonical_sth_bytes`] the producer's primary signature covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cosignature {
    /// Stable identifier for the witness's key (matches
    /// `Ed25519Witness::kid` for in-process witnesses; arbitrary
    /// string for HTTP-backed witnesses).
    pub witness_kid: String,
    /// Ed25519 signature over the producer's canonical STH bytes.
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
    /// Wall-clock POSIX milliseconds at which the witness countersigned.
    /// Metadata only in v2.1 — NOT covered by `signature`. v2.2 will
    /// bind this into the signed bytes per C2SP `tlog-witness`.
    pub timestamp_ms: u64,
}

/// An external witness — anything that can be asked to countersign a
/// [`SignedTreeHead`]. Implementations:
/// - [`InProcessWitness`] for tests + local federation.
/// - *(v2.2)* `HttpWitness` for C2SP `tlog-witness` endpoints.
/// - *(v2.2+)* `RekorWitnessClient` for Sigstore Rekor v2 integration.
pub trait WitnessClient: Send + Sync {
    /// Countersign `sth` and return the resulting [`Cosignature`].
    fn cosign(&self, sth: &SignedTreeHead) -> Result<Cosignature, WitnessError>;
}

/// In-process witness wrapping an [`Ed25519Witness`]. Production
/// deployments use this only for local-federation experiments and
/// for the trust-anchor side where the verifier already holds the
/// witness's verifying key bytes. Real cross-org witnessing belongs
/// behind an HTTP transport.
pub struct InProcessWitness {
    inner: Ed25519Witness,
}

impl InProcessWitness {
    /// Wrap an existing [`Ed25519Witness`].
    pub fn from_witness(inner: Ed25519Witness) -> Self {
        Self { inner }
    }

    /// Construct from a 32-byte Ed25519 seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            inner: Ed25519Witness::from_seed(seed),
        }
    }

    /// The verifying-key bytes. Publish out-of-band so verifiers can
    /// place this witness on their trusted list.
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.inner.verifying_key_bytes()
    }

    /// Stable kid (URL-safe base64 of SHA-256(pubkey) truncated to 12 chars).
    pub fn kid(&self) -> &str {
        self.inner.kid()
    }
}

impl WitnessClient for InProcessWitness {
    fn cosign(&self, sth: &SignedTreeHead) -> Result<Cosignature, WitnessError> {
        // Decode the producer's signed root hash so we sign the same
        // 48 bytes the producer did. A malformed root_hash_hex makes
        // the whole STH invalid; surface that here rather than letting
        // a corrupt cosignature ship.
        let root = hex_decode_32(&sth.root_hash_hex)
            .ok_or_else(|| WitnessError::Backend("malformed root_hash_hex in STH".into()))?;
        let canonical = canonical_sth_bytes(sth.tree_size, sth.timestamp_ms, &root);
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| WitnessError::Clock)?
            .as_millis() as u64;
        let signature = self.inner.sign_message(&canonical).to_vec();
        Ok(Cosignature {
            witness_kid: self.inner.kid().to_string(),
            signature,
            timestamp_ms,
        })
    }
}

fn hex_decode_32(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

// ─────────────────────────────────────────────────────────────────────
// v2.2 HTTP witness — nucleus-native cosign protocol over HTTP/JSON.
//
// Wire shape (feature = "http"):
//
//   POST <base_url>/v2.1/cosign
//   Content-Type: application/json
//   Body: SignedTreeHead JSON
//
//   200 OK
//   Content-Type: application/json
//   Body: Cosignature JSON
//
// This is NOT the C2SP `tlog-witness` `POST /add-checkpoint` protocol
// (which signs the C2SP signed-note checkpoint format, not our
// `canonical_sth_bytes`). Federation with the external ArmoredWitness
// / Sigstore ecosystem requires a C2SP signed-note layer — tracked as
// v2.3. Today's HttpWitnessClient lets two nucleus deployments
// federate with each other via simple HTTP.

#[cfg(feature = "http")]
mod http {
    use std::time::Duration;

    use reqwest::blocking::Client;

    use super::{Cosignature, SignedTreeHead, WitnessClient, WitnessError};

    /// Default request timeout for a witness HTTP call. Witnesses
    /// typically respond in milliseconds; 10s gives plenty of slack
    /// for slow links without holding bundle assembly forever.
    const DEFAULT_TIMEOUT_MS: u64 = 10_000;

    /// Nucleus-native HTTP witness client. POSTs the [`SignedTreeHead`]
    /// to a configurable endpoint as JSON; expects a JSON
    /// [`Cosignature`] back.
    ///
    /// Not C2SP-compliant — see module-level docs in `cosign.rs` above.
    /// Federation with transparency.dev / Sigstore witnesses requires
    /// the v2.3 signed-note adapter.
    pub struct HttpWitnessClient {
        base_url: String,
        client: Client,
        expected_kid: Option<String>,
    }

    impl HttpWitnessClient {
        /// Construct with a base URL (the `/v2.1/cosign` path is
        /// appended automatically). Errors if reqwest can't build a
        /// client with the default TLS backend.
        pub fn new(base_url: impl Into<String>) -> Result<Self, WitnessError> {
            let client = Client::builder()
                .timeout(Duration::from_millis(DEFAULT_TIMEOUT_MS))
                .build()
                .map_err(|e| WitnessError::Backend(format!("reqwest client build: {e}")))?;
            Ok(Self {
                base_url: base_url.into(),
                client,
                expected_kid: None,
            })
        }

        /// Override the default request timeout.
        pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, WitnessError> {
            self.client = Client::builder()
                .timeout(timeout)
                .build()
                .map_err(|e| WitnessError::Backend(format!("reqwest client build: {e}")))?;
            Ok(self)
        }

        /// Pin the expected witness `kid`. When set, `cosign` rejects
        /// responses whose `witness_kid` doesn't match — catches a
        /// mis-pointed `base_url` early. The verifier-side
        /// `TrustAnchor::with_trusted_witness` is the load-bearing
        /// integrity check; this is a sanity guard.
        pub fn with_expected_kid(mut self, kid: impl Into<String>) -> Self {
            self.expected_kid = Some(kid.into());
            self
        }

        fn url(&self) -> String {
            let trimmed = self.base_url.trim_end_matches('/');
            format!("{trimmed}/v2.1/cosign")
        }
    }

    impl WitnessClient for HttpWitnessClient {
        fn cosign(&self, sth: &SignedTreeHead) -> Result<Cosignature, WitnessError> {
            let url = self.url();
            let response = self
                .client
                .post(&url)
                .json(sth)
                .send()
                .map_err(|e| WitnessError::Backend(format!("POST {url}: {e}")))?;
            let status = response.status();
            if !status.is_success() {
                let body = response.text().unwrap_or_default();
                return Err(WitnessError::Backend(format!(
                    "witness at {url} returned {status}: {body}"
                )));
            }
            let cosig: Cosignature = response.json().map_err(|e| {
                WitnessError::Backend(format!("malformed Cosignature JSON from {url}: {e}"))
            })?;
            if let Some(expected) = &self.expected_kid {
                if &cosig.witness_kid != expected {
                    return Err(WitnessError::Backend(format!(
                        "witness at {url} returned kid {:?}, expected {:?}",
                        cosig.witness_kid, expected
                    )));
                }
            }
            Ok(cosig)
        }
    }
}

#[cfg(feature = "http")]
pub use self::http::HttpWitnessClient;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::TreeWitness;

    #[test]
    fn in_process_witness_countersigns() {
        let producer = Ed25519Witness::from_seed([1u8; 32]);
        let sth = producer.sign_sth(5, &[0x42; 32]).unwrap();

        let witness = InProcessWitness::from_seed([2u8; 32]);
        let cosig = witness.cosign(&sth).unwrap();
        assert_eq!(cosig.witness_kid, witness.kid());
        assert_eq!(cosig.signature.len(), 64);
        assert!(cosig.timestamp_ms > 0);

        // Cosignature must verify against the witness's public key over
        // the producer's canonical bytes.
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let pub_bytes = witness.verifying_key_bytes();
        let vk = VerifyingKey::from_bytes(&pub_bytes).unwrap();
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&cosig.signature);
        let sig = Signature::from_bytes(&sig_arr);
        let canonical = canonical_sth_bytes(
            sth.tree_size,
            sth.timestamp_ms,
            &hex::decode(&sth.root_hash_hex).unwrap().try_into().unwrap(),
        );
        vk.verify(&canonical, &sig)
            .expect("cosignature must verify");
    }

    #[test]
    fn cosignature_round_trips_through_json() {
        let producer = Ed25519Witness::from_seed([3u8; 32]);
        let sth = producer.sign_sth(7, &[0x99; 32]).unwrap();
        let witness = InProcessWitness::from_seed([4u8; 32]);
        let cosig = witness.cosign(&sth).unwrap();
        let json = serde_json::to_string(&cosig).unwrap();
        let back: Cosignature = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cosig);
    }
}
