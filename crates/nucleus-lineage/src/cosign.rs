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
/// witness. The `kind` field selects which byte sequence the
/// `signature` covers:
///
/// - [`CosignatureKind::Nucleus`] (default, backwards-compat): signs
///   [`canonical_sth_bytes`] — the 48-byte tuple `(tree_size,
///   timestamp_ms, root_hash)`. The original v2.1 nucleus-native
///   protocol.
/// - [`CosignatureKind::C2sp`] (v2.3): signs the C2SP **tlog-checkpoint
///   body** built via
///   [`crate::signed_note::format_checkpoint_body`] — the same bytes
///   the external `tlog-witness` ecosystem (ArmoredWitness, Sigstore)
///   uses. The `signature` value is still Ed25519 over those bytes;
///   only the bytes-being-signed differ.
///
/// Cosignatures from a single STH MAY mix kinds; the verifier checks
/// each one against the appropriate byte sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cosignature {
    /// Stable identifier for the witness's key (matches
    /// `Ed25519Witness::kid` for in-process witnesses; key_name for
    /// C2SP witnesses).
    pub witness_kid: String,
    /// Ed25519 signature over the bytes selected by `kind`.
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
    /// Wall-clock POSIX milliseconds at which the witness countersigned.
    /// Metadata only — NOT covered by `signature` in either kind today.
    /// v2.4 may bind this per C2SP `tlog-witness` once we add the full
    /// cosignature-with-timestamp signed-bytes prefix.
    pub timestamp_ms: u64,
    /// **v2.3.** Which byte sequence `signature` covers. Defaults to
    /// `Nucleus` for backwards-compat with v2.1 cosignatures that
    /// were emitted before this field existed.
    #[serde(default)]
    pub kind: CosignatureKind,
}

/// Which protocol's signed-bytes the [`Cosignature::signature`] covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CosignatureKind {
    /// Nucleus-native: signature is Ed25519 over
    /// [`canonical_sth_bytes`]. v2.1 default.
    #[default]
    Nucleus,
    /// C2SP-native: signature is Ed25519 over the C2SP tlog-checkpoint
    /// body bytes. v2.3 federation path.
    C2sp,
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
            kind: CosignatureKind::Nucleus,
        })
    }
}

impl InProcessWitness {
    /// **v2.3.** Produce a C2SP-protocol cosignature: signs the
    /// tlog-checkpoint body bytes rather than `canonical_sth_bytes`.
    /// Used when federating with the external transparency.dev /
    /// ArmoredWitness / Sigstore ecosystem.
    ///
    /// `origin` is the log identifier the C2SP checkpoint declares
    /// (e.g. `"nucleus.example.com/log42"`). Must match between
    /// producer and verifier — if a verifier expects origin X but
    /// the cosignature was produced over a checkpoint with origin Y,
    /// verification fails (bytes differ).
    pub fn cosign_c2sp(
        &self,
        sth: &SignedTreeHead,
        origin: &str,
    ) -> Result<Cosignature, WitnessError> {
        let root = hex_decode_32(&sth.root_hash_hex)
            .ok_or_else(|| WitnessError::Backend("malformed root_hash_hex in STH".into()))?;
        let body = crate::signed_note::checkpoint_signed_bytes(origin, sth.tree_size, &root)
            .map_err(|e| WitnessError::Backend(format!("checkpoint body: {e}")))?;
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| WitnessError::Clock)?
            .as_millis() as u64;
        let signature = self.inner.sign_message(&body).to_vec();
        Ok(Cosignature {
            witness_kid: self.inner.kid().to_string(),
            signature,
            timestamp_ms,
            kind: CosignatureKind::C2sp,
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
//
// # Threat model
//
// Cosignature bytes are integrity-protected by the witness's Ed25519
// signature over the producer's canonical STH bytes — an active MITM
// cannot forge a cosignature without the witness's signing key. What
// a MITM CAN do is:
//
// - **Drop responses** → producer's `BundleBuilder` ships fewer
//   cosignatures than expected; a verifier with
//   `cosignature_threshold(N)` rejects. Effectively a DoS.
// - **Replay a stale cosig** → harmless: each cosignature signs the
//   exact (tree_size, producer_ts, root_hash) tuple, so a stale cosig
//   doesn't apply to a new STH.
//
// Operate over TLS (`https://...`) or on a trusted network. The
// rustls feature is enabled in this crate's `http` build.
//
// # Concurrency cost
//
// `BundleBuilder` invokes each `WitnessClient::cosign` SEQUENTIALLY
// from a blocking thread. With N witnesses and `DEFAULT_TIMEOUT_MS`
// = 10s, worst-case bundle build stalls for N × 10s. The trait is
// sync; a future v2.3 will switch to `async fn cosign` and `join_all`
// the fanout. For now: keep witness counts small (≤ 5) and timeouts
// tight (`with_timeout` to override).

#[cfg(feature = "http")]
mod http {
    use std::time::Duration;

    use reqwest::blocking::Client;

    use super::{Cosignature, SignedTreeHead, WitnessClient, WitnessError};

    /// Default request timeout for a witness HTTP call. Witnesses
    /// typically respond in milliseconds; 10s gives plenty of slack
    /// for slow links without holding bundle assembly forever.
    const DEFAULT_TIMEOUT_MS: u64 = 10_000;
    /// **CRIT-1 from the audit on slice C.** A `Cosignature` is ~150
    /// bytes JSON-encoded. Cap response bodies at 8 KiB so a hostile
    /// witness cannot OOM the producer by streaming back gigabytes.
    /// Applied via both `Content-Length` pre-check AND post-read body
    /// length check (a lying `Content-Length: 0` with chunked transfer
    /// is still bounded by the buffered read).
    const MAX_COSIG_RESPONSE_BYTES: usize = 8 * 1024;

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
        /// responses whose `witness_kid` doesn't match.
        ///
        /// **This is a misconfiguration check (catches a mis-pointed
        /// `base_url`), NOT a trust check.** A hostile witness can
        /// return any kid string it wants — the kid is producer-
        /// controlled metadata. The load-bearing trust authority lives
        /// on the verifier side via
        /// [`crate::cosign::WitnessClient`]'s consumers configuring
        /// `TrustAnchor::with_trusted_witness` (in nucleus-envelope)
        /// with the witness's OOB-known verifying key bytes.
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
                // Bound the error-body excerpt so a server returning a
                // multi-MB error page can't bloat the producer's logs.
                let body_cap = 1024;
                let body = response
                    .text()
                    .unwrap_or_default()
                    .chars()
                    .take(body_cap)
                    .collect::<String>();
                return Err(WitnessError::Backend(format!(
                    "witness at {url} returned {status}: {body}"
                )));
            }
            // CRIT-1: bound the response body BEFORE buffering it.
            // A hostile witness returning gigabytes of JSON cannot
            // force the producer to allocate that much memory.
            if let Some(declared) = response.content_length() {
                if declared > MAX_COSIG_RESPONSE_BYTES as u64 {
                    return Err(WitnessError::Backend(format!(
                        "witness at {url} declared Content-Length {declared} > {MAX_COSIG_RESPONSE_BYTES}"
                    )));
                }
            }
            // MED-6: validate Content-Type so a witness returning HTML
            // that happens to parse as JSON doesn't silently slip
            // through. We accept any `application/json[; charset=...]`.
            let content_type = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            if !content_type
                .split(';')
                .next()
                .map(|t| t.trim().eq_ignore_ascii_case("application/json"))
                .unwrap_or(false)
            {
                return Err(WitnessError::Backend(format!(
                    "witness at {url} returned non-JSON Content-Type: {content_type:?}"
                )));
            }
            // Even with a Content-Length cap, a chunked-encoding response
            // can lie. `bytes()` accumulates into memory but we check
            // length again after reading.
            let body_bytes = response
                .bytes()
                .map_err(|e| WitnessError::Backend(format!("reading body from {url}: {e}")))?;
            if body_bytes.len() > MAX_COSIG_RESPONSE_BYTES {
                return Err(WitnessError::Backend(format!(
                    "witness at {url} returned {}-byte body > {MAX_COSIG_RESPONSE_BYTES}",
                    body_bytes.len()
                )));
            }
            let cosig: Cosignature = serde_json::from_slice(&body_bytes).map_err(|e| {
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
