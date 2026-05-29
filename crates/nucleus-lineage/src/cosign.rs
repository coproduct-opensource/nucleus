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
#[serde(deny_unknown_fields)]
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

    /// **v2.3b CRIT-2 fix.** Return ALL cosignatures this witness has
    /// for `sth`. The default implementation calls [`cosign`] once and
    /// wraps the result in a `Vec` — correct for single-key witnesses
    /// like [`InProcessWitness`].
    ///
    /// **Aggregator witnesses** (one HTTP endpoint proxying multiple
    /// witness keys — common pattern for transparency.dev / ArmoredWitness
    /// distributors) MUST override to return all proxied signatures.
    /// [`crate::C2spHttpWitnessClient`] does this. Without the override,
    /// `BundleBuilder::with_cosignatures` would silently retain only
    /// the first cosignature of an N-cosig response — making
    /// `cosignature_threshold(N)` unsatisfiable against an aggregator.
    ///
    /// [`cosign`]: WitnessClient::cosign
    fn cosign_many(&self, sth: &SignedTreeHead) -> Result<Vec<Cosignature>, WitnessError> {
        Ok(vec![self.cosign(sth)?])
    }
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

// ─────────────────────────────────────────────────────────────────────
// v2.3b — C2SP-compliant HTTP witness (POST /add-checkpoint per
// https://github.com/C2SP/C2SP/blob/main/tlog-witness.md).
//
// Wire shape (feature = "http"):
//
//   POST <base_url>/add-checkpoint
//   Content-Type: text/plain (UTF-8 line-oriented body)
//   Body:
//     old <prev_tree_size_decimal>\n
//     <0..63 base64 consistency-proof lines, each \n-terminated>
//     \n                                  ← blank line
//     <checkpoint body lines>             ← origin / size / base64(root)
//     \n                                  ← signed-note body/sig separator
//     — <producer_key_name> <base64(key_id_4 || producer_sig)>\n
//
//   Response 200 OK
//   Content-Type: text/plain
//   Body: one or more cosignature lines `— <key_name> <base64>\n`
//
// Each response line maps to one `Cosignature { kind: C2sp, ... }`
// where `witness_kid` is the response's `key_name` and `signature`
// is the bytes AFTER the 4-byte key_id (i.e. the raw Ed25519 sig).
//
// Compared to the nucleus-native HttpWitnessClient earlier in this
// module, the C2SP client is what federates with the external
// ArmoredWitness / Sigstore / transparency.dev ecosystem.

#[cfg(feature = "http")]
mod c2sp_http {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use reqwest::blocking::Client;

    use super::{Cosignature, CosignatureKind, Ed25519Witness, SignedTreeHead, WitnessError};
    use crate::prover::MerkleProver;
    use crate::signed_note::{
        checkpoint_signed_bytes, ed25519_key_id, format_signature_line, parse_signature_line,
        SIG_LINE_PREFIX, SIG_TYPE_ED25519,
    };

    const DEFAULT_TIMEOUT_MS: u64 = 10_000;
    /// Same DoS bound as the nucleus-native HttpWitnessClient. A C2SP
    /// response is small (a few hundred bytes per signature line); 8
    /// KiB comfortably covers up to ~50 cosigs per response.
    const MAX_RESPONSE_BYTES: usize = 8 * 1024;
    /// **v2.3c.** Spec cap: "The client MUST NOT send more than 63
    /// consistency proof lines." Tracked here as a defensive check so a
    /// bug in `prove_consistency_from` can't generate a request the
    /// witness will reject for being oversized.
    const MAX_CONSISTENCY_PROOF_LINES: usize = 63;

    /// HTTP client that speaks the C2SP `POST /add-checkpoint` protocol.
    ///
    /// Construction takes the producer's signing witness so the client
    /// can compute the C2SP-style producer signature line that goes in
    /// the request body (a real C2SP witness rejects requests whose
    /// checkpoint isn't signed by a key it trusts for that origin).
    ///
    /// **v2.3c stateful federation.** The client tracks the witness's
    /// last-cosigned tree size in `state: Mutex<ClientState>`:
    ///
    /// - `last_known_size: None` → first submission ever; sends `old 0`
    ///   with NO proof.
    /// - `last_known_size: Some(n)` with `n > 0` and a [`MerkleProver`]
    ///   attached via [`Self::with_consistency_prover`] → sends `old n`
    ///   followed by the RFC 6962 §2.1.2 consistency proof from `n` to
    ///   the STH's tree_size, encoded as base64 lines.
    /// - On HTTP 200 OK, state advances to the STH's `tree_size`.
    /// - On HTTP 409 Conflict (Content-Type: `text/x.tlog.size`), state
    ///   is updated to the witness-reported size and the request is
    ///   retried ONCE with a fresh consistency proof. A second 409
    ///   surfaces as [`WitnessError::Conflict`] — no infinite loops.
    ///
    /// # Concurrency (CRIT-1 fix, issue #1646)
    ///
    /// The full attempt+retry-on-409 sequence runs under one
    /// [`Mutex<ClientState>`] acquisition. Two concurrent `cosign_many`
    /// calls against the same client serialize end-to-end (each waits
    /// for the previous one's HTTP round-trip + state update before
    /// reading state). This prevents the v2.3c race where two threads
    /// could read the same `prev_size`, both succeed, and the slower
    /// thread's write would clobber the faster thread's correct new
    /// size with a stale, smaller one — triggering spurious 409s on
    /// the next call.
    ///
    /// The mutex is `std::sync::Mutex`, NOT `tokio::sync::Mutex`: the
    /// underlying HTTP transport is `reqwest::blocking`, never `.await`,
    /// so callers from async contexts must wrap `cosign_many` in
    /// `tokio::task::spawn_blocking`. For parallel throughput, use
    /// multiple `C2spHttpWitnessClient` instances pointed at the same
    /// origin — the witness reconciles via 409.
    ///
    /// **Operator note**: without a consistency-prover attached, the
    /// client always sends `old 0`. The witness will reject the second
    /// and subsequent submissions with 409. Use this mode only for
    /// witness bring-up / testing. For production federation, attach a
    /// prover via [`Self::with_consistency_prover`].
    pub struct C2spHttpWitnessClient {
        base_url: String,
        origin: String,
        producer: Arc<Ed25519Witness>,
        producer_key_name: String,
        client: Client,
        expected_witness_name: Option<String>,
        /// **v2.3c.** Optional MerkleProver used to compute RFC 6962
        /// consistency proofs when `last_known_size > 0`. If absent,
        /// the client always sends `old 0` regardless of state.
        consistency_prover: Option<Arc<dyn MerkleProver>>,
        /// **CRIT-1 (#1646) fix.** Per-client serialized state: the
        /// full read-attempt-write-(retry) sequence in `cosign_many`
        /// holds this lock so concurrent callers can't interleave and
        /// clobber `last_known_size`. Wrapping ALL state in one
        /// `Mutex<ClientState>` (vs separate locks per field) closes
        /// the race-on-multiple-mutex foot-gun.
        state: Mutex<ClientState>,
    }

    /// **CRIT-1 (#1646) fix.** All per-client mutable state, locked as
    /// one unit. Extending this struct with new state requires NO
    /// additional locks — keep it that way.
    struct ClientState {
        /// Witness's last-cosigned tree size, per its 409 signals or
        /// per our own bookkeeping on successful POSTs. `None` means
        /// "haven't talked to this witness yet" — sends `old 0` with
        /// no consistency proof.
        last_known_size: Option<u64>,
    }

    impl C2spHttpWitnessClient {
        /// `base_url` is the witness's submission prefix (the
        /// `/add-checkpoint` path is appended). `origin` is the
        /// schema-less URL identifying this log to the witness (e.g.
        /// `nucleus.example.com/log42`). `producer` signs the
        /// checkpoint body for the request; `producer_key_name`
        /// becomes the C2SP key_name in the producer's signature line.
        pub fn new(
            base_url: impl Into<String>,
            origin: impl Into<String>,
            producer: Arc<Ed25519Witness>,
            producer_key_name: impl Into<String>,
        ) -> Result<Self, WitnessError> {
            let client = Client::builder()
                .timeout(Duration::from_millis(DEFAULT_TIMEOUT_MS))
                .build()
                .map_err(|e| WitnessError::Backend(format!("reqwest client build: {e}")))?;
            Ok(Self {
                base_url: base_url.into(),
                origin: origin.into(),
                producer,
                producer_key_name: producer_key_name.into(),
                client,
                expected_witness_name: None,
                consistency_prover: None,
                state: Mutex::new(ClientState {
                    last_known_size: None,
                }),
            })
        }

        /// Override the default 10s request timeout.
        pub fn with_timeout(mut self, timeout: Duration) -> Result<Self, WitnessError> {
            self.client = Client::builder()
                .timeout(timeout)
                .build()
                .map_err(|e| WitnessError::Backend(format!("reqwest client build: {e}")))?;
            Ok(self)
        }

        /// **Misconfiguration check** (NOT a trust check). When set,
        /// `cosign_many` rejects responses where the FIRST cosig line's
        /// `key_name` doesn't match. Useful for catching mis-pointed
        /// `base_url`s in dev. The load-bearing trust authority is
        /// `TrustAnchor::with_trusted_witness` on the verifier side.
        pub fn with_expected_witness_name(mut self, name: impl Into<String>) -> Self {
            self.expected_witness_name = Some(name.into());
            self
        }

        /// **v2.3c.** Attach a [`MerkleProver`] for computing RFC 6962
        /// consistency proofs. Required for production federation
        /// against a witness that has seen prior checkpoints — without
        /// a prover, the client sends `old 0` on every request and the
        /// witness returns 409 Conflict on all but the first submission.
        ///
        /// Production callers typically pass the same `MerkleSink` they
        /// gave the `BundleBuilder::with_merkle_prover` call. The proof
        /// must be computed against the SAME tree state the producer
        /// sealed for this STH, so callers MUST attach the prover
        /// BEFORE calling `cosign_many`.
        pub fn with_consistency_prover(mut self, prover: Arc<dyn MerkleProver>) -> Self {
            self.consistency_prover = Some(prover);
            self
        }

        /// **v2.3c.** Seed the client's `last_known_size` from
        /// out-of-band state — e.g., a producer that persists witness
        /// state across process restarts can call this to skip the
        /// first 409 handshake on resume.
        pub fn with_initial_known_size(self, size: u64) -> Self {
            self.state.lock().unwrap().last_known_size = Some(size);
            self
        }

        fn endpoint(&self) -> String {
            let trimmed = self.base_url.trim_end_matches('/');
            format!("{trimmed}/add-checkpoint")
        }

        /// Build the `POST /add-checkpoint` request body for `sth`.
        /// `prev_tree_size` is the size the witness last cosigned for
        /// this origin (or 0 for the first submission).
        ///
        /// **v2.3c**: if `prev_tree_size > 0` and a consistency prover
        /// is attached, computes the RFC 6962 consistency proof from
        /// `prev_tree_size` to `sth.tree_size` and emits one base64 line
        /// per proof hash between the `old` line and the blank
        /// separator. Per spec, at most 63 proof lines.
        fn build_request_body(
            &self,
            sth: &SignedTreeHead,
            prev_tree_size: u64,
        ) -> Result<Vec<u8>, WitnessError> {
            use base64::{engine::general_purpose::STANDARD, Engine as _};

            let root = hex_decode_32(&sth.root_hash_hex)
                .ok_or_else(|| WitnessError::Backend("malformed root_hash_hex in STH".into()))?;
            let checkpoint_body = checkpoint_signed_bytes(&self.origin, sth.tree_size, &root)
                .map_err(|e| WitnessError::Backend(format!("checkpoint body: {e}")))?;
            let producer_sig = self.producer.sign_message(&checkpoint_body);
            let producer_pub = self.producer.verifying_key_bytes();
            let key_id = ed25519_key_id(&self.producer_key_name, SIG_TYPE_ED25519, &producer_pub);
            let sig_line = format_signature_line(&self.producer_key_name, &key_id, &producer_sig)
                .map_err(|e| WitnessError::Backend(format!("producer sig line: {e}")))?;

            // **v2.3c consistency proof** when prev_size > 0 AND a
            // prover is attached. Without a prover at prev_size > 0, we
            // still send `old <prev_size>` and zero proof lines — the
            // witness will reject (since spec requires the proof) but
            // the operator gets a clear backend error mentioning the
            // missing proof. With prev_size == 0, never emit proof
            // lines regardless of prover (spec: first submission has
            // no proof).
            let mut proof_lines: Vec<String> = Vec::new();
            if prev_tree_size > 0 {
                if let Some(prover) = &self.consistency_prover {
                    let proof = prover
                        .prove_consistency_from(prev_tree_size)
                        .map_err(|e| WitnessError::Backend(format!("consistency proof: {e}")))?;
                    let raw = proof.as_bytes();
                    // ct-merkle ConsistencyProof.as_bytes() is the
                    // concatenation of 32-byte SHA-256 hashes; split.
                    if raw.len() % 32 != 0 {
                        return Err(WitnessError::Backend(format!(
                            "consistency proof byte length {} not a multiple of 32",
                            raw.len()
                        )));
                    }
                    let hash_count = raw.len() / 32;
                    if hash_count > MAX_CONSISTENCY_PROOF_LINES {
                        return Err(WitnessError::Backend(format!(
                            "consistency proof has {hash_count} hashes; spec caps at \
                             {MAX_CONSISTENCY_PROOF_LINES}",
                        )));
                    }
                    proof_lines.reserve(hash_count);
                    for chunk in raw.chunks_exact(32) {
                        proof_lines.push(STANDARD.encode(chunk));
                    }
                }
                // else: prev_size > 0 but no prover; emit no proof
                // lines. Spec-non-conforming but produces a clear
                // witness-reject for operator diagnosis.
            }

            // C2SP tlog-witness add-checkpoint body (per
            // tlog-witness.md):
            //   "old <prev_size>\n"
            //   <0..63 base64 consistency-proof lines, each \n-term>
            //   "\n"                  (blank line separator)
            //   <checkpoint body>     (already ends in \n per spec)
            //   "\n"                  (signed-note body/sig separator)
            //   <producer signature line>\n
            let mut body = Vec::with_capacity(checkpoint_body.len() + 256 + proof_lines.len() * 48);
            body.extend_from_slice(format!("old {prev_tree_size}\n").as_bytes());
            for line in &proof_lines {
                body.extend_from_slice(line.as_bytes());
                body.push(b'\n');
            }
            body.push(b'\n');
            body.extend_from_slice(&checkpoint_body);
            body.push(b'\n');
            body.extend_from_slice(sig_line.as_bytes());
            body.push(b'\n');
            Ok(body)
        }

        /// Parse a response body into Cosignatures. Each line starting
        /// with the em-dash signature prefix becomes one Cosignature
        /// of kind C2sp. Other lines (e.g. blank lines, comments) are
        /// silently skipped.
        fn parse_response(&self, body: &[u8]) -> Result<Vec<Cosignature>, WitnessError> {
            let text = std::str::from_utf8(body).map_err(|e| {
                WitnessError::Backend(format!("witness response is not UTF-8: {e}"))
            })?;
            let timestamp_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| WitnessError::Clock)?
                .as_millis() as u64;
            let mut out = Vec::new();
            for line in text.lines() {
                if !line.starts_with(SIG_LINE_PREFIX) {
                    continue;
                }
                let parsed = parse_signature_line(line)
                    .map_err(|e| WitnessError::Backend(format!("malformed cosig line: {e}")))?;
                out.push(Cosignature {
                    witness_kid: parsed.key_name,
                    signature: parsed.signature,
                    timestamp_ms,
                    kind: CosignatureKind::C2sp,
                });
            }
            Ok(out)
        }

        /// Call the witness and return ALL cosignatures it returned.
        /// Production callers federating with an aggregator witness
        /// service (which proxies many witness keys) should use this
        /// rather than [`WitnessClient::cosign`], which returns only
        /// the first cosig.
        ///
        /// **v2.3c stateful federation.** Uses the tracked
        /// `last_known_size` to build the `old <prev_size>` line +
        /// consistency proof. On HTTP 200, advances state to
        /// `sth.tree_size`. On HTTP 409 Conflict carrying the witness's
        /// actual last-known size, updates state and retries ONCE with
        /// a fresh proof. A second 409 surfaces as
        /// [`WitnessError::Conflict`] (no retry loop).
        ///
        /// **CRIT-1 (#1646) fix.** The full sequence runs under one
        /// `state.lock()` acquisition so concurrent callers cannot
        /// interleave read-attempt-write and clobber each other's
        /// `last_known_size`. The lock is a `std::sync::Mutex`, held
        /// across the synchronous (blocking) HTTP round-trip — never
        /// across an `.await`. Callers from async contexts MUST wrap
        /// in `spawn_blocking`.
        pub fn cosign_many(&self, sth: &SignedTreeHead) -> Result<Vec<Cosignature>, WitnessError> {
            // Single critical section: read → POST → (on 409) update +
            // retry → write. Concurrent callers wait FIFO at the lock.
            let mut state = self
                .state
                .lock()
                .map_err(|_| WitnessError::Poisoned("C2spHttpWitnessClient.state"))?;

            let prev = state.last_known_size.unwrap_or(0);
            match self.attempt_cosign(sth, prev) {
                Ok(cosigs) => {
                    state.last_known_size = Some(sth.tree_size);
                    Ok(cosigs)
                }
                Err(WitnessError::Conflict { last_known_size }) => {
                    // **v2.3c retry-once.** Witness's state diverged
                    // from ours; update and retry with a proof from
                    // the witness-reported size. State is updated
                    // BEFORE the retry so that even if the retry
                    // fails, the next call starts from the right
                    // position.
                    state.last_known_size = Some(last_known_size);
                    match self.attempt_cosign(sth, last_known_size) {
                        Ok(cosigs) => {
                            state.last_known_size = Some(sth.tree_size);
                            Ok(cosigs)
                        }
                        Err(e) => Err(e),
                    }
                }
                Err(e) => Err(e),
            }
        }

        /// Single POST attempt — no retries. Extracted from
        /// `cosign_many` so the state-update + retry-once dance lives
        /// in exactly one place.
        fn attempt_cosign(
            &self,
            sth: &SignedTreeHead,
            prev_tree_size: u64,
        ) -> Result<Vec<Cosignature>, WitnessError> {
            let body = self.build_request_body(sth, prev_tree_size)?;
            let url = self.endpoint();
            let response = self
                .client
                .post(&url)
                .header(reqwest::header::CONTENT_TYPE, "text/plain")
                .body(body)
                .send()
                .map_err(|e| WitnessError::Backend(format!("POST {url}: {e}")))?;
            let status = response.status();
            if !status.is_success() {
                // **v2.3b HIGH-3 fix.** A C2SP witness signals
                // `old <prev_tree_size>` mismatch via 409 Conflict;
                // per tlog-witness.md the body is the witness's
                // actual last-cosigned tree size in decimal,
                // Content-Type: `text/x.tlog.size`.
                //
                // **HIGH-4 (audit) fix.** Liberally accept any 409
                // whose body parses as decimal as a Conflict (don't
                // gate on Content-Type — proxies can mangle headers
                // without invalidating the spec semantics). For
                // 409s whose body does NOT parse (HTML rate-limit
                // pages, garbled proxy responses), include the
                // Content-Type in the surfaced error so operators
                // can disambiguate "witness misbehavior" from
                // "intermediary misbehavior". This closes the audit
                // concern about HTML 409s silently being treated as
                // generic backend errors — operators now see the
                // Content-Type hint instead of just a body excerpt.
                let is_409 = status.as_u16() == 409;
                let ct = response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "<missing>".to_string());
                let raw = response.text().unwrap_or_default();
                if is_409 {
                    if let Ok(size) = raw.trim().parse::<u64>() {
                        return Err(WitnessError::Conflict {
                            last_known_size: size,
                        });
                    }
                    // 409 with non-decimal body: distinct Backend
                    // error including Content-Type so operators can
                    // tell "witness sent garbage" from "proxy
                    // returned HTML rate-limit page".
                    let body_cap = 512;
                    let body_excerpt: String = raw.chars().take(body_cap).collect();
                    return Err(WitnessError::Backend(format!(
                        "C2SP witness at {url} returned 409 Conflict with non-decimal body \
                         (Content-Type: {ct}); spec requires `text/x.tlog.size` + decimal \
                         tree size. Body excerpt: {body_excerpt}"
                    )));
                }
                let body_cap = 1024;
                let body_excerpt: String = raw.chars().take(body_cap).collect();
                return Err(WitnessError::Backend(format!(
                    "C2SP witness at {url} returned {status}: {body_excerpt}"
                )));
            }
            if let Some(len) = response.content_length() {
                if len > MAX_RESPONSE_BYTES as u64 {
                    return Err(WitnessError::Backend(format!(
                        "C2SP witness at {url} declared Content-Length {len} > {MAX_RESPONSE_BYTES}"
                    )));
                }
            }
            let body_bytes = response
                .bytes()
                .map_err(|e| WitnessError::Backend(format!("reading body from {url}: {e}")))?;
            if body_bytes.len() > MAX_RESPONSE_BYTES {
                return Err(WitnessError::Backend(format!(
                    "C2SP witness at {url} returned {}-byte body > {MAX_RESPONSE_BYTES}",
                    body_bytes.len()
                )));
            }
            let cosigs = self.parse_response(&body_bytes)?;
            if cosigs.is_empty() {
                return Err(WitnessError::Backend(format!(
                    "C2SP witness at {url} returned 200 OK but body had no signature lines"
                )));
            }
            // **v2.3b HIGH-4 fix.** Check whether the EXPECTED name
            // appears ANYWHERE in the response (aggregators may put
            // the trusted witness's cosig in any position; first-only
            // checking was misleading).
            if let Some(expected) = &self.expected_witness_name {
                if !cosigs.iter().any(|c| &c.witness_kid == expected) {
                    let names: Vec<&str> = cosigs.iter().map(|c| c.witness_kid.as_str()).collect();
                    return Err(WitnessError::Backend(format!(
                        "C2SP witness at {url} returned key_names {:?}, expected one to be {:?}",
                        names, expected
                    )));
                }
            }
            Ok(cosigs)
        }
    }

    impl super::WitnessClient for C2spHttpWitnessClient {
        fn cosign(&self, sth: &SignedTreeHead) -> Result<Cosignature, WitnessError> {
            let cosigs = self.cosign_many(sth)?;
            // **v2.3b LOW-1 fix.** Don't `.expect` — surface the
            // invariant breach as a Backend error if `cosign_many`'s
            // empty-check is ever loosened in a future refactor.
            cosigs.into_iter().next().ok_or_else(|| {
                WitnessError::Backend(
                    "C2spHttpWitnessClient::cosign_many returned empty Vec (invariant breach)"
                        .into(),
                )
            })
        }

        /// **v2.3b CRIT-2 override.** Aggregator path: return ALL
        /// cosigs from the response so `BundleBuilder::with_cosignatures`
        /// federates the full set.
        fn cosign_many(&self, sth: &SignedTreeHead) -> Result<Vec<Cosignature>, WitnessError> {
            // Delegate to the inherent method that does the HTTP work.
            C2spHttpWitnessClient::cosign_many(self, sth)
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
}

#[cfg(feature = "http")]
pub use self::c2sp_http::C2spHttpWitnessClient;

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
        use ed25519_dalek::{Signature, VerifyingKey};
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
        vk.verify_strict(&canonical, &sig)
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
