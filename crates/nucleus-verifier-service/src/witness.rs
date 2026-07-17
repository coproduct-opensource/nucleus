//! Witness gossip federation primitive (#73 iter-1).
//!
//! Accepts peer verifier-service operators' signed assertions about
//! OUR STH (or theirs) and exposes them as cross-cosignatures. The
//! goal is to defeat split-brain attacks where a single operator
//! could in principle serve a different STH to different audiences:
//! once multiple operators have observed the same root and signed
//! it, any divergence is detectable by anyone aggregating their
//! cosignatures.
//!
//! # Iter-1 scope
//!
//! - In-memory ring buffer of the last [`PEER_RING_CAPACITY`] valid
//!   peer cosignatures.
//! - Pre-configured peer allowlist (peer_pubkey_hex → Ed25519 key).
//! - `POST /v1/witness/peer-sth` accepts `{peer_pubkey_hex, sth_json,
//!   signature_b64}`; validates the signature over the canonical
//!   bytes derived from the STH; adds to the ring on success.
//! - `GET /v1/witness/peers` returns the current ring contents.
//!
//! # Iter-2 follow-ups
//!
//! - Full C2SP `tlog-witness` HTTP API conformance (request takes a
//!   checkpoint + consistency proof + previous STH; we verify the
//!   consistency proof before cosigning).
//! - Persistent storage for peer cosignatures (SQLite table; survives
//!   restart so split-brain detection isn't reset by a deploy).
//! - Periodic outbound: we post OUR STH to each peer's `/v1/witness/peer-sth`
//!   on a 5-min cadence.
//! - C2SP signed-note wire format (`cosignature/v1\n<ts>\n<note>`)
//!   for byte-compatibility with the transparency.dev witness pool.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use ed25519_dalek::{Signature, VerifyingKey};
use tokio::sync::RwLock;

/// How many recent peer cosignatures the in-memory ring retains.
/// Older entries are evicted FIFO.
pub const PEER_RING_CAPACITY: usize = 128;

/// Allowlisted peer set: short kid (hex prefix of pubkey) →
/// VerifyingKey. Constructed at startup from the CLI flag.
#[derive(Clone, Debug, Default)]
pub struct PeerAllowlist {
    by_pubkey_hex: HashMap<String, VerifyingKey>,
}

impl PeerAllowlist {
    pub fn from_hex_keys(hex_keys: &[String]) -> Result<Self, String> {
        let mut by_pubkey_hex = HashMap::new();
        for hex_key in hex_keys {
            let bytes = hex::decode(hex_key.trim())
                .map_err(|e| format!("peer pubkey {hex_key:?}: hex decode {e}"))?;
            let array: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| format!("peer pubkey {hex_key:?}: must be 32 bytes"))?;
            let vk = VerifyingKey::from_bytes(&array)
                .map_err(|e| format!("peer pubkey {hex_key:?}: invalid Ed25519 key: {e}"))?;
            by_pubkey_hex.insert(hex_key.trim().to_lowercase(), vk);
        }
        Ok(Self { by_pubkey_hex })
    }

    pub fn is_empty(&self) -> bool {
        self.by_pubkey_hex.is_empty()
    }

    pub fn lookup(&self, pubkey_hex: &str) -> Option<&VerifyingKey> {
        self.by_pubkey_hex.get(&pubkey_hex.trim().to_lowercase())
    }

    pub fn len(&self) -> usize {
        self.by_pubkey_hex.len()
    }
}

/// One accepted peer cosignature. Exposed verbatim on the
/// `/v1/witness/peers` endpoint.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PeerCosignature {
    pub peer_pubkey_hex: String,
    pub sth_json: String,
    pub signature_b64: String,
    pub accepted_at_ms: i64,
}

/// In-memory ring of accepted cosignatures.
pub struct PeerCosignatureRing {
    inner: std::collections::VecDeque<PeerCosignature>,
    capacity: usize,
}

impl PeerCosignatureRing {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: std::collections::VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn push(&mut self, entry: PeerCosignature) {
        if self.inner.len() == self.capacity {
            self.inner.pop_front();
        }
        self.inner.push_back(entry);
    }

    pub fn snapshot(&self) -> Vec<PeerCosignature> {
        self.inner.iter().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// Shared ring + allowlist handle; lives in AppState.
#[derive(Clone)]
pub struct WitnessFederation {
    pub allowlist: Arc<PeerAllowlist>,
    pub ring: Arc<RwLock<PeerCosignatureRing>>,
}

impl WitnessFederation {
    pub fn new(allowlist: PeerAllowlist) -> Self {
        Self {
            allowlist: Arc::new(allowlist),
            ring: Arc::new(RwLock::new(PeerCosignatureRing::new(PEER_RING_CAPACITY))),
        }
    }

    /// Validate + accept a peer cosignature. Returns Ok(()) when the
    /// signature verifies against the peer's pubkey; Err on any
    /// validation failure.
    pub async fn accept(
        &self,
        peer_pubkey_hex: &str,
        sth_json: &str,
        signature_b64: &str,
    ) -> Result<(), WitnessError> {
        let vk = self
            .allowlist
            .lookup(peer_pubkey_hex)
            .ok_or(WitnessError::UnknownPeer)?;
        let sig_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, signature_b64)
                .map_err(|_| WitnessError::BadSignature)?;
        let sig_array: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| WitnessError::BadSignature)?;
        let signature = Signature::from_bytes(&sig_array);
        vk.verify_strict(sth_json.as_bytes(), &signature)
            .map_err(|_| WitnessError::BadSignature)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        self.ring.write().await.push(PeerCosignature {
            peer_pubkey_hex: peer_pubkey_hex.to_lowercase(),
            sth_json: sth_json.to_string(),
            signature_b64: signature_b64.to_string(),
            accepted_at_ms: now,
        });
        Ok(())
    }
}

/// Errors surfaced by [`WitnessFederation::accept`].
#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    #[error("peer pubkey not in allowlist")]
    UnknownPeer,
    #[error("signature did not verify against peer pubkey")]
    BadSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey, SECRET_KEY_LENGTH};

    fn fixture_signer(seed: u8) -> (SigningKey, String) {
        let key = SigningKey::from_bytes(&[seed; SECRET_KEY_LENGTH]);
        let hex = hex::encode(key.verifying_key().to_bytes());
        (key, hex)
    }

    #[test]
    fn empty_allowlist_rejects_lookups() {
        let allow = PeerAllowlist::default();
        assert!(allow.is_empty());
        assert!(allow.lookup("anything").is_none());
    }

    #[test]
    fn allowlist_construction_rejects_short_hex() {
        let err = PeerAllowlist::from_hex_keys(&["deadbeef".to_string()]).unwrap_err();
        assert!(err.contains("must be 32 bytes"), "got: {err}");
    }

    #[test]
    fn allowlist_lookup_is_case_insensitive() {
        let (_, hex_lower) = fixture_signer(1);
        let allow = PeerAllowlist::from_hex_keys(&[hex_lower.to_uppercase()]).expect("valid");
        // Original lowercase works…
        assert!(allow.lookup(&hex_lower).is_some());
        // …and so does mixed case.
        let mixed: String = hex_lower
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect();
        assert!(allow.lookup(&mixed).is_some());
    }

    #[test]
    fn ring_evicts_oldest_at_capacity() {
        let mut ring = PeerCosignatureRing::new(2);
        for i in 0..5u8 {
            ring.push(PeerCosignature {
                peer_pubkey_hex: format!("{i:02x}"),
                sth_json: "{}".to_string(),
                signature_b64: "".to_string(),
                accepted_at_ms: i as i64,
            });
        }
        assert_eq!(ring.len(), 2);
        let snap = ring.snapshot();
        assert_eq!(snap[0].accepted_at_ms, 3);
        assert_eq!(snap[1].accepted_at_ms, 4);
    }

    #[tokio::test]
    async fn accept_with_valid_signature_pushes_to_ring() {
        let (signer, hex_pubkey) = fixture_signer(42);
        let allow = PeerAllowlist::from_hex_keys(std::slice::from_ref(&hex_pubkey)).unwrap();
        let fed = WitnessFederation::new(allow);

        let sth = r#"{"tree_size":3,"root":"abc"}"#;
        let sig = signer.sign(sth.as_bytes());
        let sig_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes());

        fed.accept(&hex_pubkey, sth, &sig_b64).await.unwrap();
        let snap = fed.ring.read().await.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].peer_pubkey_hex, hex_pubkey.to_lowercase());
        assert_eq!(snap[0].sth_json, sth);
    }

    #[tokio::test]
    async fn accept_rejects_unknown_peer() {
        let (signer, hex_pubkey) = fixture_signer(42);
        let allow = PeerAllowlist::default(); // peer NOT in allowlist
        let fed = WitnessFederation::new(allow);

        let sth = r#"{"tree_size":3}"#;
        let sig = signer.sign(sth.as_bytes());
        let sig_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes());

        let err = fed.accept(&hex_pubkey, sth, &sig_b64).await.unwrap_err();
        assert!(matches!(err, WitnessError::UnknownPeer));
    }

    #[tokio::test]
    async fn accept_rejects_bad_signature() {
        let (_, hex_pubkey) = fixture_signer(42);
        let allow = PeerAllowlist::from_hex_keys(std::slice::from_ref(&hex_pubkey)).unwrap();
        let fed = WitnessFederation::new(allow);

        let sth = r#"{"tree_size":3}"#;
        // Random 64 bytes — not a valid signature for this STH+pubkey.
        let sig_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0xff_u8; 64]);

        let err = fed.accept(&hex_pubkey, sth, &sig_b64).await.unwrap_err();
        assert!(matches!(err, WitnessError::BadSignature));
    }

    #[tokio::test]
    async fn accept_with_truncated_signature_rejected_as_bad_sig() {
        let (_, hex_pubkey) = fixture_signer(42);
        let allow = PeerAllowlist::from_hex_keys(std::slice::from_ref(&hex_pubkey)).unwrap();
        let fed = WitnessFederation::new(allow);

        let sth = r#"{"tree_size":3}"#;
        // 60 bytes — not 64.
        let sig_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0xff_u8; 60]);

        let err = fed.accept(&hex_pubkey, sth, &sig_b64).await.unwrap_err();
        assert!(matches!(err, WitnessError::BadSignature));
    }
}
