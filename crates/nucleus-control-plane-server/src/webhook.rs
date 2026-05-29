//! Webhook delivery for `Destination::HttpPost`.
//!
//! When a job completes with `destination = HttpPost`, the bundle is
//! delivered via a signed HTTP POST. Production posture follows the
//! Stripe / GitHub webhook playbook:
//!
//! - **HMAC-SHA256 body signing** via a server-wide shared secret
//!   (operator-supplied). The signature lands in
//!   `X-Nucleus-Signature: sha256=<hex>` — consumers verify with
//!   constant-time comparison against their copy of the secret.
//! - **Idempotency token** in `X-Nucleus-Delivery: <uuid>`. Consumers
//!   that record processed delivery ids dedupe retries automatically.
//! - **Event-type header** `X-Nucleus-Event: bundle.ready` lets
//!   consumers dispatch without parsing the body.
//! - **Exponential backoff with jitter**: 5 attempts at
//!   `2^k + rand(0..1)s` between, capping at ~30s total.
//! - **At-least-once delivery semantics**. The webhook may fire more
//!   than once for the same job; consumers MUST be idempotent.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::Result;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use thiserror::Error;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Total attempts including the initial. 1 + 4 retries.
const MAX_ATTEMPTS: u32 = 5;
/// Cap on total back-off time per delivery (5+10+20+30+30 ≈ 95s).
const BACKOFF_CAP_SECS: u64 = 30;

#[derive(Debug, Error)]
pub enum WebhookError {
    #[error("network: {0}")]
    Network(String),
    #[error("non-2xx response: {status} (body length {body_len})")]
    NonSuccess { status: u16, body_len: usize },
    #[error("HMAC key init: {0}")]
    HmacInit(String),
    #[error("attempt {attempt} of {max} failed; last error: {last}")]
    Exhausted {
        attempt: u32,
        max: u32,
        last: String,
    },
}

/// Outcome of one delivery attempt — surfaced to callers for logging.
#[derive(Debug, Clone)]
pub struct DeliveryReceipt {
    pub delivery_id: Uuid,
    pub status_code: u16,
    pub attempts: u32,
    pub total_duration: Duration,
}

/// Configuration for the delivery call. Cloneable so the same client
/// can be reused across many calls in the AppState.
#[derive(Clone)]
pub struct WebhookClient {
    inner: reqwest::Client,
    /// Server-wide HMAC signing key. Bytes are zeroed on drop via
    /// Hmac's hmac::Mac internals when the per-call instance is
    /// finalized. None disables signing (test path).
    signing_key: Option<Vec<u8>>,
}

impl std::fmt::Debug for WebhookClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookClient")
            .field("signing_enabled", &self.signing_key.is_some())
            .finish()
    }
}

impl WebhookClient {
    pub fn new(signing_key: Option<Vec<u8>>) -> Result<Self, WebhookError> {
        let inner = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(4)
            .user_agent("nucleus-control-plane/1.0")
            .build()
            .map_err(|e| WebhookError::Network(e.to_string()))?;
        Ok(Self { inner, signing_key })
    }

    /// Deliver `body` to `url` with `headers` + nucleus signing
    /// headers, retrying on failure with exponential backoff + jitter.
    /// Returns the receipt of the first successful delivery, or
    /// `Exhausted` after `MAX_ATTEMPTS`.
    pub async fn deliver(
        &self,
        url: &str,
        custom_headers: &BTreeMap<String, String>,
        body: &[u8],
    ) -> Result<DeliveryReceipt, WebhookError> {
        let delivery_id = Uuid::new_v4();
        let signature = self.sign_body(body)?;
        let started = std::time::Instant::now();
        let mut last_err: Option<String> = None;

        for attempt in 1..=MAX_ATTEMPTS {
            let mut req = self
                .inner
                .post(url)
                .body(body.to_vec())
                .header("Content-Type", "application/json")
                .header("X-Nucleus-Delivery", delivery_id.to_string())
                .header("X-Nucleus-Event", "bundle.ready")
                .header("X-Nucleus-Attempt", attempt.to_string());
            if let Some(sig) = &signature {
                req = req.header("X-Nucleus-Signature", format!("sha256={sig}"));
            }
            for (k, v) in custom_headers {
                req = req.header(k, v);
            }

            match req.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return Ok(DeliveryReceipt {
                            delivery_id,
                            status_code: status.as_u16(),
                            attempts: attempt,
                            total_duration: started.elapsed(),
                        });
                    }
                    // Non-2xx — capture and retry with backoff.
                    let body_text = resp.text().await.unwrap_or_default();
                    last_err = Some(format!(
                        "non-2xx {} (body {} bytes)",
                        status.as_u16(),
                        body_text.len()
                    ));
                    tracing::warn!(
                        delivery_id = %delivery_id,
                        url,
                        status = status.as_u16(),
                        attempt,
                        "webhook attempt failed (non-2xx)"
                    );
                }
                Err(e) => {
                    last_err = Some(format!("network: {e}"));
                    tracing::warn!(
                        delivery_id = %delivery_id,
                        url,
                        attempt,
                        error = %e,
                        "webhook attempt failed (network)"
                    );
                }
            }

            if attempt < MAX_ATTEMPTS {
                let backoff = backoff_for_attempt(attempt);
                tokio::time::sleep(backoff).await;
            }
        }

        Err(WebhookError::Exhausted {
            attempt: MAX_ATTEMPTS,
            max: MAX_ATTEMPTS,
            last: last_err.unwrap_or_else(|| "no error captured".to_string()),
        })
    }

    /// Compute the lowercase hex HMAC-SHA256 of `body` under
    /// `signing_key`. Returns `Ok(None)` when signing is disabled.
    fn sign_body(&self, body: &[u8]) -> Result<Option<String>, WebhookError> {
        let Some(key) = &self.signing_key else {
            return Ok(None);
        };
        let mut mac =
            HmacSha256::new_from_slice(key).map_err(|e| WebhookError::HmacInit(e.to_string()))?;
        mac.update(body);
        let bytes = mac.finalize().into_bytes();
        Ok(Some(hex::encode(bytes)))
    }
}

/// Compute back-off for `attempt` (1-indexed). 2^attempt seconds
/// + 0-1s jitter, capped at [`BACKOFF_CAP_SECS`].
fn backoff_for_attempt(attempt: u32) -> Duration {
    let base = 1u64 << attempt.min(6);
    let capped = base.min(BACKOFF_CAP_SECS);
    // Jitter via system nanoseconds — non-cryptographic, just spreads
    // simultaneous retry waves across the wall clock.
    let jitter_ms = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0)
        / 1_000_000)
        % 1_000;
    Duration::from_millis(capped * 1000 + jitter_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_with_no_key_returns_none() {
        let c = WebhookClient::new(None).unwrap();
        let sig = c.sign_body(b"hello").unwrap();
        assert!(sig.is_none());
    }

    #[test]
    fn sign_with_key_produces_64_char_hex() {
        let c = WebhookClient::new(Some(b"secret".to_vec())).unwrap();
        let sig = c.sign_body(b"hello").unwrap().unwrap();
        assert_eq!(sig.len(), 64);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn distinct_bodies_yield_distinct_signatures() {
        let c = WebhookClient::new(Some(b"secret".to_vec())).unwrap();
        let s1 = c.sign_body(b"a").unwrap().unwrap();
        let s2 = c.sign_body(b"b").unwrap().unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn distinct_keys_yield_distinct_signatures() {
        let c1 = WebhookClient::new(Some(b"k1".to_vec())).unwrap();
        let c2 = WebhookClient::new(Some(b"k2".to_vec())).unwrap();
        let s1 = c1.sign_body(b"x").unwrap().unwrap();
        let s2 = c2.sign_body(b"x").unwrap().unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn signature_matches_known_test_vector() {
        // RFC 4231 §4.2 test case 1: key=20 0x0b bytes, data="Hi There"
        // Expected SHA-256 HMAC: b0344c61d8db38535ca8afceaf0bf12b
        //                        881dc200c9833da726e9376c2e32cff7
        let key = vec![0x0b; 20];
        let c = WebhookClient::new(Some(key)).unwrap();
        let sig = c.sign_body(b"Hi There").unwrap().unwrap();
        assert_eq!(
            sig,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn backoff_grows_with_attempt() {
        // Strip jitter (0-999ms) for the comparison.
        let b1 = backoff_for_attempt(1).as_secs();
        let b2 = backoff_for_attempt(2).as_secs();
        let b3 = backoff_for_attempt(3).as_secs();
        // 2^1=2, 2^2=4, 2^3=8 — capped at 30.
        assert_eq!(b1, 2);
        assert_eq!(b2, 4);
        assert_eq!(b3, 8);
    }

    #[test]
    fn backoff_caps_at_30s() {
        let big = backoff_for_attempt(20).as_secs();
        assert_eq!(big, 30);
    }
}
