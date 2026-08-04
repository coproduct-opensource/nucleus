//! Streaming Article 12 records to the host as they are produced.
//!
//! # Why a channel and not a shared file
//!
//! A log the pod writes and the host reads *later* can be rewritten in between:
//! the host ends up attesting a head the pod reported, not one it observed. The
//! standard answer in the secure-logging literature is to get each record to a
//! collector at the moment it is produced — the collector already holds record N
//! when the writer tries to delete it, so truncation stops being possible rather
//! than merely detectable.
//!
//! Forward-secure sequential aggregate signatures (Ma & Tsudik, FssAgg) solve
//! the same problem *without* a reachable collector, by erasing the key for each
//! epoch so past entries cannot be forged after compromise. That machinery earns
//! its complexity on unattended devices. Nucleus has a collector — the host —
//! and unlike the confidential-VM setting the host is the trusted party here, so
//! streaming is both simpler and stronger. FssAgg remains the answer if the log
//! ever has to survive on a pod with no host to talk to.
//!
//! # Not fire-and-forget, unlike the audit webhook
//!
//! `AuditLog`'s webhook spawns and warns on failure. For Article 12 that is the
//! wrong trade: a record that silently fails to arrive is precisely the gap this
//! design exists to close. When shipping fails or falls behind, the shipper
//! latches **degraded**, and `Art12Sink::preflight` then refuses the next
//! operation — the same fail-closed rule the local log already follows.
//!
//! Backpressure is treated as failure for the same reason. A full queue means
//! records are being produced faster than they can be witnessed; continuing
//! would mean executing operations whose evidence is only in a place the pod
//! controls.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use hmac::{digest::KeyInit, Hmac, Mac};
use sha2::Sha256;

/// How many records may be in flight before the shipper calls it a failure.
///
/// Small on purpose. A deep queue converts "the host is not hearing us" into
/// "the host is not hearing us yet", which is the same state with a comforting
/// name — and every record in the queue is one whose only copy is pod-side.
const QUEUE_DEPTH: usize = 64;

/// Ships Article 12 records to the host as they are produced.
pub(crate) struct Art12Shipper {
    tx: tokio::sync::mpsc::Sender<String>,
    degraded: Arc<AtomicBool>,
    unshipped: Arc<AtomicU64>,
}

impl Art12Shipper {
    /// Start the shipper and its background sender.
    ///
    /// `url` is operator-configured and points at the host. It is not agent
    /// egress: nothing the agent does can influence it, and the mediation gate
    /// exempts this path for the same reason it exempts the audit webhook.
    pub(crate) fn start(url: String, secret: Vec<u8>, client: reqwest::Client) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(QUEUE_DEPTH);
        let degraded = Arc::new(AtomicBool::new(false));
        let unshipped = Arc::new(AtomicU64::new(0));

        let flag = degraded.clone();
        let missed = unshipped.clone();
        tokio::spawn(async move {
            while let Some(line) = rx.recv().await {
                let sig = {
                    let mut mac =
                        Hmac::<Sha256>::new_from_slice(&secret).expect("hmac accepts any key");
                    mac.update(line.as_bytes());
                    hex::encode(mac.finalize().into_bytes())
                };
                let sent = client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .header("X-Nucleus-Signature", &sig)
                    .body(line)
                    .send() // net-infra: Article 12 evidence channel (operator-configured host URL — not agent egress)
                    .await;

                let ok = match sent {
                    Ok(r) if r.status().is_success() => true,
                    Ok(r) => {
                        tracing::error!(status = %r.status(), "host refused an Article 12 record");
                        false
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "could not ship an Article 12 record");
                        false
                    }
                };
                if !ok {
                    // Latched, not counted-and-continued: after this the next
                    // preflight refuses, so the gap is bounded by the records
                    // already lost rather than growing for the rest of the run.
                    missed.fetch_add(1, Ordering::AcqRel);
                    flag.store(true, Ordering::Release);
                }
            }
        });

        Self {
            tx,
            degraded,
            unshipped,
        }
    }

    /// Hand a record to the shipper.
    ///
    /// Never blocks. A full queue latches degraded rather than waiting: blocking
    /// here would stall the decision path, and dropping silently would produce
    /// exactly the invisible gap this exists to prevent.
    pub(crate) fn submit(&self, line: String) {
        if self.tx.try_send(line).is_err() {
            self.unshipped.fetch_add(1, Ordering::AcqRel);
            self.degraded.store(true, Ordering::Release);
            tracing::error!(
                "Article 12 evidence channel is backed up; records are not reaching the host"
            );
        }
    }

    /// Build from the CLI arguments, or `None` when no host URL is configured.
    ///
    /// Here rather than in `main`, so the secret choice and the client setup sit
    /// beside the reasoning that governs them — and so main.rs stays under its
    /// line ratchet.
    pub(crate) fn from_args(
        url: Option<&String>,
        audit_secret: Option<&str>,
        session_id: &str,
    ) -> Option<Arc<Self>> {
        let url = url?;
        let secret = audit_secret.map_or_else(
            || format!("art12:{session_id}").into_bytes(),
            |s| s.as_bytes().to_vec(),
        );
        Some(Arc::new(Self::start(
            url.clone(),
            secret,
            reqwest::Client::new(),
        )))
    }

    pub(crate) fn is_degraded(&self) -> bool {
        self.degraded.load(Ordering::Acquire)
    }

    pub(crate) fn unshipped(&self) -> u64 {
        self.unshipped.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `reqwest::Client::new()` panics without a rustls provider. Production
    /// installs one at startup (main.rs); a test process has to do it itself,
    /// and `install_default` is idempotent-ish so the `ok()` is deliberate.
    fn client() -> reqwest::Client {
        let _ = rustls::crypto::ring::default_provider().install_default();
        reqwest::Client::new()
    }

    /// A shipper pointed at nothing reachable must latch degraded rather than
    /// warn and carry on. This is the difference from the audit webhook, and it
    /// is the whole reason the type exists.
    #[tokio::test]
    async fn a_failed_ship_latches_degraded() {
        // 127.0.0.1:1 refuses immediately, so this does not depend on a timeout.
        let s = Art12Shipper::start(
            "http://127.0.0.1:1/v1/art12".to_string(),
            b"k".to_vec(),
            client(),
        );
        assert!(
            !s.is_degraded(),
            "a fresh shipper must be healthy, or the assertion below proves nothing"
        );

        s.submit("{}".to_string());
        for _ in 0..200 {
            if s.is_degraded() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            s.is_degraded(),
            "a record the host never received must latch degraded, not pass quietly"
        );
        assert!(s.unshipped() >= 1, "and the loss must be counted");
    }

    /// **Backpressure is failure, not patience.** A queue that fills means
    /// records are being produced faster than the host can witness them, and
    /// every queued record is one whose only copy is pod-side.
    #[tokio::test]
    async fn a_full_queue_latches_degraded_rather_than_blocking() {
        let s = Art12Shipper::start(
            "http://127.0.0.1:1/v1/art12".to_string(),
            b"k".to_vec(),
            client(),
        );
        // Submit well past the queue depth without awaiting the drain.
        for i in 0..(QUEUE_DEPTH * 4) {
            s.submit(format!("{{\"n\":{i}}}"));
        }
        assert!(
            s.is_degraded(),
            "overrunning the queue must be visible, never a silent drop"
        );
    }
}
