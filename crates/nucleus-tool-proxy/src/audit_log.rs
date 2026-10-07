//! The tool-proxy's hash-chained audit log, signed by a key the workload
//! cannot reach (#3293).
//!
//! # Which key signs, and why the workload cannot reach it
//!
//! [`AuditSigner`] is an Ed25519 key this process generates at startup from
//! the OS RNG. It exists only in this process's memory: it is never written to
//! disk, never put in an environment variable, and never sent anywhere. Only
//! its public half leaves the process. Wherever the runtime can drop one, the
//! workload runs under a uid distinct from this process's (`workload::RunsAs::Dropped`:
//! the Firecracker guest, and a container whose proxy runs as root), so it cannot
//! read this process's memory. On the bare host tier (`--unsandboxed`) the
//! workload inherits this process's uid (`RunsAs::Inherited`), a tier that
//! claims no isolation from it; there the signature still keeps out every
//! party that is not this uid.
//!
//! The record format, and the preimage both this writer and
//! `nucleus-audit verify` use, is declared once in
//! [`nucleus_spec::tool_proxy_audit`].
//!
//! # How a verifier learns the key
//!
//! - Every record names its signer, inside the signed bytes and so inside the
//!   chain hash. The node signs the chain's tail hash into the pod receipt
//!   (`audit_tail_hash`), so the receipt pins the signer:
//!   `nucleus-audit verify --log … --tail-hash <receipt.audit_tail_hash>`.
//! - The proxy prints `NUCLEUS-AUDIT-SIGNER <hex>` on its console at boot,
//!   before it serves anything, and the host keeps that console:
//!   `nucleus-audit verify --log … --signer-pubkey <hex>`.
//!
//! # What replaced what
//!
//! Records used to carry `HMAC(audit secret, …)`, and the audit secret
//! defaulted to the auth secret, which is EMPTY on vsock and on the
//! peer-verified socket. Anyone could compute that MAC. There is no MAC path
//! left here to fall back to, so no configuration can produce one, empty key or
//! not: a proxy that cannot generate its signing key refuses to start.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey};
use nucleus_spec::tool_proxy_audit::{AuditEvent, AuditRecord};
use tracing::info;

use crate::{ApiError, Args};

/// The key this proxy signs its audit records with. Not `Clone`, no
/// `Default`, no constructor from bytes outside tests: the only way to get one
/// in production is [`AuditSigner::generate`].
pub(crate) struct AuditSigner {
    key: SigningKey,
    public_hex: String,
}

impl std::fmt::Debug for AuditSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the key.
        f.debug_struct("AuditSigner")
            .field("public", &self.public_hex)
            .finish_non_exhaustive()
    }
}

impl AuditSigner {
    /// A fresh key from the OS RNG.
    ///
    /// # Errors
    /// When the RNG fails. The caller refuses to start: a log nobody can
    /// authenticate must not be written as though it were authenticated.
    pub(crate) fn generate() -> Result<Self, ApiError> {
        use ring::rand::SecureRandom;
        let mut seed = [0u8; 32];
        ring::rand::SystemRandom::new()
            .fill(&mut seed)
            .map_err(|_| {
                ApiError::Spec(
                    "refusing to start: the OS RNG could not produce an audit signing key, \
                     and an unsigned audit log would read as authenticated (#3293)"
                        .to_string(),
                )
            })?;
        Ok(Self::from_seed(seed))
    }

    fn from_seed(seed: [u8; 32]) -> Self {
        let key = SigningKey::from_bytes(&seed);
        let public_hex = hex::encode(key.verifying_key().to_bytes());
        Self { key, public_hex }
    }

    /// The public half, hex-encoded: what every record names as its signer.
    pub(crate) fn public_hex(&self) -> &str {
        &self.public_hex
    }

    fn sign(&self, bytes: &[u8]) -> String {
        hex::encode(self.key.sign(bytes).to_bytes())
    }

    #[cfg(test)]
    pub(crate) fn for_test(seed: u8) -> Self {
        Self::from_seed([seed; 32])
    }
}

pub(crate) struct AuditLog {
    pub(crate) path: PathBuf,
    signer: AuditSigner,
    last_hash: Mutex<String>,
    /// Serialises extending the chain with writing the entry. See `log`.
    append_order: tokio::sync::Mutex<()>,
    entry_count: std::sync::atomic::AtomicU64,
    webhook: Option<WebhookSink>,
    /// Optional drand client for cryptographic time anchoring.
    pub(crate) drand_client: Option<Arc<nucleus_client::drand::DrandClient>>,
    /// Optional S3-compatible sink for deletion-resistant audit storage.
    #[cfg(feature = "remote-audit")]
    s3_sink: Option<Arc<S3Sink>>,
}

struct WebhookSink {
    url: String,
    client: reqwest::Client,
}

/// S3-compatible append-only audit sink.
///
/// Each audit entry is stored as a separate S3 object. The `if_none_match("*")`
/// precondition prevents overwriting existing entries. Combined with a bucket
/// policy that denies `s3:DeleteObject`, this provides a deletion-resistant
/// audit trail that a compromised pod cannot erase.
#[cfg(feature = "remote-audit")]
struct S3Sink {
    client: aws_sdk_s3::Client,
    bucket: String,
    prefix: String,
}

#[cfg(feature = "remote-audit")]
impl S3Sink {
    /// Put a single audit line as an S3 object.
    ///
    /// Key format: `{prefix}/{timestamp_unix}-{hash_prefix}.jsonl`
    /// Uses `if_none_match("*")` for append-only semantics: S3 returns 412
    /// if an object with this key already exists.
    async fn put_entry(&self, timestamp_unix: u64, hash: &str, line: &str) {
        let hash_prefix = if hash.len() >= 8 { &hash[..8] } else { hash };
        let key = format!("{}/{}-{}.jsonl", self.prefix, timestamp_unix, hash_prefix);

        let result = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(line.as_bytes().to_vec().into())
            .content_type("application/jsonl")
            .if_none_match("*")
            .send() // net-infra: audit S3 append (aws_sdk_s3, operator sink — not agent egress)
            .await;

        if let Err(e) = result {
            tracing::warn!("failed to write audit entry to S3 (key={key}): {e}");
        }
    }
}

/// Open the audit log the CLI configured, with a freshly generated signer.
pub(crate) async fn build_audit_log(
    args: &Args,
    dns_allow: &[String],
) -> Result<Arc<AuditLog>, ApiError> {
    let path = args.audit_log.clone();

    // Ensure parent directory exists (e.g., /var/log/nucleus/ or the pod state dir).
    // Without this, the first write silently fails when the parent is missing.
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            ApiError::Spec(format!(
                "failed to create audit log directory {}: {e}",
                parent.display()
            ))
        })?;
    }

    let signer = AuditSigner::generate()?;
    // Before anything is served, on the console the host keeps: the key a
    // verifier pins without a receipt. Public half only.
    crate::console_line(&format!("NUCLEUS-AUDIT-SIGNER {}", signer.public_hex()));
    info!(signer = %signer.public_hex(), "audit log signing key generated");

    // Set up webhook sink if configured
    let webhook = if let Some(url) = args.audit_webhook.as_ref() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            // Never follow a redirect for audit records — a 3xx to another host
            // would leak the audit stream there.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| ApiError::Spec(format!("failed to build webhook client: {e}")))?;
        info!("audit webhook configured: {}", url);
        Some(WebhookSink {
            url: url.clone(),
            client,
        })
    } else {
        None
    };

    let drand_client = crate::drand_setup::build_drand_client(args, dns_allow);

    // Set up S3 sink for deletion-resistant audit storage
    #[cfg(feature = "remote-audit")]
    let s3_sink = if let Some(bucket) = args.audit_s3_bucket.as_ref() {
        let region = args.audit_s3_region.as_deref().unwrap_or("us-east-1");
        let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()));
        if let Some(endpoint) = args.audit_s3_endpoint.as_ref() {
            config_loader = config_loader.endpoint_url(endpoint);
        }
        let sdk_config = config_loader.load().await;
        let s3_client = aws_sdk_s3::Client::new(&sdk_config);
        let prefix = args
            .audit_s3_prefix
            .clone()
            .unwrap_or_else(|| "audit".to_string());
        info!(
            "S3 audit sink configured: bucket={}, prefix={}",
            bucket, prefix
        );
        Some(Arc::new(S3Sink {
            client: s3_client,
            bucket: bucket.clone(),
            prefix,
        }))
    } else {
        None
    };

    let mut log = AuditLog::open(path, signer, drand_client);
    log.webhook = webhook;
    #[cfg(feature = "remote-audit")]
    {
        log.s3_sink = s3_sink;
    }
    Ok(Arc::new(log))
}

impl AuditLog {
    /// A log at `path` that continues whatever chain is already there.
    pub(crate) fn open(
        path: PathBuf,
        signer: AuditSigner,
        drand_client: Option<Arc<nucleus_client::drand::DrandClient>>,
    ) -> Self {
        let last_hash = load_last_hash(&path).unwrap_or_default();
        Self {
            path,
            signer,
            last_hash: Mutex::new(last_hash),
            append_order: tokio::sync::Mutex::new(()),
            entry_count: std::sync::atomic::AtomicU64::new(0),
            webhook: None,
            drand_client,
            #[cfg(feature = "remote-audit")]
            s3_sink: None,
        }
    }

    /// Append `event`, signed and chained.
    pub(crate) async fn log(&self, event: AuditEvent) -> Result<(), ApiError> {
        // Fetch drand round for cryptographic time anchoring
        let mut drand_round = None;
        if let Some(ref drand) = self.drand_client {
            match drand.current_round().await {
                Ok(round) => drand_round = Some(round),
                Err(e) => {
                    tracing::warn!("failed to fetch drand round for audit: {e}");
                    // Continue without drand anchoring - don't block audit logging
                }
            }
        }

        // Held from reading the chain's tail until this entry is on disk, so the
        // file is in the order the chain was extended. The tail used to be read and
        // advanced under `last_hash` alone, released before the write, so two
        // concurrent entries could land in the opposite order to the one they were
        // hashed in — and `nucleus-audit verify` walks the file top to bottom.
        let _in_chain_order = self.append_order.lock().await;
        let record = {
            let prev_hash = self.last_hash.lock().unwrap().clone();
            let unsigned =
                event.unsigned(prev_hash, drand_round, self.signer.public_hex().to_string());
            let bytes = unsigned
                .signed_bytes()
                .map_err(|e| ApiError::Spec(format!("audit record: {e}")))?;
            let signature = self.signer.sign(&bytes);
            unsigned
                .with_signature(signature)
                .map_err(|e| ApiError::Spec(format!("audit record: {e}")))?
        };

        let line = serde_json::to_string(&record).map_err(|e| ApiError::Spec(e.to_string()))?;

        // One O_APPEND write per entry (see `nucleus_jsonl` for the tearing this
        // replaced). The tail advances only once the entry is on disk: advancing it
        // first meant a failed write left the chain naming an entry the file lacks.
        nucleus_jsonl::append_line_unsynced_async(self.path.clone(), line.clone()).await?;
        *self.last_hash.lock().unwrap() = record.hash.clone();
        self.entry_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        drop(_in_chain_order);

        // Send to webhook if configured
        if let Some(webhook) = &self.webhook {
            // Fire and forget - don't block on webhook delivery
            // In production, you'd want retry logic and a buffer
            let url = webhook.url.clone();
            let client = webhook.client.clone();
            let body = line.clone();
            let sig = record.signature.clone();

            tokio::spawn(async move {
                let result = client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .header("X-Nucleus-Signature", &sig)
                    .body(body)
                    .send() // net-infra: audit webhook (operator-configured URL — not agent egress)
                    .await;

                if let Err(e) = result {
                    tracing::warn!("failed to send audit entry to webhook: {e}");
                }
            });
        }

        // Send to S3 if configured (fire-and-forget, like webhook)
        #[cfg(feature = "remote-audit")]
        if let Some(s3) = &self.s3_sink {
            let s3 = Arc::clone(s3);
            let body = line.clone();
            let ts = record.timestamp_unix;
            let h = record.hash.clone();
            tokio::spawn(async move {
                s3.put_entry(ts, &h, &body).await;
            });
        }

        Ok(())
    }

    /// Get the current tail hash and entry count for the exit report.
    pub(crate) fn tail_hash_and_count(&self) -> (String, u64) {
        let hash = self.last_hash.lock().unwrap().clone();
        let count = self.entry_count.load(std::sync::atomic::Ordering::Relaxed);
        (hash, count)
    }
}

#[expect(
    clippy::disallowed_methods,
    reason = "#1216: reads the proxy's own audit hash chain, not agent-directed I/O"
)]
fn load_last_hash(path: &Path) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if metadata.len() == 0 {
        return None;
    }
    let read_len = metadata.len().min(8192) as usize;
    let mut file = file;
    let start = metadata.len().saturating_sub(read_len as u64);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return None;
    }
    let mut buf = vec![0u8; read_len];
    if file.read_exact(&mut buf).is_err() {
        return None;
    }
    let text = String::from_utf8_lossy(&buf);
    let line = text.lines().rev().find(|line| !line.trim().is_empty())?;
    let entry: AuditRecord = serde_json::from_str(line).ok()?;
    if entry.hash.is_empty() {
        return None;
    }
    Some(entry.hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, VerifyingKey};
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    fn event(i: usize) -> AuditEvent {
        AuditEvent {
            timestamp_unix: 1_757_000_000,
            actor: Some("test".into()),
            event: format!("event-{i}"),
            subject: "x".repeat(4096),
            result: "ok".into(),
            spiffe_id: None,
            policy_rule: None,
        }
    }

    fn records(path: &Path) -> Vec<AuditRecord> {
        std::fs::read_to_string(path)
            .expect("read")
            .lines()
            .map(|l| serde_json::from_str(l).expect("a whole record"))
            .collect()
    }

    /// Tool calls are served concurrently, and every one writes an audit entry. Each
    /// entry must land whole, and the file must be in CHAIN order — `nucleus-audit
    /// verify` walks it top to bottom requiring each `prev_hash` to be the line above's
    /// `hash`. The chain used to be extended under a lock that was released before the
    /// write, so two entries could land in the opposite order to the one they were
    /// hashed in, and the write itself was two writes (line, then newline) that
    /// concurrent entries could interleave.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_audit_entries_land_whole_and_in_chain_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.log");
        let log = Arc::new(AuditLog::open(path.clone(), AuditSigner::for_test(1), None));
        let mut tasks = Vec::new();
        for i in 0..64 {
            let log = Arc::clone(&log);
            tasks.push(tokio::spawn(async move {
                log.log(event(i)).await.expect("audit entry written");
            }));
        }
        for t in tasks {
            t.await.expect("task");
        }
        let mut prev = String::new();
        let all = records(&path);
        for (i, rec) in all.iter().enumerate() {
            assert_eq!(rec.prev_hash, prev, "line {i} is out of chain order");
            prev = rec.hash.clone();
        }
        assert_eq!(all.len(), 64, "every entry exactly once");
    }

    /// #3293, the writer half of A-19. On vsock and on the peer-verified socket
    /// the proxy holds no auth secret, and the audit MAC was keyed with that
    /// empty secret, so a party holding no key at all could recompute every
    /// record's "signature". The record must now verify under the announced
    /// public key, and the keyless MAC must not be its signature.
    #[tokio::test]
    async fn no_party_without_the_key_can_compute_a_records_signature() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.log");
        let signer = AuditSigner::for_test(9);
        let public = signer.public_hex().to_string();
        let log = AuditLog::open(path.clone(), signer, None);
        log.log(event(0)).await.expect("written");

        let rec = records(&path).pop().expect("one record");
        assert_eq!(rec.signer.as_deref(), Some(public.as_str()));

        // What a keyless party computes: the MAC under the empty key, over the
        // record's own bytes.
        let bytes = rec.signed_bytes().expect("a form");
        let mut mac = Hmac::<Sha256>::new_from_slice(b"").expect("any key length");
        mac.update(&bytes);
        assert_ne!(
            rec.signature,
            hex::encode(mac.finalize().into_bytes()),
            "the record's signature is the empty-key MAC: anyone can forge it"
        );

        let key: [u8; 32] = hex::decode(&public).unwrap().try_into().unwrap();
        let sig: [u8; 64] = hex::decode(&rec.signature).unwrap().try_into().unwrap();
        VerifyingKey::from_bytes(&key)
            .expect("key")
            .verify_strict(&bytes, &Signature::from_bytes(&sig))
            .expect("the record verifies under the key the proxy announced");
        assert_eq!(rec.chain_hash().expect("form"), rec.hash);
    }

    /// A restarted proxy continues the chain on disk under its new key.
    #[tokio::test]
    async fn a_restart_continues_the_chain_under_a_new_signer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("audit.log");
        AuditLog::open(path.clone(), AuditSigner::for_test(1), None)
            .log(event(0))
            .await
            .expect("first");
        AuditLog::open(path.clone(), AuditSigner::for_test(2), None)
            .log(event(1))
            .await
            .expect("second");
        let all = records(&path);
        assert_eq!(all[1].prev_hash, all[0].hash);
        assert_ne!(all[0].signer, all[1].signer);
    }
}
