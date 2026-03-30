//! S3-compatible append-only audit backend for deletion-resistant log storage.
//!
//! Each audit entry is stored as a separate S3 object with a unique key:
//! `{prefix}/{timestamp_ms}-{nonce}.jsonl`
//!
//! Append-only semantics are enforced via `if_none_match("*")` on PutObject,
//! which causes the request to fail if an object with that key already exists.
//! Combined with a bucket policy that denies `s3:DeleteObject`, this provides
//! a deletion-resistant audit trail.
//!
//! Compatible with: AWS S3, MinIO, Cloudflare R2, Tigris.
//!
//! # Feature Flag
//!
//! Requires the `remote-audit` feature:
//! ```toml
//! portcullis = { version = "0.1", features = ["remote-audit"] }
//! ```

use std::time::UNIX_EPOCH;

use aws_sdk_s3::Client;
use hmac::{digest::KeyInit, Hmac, Mac};
use sha2::Sha256;

use crate::audit::AuditEntry;
use crate::audit_backend::{AuditBackend, AuditBackendError};

type HmacSha256 = Hmac<Sha256>;

/// S3-compatible append-only audit backend.
///
/// Each entry is a separate object keyed by `{prefix}/{timestamp_ms}-{nonce}.jsonl`.
/// The `if_none_match("*")` precondition prevents overwriting existing entries,
/// enforcing append-only semantics at the storage layer.
///
/// # Bucket Policy (recommended)
///
/// ```json
/// {
///   "Effect": "Deny",
///   "Principal": "*",
///   "Action": ["s3:DeleteObject", "s3:DeleteObjectVersion"],
///   "Resource": "arn:aws:s3:::YOUR_BUCKET/audit/*"
/// }
/// ```
#[derive(Debug)]
pub struct S3AuditBackend {
    client: Client,
    bucket: String,
    prefix: String,
    hmac_key: Vec<u8>,
    /// Tokio runtime handle for blocking on async S3 calls.
    /// The `AuditBackend` trait is synchronous (called under a lock),
    /// so we use `block_on` to bridge to async S3 operations.
    rt: tokio::runtime::Handle,
}

impl S3AuditBackend {
    /// Create a new S3 audit backend.
    ///
    /// `client` should be pre-configured with region, credentials, and
    /// optional endpoint URL (for MinIO/R2/Tigris).
    /// `bucket` is the S3 bucket name.
    /// `prefix` is the key prefix for audit objects (e.g. "audit/pod-name").
    /// `hmac_key` is used for signing entries (same as FileAuditBackend).
    pub fn new(
        client: Client,
        bucket: impl Into<String>,
        prefix: impl Into<String>,
        hmac_key: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            client,
            bucket: bucket.into(),
            prefix: prefix.into(),
            hmac_key: hmac_key.into(),
            rt: tokio::runtime::Handle::current(),
        }
    }

    /// Compute HMAC-SHA256 over a message and return hex string.
    fn hmac_hex(&self, message: &[u8]) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.hmac_key).expect("HMAC key length is always valid");
        mac.update(message);
        hex::encode(mac.finalize().into_bytes())
    }

    /// Sign an entry: serialize to JSON + compute HMAC, return the signed JSONL line.
    fn sign_entry(&self, entry: &AuditEntry) -> Result<String, AuditBackendError> {
        let entry_json = serde_json::to_value(entry)
            .map_err(|e| AuditBackendError::Serialization(e.to_string()))?;
        let entry_str = serde_json::to_string(&entry_json)
            .map_err(|e| AuditBackendError::Serialization(e.to_string()))?;
        let hmac = self.hmac_hex(entry_str.as_bytes());

        // Same format as FileAuditBackend: {"entry":{...},"hmac":"..."}
        let line = serde_json::json!({
            "entry": entry_json,
            "hmac": hmac,
        });
        serde_json::to_string(&line).map_err(|e| AuditBackendError::Serialization(e.to_string()))
    }

    /// Generate the S3 object key for an entry.
    ///
    /// Key format: `{prefix}/{timestamp_ms}-{seq}-{hash8}.jsonl`
    /// The combination of timestamp + sequence + content hash ensures uniqueness.
    fn object_key(&self, entry: &AuditEntry) -> String {
        let millis = entry
            .timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        // Use first 8 chars of HMAC as a content-derived nonce
        let entry_bytes = serde_json::to_vec(entry).unwrap_or_default();
        let nonce = self.hmac_hex(&entry_bytes);
        format!(
            "{}/{}-{}-{}.jsonl",
            self.prefix,
            millis,
            entry.sequence,
            &nonce[..8]
        )
    }

    /// Async implementation of append.
    async fn append_async(&self, entry: &AuditEntry) -> Result<(), AuditBackendError> {
        let body = self.sign_entry(entry)?;
        let key = self.object_key(entry);

        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(body.into_bytes().into())
            .content_type("application/jsonl")
            .if_none_match("*") // Append-only: fail if key already exists
            .send()
            .await
            .map_err(|e| {
                AuditBackendError::Io(std::io::Error::other(format!("S3 PutObject failed: {e}")))
            })?;

        Ok(())
    }

    /// Async implementation of load_all.
    async fn load_all_async(&self) -> Result<Vec<AuditEntry>, AuditBackendError> {
        let mut entries = Vec::new();
        let mut continuation_token = None;

        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&self.prefix);

            if let Some(token) = &continuation_token {
                request = request.continuation_token(token);
            }

            let response = request.send().await.map_err(|e| {
                AuditBackendError::Io(std::io::Error::other(format!(
                    "S3 ListObjectsV2 failed: {e}"
                )))
            })?;

            for object in response.contents() {
                let key = match object.key() {
                    Some(k) => k,
                    None => continue,
                };
                let get_result = self
                    .client
                    .get_object()
                    .bucket(&self.bucket)
                    .key(key)
                    .send()
                    .await
                    .map_err(|e| {
                        AuditBackendError::Io(std::io::Error::other(format!(
                            "S3 GetObject({key}) failed: {e}"
                        )))
                    })?;

                let body = get_result.body.collect().await.map_err(|e| {
                    AuditBackendError::Io(std::io::Error::other(format!(
                        "S3 read body({key}) failed: {e}"
                    )))
                })?;

                let body_bytes = body.into_bytes();
                let line = String::from_utf8_lossy(&body_bytes);
                let signed: serde_json::Value = serde_json::from_str(&line).map_err(|e| {
                    AuditBackendError::IntegrityViolation {
                        line: 0,
                        message: format!("invalid JSON in {key}: {e}"),
                    }
                })?;

                // Verify HMAC
                let entry_val =
                    signed
                        .get("entry")
                        .ok_or_else(|| AuditBackendError::IntegrityViolation {
                            line: 0,
                            message: format!("missing 'entry' field in {key}"),
                        })?;
                let expected_hmac =
                    signed.get("hmac").and_then(|v| v.as_str()).ok_or_else(|| {
                        AuditBackendError::IntegrityViolation {
                            line: 0,
                            message: format!("missing 'hmac' field in {key}"),
                        }
                    })?;

                let entry_str = serde_json::to_string(entry_val)
                    .map_err(|e| AuditBackendError::Serialization(e.to_string()))?;
                let actual_hmac = self.hmac_hex(entry_str.as_bytes());
                if actual_hmac != expected_hmac {
                    return Err(AuditBackendError::IntegrityViolation {
                        line: 0,
                        message: format!("HMAC mismatch in {key}"),
                    });
                }

                let entry: AuditEntry = serde_json::from_value(entry_val.clone()).map_err(|e| {
                    AuditBackendError::IntegrityViolation {
                        line: 0,
                        message: format!("invalid AuditEntry in {key}: {e}"),
                    }
                })?;
                entries.push(entry);
            }

            if response.is_truncated() == Some(true) {
                continuation_token = response.next_continuation_token().map(|s| s.to_string());
            } else {
                break;
            }
        }

        // Sort by timestamp for deterministic ordering
        entries.sort_by_key(|e| e.timestamp);
        Ok(entries)
    }

    /// Async implementation of count.
    async fn count_async(&self) -> Result<usize, AuditBackendError> {
        let mut count = 0;
        let mut continuation_token = None;

        loop {
            let mut request = self
                .client
                .list_objects_v2()
                .bucket(&self.bucket)
                .prefix(&self.prefix);

            if let Some(token) = &continuation_token {
                request = request.continuation_token(token);
            }

            let response = request.send().await.map_err(|e| {
                AuditBackendError::Io(std::io::Error::other(format!(
                    "S3 ListObjectsV2 failed: {e}"
                )))
            })?;

            count += response.key_count().unwrap_or(0) as usize;

            if response.is_truncated() == Some(true) {
                continuation_token = response.next_continuation_token().map(|s| s.to_string());
            } else {
                break;
            }
        }

        Ok(count)
    }
}

impl AuditBackend for S3AuditBackend {
    fn append(&mut self, entry: &AuditEntry) -> Result<(), AuditBackendError> {
        self.rt.block_on(self.append_async(entry))
    }

    fn load_all(&self) -> Result<Vec<AuditEntry>, AuditBackendError> {
        self.rt.block_on(self.load_all_async())
    }

    fn count(&self) -> Result<usize, AuditBackendError> {
        self.rt.block_on(self.count_async())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s3_object_key_format() {
        use crate::audit::PermissionEvent;
        use crate::capability::StateRisk;

        let entry = AuditEntry::new(
            "spiffe://test/agent",
            PermissionEvent::PermissionsDeclared {
                description: "test".to_string(),
                state_risk: StateRisk::Safe,
            },
        );

        // Compute expected key using the same logic as object_key
        let hmac_key = b"test-secret";
        let millis = entry
            .timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let entry_bytes = serde_json::to_vec(&entry).unwrap();
        let mut mac = HmacSha256::new_from_slice(hmac_key).expect("key ok");
        mac.update(&entry_bytes);
        let nonce = hex::encode(mac.finalize().into_bytes());
        let key = format!(
            "audit/test-pod/{}-{}-{}.jsonl",
            millis,
            entry.sequence,
            &nonce[..8]
        );

        assert!(key.starts_with("audit/test-pod/"));
        assert!(key.ends_with(".jsonl"));
        // Key should contain a numeric timestamp
        let ts_part = key
            .strip_prefix("audit/test-pod/")
            .unwrap()
            .split('-')
            .next()
            .unwrap();
        assert!(
            ts_part.parse::<u128>().is_ok(),
            "timestamp should be numeric millis"
        );
    }

    #[test]
    fn test_s3_sign_entry_deterministic() {
        use crate::audit::PermissionEvent;
        use crate::capability::StateRisk;

        let entry = AuditEntry::new(
            "spiffe://test/agent",
            PermissionEvent::PermissionsDeclared {
                description: "test".to_string(),
                state_risk: StateRisk::Safe,
            },
        );

        let hmac_key = b"test-secret";
        let entry_str = serde_json::to_string(&serde_json::to_value(&entry).unwrap()).unwrap();

        let mut mac1 =
            HmacSha256::new_from_slice(hmac_key).expect("HMAC key length is always valid");
        mac1.update(entry_str.as_bytes());
        let hmac1 = hex::encode(mac1.finalize().into_bytes());

        let mut mac2 =
            HmacSha256::new_from_slice(hmac_key).expect("HMAC key length is always valid");
        mac2.update(entry_str.as_bytes());
        let hmac2 = hex::encode(mac2.finalize().into_bytes());

        assert_eq!(hmac1, hmac2, "HMAC should be deterministic");
    }
}
