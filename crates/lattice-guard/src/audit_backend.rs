//! Pluggable audit backends for persistent storage.
//!
//! The default [`AuditLog`] keeps entries in memory. This module provides
//! a trait for plugging in persistent backends and a file-based JSONL
//! implementation with HMAC integrity.
//!
//! # File Backend Format
//!
//! Each line in the JSONL file is a JSON object containing the serialized
//! [`AuditEntry`] plus an `hmac` field computed over the line content:
//!
//! ```text
//! {"entry":{...},"hmac":"<hex-encoded HMAC-SHA256>"}
//! ```

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::audit::AuditEntry;

type HmacSha256 = Hmac<Sha256>;

/// Trait for audit log backends.
///
/// Implementations must be safe for concurrent use (the AuditLog holds
/// a lock around calls to `append`).
pub trait AuditBackend: Send + Sync + std::fmt::Debug {
    /// Append an entry to the backend.
    ///
    /// Called under the AuditLog write lock, so implementations do not
    /// need their own synchronization.
    fn append(&mut self, entry: &AuditEntry) -> Result<(), AuditBackendError>;

    /// Load all entries from the backend (for recovery/startup).
    fn load_all(&self) -> Result<Vec<AuditEntry>, AuditBackendError>;

    /// Return the number of persisted entries.
    fn count(&self) -> Result<usize, AuditBackendError>;
}

/// Errors from audit backends.
#[derive(Debug)]
pub enum AuditBackendError {
    /// I/O error writing or reading the backend.
    Io(std::io::Error),
    /// Serialization error.
    Serialization(String),
    /// HMAC verification failed on a loaded entry.
    IntegrityViolation {
        /// Line number (1-indexed) where the violation occurred.
        line: usize,
        /// Description of what went wrong.
        message: String,
    },
}

impl std::fmt::Display for AuditBackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "audit backend I/O error: {}", e),
            Self::Serialization(msg) => write!(f, "audit backend serialization error: {}", msg),
            Self::IntegrityViolation { line, message } => {
                write!(
                    f,
                    "audit backend integrity violation at line {}: {}",
                    line, message
                )
            }
        }
    }
}

impl std::error::Error for AuditBackendError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for AuditBackendError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// JSONL line format: entry JSON + HMAC.
#[derive(serde::Serialize, serde::Deserialize)]
struct SignedLine {
    entry: serde_json::Value,
    hmac: String,
}

/// File-backed audit backend using append-only JSONL with HMAC-SHA256 signatures.
///
/// Each line is a JSON object with the serialized `AuditEntry` and an HMAC
/// computed with a shared secret. This provides:
///
/// - **Persistence**: Entries survive process restarts
/// - **Integrity**: HMAC detects tampering of individual lines
/// - **Chain integrity**: `prev_hash` in each `AuditEntry` links entries
/// - **Append-only**: File is opened in append mode; no truncation
///
/// The HMAC secret should be kept separate from the audit log file.
#[derive(Debug)]
pub struct FileAuditBackend {
    path: PathBuf,
    secret: Vec<u8>,
    /// Open file handle for appending (None until first write).
    writer: Option<File>,
}

impl FileAuditBackend {
    /// Create a new file-backed audit backend.
    ///
    /// The file is created if it doesn't exist. Writes are appended.
    /// The `secret` is used for HMAC-SHA256 signatures on each line.
    pub fn new(path: impl Into<PathBuf>, secret: impl Into<Vec<u8>>) -> Self {
        Self {
            path: path.into(),
            secret: secret.into(),
            writer: None,
        }
    }

    /// Open or re-open the file for appending.
    fn ensure_writer(&mut self) -> Result<&mut File, AuditBackendError> {
        if self.writer.is_none() {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            self.writer = Some(file);
        }
        Ok(self.writer.as_mut().unwrap())
    }

    /// Compute HMAC-SHA256 over a message.
    fn hmac_hex(&self, message: &[u8]) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC key length is always valid");
        mac.update(message);
        hex::encode(mac.finalize().into_bytes())
    }

    /// Verify an HMAC-SHA256 signature.
    fn verify_hmac(&self, message: &[u8], expected_hex: &str) -> bool {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC key length is always valid");
        mac.update(message);
        let expected = match hex::decode(expected_hex) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        mac.verify_slice(&expected).is_ok()
    }
}

impl AuditBackend for FileAuditBackend {
    fn append(&mut self, entry: &AuditEntry) -> Result<(), AuditBackendError> {
        let entry_json = serde_json::to_value(entry)
            .map_err(|e| AuditBackendError::Serialization(e.to_string()))?;
        let entry_str = serde_json::to_string(&entry_json)
            .map_err(|e| AuditBackendError::Serialization(e.to_string()))?;

        let hmac = self.hmac_hex(entry_str.as_bytes());

        let line = SignedLine {
            entry: entry_json,
            hmac,
        };
        let line_str = serde_json::to_string(&line)
            .map_err(|e| AuditBackendError::Serialization(e.to_string()))?;

        let writer = self.ensure_writer()?;
        writeln!(writer, "{}", line_str)?;
        writer.flush()?;

        Ok(())
    }

    fn load_all(&self) -> Result<Vec<AuditEntry>, AuditBackendError> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();

        for (idx, line) in reader.lines().enumerate() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let line_no = idx + 1;
            let signed: SignedLine =
                serde_json::from_str(line).map_err(|e| AuditBackendError::IntegrityViolation {
                    line: line_no,
                    message: format!("invalid JSON: {}", e),
                })?;

            // Verify HMAC
            let entry_str = serde_json::to_string(&signed.entry)
                .map_err(|e| AuditBackendError::Serialization(e.to_string()))?;
            if !self.verify_hmac(entry_str.as_bytes(), &signed.hmac) {
                return Err(AuditBackendError::IntegrityViolation {
                    line: line_no,
                    message: "HMAC verification failed".to_string(),
                });
            }

            let entry: AuditEntry = serde_json::from_value(signed.entry).map_err(|e| {
                AuditBackendError::IntegrityViolation {
                    line: line_no,
                    message: format!("invalid AuditEntry: {}", e),
                }
            })?;

            entries.push(entry);
        }

        Ok(entries)
    }

    fn count(&self) -> Result<usize, AuditBackendError> {
        if !self.path.exists() {
            return Ok(0);
        }
        let file = File::open(&self.path)?;
        let reader = BufReader::new(file);
        Ok(reader
            .lines()
            .filter(|l| l.as_ref().is_ok_and(|s| !s.trim().is_empty()))
            .count())
    }
}

/// Webhook audit backend that POSTs each entry as JSON with HMAC-SHA256 signature.
///
/// Delivery is fire-and-forget via `tokio::spawn`. The backend never blocks the
/// caller — if the webhook is down, entries are logged to stderr and dropped.
///
/// The `X-Nucleus-Signature` header carries `HMAC-SHA256(body, secret)` for SIEM
/// receivers to verify authenticity.
#[cfg(feature = "webhook")]
#[derive(Debug)]
pub struct WebhookAuditBackend {
    url: String,
    client: reqwest::Client,
    secret: Vec<u8>,
}

#[cfg(feature = "webhook")]
impl WebhookAuditBackend {
    /// Create a new webhook backend.
    ///
    /// `url` is the SIEM/alerting endpoint. `secret` is used for HMAC signing.
    pub fn new(url: impl Into<String>, secret: impl Into<Vec<u8>>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to build webhook HTTP client");
        Self {
            url: url.into(),
            client,
            secret: secret.into(),
        }
    }

    fn hmac_hex(&self, message: &[u8]) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("HMAC key length is always valid");
        mac.update(message);
        hex::encode(mac.finalize().into_bytes())
    }
}

#[cfg(feature = "webhook")]
impl AuditBackend for WebhookAuditBackend {
    fn append(&mut self, entry: &AuditEntry) -> Result<(), AuditBackendError> {
        let body = serde_json::to_string(entry)
            .map_err(|e| AuditBackendError::Serialization(e.to_string()))?;
        let signature = self.hmac_hex(body.as_bytes());

        let url = self.url.clone();
        let client = self.client.clone();
        tokio::spawn(async move {
            let result = client
                .post(&url)
                .header("Content-Type", "application/json")
                .header("X-Nucleus-Signature", &signature)
                .body(body)
                .send()
                .await;
            if let Err(e) = result {
                eprintln!("audit webhook delivery failed: {e}");
            }
        });
        Ok(())
    }

    fn load_all(&self) -> Result<Vec<AuditEntry>, AuditBackendError> {
        // Webhook is write-only; cannot recover entries from a SIEM.
        Ok(Vec::new())
    }

    fn count(&self) -> Result<usize, AuditBackendError> {
        Ok(0)
    }
}

/// Composite backend that fans out `append()` to multiple underlying backends.
///
/// Use this to write simultaneously to a file and a webhook, for example.
/// Errors from individual backends are logged but do not block other backends.
#[derive(Debug)]
pub struct CompositeAuditBackend {
    backends: Vec<Box<dyn AuditBackend>>,
}

impl CompositeAuditBackend {
    /// Create a composite from multiple backends.
    pub fn new(backends: Vec<Box<dyn AuditBackend>>) -> Self {
        Self { backends }
    }
}

impl AuditBackend for CompositeAuditBackend {
    fn append(&mut self, entry: &AuditEntry) -> Result<(), AuditBackendError> {
        let mut first_error = None;
        for backend in &mut self.backends {
            if let Err(e) = backend.append(entry) {
                eprintln!("composite backend append failed: {e}");
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn load_all(&self) -> Result<Vec<AuditEntry>, AuditBackendError> {
        for backend in &self.backends {
            let entries = backend.load_all()?;
            if !entries.is_empty() {
                return Ok(entries);
            }
        }
        Ok(Vec::new())
    }

    fn count(&self) -> Result<usize, AuditBackendError> {
        self.backends
            .iter()
            .map(|b| b.count().unwrap_or(0))
            .max()
            .ok_or_else(|| AuditBackendError::Io(std::io::Error::other("no backends")))
    }
}

/// Load entries from a file backend, recovering state for an `AuditLog`.
///
/// This is useful for restarting a service and restoring the in-memory log
/// from persisted entries.
pub fn recover_from_file(path: &Path, secret: &[u8]) -> Result<Vec<AuditEntry>, AuditBackendError> {
    let backend = FileAuditBackend::new(path, secret.to_vec());
    backend.load_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::PermissionEvent;
    use crate::capability::TrifectaRisk;

    fn make_entry(seq: u64, identity: &str) -> AuditEntry {
        let mut entry = AuditEntry::new(
            identity,
            PermissionEvent::PermissionsDeclared {
                description: format!("test entry {}", seq),
                trifecta_risk: TrifectaRisk::None,
            },
        );
        entry.sequence = seq;
        entry
    }

    #[test]
    fn test_file_backend_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let secret = b"test-secret-key-12345";

        let mut backend = FileAuditBackend::new(&path, secret.as_slice());

        let entry1 = make_entry(1, "spiffe://test/agent-1");
        let entry2 = make_entry(2, "spiffe://test/agent-2");

        backend.append(&entry1).unwrap();
        backend.append(&entry2).unwrap();

        // Load and verify
        let loaded = backend.load_all().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].sequence, 1);
        assert_eq!(loaded[0].identity, "spiffe://test/agent-1");
        assert_eq!(loaded[1].sequence, 2);
        assert_eq!(loaded[1].identity, "spiffe://test/agent-2");
    }

    #[test]
    fn test_file_backend_hmac_tamper_detection() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let secret = b"test-secret-key-12345";

        let mut backend = FileAuditBackend::new(&path, secret.as_slice());
        backend
            .append(&make_entry(1, "spiffe://test/agent"))
            .unwrap();

        // Tamper with the file
        let contents = std::fs::read_to_string(&path).unwrap();
        let tampered = contents.replace("agent", "TAMPERED");
        std::fs::write(&path, tampered).unwrap();

        // Load should fail
        let result = backend.load_all();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, AuditBackendError::IntegrityViolation { .. }));
    }

    #[test]
    fn test_file_backend_empty_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let backend = FileAuditBackend::new(&path, b"secret".as_slice());

        // Non-existent file returns empty
        let entries = backend.load_all().unwrap();
        assert!(entries.is_empty());
        assert_eq!(backend.count().unwrap(), 0);
    }

    #[test]
    fn test_file_backend_wrong_secret_fails() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");

        // Write with one secret
        let mut writer = FileAuditBackend::new(&path, b"secret-A".as_slice());
        writer.append(&make_entry(1, "spiffe://test/a")).unwrap();

        // Read with different secret
        let reader = FileAuditBackend::new(&path, b"secret-B".as_slice());
        let result = reader.load_all();
        assert!(result.is_err());
    }

    #[test]
    fn test_file_backend_count() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut backend = FileAuditBackend::new(&path, b"secret".as_slice());

        backend.append(&make_entry(1, "a")).unwrap();
        backend.append(&make_entry(2, "b")).unwrap();
        backend.append(&make_entry(3, "c")).unwrap();

        assert_eq!(backend.count().unwrap(), 3);
    }

    #[test]
    fn test_recover_from_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let secret = b"recovery-secret";

        let mut backend = FileAuditBackend::new(&path, secret.as_slice());
        backend
            .append(&make_entry(1, "spiffe://test/agent"))
            .unwrap();
        backend
            .append(&make_entry(2, "spiffe://test/agent"))
            .unwrap();

        // Recover via convenience function
        let entries = recover_from_file(&path, secret).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_composite_backend_fans_out() {
        let dir = tempfile::TempDir::new().unwrap();
        let path_a = dir.path().join("audit_a.jsonl");
        let path_b = dir.path().join("audit_b.jsonl");

        let backend_a = Box::new(FileAuditBackend::new(&path_a, b"secret".as_slice()));
        let backend_b = Box::new(FileAuditBackend::new(&path_b, b"secret".as_slice()));
        let mut composite = CompositeAuditBackend::new(vec![backend_a, backend_b]);

        composite.append(&make_entry(1, "agent-1")).unwrap();
        composite.append(&make_entry(2, "agent-2")).unwrap();

        // Both files should have 2 entries
        let reader_a = FileAuditBackend::new(&path_a, b"secret".as_slice());
        let reader_b = FileAuditBackend::new(&path_b, b"secret".as_slice());
        assert_eq!(reader_a.count().unwrap(), 2);
        assert_eq!(reader_b.count().unwrap(), 2);

        // load_all returns from first backend with entries
        let loaded = composite.load_all().unwrap();
        assert_eq!(loaded.len(), 2);

        // count returns max
        assert_eq!(composite.count().unwrap(), 2);
    }

    #[test]
    fn test_composite_backend_empty() {
        let composite = CompositeAuditBackend::new(vec![]);
        assert!(composite.load_all().unwrap().is_empty());
        assert!(composite.count().is_err()); // no backends
    }

    #[test]
    fn test_audit_log_with_file_backend() {
        use crate::audit::{AuditLog, RetentionPolicy};
        use crate::capability::Operation;
        use crate::CapabilityLevel;

        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("audit.jsonl");
        let secret = b"integration-test-secret";

        // Create AuditLog with file backend
        let backend = Box::new(FileAuditBackend::new(&path, secret.as_slice()));
        let log = AuditLog::with_backend(RetentionPolicy::unlimited(), backend);

        // Record entries through the AuditLog API
        log.record(AuditEntry::new(
            "spiffe://test/agent-1",
            PermissionEvent::PermissionsDeclared {
                description: "test".to_string(),
                trifecta_risk: TrifectaRisk::None,
            },
        ));
        log.record(AuditEntry::new(
            "spiffe://test/agent-1",
            PermissionEvent::OperationRequested {
                operation: Operation::ReadFiles,
                declared_level: CapabilityLevel::Always,
                requested_level: CapabilityLevel::Always,
            },
        ));

        // Verify chain in memory
        assert!(log.verify_chain().is_ok());
        assert_eq!(log.total_entries(), 2);

        // Verify entries were persisted to file
        let file_backend = FileAuditBackend::new(&path, secret.as_slice());
        let persisted = file_backend.load_all().unwrap();
        assert_eq!(persisted.len(), 2);
        assert_eq!(persisted[0].identity, "spiffe://test/agent-1");
        assert!(persisted[0].prev_hash.is_none()); // First entry
        assert!(persisted[1].prev_hash.is_some()); // Chained

        // Recover into a new AuditLog and verify chain continuity
        let backend2 = Box::new(FileAuditBackend::new(&path, secret.as_slice()));
        let recovered =
            AuditLog::recover_from_backend(RetentionPolicy::unlimited(), backend2).unwrap();
        assert_eq!(recovered.total_entries(), 2);
        assert!(recovered.verify_chain().is_ok());

        // New entries should chain from the recovered tail
        recovered.record(AuditEntry::new(
            "spiffe://test/agent-1",
            PermissionEvent::PermissionsDeclared {
                description: "after recovery".to_string(),
                trifecta_risk: TrifectaRisk::Low,
            },
        ));
        assert_eq!(recovered.total_entries(), 3);
        assert!(recovered.verify_chain().is_ok());
    }
}
