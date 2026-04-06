#![allow(clippy::disallowed_types)] // #1216: migration pending
//! Exit report generation for execution receipts.
//!
//! Before shutdown, the tool-proxy computes a workspace content hash and
//! captures the audit chain tail, writing this as the final audit log entry.
//! The host (nucleus-node) reads this to build an `ExecutionReceipt`.

use nucleus_spec::{sha256_bytes_hex, ExitReport};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Compute a deterministic SHA-256 hash of a directory's contents.
///
/// Walks the directory recursively, computes SHA-256 of each file's contents,
/// then hashes the sorted list of `(relative_path, file_hash)` pairs.
/// This produces a reproducible hash regardless of filesystem ordering.
///
/// Skips:
/// - Hidden files/directories (starting with `.`)
/// - The `.nucleus-exit-report.json` file itself
pub async fn hash_workspace(root: &Path) -> Result<String, std::io::Error> {
    let mut entries: Vec<(String, String)> = Vec::new();
    collect_file_hashes(root, root, &mut entries).await?;
    entries.sort();

    let mut hasher = Sha256::new();
    for (path, hash) in &entries {
        hasher.update(path.as_bytes());
        hasher.update(b":");
        hasher.update(hash.as_bytes());
        hasher.update(b"\n");
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Recursively collect (relative_path, sha256_hex) for all files.
async fn collect_file_hashes(
    root: &Path,
    dir: &Path,
    entries: &mut Vec<(String, String)>,
) -> Result<(), std::io::Error> {
    let mut read_dir = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = read_dir.next_entry().await? {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Skip hidden files and the exit report itself
        if name_str.starts_with('.') {
            continue;
        }

        let path = entry.path();
        let file_type = entry.file_type().await?;

        if file_type.is_dir() {
            Box::pin(collect_file_hashes(root, &path, entries)).await?;
        } else if file_type.is_file() {
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .to_string();
            let contents = tokio::fs::read(&path).await?;
            let hash = sha256_bytes_hex(&contents);
            entries.push((relative, hash));
        }
    }
    Ok(())
}

/// Token usage statistics collected during execution.
#[derive(Debug, Clone, Default)]
pub struct TokenUsage {
    /// Input tokens consumed.
    pub input_tokens: u64,
    /// Output tokens generated.
    pub output_tokens: u64,
    /// Cache read tokens (prompt caching hits).
    pub cache_read_tokens: u64,
    /// Estimated cost in USD.
    pub cost_usd: f64,
}

/// Build an exit report from the current state.
pub fn build_exit_report(
    workspace_hash: String,
    audit_tail_hash: String,
    audit_entry_count: u64,
    token_usage: Option<TokenUsage>,
) -> ExitReport {
    let timestamp_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let usage = token_usage.unwrap_or_default();

    ExitReport {
        workspace_hash,
        audit_tail_hash,
        audit_entry_count,
        timestamp_unix,
        input_tokens: usage.input_tokens,
        output_tokens: usage.output_tokens,
        cache_read_tokens: usage.cache_read_tokens,
        cost_usd: usage.cost_usd,
        // Exposure populated by write_exit_report() after guard extraction
        observed_exposure_labels: Vec::new(),
        observed_risk_tier: String::new(),
        uninhabitable_reached: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_hash_workspace_empty() {
        let dir = TempDir::new().unwrap();
        let hash = hash_workspace(dir.path()).await.unwrap();
        assert_eq!(hash.len(), 64); // SHA-256 hex
    }

    #[tokio::test]
    async fn test_hash_workspace_deterministic() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"hello").unwrap();
        std::fs::write(dir.path().join("b.txt"), b"world").unwrap();

        let hash1 = hash_workspace(dir.path()).await.unwrap();
        let hash2 = hash_workspace(dir.path()).await.unwrap();
        assert_eq!(hash1, hash2);
    }

    #[tokio::test]
    async fn test_hash_workspace_content_sensitive() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"version1").unwrap();
        let hash1 = hash_workspace(dir.path()).await.unwrap();

        std::fs::write(dir.path().join("file.txt"), b"version2").unwrap();
        let hash2 = hash_workspace(dir.path()).await.unwrap();

        assert_ne!(hash1, hash2);
    }

    #[tokio::test]
    async fn test_hash_workspace_skips_hidden() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("visible.txt"), b"data").unwrap();
        std::fs::write(dir.path().join(".hidden"), b"secret").unwrap();

        let hash_with_hidden = hash_workspace(dir.path()).await.unwrap();

        // Remove hidden file — hash should be the same
        std::fs::remove_file(dir.path().join(".hidden")).unwrap();
        let hash_without_hidden = hash_workspace(dir.path()).await.unwrap();

        assert_eq!(hash_with_hidden, hash_without_hidden);
    }

    #[tokio::test]
    async fn test_hash_workspace_recursive() {
        let dir = TempDir::new().unwrap();
        std::fs::create_dir_all(dir.path().join("sub/dir")).unwrap();
        std::fs::write(dir.path().join("sub/dir/deep.txt"), b"nested").unwrap();

        let hash = hash_workspace(dir.path()).await.unwrap();
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_build_exit_report() {
        let report = build_exit_report(
            "workspace_hash".to_string(),
            "audit_hash".to_string(),
            10,
            None,
        );
        assert_eq!(report.workspace_hash, "workspace_hash");
        assert_eq!(report.audit_tail_hash, "audit_hash");
        assert_eq!(report.audit_entry_count, 10);
        assert!(report.timestamp_unix > 0);
        assert_eq!(report.input_tokens, 0);
        assert_eq!(report.cost_usd, 0.0);
    }

    #[test]
    fn test_build_exit_report_with_usage() {
        let usage = TokenUsage {
            input_tokens: 1500,
            output_tokens: 500,
            cache_read_tokens: 200,
            cost_usd: 0.42,
        };
        let report = build_exit_report("hash".to_string(), "tail".to_string(), 5, Some(usage));
        assert_eq!(report.input_tokens, 1500);
        assert_eq!(report.output_tokens, 500);
        assert_eq!(report.cache_read_tokens, 200);
        assert!((report.cost_usd - 0.42).abs() < f64::EPSILON);
    }
}
