//! Exit report generation for execution receipts.
//!
//! Before shutdown, the tool-proxy computes a workspace content hash and
//! captures the audit chain tail, writing this as the final audit log entry.
//! The host (nucleus-node) reads this to build an `ExecutionReceipt`.
//!
//! For multi-repo execution, each named workspace is hashed independently.
//! The per-workspace hashes are combined into a single root hash for backward
//! compatibility with single-workspace consumers.

use nucleus_spec::{sha256_bytes_hex, ExitReport};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
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

/// Compute SHA-256 hashes for multiple named workspaces.
///
/// Returns a map of `workspace_name -> sha256_hex` for each provided workspace.
/// Workspaces are processed in order; the first error aborts and is returned.
pub async fn hash_workspaces(
    workspaces: &[(String, &Path)],
) -> Result<BTreeMap<String, String>, std::io::Error> {
    let mut result = BTreeMap::new();
    for (name, root) in workspaces {
        let hash = hash_workspace(root).await?;
        result.insert(name.clone(), hash);
    }
    Ok(result)
}

/// Combine multiple workspace hashes into a single deterministic root hash.
///
/// Hashes the sorted list of `(name, hash)` pairs so the result is stable
/// regardless of insertion order.  Used to populate the backward-compatible
/// `ExitReport::workspace_hash` field when multi-workspace mode is active.
pub fn combined_workspace_hash(workspace_hashes: &BTreeMap<String, String>) -> String {
    let mut hasher = Sha256::new();
    // BTreeMap iterates in sorted key order — deterministic by construction.
    for (name, hash) in workspace_hashes {
        hasher.update(name.as_bytes());
        hasher.update(b":");
        hasher.update(hash.as_bytes());
        hasher.update(b"\n");
    }
    hex::encode(hasher.finalize())
}

/// Build an exit report for a single-workspace pod.
pub fn build_exit_report(
    workspace_hash: String,
    audit_tail_hash: String,
    audit_entry_count: u64,
) -> ExitReport {
    let timestamp_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    ExitReport {
        workspace_hash,
        workspace_hashes: BTreeMap::new(),
        audit_tail_hash,
        audit_entry_count,
        timestamp_unix,
    }
}

/// Build an exit report for a multi-workspace pod.
///
/// The `workspace_hash` field is set to the combined hash of all workspace
/// hashes for backward compatibility.
pub fn build_exit_report_multi(
    workspace_hashes: BTreeMap<String, String>,
    audit_tail_hash: String,
    audit_entry_count: u64,
) -> ExitReport {
    let combined = combined_workspace_hash(&workspace_hashes);
    let timestamp_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    ExitReport {
        workspace_hash: combined,
        workspace_hashes,
        audit_tail_hash,
        audit_entry_count,
        timestamp_unix,
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
        let report = build_exit_report("workspace_hash".to_string(), "audit_hash".to_string(), 10);
        assert_eq!(report.workspace_hash, "workspace_hash");
        assert!(report.workspace_hashes.is_empty());
        assert_eq!(report.audit_tail_hash, "audit_hash");
        assert_eq!(report.audit_entry_count, 10);
        assert!(report.timestamp_unix > 0);
    }

    #[tokio::test]
    async fn test_hash_workspaces_multiple() {
        let dir1 = TempDir::new().unwrap();
        let dir2 = TempDir::new().unwrap();
        std::fs::write(dir1.path().join("a.txt"), b"repo1").unwrap();
        std::fs::write(dir2.path().join("b.txt"), b"repo2").unwrap();

        let workspaces = vec![
            ("primary".to_string(), dir1.path()),
            ("secondary".to_string(), dir2.path()),
        ];
        let hashes = hash_workspaces(&workspaces).await.unwrap();

        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains_key("primary"));
        assert!(hashes.contains_key("secondary"));
        assert_eq!(hashes["primary"].len(), 64);
        assert_ne!(hashes["primary"], hashes["secondary"]);
    }

    #[tokio::test]
    async fn test_hash_workspaces_deterministic() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"content").unwrap();

        let workspaces = vec![("repo".to_string(), dir.path())];
        let h1 = hash_workspaces(&workspaces).await.unwrap();
        let h2 = hash_workspaces(&workspaces).await.unwrap();

        assert_eq!(h1["repo"], h2["repo"]);
    }

    #[test]
    fn test_combined_workspace_hash_deterministic() {
        let mut hashes = BTreeMap::new();
        hashes.insert("alpha".to_string(), "hash_a".to_string());
        hashes.insert("beta".to_string(), "hash_b".to_string());

        let combined1 = combined_workspace_hash(&hashes);
        let combined2 = combined_workspace_hash(&hashes);
        assert_eq!(combined1, combined2);
        assert_eq!(combined1.len(), 64);
    }

    #[test]
    fn test_combined_workspace_hash_order_independent() {
        // BTreeMap guarantees sorted order, so insertion order doesn't matter
        let mut h1 = BTreeMap::new();
        h1.insert("alpha".to_string(), "hash_a".to_string());
        h1.insert("beta".to_string(), "hash_b".to_string());

        let mut h2 = BTreeMap::new();
        h2.insert("beta".to_string(), "hash_b".to_string());
        h2.insert("alpha".to_string(), "hash_a".to_string());

        assert_eq!(combined_workspace_hash(&h1), combined_workspace_hash(&h2));
    }

    #[test]
    fn test_build_exit_report_multi() {
        let mut hashes = BTreeMap::new();
        hashes.insert("primary".to_string(), "hash1".to_string());
        hashes.insert("secondary".to_string(), "hash2".to_string());

        let report =
            build_exit_report_multi(hashes.clone(), "audit_hash".to_string(), 5);

        // workspace_hashes should contain both entries
        assert_eq!(report.workspace_hashes.len(), 2);
        assert_eq!(report.workspace_hashes["primary"], "hash1");
        assert_eq!(report.workspace_hashes["secondary"], "hash2");

        // workspace_hash should be the combined hash
        assert_eq!(report.workspace_hash, combined_workspace_hash(&hashes));
        assert_eq!(report.workspace_hash.len(), 64);

        assert_eq!(report.audit_tail_hash, "audit_hash");
        assert_eq!(report.audit_entry_count, 5);
        assert!(report.timestamp_unix > 0);
    }

    #[test]
    fn test_combined_vs_single_hash_differ() {
        // A combined hash across multiple workspaces should differ from a single workspace hash
        let mut hashes = BTreeMap::new();
        hashes.insert("primary".to_string(), "abc123".to_string());
        hashes.insert("secondary".to_string(), "def456".to_string());

        let combined = combined_workspace_hash(&hashes);
        assert_ne!(combined, "abc123");
        assert_ne!(combined, "def456");
    }

    #[test]
    fn test_combined_workspace_hash_empty_map() {
        // An empty workspace set should still produce a stable, valid 64-char hash.
        let hashes: BTreeMap<String, String> = BTreeMap::new();
        let combined1 = combined_workspace_hash(&hashes);
        let combined2 = combined_workspace_hash(&hashes);
        assert_eq!(combined1.len(), 64, "empty map should yield 64-char SHA-256 hex");
        assert_eq!(combined1, combined2, "empty map hash must be deterministic");
    }

    #[test]
    fn test_build_exit_report_multi_empty_hashes() {
        // build_exit_report_multi with an empty workspace map should still produce
        // a valid report (workspace_hash = hash of empty input, workspace_hashes empty).
        let hashes: BTreeMap<String, String> = BTreeMap::new();
        let report = build_exit_report_multi(hashes.clone(), "audit".to_string(), 0);

        assert!(report.workspace_hashes.is_empty());
        assert_eq!(report.workspace_hash, combined_workspace_hash(&hashes));
        assert_eq!(report.workspace_hash.len(), 64);
        assert_eq!(report.audit_entry_count, 0);
        assert!(report.timestamp_unix > 0);
    }

    #[tokio::test]
    async fn test_hash_workspaces_single_matches_hash_workspace() {
        // hash_workspaces with one entry should produce the same hash as the
        // direct hash_workspace call — the two APIs must be consistent.
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("file.txt"), b"content").unwrap();

        let direct = hash_workspace(dir.path()).await.unwrap();
        let via_map = hash_workspaces(&[("repo".to_string(), dir.path())])
            .await
            .unwrap();

        assert_eq!(
            via_map["repo"], direct,
            "hash_workspaces single entry must match hash_workspace"
        );
    }

    #[tokio::test]
    async fn test_hash_workspace_nonexistent_path_errors() {
        let result = hash_workspace(std::path::Path::new("/nonexistent/path/xyz")).await;
        assert!(
            result.is_err(),
            "hashing a nonexistent path must return an error"
        );
    }

    #[tokio::test]
    async fn test_hash_workspace_name_sensitive() {
        // Same content in two differently-named files must produce different hashes.
        let dir1 = TempDir::new().unwrap();
        let dir2 = TempDir::new().unwrap();
        std::fs::write(dir1.path().join("alpha.txt"), b"same content").unwrap();
        std::fs::write(dir2.path().join("beta.txt"), b"same content").unwrap();

        let hash1 = hash_workspace(dir1.path()).await.unwrap();
        let hash2 = hash_workspace(dir2.path()).await.unwrap();
        assert_ne!(
            hash1, hash2,
            "files with same content but different names must produce different workspace hashes"
        );
    }

    #[tokio::test]
    async fn test_hash_workspaces_error_propagation() {
        // If one workspace path does not exist, the error should propagate.
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"data").unwrap();

        let workspaces = vec![
            ("good".to_string(), dir.path()),
            (
                "bad".to_string(),
                std::path::Path::new("/nonexistent/missing"),
            ),
        ];
        let result = hash_workspaces(&workspaces).await;
        assert!(
            result.is_err(),
            "hash_workspaces must propagate errors from invalid paths"
        );
    }
}
