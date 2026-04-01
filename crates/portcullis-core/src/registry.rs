//! Local registry for compartment artifact distribution.
//!
//! Provides push/pull semantics for compartment artifacts using a local
//! content-addressable store. This is the foundation layer — actual OCI
//! registry network clients would build on top of these types.
//!
//! ## Storage layout
//!
//! ```text
//! .nucleus/registry/
//! └── <name>/
//!     ├── sha256:<hex>.json   ← artifact manifest content
//!     └── <tag>               ← text file containing the digest
//! ```
//!
//! Tags are stored as small text files whose content is the digest string
//! (e.g. `sha256:abcd1234...`). This avoids symlink portability issues
//! across platforms while maintaining the tag→digest indirection.
//!
//! ## Artifact references
//!
//! References follow the OCI/Docker convention:
//!
//! ```text
//! registry.example.com/org/compartment:tag
//! └── registry ──────┘ └── name ──────┘ └ tag
//! ```

use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

/// A parsed artifact reference in `registry/name:tag` format.
///
/// Follows the OCI distribution spec naming convention:
/// `<registry>/<name>:<tag>[@<digest>]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRef {
    /// Registry hostname (e.g. `ghcr.io`, `registry.example.com`).
    pub registry: String,
    /// Repository name, potentially including org prefix (e.g. `myorg/secure-codegen`).
    pub name: String,
    /// Tag label (e.g. `v1`, `latest`).
    pub tag: String,
    /// Content-addressable digest, if resolved (e.g. `sha256:abcd1234...`).
    pub digest: Option<String>,
}

impl ArtifactRef {
    /// Parse an artifact reference string.
    ///
    /// Accepted formats:
    /// - `registry.example.com/org/name:tag`
    /// - `org/name:tag` (registry defaults to `"local"`)
    /// - `org/name` (tag defaults to `"latest"`)
    ///
    /// The heuristic for distinguishing registry from name: the first segment
    /// is treated as a registry if it contains a `.` or `:` (port), otherwise
    /// the registry defaults to `"local"`.
    pub fn parse(ref_str: &str) -> Result<Self, RegistryError> {
        if ref_str.is_empty() {
            return Err(RegistryError::InvalidReference(
                "empty reference string".into(),
            ));
        }

        // Split off @digest if present
        let (main_part, digest) = if let Some(idx) = ref_str.rfind('@') {
            let d = &ref_str[idx + 1..];
            if !d.starts_with("sha256:") {
                return Err(RegistryError::InvalidReference(format!(
                    "digest must start with 'sha256:': {d}"
                )));
            }
            (&ref_str[..idx], Some(d.to_string()))
        } else {
            (ref_str, None)
        };

        // Split off :tag from the last segment
        let (path_part, tag) = if let Some(colon_idx) = main_part.rfind(':') {
            // Make sure this colon isn't part of a port in the registry
            // (port colons appear before the first /)
            let after_first_slash = main_part.find('/').unwrap_or(main_part.len());
            if colon_idx > after_first_slash {
                (
                    &main_part[..colon_idx],
                    main_part[colon_idx + 1..].to_string(),
                )
            } else {
                (main_part, "latest".to_string())
            }
        } else {
            (main_part, "latest".to_string())
        };

        if tag.is_empty() {
            return Err(RegistryError::InvalidReference("empty tag".into()));
        }

        // Split registry from name by first path segment
        let segments: Vec<&str> = path_part.splitn(2, '/').collect();
        let (registry, name) = if segments.len() == 1 {
            // No slash at all — treat as just a name
            ("local".to_string(), segments[0].to_string())
        } else {
            let first = segments[0];
            // Heuristic: if first segment has a dot or colon it's a registry hostname
            if first.contains('.') || first.contains(':') {
                (first.to_string(), segments[1].to_string())
            } else {
                // e.g. "myorg/compartment" — no explicit registry
                ("local".to_string(), path_part.to_string())
            }
        };

        if name.is_empty() {
            return Err(RegistryError::InvalidReference("empty name".into()));
        }

        Ok(ArtifactRef {
            registry,
            name,
            tag,
            digest,
        })
    }

    /// Return the storage-safe name path (slashes preserved for directory nesting).
    fn storage_name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for ArtifactRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.registry == "local" {
            write!(f, "{}:{}", self.name, self.tag)?;
        } else {
            write!(f, "{}/{}:{}", self.registry, self.name, self.tag)?;
        }
        if let Some(d) = &self.digest {
            write!(f, "@{d}")?;
        }
        Ok(())
    }
}

/// Errors produced by registry operations.
#[derive(Debug)]
pub enum RegistryError {
    /// The reference string could not be parsed.
    InvalidReference(String),
    /// An I/O error from the local filesystem store.
    Io(std::io::Error),
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryError::InvalidReference(msg) => write!(f, "invalid reference: {msg}"),
            RegistryError::Io(e) => write!(f, "registry I/O error: {e}"),
        }
    }
}

impl std::error::Error for RegistryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RegistryError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for RegistryError {
    fn from(e: std::io::Error) -> Self {
        RegistryError::Io(e)
    }
}

/// A local, filesystem-backed artifact registry.
///
/// Stores artifacts as JSON files addressed by their SHA-256 digest,
/// with tags stored as small text files containing the digest pointer.
///
/// ```text
/// <root>/
/// └── myorg/secure-codegen/
///     ├── sha256:abcdef1234567890.json   ← manifest content
///     └── v1                              ← contains "sha256:abcdef1234567890"
/// ```
pub struct LocalRegistry {
    root: PathBuf,
}

impl LocalRegistry {
    /// Open (or create) a local registry rooted at the given directory.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, RegistryError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(LocalRegistry { root })
    }

    /// Return the root path of this registry.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Push an artifact manifest (as JSON string) into the registry.
    ///
    /// The content is stored by its SHA-256 digest, and the tag in the
    /// artifact ref is updated to point at that digest. Returns the
    /// computed digest string.
    pub fn push(
        &self,
        artifact_ref: &ArtifactRef,
        manifest_json: &str,
    ) -> Result<String, RegistryError> {
        let digest = compute_digest(manifest_json);

        let name_dir = self.root.join(artifact_ref.storage_name());
        fs::create_dir_all(&name_dir)?;

        // Write content-addressed blob
        let blob_path = name_dir.join(format!("{digest}.json"));
        fs::write(&blob_path, manifest_json)?;

        // Write tag pointer
        let tag_path = name_dir.join(&artifact_ref.tag);
        fs::write(&tag_path, &digest)?;

        Ok(digest)
    }

    /// Pull an artifact by reference, returning the manifest JSON.
    ///
    /// Resolution order:
    /// 1. If the ref has an explicit digest, fetch by digest directly.
    /// 2. Otherwise, resolve the tag to a digest, then fetch.
    pub fn pull(&self, artifact_ref: &ArtifactRef) -> Result<Option<String>, RegistryError> {
        let name_dir = self.root.join(artifact_ref.storage_name());
        if !name_dir.exists() {
            return Ok(None);
        }

        let digest = if let Some(d) = &artifact_ref.digest {
            d.clone()
        } else {
            match self.resolve_digest(artifact_ref)? {
                Some(d) => d,
                None => return Ok(None),
            }
        };

        let blob_path = name_dir.join(format!("{digest}.json"));
        if blob_path.exists() {
            Ok(Some(fs::read_to_string(&blob_path)?))
        } else {
            Ok(None)
        }
    }

    /// Resolve a tag to its content digest.
    pub fn resolve_digest(
        &self,
        artifact_ref: &ArtifactRef,
    ) -> Result<Option<String>, RegistryError> {
        let tag_path = self
            .root
            .join(artifact_ref.storage_name())
            .join(&artifact_ref.tag);
        if tag_path.exists() {
            let digest = fs::read_to_string(&tag_path)?.trim().to_string();
            Ok(Some(digest))
        } else {
            Ok(None)
        }
    }

    /// List all stored artifact references (one per tag).
    pub fn list(&self) -> Result<Vec<ArtifactRef>, RegistryError> {
        let mut refs = Vec::new();
        self.list_recursive(&self.root, &mut String::new(), &mut refs)?;
        Ok(refs)
    }

    /// Walk the registry tree collecting tag files.
    ///
    /// A file is considered a tag (not a blob) if its name does NOT end in `.json`.
    fn list_recursive(
        &self,
        dir: &Path,
        current_name: &mut String,
        refs: &mut Vec<ArtifactRef>,
    ) -> Result<(), RegistryError> {
        if !dir.exists() {
            return Ok(());
        }

        let mut has_json = false;
        let mut entries: Vec<_> = fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
        entries.sort_by_key(|e| e.file_name());

        for entry in &entries {
            if entry.file_name().to_string_lossy().ends_with(".json") {
                has_json = true;
                break;
            }
        }

        for entry in entries {
            let fname = entry.file_name().to_string_lossy().to_string();
            let ftype = entry.file_type()?;

            if ftype.is_dir() {
                let prev_len = current_name.len();
                if !current_name.is_empty() {
                    current_name.push('/');
                }
                current_name.push_str(&fname);
                self.list_recursive(&entry.path(), current_name, refs)?;
                current_name.truncate(prev_len);
            } else if ftype.is_file() && !fname.ends_with(".json") && has_json {
                // This is a tag file in a leaf directory that also has .json blobs
                let digest = fs::read_to_string(entry.path())?.trim().to_string();
                let name = if current_name.is_empty() {
                    fname.clone()
                } else {
                    current_name.clone()
                };
                refs.push(ArtifactRef {
                    registry: "local".into(),
                    name,
                    tag: fname,
                    digest: Some(digest),
                });
            }
        }

        Ok(())
    }
}

/// Compute the `sha256:<hex>` digest of content.
fn compute_digest(content: &str) -> String {
    let hash = Sha256::digest(content.as_bytes());
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── ArtifactRef parsing ────────────────────────────────────────

    #[test]
    fn parse_full_ref() {
        let r = ArtifactRef::parse("ghcr.io/myorg/secure-codegen:v1").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.name, "myorg/secure-codegen");
        assert_eq!(r.tag, "v1");
        assert_eq!(r.digest, None);
    }

    #[test]
    fn parse_no_registry() {
        let r = ArtifactRef::parse("myorg/secure-codegen:v2").unwrap();
        assert_eq!(r.registry, "local");
        assert_eq!(r.name, "myorg/secure-codegen");
        assert_eq!(r.tag, "v2");
    }

    #[test]
    fn parse_default_tag() {
        let r = ArtifactRef::parse("myorg/compartment").unwrap();
        assert_eq!(r.tag, "latest");
    }

    #[test]
    fn parse_with_digest() {
        let r = ArtifactRef::parse("myorg/comp:v1@sha256:abcdef").unwrap();
        assert_eq!(r.tag, "v1");
        assert_eq!(r.digest, Some("sha256:abcdef".into()));
    }

    #[test]
    fn parse_registry_with_port() {
        let r = ArtifactRef::parse("localhost:5000/mylib:latest").unwrap();
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.name, "mylib");
        assert_eq!(r.tag, "latest");
    }

    #[test]
    fn parse_empty_ref_fails() {
        assert!(ArtifactRef::parse("").is_err());
    }

    #[test]
    fn parse_bad_digest_prefix() {
        assert!(ArtifactRef::parse("foo/bar:v1@md5:abc").is_err());
    }

    #[test]
    fn display_with_registry() {
        let r = ArtifactRef {
            registry: "ghcr.io".into(),
            name: "org/comp".into(),
            tag: "v1".into(),
            digest: None,
        };
        assert_eq!(r.to_string(), "ghcr.io/org/comp:v1");
    }

    #[test]
    fn display_local() {
        let r = ArtifactRef {
            registry: "local".into(),
            name: "myorg/comp".into(),
            tag: "latest".into(),
            digest: None,
        };
        assert_eq!(r.to_string(), "myorg/comp:latest");
    }

    #[test]
    fn display_with_digest() {
        let r = ArtifactRef {
            registry: "local".into(),
            name: "comp".into(),
            tag: "v1".into(),
            digest: Some("sha256:abc123".into()),
        };
        assert_eq!(r.to_string(), "comp:v1@sha256:abc123");
    }

    #[test]
    fn parse_display_roundtrip() {
        let original = "ghcr.io/myorg/secure-codegen:v1";
        let parsed = ArtifactRef::parse(original).unwrap();
        assert_eq!(parsed.to_string(), original);
    }

    // ── LocalRegistry push/pull ────────────────────────────────────

    #[test]
    fn push_pull_roundtrip() {
        let dir = tempdir();
        let reg = LocalRegistry::new(&dir).unwrap();
        let aref = ArtifactRef::parse("myorg/comp:v1").unwrap();
        let manifest = r#"{"schema_version":"1","layers":[]}"#;

        let digest = reg.push(&aref, manifest).unwrap();
        assert!(digest.starts_with("sha256:"));

        let pulled = reg.pull(&aref).unwrap();
        assert_eq!(pulled, Some(manifest.to_string()));
    }

    #[test]
    fn pull_by_digest() {
        let dir = tempdir();
        let reg = LocalRegistry::new(&dir).unwrap();
        let aref = ArtifactRef::parse("myorg/comp:v1").unwrap();
        let manifest = r#"{"test":"data"}"#;

        let digest = reg.push(&aref, manifest).unwrap();

        // Pull using explicit digest instead of tag
        let digest_ref = ArtifactRef {
            registry: "local".into(),
            name: "myorg/comp".into(),
            tag: "v1".into(),
            digest: Some(digest),
        };
        let pulled = reg.pull(&digest_ref).unwrap();
        assert_eq!(pulled, Some(manifest.to_string()));
    }

    #[test]
    fn pull_missing_returns_none() {
        let dir = tempdir();
        let reg = LocalRegistry::new(&dir).unwrap();
        let aref = ArtifactRef::parse("nonexistent/comp:v1").unwrap();
        assert_eq!(reg.pull(&aref).unwrap(), None);
    }

    #[test]
    fn resolve_digest_for_tag() {
        let dir = tempdir();
        let reg = LocalRegistry::new(&dir).unwrap();
        let aref = ArtifactRef::parse("myorg/comp:v1").unwrap();
        let manifest = r#"{"data":"value"}"#;

        let digest = reg.push(&aref, manifest).unwrap();
        let resolved = reg.resolve_digest(&aref).unwrap();
        assert_eq!(resolved, Some(digest));
    }

    #[test]
    fn resolve_digest_missing_tag() {
        let dir = tempdir();
        let reg = LocalRegistry::new(&dir).unwrap();
        let aref = ArtifactRef::parse("myorg/comp:nonexistent").unwrap();
        assert_eq!(reg.resolve_digest(&aref).unwrap(), None);
    }

    #[test]
    fn list_artifacts() {
        let dir = tempdir();
        let reg = LocalRegistry::new(&dir).unwrap();

        let a1 = ArtifactRef::parse("myorg/comp:v1").unwrap();
        let a2 = ArtifactRef::parse("myorg/comp:v2").unwrap();
        let a3 = ArtifactRef::parse("other/lib:latest").unwrap();

        reg.push(&a1, r#"{"v":"1"}"#).unwrap();
        reg.push(&a2, r#"{"v":"2"}"#).unwrap();
        reg.push(&a3, r#"{"v":"3"}"#).unwrap();

        let listed = reg.list().unwrap();
        assert_eq!(listed.len(), 3);

        let names: Vec<_> = listed.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"myorg/comp"));
        assert!(names.contains(&"other/lib"));

        let tags: Vec<_> = listed.iter().map(|r| r.tag.as_str()).collect();
        assert!(tags.contains(&"v1"));
        assert!(tags.contains(&"v2"));
        assert!(tags.contains(&"latest"));
    }

    #[test]
    fn tag_update_points_to_new_digest() {
        let dir = tempdir();
        let reg = LocalRegistry::new(&dir).unwrap();
        let aref = ArtifactRef::parse("myorg/comp:latest").unwrap();

        let d1 = reg.push(&aref, r#"{"version":1}"#).unwrap();
        let d2 = reg.push(&aref, r#"{"version":2}"#).unwrap();
        assert_ne!(d1, d2);

        // Tag should now point to the second digest
        let resolved = reg.resolve_digest(&aref).unwrap().unwrap();
        assert_eq!(resolved, d2);

        // Pulling should return the latest content
        let pulled = reg.pull(&aref).unwrap().unwrap();
        assert_eq!(pulled, r#"{"version":2}"#);
    }

    #[test]
    fn old_digest_still_accessible() {
        let dir = tempdir();
        let reg = LocalRegistry::new(&dir).unwrap();
        let aref = ArtifactRef::parse("myorg/comp:latest").unwrap();

        let d1 = reg.push(&aref, r#"{"version":1}"#).unwrap();
        let _d2 = reg.push(&aref, r#"{"version":2}"#).unwrap();

        // Old content still reachable by digest
        let old_ref = ArtifactRef {
            registry: "local".into(),
            name: "myorg/comp".into(),
            tag: "latest".into(),
            digest: Some(d1),
        };
        let pulled = reg.pull(&old_ref).unwrap().unwrap();
        assert_eq!(pulled, r#"{"version":1}"#);
    }

    // ── helpers ────────────────────────────────────────────────────

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "nucleus-registry-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }
}
