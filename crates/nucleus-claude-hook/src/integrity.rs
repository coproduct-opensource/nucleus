#![allow(clippy::disallowed_types)] // #1216: migration pending
//! Binary self-integrity verification (#946).
//!
//! At startup, compute SHA-256 of the running binary and compare against
//! a pinned hash in `.nucleus/integrity.toml`. If mismatched, warn that
//! the binary may have been tampered with.
//!
//! This is defense-in-depth: an attacker who replaces the binary can also
//! replace the manifest, but they'd need to do both — and the manifest
//! can be pinned in version control where changes are visible.

use sha2::{Digest, Sha256};

/// Result of the integrity check.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IntegrityResult {
    /// Binary hash matches the manifest.
    Verified,
    /// Binary hash doesn't match — possible tampering.
    Mismatch { expected: String, actual: String },
    /// No integrity manifest found (not configured).
    NoManifest,
    /// Could not read the binary for hashing.
    ReadError(String),
}

/// Check the running binary's integrity against `.nucleus/integrity.toml`.
///
/// The manifest format:
/// ```toml
/// [binary]
/// hash = "sha256:abcdef..."
/// ```
pub(crate) fn verify_binary_integrity() -> IntegrityResult {
    // Find the integrity manifest.
    let manifest_paths = [
        std::env::current_dir()
            .ok()
            .map(|d| d.join(".nucleus").join("integrity.toml")),
        dirs_next::home_dir().map(|d| d.join(".nucleus").join("integrity.toml")),
    ];

    let manifest_content = manifest_paths
        .iter()
        .flatten()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .next();

    let Some(content) = manifest_content else {
        return IntegrityResult::NoManifest;
    };

    // Parse the expected hash.
    let table: toml::Table = match content.parse() {
        Ok(t) => t,
        Err(_) => return IntegrityResult::NoManifest,
    };
    let expected_hash = table
        .get("binary")
        .and_then(|b| b.get("hash"))
        .and_then(|h| h.as_str());

    let Some(expected) = expected_hash else {
        return IntegrityResult::NoManifest;
    };

    // Compute the actual hash of the running binary.
    let exe_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => return IntegrityResult::ReadError(e.to_string()),
    };

    let binary_bytes = match std::fs::read(&exe_path) {
        Ok(b) => b,
        Err(e) => return IntegrityResult::ReadError(format!("{}: {e}", exe_path.display())),
    };

    let mut hasher = Sha256::new();
    hasher.update(&binary_bytes);
    let result = hasher.finalize();
    let actual = format!("sha256:{}", hex::encode(result));

    if actual == expected {
        IntegrityResult::Verified
    } else {
        IntegrityResult::Mismatch {
            expected: expected.to_string(),
            actual,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_manifest_returns_no_manifest() {
        // In test environment, no .nucleus/integrity.toml exists.
        let result = verify_binary_integrity();
        assert!(
            matches!(result, IntegrityResult::NoManifest),
            "expected NoManifest without integrity.toml, got: {result:?}"
        );
    }

    #[test]
    fn current_exe_is_readable() {
        // Verify we can at least read the binary (for hash computation).
        let exe = std::env::current_exe().unwrap();
        let bytes = std::fs::read(&exe);
        assert!(bytes.is_ok(), "should be able to read {}", exe.display());
    }
}
