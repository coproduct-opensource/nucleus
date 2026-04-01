//! `nucleus-claude-hook --build` — compile `.nucleus/` into a content-addressable artifact.
//!
//! Reads the Compartmentfile, optional policy/egress/enterprise TOML files,
//! and all tool manifests from `.nucleus/manifests/`, then produces an
//! [`ArtifactManifest`] with a SHA-256 digest computed over the canonical
//! layer ordering.

use portcullis_core::artifact::{ArtifactBuilder, ArtifactManifest};
use portcullis_core::compartmentfile::Compartmentfile;
use std::path::Path;

/// CLI entry point for `--build [DIR] [-o FILE]`.
pub fn run_build(args: &[String]) {
    // Find the directory argument: the arg after --build, or "." if absent.
    let dir_arg = args
        .iter()
        .position(|a| a == "--build")
        .and_then(|pos| args.get(pos + 1))
        .filter(|s| !s.starts_with('-'))
        .map(|s| s.as_str())
        .unwrap_or(".");
    let dir = Path::new(dir_arg);

    // Check for --output flag to write to a file instead of stdout.
    let output_path = args
        .iter()
        .position(|a| a == "--output" || a == "-o")
        .and_then(|pos| args.get(pos + 1));

    eprintln!("=> [1/3] Parsing Compartmentfile");
    eprintln!("=> [2/3] Bundling layers from .nucleus/");

    match build_artifact(dir) {
        Ok(manifest) => {
            eprintln!("=> [3/3] Computing digest");
            let json = match manifest.to_json() {
                Ok(j) => j,
                Err(e) => {
                    eprintln!("error: failed to serialize artifact: {e}");
                    crate::exit_codes::ExitCode::Error.exit();
                }
            };
            match output_path {
                Some(path) => {
                    if let Err(e) = std::fs::write(path, &json) {
                        eprintln!("error: failed to write {path}: {e}");
                        crate::exit_codes::ExitCode::Error.exit();
                    }
                    eprintln!("Built: {} -> {path}", manifest.digest);
                }
                None => {
                    println!("{json}");
                    eprintln!("Built: {}", manifest.digest);
                }
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            crate::exit_codes::ExitCode::Error.exit();
        }
    }
}

/// Errors that can occur during artifact building.
#[derive(Debug)]
pub enum BuildError {
    /// The Compartmentfile is missing or invalid.
    Compartmentfile(portcullis_core::compartmentfile::CompartmentfileError),
    /// I/O error reading a file from the `.nucleus/` directory.
    Io(std::io::Error),
    /// The computed digest did not verify (should never happen; indicates a bug).
    DigestMismatch,
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Compartmentfile(e) => write!(f, "Compartmentfile error: {e}"),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::DigestMismatch => write!(f, "artifact digest verification failed (bug)"),
        }
    }
}

impl std::error::Error for BuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Compartmentfile(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::DigestMismatch => None,
        }
    }
}

impl From<std::io::Error> for BuildError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<portcullis_core::compartmentfile::CompartmentfileError> for BuildError {
    fn from(e: portcullis_core::compartmentfile::CompartmentfileError) -> Self {
        Self::Compartmentfile(e)
    }
}

/// Build a content-addressable compartment artifact from a project directory.
///
/// Expects the directory to contain a `.nucleus/` subdirectory with at least
/// a `Compartmentfile`. Optional files (`policy.toml`, `egress.toml`,
/// `enterprise.toml`) and tool manifests (`manifests/*.toml`) are included
/// when present.
///
/// Returns the built [`ArtifactManifest`] with a verified SHA-256 digest.
pub fn build_artifact(dir: &Path) -> Result<ArtifactManifest, BuildError> {
    let nucleus_dir = dir.join(".nucleus");

    // 1. Compartmentfile (required) — also validates the content.
    let compartmentfile_path = nucleus_dir.join("Compartmentfile");
    let compartmentfile_content = std::fs::read_to_string(&compartmentfile_path)?;
    // Validate by parsing — this ensures the TOML is well-formed and passes
    // all structural checks (version, no forward refs, no duplicates, etc.)
    let _cf = Compartmentfile::parse(&compartmentfile_content)?;

    let mut builder = ArtifactBuilder::new();

    // Use current unix timestamp.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    builder = builder.created_at(now);

    // Add compartmentfile layer.
    builder = builder.compartmentfile(compartmentfile_content);

    // 2. policy.toml (optional)
    let policy_path = nucleus_dir.join("policy.toml");
    if policy_path.exists() {
        let content = std::fs::read_to_string(&policy_path)?;
        builder = builder.policy(content);
    }

    // 3. egress.toml (optional)
    let egress_path = nucleus_dir.join("egress.toml");
    if egress_path.exists() {
        let content = std::fs::read_to_string(&egress_path)?;
        builder = builder.egress_policy(content);
    }

    // 4. enterprise.toml (optional)
    let enterprise_path = nucleus_dir.join("enterprise.toml");
    if enterprise_path.exists() {
        let content = std::fs::read_to_string(&enterprise_path)?;
        builder = builder.enterprise_allowlist(content);
    }

    // 5. Tool manifests from .nucleus/manifests/*.toml (sorted for determinism)
    let manifests_dir = nucleus_dir.join("manifests");
    if manifests_dir.is_dir() {
        let mut manifest_files: Vec<_> = std::fs::read_dir(&manifests_dir)?
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "toml"))
            .collect();
        // Sort by filename for deterministic ordering.
        manifest_files.sort_by_key(|e| e.file_name());

        for entry in manifest_files {
            let content = std::fs::read_to_string(entry.path())?;
            builder = builder.tool_manifest(content);
        }
    }

    // 6. Build and verify.
    let manifest = builder.build();
    if !manifest.verify_digest() {
        return Err(BuildError::DigestMismatch);
    }

    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis_core::compartmentfile::default_compartmentfile;
    use std::fs;
    use std::path::PathBuf;

    use std::sync::atomic::{AtomicU64, Ordering};

    /// Create a unique temp dir for each test (thread-safe monotonic counter).
    fn temp_dir() -> PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("nucleus-build-test-{pid}-{id}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Scaffold a `.nucleus/` directory with all files.
    fn scaffold_full(dir: &Path) {
        let nucleus = dir.join(".nucleus");
        fs::create_dir_all(nucleus.join("manifests")).unwrap();

        fs::write(nucleus.join("Compartmentfile"), default_compartmentfile()).unwrap();
        fs::write(nucleus.join("policy.toml"), "[profile]\nname = \"test\"\n").unwrap();
        fs::write(
            nucleus.join("egress.toml"),
            "allowed_hosts = [\"api.github.com\"]\n",
        )
        .unwrap();
        fs::write(
            nucleus.join("enterprise.toml"),
            "allowed_tools = [\"git\"]\n",
        )
        .unwrap();
        fs::write(
            nucleus.join("manifests").join("git.toml"),
            "[tool]\nname = \"git\"\n",
        )
        .unwrap();
        fs::write(
            nucleus.join("manifests").join("cargo.toml"),
            "[tool]\nname = \"cargo\"\n",
        )
        .unwrap();
    }

    /// Scaffold a `.nucleus/` directory with only the required Compartmentfile.
    fn scaffold_minimal(dir: &Path) {
        let nucleus = dir.join(".nucleus");
        fs::create_dir_all(&nucleus).unwrap();
        fs::write(nucleus.join("Compartmentfile"), default_compartmentfile()).unwrap();
    }

    #[test]
    fn build_full_directory() {
        let dir = temp_dir();
        scaffold_full(&dir);

        let manifest = build_artifact(&dir).expect("build should succeed");
        assert!(manifest.verify_digest());
        assert!(manifest.digest.starts_with("sha256:"));
        // Compartmentfile + policy + egress + enterprise + tool manifests = 5 layers
        assert_eq!(manifest.layers.len(), 5);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn build_minimal_directory() {
        let dir = temp_dir();
        scaffold_minimal(&dir);

        let manifest = build_artifact(&dir).expect("build should succeed");
        assert!(manifest.verify_digest());
        // Only the Compartmentfile layer.
        assert_eq!(manifest.layers.len(), 1);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn build_fails_without_compartmentfile() {
        let dir = temp_dir();
        let nucleus = dir.join(".nucleus");
        fs::create_dir_all(&nucleus).unwrap();
        // No Compartmentfile written.

        let result = build_artifact(&dir);
        assert!(result.is_err());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn build_is_deterministic() {
        let dir = temp_dir();
        scaffold_full(&dir);

        let m1 = build_artifact(&dir).unwrap();
        let m2 = build_artifact(&dir).unwrap();
        // Digests should match (timestamps differ but digest only covers layers).
        assert_eq!(m1.digest, m2.digest);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn build_json_roundtrip() {
        let dir = temp_dir();
        scaffold_full(&dir);

        let manifest = build_artifact(&dir).unwrap();
        let json = manifest.to_json().expect("serialize");
        let restored =
            portcullis_core::artifact::ArtifactManifest::from_json(&json).expect("deserialize");
        assert_eq!(manifest.digest, restored.digest);
        assert!(restored.verify_digest());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn build_fails_with_invalid_compartmentfile() {
        let dir = temp_dir();
        let nucleus = dir.join(".nucleus");
        fs::create_dir_all(&nucleus).unwrap();
        fs::write(
            nucleus.join("Compartmentfile"),
            "this is not valid toml {{{",
        )
        .unwrap();

        let result = build_artifact(&dir);
        assert!(result.is_err());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn manifests_sorted_by_filename() {
        let dir = temp_dir();
        let nucleus = dir.join(".nucleus");
        fs::create_dir_all(nucleus.join("manifests")).unwrap();
        fs::write(nucleus.join("Compartmentfile"), default_compartmentfile()).unwrap();

        // Write in reverse order to verify sorting.
        fs::write(
            nucleus.join("manifests").join("z_last.toml"),
            "[tool]\nname = \"last\"\n",
        )
        .unwrap();
        fs::write(
            nucleus.join("manifests").join("a_first.toml"),
            "[tool]\nname = \"first\"\n",
        )
        .unwrap();

        let manifest = build_artifact(&dir).unwrap();
        // Extract ToolManifests layer.
        let tools = manifest
            .layers
            .iter()
            .find_map(|l| {
                if let portcullis_core::artifact::ArtifactLayer::ToolManifests(ms) = l {
                    Some(ms.clone())
                } else {
                    None
                }
            })
            .expect("should have tool manifests");

        assert_eq!(tools.len(), 2);
        assert!(tools[0].contains("first"));
        assert!(tools[1].contains("last"));

        fs::remove_dir_all(&dir).ok();
    }
}
