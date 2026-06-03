// SPDX-License-Identifier: MIT
//
//! Deterministic compilation of a registry directory into a
//! [`FederationSet`] (the reproducible, sorted map that feeds
//! `nucleus-oidc-core::FederationStore`), plus PR-diff guards:
//! diff-smuggling and silent-rotation.

use std::collections::BTreeMap;
use std::path::Path;

use nucleus_oidc_core::spiffe_federation::SpiffeBundle;

use crate::error::RegistryError;
use crate::metadata::{
    DomainEnrollment, DomainMetadata, BUNDLE_FILE, DOMAINS_SUBDIR, METADATA_FILE,
};

/// One compiled binding: everything the federation layer + the
/// transparency log need for a single trust domain.
#[derive(Debug, Clone)]
pub struct CompiledBinding {
    /// The validated metadata (carries `owner_id`, endpoint, profile).
    pub metadata: DomainMetadata,
    /// The parsed SPIFFE bundle (JWK Set + sequence).
    pub bundle: SpiffeBundle,
    /// Raw bundle bytes, for canonical-JSON leaf hashing.
    pub bundle_bytes: Vec<u8>,
}

/// The deterministic output of compiling a registry: trust-domain →
/// compiled binding, in sorted (`BTreeMap`) order so the same input tree
/// always yields the same federation set and the same transparency-log
/// leaf order.
#[derive(Debug, Clone, Default)]
pub struct FederationSet {
    /// Sorted by trust domain. Reproducible across machines.
    pub bindings: BTreeMap<String, CompiledBinding>,
}

impl FederationSet {
    /// The number of compiled bindings.
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }
}

/// Compile every domain directory under `<registry_dir>/domains/` into a
/// deterministic [`FederationSet`].
///
/// Determinism: directory entries are collected and inserted into a
/// `BTreeMap` keyed by trust domain, so iteration order is the sorted
/// trust-domain order regardless of filesystem listing order. Each
/// directory is validated via [`DomainEnrollment::load`] (which also
/// enforces dir-name == `trust_domain`).
///
/// NOTE: compilation parses + validates structure; it does NOT verify the
/// OIDC proof-of-control (that is [`crate::verify_proof_of_control`],
/// driven by the PR gate with the per-PR token). A compiled set is the
/// structural truth; trust is conferred only once a binding's leaf is in
/// the cosigned STH.
pub fn compile(registry_dir: &Path) -> Result<FederationSet, RegistryError> {
    let domains_dir = registry_dir.join(DOMAINS_SUBDIR);
    let mut bindings = BTreeMap::new();

    let entries = match std::fs::read_dir(&domains_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // An empty/absent domains dir compiles to an empty set.
            return Ok(FederationSet::default());
        }
        Err(e) => return Err(RegistryError::Io(format!("read {domains_dir:?}: {e}"))),
    };

    for entry in entries {
        let entry = entry.map_err(|e| RegistryError::Io(e.to_string()))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let enrollment = DomainEnrollment::load(&path)?;
        let td = enrollment.metadata.trust_domain.clone();
        if bindings
            .insert(
                td.clone(),
                CompiledBinding {
                    metadata: enrollment.metadata,
                    bundle: enrollment.bundle,
                    bundle_bytes: enrollment.bundle_bytes,
                },
            )
            .is_some()
        {
            // Two directories can't map to the same trust domain because
            // dir-name == trust_domain is enforced; this is a guardrail.
            return Err(RegistryError::Layout(format!(
                "duplicate trust domain {td:?} in registry"
            )));
        }
    }

    Ok(FederationSet { bindings })
}

/// The set of repo-relative paths a PR changed (added/modified/deleted).
/// The caller produces this from `git diff --name-only` (the workflow
/// wires that); this function is the testable policy.
///
/// Returns `Ok(())` iff EVERY changed path is inside
/// `registry/domains/<claimed_domain>/` (the one domain the enroller
/// claims). Anything outside — touching another domain, CODEOWNERS, the
/// workflow, or unrelated source — is diff-smuggling and is rejected.
pub fn check_pr_diff(
    changed_paths: &[String],
    claimed_domain: &str,
    registry_prefix: &str,
) -> Result<(), RegistryError> {
    // The single allowed prefix, normalized to forward slashes.
    let allowed = format!(
        "{}/{}/{}/",
        registry_prefix.trim_end_matches('/'),
        DOMAINS_SUBDIR,
        claimed_domain
    );
    let mut offending = Vec::new();
    for raw in changed_paths {
        let p = raw.replace('\\', "/");
        let p = p.trim_start_matches("./");
        if p.is_empty() {
            continue;
        }
        // Only `bundle.json` and `metadata.toml` directly under the
        // claimed domain dir are allowed; reject path traversal and any
        // file outside the dir.
        let inside = p.starts_with(&allowed) && {
            let tail = &p[allowed.len()..];
            // No nested subdirs, no traversal.
            !tail.contains('/') && (tail == BUNDLE_FILE || tail == METADATA_FILE)
        };
        if !inside {
            offending.push(raw.clone());
        }
    }
    if offending.is_empty() {
        Ok(())
    } else {
        Err(RegistryError::DiffSmuggling {
            claimed: claimed_domain.to_string(),
            offending,
        })
    }
}

/// Silent-rotation guard: if `trust_domain` already exists in the
/// `incumbent` federation set, the new proof's numeric `proof_owner_id`
/// MUST equal the incumbent's recorded `owner_id`. A mismatch is a
/// takeover attempt (a different GitHub org trying to rotate an existing
/// domain's bundle) and is rejected.
///
/// For a brand-new domain (not in the incumbent set) this is a no-op:
/// first enrollment establishes the owner_id.
pub fn check_no_silent_rotation(
    incumbent: &FederationSet,
    trust_domain: &str,
    proof_owner_id: u64,
) -> Result<(), RegistryError> {
    if let Some(existing) = incumbent.bindings.get(trust_domain) {
        if existing.metadata.owner_id != proof_owner_id {
            return Err(RegistryError::SilentRotation {
                trust_domain: trust_domain.to_string(),
                incumbent: existing.metadata.owner_id,
                proof: proof_owner_id,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_accepts_only_claimed_domain_files() {
        let changed = vec![
            "registry/domains/ci.example.org/bundle.json".to_string(),
            "registry/domains/ci.example.org/metadata.toml".to_string(),
        ];
        check_pr_diff(&changed, "ci.example.org", "registry").unwrap();
    }

    #[test]
    fn diff_rejects_other_domain() {
        let changed = vec![
            "registry/domains/ci.example.org/bundle.json".to_string(),
            "registry/domains/evil.example.org/bundle.json".to_string(),
        ];
        let err = check_pr_diff(&changed, "ci.example.org", "registry").unwrap_err();
        assert!(matches!(err, RegistryError::DiffSmuggling { .. }));
    }

    #[test]
    fn diff_rejects_codeowners_smuggle() {
        let changed = vec![
            "registry/domains/ci.example.org/bundle.json".to_string(),
            ".github/CODEOWNERS".to_string(),
        ];
        let err = check_pr_diff(&changed, "ci.example.org", "registry").unwrap_err();
        match err {
            RegistryError::DiffSmuggling { offending, .. } => {
                assert_eq!(offending, vec![".github/CODEOWNERS".to_string()]);
            }
            other => panic!("expected DiffSmuggling, got {other:?}"),
        }
    }

    #[test]
    fn diff_rejects_traversal_and_nested() {
        let changed = vec!["registry/domains/ci.example.org/../other/x".to_string()];
        assert!(check_pr_diff(&changed, "ci.example.org", "registry").is_err());
        let nested = vec!["registry/domains/ci.example.org/sub/bundle.json".to_string()];
        assert!(check_pr_diff(&nested, "ci.example.org", "registry").is_err());
    }

    #[test]
    fn diff_rejects_unexpected_filename() {
        let changed = vec!["registry/domains/ci.example.org/secrets.txt".to_string()];
        assert!(check_pr_diff(&changed, "ci.example.org", "registry").is_err());
    }
}
