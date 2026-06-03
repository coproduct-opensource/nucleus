// SPDX-License-Identifier: MIT
//
//! Repo-format parser for one enrolled domain directory:
//! `registry/domains/<trust-domain>/{bundle.json, metadata.toml}`.
//!
//! `bundle.json` is a SPIFFE trust-domain bundle (a JWK Set + the SPIFFE
//! Federation top-level fields), parsed through the EXACT same
//! [`SpiffeBundle`] type the inbound validator uses. `metadata.toml`
//! carries the out-of-band federation binding the SPIFFE spec says
//! "cannot be securely inferred": the trust domain, its pinned bundle
//! endpoint URL, the endpoint profile, and the GitHub identity that
//! controls it (org name + NUMERIC org id).

use std::path::Path;

use nucleus_oidc_core::spiffe_federation::{Profile, SpiffeBundle};
use serde::Deserialize;

use crate::error::RegistryError;

/// Directory name under `registry/` that holds per-domain enrollments.
pub const DOMAINS_SUBDIR: &str = "domains";
/// Filename of the SPIFFE bundle inside a domain directory.
pub const BUNDLE_FILE: &str = "bundle.json";
/// Filename of the enrollment metadata inside a domain directory.
pub const METADATA_FILE: &str = "metadata.toml";

/// The only supported SPIFFE Federation endpoint profile string.
pub const PROFILE_HTTPS_WEB: &str = "https_web";

/// Parsed `metadata.toml` for one enrolled trust domain.
///
/// All three SPIFFE-federation parameters (`trust_domain`,
/// `bundle_endpoint_url`, `profile`) are REQUIRED — there is no default,
/// because the SPIFFE Federation spec states the binding cannot be
/// securely inferred. `owner_github_org` + `owner_id` anchor authority to
/// a GitHub identity (see crate docs: v1 proves GitHub-ORG control, NOT
/// trust-domain ownership).
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DomainMetadata {
    /// The SPIFFE trust-domain authority, e.g. `"ci.example.org"`. MUST
    /// match the directory name.
    pub trust_domain: String,
    /// The GitHub org/user login that controls this enrollment, e.g.
    /// `"coproduct-opensource"`. Matched against the OIDC
    /// `repository_owner` claim.
    pub owner_github_org: String,
    /// The GitHub NUMERIC owner id. Matched against the OIDC
    /// `repository_owner_id` claim — this is the squat-proof pin: a
    /// renamed/re-registered org keeps a different numeric id.
    pub owner_id: u64,
    /// The pinned `https_web` bundle-endpoint URL. NEVER inferred from
    /// `trust_domain`.
    pub bundle_endpoint_url: String,
    /// The endpoint profile string. Only `"https_web"` is supported.
    pub profile: String,
}

impl DomainMetadata {
    /// Parse + validate `metadata.toml` from its raw bytes.
    ///
    /// Enforces presence of all three federation params (serde rejects a
    /// missing field), a supported profile, and — crucially — that the
    /// endpoint host is NOT merely the trust domain (no inferred binding).
    pub fn from_toml(bytes: &[u8]) -> Result<Self, RegistryError> {
        let text = std::str::from_utf8(bytes)
            .map_err(|e| RegistryError::Metadata(format!("utf8: {e}")))?;
        let md: DomainMetadata =
            toml::from_str(text).map_err(|e| RegistryError::Metadata(e.to_string()))?;
        md.validate()?;
        Ok(md)
    }

    /// Validate the federation params: non-empty, supported profile, and
    /// not an inferred binding.
    fn validate(&self) -> Result<(), RegistryError> {
        if self.trust_domain.trim().is_empty() {
            return Err(RegistryError::MissingFederationParam("trust_domain"));
        }
        if self.bundle_endpoint_url.trim().is_empty() {
            return Err(RegistryError::MissingFederationParam("bundle_endpoint_url"));
        }
        if self.profile.trim().is_empty() {
            return Err(RegistryError::MissingFederationParam("profile"));
        }
        if self.profile != PROFILE_HTTPS_WEB {
            return Err(RegistryError::UnsupportedProfile(self.profile.clone()));
        }
        // No-inferred-binding (SPIFFE Federation): reject when the
        // endpoint host is identical to the trust domain. SPIFFE says the
        // binding cannot be securely inferred — an endpoint derived from
        // the trust-domain name is exactly the inference the spec forbids.
        let host = endpoint_host(&self.bundle_endpoint_url)?;
        if host.eq_ignore_ascii_case(&self.trust_domain) {
            return Err(RegistryError::InferredBinding {
                host,
                trust_domain: self.trust_domain.clone(),
            });
        }
        Ok(())
    }

    /// The parsed profile as the typed [`Profile`] (always
    /// [`Profile::HttpsWeb`] given validation passed).
    pub fn typed_profile(&self) -> Profile {
        Profile::HttpsWeb
    }
}

/// Extract the host (authority minus userinfo/port) from an `https://`
/// URL without a URL-parsing dependency — we keep the supply chain lean.
///
/// Rejects non-`https` schemes (the `https_web` profile is HTTPS-only).
fn endpoint_host(url: &str) -> Result<String, RegistryError> {
    let rest = url.strip_prefix("https://").ok_or_else(|| {
        RegistryError::Bundle(format!("bundle_endpoint_url must be https://, got {url:?}"))
    })?;
    // Authority is up to the first '/', '?', or '#'.
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.is_empty() {
        return Err(RegistryError::Bundle(format!(
            "bundle_endpoint_url has empty host: {url:?}"
        )));
    }
    // Drop userinfo (before '@') and port (after ':').
    let after_userinfo = authority.rsplit('@').next().unwrap_or(authority);
    let host = after_userinfo.split(':').next().unwrap_or(after_userinfo);
    if host.is_empty() {
        return Err(RegistryError::Bundle(format!(
            "bundle_endpoint_url has empty host: {url:?}"
        )));
    }
    Ok(host.to_ascii_lowercase())
}

/// A fully-parsed enrollment for one trust domain: its metadata + the
/// parsed SPIFFE bundle.
#[derive(Debug, Clone)]
pub struct DomainEnrollment {
    /// The validated metadata.
    pub metadata: DomainMetadata,
    /// The parsed SPIFFE bundle (JWK Set + sequence). Reuses the inbound
    /// validator's [`SpiffeBundle`] so the same parser that gates live
    /// JWT-SVID validation gates enrollment.
    pub bundle: SpiffeBundle,
    /// The raw bundle bytes, retained for canonical-JSON leaf hashing in
    /// the transparency log.
    pub bundle_bytes: Vec<u8>,
}

impl DomainEnrollment {
    /// Load + validate one domain directory:
    /// `<dir>/{metadata.toml, bundle.json}`.
    ///
    /// Enforces that `metadata.trust_domain` matches the directory name —
    /// a mismatch is a layout error (so the directory name is not a
    /// second, unverified source of truth).
    pub fn load(dir: &Path) -> Result<Self, RegistryError> {
        let dir_name = dir
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| RegistryError::Layout(format!("bad domain dir name: {dir:?}")))?;

        let md_bytes = std::fs::read(dir.join(METADATA_FILE)).map_err(|e| {
            RegistryError::Metadata(format!("read {METADATA_FILE} in {dir_name}: {e}"))
        })?;
        let metadata = DomainMetadata::from_toml(&md_bytes)?;

        if metadata.trust_domain != dir_name {
            return Err(RegistryError::Layout(format!(
                "domain dir {dir_name:?} but metadata.trust_domain is {:?}",
                metadata.trust_domain
            )));
        }

        let bundle_bytes = std::fs::read(dir.join(BUNDLE_FILE))
            .map_err(|e| RegistryError::Bundle(format!("read {BUNDLE_FILE} in {dir_name}: {e}")))?;
        let bundle = SpiffeBundle::from_json(&bundle_bytes).map_err(|e| {
            RegistryError::Bundle(format!("parse {BUNDLE_FILE} in {dir_name}: {e}"))
        })?;

        Ok(Self {
            metadata,
            bundle,
            bundle_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
trust_domain = "ci.example.org"
owner_github_org = "coproduct-opensource"
owner_id = 12345
bundle_endpoint_url = "https://bundles.example.net/ci/bundle.json"
profile = "https_web"
"#;

    #[test]
    fn parses_good_metadata() {
        let md = DomainMetadata::from_toml(GOOD.as_bytes()).unwrap();
        assert_eq!(md.trust_domain, "ci.example.org");
        assert_eq!(md.owner_id, 12345);
        assert_eq!(md.typed_profile(), Profile::HttpsWeb);
    }

    #[test]
    fn rejects_missing_endpoint() {
        let toml = r#"
trust_domain = "ci.example.org"
owner_github_org = "org"
owner_id = 1
profile = "https_web"
"#;
        // serde reports the missing field as a metadata parse error.
        assert!(matches!(
            DomainMetadata::from_toml(toml.as_bytes()),
            Err(RegistryError::Metadata(_))
        ));
    }

    #[test]
    fn rejects_unsupported_profile() {
        let toml = GOOD.replace("https_web", "https_spiffe");
        assert!(matches!(
            DomainMetadata::from_toml(toml.as_bytes()),
            Err(RegistryError::UnsupportedProfile(_))
        ));
    }

    #[test]
    fn rejects_inferred_binding_host_equals_trust_domain() {
        let toml = r#"
trust_domain = "ci.example.org"
owner_github_org = "org"
owner_id = 1
bundle_endpoint_url = "https://ci.example.org/bundle"
profile = "https_web"
"#;
        assert!(matches!(
            DomainMetadata::from_toml(toml.as_bytes()),
            Err(RegistryError::InferredBinding { .. })
        ));
    }

    #[test]
    fn rejects_non_https_endpoint() {
        let toml = GOOD.replace("https://", "http://");
        assert!(matches!(
            DomainMetadata::from_toml(toml.as_bytes()),
            Err(RegistryError::Bundle(_))
        ));
    }

    #[test]
    fn endpoint_host_strips_port_and_path() {
        assert_eq!(
            endpoint_host("https://bundles.example.net:8443/a/b").unwrap(),
            "bundles.example.net"
        );
    }
}
