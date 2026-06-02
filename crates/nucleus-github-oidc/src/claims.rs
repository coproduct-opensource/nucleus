//! GitHub Actions OIDC claim schema + SPIFFE-id derivation.
//!
//! GitHub mints a token from `token.actions.githubusercontent.com` whenever
//! a workflow with `id-token: write` permission asks for one. The claims
//! describe the workflow's provenance: which repo, which ref, which
//! workflow file, which actor. This crate verifies the token and maps the
//! claims to a SPIFFE id Nucleus uses everywhere else.
//!
//! Reference:
//! <https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect#understanding-the-oidc-token>

use nucleus_lineage::CallSpiffeId;
use nucleus_oidc_core::OidcError;
use serde::Deserialize;

/// The verified claims a GitHub Actions OIDC token carries. Only the
/// fields Nucleus uses for identity + allowlisting are deserialized; the
/// rest are silently dropped.
#[derive(Debug, Clone, Deserialize)]
pub struct GitHubClaims {
    /// `repo:org/repo:ref:refs/heads/main` (subject identifier).
    pub sub: String,
    /// Audience the workflow asked for.
    pub aud: String,
    /// Issuer — always `https://token.actions.githubusercontent.com`.
    pub iss: String,
    /// JWT id (replay protection).
    pub jti: String,
    /// Expiry, unix seconds.
    pub exp: u64,
    /// `org/repo` — the repo the workflow runs in.
    pub repository: String,
    /// `org` — the repo's owner (an org or a user).
    pub repository_owner: String,
    /// Git ref the workflow runs against, e.g. `refs/heads/main`.
    #[serde(rename = "ref")]
    pub git_ref: String,
    /// The actor that triggered the run (a GitHub username).
    pub actor: String,
    /// The event that triggered the run (`push`, `pull_request`, …).
    pub event_name: String,
    /// Workflow filename ref, e.g. `octo-org/.github/workflows/x.yml@refs/heads/main`.
    #[serde(default)]
    pub job_workflow_ref: String,
}

/// Derive a Nucleus SPIFFE id from verified GitHub claims.
///
/// Shape: `spiffe://{trust_domain}/ns/github/sa/{owner}/{repo}/refs/{ref}`
///
/// Why this shape:
/// - `ns/github` segments off GitHub identities from Fly machine identities
///   (`ns/fly`) and builder identities (`ns/builders`).
/// - The full ref is included so a token minted by `refs/heads/main` is a
///   different SPIFFE id than one minted by `refs/heads/dev` — the bucket
///   partition can be scoped per branch if desired.
/// - The owner + repo come from the verified `repository` claim, never
///   from `sub` parsing (defense against a malicious workflow that tries
///   to spoof its subject string).
pub fn derive_spiffe_id(
    claims: &GitHubClaims,
    trust_domain: &str,
) -> Result<CallSpiffeId, OidcError> {
    let (owner, repo) = claims.repository.split_once('/').ok_or_else(|| {
        OidcError::SpiffeId(format!(
            "repository claim {:?} is not in the `org/repo` form",
            claims.repository
        ))
    })?;
    if claims.repository_owner != owner {
        // nucleus-oidc-core's neutral OidcError has no dedicated org-mismatch
        // variant; surface it as a SPIFFE-derivation failure (the verified
        // `repository_owner` claim disagrees with the `org` parsed out of the
        // `repository` claim, so we refuse to mint an identity for it).
        return Err(OidcError::SpiffeId(format!(
            "repository_owner {:?} does not match the org in repository {:?}",
            claims.repository_owner, claims.repository
        )));
    }
    let r#ref = sanitize_segment(&claims.git_ref);
    if r#ref.is_empty() {
        return Err(OidcError::SpiffeId(
            "ref claim was empty after sanitization".to_string(),
        ));
    }
    let owner = sanitize_segment(owner);
    let repo = sanitize_segment(repo);
    if owner.is_empty() || repo.is_empty() {
        return Err(OidcError::SpiffeId(
            "owner/repo were empty after sanitization".to_string(),
        ));
    }
    let path = format!(
        "spiffe://{trust_domain}/ns/github/sa/{owner}/{repo}/refs/{}",
        r#ref
    );
    CallSpiffeId::parse(&path).map_err(|e| OidcError::SpiffeId(e.to_string()))
}

/// SPIFFE path segments only allow `[a-zA-Z0-9._-]`. Map anything else to
/// `-` and collapse runs of `-`. The replacement is lossy on purpose —
/// GitHub refs can contain `/`, `:`, etc. The lossy mapping is fine
/// because the *verified* claim is what we authorize on, not the SPIFFE
/// id we render from it. The SPIFFE id is purely a downstream identifier.
fn sanitize_segment(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_dash = false;
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-' {
            out.push(ch);
            prev_dash = ch == '-';
        } else {
            if !prev_dash {
                out.push('-');
            }
            prev_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_claims(repo: &str, owner: &str, git_ref: &str) -> GitHubClaims {
        GitHubClaims {
            sub: format!("repo:{repo}:ref:{git_ref}"),
            aud: "nucleus.io".to_string(),
            iss: "https://token.actions.githubusercontent.com".to_string(),
            jti: "j1".to_string(),
            exp: 9_999_999_999,
            repository: repo.to_string(),
            repository_owner: owner.to_string(),
            git_ref: git_ref.to_string(),
            actor: "octocat".to_string(),
            event_name: "push".to_string(),
            job_workflow_ref: String::new(),
        }
    }

    #[test]
    fn derive_main_ref_yields_expected_spiffe_id() {
        let c = sample_claims(
            "coproduct-opensource/nucleus-agent-starter",
            "coproduct-opensource",
            "refs/heads/main",
        );
        let id = derive_spiffe_id(&c, "nucleus.io").unwrap();
        assert_eq!(
            id.as_str(),
            "spiffe://nucleus.io/ns/github/sa/coproduct-opensource/nucleus-agent-starter/refs/refs-heads-main"
        );
    }

    #[test]
    fn derive_pr_ref_with_slashes_sanitized() {
        let c = sample_claims("org/r", "org", "refs/pull/42/merge");
        let id = derive_spiffe_id(&c, "nucleus.io").unwrap();
        assert_eq!(
            id.as_str(),
            "spiffe://nucleus.io/ns/github/sa/org/r/refs/refs-pull-42-merge"
        );
    }

    #[test]
    fn derive_rejects_repository_with_no_slash() {
        let mut c = sample_claims("org/r", "org", "refs/heads/main");
        c.repository = "no-slash".to_string();
        let err = derive_spiffe_id(&c, "nucleus.io").unwrap_err();
        assert!(matches!(err, OidcError::SpiffeId(_)));
    }

    #[test]
    fn derive_rejects_owner_mismatch() {
        let mut c = sample_claims("org/r", "different-org", "refs/heads/main");
        c.repository = "org/r".to_string();
        let err = derive_spiffe_id(&c, "nucleus.io").unwrap_err();
        assert!(matches!(err, OidcError::SpiffeId(_)));
    }

    #[test]
    fn sanitize_collapses_runs() {
        assert_eq!(sanitize_segment("a//b"), "a-b");
        assert_eq!(sanitize_segment("a---b"), "a---b"); // already valid dashes preserved
        assert_eq!(sanitize_segment("/a/"), "a");
        assert_eq!(sanitize_segment("a:b:c"), "a-b-c");
    }
}
