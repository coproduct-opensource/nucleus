// SPDX-License-Identifier: MIT
//
//! Proof-of-control: verify a GitHub Actions OIDC token binds the
//! enrolling PR to the GitHub identity named in `metadata.toml`.
//!
//! # What this proves (honest scope)
//!
//! This proves the PR was produced by a workflow running **inside a
//! GitHub repository owned by the org whose numeric id is pinned in the
//! metadata**. It anchors enrollment authority to a GitHub identity.
//!
//! It does **NOT** prove the enroller owns the SPIFFE trust domain. A
//! DNS-01-style trust-domain proof is v2 (see crate docs). Do not read
//! more into a green proof than "the GitHub org with this numeric id
//! authorized this binding".
//!
//! # The verification (alg-pinned, fail-closed)
//!
//! Mirrors the alg-pinned `jsonwebtoken` pattern in
//! `nucleus-oidc-core::spiffe_federation`: the algorithm is checked
//! against an allowlist BEFORE any key work; the issuer must be exactly
//! GitHub's; `exp` is enforced; and — the squat-proof pin — the NUMERIC
//! `repository_owner_id` claim must equal `metadata.owner_id` AND the
//! string `repository_owner` must equal `metadata.owner_github_org`.
//!
//! The verifying key is selected from the supplied GitHub JWKS by `kid`
//! only; nothing in the token chooses its own key.

use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use nucleus_oidc_core::Jwks;
use serde::Deserialize;

use crate::error::RegistryError;
use crate::metadata::DomainMetadata;

/// The canonical GitHub Actions OIDC issuer. A token whose `iss` is not
/// exactly this is rejected (GitHub Enterprise is out of scope for v1).
pub const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// GitHub Actions OIDC tokens are RS256. We pin exactly that one
/// algorithm — the tightest possible allowlist, defeating algorithm
/// confusion (RFC 8725 §3.1). `none`/EdDSA/HS* are structurally
/// unreachable because they are not in this set and the check runs before
/// any key material is touched.
pub const ALLOWED_ALGS: &[Algorithm] = &[Algorithm::RS256];

/// The subset of GitHub OIDC claims proof-of-control reads.
///
/// The load-bearing field is `repository_owner_id` — the GitHub NUMERIC
/// org id, which survives an org rename and so defeats org-rename
/// squatting. `repository_owner` (the login string) is checked too as a
/// belt-and-suspenders human-readable cross-check.
#[derive(Debug, Clone, Deserialize)]
pub struct ProofClaims {
    /// Issuer — must be exactly [`GITHUB_ISSUER`].
    pub iss: String,
    /// Expiry (unix seconds). Enforced by jsonwebtoken.
    pub exp: u64,
    /// `org/repo` the workflow runs in (diagnostics only).
    #[serde(default)]
    pub repository: String,
    /// The org/user login that owns the repo. Cross-checked against
    /// `metadata.owner_github_org`.
    pub repository_owner: String,
    /// The NUMERIC owner id. GitHub serializes this as a JSON string;
    /// we parse it to u64 and pin it against `metadata.owner_id`.
    #[serde(deserialize_with = "de_stringy_u64")]
    pub repository_owner_id: u64,
}

/// GitHub serializes `repository_owner_id` as a JSON string (e.g.
/// `"12345"`). Accept either a string or a number so a test minting a
/// numeric claim and a real GitHub token both parse.
fn de_stringy_u64<'de, D>(d: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrU64 {
        Str(String),
        Num(u64),
    }
    match StringOrU64::deserialize(d)? {
        StringOrU64::Num(n) => Ok(n),
        StringOrU64::Str(s) => s.parse::<u64>().map_err(D::Error::custom),
    }
}

/// Verify a GitHub Actions OIDC token proves control of the GitHub
/// identity pinned in `metadata`.
///
/// Steps (every one fails closed, in order):
/// 1. Decode header WITHOUT verifying; assert `alg ∈ ALLOWED_ALGS`.
/// 2. Resolve the verifying key for `header.kid` from `github_jwks`
///    (RSA only). No `kid`, or a `kid` not in the JWKS → reject.
/// 3. Verify the signature under the pinned RS256, requiring `exp`,
///    `iss`, `aud`, validating `exp` (so an expired token is rejected),
///    and pinning `iss == GITHUB_ISSUER`.
/// 4. Pin `repository_owner_id == metadata.owner_id` (NUMERIC — defeats
///    org-rename squatting) AND `repository_owner ==
///    metadata.owner_github_org`.
///
/// Returns the verified [`ProofClaims`] on success.
pub fn verify_proof_of_control(
    oidc_token: &str,
    metadata: &DomainMetadata,
    github_jwks: &Jwks,
) -> Result<ProofClaims, RegistryError> {
    // (1) header WITHOUT verifying; alg allowlist before any key work.
    let header = decode_header(oidc_token)
        .map_err(|e| RegistryError::ProofOfControl(format!("malformed token header: {e}")))?;
    if !ALLOWED_ALGS.contains(&header.alg) {
        return Err(RegistryError::ProofOfControl(format!(
            "algorithm {:?} not accepted (RS256 only)",
            header.alg
        )));
    }
    let kid = header
        .kid
        .ok_or_else(|| RegistryError::ProofOfControl("token header has no kid".to_string()))?;

    // (2) select the verifying key from the supplied GitHub JWKS BY KID
    // ONLY. Nothing in the token picks its own key.
    let jwk = github_jwks
        .keys
        .iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| {
            RegistryError::ProofOfControl(format!("no GitHub JWKS key for kid {kid:?}"))
        })?;
    let decoding_key = match jwk.kty.as_str() {
        "RSA" => {
            let n = jwk.n.as_deref().ok_or_else(|| {
                RegistryError::ProofOfControl("GitHub RSA jwk missing `n`".to_string())
            })?;
            let e = jwk.e.as_deref().ok_or_else(|| {
                RegistryError::ProofOfControl("GitHub RSA jwk missing `e`".to_string())
            })?;
            DecodingKey::from_rsa_components(n, e).map_err(|err| {
                RegistryError::ProofOfControl(format!("bad GitHub RSA components: {err}"))
            })?
        }
        other => {
            return Err(RegistryError::ProofOfControl(format!(
                "GitHub OIDC key type {other:?} not usable for RS256"
            )))
        }
    };

    // (3) verify signature + registered claims under the pinned alg.
    let mut validation = Validation::new(header.alg);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    validation.validate_exp = true;
    validation.leeway = 60;
    validation.set_issuer(&[GITHUB_ISSUER]);
    // The enroller asks for an audience; we don't pin a specific aud here
    // (the workflow chooses it), but `aud` MUST be present (required spec
    // claim above). Disable jsonwebtoken's aud match since any audience
    // the enroller chose is acceptable for proof-of-control.
    validation.validate_aud = false;

    let data = decode::<ProofClaims>(oidc_token, &decoding_key, &validation).map_err(|e| {
        RegistryError::ProofOfControl(format!("signature/claim validation failed: {e}"))
    })?;
    let claims = data.claims;

    // Defense in depth: jsonwebtoken already pinned `iss`, but assert it
    // explicitly so the invariant is local + testable.
    if claims.iss != GITHUB_ISSUER {
        return Err(RegistryError::ProofOfControl(format!(
            "issuer {:?} is not the GitHub Actions OIDC issuer",
            claims.iss
        )));
    }

    // (4) THE squat-proof pin: numeric owner id, then login cross-check.
    if claims.repository_owner_id != metadata.owner_id {
        return Err(RegistryError::ProofOfControl(format!(
            "repository_owner_id {} does not match metadata owner_id {} (org-rename squat defense)",
            claims.repository_owner_id, metadata.owner_id
        )));
    }
    if claims.repository_owner != metadata.owner_github_org {
        return Err(RegistryError::ProofOfControl(format!(
            "repository_owner {:?} does not match metadata owner_github_org {:?}",
            claims.repository_owner, metadata.owner_github_org
        )));
    }

    Ok(claims)
}
