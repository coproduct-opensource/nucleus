//! Fly.io OIDC token claims and SPIFFE ID derivation.

use std::collections::BTreeMap;

use nucleus_lineage::CallSpiffeId;
use serde::{Deserialize, Serialize};

use crate::error::OidcError;

/// Claims carried by a Fly.io machine OIDC token.
///
/// Field names match Fly's token exactly. Claims beyond the ones used here —
/// `app_id`, `org_id`, `image`, `image_digest`, `aud`, ... — are captured
/// untyped in [`Self::extra`], so a real token can never fail to deserialize
/// on an unmodeled field or an unexpected JSON type.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FlyClaims {
    /// Token issuer, `https://oidc.fly.io/<org-slug>`.
    pub iss: String,
    /// Subject, formatted `"<org-name>:<app-name>:<machine-name>"`.
    pub sub: String,
    /// Expiry, unix seconds.
    pub exp: u64,
    /// Issued-at, unix seconds.
    pub iat: u64,
    /// Not-before, unix seconds.
    pub nbf: u64,
    /// Unique token id; used for replay protection.
    pub jti: String,
    /// Fly application name (slug).
    pub app_name: String,
    /// Fly machine id.
    pub machine_id: String,
    /// Fly organization name (slug).
    pub org_name: String,
    /// Fly machine name.
    #[serde(default)]
    pub machine_name: String,
    /// Fly region code (e.g. `ord`).
    #[serde(default)]
    pub region: String,
    /// Any further claims, captured untyped.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

/// The `<org>:<app>:<machine>` triple parsed out of a `sub` claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubParts {
    /// Organization name.
    pub org: String,
    /// Application name.
    pub app: String,
    /// Machine name.
    pub machine: String,
}

/// Parse a Fly `sub` claim (`"<org>:<app>:<machine>"`). Returns `None` if the
/// claim does not have exactly three non-empty colon-separated parts.
pub fn parse_sub(sub: &str) -> Option<SubParts> {
    let mut parts = sub.splitn(3, ':');
    let org = parts.next()?.to_string();
    let app = parts.next()?.to_string();
    let machine = parts.next()?.to_string();
    if org.is_empty() || app.is_empty() || machine.is_empty() {
        return None;
    }
    Some(SubParts { org, app, machine })
}

/// Derive the SPIFFE identity a Nucleus runner runs under from validated
/// claims:
///
/// ```text
/// spiffe://<trust_domain>/ns/fly/sa/<app_name>/<machine_id>
/// ```
pub fn derive_spiffe_id(claims: &FlyClaims, trust_domain: &str) -> Result<CallSpiffeId, OidcError> {
    let app = sanitize_segment(&claims.app_name);
    let machine = sanitize_segment(&claims.machine_id);
    if app.is_empty() || machine.is_empty() {
        return Err(OidcError::SpiffeId(
            "app_name and machine_id must both be non-empty".to_string(),
        ));
    }
    CallSpiffeId::parse(format!("spiffe://{trust_domain}/ns/fly/sa/{app}/{machine}"))
        .map_err(|e| OidcError::SpiffeId(e.to_string()))
}

/// Map any character outside the SPIFFE path-segment charset `[A-Za-z0-9._-]`
/// to `-`. Fly app names and machine ids already satisfy the charset; this is
/// defense in depth against a malformed claim.
fn sanitize_segment(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(app: &str, machine: &str) -> FlyClaims {
        FlyClaims {
            iss: "https://oidc.fly.io/test-org".to_string(),
            sub: format!("test-org:{app}:{machine}-name"),
            exp: 0,
            iat: 0,
            nbf: 0,
            jti: "jti-1".to_string(),
            app_name: app.to_string(),
            machine_id: machine.to_string(),
            org_name: "test-org".to_string(),
            machine_name: format!("{machine}-name"),
            region: "ord".to_string(),
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn parse_sub_splits_three_parts() {
        let p = parse_sub("acme:weather-bot:abc123").unwrap();
        assert_eq!(p.org, "acme");
        assert_eq!(p.app, "weather-bot");
        assert_eq!(p.machine, "abc123");
    }

    #[test]
    fn parse_sub_rejects_too_few_parts() {
        assert!(parse_sub("acme:weather-bot").is_none());
        assert!(parse_sub("acme").is_none());
        assert!(parse_sub("").is_none());
    }

    #[test]
    fn parse_sub_rejects_empty_component() {
        assert!(parse_sub("acme::abc123").is_none());
    }

    #[test]
    fn derive_spiffe_id_builds_expected_path() {
        let id = derive_spiffe_id(&claims("weather-bot", "148ed193b14e89"), "nucleus.io").unwrap();
        assert_eq!(
            id.as_str(),
            "spiffe://nucleus.io/ns/fly/sa/weather-bot/148ed193b14e89"
        );
    }

    #[test]
    fn derive_spiffe_id_rejects_empty_app() {
        let err = derive_spiffe_id(&claims("", "m1"), "nucleus.io").unwrap_err();
        assert!(matches!(err, OidcError::SpiffeId(_)));
    }

    #[test]
    fn sanitize_segment_replaces_invalid_chars() {
        assert_eq!(sanitize_segment("weather-bot"), "weather-bot");
        assert_eq!(sanitize_segment("a b/c"), "a-b-c");
    }

    #[test]
    fn fly_claims_deserializes_with_unmodeled_fields() {
        // A token with extra claims (app_id numeric, image string) must still
        // parse — the unmodeled ones land in `extra`.
        let json = r#"{
            "iss": "https://oidc.fly.io/acme",
            "sub": "acme:bot:m1-name",
            "exp": 100, "iat": 1, "nbf": 1, "jti": "j1",
            "app_name": "bot", "machine_id": "m1", "org_name": "acme",
            "app_id": 12345,
            "image": "registry.fly.io/bot:deployment-01"
        }"#;
        let claims: FlyClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.app_name, "bot");
        assert!(claims.extra.contains_key("app_id"));
        assert!(claims.extra.contains_key("image"));
    }
}
