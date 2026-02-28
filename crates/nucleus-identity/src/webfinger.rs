//! WebFinger discovery protocol types (RFC 7033).
//!
//! WebFinger enables discovery of identity resources using the
//! `/.well-known/webfinger` endpoint. For SPIFFE-DID integration,
//! WebFinger maps a SPIFFE ID (as `acct:` or `spiffe:` URI) to the
//! corresponding `did:web` document URL.
//!
//! # WebFinger Flow
//!
//! ```text
//! GET /.well-known/webfinger?resource=spiffe://example.com/ns/apps/sa/my-app
//!
//! {
//!   "subject": "spiffe://example.com/ns/apps/sa/my-app",
//!   "links": [
//!     {
//!       "rel": "self",
//!       "type": "application/did+ld+json",
//!       "href": "https://my-app.example.com/.well-known/did.json"
//!     },
//!     {
//!       "rel": "describedby",
//!       "type": "application/json",
//!       "href": "https://my-app.example.com/.well-known/spiffe-did-binding.json"
//!     }
//!   ]
//! }
//! ```
//!
//! # Example
//!
//! ```
//! use nucleus_identity::webfinger::{WebFingerResponse, WebFingerLink};
//!
//! let response = WebFingerResponse::for_spiffe_did(
//!     "spiffe://example.com/ns/apps/sa/my-app",
//!     "did:web:my-app.example.com",
//! );
//!
//! assert_eq!(response.subject, "spiffe://example.com/ns/apps/sa/my-app");
//! assert_eq!(response.links.len(), 2);
//! assert_eq!(response.links[0].rel, "self");
//! ```

use serde::{Deserialize, Serialize};

use crate::did::did_web_to_url;

/// A WebFinger JSON Resource Descriptor (JRD) response per RFC 7033.
///
/// This is the JSON document returned by `/.well-known/webfinger`
/// endpoints when queried for a resource.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebFingerResponse {
    /// The URI of the resource being described.
    pub subject: String,

    /// Optional aliases for the subject.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aliases: Option<Vec<String>>,

    /// Links related to the subject resource.
    pub links: Vec<WebFingerLink>,
}

/// A link in a WebFinger response.
///
/// Per RFC 7033, each link has a relation type and typically an href
/// pointing to the related resource.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebFingerLink {
    /// Link relation type (e.g., `"self"`, `"describedby"`).
    pub rel: String,

    /// Media type of the target resource.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,

    /// URI of the target resource.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub href: Option<String>,
}

impl WebFingerResponse {
    /// Create a WebFinger response mapping a SPIFFE ID to its did:web document.
    ///
    /// Generates two links:
    /// 1. `self` → the DID document URL (`application/did+ld+json`)
    /// 2. `describedby` → the SPIFFE-DID binding document (`application/json`)
    ///
    /// Both URLs are derived from the `did:web` identifier using the
    /// standard resolution rules.
    ///
    /// # Panics
    ///
    /// Panics if the DID is not a valid `did:web` identifier (use
    /// [`try_for_spiffe_did`](Self::try_for_spiffe_did) for fallible construction).
    pub fn for_spiffe_did(spiffe_id: &str, did: &str) -> Self {
        Self::try_for_spiffe_did(spiffe_id, did).expect("invalid did:web identifier")
    }

    /// Try to create a WebFinger response mapping a SPIFFE ID to its did:web document.
    ///
    /// Returns an error if the DID is not a valid `did:web` identifier.
    pub fn try_for_spiffe_did(spiffe_id: &str, did: &str) -> crate::Result<Self> {
        let did_url = did_web_to_url(did)?;

        // The binding URL is alongside the DID doc at /.well-known/
        let binding_url = did_url.replace("did.json", "spiffe-did-binding.json");

        Ok(Self {
            subject: spiffe_id.to_string(),
            aliases: Some(vec![did.to_string()]),
            links: vec![
                WebFingerLink {
                    rel: "self".into(),
                    media_type: Some("application/did+ld+json".into()),
                    href: Some(did_url),
                },
                WebFingerLink {
                    rel: "describedby".into(),
                    media_type: Some("application/json".into()),
                    href: Some(binding_url),
                },
            ],
        })
    }

    /// Find the first link with the given relation type.
    pub fn find_link(&self, rel: &str) -> Option<&WebFingerLink> {
        self.links.iter().find(|l| l.rel == rel)
    }

    /// Get the DID document URL (the `self` link's href).
    pub fn did_document_url(&self) -> Option<&str> {
        self.find_link("self").and_then(|l| l.href.as_deref())
    }

    /// Get the SPIFFE-DID binding URL (the `describedby` link's href).
    pub fn binding_url(&self) -> Option<&str> {
        self.find_link("describedby")
            .and_then(|l| l.href.as_deref())
    }
}

/// Parse a WebFinger query resource parameter.
///
/// Validates that the resource is either a `spiffe://` URI or an `acct:` URI,
/// and returns the normalized resource identifier.
///
/// # Errors
///
/// Returns an error if the resource scheme is not recognized.
pub fn parse_webfinger_resource(resource: &str) -> crate::Result<WebFingerResource> {
    if resource.starts_with("spiffe://") {
        Ok(WebFingerResource::SpiffeId(resource.to_string()))
    } else if resource.starts_with("acct:") {
        Ok(WebFingerResource::Account(resource.to_string()))
    } else if resource.starts_with("did:web:") {
        Ok(WebFingerResource::Did(resource.to_string()))
    } else {
        Err(crate::Error::InvalidSpiffeUri(format!(
            "unsupported WebFinger resource scheme: {resource}"
        )))
    }
}

/// A parsed WebFinger resource identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebFingerResource {
    /// A SPIFFE ID (e.g., `spiffe://example.com/ns/apps/sa/my-app`).
    SpiffeId(String),
    /// An account URI (e.g., `acct:user@example.com`).
    Account(String),
    /// A DID (e.g., `did:web:app.example.com`).
    Did(String),
}

impl WebFingerResource {
    /// Returns the raw resource URI string.
    pub fn as_str(&self) -> &str {
        match self {
            Self::SpiffeId(s) | Self::Account(s) | Self::Did(s) => s,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webfinger_for_spiffe_did() {
        let response = WebFingerResponse::for_spiffe_did(
            "spiffe://example.com/ns/apps/sa/my-app",
            "did:web:my-app.example.com",
        );

        assert_eq!(response.subject, "spiffe://example.com/ns/apps/sa/my-app");
        assert_eq!(
            response.aliases,
            Some(vec!["did:web:my-app.example.com".into()])
        );
        assert_eq!(response.links.len(), 2);

        // Self link → DID document
        let self_link = response.find_link("self").unwrap();
        assert_eq!(
            self_link.href.as_deref(),
            Some("https://my-app.example.com/.well-known/did.json")
        );
        assert_eq!(
            self_link.media_type.as_deref(),
            Some("application/did+ld+json")
        );

        // Describedby link → binding document
        let binding_link = response.find_link("describedby").unwrap();
        assert_eq!(
            binding_link.href.as_deref(),
            Some("https://my-app.example.com/.well-known/spiffe-did-binding.json")
        );
    }

    #[test]
    fn webfinger_serde_roundtrip() {
        let response =
            WebFingerResponse::for_spiffe_did("spiffe://dev/ns/x/sa/app", "did:web:app.dev");

        let json = serde_json::to_string_pretty(&response).unwrap();
        let parsed: WebFingerResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, response);
    }

    #[test]
    fn webfinger_json_structure() {
        let response =
            WebFingerResponse::for_spiffe_did("spiffe://dev/ns/x/sa/app", "did:web:app.dev");

        let json: serde_json::Value = serde_json::to_value(&response).unwrap();

        assert_eq!(json["subject"], "spiffe://dev/ns/x/sa/app");
        assert!(json["aliases"].is_array());
        assert!(json["links"].is_array());
        assert_eq!(json["links"][0]["rel"], "self");
        assert_eq!(json["links"][0]["type"], "application/did+ld+json");
        assert_eq!(json["links"][1]["rel"], "describedby");
    }

    #[test]
    fn webfinger_helper_methods() {
        let response =
            WebFingerResponse::for_spiffe_did("spiffe://dev/ns/x/sa/app", "did:web:app.dev");

        assert_eq!(
            response.did_document_url(),
            Some("https://app.dev/.well-known/did.json")
        );
        assert_eq!(
            response.binding_url(),
            Some("https://app.dev/.well-known/spiffe-did-binding.json")
        );
    }

    #[test]
    fn webfinger_with_subpath() {
        let response = WebFingerResponse::for_spiffe_did(
            "spiffe://dev/ns/x/sa/app",
            "did:web:example.com:apps:my-app",
        );

        assert_eq!(
            response.did_document_url(),
            Some("https://example.com/apps/my-app/did.json")
        );
        assert_eq!(
            response.binding_url(),
            Some("https://example.com/apps/my-app/spiffe-did-binding.json")
        );
    }

    #[test]
    fn webfinger_invalid_did_returns_error() {
        let result =
            WebFingerResponse::try_for_spiffe_did("spiffe://dev/ns/x/sa/app", "did:key:abc123");
        assert!(result.is_err());
    }

    // ── parse_webfinger_resource ─────────────────────────────────────────

    #[test]
    fn parse_spiffe_resource() {
        let res = parse_webfinger_resource("spiffe://example.com/ns/apps/sa/my-app").unwrap();
        assert!(matches!(res, WebFingerResource::SpiffeId(_)));
        assert_eq!(res.as_str(), "spiffe://example.com/ns/apps/sa/my-app");
    }

    #[test]
    fn parse_acct_resource() {
        let res = parse_webfinger_resource("acct:user@example.com").unwrap();
        assert!(matches!(res, WebFingerResource::Account(_)));
        assert_eq!(res.as_str(), "acct:user@example.com");
    }

    #[test]
    fn parse_did_resource() {
        let res = parse_webfinger_resource("did:web:app.example.com").unwrap();
        assert!(matches!(res, WebFingerResource::Did(_)));
        assert_eq!(res.as_str(), "did:web:app.example.com");
    }

    #[test]
    fn parse_unknown_resource_fails() {
        let result = parse_webfinger_resource("https://example.com/foo");
        assert!(result.is_err());
    }

    #[test]
    fn find_link_returns_none_for_missing_rel() {
        let response =
            WebFingerResponse::for_spiffe_did("spiffe://dev/ns/x/sa/app", "did:web:app.dev");
        assert!(response.find_link("nonexistent").is_none());
    }
}
