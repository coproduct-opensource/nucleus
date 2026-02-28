//! DID Document types for the did:web method.
//!
//! Provides W3C DID Core v1.0 types for representing Decentralized Identifier
//! documents, verification methods, and service endpoints. These types are
//! vendor-agnostic and can represent any did:web document.
//!
//! # did:web Method
//!
//! The `did:web` method uses the domain name system as a trust anchor.
//! Resolution converts a DID to an HTTPS URL:
//!
//! ```text
//! did:web:example.com        → https://example.com/.well-known/did.json
//! did:web:example.com:path   → https://example.com/path/did.json
//! ```
//!
//! # SPIFFE Mapping
//!
//! SPIFFE identities map deterministically to did:web identifiers:
//!
//! ```text
//! spiffe://groundtruth.dev/ns/apps/sa/music-app  →  did:web:music-app.groundtruth.dev
//! ```
//!
//! See [`Identity::to_did_web`] and [`Identity::from_did_web`] for the mapping.
//!
//! # Example
//!
//! ```
//! use nucleus_identity::did::{DidDocument, VerificationMethod, JsonWebKey, ServiceEndpoint};
//!
//! let doc = DidDocument {
//!     context: vec![
//!         "https://www.w3.org/ns/did/v1".into(),
//!         "https://w3id.org/security/suites/jws-2020/v1".into(),
//!     ],
//!     id: "did:web:music-app.groundtruth.dev".into(),
//!     verification_method: vec![VerificationMethod {
//!         id: "did:web:music-app.groundtruth.dev#key-1".into(),
//!         method_type: "JsonWebKey2020".into(),
//!         controller: "did:web:music-app.groundtruth.dev".into(),
//!         public_key_jwk: JsonWebKey {
//!             kty: "EC".into(),
//!             crv: "P-256".into(),
//!             x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU".into(),
//!             y: Some("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0".into()),
//!             kid: Some("key-1".into()),
//!             alg: Some("ES256".into()),
//!         },
//!     }],
//!     authentication: Some(vec!["did:web:music-app.groundtruth.dev#key-1".into()]),
//!     assertion_method: Some(vec!["did:web:music-app.groundtruth.dev#key-1".into()]),
//!     key_agreement: None,
//!     service: Some(vec![ServiceEndpoint {
//!         id: "did:web:music-app.groundtruth.dev#api".into(),
//!         service_type: "RestApi".into(),
//!         service_endpoint: "https://music-app.groundtruth.dev/api/v1".into(),
//!         description: None,
//!     }]),
//! };
//!
//! let json = serde_json::to_string_pretty(&doc).unwrap();
//! assert!(json.contains("did:web:music-app.groundtruth.dev"));
//! ```

use serde::{Deserialize, Serialize};

use crate::{Error, Result};

/// A DID Document conforming to W3C DID Core v1.0.
///
/// The document is the primary artifact of the did:web method — served at
/// `/.well-known/did.json` for root domains or `/{path}/did.json` for sub-paths.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DidDocument {
    /// JSON-LD context(s). Must include `"https://www.w3.org/ns/did/v1"`.
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    /// The DID subject (e.g., `"did:web:music-app.groundtruth.dev"`).
    pub id: String,

    /// Verification methods (public keys) associated with this DID.
    #[serde(rename = "verificationMethod")]
    pub verification_method: Vec<VerificationMethod>,

    /// Key IDs authorized for authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<String>>,

    /// Key IDs authorized for making assertions (signing claims).
    #[serde(rename = "assertionMethod", skip_serializing_if = "Option::is_none")]
    pub assertion_method: Option<Vec<String>>,

    /// Key IDs authorized for key agreement (encryption).
    #[serde(rename = "keyAgreement", skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<Vec<String>>,

    /// Service endpoints associated with this DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<Vec<ServiceEndpoint>>,
}

impl DidDocument {
    /// Create a minimal DID document with the standard context.
    pub fn new(did: impl Into<String>) -> Self {
        Self {
            context: vec!["https://www.w3.org/ns/did/v1".into()],
            id: did.into(),
            verification_method: Vec::new(),
            authentication: None,
            assertion_method: None,
            key_agreement: None,
            service: None,
        }
    }

    /// Find a verification method by its key ID fragment (e.g., `"key-1"`).
    pub fn find_verification_method(&self, fragment: &str) -> Option<&VerificationMethod> {
        let full_id = if fragment.starts_with(&self.id) {
            fragment.to_string()
        } else {
            format!("{}#{}", self.id, fragment)
        };
        self.verification_method.iter().find(|vm| vm.id == full_id)
    }
}

/// A verification method (public key) in a DID Document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VerificationMethod {
    /// Unique identifier (DID URL with fragment, e.g., `"did:web:...#key-1"`).
    pub id: String,

    /// The verification method type (e.g., `"JsonWebKey2020"`).
    #[serde(rename = "type")]
    pub method_type: String,

    /// The DID that controls this key.
    pub controller: String,

    /// The public key in JWK format (RFC 7517).
    /// MUST NOT contain the `"d"` (private key) parameter.
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: JsonWebKey,
}

/// A JSON Web Key (RFC 7517) for public keys only.
///
/// Supports EC (P-256) keys used by SPIFFE SVIDs. The `d` parameter
/// (private key material) is intentionally excluded from this type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JsonWebKey {
    /// Key type (e.g., `"EC"`, `"OKP"`).
    pub kty: String,

    /// Curve (e.g., `"P-256"`, `"Ed25519"`).
    pub crv: String,

    /// Public key X coordinate (base64url-encoded).
    pub x: String,

    /// Public key Y coordinate (base64url-encoded, EC keys only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,

    /// Key ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// Algorithm (e.g., `"ES256"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
}

impl JsonWebKey {
    /// Create a new EC P-256 JWK from base64url-encoded coordinates.
    pub fn ec_p256(x: impl Into<String>, y: impl Into<String>) -> Self {
        Self {
            kty: "EC".into(),
            crv: "P-256".into(),
            x: x.into(),
            y: Some(y.into()),
            kid: None,
            alg: None,
        }
    }
}

/// A service endpoint in a DID Document.
///
/// Service endpoints describe APIs, messaging, or other capabilities
/// offered by the DID subject.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceEndpoint {
    /// Service ID (DID URL with fragment).
    pub id: String,

    /// Service type (e.g., `"RestApi"`, `"GrpcService"`, `"SpiffeBinding"`).
    #[serde(rename = "type")]
    pub service_type: String,

    /// Endpoint URL.
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,

    /// Optional human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Convert a `did:web` identifier to its HTTPS resolution URL.
///
/// Per the [did:web specification](https://w3c-ccg.github.io/did-method-web/):
/// - `did:web:example.com` → `https://example.com/.well-known/did.json`
/// - `did:web:example.com:path:to` → `https://example.com/path/to/did.json`
/// - Port-encoded: `did:web:example.com%3A3000` → `https://example.com:3000/.well-known/did.json`
///
/// # Errors
///
/// Returns an error if the DID doesn't start with `did:web:` or has an empty domain.
pub fn did_web_to_url(did: &str) -> Result<String> {
    let method_specific = did
        .strip_prefix("did:web:")
        .ok_or_else(|| Error::InvalidSpiffeUri("DID must start with did:web:".into()))?;

    if method_specific.is_empty() {
        return Err(Error::InvalidSpiffeUri(
            "empty method-specific identifier".into(),
        ));
    }

    // Split on colons — first segment is the domain, rest form the path
    let parts: Vec<&str> = method_specific.split(':').collect();

    // Percent-decode the domain (e.g., %3A → : for port numbers)
    let domain = parts[0].replace("%3A", ":").replace("%3a", ":");

    if parts.len() == 1 {
        // Root domain → /.well-known/did.json
        Ok(format!("https://{domain}/.well-known/did.json"))
    } else {
        // Sub-path → /{path}/did.json
        let path = parts[1..].join("/");
        Ok(format!("https://{domain}/{path}/did.json"))
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// TESTS
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_document_new() {
        let doc = DidDocument::new("did:web:example.com");
        assert_eq!(doc.id, "did:web:example.com");
        assert_eq!(doc.context, vec!["https://www.w3.org/ns/did/v1"]);
        assert!(doc.verification_method.is_empty());
        assert!(doc.service.is_none());
    }

    #[test]
    fn did_document_serde_roundtrip() {
        let doc = DidDocument {
            context: vec![
                "https://www.w3.org/ns/did/v1".into(),
                "https://w3id.org/security/suites/jws-2020/v1".into(),
            ],
            id: "did:web:music-app.groundtruth.dev".into(),
            verification_method: vec![VerificationMethod {
                id: "did:web:music-app.groundtruth.dev#key-1".into(),
                method_type: "JsonWebKey2020".into(),
                controller: "did:web:music-app.groundtruth.dev".into(),
                public_key_jwk: JsonWebKey::ec_p256("abc123", "def456"),
            }],
            authentication: Some(vec!["did:web:music-app.groundtruth.dev#key-1".into()]),
            assertion_method: None,
            key_agreement: None,
            service: Some(vec![ServiceEndpoint {
                id: "did:web:music-app.groundtruth.dev#api".into(),
                service_type: "RestApi".into(),
                service_endpoint: "https://music-app.groundtruth.dev/api/v1".into(),
                description: None,
            }]),
        };

        let json = serde_json::to_string(&doc).unwrap();
        let parsed: DidDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, doc);
    }

    #[test]
    fn did_document_json_field_names() {
        let doc = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".into()],
            id: "did:web:example.com".into(),
            verification_method: vec![VerificationMethod {
                id: "did:web:example.com#key-1".into(),
                method_type: "JsonWebKey2020".into(),
                controller: "did:web:example.com".into(),
                public_key_jwk: JsonWebKey::ec_p256("x", "y"),
            }],
            authentication: None,
            assertion_method: Some(vec!["did:web:example.com#key-1".into()]),
            key_agreement: None,
            service: None,
        };

        let json = serde_json::to_string(&doc).unwrap();

        // Verify W3C field names
        assert!(json.contains("\"@context\""));
        assert!(json.contains("\"verificationMethod\""));
        assert!(json.contains("\"publicKeyJwk\""));
        assert!(json.contains("\"assertionMethod\""));
        // Absent optionals should not appear
        assert!(!json.contains("\"authentication\""));
        assert!(!json.contains("\"keyAgreement\""));
        assert!(!json.contains("\"service\""));
    }

    #[test]
    fn did_document_find_verification_method() {
        let doc = DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".into()],
            id: "did:web:app.dev".into(),
            verification_method: vec![
                VerificationMethod {
                    id: "did:web:app.dev#key-1".into(),
                    method_type: "JsonWebKey2020".into(),
                    controller: "did:web:app.dev".into(),
                    public_key_jwk: JsonWebKey::ec_p256("a", "b"),
                },
                VerificationMethod {
                    id: "did:web:app.dev#key-2".into(),
                    method_type: "JsonWebKey2020".into(),
                    controller: "did:web:app.dev".into(),
                    public_key_jwk: JsonWebKey::ec_p256("c", "d"),
                },
            ],
            authentication: None,
            assertion_method: None,
            key_agreement: None,
            service: None,
        };

        // Find by fragment
        let vm = doc.find_verification_method("key-1").unwrap();
        assert_eq!(vm.public_key_jwk.x, "a");

        // Find by full ID
        let vm = doc
            .find_verification_method("did:web:app.dev#key-2")
            .unwrap();
        assert_eq!(vm.public_key_jwk.x, "c");

        // Not found
        assert!(doc.find_verification_method("key-3").is_none());
    }

    #[test]
    fn json_web_key_ec_p256() {
        let jwk = JsonWebKey::ec_p256("x_coord", "y_coord");
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, "P-256");
        assert_eq!(jwk.x, "x_coord");
        assert_eq!(jwk.y, Some("y_coord".into()));
    }

    #[test]
    fn json_web_key_serde_skip_nones() {
        let jwk = JsonWebKey::ec_p256("x", "y");
        let json = serde_json::to_string(&jwk).unwrap();
        assert!(!json.contains("kid"));
        assert!(!json.contains("alg"));
    }

    #[test]
    fn service_endpoint_serde_roundtrip() {
        let ep = ServiceEndpoint {
            id: "did:web:app.dev#grpc".into(),
            service_type: "GrpcService".into(),
            service_endpoint: "https://app.dev:443".into(),
            description: Some("gRPC via ALPN h2".into()),
        };
        let json = serde_json::to_string(&ep).unwrap();
        let parsed: ServiceEndpoint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, ep);
        assert!(json.contains("\"serviceEndpoint\""));
    }

    // ── did_web_to_url ──────────────────────────────────────────────────

    #[test]
    fn did_web_to_url_root_domain() {
        let url = did_web_to_url("did:web:example.com").unwrap();
        assert_eq!(url, "https://example.com/.well-known/did.json");
    }

    #[test]
    fn did_web_to_url_with_path() {
        let url = did_web_to_url("did:web:example.com:user:alice").unwrap();
        assert_eq!(url, "https://example.com/user/alice/did.json");
    }

    #[test]
    fn did_web_to_url_with_port() {
        let url = did_web_to_url("did:web:example.com%3A3000").unwrap();
        assert_eq!(url, "https://example.com:3000/.well-known/did.json");
    }

    #[test]
    fn did_web_to_url_with_subdomain() {
        let url = did_web_to_url("did:web:music-app.groundtruth.dev").unwrap();
        assert_eq!(
            url,
            "https://music-app.groundtruth.dev/.well-known/did.json"
        );
    }

    #[test]
    fn did_web_to_url_invalid_prefix() {
        let err = did_web_to_url("did:key:abc123").unwrap_err();
        assert!(matches!(err, Error::InvalidSpiffeUri(_)));
    }

    #[test]
    fn did_web_to_url_empty_domain() {
        let err = did_web_to_url("did:web:").unwrap_err();
        assert!(matches!(err, Error::InvalidSpiffeUri(_)));
    }

    #[test]
    fn did_web_to_url_not_a_did() {
        let err = did_web_to_url("https://example.com").unwrap_err();
        assert!(matches!(err, Error::InvalidSpiffeUri(_)));
    }

    // ── W3C-compatible JSON output ──────────────────────────────────────

    #[test]
    fn did_document_w3c_compatible_json() {
        let doc = DidDocument {
            context: vec![
                "https://www.w3.org/ns/did/v1".into(),
                "https://w3id.org/security/suites/jws-2020/v1".into(),
            ],
            id: "did:web:example.com".into(),
            verification_method: vec![VerificationMethod {
                id: "did:web:example.com#owner".into(),
                method_type: "JsonWebKey2020".into(),
                controller: "did:web:example.com".into(),
                public_key_jwk: JsonWebKey {
                    kty: "EC".into(),
                    crv: "P-256".into(),
                    x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU".into(),
                    y: Some("x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0".into()),
                    kid: Some("owner".into()),
                    alg: Some("ES256".into()),
                },
            }],
            authentication: Some(vec!["did:web:example.com#owner".into()]),
            assertion_method: Some(vec!["did:web:example.com#owner".into()]),
            key_agreement: None,
            service: None,
        };

        let json: serde_json::Value = serde_json::to_value(&doc).unwrap();

        // Verify structure matches W3C examples
        assert!(json["@context"].is_array());
        assert_eq!(json["id"], "did:web:example.com");
        assert!(json["verificationMethod"].is_array());
        assert_eq!(json["verificationMethod"][0]["type"], "JsonWebKey2020");
        assert_eq!(json["verificationMethod"][0]["publicKeyJwk"]["kty"], "EC");
    }
}
