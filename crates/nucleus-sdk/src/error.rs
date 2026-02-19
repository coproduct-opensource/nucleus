//! Error types for nucleus SDK operations.
//!
//! Maps the tool-proxy JSON error `kind` field to typed variants,
//! mirroring the Python SDK's `errors.py`.

use serde_json::Value;

/// Errors returned by nucleus SDK operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The operation requires explicit approval before it can proceed.
    #[error("approval required for operation: {operation}")]
    ApprovalRequired { operation: String, message: String },

    /// The requested operation was denied by the permission lattice.
    #[error("access denied ({kind}): {message}")]
    AccessDenied {
        kind: String,
        message: String,
        operation: Option<String>,
    },

    /// Authentication failed (invalid HMAC, expired timestamp, etc.).
    #[error("auth error: {0}")]
    Auth(String),

    /// Invalid spec, request body, or parameter.
    #[error("spec error: {0}")]
    Spec(String),

    /// HTTP request failed with a non-specific error.
    #[error("request failed ({status}): {message}")]
    Request { status: u16, message: String },

    /// gRPC transport or status error.
    #[error("gRPC error: {0}")]
    Grpc(#[from] tonic::Status),

    /// HTTP transport error (connection, DNS, TLS, etc.).
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization or deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Configuration error (missing URL, invalid builder state, etc.).
    #[error("configuration error: {0}")]
    Config(String),

    /// Catch-all for unclassified errors.
    #[error("{0}")]
    Other(String),
}

/// Parse a tool-proxy JSON error response into a typed [`Error`].
///
/// The tool-proxy returns errors as:
/// ```json
/// {"error": "message", "kind": "approval_required", "operation": "write"}
/// ```
pub fn from_error_payload(status: u16, payload: &Value) -> Error {
    let message = payload
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("request failed")
        .to_string();
    let kind = payload.get("kind").and_then(|v| v.as_str()).unwrap_or("");
    let operation = payload
        .get("operation")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    match kind {
        "approval_required" => Error::ApprovalRequired {
            operation: operation.unwrap_or_default(),
            message,
        },
        "path_denied"
        | "command_denied"
        | "sandbox_escape"
        | "trifecta_blocked"
        | "insufficient_capability"
        | "dns_not_allowed" => Error::AccessDenied {
            kind: kind.to_string(),
            message,
            operation,
        },
        "auth_error" => Error::Auth(message),
        "spec_error" | "serde_error" | "body_error" | "validation_error" => Error::Spec(message),
        _ => Error::Request { status, message },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_approval_required() {
        let payload = json!({
            "error": "write requires approval",
            "kind": "approval_required",
            "operation": "write"
        });
        let err = from_error_payload(403, &payload);
        assert!(matches!(err, Error::ApprovalRequired { .. }));
        assert!(err.to_string().contains("write"));
    }

    #[test]
    fn test_access_denied_variants() {
        for kind in [
            "path_denied",
            "command_denied",
            "sandbox_escape",
            "trifecta_blocked",
            "insufficient_capability",
            "dns_not_allowed",
        ] {
            let payload = json!({
                "error": "denied",
                "kind": kind,
            });
            let err = from_error_payload(403, &payload);
            assert!(
                matches!(err, Error::AccessDenied { .. }),
                "kind '{}' should map to AccessDenied",
                kind
            );
        }
    }

    #[test]
    fn test_auth_error() {
        let payload = json!({
            "error": "invalid signature",
            "kind": "auth_error",
        });
        let err = from_error_payload(401, &payload);
        assert!(matches!(err, Error::Auth(_)));
    }

    #[test]
    fn test_spec_error_variants() {
        for kind in [
            "spec_error",
            "serde_error",
            "body_error",
            "validation_error",
        ] {
            let payload = json!({
                "error": "bad input",
                "kind": kind,
            });
            let err = from_error_payload(400, &payload);
            assert!(
                matches!(err, Error::Spec(_)),
                "kind '{}' should map to Spec",
                kind
            );
        }
    }

    #[test]
    fn test_unknown_kind_falls_back_to_request() {
        let payload = json!({
            "error": "something went wrong",
            "kind": "internal_error",
        });
        let err = from_error_payload(500, &payload);
        assert!(matches!(err, Error::Request { status: 500, .. }));
    }

    #[test]
    fn test_missing_fields() {
        let payload = json!({});
        let err = from_error_payload(500, &payload);
        assert!(matches!(err, Error::Request { status: 500, .. }));
        assert!(err.to_string().contains("request failed"));
    }
}
