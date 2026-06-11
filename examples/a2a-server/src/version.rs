//! `A2A-Version` negotiation (A2A v1.0 §3.6).
//!
//! Servers MUST process requests under the semantics of the requested
//! `Major.Minor` version, MUST interpret an empty value as `0.3`
//! (§3.6.2), and MUST answer unsupported versions with
//! `VersionNotSupportedError` — JSON-RPC code `-32009`, HTTP
//! `400 Bad Request` / gRPC `FAILED_PRECONDITION` (§5.4).
//!
//! This server's card advertises `1.0` interfaces only, so everything
//! that doesn't negotiate to `1.0` — including the absent-header `0.3`
//! default — is rejected. Patch components are tolerated but never
//! considered (§3.6: "MUST not be considered when clients and servers
//! negotiate protocol versions").

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use nucleus_agent_card::A2A_PROTOCOL_VERSION;

/// The `A2A-Version` service-parameter header (§3.2.6; HTTP headers are
/// case-insensitive).
pub const A2A_VERSION_HEADER: &str = "a2a-version";

/// JSON-RPC code for `VersionNotSupportedError` (§5.4).
pub const VERSION_NOT_SUPPORTED: i32 = -32009;

/// Largest JSON-RPC request body we read back just to echo its `id` into
/// an error envelope.
const ID_RECOVERY_BODY_LIMIT: usize = 64 * 1024;

/// Axum middleware: negotiate `A2A-Version` before the SDK sees the
/// request. Pass on `1.0`; answer everything else with the binding's
/// `VersionNotSupportedError` representation.
pub async fn negotiate(req: Request, next: Next) -> Response {
    let requested = requested_version(&req);
    if is_supported(&requested) {
        return next.run(req).await;
    }
    version_not_supported(req, &requested).await
}

/// The version the client asked for. Header first; §3.6.1 also lets
/// clients send it as a request parameter. Absent or empty ⇒ `0.3`
/// (§3.6.2).
fn requested_version(req: &Request) -> String {
    if let Some(v) = req
        .headers()
        .get(A2A_VERSION_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        let v = v.trim();
        return if v.is_empty() { "0.3".into() } else { v.into() };
    }
    // Query-parameter form (§3.6.1). Version strings are `Major.Minor` —
    // no characters that need percent-decoding.
    if let Some(query) = req.uri().query() {
        for pair in query.split('&') {
            if let Some(v) = pair.strip_prefix("A2A-Version=") {
                if !v.is_empty() {
                    return v.into();
                }
            }
        }
    }
    "0.3".into()
}

/// Parse `Major.Minor` (§3.6). A numeric third component is tolerated and
/// ignored; anything else is not a protocol version.
fn major_minor(v: &str) -> Option<(u32, u32)> {
    let mut parts = v.split('.');
    let major: u32 = parts.next()?.parse().ok()?;
    let minor: u32 = parts.next()?.parse().ok()?;
    if let Some(patch) = parts.next() {
        patch.parse::<u32>().ok()?; // "1.0.2" negotiates as 1.0
        if parts.next().is_some() {
            return None;
        }
    }
    Some((major, minor))
}

fn is_supported(v: &str) -> bool {
    major_minor(v) == Some((1, 0))
}

/// Build the binding-appropriate `VersionNotSupportedError`.
async fn version_not_supported(req: Request, requested: &str) -> Response {
    let error_info = serde_json::json!({
        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
        "reason": "VERSION_NOT_SUPPORTED",
        "domain": "a2a-protocol.org",
        "metadata": {
            "requestedVersion": requested,
            "supportedVersions": A2A_PROTOCOL_VERSION,
        }
    });
    let message = format!(
        "A2A version {requested} is not supported; this interface speaks \
         {A2A_PROTOCOL_VERSION} only (send `A2A-Version: {A2A_PROTOCOL_VERSION}`)"
    );

    if req.uri().path().starts_with("/jsonrpc") {
        // JSON-RPC binding (§9.5): proper error envelope, id echoed from
        // the request when it can be recovered.
        let id = match axum::body::to_bytes(req.into_body(), ID_RECOVERY_BODY_LIMIT).await {
            Ok(bytes) => serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|v| v.get("id").cloned())
                .unwrap_or(serde_json::Value::Null),
            Err(_) => serde_json::Value::Null,
        };
        let envelope = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": VERSION_NOT_SUPPORTED,
                "message": message,
                "data": [error_info],
            }
        });
        (StatusCode::OK, axum::Json(envelope)).into_response()
    } else {
        // HTTP+JSON binding (§11.6): google.rpc.Status shape, 400 per the
        // §5.4 mapping table.
        let body = serde_json::json!({
            "error": {
                "code": 400,
                "status": "FAILED_PRECONDITION",
                "message": message,
                "details": [error_info],
            }
        });
        (StatusCode::BAD_REQUEST, axum::Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_major_minor_one_zero_negotiates() {
        assert!(is_supported("1.0"));
        assert!(is_supported(" 1.0 ".trim()));
        // §3.6: patch numbers MUST not be considered in negotiation.
        assert!(is_supported("1.0.7"));
        assert!(!is_supported("0.3"));
        assert!(!is_supported("1.1"));
        assert!(!is_supported("2.0"));
        assert!(!is_supported("1"));
        assert!(!is_supported(""));
        assert!(!is_supported("1.0.x"));
        assert!(!is_supported("garbage"));
        assert!(!is_supported("1.0.0.0"));
    }

    #[test]
    fn absent_and_empty_default_to_zero_three() {
        let req = Request::builder()
            .uri("/jsonrpc")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(requested_version(&req), "0.3");

        let req = Request::builder()
            .uri("/jsonrpc")
            .header("A2A-Version", "")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(requested_version(&req), "0.3");
    }

    #[test]
    fn header_and_query_parameter_forms() {
        let req = Request::builder()
            .uri("/jsonrpc")
            .header("a2a-version", "1.0")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(requested_version(&req), "1.0");

        let req = Request::builder()
            .uri("/jsonrpc?A2A-Version=1.0")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(requested_version(&req), "1.0");
    }
}
