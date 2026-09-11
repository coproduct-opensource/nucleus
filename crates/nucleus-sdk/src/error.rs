//! Error types for nucleus SDK operations.
//!
//! Maps the tool-proxy JSON error `kind` field to typed variants,
//! mirroring the Python SDK's `errors.py`.

use portcullis::escalation_proposal::EscalationProposal;
use serde_json::Value;

/// Errors returned by nucleus SDK operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The operation requires explicit approval before it can proceed.
    #[error("approval required for operation: {operation}")]
    ApprovalRequired { operation: String, message: String },

    /// The requested operation was denied by the permission lattice.
    ///
    /// `proposal`, when present, is the tool-proxy's escalation proposal for
    /// *this* denial: what was attempted, the least authority that would have
    /// allowed it, what new risk that adds, and the command that grants it.
    /// Before this field the same analysis existed only at the CLI, rebuilt
    /// from a trace file once the run had already ended — so an agent holding
    /// this error had a sentence and nothing to act on.
    ///
    /// It is `None` whenever the proxy had no grant to propose against, which
    /// is every profile run. Callers must treat it as an explanation that may
    /// be missing, never as the thing that makes a denial a denial.
    #[error("access denied ({kind}): {message}")]
    AccessDenied {
        kind: String,
        message: String,
        operation: Option<String>,
        proposal: Option<Box<EscalationProposal>>,
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
///
/// A denial may additionally carry `proposal`. A payload whose `proposal` is
/// absent, null or malformed still parses to the same denial with `None` — an
/// explanation that fails to decode must never downgrade the refusal it
/// explains into an unclassified `Request` error.
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
    let proposal = payload
        .get("proposal")
        .and_then(|v| serde_json::from_value::<EscalationProposal>(v.clone()).ok())
        .map(Box::new);

    match kind {
        "approval_required" => Error::ApprovalRequired {
            operation: operation.unwrap_or_default(),
            message,
        },
        "path_denied"
        | "command_denied"
        | "sandbox_escape"
        | "uninhabitable_blocked"
        | "insufficient_capability"
        // The permission kernel refused for a reason that is not a capability
        // level — a delegation ceiling, an isolation gate, an expired session.
        // It is an access denial like the rest; without this arm it would fall
        // through to the generic `Request` error and lose that classification.
        | "kernel_denied"
        | "dns_not_allowed" => Error::AccessDenied {
            kind: kind.to_string(),
            message,
            operation,
            proposal,
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
            "uninhabitable_blocked",
            "insufficient_capability",
            "kernel_denied",
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

    /// A denial that carries a proposal parses it, and the proposal survives
    /// intact — the SDK is the last hop before the agent, so anything it drops
    /// here is dropped for good.
    #[test]
    fn a_denial_carries_its_proposal_through() {
        let sent = a_proposal();
        let payload = json!({
            "error": "kernel denied",
            "kind": "kernel_denied",
            "operation": "web_fetch",
            "proposal": serde_json::to_value(&sent).unwrap(),
        });
        match from_error_payload(403, &payload) {
            Error::AccessDenied { proposal, .. } => {
                let got = proposal.expect("the proposal must survive the hop");
                assert_eq!(got.attempted, sent.attempted);
                assert_eq!(got.blocked, sent.blocked);
                assert_eq!(got.plain, sent.plain);
            }
            other => panic!("expected AccessDenied, got {other:?}"),
        }
    }

    /// Non-vacuity for the test above: a denial without the field is still a
    /// denial, so the assertion is not passing because every payload yields a
    /// proposal. This is the common case — every profile run.
    #[test]
    fn a_denial_without_a_proposal_is_still_a_denial() {
        let payload = json!({"error": "kernel denied", "kind": "kernel_denied"});
        match from_error_payload(403, &payload) {
            Error::AccessDenied { proposal, .. } => assert!(proposal.is_none()),
            other => panic!("expected AccessDenied, got {other:?}"),
        }
    }

    /// THE property. An explanation is a courtesy; the refusal is the contract.
    /// A proposal the SDK cannot decode — a newer schema, a truncated body, a
    /// field renamed upstream — must leave the classification exactly where it
    /// was. The failure this forbids is a client that stops recognising a
    /// denial as a denial because the *reason* it was given got harder to read.
    #[test]
    fn a_malformed_proposal_never_downgrades_the_denial() {
        for junk in [
            json!("not an object"),
            json!(null),
            json!({"version": 1}),
            json!({"attempted": {"operation": "no_such_operation", "subject": "s"}}),
        ] {
            let payload = json!({
                "error": "kernel denied",
                "kind": "kernel_denied",
                "proposal": junk,
            });
            match from_error_payload(403, &payload) {
                Error::AccessDenied { proposal, .. } => {
                    assert!(proposal.is_none(), "junk must not parse: {junk}");
                }
                other => panic!("a bad proposal changed the classification: {other:?}"),
            }
        }
    }

    fn a_proposal() -> EscalationProposal {
        use portcullis::escalation_proposal::{Attempt, Blocked};
        use portcullis::kernel::DenyReason;
        EscalationProposal {
            version: EscalationProposal::VERSION,
            grant_id: uuid::Uuid::nil(),
            attempted: Attempt {
                operation: portcullis::Operation::WebFetch,
                subject: "https://api.github.com/x".to_string(),
            },
            blocked: Blocked {
                code: "kernel_denied".to_string(),
                reason: DenyReason::EgressBlocked {
                    host: "api.github.com".to_string(),
                    policy_reason: "not in allowlist".to_string(),
                },
            },
            plain: "web_fetch was denied".to_string(),
            minimum: None,
            risk: None,
            scopes: Vec::new(),
            outside_ceiling: None,
            repair: None,
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
