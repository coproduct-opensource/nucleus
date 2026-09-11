//! The wire shape of a refusal.
//!
//! Extracted verbatim from `main.rs`, which had grown past its line ratchet.
//! Nothing here changed in the move: the same variants, the same status codes,
//! the same stable `kind` strings that callers branch on.
//!
//! The `kind` strings ARE the contract. `nucleus-sdk`'s `from_error_payload`
//! matches on them, and so does every other client; the human-readable message
//! beside them is not a contract and may be reworded. Keep the two apart when
//! editing this file.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use nucleus::NucleusError;
use serde::Serialize;

use crate::auth::AuthError;
use crate::validation;

#[derive(Debug, Serialize)]
pub(crate) struct ErrorBody {
    error: String,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: Option<String>,
    /// Payment metadata for 402 responses (vendor-agnostic).
    #[serde(skip_serializing_if = "Option::is_none")]
    payment: Option<nucleus_spec::PaymentRequiredInfo>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ApiError {
    #[error("spec error: {0}")]
    Spec(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_yaml::Error),
    #[error("nucleus error: {0}")]
    Nucleus(#[from] NucleusError),
    #[error("auth error: {0}")]
    Auth(#[from] AuthError),
    #[error("request body error: {0}")]
    Body(String),
    #[error("rate limited: too many approval requests")]
    RateLimited,
    #[error("web fetch error: {0}")]
    WebFetch(String),
    #[error("url not in dns_allow list: {0}")]
    DnsNotAllowed(String),
    #[error("attestation verification failed: {0}")]
    AttestationFailed(String),
    /// A request-borne delegation certificate was presented and cannot be
    /// honoured (unbound tier, malformed, unverifiable, wrong leaf). Never a
    /// downgrade to the unsigned bid — see `pod_cert::evaluate_request_cert`.
    #[error("delegation certificate rejected: {0}")]
    DelegationCert(String),
    #[error("escalation error: {0}")]
    Escalation(String),
    /// The permission kernel refused, for a reason that is not a capability
    /// level. Carries the kernel's own reason rather than flattening every
    /// refusal into "capability is Never".
    #[error("kernel denied: {0}")]
    KernelDenied(String),
    #[error("validation error: {0}")]
    Validation(#[from] validation::ValidationError),
    #[error("permission bid denied: insufficient value")]
    PermissionDenied(#[allow(unused)] nucleus_spec::PaymentRequiredInfo),
    /// Operation denied by the information-flow control monitor: the session has
    /// ingested adversarial (untrusted/web) content and this is an outbound
    /// action that could exfiltrate or act on it (the lethal-trifecta guard,
    /// #1633). Wired into the HTTP path so it has parity with the MCP server.
    #[error("ifc denied: {0}")]
    IfcDenied(String),
    /// A governor declassification token was rejected (bad/absent signature,
    /// no trusted keys, expired, precondition unmet, or node not found).
    #[error("declassification denied: {0}")]
    Declassification(String),
    /// A governor declassification token was well-formed and signed but cannot
    /// take effect because its one-shot authority is spent or the node is
    /// already declassified. Distinct from a rejection so a governor can tell
    /// "already done" from "refused".
    #[error("declassification conflict: {0}")]
    DeclassificationConflict(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, kind, operation, payment) = match &self {
            ApiError::Nucleus(NucleusError::ApprovalRequired { operation }) => (
                StatusCode::FORBIDDEN,
                "approval_required",
                Some(operation.clone()),
                None,
            ),
            ApiError::Nucleus(NucleusError::BudgetExhausted {
                requested,
                remaining,
            }) => {
                let payment_info = nucleus_spec::PaymentRequiredInfo {
                    amount_usd: *requested,
                    reason: format!(
                        "budget exhausted: requested ${requested:.4}, remaining ${remaining:.4}"
                    ),
                    kind: nucleus_spec::PaymentRequiredKind::BudgetExhausted {
                        requested: *requested,
                        remaining: *remaining,
                    },
                    recipient: std::env::var("NUCLEUS_PAYMENT_RECIPIENT").ok(),
                    resource: None,
                };
                (
                    StatusCode::PAYMENT_REQUIRED,
                    "budget_exhausted",
                    None,
                    Some(payment_info),
                )
            }
            ApiError::Nucleus(NucleusError::CommandDenied { .. }) => {
                (StatusCode::FORBIDDEN, "command_denied", None, None)
            }
            // An authority earned for a different action was presented. FORBIDDEN
            // rather than 400: the request was well-formed, the authority was not
            // valid for it.
            ApiError::Nucleus(NucleusError::ScopeMismatch { .. }) => {
                (StatusCode::FORBIDDEN, "scope_mismatch", None, None)
            }
            ApiError::Nucleus(NucleusError::PathDenied { .. }) => {
                (StatusCode::FORBIDDEN, "path_denied", None, None)
            }
            // Filesystem facts, NOT authorization outcomes. 404/400 rather than
            // 403 so a caller can tell "the policy refused you" from "that file
            // is not there" and "that is a directory". Reported as 403
            // `path_denied`, an absent file sends the reader to a policy that
            // had no part in it -- measured on a live pod, where the sandbox's
            // only entry was a directory and reading it said "access denied".
            ApiError::Nucleus(NucleusError::PathNotFound { .. }) => {
                (StatusCode::NOT_FOUND, "path_not_found", None, None)
            }
            ApiError::Nucleus(NucleusError::PathUnusable { .. }) => {
                (StatusCode::BAD_REQUEST, "path_unusable", None, None)
            }
            ApiError::Nucleus(NucleusError::SandboxEscape { .. }) => {
                (StatusCode::FORBIDDEN, "sandbox_escape", None, None)
            }
            ApiError::KernelDenied(_) => (StatusCode::FORBIDDEN, "kernel_denied", None, None),
            ApiError::Nucleus(NucleusError::Io(_)) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "io_error", None, None)
            }
            ApiError::Nucleus(NucleusError::TimeViolation { .. }) => {
                (StatusCode::REQUEST_TIMEOUT, "time_violation", None, None)
            }
            ApiError::Nucleus(NucleusError::StateBlocked { .. }) => {
                (StatusCode::FORBIDDEN, "uninhabitable_blocked", None, None)
            }
            ApiError::Nucleus(NucleusError::InsufficientCapability { .. }) => {
                (StatusCode::FORBIDDEN, "insufficient_capability", None, None)
            }
            ApiError::Nucleus(NucleusError::IsolationNotConfigured)
            | ApiError::Nucleus(NucleusError::IsolationInsufficient { .. })
            | ApiError::Nucleus(NucleusError::HardeningUnavailable { .. }) => {
                (StatusCode::FORBIDDEN, "isolation_denied", None, None)
            }
            ApiError::Nucleus(NucleusError::ProvenanceUnverified { .. }) => {
                (StatusCode::FORBIDDEN, "provenance_unverified", None, None)
            }
            ApiError::Nucleus(NucleusError::InvalidApproval { operation }) => (
                StatusCode::FORBIDDEN,
                "invalid_approval",
                Some(operation.clone()),
                None,
            ),
            ApiError::Nucleus(NucleusError::InvalidCharge { .. }) => {
                (StatusCode::BAD_REQUEST, "invalid_charge", None, None)
            }
            ApiError::Spec(_) => (StatusCode::BAD_REQUEST, "spec_error", None, None),
            ApiError::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, "io_error", None, None),
            ApiError::Serde(_) => (StatusCode::BAD_REQUEST, "serde_error", None, None),
            ApiError::Auth(_) => (StatusCode::UNAUTHORIZED, "auth_error", None, None),
            ApiError::Body(_) => (StatusCode::BAD_REQUEST, "body_error", None, None),
            ApiError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited", None, None),
            ApiError::WebFetch(_) => (StatusCode::BAD_GATEWAY, "web_fetch_error", None, None),
            ApiError::DnsNotAllowed(_) => (StatusCode::FORBIDDEN, "dns_not_allowed", None, None),
            ApiError::AttestationFailed(_) => {
                (StatusCode::FORBIDDEN, "attestation_failed", None, None)
            }
            ApiError::DelegationCert(_) => (
                StatusCode::FORBIDDEN,
                "delegation_cert_rejected",
                None,
                None,
            ),
            ApiError::Escalation(_) => (StatusCode::FORBIDDEN, "escalation_denied", None, None),
            ApiError::Validation(_) => (StatusCode::BAD_REQUEST, "validation_error", None, None),
            ApiError::PermissionDenied(info) => (
                StatusCode::PAYMENT_REQUIRED,
                "permission_denied",
                None,
                Some(info.clone()),
            ),
            ApiError::IfcDenied(_) => (StatusCode::FORBIDDEN, "ifc_denied", None, None),
            ApiError::Declassification(_) => {
                (StatusCode::FORBIDDEN, "declassification_denied", None, None)
            }
            ApiError::DeclassificationConflict(_) => (
                StatusCode::CONFLICT,
                "declassification_conflict",
                None,
                None,
            ),
        };

        // Sanitize error message to prevent information disclosure
        let sanitized_error = validation::sanitize_error_message(&self.to_string(), None);

        let body = Json(ErrorBody {
            error: sanitized_error,
            kind: kind.to_string(),
            operation,
            payment,
        });
        (status, body).into_response()
    }
}
