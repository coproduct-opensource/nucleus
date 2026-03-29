//! Request/response types and error handling for the tool-proxy HTTP API.

use std::collections::HashMap;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use nucleus::NucleusError;
use serde::{Deserialize, Serialize};

use crate::validation;

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct ReadRequest {
    pub(crate) path: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReadResponse {
    pub(crate) contents: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct WriteRequest {
    pub(crate) path: String,
    pub(crate) contents: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct WriteResponse {
    pub(crate) ok: bool,
}

/// Run command request using secure array-based format.
///
/// The array form prevents shell injection by executing commands directly
/// without shell interpretation. Each array element is passed as a separate
/// argument to the process.
#[derive(Debug, Deserialize)]
pub(crate) struct RunRequest {
    /// Command as array, e.g. ["ls", "-la", "/tmp"]
    pub(crate) args: Vec<String>,
    /// Optional input to pass to command stdin
    #[serde(default)]
    pub(crate) stdin: Option<String>,
    /// Optional working directory (relative to sandbox)
    #[serde(default)]
    pub(crate) directory: Option<String>,
    /// Optional timeout in seconds (clamped to policy limit)
    #[serde(default)]
    #[allow(dead_code)] // Reserved for future timeout implementation
    pub(crate) timeout_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct RunResponse {
    pub(crate) status: i32,
    pub(crate) success: bool,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ApproveRequest {
    pub(crate) operation: String,
    #[serde(default = "default_approve_count")]
    pub(crate) count: usize,
    #[serde(default)]
    pub(crate) expires_at_unix: Option<u64>,
    #[serde(default)]
    pub(crate) nonce: Option<String>,
}

pub(crate) fn default_approve_count() -> usize {
    1
}

pub(crate) const MAX_APPROVAL_TTL_SECS: u64 = 300;

#[derive(Debug, Serialize)]
pub(crate) struct ApproveResponse {
    pub(crate) ok: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct WebFetchRequest {
    pub(crate) url: String,
    #[serde(default)]
    pub(crate) method: Option<String>,
    #[serde(default)]
    pub(crate) headers: Option<HashMap<String, String>>,
    #[serde(default)]
    pub(crate) body: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct WebFetchResponse {
    pub(crate) status: u16,
    pub(crate) headers: HashMap<String, String>,
    pub(crate) body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) truncated: Option<bool>,
}

/// Glob pattern search request.
#[derive(Debug, Deserialize)]
pub(crate) struct GlobRequest {
    /// Glob pattern to match (e.g., "**/*.rs", "src/*.json")
    pub(crate) pattern: String,
    /// Optional directory to search in (relative to sandbox root)
    #[serde(default)]
    pub(crate) directory: Option<String>,
    /// Maximum number of results to return
    #[serde(default)]
    pub(crate) max_results: Option<usize>,
}

/// Glob search response.
#[derive(Debug, Serialize)]
pub(crate) struct GlobResponse {
    /// Matching file paths (relative to sandbox)
    pub(crate) matches: Vec<String>,
    /// True if results were truncated due to max_results
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) truncated: Option<bool>,
}

/// Grep (content search) request.
#[derive(Debug, Deserialize)]
pub(crate) struct GrepRequest {
    /// Regex pattern to search for
    pub(crate) pattern: String,
    /// Optional file path to search in (relative to sandbox)
    #[serde(default)]
    pub(crate) path: Option<String>,
    /// Optional glob pattern to filter files
    #[serde(default, rename = "glob")]
    pub(crate) file_glob: Option<String>,
    /// Number of context lines before/after match
    #[serde(default)]
    pub(crate) context_lines: Option<usize>,
    /// Maximum number of matches to return
    #[serde(default)]
    pub(crate) max_matches: Option<usize>,
    /// Case-insensitive search
    #[serde(default)]
    pub(crate) case_insensitive: Option<bool>,
}

/// A single grep match result.
#[derive(Debug, Serialize)]
pub(crate) struct GrepMatch {
    /// File path (relative to sandbox)
    pub(crate) file: String,
    /// Line number (1-indexed)
    pub(crate) line: usize,
    /// Matching line content
    pub(crate) content: String,
    /// Optional context lines before
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) context_before: Option<Vec<String>>,
    /// Optional context lines after
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) context_after: Option<Vec<String>>,
}

/// Grep search response.
#[derive(Debug, Serialize)]
pub(crate) struct GrepResponse {
    /// Matching results
    pub(crate) matches: Vec<GrepMatch>,
    /// True if results were truncated due to max_matches
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) truncated: Option<bool>,
}

/// Web search request.
#[derive(Debug, Deserialize)]
pub(crate) struct WebSearchRequest {
    /// Search query
    pub(crate) query: String,
    /// Maximum number of results
    #[serde(default)]
    pub(crate) max_results: Option<usize>,
}

/// A single web search result.
#[derive(Debug, Serialize)]
pub(crate) struct WebSearchResult {
    /// Result title
    pub(crate) title: String,
    /// Result URL
    pub(crate) url: String,
    /// Result snippet/description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) snippet: Option<String>,
}

/// Web search response.
#[derive(Debug, Serialize)]
pub(crate) struct WebSearchResponse {
    /// Search results
    pub(crate) results: Vec<WebSearchResult>,
}

/// Request to escalate permissions for an agent.
#[derive(Debug, Deserialize)]
pub(crate) struct EscalateRequest {
    /// The requesting agent's SPIFFE trace chain (serialized).
    pub(crate) requestor_chain: SerializedTraceChain,
    /// The approver's SPIFFE trace chain (serialized).
    pub(crate) approver_chain: SerializedTraceChain,
    /// Requested permission preset (e.g., "fix_issue", "permissive").
    pub(crate) requested_preset: String,
    /// Justification for the escalation.
    pub(crate) reason: String,
    /// TTL in seconds for the escalated permissions.
    pub(crate) ttl_seconds: u64,
    /// Unique nonce to prevent replay attacks.
    pub(crate) nonce: String,
}

/// Serialized trace chain for transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerializedTraceChain {
    /// Chain ID.
    pub(crate) id: String,
    /// Links in the chain.
    pub(crate) links: Vec<SerializedTraceLink>,
}

/// Serialized trace link for transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SerializedTraceLink {
    /// Link ID.
    pub(crate) id: String,
    /// SPIFFE ID.
    pub(crate) spiffe_id: String,
    /// Permission preset name (for reconstruction).
    pub(crate) preset: String,
    /// Drand round when created.
    pub(crate) drand_round: u64,
    /// Creation timestamp (Unix seconds).
    pub(crate) created_at: u64,
    /// Expiry timestamp (Unix seconds), if any.
    pub(crate) expires_at: Option<u64>,
    /// Reason for this link.
    pub(crate) reason: String,
}

/// Response from an escalation request.
#[derive(Debug, Serialize)]
pub(crate) struct EscalateResponse {
    /// Whether the escalation was granted.
    pub(crate) granted: bool,
    /// The grant ID (if granted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) grant_id: Option<String>,
    /// Granted permission preset (if granted).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) granted_preset: Option<String>,
    /// Expiry timestamp (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) expires_at: Option<u64>,
    /// Drand round of the grant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) drand_round: Option<u64>,
    /// Error message (if denied).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub(crate) struct ErrorBody {
    pub(crate) error: String,
    pub(crate) kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) operation: Option<String>,
    /// Payment metadata for 402 responses (vendor-agnostic).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) payment: Option<nucleus_spec::PaymentRequiredInfo>,
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
    Auth(#[from] crate::auth::AuthError),
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
    #[error("escalation error: {0}")]
    Escalation(String),
    #[error("validation error: {0}")]
    Validation(#[from] validation::ValidationError),
    #[error("permission bid denied: insufficient value")]
    PermissionDenied(#[allow(unused)] nucleus_spec::PaymentRequiredInfo),
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
            ApiError::Nucleus(NucleusError::PathDenied { .. }) => {
                (StatusCode::FORBIDDEN, "path_denied", None, None)
            }
            ApiError::Nucleus(NucleusError::SandboxEscape { .. }) => {
                (StatusCode::FORBIDDEN, "sandbox_escape", None, None)
            }
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
            ApiError::Escalation(_) => (StatusCode::FORBIDDEN, "escalation_denied", None, None),
            ApiError::Validation(_) => (StatusCode::BAD_REQUEST, "validation_error", None, None),
            ApiError::PermissionDenied(ref info) => (
                StatusCode::PAYMENT_REQUIRED,
                "permission_denied",
                None,
                Some(info.clone()),
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
