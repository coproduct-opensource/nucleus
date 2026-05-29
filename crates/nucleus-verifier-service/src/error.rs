//! Error wire format for the verifier service.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifyApiError {
    #[error("invalid request: {0}")]
    BadRequest(String),
    /// Verification ran but the bundle was rejected. Carries the
    /// underlying nucleus-envelope error string so clients can see
    /// exactly which edge / which check failed.
    #[error("verification failed: {0}")]
    VerificationFailed(String),
    /// Payload exceeded the request-size limit. The CORS+limit layer
    /// catches the over-budget case before the handler runs; this
    /// variant is for any manual size validation.
    #[error("payload too large: {0}")]
    PayloadTooLarge(String),
    /// Bundle hash lookup against a hash that hasn't been submitted.
    #[error("envelope hash not found: {0}")]
    NotFound(String),
    /// Hit a persistence-required endpoint while the service is
    /// running in stateless mode (no `--db` flag). Surfaces as 503
    /// rather than 404 to distinguish a misconfigured deployment
    /// from "hash legitimately absent."
    #[error("persistence disabled: {0}")]
    PersistenceDisabled(String),
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Serialize)]
struct Body {
    ok: bool,
    error: &'static str,
    message: String,
}

impl IntoResponse for VerifyApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            VerifyApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            VerifyApiError::VerificationFailed(_) => {
                (StatusCode::UNPROCESSABLE_ENTITY, "verification_failed")
            }
            VerifyApiError::PayloadTooLarge(_) => {
                (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large")
            }
            VerifyApiError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            VerifyApiError::PersistenceDisabled(_) => {
                (StatusCode::SERVICE_UNAVAILABLE, "persistence_disabled")
            }
            VerifyApiError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        };
        let body = Body {
            ok: false,
            error: code,
            message: self.to_string(),
        };
        (status, Json(body)).into_response()
    }
}
