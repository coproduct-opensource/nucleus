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
