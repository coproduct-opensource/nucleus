//! [`ApiError`] — wire-format errors returned by every route handler.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

/// Errors emitted by route handlers. Each variant maps to a single HTTP
/// status code; the wire format is `{"error": "<machine_code>", "message": "..."}`.
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("invalid request: {0}")]
    BadRequest(String),
    #[error("job not found")]
    NotFound,
    #[error("job not yet completed (state: {state})")]
    Conflict { state: &'static str },
    #[error("unknown agent driver: {0}")]
    UnknownDriver(String),
    #[error("internal error: {0}")]
    Internal(String),
    /// **MED-6 (audit) fix.** Server reached `MAX_INFLIGHT_JOBS` and
    /// cannot accept a new submission until prior jobs complete. Maps
    /// to 503 Service Unavailable with `Retry-After: 10`.
    #[error("server at capacity: {in_flight} jobs in flight, max {max}")]
    AtCapacity { in_flight: usize, max: usize },
}

#[derive(Serialize)]
struct ApiErrorBody {
    error: &'static str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            ApiError::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            ApiError::Conflict { .. } => (StatusCode::CONFLICT, "conflict"),
            ApiError::UnknownDriver(_) => (StatusCode::UNPROCESSABLE_ENTITY, "unknown_driver"),
            ApiError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
            ApiError::AtCapacity { .. } => (StatusCode::SERVICE_UNAVAILABLE, "at_capacity"),
        };
        let body = ApiErrorBody {
            error: code,
            message: self.to_string(),
        };
        (status, Json(body)).into_response()
    }
}
