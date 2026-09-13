//! HTTP failures retain the distinction between a refused request and a
//! temporarily unavailable observation (ADR 0007 A-4/A-8).

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::auth::{AuthError, AuthorizationError};

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ApiError {
    #[error("invalid spec: {0}")]
    InvalidSpec(String),
    #[error("pod not found")]
    NotFound,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_yaml::Error),
    #[error("driver error: {0}")]
    Driver(String),
    #[error("workload supervisor unavailable: {0}")]
    SupervisorUnavailable(String),
    #[error("auth error: {0}")]
    Auth(#[from] AuthError),
    #[error("authorization error: {0}")]
    Authorization(#[from] AuthorizationError), // authenticated, not permitted
    /// Authenticated and route-authorized, but the caller could not prove
    /// authority for the pod it asked for (pod_authority.rs).
    #[error("authority denied: {0}")]
    Authority(String),
    #[error("request body error: {0}")]
    Body(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self {
            ApiError::InvalidSpec(_) => StatusCode::BAD_REQUEST,
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::Serde(_) => StatusCode::BAD_REQUEST,
            ApiError::Driver(_) => StatusCode::BAD_REQUEST,
            ApiError::SupervisorUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            ApiError::Auth(_) => StatusCode::UNAUTHORIZED,
            ApiError::Authorization(_) => StatusCode::FORBIDDEN,
            ApiError::Authority(_) => StatusCode::FORBIDDEN,
            ApiError::Body(_) => StatusCode::BAD_REQUEST,
        };
        let body = Json(ErrorBody {
            error: self.to_string(),
        });
        (status, body).into_response()
    }
}
