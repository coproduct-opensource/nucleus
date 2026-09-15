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

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    /// #2902: `nucleus node create` reported `status 400` and nothing else, so
    /// `missing spec.image` — a complete diagnosis the node had already
    /// produced — never reached the caller. The CLI half is fixed in
    /// `nucleus-cli/src/node.rs`; this is the other half.
    ///
    /// That half was asserted by this file's own header comment and checked by
    /// nothing: the CLI can only print a reason the node actually sends. A
    /// claim about a body, with no test that reads one, is a gate whose green
    /// is indistinguishable from vacuity (ADR 0007 I-1). This fails if
    /// `into_response` ever returns to a status without a reason.
    #[tokio::test]
    async fn driver_error_renders_the_reason_in_the_body() {
        let response = ApiError::Driver("missing spec.image".to_string()).into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("the error response body must be readable")
            .to_bytes();
        assert!(
            !bytes.is_empty(),
            "a 400 with a zero-length body is exactly the #2902 defect"
        );

        let parsed: serde_json::Value =
            serde_json::from_slice(&bytes).expect("the body must be the JSON the CLI parses");
        assert_eq!(
            parsed.get("error").and_then(serde_json::Value::as_str),
            Some("driver error: missing spec.image"),
            "the body must name the reason, not merely exist"
        );
    }
}
