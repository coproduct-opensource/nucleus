//! Error wire format. Full RFC 6749 / 8693 mapping.
//!
//! Token-endpoint errors follow RFC 6749 §5.2 + RFC 8693 §2.2.2 — JSON
//! body with `error` (canonical code) and optional `error_description`.
//! Other endpoints emit the OP's house JSON shape (`ok: false, error,
//! message`) used by the verifier-service.
//!
//! # Constant-time discrimination on auth-related errors
//!
//! Auth-related variants (`InvalidGrant`, `InvalidTarget`) carry their
//! detail message internally for operator logs but emit a **fixed,
//! opaque `error_description`** on the wire. This defends the
//! federation-rule matcher against oracle attacks where a probing
//! attacker would otherwise learn which `(subject_prefix, audience)`
//! pairs map to a rule (vs. don't match at all vs. match-but-wrong-grant).
//!
//! The detailed message is preserved via the [`OidcApiError::Display`]
//! impl — log it at the call site with `tracing::warn!` BEFORE returning
//! the error.
//!
//! The internal `Internal` variant is always wire-stripped — clients
//! see only `error: "server_error"`, never internal state.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use thiserror::Error;

/// Wire-opaque description for `invalid_grant`. Identical bytes
/// regardless of the underlying cause (sig fail / expiry / replay /
/// missing claim) so an attacker can't probe which validation step
/// rejected their token.
pub const OPAQUE_INVALID_GRANT: &str = "subject token validation failed";

/// Wire-opaque description for `invalid_target`. Identical bytes
/// whether no rule matched OR a rule matched but the requested grant
/// was not permitted. Defends the federation-rule matcher oracle.
pub const OPAQUE_INVALID_TARGET: &str =
    "federation policy denies the requested (subject, audience) exchange";

#[derive(Debug, Error)]
pub enum OidcApiError {
    /// Bad request shape (parsing, missing parameter, malformed value).
    #[error("invalid request: {0}")]
    BadRequest(String),
    /// RFC 8693 §2.2.2 `invalid_request` — missing or duplicated parameter.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
    /// RFC 8693 §2.2.2 `invalid_grant` — subject_token rejected
    /// (signature, expiry, claims, replay). **Wire description is
    /// always [`OPAQUE_INVALID_GRANT`]** to defend the validator oracle.
    /// The inner string is for operator logs only (`Display`).
    #[error("invalid grant: {0}")]
    InvalidGrant(String),
    /// RFC 8693 §2.2.2 `invalid_target` — federation rule denies the
    /// requested (subject, audience) pair. **Wire description is
    /// always [`OPAQUE_INVALID_TARGET`]** to defend the rule-matcher
    /// oracle. The inner string is for operator logs only (`Display`).
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    /// RFC 8693 §2.2.2 `unsupported_grant_type` — grant_type not
    /// `urn:ietf:params:oauth:grant-type:token-exchange`. Not
    /// auth-sensitive (any client immediately learns this from the
    /// public discovery doc), so the description leaks no information.
    #[error("unsupported grant type: {0}")]
    UnsupportedGrantType(String),
    /// RFC 6749 §5.2 `invalid_scope` — requested scope not allowed.
    /// Not auth-sensitive (operators publish the allowed scope set).
    #[error("invalid scope: {0}")]
    InvalidScope(String),
    /// Catch-all for unimplemented endpoints; goes away as routes land.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
    /// Always wire-stripped to `error: server_error` without details.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Token-endpoint OAuth error response per RFC 6749 §5.2 / RFC 8693 §2.2.2.
#[derive(Serialize)]
struct OauthErrorBody {
    error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
}

/// House JSON shape for non-token endpoints (verifier-service parity).
#[derive(Serialize)]
struct HouseErrorBody {
    ok: bool,
    error: &'static str,
    message: String,
}

impl OidcApiError {
    /// True if the error is an RFC 8693 / 6749 OAuth error and should
    /// be serialized with the OAuth `{error, error_description}` shape.
    fn is_oauth_error(&self) -> bool {
        matches!(
            self,
            OidcApiError::InvalidRequest(_)
                | OidcApiError::InvalidGrant(_)
                | OidcApiError::InvalidTarget(_)
                | OidcApiError::UnsupportedGrantType(_)
                | OidcApiError::InvalidScope(_)
        )
    }
}

impl IntoResponse for OidcApiError {
    fn into_response(self) -> Response {
        // Constant-time discipline for auth-related variants: emit a
        // FIXED `error_description` regardless of the inner cause.
        // The inner detail string is for operator-side logs only.
        let (status, code, description) = match &self {
            OidcApiError::BadRequest(m) => {
                (StatusCode::BAD_REQUEST, "invalid_request", Some(m.clone()))
            }
            OidcApiError::InvalidRequest(m) => {
                (StatusCode::BAD_REQUEST, "invalid_request", Some(m.clone()))
            }
            OidcApiError::InvalidGrant(_) => (
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                Some(OPAQUE_INVALID_GRANT.to_string()),
            ),
            OidcApiError::InvalidTarget(_) => (
                StatusCode::BAD_REQUEST,
                "invalid_target",
                Some(OPAQUE_INVALID_TARGET.to_string()),
            ),
            OidcApiError::UnsupportedGrantType(m) => (
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                Some(m.clone()),
            ),
            OidcApiError::InvalidScope(m) => {
                (StatusCode::BAD_REQUEST, "invalid_scope", Some(m.clone()))
            }
            OidcApiError::NotImplemented(_) => {
                (StatusCode::NOT_IMPLEMENTED, "not_implemented", None)
            }
            OidcApiError::Internal(_) => {
                // Never reflect internal state.
                (StatusCode::INTERNAL_SERVER_ERROR, "server_error", None)
            }
        };

        if self.is_oauth_error() {
            (
                status,
                Json(OauthErrorBody {
                    error: code,
                    error_description: description,
                }),
            )
                .into_response()
        } else {
            // House-shape errors are NotImplemented / Internal. Neither
            // is safe to expose the inner detail of — fall back to the
            // canonical code as the user-visible message.
            let safe_message = description.unwrap_or_else(|| code.to_string());
            (
                status,
                Json(HouseErrorBody {
                    ok: false,
                    error: code,
                    message: safe_message,
                }),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;

    async fn body_value(resp: Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn invalid_grant_always_emits_opaque_description() {
        let descs = [
            "subject_token signature verify failed",
            "subject_token expired",
            "subject_token jti already presented",
            "subject_token missing exp",
            "subject_token sub not a SPIFFE ID",
        ];
        for d in descs {
            let v = body_value(OidcApiError::InvalidGrant(d.to_string()).into_response()).await;
            assert_eq!(v["error"], "invalid_grant");
            assert_eq!(
                v["error_description"], OPAQUE_INVALID_GRANT,
                "inner detail {d:?} must not leak into wire"
            );
        }
    }

    #[tokio::test]
    async fn invalid_target_always_emits_opaque_description() {
        let descs = [
            "federation rule matched but grant not allowed",
            "no rule matched (sub, audience)",
            "rule expired",
        ];
        for d in descs {
            let v = body_value(OidcApiError::InvalidTarget(d.to_string()).into_response()).await;
            assert_eq!(v["error"], "invalid_target");
            assert_eq!(v["error_description"], OPAQUE_INVALID_TARGET);
        }
    }

    #[tokio::test]
    async fn internal_error_never_leaks_inner_message() {
        let v =
            body_value(OidcApiError::Internal("private detail x42".to_string()).into_response())
                .await;
        assert_eq!(v["error"], "server_error");
        assert!(
            !v.to_string().contains("private detail"),
            "internal detail must never reach the wire"
        );
    }

    #[tokio::test]
    async fn invalid_request_passes_description_through() {
        let v = body_value(
            OidcApiError::InvalidRequest("missing audience".to_string()).into_response(),
        )
        .await;
        assert_eq!(v["error"], "invalid_request");
        assert_eq!(v["error_description"], "missing audience");
    }

    #[tokio::test]
    async fn unsupported_grant_type_carries_description() {
        let v = body_value(
            OidcApiError::UnsupportedGrantType("authorization_code".to_string()).into_response(),
        )
        .await;
        assert_eq!(v["error"], "unsupported_grant_type");
        assert!(v["error_description"]
            .as_str()
            .unwrap_or("")
            .contains("authorization_code"));
    }

    #[tokio::test]
    async fn invalid_scope_emits_canonical_code() {
        let v =
            body_value(OidcApiError::InvalidScope("admin:everything".to_string()).into_response())
                .await;
        assert_eq!(v["error"], "invalid_scope");
    }

    #[tokio::test]
    async fn token_errors_share_400_status() {
        let cases: Vec<OidcApiError> = vec![
            OidcApiError::InvalidRequest("x".into()),
            OidcApiError::InvalidGrant("x".into()),
            OidcApiError::InvalidTarget("x".into()),
            OidcApiError::UnsupportedGrantType("x".into()),
            OidcApiError::InvalidScope("x".into()),
        ];
        for e in cases {
            let resp = e.into_response();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }
    }
}
