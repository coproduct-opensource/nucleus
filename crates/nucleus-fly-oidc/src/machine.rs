//! Fetching *this* Fly machine's own OIDC token — the in-machine side of
//! the identity exchange.
//!
//! Every Fly Machine runs an init that serves a small API on the unix
//! socket `/.fly/api`. A `POST /v1/tokens/oidc` there mints a short-lived
//! JWT scoped to a requested audience; a runner or gateway calls this at
//! boot and hands the token to the control plane's `ExchangeFlyIdentity`.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::error::OidcError;

/// The in-machine Fly API unix socket.
const FLY_API_SOCKET: &str = "/.fly/api";

/// Best-effort source of this machine's Fly OIDC token: the
/// `NUCLEUS_FLY_TOKEN` env override if set (handy for local testing), else
/// [`fetch_machine_oidc_token`] over the in-machine socket. `None` when
/// neither path produces one — off-Fly local runs.
pub async fn obtain_fly_token(audience: &str) -> Option<String> {
    if let Ok(token) = std::env::var("NUCLEUS_FLY_TOKEN") {
        if !token.is_empty() {
            return Some(token);
        }
    }
    match fetch_machine_oidc_token(audience).await {
        Ok(token) => Some(token),
        Err(e) => {
            tracing::warn!(error = %e, audience, "could not fetch a Fly machine OIDC token");
            None
        }
    }
}

/// Fetch an OIDC token for this Fly machine, scoped to `audience`.
///
/// Issues `POST /v1/tokens/oidc` over the `/.fly/api` unix socket. Only
/// works inside a Fly Machine; off-Fly the connect fails and the caller
/// should fall back to a local identity.
pub async fn fetch_machine_oidc_token(audience: &str) -> Result<String, OidcError> {
    let body = format!(
        r#"{{"aud":{}}}"#,
        serde_json::to_string(audience).expect("audience string serializes")
    );
    let request = format!(
        "POST /v1/tokens/oidc HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len(),
    );

    let mut stream = UnixStream::connect(FLY_API_SOCKET)
        .await
        .map_err(|e| OidcError::Network(format!("connect {FLY_API_SOCKET}: {e}")))?;
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| OidcError::Network(format!("write to {FLY_API_SOCKET}: {e}")))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .map_err(|e| OidcError::Network(format!("read from {FLY_API_SOCKET}: {e}")))?;

    parse_token_response(&response)
}

/// Pull the token out of the raw HTTP response. The endpoint returns the
/// bare JWT as the response body.
fn parse_token_response(raw: &[u8]) -> Result<String, OidcError> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| OidcError::Network("malformed HTTP response from /.fly/api".to_string()))?;

    let status_line = head.lines().next().unwrap_or_default();
    if !status_line.contains(" 200") {
        return Err(OidcError::Network(format!(
            "/.fly/api token request failed: {status_line:?}"
        )));
    }

    let token = body.trim();
    if token.is_empty() {
        return Err(OidcError::Network(
            "/.fly/api returned an empty token".to_string(),
        ));
    }
    Ok(token.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_token_out_of_a_200_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc.d";
        assert_eq!(parse_token_response(raw).unwrap(), "abc.d");
    }

    #[test]
    fn rejects_a_non_200_response() {
        let raw = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        assert!(matches!(
            parse_token_response(raw),
            Err(OidcError::Network(_))
        ));
    }

    #[test]
    fn rejects_a_malformed_response() {
        assert!(matches!(
            parse_token_response(b"not http"),
            Err(OidcError::Network(_))
        ));
    }
}
