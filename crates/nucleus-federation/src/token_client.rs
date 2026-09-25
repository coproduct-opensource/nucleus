// SPDX-License-Identifier: MIT
//
//! The token-endpoint client: an assertion in, a short-lived Bearer out.
//!
//! This replaces the RFC 7523 client that used to live in one of the
//! per-provider validator crates, whose entry point now forwards here. Four
//! things it did are deliberately not carried over:
//!
//! - **It printed the token.** `ExchangedToken` derived `Debug` over the
//!   bearer, so any `{:?}` in a log line was a credential leak. Here the value
//!   is zeroizing, has no `Display`, and `Debug` prints `[redacted]`.
//! - **Its errors carried the endpoint's body.** Up to 200 bytes of it — and a
//!   token endpoint's error body can echo the scopes that were asked for,
//!   which ADR 0004 forbids revealing to the caller. [`ExchangeError`] carries
//!   a status code at most.
//! - **A missing `expires_in` became 0.** Zero is a lifetime ("already
//!   expired"); absence is not knowing. [`ExchangedToken::expires_in`] is an
//!   `Option`, and the caller's cache decides what not knowing means (the
//!   node's answer: use once).
//! - **It always sent `audience`, form-encoded, as an `assertion`.** Providers
//!   differ on all three, so grant, encoding and audience are request fields.
//!
//! Provider-specific identifiers (a federation rule id, an organization id)
//! travel in [`TokenRequest`]'s opaque `params`, which the operator supplies
//! and this crate never interprets.

use std::collections::BTreeMap;
use std::fmt;

use reqwest::Url;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::assertion::CompactJwt;
use crate::net::{REQUEST_TIMEOUT, read_capped, transport_allowed};

/// RFC 8693 §2.1 grant type.
pub const GRANT_TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// RFC 7523 §2.1 grant type.
pub const GRANT_JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
/// RFC 8693 §3 token type for a JWT subject token.
pub const TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";

/// The request keys this client sets itself. An operator `param` with one of
/// these names would either be overwritten or duplicate a standard field —
/// and a duplicated `grant_type` or `subject_token` is exactly the ambiguity
/// a parser-differential attack wants — so they are refused.
const RESERVED_PARAMS: &[&str] = &[
    "grant_type",
    "assertion",
    "subject_token",
    "subject_token_type",
    "audience",
    "scope",
];

/// Which grant presents the assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grant {
    /// RFC 8693: `subject_token` + `subject_token_type=…:jwt`.
    TokenExchange8693,
    /// RFC 7523: `assertion`.
    JwtBearer7523,
}

/// How the request body is encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// `application/x-www-form-urlencoded` (RFC 6749 §4.1.3 style).
    Form,
    /// `application/json`, one flat object of strings.
    Json,
}

/// One token request. Built by [`TokenRequest::new`], which refuses an
/// endpoint that is neither `https` nor loopback; `params` refuse the
/// standard keys. An invalid request therefore cannot reach [`exchange`].
#[derive(Debug, Clone)]
pub struct TokenRequest {
    endpoint: Url,
    grant: Grant,
    encoding: Encoding,
    subject: CompactJwt,
    audience: Option<String>,
    scope: Option<String>,
    params: BTreeMap<String, String>,
}

impl TokenRequest {
    /// A request presenting `subject` to `endpoint`.
    pub fn new(
        endpoint: Url,
        grant: Grant,
        encoding: Encoding,
        subject: CompactJwt,
    ) -> Result<Self, ExchangeError> {
        if !transport_allowed(&endpoint) {
            return Err(ExchangeError::InvalidRequest);
        }
        Ok(Self {
            endpoint,
            grant,
            encoding,
            subject,
            audience: None,
            scope: None,
            params: BTreeMap::new(),
        })
    }

    /// Send `audience`.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    /// Send `scope`.
    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// Add operator-supplied parameters, passed through untouched. Refuses
    /// the whole set if any key is one this client sets itself.
    pub fn with_params(mut self, params: BTreeMap<String, String>) -> Result<Self, ExchangeError> {
        if params.keys().any(|k| RESERVED_PARAMS.contains(&k.as_str())) {
            return Err(ExchangeError::InvalidRequest);
        }
        self.params.extend(params);
        Ok(self)
    }

    /// The endpoint this request goes to.
    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    /// The body's fields, in a fixed order: the grant, the subject, the
    /// optional standard fields, then operator params in key order.
    fn fields(&self) -> Vec<(&str, &str)> {
        let mut out: Vec<(&str, &str)> = Vec::with_capacity(5 + self.params.len());
        match self.grant {
            Grant::TokenExchange8693 => {
                out.push(("grant_type", GRANT_TOKEN_EXCHANGE));
                out.push(("subject_token", self.subject.expose()));
                out.push(("subject_token_type", TOKEN_TYPE_JWT));
            }
            Grant::JwtBearer7523 => {
                out.push(("grant_type", GRANT_JWT_BEARER));
                out.push(("assertion", self.subject.expose()));
            }
        }
        if let Some(a) = &self.audience {
            out.push(("audience", a));
        }
        if let Some(s) = &self.scope {
            out.push(("scope", s));
        }
        out.extend(self.params.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        out
    }

    /// The encoded body and its content type. Zeroizing: it holds the
    /// assertion.
    fn body(&self) -> Result<(Zeroizing<Vec<u8>>, &'static str), ExchangeError> {
        let fields = self.fields();
        match self.encoding {
            Encoding::Form => {
                let mut s = Zeroizing::new(String::new());
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        s.push('&');
                    }
                    form_encode_into(&mut s, k);
                    s.push('=');
                    form_encode_into(&mut s, v);
                }
                Ok((
                    Zeroizing::new(s.as_bytes().to_vec()),
                    "application/x-www-form-urlencoded",
                ))
            }
            Encoding::Json => {
                let map: serde_json::Map<String, serde_json::Value> = fields
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
                    .collect();
                let bytes = serde_json::to_vec(&map).map_err(|_| ExchangeError::InvalidRequest)?;
                Ok((Zeroizing::new(bytes), "application/json"))
            }
        }
    }
}

/// Percent-encode for `application/x-www-form-urlencoded`: the RFC 3986
/// unreserved set stays literal, everything else becomes `%XX`.
fn form_encode_into(out: &mut String, s: &str) {
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0xF) as usize] as char);
            }
        }
    }
}

/// A short-lived Bearer token minted by the exchange.
///
/// No `Display`, no `Clone`, no `Serialize`, and a `Debug` that prints
/// `[redacted]`: the value leaves only through [`ExchangedToken::expose`],
/// at the one point where it goes into an `Authorization` header.
pub struct ExchangedToken {
    access_token: Zeroizing<String>,
    expires_in: Option<u64>,
}

impl ExchangedToken {
    /// The access token, to be sent as `Authorization: Bearer <token>`.
    /// Named to be greppable: every call is a place the secret is plaintext.
    pub fn expose(&self) -> &str {
        &self.access_token
    }

    /// Seconds until expiry as the endpoint stated it, or `None` if it did
    /// not. `None` is not zero and not "forever": a caller that cannot
    /// bound the lifetime should use the token once.
    pub fn expires_in(&self) -> Option<u64> {
        self.expires_in
    }
}

impl fmt::Debug for ExchangedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExchangedToken")
            .field("access_token", &"[redacted]")
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

/// Why an exchange yielded no token. Coarse on purpose: nothing here
/// carries bytes the endpoint sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExchangeError {
    /// The request was refused locally before any I/O: a non-https,
    /// non-loopback endpoint, an operator param that collides with a
    /// standard key, or an unknown grant.
    #[error("token request is not valid")]
    InvalidRequest,
    /// Connect, TLS, timeout, an oversized body, or a redirect.
    #[error("token endpoint could not be reached")]
    Transport,
    /// The endpoint answered with a non-2xx status.
    #[error("token endpoint refused the exchange (status {status})")]
    Refused { status: u16 },
    /// A 2xx answer that is not an RFC 6749 §5.1 Bearer token response.
    #[error("token endpoint returned a malformed response")]
    Malformed,
}

/// The RFC 6749 §5.1 fields this client reads. `expires_in` is a raw value so
/// that "absent" and "present but not a non-negative integer" stay distinct:
/// the first is `None`, the second is malformed.
#[derive(Deserialize)]
struct SuccessBody {
    access_token: Option<String>,
    token_type: Option<String>,
    #[serde(default)]
    expires_in: Option<serde_json::Value>,
}

/// Exchange `req.subject` at `req.endpoint` for a Bearer token.
///
/// Fail-closed: `Ok` only for a 2xx JSON body with a non-empty
/// `access_token` and `token_type` equal to `Bearer` (case-insensitive),
/// from the endpoint itself rather than a redirect target. Build `http` with
/// [`crate::default_client`], or at least with redirects off.
pub async fn exchange(
    http: &reqwest::Client,
    req: &TokenRequest,
) -> Result<ExchangedToken, ExchangeError> {
    let (body, content_type) = req.body()?;
    let resp = http
        .post(req.endpoint.clone())
        .timeout(REQUEST_TIMEOUT)
        .header(reqwest::header::CONTENT_TYPE, content_type)
        .header(reqwest::header::ACCEPT, "application/json")
        // reqwest takes its own copy of the body; ours is wiped when `body`
        // drops at the end of this function. The transport's buffers are
        // outside what this crate can zero.
        .body(body.to_vec())
        .send()
        .await
        .map_err(|_| ExchangeError::Transport)?;

    // A client that follows redirects may have re-sent the assertion
    // elsewhere; whatever answered, it was not the endpoint the operator
    // registered, so its token is not one we asked for.
    if resp.url() != &req.endpoint {
        return Err(ExchangeError::Transport);
    }
    let status = resp.status();
    if !status.is_success() {
        // The body is dropped unread. It is the endpoint's to explain, not
        // ours to carry: it can echo the scopes requested.
        return Err(ExchangeError::Refused {
            status: status.as_u16(),
        });
    }
    let bytes = read_capped(resp).await.ok_or(ExchangeError::Transport)?;
    let parsed: SuccessBody =
        serde_json::from_slice(&bytes).map_err(|_| ExchangeError::Malformed)?;

    match parsed.token_type.as_deref() {
        Some(t) if t.eq_ignore_ascii_case("bearer") => {}
        _ => return Err(ExchangeError::Malformed),
    }
    // Wrapping moves the parsed String's allocation; nothing is copied.
    let access_token = Zeroizing::new(
        parsed
            .access_token
            .filter(|t| !t.is_empty())
            .ok_or(ExchangeError::Malformed)?,
    );
    let expires_in = match parsed.expires_in {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(v.as_u64().ok_or(ExchangeError::Malformed)?),
    };
    Ok(ExchangedToken {
        access_token,
        expires_in,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(grant: Grant, enc: Encoding) -> TokenRequest {
        TokenRequest::new(
            Url::parse("https://token.example/oauth/token").unwrap(),
            grant,
            enc,
            CompactJwt::new("h.p.s"),
        )
        .unwrap()
    }

    #[test]
    fn a_cleartext_non_loopback_endpoint_is_refused() {
        let r = TokenRequest::new(
            Url::parse("http://token.example/oauth/token").unwrap(),
            Grant::JwtBearer7523,
            Encoding::Form,
            CompactJwt::new("h.p.s"),
        );
        assert_eq!(r.unwrap_err(), ExchangeError::InvalidRequest);
    }

    #[test]
    fn every_standard_key_is_reserved() {
        for k in RESERVED_PARAMS {
            let p = BTreeMap::from([(k.to_string(), "x".to_string())]);
            let r = req(Grant::TokenExchange8693, Encoding::Form).with_params(p);
            assert_eq!(r.unwrap_err(), ExchangeError::InvalidRequest, "{k}");
        }
    }

    #[test]
    fn form_encoding_escapes_reserved_characters() {
        let mut s = String::new();
        form_encode_into(&mut s, "a b&c=d/é");
        assert_eq!(s, "a%20b%26c%3Dd%2F%C3%A9");
    }

    #[test]
    fn debug_of_a_request_does_not_print_the_assertion() {
        let r = req(Grant::JwtBearer7523, Encoding::Json);
        assert!(!format!("{r:?}").contains("h.p.s"));
    }
}
