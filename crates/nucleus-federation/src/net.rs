// SPDX-License-Identifier: MIT
//
//! The few transport rules both directions share.

use std::net::IpAddr;
use std::time::Duration;

use reqwest::Url;
use zeroize::Zeroizing;

/// Upper bound on one request, connect to last byte. A token endpoint or a
/// JWKS server that hangs must not hold a pod's call — or an inbound
/// exchange — open indefinitely.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The largest response body read from a token endpoint, discovery document
/// or JWKS. All three are a few hundred bytes to a few KiB; a server that
/// streams more is either broken or trying to exhaust memory.
pub(crate) const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// A reqwest client fit for federation traffic: bounded timeouts and **no
/// redirects**.
///
/// The redirect rule is the load-bearing one. reqwest follows a 307/308 by
/// re-sending the same POST body, and the body of a token request is the
/// assertion. A token endpoint that redirected would hand the assertion to
/// wherever it pointed. [`crate::exchange`] also refuses a response whose
/// final URL is not the endpoint, but by then the body has gone, so the
/// client must not follow in the first place. Callers that build their own
/// client must set `redirect::Policy::none()` too.
///
/// A rustls crypto provider must already be installed: this crate links
/// reqwest with `rustls-no-provider`, like the rest of the workspace, and
/// reqwest PANICS building a TLS client without one rather than returning the
/// `Err` this signature suggests. A caller that cannot guarantee the ordering
/// checks `rustls::crypto::CryptoProvider::get_default()` first.
pub fn default_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(REQUEST_TIMEOUT)
        .build()
}

/// Whether a URL may carry federation traffic: `https`, or plain `http` to a
/// loopback address.
///
/// Loopback is allowed so the hermetic tests (and a sidecar on the same
/// host) work. Anything else in cleartext would put an assertion, a token or
/// a JWKS — which decides whose signatures are believed — on the network
/// unprotected.
pub(crate) fn transport_allowed(url: &Url) -> bool {
    match url.scheme() {
        "https" => url.host().is_some(),
        "http" => match url.host_str() {
            Some(h) if h.eq_ignore_ascii_case("localhost") => true,
            // `host_str` brackets an IPv6 literal; strip them before parsing.
            Some(h) => h
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<IpAddr>()
                .is_ok_and(|ip| ip.is_loopback()),
            None => false,
        },
        _ => false,
    }
}

/// Read a response body, refusing one larger than [`MAX_RESPONSE_BYTES`].
///
/// The buffer is zeroizing because on the token path it holds the access
/// token in plaintext until it is parsed out.
pub(crate) async fn read_capped(mut resp: reqwest::Response) -> Option<Zeroizing<Vec<u8>>> {
    let mut buf = Zeroizing::new(Vec::new());
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                if buf.len() + chunk.len() > MAX_RESPONSE_BYTES {
                    return None;
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(None) => return Some(buf),
            Err(_) => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(s: &str) -> bool {
        transport_allowed(&Url::parse(s).unwrap())
    }

    #[test]
    fn https_anywhere_and_http_only_to_loopback() {
        assert!(allowed("https://token.example/oauth/token"));
        assert!(allowed("http://127.0.0.1:8080/t"));
        assert!(allowed("http://[::1]:8080/t"));
        assert!(allowed("http://localhost/t"));
        assert!(!allowed("http://token.example/t"));
        assert!(!allowed("http://10.0.0.1/t"));
        assert!(!allowed("ftp://token.example/t"));
    }
}
