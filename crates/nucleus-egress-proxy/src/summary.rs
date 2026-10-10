//! The canonical summary of one request: what the node decides on.
//!
//! ADR 0015 §2: the proxy sends the node method, normalised origin and path,
//! header names, body length and body hash. They travel as the `subject` of
//! one [`nucleus_decision_protocol::GuestFrame::Decide`] (no new wire format,
//! §7), in a text form with exactly one spelling per request:
//!
//! ```text
//! POST http://api.example:443/v1/items?x=1
//! headers=accept,content-type
//! body=3:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
//! ```
//!
//! [`Summary::parse`] is total and canonical: it accepts a text only if
//! [`Summary::text`] of what it parsed is that text again. The node parses the
//! subject with it, decides on the parsed value, and computes the frame's
//! digest itself with [`digest`] (ADR 0007 C-2: the checker mints the
//! binding, the proxy's digest is only compared against it). Both ends link
//! this one module, so they cannot spell a request two ways (G-1).

use std::collections::BTreeSet;

use nucleus_decision_protocol::{ArgsDigest, Operation, Subject};
use sha2::{Digest, Sha256};

use crate::Refusal;
use crate::request::{Method, Origin, Request, check_path, check_query, parse_authority};

/// The operation every proxied request is decided as. One constant, so the
/// proxy and the node cannot ask and answer about different operations.
pub const OPERATION: Operation = Operation::WebFetch;

/// Domain separation for [`digest`], so a summary digest is never equal to
/// a digest of the same bytes computed for another purpose.
const DIGEST_DOMAIN: &[u8] = b"nucleus-egress-proxy/summary/v1\0";

/// One request, as the node decides it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub method: Method,
    pub origin: Origin,
    /// Starts with `/`, checked as the guest-facing parser checks it.
    pub path: String,
    pub query: Option<String>,
    /// The forwarded header NAMES, lower-case. Never their values.
    pub header_names: BTreeSet<String>,
    pub body_len: u64,
    pub body_sha256: [u8; 32],
}

/// Why a subject is not a summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SummaryError {
    /// Not three lines of the expected shape.
    Shape,
    /// A method outside [`Method`].
    Method,
    /// The URL is not `http://host:port/path[?query]` as the parser accepts.
    Url,
    /// A header name that is not a lower-case token.
    HeaderName,
    /// The body line is not `len:hex64`.
    Body,
    /// It parsed, but [`Summary::text`] spells it differently.
    NotCanonical,
}

impl Summary {
    /// The summary of `request` with `body`.
    pub fn of(request: &Request, body: &[u8]) -> Self {
        let Request {
            method,
            origin,
            path,
            query,
            headers,
            content_length: _,
        } = request;
        Self {
            method: *method,
            origin: origin.clone(),
            path: path.clone(),
            query: query.clone(),
            header_names: headers.iter().map(|(n, _)| n.clone()).collect(),
            body_len: u64::try_from(body.len()).unwrap_or(u64::MAX),
            body_sha256: Sha256::digest(body).into(),
        }
    }

    /// `http://host:port/path[?query]`: the URL the node's registry matches
    /// and the pod policy decides.
    pub fn url(&self) -> String {
        match &self.query {
            Some(q) => format!("{}{}?{q}", self.origin, self.path),
            None => format!("{}{}", self.origin, self.path),
        }
    }

    /// The canonical text.
    pub fn text(&self) -> String {
        let Self {
            method,
            origin: _,
            path: _,
            query: _,
            header_names,
            body_len,
            body_sha256,
        } = self;
        let names: Vec<&str> = header_names.iter().map(String::as_str).collect();
        format!(
            "{} {}\nheaders={}\nbody={body_len}:{}",
            method.as_str(),
            self.url(),
            names.join(","),
            hex::encode(body_sha256)
        )
    }

    /// The decision frame's subject.
    ///
    /// # Errors
    /// [`Refusal::SummaryTooLong`] when the text does not fit one frame: a
    /// request the node cannot be asked about is not sent.
    pub fn subject(&self) -> Result<Subject, Refusal> {
        Subject::new(self.text()).map_err(|_| Refusal::SummaryTooLong)
    }

    /// Parse a subject back into a summary. Total; canonical.
    ///
    /// # Errors
    /// The first [`SummaryError`] found.
    pub fn parse(text: &str) -> Result<Self, SummaryError> {
        let mut lines = text.split('\n');
        let (Some(first), Some(headers), Some(body), None) =
            (lines.next(), lines.next(), lines.next(), lines.next())
        else {
            return Err(SummaryError::Shape);
        };
        let (method, url) = first.split_once(' ').ok_or(SummaryError::Shape)?;
        let method = Method::from_token(method).ok_or(SummaryError::Method)?;
        let rest = url.strip_prefix("http://").ok_or(SummaryError::Url)?;
        let split = rest.find('/').ok_or(SummaryError::Url)?;
        let (authority, tail) = rest.split_at(split);
        let origin = parse_authority(authority).map_err(|_| SummaryError::Url)?;
        let (path, query) = match tail.split_once('?') {
            Some((p, q)) => (p, Some(q)),
            None => (tail, None),
        };
        check_path(path).map_err(|_| SummaryError::Url)?;
        if let Some(q) = query {
            check_query(q).map_err(|_| SummaryError::Url)?;
        }
        let names = headers
            .strip_prefix("headers=")
            .ok_or(SummaryError::Shape)?;
        let mut header_names = BTreeSet::new();
        if !names.is_empty() {
            for name in names.split(',') {
                let token = !name.is_empty()
                    && name.bytes().all(|b| {
                        b.is_ascii_lowercase()
                            || b.is_ascii_digit()
                            || b"!#$%&'*+-.^_`|~".contains(&b)
                    });
                if !token {
                    return Err(SummaryError::HeaderName);
                }
                header_names.insert(name.to_string());
            }
        }
        let body = body.strip_prefix("body=").ok_or(SummaryError::Shape)?;
        let (len, hash) = body.split_once(':').ok_or(SummaryError::Body)?;
        let body_len = len.parse::<u64>().map_err(|_| SummaryError::Body)?;
        let mut body_sha256 = [0u8; 32];
        hex::decode_to_slice(hash, &mut body_sha256).map_err(|_| SummaryError::Body)?;
        let summary = Self {
            method,
            origin,
            path: path.to_string(),
            query: query.map(str::to_string),
            header_names,
            body_len,
            body_sha256,
        };
        if summary.text() == text {
            Ok(summary)
        } else {
            Err(SummaryError::NotCanonical)
        }
    }
}

/// The action digest of a summary's text: what a decision id is bound to.
/// The node computes it from the subject it received; the proxy's copy in
/// the frame is only compared with it.
pub fn digest(text: &str) -> ArgsDigest {
    let mut h = Sha256::new();
    h.update(DIGEST_DOMAIN);
    h.update(text.as_bytes());
    ArgsDigest::new(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::{Parsed, parse_head};

    fn request(raw: &str) -> Request {
        match parse_head(raw.as_bytes()) {
            Ok(Parsed::Complete { request, .. }) => request,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_text_round_trips_and_is_the_only_spelling() {
        let r = request(
            "POST http://api.example/v1/items?x=1 HTTP/1.1\r\nHost: api.example\r\n\
             Content-Type: text/plain\r\nAccept: */*\r\nContent-Length: 3\r\n\r\n",
        );
        let s = Summary::of(&r, b"abc");
        let text = s.text();
        assert_eq!(
            text,
            "POST http://api.example:80/v1/items?x=1\nheaders=accept,content-type\n\
             body=3:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(Summary::parse(&text), Ok(s));
        for other in [
            text.replace(":80/", "/"),
            text.replace("api.example", "API.example"),
            text.replace("accept,content-type", "content-type,accept"),
            text.replace("body=3:", "body=03:"),
            text.replace("ba78", "BA78"),
            format!("{text}\n"),
        ] {
            assert!(Summary::parse(&other).is_err(), "{other:?}");
        }
    }

    #[test]
    fn the_digest_is_domain_separated() {
        let plain: [u8; 32] = Sha256::digest(b"x").into();
        assert_ne!(*digest("x").as_bytes(), plain);
    }
}
