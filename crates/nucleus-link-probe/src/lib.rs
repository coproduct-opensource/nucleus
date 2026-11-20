//! The links gauntlet's in-guest workload (ADR 0017 §10): what it reports, and
//! how the host reads it back.
//!
//! The probe decides nothing. It serves, sends or attacks, and prints one
//! sentinel line per thing it saw, on stdout and stderr (stderr reaches the
//! guest console log, as `nucleus-podlist-probe`'s does). The host harness
//! (`nucleus-cli` `host_evidence_live::links`) holds the ids of every pod and
//! decides each property from what both ends reported.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The prefix of every report line.
pub const SENTINEL: &str = "NUCLEUS_LINK_PROBE ";

/// The suffix of a link's DNS name (ADR 0017 L4b).
pub const LINK_SUFFIX: &str = ".link.nucleus.invalid";

/// The header that carries a request's id end to end.
pub const ID_HEADER: &str = "x-gauntlet-id";

/// How one adversary attempt ended, as the guest saw it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptOutcome {
    /// Refused before anything reached a destination: a denied syscall, a
    /// refusal status from the relay, a failed handshake, a closed connection.
    Refused,
    /// Answered with a success status: the host decided it. The harness checks
    /// the destination for whether such a request was ever meant to arrive.
    Answered,
    /// A raw channel opened that no host decision stands behind (a vsock
    /// connect that succeeded). Always a failure.
    Reached,
    /// The probe could not run the attempt at all (setup failure). Not a pass.
    NotRun,
}

/// One thing the probe saw.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    /// `serve`: a request arrived at the workload.
    Received {
        id: String,
        method: String,
        path: String,
        port: u16,
        body_sha256: String,
    },
    /// `serve`: a port is bound and listening. Found on the first live run
    /// (2026-11-19): an unlinked canary that is working correctly reports
    /// nothing else, which read the same as a canary whose logs were never
    /// found.
    Listening { port: u16 },
    /// `serve`: a port could not be bound (for example 443 as an unprivileged
    /// workload).
    BindFailed { port: u16, error: String },
    /// `send`: one request and what came back.
    Sent {
        id: String,
        port: u32,
        tls: bool,
        status: Option<u16>,
        error: Option<String>,
        /// Milliseconds since the probe started.
        at_ms: u64,
    },
    /// `adversary`: one attempt.
    Attempt {
        name: String,
        outcome: AttemptOutcome,
        detail: String,
        /// The request id the attempt carried, if it was an HTTP request.
        id: Option<String>,
    },
    /// The mode finished.
    Done { mode: String },
}

/// The report line for `event`.
#[must_use]
pub fn line(event: &Event) -> String {
    let body = serde_json::to_string(event).unwrap_or_else(|_| "{}".into());
    format!("{SENTINEL}{body}")
}

/// Every event in `log`, in order. Lines without the sentinel, and sentinel
/// lines that do not parse, are skipped (a console log interleaves kernel
/// output). Each line is read once even if it was echoed to both streams: the
/// caller passes one stream, or dedups by id.
#[must_use]
pub fn parse(log: &str) -> Vec<Event> {
    log.lines()
        .filter_map(|l| l.split_once(SENTINEL).map(|(_, rest)| rest.trim()))
        .filter_map(|json| serde_json::from_str(json).ok())
        .collect()
}

/// A request id that is unique per (seed, tag, index) and unguessable by a
/// different seed: the harness learns ids only from reports.
#[must_use]
pub fn request_id(seed: u64, tag: &str, index: u64) -> String {
    let mut h = Sha256::new();
    h.update(seed.to_le_bytes());
    h.update(tag.as_bytes());
    h.update(index.to_le_bytes());
    hex::encode(&h.finalize()[..12])
}

/// The link host for a destination pod id.
#[must_use]
pub fn link_host(dst: &str) -> String {
    format!("{dst}{LINK_SUFFIX}")
}

/// The status code of an HTTP/1.x response head, if `head` starts with one.
#[must_use]
pub fn status_of(head: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(head.get(..head.len().min(64))?).ok()?;
    let mut parts = text.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    parts.next()?.parse().ok()
}

/// SHA-256 of a request body, hex.
#[must_use]
pub fn body_digest(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

/// A parsed request head: method, path, and the id header if present.
#[derive(Debug, PartialEq, Eq)]
pub struct Head {
    pub method: String,
    pub path: String,
    pub id: Option<String>,
    pub content_length: usize,
}

/// Parse a request head (everything before the blank line). `None` if it is
/// not an HTTP/1.x request line.
#[must_use]
pub fn parse_head(head: &str) -> Option<Head> {
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_owned();
    let path = first.next()?.to_owned();
    if !first.next()?.starts_with("HTTP/1.") {
        return None;
    }
    let mut id = None;
    let mut content_length = 0;
    for l in lines {
        let Some((k, v)) = l.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim());
        if k == ID_HEADER {
            id = Some(v.to_owned());
        } else if k == "content-length" {
            content_length = v.parse().unwrap_or(0);
        }
    }
    Some(Head {
        method,
        path,
        id,
        content_length,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_report_round_trips_through_a_noisy_console() {
        let e = Event::Sent {
            id: "a1".into(),
            port: 8080,
            tls: false,
            status: Some(200),
            error: None,
            at_ms: 7,
        };
        let log = format!(
            "[    1.0] kernel noise\n{}\r\nnot {SENTINEL}json\n{}\n",
            line(&e),
            line(&Event::Done {
                mode: "send".into()
            })
        );
        assert_eq!(
            parse(&log),
            vec![
                e,
                Event::Done {
                    mode: "send".into()
                }
            ]
        );
    }

    #[test]
    fn listening_round_trips_through_a_noisy_console() {
        let line = format!(
            "[    2.1] [workload] {}",
            line(&Event::Listening { port: 8080 })
        );
        assert_eq!(parse(&line), vec![Event::Listening { port: 8080 }]);
    }

    #[test]
    fn ids_are_distinct_and_seeded() {
        assert_ne!(request_id(1, "s", 0), request_id(1, "s", 1));
        assert_ne!(request_id(1, "s", 0), request_id(2, "s", 0));
        assert_ne!(request_id(1, "s", 0), request_id(1, "t", 0));
        assert_eq!(request_id(1, "s", 0), request_id(1, "s", 0));
    }

    #[test]
    fn status_and_head_parse() {
        assert_eq!(status_of(b"HTTP/1.1 403 Forbidden\r\n"), Some(403));
        assert_eq!(status_of(b"garbage"), None);
        let h =
            parse_head("POST /r/x HTTP/1.1\r\nHost: h\r\nX-Gauntlet-Id: abc\r\nContent-Length: 3")
                .unwrap();
        assert_eq!(
            h,
            Head {
                method: "POST".into(),
                path: "/r/x".into(),
                id: Some("abc".into()),
                content_length: 3
            }
        );
        assert!(parse_head("not a request").is_none());
    }
}
