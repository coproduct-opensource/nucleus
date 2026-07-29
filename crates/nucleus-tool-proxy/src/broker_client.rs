//! The guest's side of the credential broker.
//!
//! # What this replaces
//!
//! Today the tool-proxy reads credential values out of its own `PodSpec`, which
//! means those values are inside the guest — in a file the agent can read. The
//! broker exists so the values stay host-side and the guest asks for an action
//! instead of a secret.
//!
//! This is the asking half. It sends a
//! [`TaskRequestEnvelope`](nucleus_cred_protocol::TaskRequestEnvelope) over
//! vsock to the host and reads back an outcome. **It never receives a
//! credential**, and cannot: `Credential` (which lives in the host-only broker crate this one deliberately
//! does not link) has no
//! `Serialize` impl, so the host's response type could not carry one even if
//! someone tried.
//!
//! # Failure is a refusal, never a fallback
//!
//! Every failure — no socket, connection refused, timeout, malformed reply —
//! resolves to "not granted". The tempting alternative is to fall back to
//! reading the credential from the spec when the broker is unreachable, which
//! would make the broker advisory: an attacker who could break the connection
//! would restore the old exposure. A broker that can be bypassed by breaking it
//! is not a boundary.
//!
//! # On retries and idempotency
//!
//! Agents retry, and a timeout can hide a completed side effect. That matters
//! enormously for a broker that *performs actions*, where a duplicate retry is a
//! duplicate action — the standard answer is an idempotency key the server
//! remembers.
//!
//! This request carries none, deliberately, because it is currently a **query**:
//! "may I, and is a credential available". Asking twice changes nothing. The
//! moment the broker gains a `perform` operation, that stops being true and an
//! idempotency key becomes mandatory — recorded here so it is a decision rather
//! than an omission.

// Not yet called: the tool-proxy still reads credential values from its spec,
// and switching it over is gated on `BrokerRollout::Enforcing` on the host.
// Landed first so the fail-closed reply semantics are reviewable on their own,
// rather than inside the change that also rewires credential delivery.
#![cfg_attr(not(test), allow(dead_code))]

use std::time::Duration;

/// How long the guest waits for the host to answer.
///
/// Shorter than the host's own connection deadline so the guest gives up first
/// and reports a refusal, rather than both sides sitting on the same timeout and
/// racing to decide who reports the failure.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The outcome of asking the broker.
///
/// Deliberately not a `Result<Credential, _>`: there is no shape of this type
/// that carries a secret, because the guest is never supposed to hold one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrokerOutcome {
    /// The host authorised the request.
    Granted,
    /// The host refused, or could not be reached.
    ///
    /// One variant for both on purpose. A guest that could distinguish "denied"
    /// from "broker down" would learn something about host state from a failure
    /// it caused, and the correct behaviour is identical either way.
    NotGranted,
}

impl BrokerOutcome {
    /// Whether the action may proceed.
    pub fn is_granted(self) -> bool {
        matches!(self, BrokerOutcome::Granted)
    }
}

/// Interpret the host's reply line.
///
/// Fails closed on everything: unparseable JSON, a missing field, an unexpected
/// shape. Only an explicit `{"granted": true}` is a grant.
pub fn parse_reply(line: &str) -> BrokerOutcome {
    #[derive(serde::Deserialize)]
    struct Reply {
        granted: bool,
    }
    match serde_json::from_str::<Reply>(line) {
        Ok(r) if r.granted => BrokerOutcome::Granted,
        _ => BrokerOutcome::NotGranted,
    }
}

/// Build the request line for an envelope.
///
/// Newline-terminated because the host frames on newlines — vsock has no
/// message boundaries, so the delimiter is the protocol.
pub fn request_line(envelope: &nucleus_cred_protocol::TaskRequestEnvelope) -> String {
    let mut s = serde_json::to_string(envelope).unwrap_or_default();
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_cred_protocol::TaskRequestEnvelope;

    fn envelope() -> TaskRequestEnvelope {
        TaskRequestEnvelope {
            operation: "WebFetch".to_string(),
            target: "api.example.test".to_string(),
            justification: "routine".to_string(),
        }
    }

    /// Only an explicit grant is a grant, and `is_granted` agrees with the
    /// variant — the accessor is what call sites will branch on, so a version of
    /// it that disagreed with the enum would defeat the parsing above.
    #[test]
    fn an_explicit_grant_is_the_only_grant() {
        assert!(BrokerOutcome::Granted.is_granted());
        assert!(!BrokerOutcome::NotGranted.is_granted());
        assert_eq!(
            parse_reply(r#"{"granted":true,"reason":"granted"}"#),
            BrokerOutcome::Granted
        );
        assert_eq!(
            parse_reply(r#"{"granted":false,"reason":"not permitted"}"#),
            BrokerOutcome::NotGranted
        );
    }

    /// **Everything unrecognisable is a refusal.** A guest that treated a
    /// malformed or truncated reply as success would turn any disruption of the
    /// host connection into an authorisation bypass.
    #[test]
    fn every_malformed_reply_fails_closed() {
        for reply in [
            "",
            "not json",
            "{}",
            r#"{"granted":"true"}"#, // string, not bool
            r#"{"grant":true}"#,     // wrong field
            r#"{"granted":true"#,    // truncated mid-object
            "null",
            "[]",
        ] {
            assert_eq!(
                parse_reply(reply),
                BrokerOutcome::NotGranted,
                "a reply of {reply:?} must not be read as a grant"
            );
        }
    }

    /// The request is newline-terminated, because that is how the host frames.
    #[test]
    fn the_request_is_newline_terminated() {
        let line = request_line(&envelope());
        assert!(
            line.ends_with('\n'),
            "the host frames on newlines: {line:?}"
        );
        assert_eq!(line.matches('\n').count(), 1, "exactly one terminator");
    }

    /// The request round-trips into what the host parses.
    #[test]
    fn the_request_parses_as_the_envelope_the_host_expects() {
        let line = request_line(&envelope());
        let back: TaskRequestEnvelope =
            serde_json::from_str(line.trim_end()).expect("the host must be able to parse this");
        assert_eq!(back, envelope());
    }

    /// The guest gives up before the host does, so the failure is reported once
    /// rather than raced between the two sides.
    #[test]
    fn the_guest_deadline_is_shorter_than_the_hosts() {
        // nucleus_node::broker_transport::CONNECTION_TIMEOUT is 10s; the guest
        // must be strictly under it. Duplicated as a literal because the guest
        // cannot depend on the node crate — that is the whole point of the
        // boundary — so this is a stated coupling, not an enforced one.
        const HOST_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
        assert!(
            REQUEST_TIMEOUT < HOST_CONNECTION_TIMEOUT,
            "the guest must time out first"
        );
    }
}
