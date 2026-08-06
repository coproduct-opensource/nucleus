//! Host-side collection of Article 12 records streamed from pods.
//!
//! # Why the host holds a copy at all
//!
//! A log the pod writes and the host reads later can be rewritten in between, so
//! an attestation over it binds a head the pod REPORTED rather than one the host
//! OBSERVED. Receiving each record as it is produced removes that gap: the host
//! already holds record N when the pod tries to drop it.
//!
//! This is the collector half of `nucleus-tool-proxy`'s `art12_shipper`. The pod
//! keeps its own log — that is the fast path and what its chain head is computed
//! over — and this is the copy the pod cannot retract.
//!
//! # What this does NOT do
//!
//! It does not re-verify the record chain. Records arrive one at a time and out
//! of order under retry, so chaining is checked by `nucleus-audit verify-art12`
//! over the assembled file, not here. This layer is responsible for exactly two
//! things: refusing records that are not HMAC-authentic, and never losing one it
//! accepted.

use std::path::{Path, PathBuf};

use tokio::io::AsyncWriteExt;

/// Where a session's collected records live on the host.
///
/// Under the node's state dir, never under the pod's work dir: this is the
/// host's record ABOUT the session and must not be in the session's reach. The
/// same reasoning as blocking `.nucleus-exit-report.json` from the agent's path
/// lattice, applied one layer up — here it is structural, because the guest has
/// no path to the node's state dir at all.
#[must_use]
pub fn session_log_path(state_dir: &Path, session_id: &str) -> PathBuf {
    // The session id comes off the wire. Anything but a plain identifier is
    // rejected by `sanitize_session_id` before reaching here, so this cannot
    // traverse out of the directory.
    state_dir.join("art12").join(format!("{session_id}.jsonl"))
}

/// Reject a session id that could escape the collection directory.
///
/// Deliberately an allowlist of characters rather than a scan for `..`: a
/// blocklist of traversal spellings is a losing game, and nothing legitimate
/// needs more than this.
#[must_use]
pub fn sanitize_session_id(raw: &str) -> Option<String> {
    if raw.is_empty()
        || raw.len() > 128
        || !raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return None;
    }
    Some(raw.to_string())
}

/// Append one authenticated record line to the session's collected log.
///
/// # Errors
/// If the directory cannot be created or the append fails. The caller must
/// surface that to the pod as a non-success status: a pod told "accepted" for a
/// record the host did not keep would carry on believing it was witnessed, which
/// is worse than refusing.
pub async fn append_record(
    state_dir: &Path,
    session_id: &str,
    line: &str,
) -> Result<(), std::io::Error> {
    let path = session_log_path(state_dir, session_id);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let mut f = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await?;
    f.write_all(line.trim_end().as_bytes()).await?;
    f.write_all(b"\n").await?;
    // Flushed AND synced: an accepted record that is only in the page cache is
    // lost by a host crash, and the pod has already been told it is safe.
    f.flush().await?;
    f.sync_data().await?;
    Ok(())
}

/// What the HOST observed of a session's Article 12 records.
///
/// Computed from the node's own collected file, not from anything the pod said.
/// This is the value the executor attestation binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedChain {
    /// Hash of the last record the host received, as that record carries it.
    pub head: String,
    /// How many records the host received.
    pub records: u64,
}

/// Read back what the host collected for a session.
///
/// Returns `None` when nothing was collected — distinct from a session that
/// collected zero records, which cannot happen (the file is created on first
/// append). `None` therefore means the channel was never used, and the caller
/// must not present that as an observation.
///
/// # Deliberately NOT re-verifying the chain here
///
/// This reports what arrived. Whether it chains, and whether each record is
/// authentic, is `nucleus-audit verify-art12`'s job over the assembled file —
/// one implementation of that logic, not two that must agree.
pub fn observed_chain(state_dir: &Path, session_id: &str) -> Option<ObservedChain> {
    let path = session_log_path(state_dir, session_id);
    let body = std::fs::read_to_string(path).ok()?;
    let mut records = 0u64;
    let mut head = String::new();
    for line in body.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            // A malformed line means the host stored something it should not
            // have, or the file was edited. Either way the observation is not
            // trustworthy and must not be reported as one.
            return None;
        };
        head = v
            .get("hash")
            .and_then(|h| h.as_str())
            .unwrap_or("")
            .to_string();
        records += 1;
    }
    (records > 0).then_some(ObservedChain { head, records })
}

/// Configure a pod's Article 12 record-keeping — LOCAL DRIVER ONLY.
///
/// # This does not cover Firecracker pods, and that is not an oversight to
/// # discover later
///
/// A guest inside a microVM cannot reach the node's HTTP listen address: it
/// talks to the host over vsock, and its environment is set by
/// `nucleus-guest-init`, not by a `Command` here. So the evidence channel is
/// currently provisioned for the local driver only.
///
/// The musl build — the one that ships — compiles `spawn_local_pod` out
/// entirely, so `-D warnings` reported this function as dead. That is the
/// dead-code check doing exactly its job: the mechanism existed and nothing on
/// the shipping path reached it.
///
/// Wiring Firecracker means shipping over vsock rather than HTTP. Until that
/// lands, a Firecracker pod keeps a pod-side log and the executor attests the
/// head the POD reported — the weaker guarantee, which `attest_art12` records
/// honestly rather than disguising.
///
/// The log lives in the pod's NODE-side directory, never in `work_dir`: it is
/// the runtime's record ABOUT the session, and the tool proxy refuses a
/// workspace path outright for that reason.
///
/// The ship URL points back at this node. Without it a pod's log is only
/// pod-side, so the executor could attest a head the pod REPORTED rather than
/// one the host observed — the gap streaming exists to close.
///
/// Both are set together, in one function, on purpose: a log with no channel is
/// the weaker configuration, and it should not be reachable by forgetting a
/// line at a call site.
#[cfg(feature = "local-driver")]
pub fn provision_pod_env(
    command: &mut tokio::process::Command,
    pod_dir: &Path,
    listen_addr: &str,
    pod_id: &str,
) {
    command.env(
        "NUCLEUS_TOOL_PROXY_ART12_LOG",
        pod_dir.join("art12.jsonl").to_string_lossy().as_ref(),
    );
    command.env(
        "NUCLEUS_TOOL_PROXY_ART12_SHIP_URL",
        format!("http://{listen_addr}/v1/art12/{pod_id}"),
    );
}

/// `POST /v1/art12/{session_id}` — one Article 12 record from a pod.
///
/// The handler lives here, beside the storage and the reasoning that governs it,
/// rather than in `main.rs`: the decision about what to accept IS this module's
/// subject, and splitting it from `accept` would put the authentication check in
/// one file and the reason for it in another.
pub async fn art12_append(
    axum::extract::State(state): axum::extract::State<crate::NodeState>,
    axum::extract::Path(sid): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    body: String,
) -> impl axum::response::IntoResponse {
    let sig = headers
        .get("X-Nucleus-Signature")
        .and_then(|v| v.to_str().ok());
    accept(
        &state.state_dir,
        state.trust_gate.art12_secret(),
        &sid,
        sig,
        &body,
    )
    .await
}

/// Authenticate and store one record, returning the status the pod will see.
///
/// # Every refusal here stops the pod
///
/// A non-success status makes the shipper latch degraded, which makes the pod
/// refuse its next operation. That coupling is deliberate: if the host cannot
/// witness a decision, the pod should stop making them. The alternative is a pod
/// that keeps acting while its evidence goes nowhere.
///
/// So the failure paths matter more than the success one, and each is distinct:
/// * no secret configured — the host cannot authenticate anything, so it accepts
///   nothing. An empty key would make EVERY signature verify, which is the
///   fail-open reading of "not configured".
/// * bad or missing signature — evidence anyone can append to is not evidence.
/// * storage failure — reported as failure, never as success. A pod told
///   "accepted" for a record the host did not keep carries on believing it was
///   witnessed.
pub async fn accept(
    state_dir: &Path,
    secret: Option<&[u8]>,
    raw_session_id: &str,
    signature: Option<&str>,
    body: &str,
) -> (axum::http::StatusCode, &'static str) {
    use axum::http::StatusCode;

    let Some(session_id) = sanitize_session_id(raw_session_id) else {
        return (StatusCode::BAD_REQUEST, "invalid session id");
    };
    let Some(secret) = secret else {
        tracing::error!(%session_id, "refusing Article 12 records: no receipt secret configured");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "no art12 secret configured",
        );
    };
    let Some(signature) = signature else {
        return (StatusCode::UNAUTHORIZED, "missing signature");
    };
    // Verify over the DESTINATION as well as the payload. Verifying the body
    // alone authenticated "someone holding the receipt secret said this", never
    // "…and meant it for THIS session" — so a validly-signed record could be
    // replayed into any other session's chain by changing the URL path, and
    // every pod configured with the node-wide receipt secret can sign.
    let signed = nucleus_client::art12_signed_bytes(&session_id, body.as_bytes());
    if crate::auth::verify_signature_pub(secret, &signed, signature).is_err() {
        tracing::warn!(%session_id, "rejected an unauthenticated Article 12 record");
        return (StatusCode::UNAUTHORIZED, "bad signature");
    }

    match append_record(state_dir, &session_id, body).await {
        Ok(()) => (StatusCode::NO_CONTENT, ""),
        Err(e) => {
            tracing::error!(%session_id, error = %e, "could not store an Article 12 record");
            (StatusCode::INTERNAL_SERVER_ERROR, "storage failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The cross-session replay, refused.** A record legitimately signed for
    /// session A must not be accepted into session B's chain. Before the
    /// signature covered the destination, this succeeded: the body verified, and
    /// the session id came from a URL path that nothing authenticated.
    ///
    /// This is an integrity property of the EVIDENCE path (Article 12
    /// record-keeping), and every pod configured with the node-wide receipt
    /// secret can produce a valid signature — so "who can sign" is not a
    /// meaningful restriction on "whose chain it lands in".
    #[test]
    fn a_record_signed_for_one_session_is_refused_by_another() {
        let secret = b"node-wide-receipt-secret";
        let body = r#"{"event":"decision"}"#;

        let sig_for_a = {
            use hmac::{digest::KeyInit, Hmac, Mac};
            let mut mac = Hmac::<sha2::Sha256>::new_from_slice(secret).expect("key");
            mac.update(&nucleus_client::art12_signed_bytes(
                "session-a",
                body.as_bytes(),
            ));
            hex::encode(mac.finalize().into_bytes())
        };

        // Its own session accepts it…
        let signed_a = nucleus_client::art12_signed_bytes("session-a", body.as_bytes());
        assert!(
            crate::auth::verify_signature_pub(secret, &signed_a, &sig_for_a).is_ok(),
            "a record must still verify for the session it was signed for"
        );

        // …and another session does not.
        let signed_b = nucleus_client::art12_signed_bytes("session-b", body.as_bytes());
        assert!(
            crate::auth::verify_signature_pub(secret, &signed_b, &sig_for_a).is_err(),
            "a record signed for session-a was accepted into session-b's chain -- \
             the signature does not bind the destination"
        );
    }

    #[test]
    fn a_traversing_session_id_is_refused() {
        for bad in [
            "../../etc/passwd",
            "a/b",
            "..",
            "",
            "with space",
            "semi;colon",
        ] {
            assert!(
                sanitize_session_id(bad).is_none(),
                "{bad:?} must not be accepted as a session id"
            );
        }
    }

    /// The control: ordinary ids still work, so the check above is not simply
    /// refusing everything.
    #[test]
    fn an_ordinary_session_id_is_accepted() {
        for ok in ["sess-1", "abcDEF123", "a_b-c"] {
            assert_eq!(sanitize_session_id(ok).as_deref(), Some(ok));
        }
    }

    #[tokio::test]
    async fn records_accumulate_in_order() {
        let dir = tempfile::tempdir().unwrap();
        append_record(dir.path(), "s1", "{\"seq\":1}")
            .await
            .unwrap();
        append_record(dir.path(), "s1", "{\"seq\":2}")
            .await
            .unwrap();
        let body = std::fs::read_to_string(session_log_path(dir.path(), "s1")).unwrap();
        assert_eq!(body.lines().count(), 2);
        assert!(body.lines().next().unwrap().contains("\"seq\":1"));
    }

    /// Sessions must not bleed into each other's evidence.
    #[tokio::test]
    async fn sessions_are_kept_apart() {
        let dir = tempfile::tempdir().unwrap();
        append_record(dir.path(), "s1", "{\"a\":1}").await.unwrap();
        append_record(dir.path(), "s2", "{\"b\":2}").await.unwrap();
        let one = std::fs::read_to_string(session_log_path(dir.path(), "s1")).unwrap();
        assert!(!one.contains("\"b\""), "s2's record leaked into s1's log");
    }

    use axum::http::StatusCode;

    /// Sign the way a real shipper does — over the DESTINATION and the payload.
    /// Taking `session` is the point: a helper that signed the body alone would
    /// let every test below pass while the destination went unauthenticated,
    /// which is precisely the defect that shipped.
    fn sign(secret: &[u8], session: &str, body: &str) -> String {
        crate::auth::sign_message(
            secret,
            &nucleus_client::art12_signed_bytes(session, body.as_bytes()),
        )
    }

    /// **Evidence anyone can append to is not evidence.** An unsigned record
    /// must be refused AND must not land on disk.
    #[tokio::test]
    async fn an_unsigned_record_is_refused_and_not_stored() {
        let dir = tempfile::tempdir().unwrap();
        let (code, _) = accept(dir.path(), Some(b"k"), "s1", None, "{}").await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
        assert!(
            !session_log_path(dir.path(), "s1").exists(),
            "a refused record must leave nothing behind"
        );
    }

    /// A wrong signature is refused for the same reason, and this is the
    /// perturbation that proves the check is live rather than the header merely
    /// being present.
    #[tokio::test]
    async fn a_wrongly_signed_record_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (code, _) = accept(
            dir.path(),
            Some(b"k"),
            "s1",
            Some(&sign(b"other", "s1", "{}")),
            "{}",
        )
        .await;
        assert_eq!(code, StatusCode::UNAUTHORIZED);
        assert!(!session_log_path(dir.path(), "s1").exists());
    }

    /// The control: correctly signed records are accepted and stored, so the
    /// refusals above are detecting signatures rather than refusing everything.
    #[tokio::test]
    async fn a_correctly_signed_record_is_stored() {
        let dir = tempfile::tempdir().unwrap();
        let body = "{\"seq\":1}";
        let (code, _) = accept(
            dir.path(),
            Some(b"k"),
            "s1",
            Some(&sign(b"k", "s1", body)),
            body,
        )
        .await;
        assert_eq!(code, StatusCode::NO_CONTENT);
        let stored = std::fs::read_to_string(session_log_path(dir.path(), "s1")).unwrap();
        assert!(stored.contains("\"seq\":1"));
    }

    /// **No secret means accept nothing.** An empty key would make every
    /// signature verify — the fail-OPEN reading of "not configured", and the
    /// most dangerous possible default for an evidence sink.
    #[tokio::test]
    async fn with_no_secret_configured_nothing_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let body = "{}";
        // Even a signature valid under the EMPTY key must not get in.
        let (code, _) = accept(dir.path(), None, "s1", Some(&sign(b"", "s1", body)), body).await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert!(!session_log_path(dir.path(), "s1").exists());
    }

    /// A traversing session id is refused before anything is written.
    #[tokio::test]
    async fn a_traversing_session_id_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let body = "{}";
        let (code, _) = accept(
            dir.path(),
            Some(b"k"),
            "../escaped",
            Some(&sign(b"k", "s1", body)),
            body,
        )
        .await;
        assert_eq!(code, StatusCode::BAD_REQUEST);
        assert!(!dir.path().join("../escaped.jsonl").exists());
    }
}
