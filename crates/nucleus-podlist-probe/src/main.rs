//! `nucleus-podlist-probe` — the C2 cross-pod backstop, checked on the REAL guest.
//!
//! The cross-pod non-interference filter (`pod_api::caller_may_manage`) is proved
//! against the Lean `PodCrossView` relation and host-unit-tested, and
//! `scripts/cross-pod-scoped-check.sh` exercises the identical auth+filter
//! composition KVM-free over the local-driver env path. What none of that checks
//! is that a *booted* pod, calling the scoped `POD_LIST` over its OWN real
//! workload-API vsock socket, is served a listing confined to its lineage. This
//! binary converts that from *documented* to *runtime-observed*: it runs as the
//! workload inside pod A and reports, from a process running as the workload uid
//! in the guest, the pod set A can actually see.
//!
//! It is the cross-pod twin of `nucleus-egress-probe`: a static binary baked into
//! the rootfs, whose verdict is a sentinel line on BOTH stdout and stderr plus
//! the exit code — the tool-proxy drains the child's stderr into the guest
//! console log, where the boot harness greps it back on the host.
//!
//! # The probe reports; the HOST decides the security property
//!
//! A probe running inside A can only ever see A's OWN scoped view over A's own
//! socket. It structurally cannot observe the operator view that proves a sibling
//! B genuinely exists, nor can it know B's id. So the split is deliberate and
//! load-bearing (it mirrors `cross-pod-scoped-check.py`): the probe emits the raw
//! id set it was served, and the host harness — which holds the ids of A, its
//! child C, and sibling B — asserts the actual property:
//!
//!   A ∈ scoped  ∧  C ∈ scoped  ∧  B ∉ scoped  ∧  {A,B,C} ⊆ operator  ∧  scoped ⊊ operator
//!
//! # What the probe CAN prove locally, and why self-present is not enough
//!
//! The probe's own anti-vacuity is narrow: the call genuinely ran, returned a
//! real (non-empty) listing, and that listing contains A's OWN id — so the query
//! reached the node and came back A's scoped view, not an error or an empty stub.
//!
//! Self-present is NECESSARY but is NOT the scoping signal, and the probe must
//! never be allowed to stand as the property: an unidentified guest that
//! fail-OPENS to the operator view *also* contains self. The scoping is proven
//! only by C-included ∧ B-excluded ∧ strict-subset, and every one of those is
//! host-side. This is why PASS here means "the listing is real and self-scoped,
//! now go check exclusion" — not "cross-pod isolation holds".

use std::io::{BufRead, BufReader, Write};
use std::time::Duration;
use vsock::VsockStream;

/// Host CID for vsock connections (always 2 in Firecracker).
const VMADDR_CID_HOST: u32 = 2;
/// Default vsock port for the Workload API (matches `nucleus-guest-init`).
const DEFAULT_WORKLOAD_API_PORT: u32 = 15012;
/// A bound so a wedged host cannot make the probe hang past its drain window.
const READ_TIMEOUT_MS: u64 = 2000;
/// Poll POD_LIST a few times: a child or sibling created around the same instant
/// as this pod may still be REGISTERING when the probe first fires. The node's
/// filter excludes a non-lineage sibling on every poll, so a view that GROWS
/// across polls can only mean a lineage member (a child) appeared — never a leak
/// — so reporting the largest view is sound and races-free. Bounded well within
/// the pod lifetime.
const POLL_ATTEMPTS: u32 = 10;
const POLL_INTERVAL_MS: u64 = 1000;

const PASS_SENTINEL: &str = "NUCLEUS_PODLIST_PROBE: PASS";
const FAIL_SENTINEL: &str = "NUCLEUS_PODLIST_PROBE: FAIL";

/// The probe's local verdict over a single POD_LIST response. Kept pure and
/// separate from the vsock I/O so it is unit-tested without a live socket.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// The listing is real and self-scoped; `ids` is the set for the host to
    /// check for B-exclusion / C-inclusion.
    Pass { ids: Vec<String> },
    /// The listing is missing, malformed, empty, or does not contain self — the
    /// probe refuses to pass so a broken query cannot certify isolation.
    Fail { reason: String },
}

fn main() {
    let port = workload_api_port();

    // The pod's own id. As a WORKLOAD — spawned by the tool-proxy, not the same
    // process as guest-init — this does NOT inherit the NUCLEUS_POD_ID that
    // guest-init sets for itself (verified on a live boot: the env var is absent
    // here). So the id is fetched from the same socket-authenticated vsock that
    // serves POD_LIST: FETCH_POD_CALLER_TOKEN answers {caller_token, pod_id}, and
    // the socket — not the guest — says which pod that is. An env override is
    // honored first, for the KVM-free harness and tests.
    let self_id = match resolve_self_id(std::env::var("NUCLEUS_POD_ID").ok()) {
        Ok(id) => id,
        Err(_) => match fetch_pod_id(port) {
            Ok(id) => id,
            Err(e) => {
                fail(&format!(
                    "no NUCLEUS_POD_ID in the environment and could not fetch this pod's id over vsock ({e}) — cannot self-check the listing; refusing to pass vacuously"
                ));
                return;
            }
        },
    };

    // Poll for the settled scoped view (see POLL_ATTEMPTS): keep the largest
    // valid, self-containing listing seen; a sibling can never enter it, so
    // larger is strictly more of this pod's own lineage.
    let mut best: Option<Vec<String>> = None;
    let mut last_reason = "no POD_LIST reply".to_string();
    for _ in 0..POLL_ATTEMPTS {
        match fetch_over_vsock(port, "POD_LIST") {
            Ok(reply) => match decide(&reply, &self_id) {
                Verdict::Pass { ids } => {
                    if best.as_ref().is_none_or(|b| ids.len() > b.len()) {
                        best = Some(ids);
                    }
                }
                Verdict::Fail { reason } => last_reason = reason,
            },
            Err(e) => last_reason = format!("could not fetch POD_LIST over vsock: {e}"),
        }
        std::thread::sleep(std::time::Duration::from_millis(POLL_INTERVAL_MS));
    }

    match best {
        // `ids=` is what the host harness parses for the B-exclusion / C-inclusion
        // assertions. The listing carries no secrets (same data as `/v1/pods`).
        Some(ids) => {
            let line = format!("{PASS_SENTINEL} self={self_id} ids={}", ids.join(","));
            println!("{line}");
            eprintln!("{line}");
        }
        None => fail(&last_reason),
    }
}

/// Resolve this pod's own id from an optional `NUCLEUS_POD_ID` override. Absent
/// or blank is an `Err` (not a default) — the caller then falls back to fetching
/// the id over vsock. Pure, so both branches are unit-tested.
fn resolve_self_id(env_value: Option<String>) -> Result<String, String> {
    match env_value {
        Some(id) if !id.trim().is_empty() => Ok(id.trim().to_string()),
        _ => Err("NUCLEUS_POD_ID not set".into()),
    }
}

/// This pod's own id, fetched over the socket-authenticated vsock. The socket is
/// per-pod, so `FETCH_POD_CALLER_TOKEN` answers THIS pod's `{caller_token,
/// pod_id}` — the id cannot be forged by the guest. The token is ignored here;
/// only the id is needed, to self-check the listing.
fn fetch_pod_id(port: u32) -> Result<String, String> {
    let reply = fetch_over_vsock(port, "FETCH_POD_CALLER_TOKEN")?;
    parse_pod_id(&reply).ok_or_else(|| {
        format!(
            "FETCH_POD_CALLER_TOKEN reply carried no pod_id: {:?}",
            reply.trim()
        )
    })
}

/// Extract `pod_id` from a `FETCH_POD_CALLER_TOKEN` reply
/// (`{"caller_token":"…","pod_id":"…"}`). Pure, so it is unit-tested; returns
/// `None` on a legacy token-only reply or an error object.
fn parse_pod_id(reply: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(reply.trim()).ok()?;
    v.get("pod_id")?.as_str().map(str::to_string)
}

/// Emit the FAIL sentinel on both streams and exit non-zero, matching the
/// egress-probe contract the boot harness greps for.
fn fail(reason: &str) {
    let line = format!("{FAIL_SENTINEL}: {reason}");
    println!("{line}");
    eprintln!("{line}");
    std::process::exit(1);
}

/// The workload-API vsock port (env override, else the default guest-init uses).
fn workload_api_port() -> u32 {
    std::env::var("NUCLEUS_WORKLOAD_API_PORT")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(DEFAULT_WORKLOAD_API_PORT)
}

/// Connect the workload-API vsock, send one `command`, and read the one reply
/// line. Mirrors the client in `nucleus-guest-init::identity` (same CID/port/
/// framing); each call is a fresh connection, matching the per-frame handler.
fn fetch_over_vsock(port: u32, command: &str) -> Result<String, String> {
    let mut stream = VsockStream::connect_with_cid_port(VMADDR_CID_HOST, port)
        .map_err(|e| format!("connect (cid {VMADDR_CID_HOST} port {port}): {e}"))?;
    // Bound the read so a host that accepts but never answers cannot wedge the
    // probe past the guest's short teardown window.
    stream
        .set_read_timeout(Some(Duration::from_millis(READ_TIMEOUT_MS)))
        .map_err(|e| format!("set read timeout: {e}"))?;
    stream
        .write_all(format!("{command}\n").as_bytes())
        .map_err(|e| format!("write {command}: {e}"))?;
    stream.flush().map_err(|e| format!("flush: {e}"))?;

    let mut reader = BufReader::new(&mut stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .map_err(|e| format!("read reply: {e}"))?;
    Ok(response)
}

/// Decide the probe's LOCAL verdict over a POD_LIST reply. Pure by design: the
/// security property (B out, C in, strict subset) is the HOST's job; this only
/// establishes that the listing is real and contains self.
fn decide(response: &str, self_id: &str) -> Verdict {
    let trimmed = response.trim();
    if trimmed.is_empty() {
        return Verdict::Fail {
            reason: "empty reply from the workload API — the query did not return a listing".into(),
        };
    }

    let value: serde_json::Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(e) => {
            return Verdict::Fail {
                reason: format!("reply is not valid JSON ({e}) — got {trimmed:?}"),
            }
        }
    };

    // The node answers a refusal as an `{"error": ...}` OBJECT, never an array;
    // treat anything that is not an array as a non-listing (not a silent pass).
    let Some(entries) = value.as_array() else {
        return Verdict::Fail {
            reason: format!(
                "reply is not a JSON array (a refusal `{{\"error\":...}}` or other object?) — got {trimmed:?}"
            ),
        };
    };

    if entries.is_empty() {
        return Verdict::Fail {
            reason: "listing is EMPTY — a scoped listing must contain at least this pod, so an empty result is a failed/unscoped query, not isolation; refusing to pass vacuously".into(),
        };
    }

    let mut ids = Vec::with_capacity(entries.len());
    for entry in entries {
        match entry.get("id").and_then(|i| i.as_str()) {
            Some(id) => ids.push(id.to_string()),
            None => {
                return Verdict::Fail {
                    reason: format!("a listing entry has no string `id` field — got {entry}"),
                }
            }
        }
    }

    if !ids.iter().any(|id| id == self_id) {
        return Verdict::Fail {
            reason: format!(
                "this pod's own id {self_id} is NOT in its own listing — the call did not come back as this pod's scoped view (an unauthenticated or failed query), so any exclusion it shows proves nothing"
            ),
        };
    }

    Verdict::Pass { ids }
}

#[cfg(test)]
mod tests {
    use super::{decide, parse_pod_id, resolve_self_id, Verdict};

    const A: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const B: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const C: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";

    fn ids(v: Verdict) -> Vec<String> {
        match v {
            Verdict::Pass { ids } => ids,
            Verdict::Fail { reason } => panic!("expected Pass, got Fail: {reason}"),
        }
    }
    fn is_fail(v: Verdict) -> bool {
        matches!(v, Verdict::Fail { .. })
    }

    /// The normal live case: A sees itself and its child C. PASS, ids extracted
    /// in order for the host to run B-exclusion / C-inclusion on.
    #[test]
    fn self_and_child_present_passes_and_extracts_ids() {
        let resp = format!(
            r#"[{{"id":"{A}","name":"orch-a"}},{{"id":"{C}","name":"child-c","parent_pod_id":"{A}"}}]"#
        );
        assert_eq!(ids(decide(&resp, A)), vec![A.to_string(), C.to_string()]);
    }

    /// `parent_pod_id` must not be mistaken for `id`: only the `id` field is
    /// extracted, so the set is exactly the pods, never their parents.
    #[test]
    fn parent_pod_id_is_not_read_as_an_id() {
        let resp = format!(r#"[{{"id":"{C}","name":"child-c","parent_pod_id":"{A}"}}]"#);
        // self_id = C here (the child querying its own socket).
        assert_eq!(ids(decide(&resp, C)), vec![C.to_string()]);
    }

    /// **The self-only case the probe CANNOT discriminate — pinned so it is not
    /// mistaken for the property.** `[A]` contains self and is non-empty, so the
    /// probe PASSes; whether the filter is genuinely lineage-scoped or broken to
    /// self-only is invisible here and is the HOST's job (assert C ∈ scoped).
    #[test]
    fn self_only_passes_locally_but_is_the_hosts_to_discriminate() {
        let resp = format!(r#"[{{"id":"{A}","name":"orch-a"}}]"#);
        assert_eq!(ids(decide(&resp, A)), vec![A.to_string()]);
    }

    /// Self absent → the query did not come back as A's scoped view. Any
    /// exclusion it shows is meaningless, so FAIL rather than certify.
    #[test]
    fn self_absent_fails_as_unauthenticated() {
        let resp = format!(r#"[{{"id":"{B}","name":"sibling-b"}}]"#);
        assert!(is_fail(decide(&resp, A)));
    }

    /// Empty listing → a scoped view must contain at least this pod, so `[]` is a
    /// failed/unscoped query, not isolation. FAIL (no vacuous pass).
    #[test]
    fn empty_listing_fails_vacuous() {
        assert!(is_fail(decide("[]", A)));
        assert!(is_fail(decide("   ", A)));
    }

    /// A refusal object (`{"error":...}`) is not a listing — must not read as a
    /// silent pass just because it is valid JSON.
    #[test]
    fn error_object_is_not_a_listing() {
        assert!(is_fail(decide(r#"{"error":"nope"}"#, A)));
    }

    /// Malformed JSON is a transport/serialization failure, not a listing.
    #[test]
    fn malformed_json_fails() {
        assert!(is_fail(decide("[{\"id\":", A)));
        assert!(is_fail(decide("not json at all", A)));
    }

    /// An entry without a string id is malformed — refuse rather than guess.
    #[test]
    fn entry_without_string_id_fails() {
        assert!(is_fail(decide(r#"[{"name":"no-id"}]"#, A)));
        assert!(is_fail(decide(r#"[{"id":42}]"#, A)));
    }

    /// Missing or blank `NUCLEUS_POD_ID` → `Err` (the caller then fetches the id
    /// over vsock); a set value is trimmed and used as the override.
    #[test]
    fn missing_or_blank_self_id_falls_through() {
        assert!(resolve_self_id(None).is_err());
        assert!(resolve_self_id(Some("   ".into())).is_err());
        assert_eq!(resolve_self_id(Some("  a-b  ".into())).unwrap(), "a-b");
    }

    /// The vsock self-id path: `pod_id` is lifted from a FETCH_POD_CALLER_TOKEN
    /// reply, and a legacy token-only reply or an error object yields `None` (so
    /// the probe fails rather than self-checks against a missing id).
    #[test]
    fn parse_pod_id_reads_the_id_or_none() {
        assert_eq!(
            parse_pod_id(&format!(r#"{{"caller_token":"t","pod_id":"{A}"}}"#)).as_deref(),
            Some(A)
        );
        assert_eq!(parse_pod_id(r#"{"caller_token":"t"}"#), None);
        assert_eq!(parse_pod_id(r#"{"error":"none"}"#), None);
        assert_eq!(parse_pod_id("not json"), None);
    }
}
