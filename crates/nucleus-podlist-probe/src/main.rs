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
//! # What the probe CAN prove locally, and why it does not know its own id
//!
//! The probe's own anti-vacuity is narrow: the call genuinely ran and returned a
//! real, non-empty listing of well-formed pod ids, not an error object or an
//! empty stub. It does NOT check that its own id is in the listing, because a
//! workload has no legitimate way to learn its own id: on Firecracker the only
//! source is `FETCH_POD_CALLER_TOKEN`, which serves the id alongside the caller
//! token, once, to `nucleus-guest-init` before any workload exists (#2724,
//! #3113). A workload asking for it is refused, correctly, and the probe must
//! not be the one exception. `POD_LIST` itself needs no token: the socket is the
//! authority.
//!
//! Self-membership is the host's to check, and it already does with the id the
//! operator was given at create time (`A ∈ scoped` above), which is a stronger
//! witness than any id the guest could report about itself. Self-present was
//! never the scoping signal anyway: an unidentified guest that fail-OPENS to the
//! operator view also contains self. The scoping is proven only by
//! C-included ∧ B-excluded ∧ strict-subset, every one of which is host-side. So
//! PASS here means "the listing is real, now go check it", not "cross-pod
//! isolation holds".

// ADR 0007 totality: a function whose signature says it returns is lying if it
// panics. Denied for the shipped build only — `assert!` IS a panic, so denying
// inside `#[cfg(test)]` would forbid the thing tests are made of. This is the
// same line `is_production_path` draws when it strips the test region.
//
// Added because this crate measures ZERO of all seven lints today, per
// `clippy.toml`'s own rule: entries are added only when the tree is already
// clean of them.
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::panic,
        clippy::unreachable,
        clippy::todo
    )
)]

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
    /// The listing is real (a non-empty array of string ids); `ids` is the set
    /// for the host to check for A-inclusion, C-inclusion and B-exclusion.
    Pass { ids: Vec<String> },
    /// The listing is missing, malformed, empty, or a refusal object — the probe
    /// refuses to pass so a broken query cannot certify isolation.
    Fail { reason: String },
}

fn main() {
    let port = workload_api_port();

    // Poll for the settled scoped view (see POLL_ATTEMPTS): keep the largest
    // valid listing seen; a sibling can never enter it, so larger is strictly
    // more of this pod's own lineage. No caller token and no pod id is asked
    // for: `POD_LIST` is authenticated by the socket, and the caller token is
    // guest-init's, served once (see the module docs).
    let mut best: Option<Vec<String>> = None;
    let mut last_reason = "no POD_LIST reply".to_string();
    for _ in 0..POLL_ATTEMPTS {
        match fetch_pod_list(port) {
            Ok(reply) => match decide(&reply) {
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
        // `ids=` is what the host harness parses for the A-inclusion,
        // C-inclusion and B-exclusion assertions. The listing carries no secrets
        // (same data as `/v1/pods`).
        Some(ids) => {
            let line = format!("{PASS_SENTINEL} ids={}", ids.join(","));
            println!("{line}");
            eprintln!("{line}");
        }
        None => fail(&last_reason),
    }
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

/// Connect the workload-API vsock, send `POD_LIST`, and read the one reply
/// line. Mirrors the client in `nucleus-guest-init::identity` (same CID/port/
/// framing); each call is a fresh connection, matching the per-frame handler.
///
/// The command is fixed, not a parameter: this is the only request the probe
/// can make. Every other workload-API value is served once, to guest-init,
/// before the workload exists (#3113), and a workload asking for one is refused,
/// so a probe that needed one could not run as a workload at all.
fn fetch_pod_list(port: u32) -> Result<String, String> {
    const POD_LIST: &str = "POD_LIST";
    let command = POD_LIST;
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
/// security property (A in, C in, B out, strict subset) is the HOST's job; this
/// only establishes that the listing is real.
fn decide(response: &str) -> Verdict {
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
            };
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
                };
            }
        }
    }

    Verdict::Pass { ids }
}

#[cfg(test)]
mod tests {
    use super::{Verdict, decide};

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
    /// in order for the host to run A/C-inclusion and B-exclusion on.
    #[test]
    fn self_and_child_present_passes_and_extracts_ids() {
        let resp = format!(
            r#"[{{"id":"{A}","name":"orch-a"}},{{"id":"{C}","name":"child-c","parent_pod_id":"{A}"}}]"#
        );
        assert_eq!(ids(decide(&resp)), vec![A.to_string(), C.to_string()]);
    }

    /// `parent_pod_id` must not be mistaken for `id`: only the `id` field is
    /// extracted, so the set is exactly the pods, never their parents. (Were
    /// the parent read as an id, C's own listing would wrongly contain A.)
    #[test]
    fn parent_pod_id_is_not_read_as_an_id() {
        let resp = format!(r#"[{{"id":"{C}","name":"child-c","parent_pod_id":"{A}"}}]"#);
        assert_eq!(ids(decide(&resp)), vec![C.to_string()]);
    }

    /// **The defects the probe CANNOT discriminate, pinned so a local PASS is
    /// not mistaken for the property.** A self-only `[A]`, an unscoped `[A,B,C]`
    /// (a node serving the operator view), and a listing without A all reach
    /// the host verbatim, where `C ∈`, `B ∉` and `A ∈` red them. The probe must
    /// not filter, reorder or drop an id, since that could hide a leak.
    #[test]
    fn scoping_defects_reach_the_host_verbatim() {
        let self_only = format!(r#"[{{"id":"{A}"}}]"#);
        assert_eq!(ids(decide(&self_only)), vec![A.to_string()]);

        let unscoped = format!(r#"[{{"id":"{A}"}},{{"id":"{B}"}},{{"id":"{C}"}}]"#);
        assert_eq!(
            ids(decide(&unscoped)),
            vec![A.to_string(), B.to_string(), C.to_string()],
            "a leaked sibling must reach the host, which reds on B in the listing"
        );

        let not_self = format!(r#"[{{"id":"{B}"}}]"#);
        assert_eq!(ids(decide(&not_self)), vec![B.to_string()]);
    }

    /// Empty listing → a scoped view must contain at least this pod, so `[]` is a
    /// failed/unscoped query, not isolation. FAIL (no vacuous pass).
    #[test]
    fn empty_listing_fails_vacuous() {
        assert!(is_fail(decide("[]")));
        assert!(is_fail(decide("   ")));
    }

    /// A refusal object (`{"error":...}`) is not a listing — must not read as a
    /// silent pass just because it is valid JSON. The second is the exact reply
    /// the node gave the previous probe for the caller token it no longer asks
    /// for (#3113): a refusal of any kind reds the probe.
    #[test]
    fn error_object_is_not_a_listing() {
        assert!(is_fail(decide(r#"{"error":"nope"}"#)));
        assert!(is_fail(decide(
            r#"{"error":"caller token already served"}"#
        )));
    }

    /// Malformed JSON is a transport/serialization failure, not a listing.
    #[test]
    fn malformed_json_fails() {
        assert!(is_fail(decide("[{\"id\":")));
        assert!(is_fail(decide("not json at all")));
    }

    /// An entry without a string id is malformed — refuse rather than guess.
    #[test]
    fn entry_without_string_id_fails() {
        assert!(is_fail(decide(r#"[{"name":"no-id"}]"#)));
        assert!(is_fail(decide(r#"[{"id":42}]"#)));
    }
}
