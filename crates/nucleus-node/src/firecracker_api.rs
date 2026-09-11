//! Driving Firecracker through its HTTP API on a Unix socket.
//!
//! This is the transport half of an API-mode boot; the lowering half is
//! [`crate::firecracker_config::config_to_requests`]. They are apart on purpose: the mapping
//! from a configuration to a request sequence can be wrong in ways nothing notices until a guest
//! misbehaves, and it is checkable on a machine with no KVM. Opening a socket is neither.
//!
//! # Why an API socket at all
//!
//! `--config-file` boots the machine the moment it is parsed. That is fine for a VM that only
//! ever runs forward, and impossible for one that is to be snapshotted: `/snapshot/create`
//! requires a VMM that is configured, running, and then PAUSED, and a config-file launch offers
//! no moment in which to ask for the pause. Everything that reads a snapshot therefore starts
//! here.
//!
//! # What the API buys besides snapshots
//!
//! A misconfiguration becomes a structured refusal instead of a corpse. Under `--config-file`
//! Firecracker exits before it creates the vsock socket, and the node reports "vsock socket not
//! found" — a message about the symptom, several steps from the cause. Here the same mistake is
//! a `400` whose body names the field.

use std::path::Path;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;

use crate::firecracker_config::ApiRequest;

/// How long to wait for Firecracker to create its API socket before giving up.
///
/// Generous because the socket appears within milliseconds of exec on any healthy host, so a
/// wait that reaches this bound means something is wrong rather than slow — and under the jailer
/// the socket appears INSIDE the chroot, so the usual way to reach this bound is having computed
/// the wrong path.
const SOCKET_TIMEOUT: Duration = Duration::from_secs(10);

/// Poll interval while waiting for the socket.
const SOCKET_POLL: Duration = Duration::from_millis(20);

/// Wait until `sock` exists, or fail saying which path was watched.
///
/// Modelled on `wait_for_vsock_socket`: the failure has to name the path, because the only
/// realistic cause is looking in the wrong place.
pub(crate) async fn wait_for_api_socket(sock: &Path) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + SOCKET_TIMEOUT;
    loop {
        if sock.exists() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "firecracker did not create its API socket at {} within {SOCKET_TIMEOUT:?} \
                 (under the jailer this path is inside the chroot)",
                sock.display()
            ));
        }
        tokio::time::sleep(SOCKET_POLL).await;
    }
}

/// Issue one API call and require a 2xx.
///
/// A non-2xx carries Firecracker's own `fault_message`, and it is included verbatim: the whole
/// reason to prefer this over a config file is that the VMM can say what it objected to.
pub(crate) async fn send(sock: &Path, req: &ApiRequest) -> Result<(), String> {
    let stream = UnixStream::connect(sock).await.map_err(|e| {
        format!(
            "cannot connect to the firecracker API at {}: {e}",
            sock.display()
        )
    })?;
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| format!("firecracker API handshake failed: {e}"))?;
    // The connection future drives the socket; it ends when the response is done.
    let pump = tokio::spawn(connection);

    let request = Request::builder()
        .method(req.method)
        .uri(&req.path)
        // Firecracker ignores the authority but HTTP/1.1 requires one.
        .header("host", "localhost")
        .header("content-type", "application/json")
        .body(Full::new(axum::body::Bytes::from(req.body.clone())))
        .map_err(|e| format!("cannot build the {} {} request: {e}", req.method, req.path))?;

    let response = sender
        .send_request(request)
        .await
        .map_err(|e| format!("{} {} failed: {e}", req.method, req.path))?;
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .map(|b| String::from_utf8_lossy(&b.to_bytes()).into_owned())
        .unwrap_or_default();
    pump.abort();

    if status.is_success() {
        Ok(())
    } else {
        Err(format!(
            "{} {} refused with {status}: {}",
            req.method,
            req.path,
            if body.is_empty() { "(no body)" } else { &body }
        ))
    }
}

/// Issue a sequence in order, stopping at the first refusal.
///
/// Ordered and sequential rather than concurrent: the sequence is a construction, and the
/// machine is not fully described until the last call lands. Stopping at the first failure keeps
/// the error attributable to the field that caused it.
pub(crate) async fn apply(sock: &Path, reqs: &[ApiRequest]) -> Result<(), String> {
    for req in reqs {
        send(sock, req).await?;
    }
    Ok(())
}

/// A `PUT` of arbitrary JSON, for the calls that are not part of the boot lowering.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn put_json(path: &str, body: &serde_json::Value) -> ApiRequest {
    ApiRequest {
        method: "PUT",
        path: path.to_string(),
        body: body.to_string(),
    }
}

/// A state transition on the VM: `Paused` or `Resumed`.
///
/// `PATCH`, not `PUT`, and Firecracker is strict about it — this is the one place the method
/// varies, which is why it is a named constructor rather than a string at each call site.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn patch_vm(state: &str) -> ApiRequest {
    ApiRequest {
        method: "PATCH",
        path: "/vm".into(),
        body: format!(r#"{{"state":"{state}"}}"#),
    }
}

/// Where Firecracker's API socket lands, which differs by how it was launched.
///
/// Unjailed, the node passes `--api-sock` explicitly into the pod directory. Under the jailer
/// it passes none, so Firecracker uses its default `/run/firecracker.socket` — and that default
/// is resolved INSIDE the chroot, so from the host it lives under the jail root. Getting this
/// wrong does not fail loudly: the wait simply never finds the file and times out, which is why
/// the timeout message names the path and mentions the chroot.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn api_socket_path(
    jail: Option<&crate::firecracker_config::JailLayout>,
    pod_dir: &Path,
) -> std::path::PathBuf {
    match jail {
        Some(j) => j.jail_root.join("run/firecracker.socket"),
        None => pod_dir.join("firecracker.socket"),
    }
}

/// Build the machine over the API, leaving it configured but NOT running.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) async fn configure(
    sock: &Path,
    cfg: &crate::firecracker_config::FirecrackerConfig,
) -> Result<(), String> {
    wait_for_api_socket(sock).await?;
    apply(sock, &crate::firecracker_config::config_to_requests(cfg)).await
}

/// Start the vCPUs. Separate from [`configure`] so the sandbox can be verified in between.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) async fn start(sock: &Path) -> Result<(), String> {
    send(sock, &crate::firecracker_config::instance_start_request()).await
}

/// A stub Firecracker API server, for tests in this module and in
/// `snapshot_restore`. Its own file so it can be shared without declaring a
/// module in `main.rs`, which is at its line ceiling.
#[cfg(test)]
#[path = "stub_vmm.rs"]
pub(crate) mod stub_vmm;

#[cfg(test)]
mod tests {
    use super::*;
    use stub_vmm::{Seen, StubVmm};
    #[cfg(target_os = "linux")]
    use stub_vmm::sample_config;

    /// A socket that never appears fails by naming the path, not by hanging.
    ///
    /// The failure mode this guards is specific: under the jailer the API socket is created
    /// inside the chroot, so a caller that passes the outside path waits forever on a file that
    /// will never exist. A timeout that said only "timed out" would send someone looking at
    /// Firecracker instead of at the path they computed.
    #[tokio::test(start_paused = true)]
    async fn a_socket_that_never_appears_fails_naming_the_path() {
        let missing = std::path::Path::new("/nonexistent/nucleus-test/firecracker.socket");
        let err = wait_for_api_socket(missing)
            .await
            .expect_err("a socket that does not exist must not report success");
        assert!(err.contains("nucleus-test"), "{err}");
        assert!(err.contains("chroot"), "the hint must survive: {err}");
    }

    /// The transport really drives a real Firecracker, including its refusals.
    ///
    /// Everything above this is a test of the client against nothing. This one spawns the
    /// pinned VMM, waits for the socket it creates, configures a machine through it, and then
    /// asks for something impossible to prove the refusal path carries the VMM's own words. It
    /// is the difference between "the code compiles" and "the protocol is right".
    ///
    /// Self-skipping: without `firecracker` on PATH there is nothing to talk to, and a test that
    /// failed for that reason would be noise on every machine that is not a node.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn it_configures_and_is_refused_by_a_real_firecracker() {
        let Ok(bin) = which_firecracker() else {
            eprintln!("skipping: no firecracker on PATH");
            return;
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("fc.socket");

        let mut child = tokio::process::Command::new(bin)
            .arg("--api-sock")
            .arg(&sock)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("firecracker spawns");

        let result = async {
            wait_for_api_socket(&sock).await?;

            // A machine it can accept.
            apply(
                &sock,
                &[ApiRequest {
                    method: "PUT",
                    path: "/machine-config".into(),
                    body: r#"{"vcpu_count":1,"mem_size_mib":128,"smt":false}"#.into(),
                }],
            )
            .await?;

            // A kernel that is not there: the VMM must refuse, and say so.
            let refused = send(
                &sock,
                &ApiRequest {
                    method: "PUT",
                    path: "/boot-source".into(),
                    body: r#"{"kernel_image_path":"/nonexistent/vmlinux"}"#.into(),
                },
            )
            .await
            .expect_err("a missing kernel must be refused");
            Ok::<String, String>(refused)
        }
        .await;

        let _ = child.kill().await;
        let refused = result.expect("the exchange itself must succeed");
        assert!(
            refused.contains("/boot-source") && refused.contains("400"),
            "the refusal must name the call and the status: {refused}"
        );
        assert!(
            refused.to_lowercase().contains("kernel") || refused.contains("fault"),
            "the VMM's own words must survive rather than be replaced: {refused}"
        );
    }

    /// `firecracker` on PATH, if it is there at all.
    #[cfg(target_os = "linux")]
    fn which_firecracker() -> Result<std::path::PathBuf, ()> {
        std::env::var_os("PATH")
            .and_then(|p| {
                std::env::split_paths(&p)
                    .map(|d| d.join("firecracker"))
                    .find(|c| c.is_file())
            })
            .ok_or(())
    }

    // ── A stub VMM, so the transport is testable without one ────────────────
    //
    // Everything below drives the REAL client (`send`/`apply`/`configure`/
    // `start`) against a socket this test owns. That matters because the only
    // test that previously exercised the success path is
    // `it_configures_and_is_refused_by_a_real_firecracker`, which self-skips
    // when `firecracker` is not on PATH — so on any machine without the VMM,
    // including the coverage runner, `send` was never executed at all and the
    // transport's success path went unexercised. The module's own header says
    // the lowering half is "checkable on a machine with no KVM"; this gives the
    // transport half the same property.
    //
    // Hand-rolled rather than hyper's server: this crate takes hyper with
    // `["client", "http1"]` only, and a test fixture is not a reason to widen a
    // production dependency. HTTP/1.1 with a known Content-Length is small
    // enough to answer honestly in a few lines.

    /// The client puts the method, path and body it was given on the wire.
    ///
    /// Asserted against what the server RECEIVED rather than against the
    /// `ApiRequest` it was handed, which would only prove the struct round-trips
    /// through itself.
    #[tokio::test]
    async fn a_request_reaches_the_vmm_as_it_was_written() {
        let vmm = StubVmm::start(vec![]).await;
        send(
            &vmm.sock,
            &ApiRequest {
                method: "PUT",
                path: "/machine-config".into(),
                body: r#"{"vcpu_count":2}"#.into(),
            },
        )
        .await
        .expect("a 204 is success");

        assert_eq!(
            vmm.seen().await,
            vec![Seen {
                method: "PUT".into(),
                path: "/machine-config".into(),
                body: r#"{"vcpu_count":2}"#.into(),
            }]
        );
    }

    /// A refusal carries the VMM's OWN words, which is the entire reason this
    /// module prefers the API socket to `--config-file`.
    #[tokio::test]
    async fn a_refusal_carries_the_vmms_fault_message_verbatim() {
        let fault = r#"{"fault_message":"No such file or directory (os error 2)"}"#;
        let vmm = StubVmm::start(vec![(400, fault)]).await;

        let err = send(
            &vmm.sock,
            &ApiRequest {
                method: "PUT",
                path: "/boot-source".into(),
                body: "{}".into(),
            },
        )
        .await
        .expect_err("a 400 is not success");

        assert!(err.contains("/boot-source"), "names the call: {err}");
        assert!(err.contains("400"), "names the status: {err}");
        assert!(
            err.contains("No such file or directory (os error 2)"),
            "the VMM's own words must survive rather than be replaced: {err}"
        );
    }

    /// An empty error body says so instead of rendering as nothing.
    #[tokio::test]
    async fn a_refusal_with_no_body_still_reads_as_a_refusal() {
        let vmm = StubVmm::start(vec![(500, "")]).await;
        let err = send(
            &vmm.sock,
            &ApiRequest {
                method: "PUT",
                path: "/vm".into(),
                body: "{}".into(),
            },
        )
        .await
        .expect_err("a 500 is not success");
        assert!(err.contains("(no body)"), "{err}");
    }

    /// `apply` stops at the first refusal — and the requests after it are never
    /// sent. Asserted on the SERVER's record, because "stopped" is a claim about
    /// what did not happen, and the error alone cannot distinguish a sequence
    /// that halted from one that ran on and reported the first failure.
    #[tokio::test]
    async fn apply_stops_at_the_first_refusal_and_sends_nothing_after_it() {
        let vmm = StubVmm::start(vec![(204, ""), (400, r#"{"fault_message":"bad"}"#)]).await;

        let reqs = [
            ApiRequest {
                method: "PUT",
                path: "/first".into(),
                body: "{}".into(),
            },
            ApiRequest {
                method: "PUT",
                path: "/second".into(),
                body: "{}".into(),
            },
            ApiRequest {
                method: "PUT",
                path: "/third".into(),
                body: "{}".into(),
            },
        ];
        let err = apply(&vmm.sock, &reqs)
            .await
            .expect_err("the second is refused");
        assert!(
            err.contains("/second"),
            "the error names the call that failed: {err}"
        );

        let paths: Vec<String> = vmm.seen().await.into_iter().map(|s| s.path).collect();
        assert_eq!(
            paths,
            vec!["/first".to_string(), "/second".to_string()],
            "/third must never be sent: the machine is not described past a refusal"
        );
    }

    /// A whole sequence lands in order when nothing refuses.
    #[tokio::test]
    async fn apply_sends_every_request_in_order_when_the_vmm_accepts() {
        let vmm = StubVmm::start(vec![]).await;
        let reqs = [
            ApiRequest {
                method: "PUT",
                path: "/a".into(),
                body: "1".into(),
            },
            ApiRequest {
                method: "PUT",
                path: "/b".into(),
                body: "2".into(),
            },
            ApiRequest {
                method: "PATCH",
                path: "/c".into(),
                body: "3".into(),
            },
        ];
        apply(&vmm.sock, &reqs).await.expect("all accepted");

        let seen = vmm.seen().await;
        assert_eq!(
            seen.iter().map(|s| s.path.as_str()).collect::<Vec<_>>(),
            vec!["/a", "/b", "/c"],
            "order is the construction, not an accident: {seen:?}"
        );
        assert_eq!(
            seen[2].method, "PATCH",
            "the method varies and must survive"
        );
    }

    /// `start` asks for the one transition that boots the vCPUs.
    #[tokio::test]
    async fn start_issues_the_instance_start_action() {
        let vmm = StubVmm::start(vec![]).await;
        start(&vmm.sock).await.expect("accepted");
        let seen = vmm.seen().await;
        assert_eq!(seen.len(), 1, "exactly one call: {seen:?}");
        assert!(
            seen[0].body.contains("InstanceStart"),
            "the body must ask for InstanceStart: {seen:?}"
        );
    }

    /// `configure` drives the lowering and leaves the machine NOT started —
    /// which is the property the snapshot path depends on.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn configure_builds_the_machine_without_starting_it() {
        let vmm = StubVmm::start(vec![]).await;
        let cfg = sample_config();
        configure(&vmm.sock, &cfg).await.expect("accepted");

        let seen = vmm.seen().await;
        assert!(!seen.is_empty(), "configure must issue calls");
        assert!(
            !seen.iter().any(|s| s.body.contains("InstanceStart")),
            "configure must leave the vCPUs stopped so the sandbox can be \
             verified before anything runs: {seen:?}"
        );
        assert!(
            seen.iter().any(|s| s.path == "/boot-source"),
            "the kernel must be configured: {seen:?}"
        );
    }

    /// `patch_vm` is the one call whose method is not PUT, and Firecracker is
    /// strict about that.
    #[tokio::test]
    async fn a_state_transition_goes_out_as_a_patch() {
        let vmm = StubVmm::start(vec![]).await;
        send(&vmm.sock, &patch_vm("Paused"))
            .await
            .expect("accepted");
        let seen = vmm.seen().await;
        assert_eq!(seen[0].method, "PATCH", "PUT would be refused: {seen:?}");
        assert_eq!(seen[0].path, "/vm");
        assert!(seen[0].body.contains("Paused"), "{seen:?}");
    }

    /// `put_json` serializes the value it was handed.
    #[tokio::test]
    async fn put_json_sends_the_value_it_was_given() {
        let vmm = StubVmm::start(vec![]).await;
        let body = serde_json::json!({ "snapshot_path": "/s/mem" });
        send(&vmm.sock, &put_json("/snapshot/create", &body))
            .await
            .expect("accepted");
        let seen = vmm.seen().await;
        assert_eq!(seen[0].method, "PUT");
        assert_eq!(seen[0].path, "/snapshot/create");
        assert!(seen[0].body.contains("/s/mem"), "{seen:?}");
    }

    /// The jailed and unjailed socket paths differ, and getting it wrong times
    /// out on a file that will never exist rather than failing loudly.
    #[test]
    fn the_api_socket_is_inside_the_jail_when_there_is_one() {
        let pod_dir = std::path::Path::new("/var/lib/nucleus/state/pods/p1");
        assert_eq!(
            api_socket_path(None, pod_dir),
            pod_dir.join("firecracker.socket"),
            "unjailed, the node passes --api-sock into the pod directory"
        );

        let jail = crate::firecracker_config::JailLayout::new(
            std::path::Path::new("/srv/jailer"),
            std::path::Path::new("/usr/bin/firecracker"),
            "p1",
        );
        let jailed = api_socket_path(Some(&jail), pod_dir);
        assert!(
            jailed.starts_with(&jail.jail_root),
            "firecracker resolves its default socket INSIDE the chroot: {}",
            jailed.display()
        );
        assert!(
            jailed.ends_with("run/firecracker.socket"),
            "{}",
            jailed.display()
        );
    }

    /// Connecting to a path with no listener is an error, never a silent success.
    #[tokio::test]
    async fn sending_to_a_dead_socket_is_an_error() {
        let req = ApiRequest {
            method: "PUT",
            path: "/machine-config".into(),
            body: "{}".into(),
        };
        let err = send(
            std::path::Path::new("/nonexistent/nucleus-test/fc.socket"),
            &req,
        )
        .await
        .expect_err("there is nothing listening");
        assert!(err.contains("cannot connect"), "{err}");
    }
}
