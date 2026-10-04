use std::fs;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

mod identity;

use nucleus_guest_init::boot::{self, Boot, MountSpec, SealedProof};
use nucleus_guest_init::fence::{self, Fenced};
use nucleus_guest_init::net::{self, NetConfig};
use nucleus_spec::guest_layout::{
    self, APPROVAL_SECRET, AUDIT_PATH_FILE, AUTH_SECRET, CaBundle, EGRESS_PROBE_BIN,
    FALLBACK_POD_SPEC, POD_SPEC_PATH, PROXY_BIN, SANDBOX_TOKEN, WORK_DIR,
};

#[cfg(target_os = "linux")]
use nix::mount::{MsFlags, mount};
#[cfg(target_os = "linux")]
use nix::sys::stat::umask;

#[cfg(not(target_os = "linux"))]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct MsFlags;

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
impl MsFlags {
    const MS_NOSUID: MsFlags = MsFlags;
    const MS_NOEXEC: MsFlags = MsFlags;
    const MS_NODEV: MsFlags = MsFlags;
    const MS_REMOUNT: MsFlags = MsFlags;
    const MS_RDONLY: MsFlags = MsFlags;
    const MS_BIND: MsFlags = MsFlags;
    fn empty() -> MsFlags {
        MsFlags
    }
}

#[cfg(not(target_os = "linux"))]
impl std::ops::BitOrAssign for MsFlags {
    fn bitor_assign(&mut self, _rhs: MsFlags) {}
}

#[cfg(not(target_os = "linux"))]
impl std::ops::BitOr for MsFlags {
    type Output = MsFlags;
    fn bitor(self, _rhs: MsFlags) -> MsFlags {
        MsFlags
    }
}

/// The pinned compiler-cache seed, read-only, and the overlay that makes it usable.
/// `CACHE_MERGED` is what a gate points `CARGO_TARGET_DIR` and `CARGO_HOME` inside.
const CACHE_SEED: &str = "/cache-seed";
const CACHE_UPPER: &str = "/work/.cache-upper";
const CACHE_WORK: &str = "/work/.cache-work";
const CACHE_MERGED: &str = "/cache";

/// Where a spec fetched from the HOST is written.
///
/// `/run` and not `/etc/nucleus`: a real pod's rootfs is READ-ONLY, so writing
/// the fetched spec beside the baked one is impossible. The first version of
/// this wrote to `POD_SPEC_PATH` and every real pod died on it —
/// `the host supplied a pod spec and /etc/nucleus/pod.yaml could not be
/// written — refusing to boot`, followed by `Kernel panic - not syncing:
/// Attempted to kill init!`. The fail-closed path was right; the target was
/// not.
///
/// `/run` is a load-bearing tmpfs mounted well before the barrier, so it is
/// writable by the time the spec arrives and gone when the pod does.
const HOST_POD_SPEC: &str = "/run/nucleus/pod.yaml";
/// Where the resolver config is written when the rootfs is read-only, and
/// bind-mounted over `/etc/resolv.conf` from.
const RUN_RESOLV_CONF: &str = "/run/nucleus/resolv.conf";

/// Mount the per-pod scratch at `/work`, if this pod has one.
///
/// Optional: a guest without a data volume, or with a read-only one, is
/// legitimate (`workload.rs` allows a read-only `/work`).
///
/// # Why it takes a [`identity::PastBarrier`]
///
/// This used to run with the other mounts, well before the barrier. Mounting
/// ext4 WRITES to its superblock — the mount count goes to 1 and the
/// last-mounted path is recorded — so a base snapshotted here carried one pod's
/// filesystem metadata, and a clone restored against a fresh image had cached
/// metadata describing a filesystem that was not there. `clone_safety` refused
/// every jailed pod for exactly that reason.
///
/// The host verifies the outcome in the superblock rather than taking the
/// guest's word (`snapshot::mount_state`), so this is not a claim being made
/// here — it is the behaviour that makes the host's check pass. The token makes
/// the ordering unwritable rather than merely correct today.
fn mount_work(_past_barrier: &identity::PastBarrier) {
    if Path::new("/dev/vdb").exists()
        && let Err(err) = mount_fs(
            "/dev/vdb",
            "/work",
            "ext4",
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            None,
        )
    {
        eprintln!("optional mount /work failed — continuing without it: {err}");
    }
}

/// Mount the compiler cache: a read-only seed with a writable overlay on the scratch.
///
/// `/dev/vdc` is the pod's `data` drive. The node gives it `is_read_only: true` and pins its
/// digest, and that digest is IN the identity this pod signs — so what a verdict was produced
/// against is named rather than ambient. A build needs to WRITE, though, so the seed is the lower
/// layer of an overlay whose upper and work directories live on the scratch: reads come from the
/// pinned bytes, writes land in this pod's own disk, and the seed cannot be modified by the
/// workload at all. A cache the guest could write back into would be the poisoning vector this
/// arrangement exists to avoid.
///
/// Every failure here is optional. A pod with no data drive, a kernel without overlayfs, a seed
/// that will not mount: the gate then compiles from nothing, which is exactly what it does today.
/// It costs time and can never change a verdict, so it must not abort a boot.
///
/// **`/cache` IS WRITABLE ON EVERY PATH, INCLUDING ALL THE FAILING ONES**, and that is what makes
/// it safe for a gate to point `CARGO_TARGET_DIR` inside it. Before, this returned early with
/// `/cache` either absent (no data drive — the directory is created after that check) or an empty
/// directory on the read-only rootfs. Either is fine while nothing points at it, and both turn
/// into a HARD gate failure the moment something does: cargo cannot create its target directory
/// and the gate fails for a reason that has nothing to do with the tree under test.
///
/// So the seed is now an optimisation layered on top of a directory that always exists: when
/// everything works, `/cache` is the overlay and reads come from the pinned bytes; when anything
/// fails, `/cache` is a bind mount of the same scratch directory the overlay would have written
/// through. Cold instead of warm — today's behaviour — rather than broken.
fn mount_cache(_past_barrier: &identity::PastBarrier) {
    // Made FIRST and unconditionally: the fallback needs them even when there is no seed.
    for dir in [CACHE_UPPER, CACHE_WORK, CACHE_MERGED] {
        if let Err(err) = ensure_dir(dir) {
            eprintln!("optional cache: {err} — continuing without it");
            return;
        }
    }
    for dir in [CACHE_UPPER, CACHE_WORK, CACHE_MERGED] {
        chown_nobody(dir);
    }
    if !Path::new("/dev/vdc").exists() {
        bind_scratch_over_cache("no data drive");
        return;
    }
    if let Err(err) = ensure_dir(CACHE_SEED) {
        eprintln!("optional cache: {err} — continuing without it");
        bind_scratch_over_cache("seed mountpoint");
        return;
    }
    if let Err(err) = mount_fs(
        "/dev/vdc",
        CACHE_SEED,
        "ext4",
        MsFlags::MS_RDONLY | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        None,
    ) {
        eprintln!("optional cache seed did not mount — continuing without it: {err}");
        bind_scratch_over_cache("seed would not mount");
        return;
    }
    let options = format!("lowerdir={CACHE_SEED},upperdir={CACHE_UPPER},workdir={CACHE_WORK}");
    if let Err(err) = mount_fs(
        "overlay",
        CACHE_MERGED,
        "overlay",
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(&options),
    ) {
        eprintln!("optional cache overlay did not mount — continuing without it: {err}");
        bind_scratch_over_cache("overlay would not mount");
    }
}

/// Make `/cache` a writable directory on the pod's own scratch when the seed could not be used.
///
/// The cold half of [`mount_cache`]'s contract. `CACHE_UPPER` is the directory the overlay would
/// have written through, so binding it over `CACHE_MERGED` gives exactly the layout a gate
/// expects, minus the pinned bytes underneath: same path, same owner, same writability, empty.
///
/// Best effort like everything else here. If even this fails the gate is no worse off than it was
/// before any of it existed, and the reason is on the console -- which is the only place a silent
/// fallback can be told apart from a working cache.
fn bind_scratch_over_cache(why: &str) {
    if let Err(err) = mount_fs(
        CACHE_UPPER,
        CACHE_MERGED,
        "none",
        MsFlags::MS_BIND | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        None,
    ) {
        eprintln!("optional cache: {why}; scratch bind also failed: {err}");
        return;
    }
    eprintln!("optional cache: {why} — /cache is empty scratch, the gate compiles cold");
}

/// The invariant the cold path rests on: the directory bound over `/cache` when the seed is
/// unusable must live on the pod's own SCRATCH, not on the rootfs.
///
/// If `CACHE_UPPER` ever moved off `/work`, `bind_scratch_over_cache` would bind a read-only
/// rootfs directory over `/cache` and every gate would fail to create its target directory --
/// the exact hard failure the fallback exists to prevent, reintroduced by a path edit that looks
/// harmless. A string comparison is enough to make that unwritable.
#[cfg(test)]
mod cache_layout {
    use super::{CACHE_MERGED, CACHE_UPPER, CACHE_WORK};

    #[test]
    fn the_overlays_writable_layers_live_on_scratch() {
        assert!(
            CACHE_UPPER.starts_with("/work/"),
            "the overlay upper must be on the pod scratch, got {CACHE_UPPER}"
        );
        assert!(
            CACHE_WORK.starts_with("/work/"),
            "the overlay workdir must be on the pod scratch, got {CACHE_WORK}"
        );
        assert!(
            !CACHE_MERGED.starts_with("/work/"),
            "the merged mount is the gate-facing path and must not be inside the scratch it \
             writes through, got {CACHE_MERGED}"
        );
    }
}

/// Give a directory to the unprivileged build user. Best effort: the caller
/// treats the whole cache as optional.
fn chown_nobody(path: &str) {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::chown;
        if let Err(err) = chown(path, Some(65534), Some(65534)) {
            eprintln!("optional cache: chown {path}: {err}");
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = path;
}

/// Time one startup step and print it as it completes.
///
/// Mirrors `nucleus-startup-phase` from the tool-proxy deliberately, including
/// printing per step rather than only in a summary: a summary that prints at the
/// end cannot diagnose a hang, because a stall means the summary never runs and
/// the console stays empty. Streaming means the LAST line names the step that
/// finished, so the stall is in the one after it.
///
/// This half of the boot was entirely untimed. `/init` performs the vsock
/// handshake and then execs the tool-proxy, whose own trace starts at ITS
/// process start -- so everything here happened before any clock the host could
/// read, and a boot trace reporting `unaccounted=334ms of 389ms` was not even
/// measuring this part.
fn timed<T>(name: &str, f: impl FnOnce() -> T) -> T {
    let t = std::time::Instant::now();
    let out = f();
    eprintln!("nucleus-init-phase {name}={}ms", t.elapsed().as_millis());
    out
}

fn main() {
    if let Err(err) = run() {
        // PID 1 exiting panics the kernel: that IS the fail-closed outcome
        // (#2589), reached deliberately with the reason on the console, not
        // by the old path of swallowing the error and falling off the end.
        eprintln!("nucleus-guest-init error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    // The environment the tool-proxy is exec'd with, collected rather than
    // written into THIS process's environment.
    //
    // These 28 values used to be `std::env::set_var`. Two things were wrong
    // with that. Edition 2024 makes `set_var` unsafe — mutating the environment
    // races any concurrent reader — so keeping it meant 28 `unsafe` blocks.
    // And several of these are secrets (broker secret, cloud credentials,
    // task token): writing them into init's own environment
    // published them to `/proc/self/environ` and to EVERY later child, when
    // only the tool-proxy needs them. `Command::envs` scopes them to the one
    // process that does.
    //
    // Order is preserved, which matters: NUCLEUS_TASK_TOKEN is written twice
    // and the later value must still win, exactly as it did with set_var.
    let mut child_env: Vec<(std::ffi::OsString, std::ffi::OsString)> = Vec::new();
    macro_rules! export {
        ($k:expr, $v:expr) => {
            child_env.push(($k.into(), $v.into()))
        };
    }

    #[cfg(target_os = "linux")]
    {
        let _ = umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
    }

    ensure_dir(guest_layout::ETC_NUCLEUS)?;
    ensure_dir(WORK_DIR)?;

    // Booting → Mounted: every load-bearing mount succeeds or the boot stops
    // with a named error (#2589). The typestate carries the boot from here to
    // `exec`; see nucleus_guest_init::boot.
    let boot = Boot::start()
        .mount_all(&mount_specs(), |m| {
            let gm = GUEST_MOUNTS
                .iter()
                .find(|g| g.target == m.target)
                .expect("mount_specs is derived from GUEST_MOUNTS");
            mount_fs(m.source, m.target, m.fstype, gm.ms_flags(), gm.fs.data())
        })
        .map_err(|e| e.to_string())?;
    for missing in &boot.optional_mount_failures {
        eprintln!("optional mount {missing} failed — continuing without it");
    }

    // devtmpfs gives us the device nodes a driver registered; it does NOT give
    // us the four symlinks every init system creates by hand. Without them any
    // workload using bash process substitution (`< <(cmd)`, `>(cmd)`) or the
    // `/dev/std*` paths fails — and it fails naming the WORKLOAD's script, not
    // the runtime, so it reads as the workload's own bug.
    //
    // Measured inside a real pod before this existed: `/dev` held 100+ nodes
    // (console, null, vda, vsock, tty0-63 …) and all four of these were absent,
    // with `cat <(echo works)` reporting
    // `/dev/fd/63: No such file or directory`. A shell CI gate cannot run in a
    // pod without them.
    //
    // Not load-bearing: a workload that never touches these should still boot
    // if the symlink cannot be made, so a failure is reported and the boot
    // continues — the same treatment `optional_mount_failures` gets above.
    #[cfg(target_os = "linux")]
    for (link, target) in DEV_FD_SYMLINKS {
        if let Err(err) = symlink_if_absent(link, target) {
            eprintln!("optional /dev symlink {link} -> {target} failed: {err}");
        }
    }

    // Read secrets from kernel command line (preferred) or files (legacy/fallback)
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let host_spec_required = boot::requires_host_spec(&cmdline).map_err(|e| e.to_string())?;

    let net_config = net::parse_cmdline(&cmdline);

    if let Some(net) = net_config.as_ref() {
        timed("network", || configure_network(net));
    }

    // The in-guest egress fence, from the guest layer's own policy files and
    // nothing the image supplies. Before the egress probe (spawned at exec) and
    // before any workload exists, so neither ever sees an unfenced guest.
    //
    // FATAL when a policy file exists and cannot be enforced: the image builder
    // asked for this fence, and a guest that boots without it while looking
    // fenced is the outcome the whole layer exists to rule out. The script this
    // replaces failed silently, and on this repository's rootfs installed
    // nothing at all (see `fence`).
    match timed("egress_fence", fence::install_from_files).map_err(|e| e.to_string())? {
        Fenced::NoPolicy => {}
        Fenced::Installed { allow, deny } => {
            eprintln!("egress fence installed: {allow} allow, {deny} deny, default DROP");
        }
    }

    // Fetch SPIFFE identity from host if configured
    let workload_api_port = identity::parse_workload_api_port(&cmdline);
    // The handshake is five SEQUENTIAL vsock round trips. Timing the whole run
    // as well as each leg is the point: the per-leg numbers say which one is
    // slow, and the total says whether batching them into one round trip is
    // worth doing at all. Neither number existed before.
    let handshake_start = std::time::Instant::now();
    // THE BARRIER. Announced once, for both paths, and it hands back the token
    // `mount_work` requires — so mounting the scratch before this line is not a
    // convention anyone has to remember, it does not compile.
    let past_barrier = identity::barrier(workload_api_port);
    mount_work(&past_barrier);
    // After the scratch: the overlay's upper and work directories live on it.
    timed("mount_cache", || mount_cache(&past_barrier));

    // THE COMMAND, FETCHED RATHER THAN BAKED.
    //
    // `FETCH_POD_SPEC` existed as a protocol variant and a host handler, and
    // nothing sent it: the guest read /etc/nucleus/pod.yaml out of its own
    // rootfs and the command was whatever the image was built with. A base is
    // then per-JOB, which is the thing the barrier exists to avoid.
    //
    // Past the barrier, because a VM that has fetched its spec is committed to
    // one job. `place_host_spec` writes it where `resolve_pod_spec` looks, so
    // the two compose and the baked spec remains the fallback for a host that
    // says nothing.
    if let Some(port) = workload_api_port {
        match identity::fetch_pod_spec(port, &past_barrier) {
            Ok(spec) => match boot::place_host_spec(HOST_POD_SPEC, Some(&spec), |p, body| {
                // The parent first: /run is a fresh tmpfs every boot.
                if let Some(dir) = Path::new(p).parent()
                    && fs::create_dir_all(dir).is_err()
                {
                    return false;
                }
                fs::write(p, body).is_ok()
            }) {
                Ok(true) => eprintln!("pod spec fetched from the host"),
                Ok(false) => {}
                // NOT a fallback to the baked spec: the host believes it
                // dispatched a different job.
                Err(e) => return Err(e.to_string()),
            },
            // Enforcing guests may not substitute the baked workload on any fetch failure.
            Err(e) if host_spec_required => {
                return Err(format!("required host spec fetch failed: {e}"));
            }
            Err(e) => eprintln!("no pod spec over vsock (keeping the baked one): {e}"),
        }
    }

    let spec_path = boot::resolve_launch_spec(
        host_spec_required,
        HOST_POD_SPEC,
        POD_SPEC_PATH,
        FALLBACK_POD_SPEC,
        |p| Path::new(p).exists(),
        |from, to| fs::copy(from, to).is_ok(),
    )
    .map_err(|e| e.to_string())?;
    if host_spec_required {
        eprintln!("{}", nucleus_spec::guest_layout::HOST_SPEC_READY);
    }
    if let Some(port) = workload_api_port {
        // Announce the barrier before asking for anything. After the first fetch below this VM
        // is one particular pod, and a snapshot of it would hand that pod's identity to every
        // clone. Best-effort: a host that does not know the command simply never records it, and
        // the only consequence is that this VM cannot be used as a base.

        match timed("identity", || identity::fetch_identity(port)) {
            Ok(spiffe_id) => {
                eprintln!("fetched identity: {spiffe_id}");
                // POINT THE PROXY AT WHAT WE JUST FETCHED.
                //
                // Without this the fetch is decorative: `fetch_identity` writes
                // the SVID to /run/nucleus/identity, and the tool-proxy looks
                // for `--identity-cert` / `NUCLEUS_IDENTITY_CERT`, which nobody
                // set — so the cert existed on disk and Tier 1/2 still reported
                // "no identity cert" and the guest died as a naked process.
                //
                // Observed on real hardware once the workload API bridge started
                // early enough for the fetch to SUCCEED. Before that the fetch
                // always failed, so this gap was invisible: the pod died one
                // step earlier for a different reason.
                export!("NUCLEUS_IDENTITY_CERT", identity::svid_cert_path());
                export!("NUCLEUS_IDENTITY_KEY", identity::svid_key_path());
                export!(
                    "NUCLEUS_IDENTITY_TRUST_BUNDLE",
                    identity::trust_bundle_path()
                );
            }
            Err(e @ identity::FetchError::Preempted(_)) => return Err(e.to_string()),
            Err(err) => {
                eprintln!("failed to fetch identity: {err}");
                // Continue without identity - not fatal for now
            }
        }
    }

    // Session capability token, preferred over the kernel command line.
    //
    // Fetching it here rather than reading `nucleus.task_token_hex` is what lets
    // the command-line copy go, and the command line is what blocks a snapshot
    // base: per-pod material baked into a boot artifact is inherited by every
    // clone restored from it. The token is not a secret — a scoped capability
    // plus a public issuer key — so this is about uniqueness surviving a
    // restore, not confidentiality.
    //
    // Synchronous, and before `exec_proxy`, so the values are in the environment
    // before anything reads them.
    // The broker capability, fetched BEFORE `exec_proxy` and therefore before any
    // workload exists. The host serves it once; arriving first is the entire
    // property, since any guest process can open AF_VSOCK.
    //
    // Not fatal when absent: a pod may have no broker at all, and the tool-proxy
    // fails closed on its own (an unsigned envelope is refused host-side). Making
    // it fatal would break every pod that never had one.
    if let Some(port) = workload_api_port {
        match timed("broker_secret", || identity::fetch_broker_secret(port)) {
            Ok(cap) => {
                export!("NUCLEUS_TOOL_PROXY_BROKER_SECRET", &cap.secret);
                // The port is NOT a secret — it is where to connect — so unlike
                // the key it is safe to log, and worth logging: a proxy that
                // cannot reach the broker looks identical to one that was never
                // given a capability.
                export!("NUCLEUS_TOOL_PROXY_BROKER_PORT", cap.port.to_string());
                // Presence only for the secret — never the value, never its length.
                eprintln!(
                    "fetched broker capability over vsock (broker port {})",
                    cap.port
                );
            }
            // Every per-pod value is served once (#2724). "Already served" means
            // something in this guest asked before init did and holds what the
            // proxy was to hold: never boot on, whichever value it was.
            Err(e @ identity::FetchError::Preempted(_)) => return Err(e.to_string()),
            Err(err) => eprintln!("no broker capability over vsock: {err}"),
        }

        // The host signs its own authorizations. Keep the audit/report transport
        // available without exporting any receipt-signing seed into the guest.
        export!("NUCLEUS_WORKLOAD_API_PORT", port.to_string());

        // The S3 audit-sink credentials, fetched with the same before-
        // `exec_proxy` ordering as the broker capability (the host serves them
        // once; arriving before any workload exists is the property). They
        // used to arrive as `nucleus.aws_*` kernel args, world-readable by the
        // workload whose audit trail they write.
        //
        // Not fatal when absent: most pods have no audit sink, and the
        // tool-proxy's S3 sink init is non-fatal on missing credentials — the
        // failure mode is audit degradation, which the proxy logs.
        match identity::fetch_audit_credentials(port) {
            Ok(Some(creds)) => {
                export!("AWS_ACCESS_KEY_ID", &creds.access_key_id);
                export!("AWS_SECRET_ACCESS_KEY", &creds.secret_access_key);
                if let Some(token) = &creds.session_token {
                    export!("AWS_SESSION_TOKEN", token);
                }
                // Presence only — never the values, never their length.
                eprintln!("fetched audit-sink credentials over vsock");
            }
            Ok(None) => {}
            Err(e @ identity::FetchError::Preempted(_)) => return Err(e.to_string()),
            Err(err) => eprintln!("no audit-sink credentials over vsock: {err}"),
        }
    }

    let mut token_from_vsock = false;
    if let Some(port) = workload_api_port {
        // The caller-identity token for the node's management API, from the
        // same per-pod socket. Fetched here rather than passed in the pod spec
        // or the kernel cmdline for the reason the whole mechanism rests on:
        // the socket says which pod this is, and nothing the guest can write
        // does.
        match timed("pod_caller_token", || {
            identity::fetch_pod_caller_token(port)
        }) {
            Ok(id) => {
                eprintln!("fetched pod caller token over vsock");
                export!("NUCLEUS_POD_CALLER_TOKEN", id.token);
                // The node verifies the (pod_id, token) PAIR; set the id only when
                // the same socket served it, so a token is never presented without
                // the id it was minted with. A legacy node serves no id, leaving
                // the pod unidentified exactly as before (fail-closed to operator).
                if let Some(pod_id) = id.pod_id {
                    eprintln!("fetched pod id over vsock");
                    export!("NUCLEUS_POD_ID", pod_id);
                }
            }
            Err(e @ identity::FetchError::Preempted(_)) => return Err(e.to_string()),
            Err(err) => {
                // Not fatal: the node still accepts unidentified callers today,
                // and a pod that cannot identify itself simply gets the older,
                // proxy-side-only enforcement.
                eprintln!("failed to fetch pod caller token: {err}");
            }
        }

        match timed("task_token", || identity::fetch_task_token(port)) {
            Ok(Some(t)) => {
                export!("NUCLEUS_TASK_TOKEN", &t.token);
                export!("NUCLEUS_TASK_TOKEN_NONCE", &t.nonce);
                export!("NUCLEUS_TASK_TOKEN_ISSUER", &t.issuer);
                token_from_vsock = true;
                eprintln!("fetched session task token over vsock");
            }
            // No token was minted for this pod: a degraded but legitimate
            // state. The tool-proxy records the token as Missing and fails
            // closed at verify, exactly as it did when the cmdline carried no
            // token — so this is not fatal.
            Ok(None) => {
                eprintln!("no session task token was minted for this pod");
            }
            Err(e @ identity::FetchError::Preempted(_)) => return Err(e.to_string()),
            // A real transport/protocol failure, and now FATAL: the node no
            // longer writes a cmdline copy for an identity-bearing pod (that
            // was the last per-pod secret on `/proc/cmdline`), so vsock is the
            // ONLY source. Failing here names the cause; letting it slide would
            // surface as a fail-closed proxy four layers away, at first use.
            Err(err) => {
                return Err(format!(
                    "failed to fetch session task token over vsock, and there is no \
                     kernel-cmdline fallback for an identity-bearing pod: {err}"
                ));
            }
        }

        // The pod's certificate of authority (pod_authority on the node). Its
        // effective permissions ARE this pod's policy, and the pinned root
        // key is what the tool-proxy verifies it against. Absence is not
        // fatal: the proxy falls back to its resolved policy as its own
        // ceiling. Presence-but-invalid is the proxy's to refuse.
        match timed("pod_certificate", || identity::fetch_pod_certificate(port)) {
            Ok(Some(c)) => {
                export!("NUCLEUS_POD_CERT", &c.certificate);
                export!("NUCLEUS_CERT_ROOT_PUBKEY", &c.root_pubkey);
                eprintln!("fetched pod certificate over vsock");
            }
            Ok(None) => eprintln!("no pod certificate was issued for this pod"),
            Err(e @ identity::FetchError::Preempted(_)) => return Err(e.to_string()),
            Err(err) => eprintln!("failed to fetch pod certificate over vsock: {err}"),
        }
    }
    // Printed even when no port was configured, so a boot with NO handshake is
    // visibly 0ms rather than silently absent — otherwise "the line is missing"
    // and "the handshake was free" look identical in a log.
    eprintln!(
        "nucleus-init-phase handshake_total={}ms",
        handshake_start.elapsed().as_millis()
    );

    // OPTIONAL. On the Firecracker path the tool-proxy is bound to a vsock
    // listener that accepts only the host (`pod_mgmt::peer_is_host`), and the
    // guest kernel — not the caller — sets the peer CID. The HMAC tier is
    // unreachable there, so requiring a key would put a world-readable secret
    // on /proc/cmdline for nothing. `enforce_hmac_key_quality` in the proxy
    // still refuses an empty key on every transport that can reach that tier.
    let auth_secret =
        parse_cmdline_secret(&cmdline, "nucleus.auth_secret").or_else(|| read_secret(AUTH_SECRET));

    // Signature-based approvals: the node delivers the Ed25519 PUBLIC half of
    // its approval signing key as `nucleus.approval_pubkeys`. A verification
    // key is safe on the world-readable cmdline — reading it grants no
    // forging power, which is exactly what the approval SECRET below lacked
    // (HMAC is symmetric, so the workload could read `/proc/cmdline` and sign
    // its own approvals). When keys are present the proxy accepts ONLY
    // signatures; the secret is legacy for pods still provisioned with one.
    let approval_pubkeys = parse_cmdline_secret(&cmdline, "nucleus.approval_pubkeys");
    if let Some(ref keys) = approval_pubkeys {
        export!("NUCLEUS_TOOL_PROXY_APPROVAL_PUBKEYS", keys);
    }

    let approval_secret = parse_cmdline_secret(&cmdline, "nucleus.approval_secret")
        .or_else(|| read_secret(APPROVAL_SECRET));
    if approval_pubkeys.is_none() && approval_secret.is_none() {
        // Fail HERE, near the cause: the tool-proxy would refuse to start
        // anyway (its approval endpoint would be unauthenticatable), but its
        // exit is four layers from this missing boot arg.
        return Err(
            "missing approval authority (set nucleus.approval_pubkeys or \
                    nucleus.approval_secret in boot args, or /etc/nucleus/approval.secret)"
                .to_string(),
        );
    }

    if let Some(auth_secret) = auth_secret {
        export!("NUCLEUS_TOOL_PROXY_AUTH_SECRET", auth_secret);
    }
    if let Some(approval_secret) = approval_secret {
        export!("NUCLEUS_TOOL_PROXY_APPROVAL_SECRET", approval_secret);
    }

    // Sandbox token is optional — Tier 3 fallback when SVID doesn't carry
    // an attestation OID. If absent, tool-proxy uses Tier 1 or Tier 2 proof.
    // DLC-D verified-admission provisioning → the in-VM tool-proxy, over the
    // workload API like the task token (the cmdline lacks the capacity for a
    // credential set, and per-pod material must not bake into snapshot bases).
    // Unprovisioned is the ordinary case and stays quiet; the proxy is inert
    // without these.
    if let Some(port) = workload_api_port {
        match identity::fetch_dlc_admission(port) {
            Ok(Some(m)) => {
                // Names from `nucleus_spec::dlc_admission`, the declaration the
                // node served this from and the tool-proxy reads with.
                for (key, value) in m.env() {
                    export!(key, value);
                }
                eprintln!("fetched DLC admission provisioning over the workload API");
            }
            Ok(None) => {}
            Err(e @ identity::FetchError::Preempted(_)) => return Err(e.to_string()),
            Err(err) => eprintln!("failed to fetch DLC admission provisioning: {err}"),
        }
    }

    if let Some(sandbox_token) = parse_cmdline_secret(&cmdline, "nucleus.sandbox_token")
        .or_else(|| read_secret(SANDBOX_TOKEN))
    {
        export!("NUCLEUS_SANDBOX_TOKEN", sandbox_token);
    }

    // Live-path session capability token (optional). The node injects it on the
    // kernel cmdline as `nucleus.task_token_hex` (hex of the token JSON — the
    // cmdline is whitespace-delimited and quote-sensitive, so raw JSON is unsafe)
    // plus hex nonce/issuer. We decode the token back to the exact JSON string
    // the tool-proxy verify half expects and forward all three as env vars. If
    // the token is absent or the hex is malformed we simply do not set them —
    // the tool-proxy then records Missing/Invalid and fails closed.
    let cmdline_token = if token_from_vsock {
        None
    } else {
        parse_cmdline_secret(&cmdline, "nucleus.task_token_hex")
    };
    if let Some(token_hex) = cmdline_token {
        match hex::decode(&token_hex)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
        {
            Some(token_json) => {
                export!("NUCLEUS_TASK_TOKEN", token_json);
                if let Some(nonce) = parse_cmdline_secret(&cmdline, "nucleus.task_token_nonce") {
                    export!("NUCLEUS_TASK_TOKEN_NONCE", nonce);
                }
                if let Some(issuer) = parse_cmdline_secret(&cmdline, "nucleus.task_token_issuer") {
                    export!("NUCLEUS_TASK_TOKEN_ISSUER", issuer);
                }
            }
            None => {
                eprintln!(
                    "nucleus-guest-init: nucleus.task_token_hex is not valid hex/UTF-8; \
                     skipping session token (tool-proxy will fail closed)"
                );
            }
        }
    }

    // S3 audit sink config (optional, passed via kernel args from nucleus-node)
    for (arg, env_var) in [
        (
            "nucleus.audit_s3_bucket",
            "NUCLEUS_TOOL_PROXY_AUDIT_S3_BUCKET",
        ),
        (
            "nucleus.audit_s3_prefix",
            "NUCLEUS_TOOL_PROXY_AUDIT_S3_PREFIX",
        ),
        (
            "nucleus.audit_s3_region",
            "NUCLEUS_TOOL_PROXY_AUDIT_S3_REGION",
        ),
        (
            "nucleus.audit_s3_endpoint",
            "NUCLEUS_TOOL_PROXY_AUDIT_S3_ENDPOINT",
        ),
    ] {
        if let Some(val) = parse_cmdline_secret(&cmdline, arg) {
            export!(env_var, val);
        }
    }

    // The AWS *credentials* no longer ride the kernel command line — they are
    // fetched over the workload API above, before any workload exists. Only
    // the region remains here: per-fleet configuration, not a secret.
    if let Some(val) = parse_cmdline_secret(&cmdline, "nucleus.aws_default_region") {
        export!("AWS_DEFAULT_REGION", val);
    }

    // The TLS stack the tool-proxy builds reads its roots from `SSL_CERT_FILE`
    // (rustls-native-certs). Pointing it at the guest layer's bundle is what
    // makes the runtime independent of whether the IMAGE ships a CA store: the
    // proxy is PID 1 after the exec below, and an HTTPS client it cannot build
    // takes the whole microVM with it. Scoped to the proxy by `child_env`, and
    // never reaching the workload, whose environment is declared, not inherited.
    match CaBundle::resolve(|p| Path::new(p).exists()) {
        CaBundle::Absent => eprintln!(
            "no CA bundle at {} or {}; the tool-proxy cannot build an HTTPS client",
            guest_layout::CA_BUNDLE,
            guest_layout::LEGACY_CA_BUNDLE
        ),
        found @ (CaBundle::GuestLayer | CaBundle::LegacyRootfs) => {
            if let Some(path) = found.path() {
                export!("SSL_CERT_FILE", path);
            }
        }
    }

    let audit_path = resolve_audit_path();
    export!("NUCLEUS_TOOL_PROXY_AUDIT_LOG", audit_path.clone());
    export!("NUCLEUS_TOOL_PROXY_BOOT_ACTOR", "guest-init");
    if let Some(report) = build_boot_report(&spec_path, net_config.as_ref(), &audit_path) {
        export!("NUCLEUS_TOOL_PROXY_BOOT_REPORT", report);
    }

    // Mounted → Provisioned → Sealed: the remount is the seal, and `exec`
    // exists only on the sealed boot — reordering these is a type error.
    let boot = boot
        .provisioned()
        .seal(remount_root_ro)
        .map_err(|e| e.to_string())?;

    // NOTE: the loopback interface is DOWN here. Measured in a booted guest —
    // `/sys/class/net/lo/flags` reads `0x8` (LOOPBACK without IFF_UP) and
    // `operstate` is `down`. Nothing in this image brings it up, and the rootfs
    // is Debian slim, so it has neither `ip` nor `ifconfig`.
    //
    // That is harmless TODAY, and the reason is worth recording because it is
    // not obvious: the tool-proxy's `--listen` defaults to `127.0.0.1:0`, but it
    // serves vsock EXCLUSIVELY when the spec declares one, and
    // `spawn_firecracker_pod` REFUSES a spec without vsock. So the TCP listener
    // is unreachable on every path this init serves and `bind()` never touches
    // loopback.
    //
    // A fix was written and then removed. It worked — flags went 0x8 to 0x9 in a
    // booted guest — but building a rootfs WITHOUT it and booting produced an
    // identical result, because the condition it guarded cannot occur here. The
    // real cause of the bind failure that prompted it was a test config with no
    // vsock DEVICE.
    //
    // Anything that makes the guest bind a TCP socket — a spec without vsock, a
    // second listener, a health endpoint on 127.0.0.1 — reintroduces the need,
    // and `EADDRNOTAVAIL` from PID 1 panics the kernel rather than logging.
    let err = boot.exec(|proof| exec_proxy(proof, &spec_path, child_env));
    Err(format!("failed to exec {PROXY_BIN}: {err}"))
}

/// The typestate's view of `GUEST_MOUNTS`: which mounts are load-bearing.
fn mount_specs() -> Vec<MountSpec> {
    GUEST_MOUNTS
        .iter()
        .map(|m| MountSpec {
            source: m.source,
            target: m.target,
            fstype: m.fs.fstype(),
            load_bearing: m.load_bearing,
        })
        .collect()
}

/// One guest mount, with its hardening flags as PLAIN BOOLS.
///
/// Bools rather than `MsFlags` so the table is inspectable on any host — the
/// same reason `firecracker_config`'s lowering seams are not gated behind
/// `target_os = "linux"`. A hardening table that can only be read on the machine
/// it runs on is a hardening table nobody checks.
pub(crate) struct GuestMount {
    pub source: &'static str,
    pub target: &'static str,
    /// The filesystem, carrying its own mount data. Typed rather than an
    /// `fstype` string beside a free-form options string, so a procfs entry
    /// cannot be written without stating its `hidepid` (ADR 0007 E-2) and the
    /// options a mount gets are derived from the filesystem, never restated
    /// beside it (G-1).
    pub fs: GuestFs,
    /// SUID/SGID bits are not honoured — blocks a dropped setuid binary.
    pub nosuid: bool,
    /// Device nodes cannot be created — blocks a crafted /dev/mem or /dev/sda.
    pub nodev: bool,
    /// Binaries cannot be executed from here.
    pub noexec: bool,
    /// A failed mount of this entry aborts the boot (#2589). Every
    /// pseudo-filesystem here is load-bearing: the proxy needs /proc and /dev,
    /// the identity handshake needs /run, the audit fallback needs /tmp.
    pub load_bearing: bool,
}

/// A guest pseudo-filesystem, with the mount data it takes.
///
/// One variant per filesystem the table mounts. Only procfs takes data today;
/// the others are unit variants, so adding data to one is a type change the
/// `match`es below will not let anyone skip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuestFs {
    /// procfs. `hidepid` is a required field, not an option: a `/proc` mounted
    /// without it lists PID 1 (the tool-proxy, guest root) to the workload and
    /// serves it `/proc/1/cmdline` (measured, P3 spike section 5).
    Proc {
        hidepid: HidePid,
    },
    Sysfs,
    Devtmpfs,
    Tmpfs {
        access: TmpfsAccess,
    },
}

/// Every writable tmpfs root needs an explicit ownership policy. The kernel's
/// default 0777 permits workload replacement of names inside runtime directories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TmpfsAccess {
    Runtime,
    SharedTemporary,
}

/// procfs `hidepid`: what a process sees of another uid's `/proc/<pid>`.
///
/// Deliberately has no `Off` (`hidepid=0`), `NoAccess` (`1`) or `Ptraceable`
/// (`4`) variant. `Off` is the defect this exists to remove, and `NoAccess`
/// still lists every pid, so a workload could enumerate the runtime's process
/// tree. A variant is added when something needs it, and then the reason is
/// written here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HidePid {
    /// `hidepid=invisible` (= `2`): another uid's `/proc/<pid>` directories do
    /// not exist for this process. They are absent from the listing and a
    /// lookup is `ENOENT`. Root and same-uid processes still see them, so PID 1
    /// (root) and the workload's own children (same uid) are unaffected.
    Invisible,
}

impl HidePid {
    /// The option as procfs spells it. Since 5.8 `proc_parse_hidepid_param`
    /// accepts the name or the number, and `proc_show_options` prints only the
    /// name. The NAME is written so the option is byte-identical to what
    /// `/proc/self/mountinfo` reports back, which is what the workload probe
    /// checks.
    pub(crate) const fn option(self) -> &'static str {
        match self {
            HidePid::Invisible => "hidepid=invisible",
        }
    }
}

impl GuestFs {
    /// The `fstype` argument to `mount(2)`.
    pub(crate) const fn fstype(self) -> &'static str {
        match self {
            GuestFs::Proc { .. } => "proc",
            GuestFs::Sysfs => "sysfs",
            GuestFs::Devtmpfs => "devtmpfs",
            GuestFs::Tmpfs { access: _ } => "tmpfs",
        }
    }

    /// The `data` argument to `mount(2)`: the filesystem-specific options.
    ///
    /// No `subset=pid` on procfs, although 6.1 supports it (5.8+). It hides
    /// every non-pid entry, and this mount is one superblock shared with
    /// guest-init itself: guest-init reads `/proc/cmdline` after mounting it for
    /// its network config and approval keys, and ordinary workloads read
    /// `/proc/meminfo`, `/proc/cpuinfo` and `/proc/sys`. What it would hide
    /// beyond hidepid is system-wide state, none of it another process's.
    pub(crate) const fn data(self) -> Option<&'static str> {
        match self {
            GuestFs::Proc { hidepid } => Some(hidepid.option()),
            GuestFs::Sysfs | GuestFs::Devtmpfs => None,
            GuestFs::Tmpfs { access } => Some(match access {
                TmpfsAccess::Runtime => "mode=0755",
                TmpfsAccess::SharedTemporary => "mode=1777",
            }),
        }
    }
}

impl GuestMount {
    fn ms_flags(&self) -> MsFlags {
        let mut f = MsFlags::empty();
        if self.nosuid {
            f |= MsFlags::MS_NOSUID;
        }
        if self.nodev {
            f |= MsFlags::MS_NODEV;
        }
        if self.noexec {
            f |= MsFlags::MS_NOEXEC;
        }
        f
    }
}

/// The guest's pseudo-filesystem mounts, hardened.
///
/// Every one of these was mounted with `MsFlags::empty()` — no nosuid, no
/// nodev, no noexec — while `/work`, the data volume mounted a few lines below,
/// already carried `MS_NOSUID | MS_NODEV`. The pattern was known and the
/// pseudo-filesystems simply missed it.
///
/// Standard practice for microVMs is a read-only rootfs with writable layers
/// marked noexec/nodev/nosuid. `/tmp` and `/run` are the writable tmpfs layers
/// and the classic staging ground for a dropped payload; `/proc` and `/sys`
/// have no business carrying setuid bits, device nodes or executables.
///
/// `/dev` keeps `nodev = false` for the obvious reason — it IS the device tree —
/// and keeps `noexec = false` deliberately rather than by omission: tightening a
/// mount the guest boots from, with no end-to-end test available here, risks the
/// mount failing and `mount_fs` continuing without it, which would be a worse
/// outcome than the flag's absence.
/// The symlinks devtmpfs does not create.
///
/// POSIX-shell tooling assumes these exist. `/dev/fd` is what bash opens for
/// process substitution; the three `std*` paths are what a script means by
/// "the file that is my stdin". All four are plain symlinks into `/proc`, so
/// they cost nothing and require only that `/proc` is mounted — which it is,
/// load-bearing, by the time these are made.
// Read only by the `#[cfg(target_os = "linux")]` loop that creates these, so a
// macOS build sees the table as dead. Gating the table on Linux too would take
// its test off every developer machine; keeping it portable means the shape of
// the table is checked wherever tests run, and only the unused-on-macOS warning
// is silenced. Narrow on purpose: this allow covers one constant, not a module.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) const DEV_FD_SYMLINKS: &[(&str, &str)] = &[
    ("/dev/fd", "/proc/self/fd"),
    ("/dev/stdin", "/proc/self/fd/0"),
    ("/dev/stdout", "/proc/self/fd/1"),
    ("/dev/stderr", "/proc/self/fd/2"),
];

/// Create `link` -> `target`, treating "already there" as success.
///
/// A rootfs that ships its own `/dev/fd` is not a problem to correct, and
/// racing a second boot on the same devtmpfs should not fail either.
#[cfg(target_os = "linux")]
fn symlink_if_absent(link: &str, target: &str) -> std::io::Result<()> {
    match std::os::unix::fs::symlink(target, link) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
}

pub(crate) const GUEST_MOUNTS: &[GuestMount] = &[
    GuestMount {
        source: "proc",
        target: "/proc",
        fs: GuestFs::Proc {
            hidepid: HidePid::Invisible,
        },
        nosuid: true,
        nodev: true,
        noexec: true,
        load_bearing: true,
    },
    GuestMount {
        source: "sys",
        target: "/sys",
        fs: GuestFs::Sysfs,
        nosuid: true,
        nodev: true,
        noexec: true,
        load_bearing: true,
    },
    GuestMount {
        source: "dev",
        target: "/dev",
        fs: GuestFs::Devtmpfs,
        nosuid: true,
        nodev: false,
        noexec: false,
        load_bearing: true,
    },
    GuestMount {
        source: "tmpfs",
        target: "/tmp",
        fs: GuestFs::Tmpfs {
            access: TmpfsAccess::SharedTemporary,
        },
        nosuid: true,
        nodev: true,
        noexec: true,
        load_bearing: true,
    },
    GuestMount {
        source: "tmpfs",
        target: "/run",
        fs: GuestFs::Tmpfs {
            access: TmpfsAccess::Runtime,
        },
        nosuid: true,
        nodev: true,
        noexec: true,
        load_bearing: true,
    },
];

fn ensure_dir(path: &str) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|err| format!("create {path}: {err}"))
}

/// One `mount(2)`. The CALLER decides what a failure means (load-bearing
/// aborts the boot, optional continues); this no longer swallows errors.
fn mount_fs(
    source: &str,
    target: &str,
    fstype: &str,
    flags: MsFlags,
    data: Option<&str>,
) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let data_bytes = data.map(|value| value.as_bytes());
        match mount(Some(source), target, Some(fstype), flags, data_bytes) {
            Ok(()) => Ok(()),
            // Already mounted — the kernel mounts devtmpfs on /dev itself when
            // built with CONFIG_DEVTMPFS_MOUNT, and the guest kernel is. The
            // old fail-open `mount_fs` hid this behind a log line; the first
            // load-bearing version aborted every boot on it (the x86_64 boot
            // lane: "mount dev -> /dev (devtmpfs) failed: EBUSY").
            //
            // EBUSY alone is not proof the mount is there, so require the
            // target to actually be a mount point, and then REMOUNT with our
            // flags: the kernel's automount carries none of them, and a /dev
            // without nosuid is not the /dev this list promises.
            Err(nix::errno::Errno::EBUSY) if is_mountpoint(target) => {
                eprintln!(
                    "mount {source} -> {target} ({fstype}): already mounted by the kernel; remounting with the required flags"
                );
                mount(
                    None::<&str>,
                    target,
                    None::<&str>,
                    flags | MsFlags::MS_REMOUNT,
                    data_bytes,
                )
                .map_err(|err| {
                    format!("remount {target} ({fstype}) with the required flags failed: {err}")
                })
            }
            Err(err) => Err(format!(
                "mount {source} -> {target} ({fstype}) failed: {err}"
            )),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (source, target, fstype, flags, data);
        Ok(())
    }
}

/// True when `path` is the root of a mount: its device differs from its
/// parent's, or it is `/`. Pure stat, so it works before /proc is mounted.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn is_mountpoint(path: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    let parent = Path::new(path).parent().unwrap_or(Path::new("/"));
    match fs::metadata(parent) {
        Ok(pmeta) => meta.dev() != pmeta.dev() || meta.ino() == pmeta.ino(),
        Err(_) => false,
    }
}

/// Remount the guest root read-only, and FAIL THE BOOT if it does not take.
///
/// This logged the failure and carried on, so a guest whose rootfs did not go
/// read-only booted anyway — silently losing the read-only-rootfs posture that
/// the whole image is built around, with nothing above it any the wiser.
///
/// The repo already states the rule for the analogous case one layer up, in
/// nucleus-node's seccomp verification: "a process whose seccomp filter cannot
/// be confirmed active is killed and the launch is aborted rather than left
/// running unconfined. The previous behavior only logged a warning and continued
/// (fail-open)." The same applies here. The Linux kernel itself panics rather
/// than continue when it cannot mount root.
///
/// Returning `Result` rather than panicking so the caller aborts BEFORE
/// `exec_proxy` — a controlled refusal with a legible message, not a panic
/// midway through boot.
fn remount_root_ro() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        mount::<str, str, str, str>(
            None,
            "/",
            None,
            MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None,
        )
        .map_err(|err| {
            format!(
                "remount / read-only failed: {err} — refusing to start the \
                     workload rather than run it on a writable rootfs"
            )
        })?;
    }
    Ok(())
}

fn read_secret(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn resolve_audit_path() -> String {
    if let Some(path) = read_secret(AUDIT_PATH_FILE) {
        return path;
    }
    if is_writable("/work") {
        let _ = fs::create_dir_all("/work/audit");
        return "/work/audit/nucleus-audit.log".to_string();
    }
    "/tmp/nucleus-audit.log".to_string()
}

fn build_boot_report(
    spec_path: &str,
    net_config: Option<&NetConfig>,
    audit_path: &str,
) -> Option<String> {
    let net_addr = net_config.map(NetConfig::cidr).unwrap_or_default();
    let net_gw = net_config
        .and_then(|cfg| cfg.gw)
        .map(|v| v.to_string())
        .unwrap_or_default();
    let net_dns = net_config
        .and_then(|cfg| cfg.dns)
        .map(|v| v.to_string())
        .unwrap_or_default();
    let auth_secret = Path::new(AUTH_SECRET).exists();
    let approval_secret = Path::new(APPROVAL_SECRET).exists();
    let sandbox_token = Path::new(SANDBOX_TOKEN).exists();

    Some(format!(
        "{{\"spec_path\":\"{spec_path}\",\"net_addr\":\"{net_addr}\",\"net_gw\":\"{net_gw}\",\"net_dns\":\"{net_dns}\",\"audit_path\":\"{audit_path}\",\"auth_secret\":{auth_secret},\"approval_secret\":{approval_secret},\"sandbox_token\":{sandbox_token}}}"
    ))
}

fn is_writable(dir: &str) -> bool {
    let test_path = Path::new(dir).join(".nucleus_write_test");
    if fs::write(&test_path, b"test").is_ok() {
        let _ = fs::remove_file(test_path);
        return true;
    }
    false
}

/// Observe, from inside the guest, that egress is actually confined.
///
/// # Why this runs at all
///
/// The IFC guarantee cannot follow a process past `exec`: once a shell is
/// running, `curl`, `/dev/tcp` and `nc` never reach `NetEffect::fetch`, so the
/// containment for that surface is the netns/iptables default-deny backstop and
/// nothing else. The host applies those rules and checks the `iptables`
/// commands SUCCEEDED — but a command returning 0 is not traffic being dropped.
/// An nftables backend translating differently, a missing conntrack module, or
/// a netns that is not the one the VM ended up in each produce a pod reported
/// healthy while the shell reaches the internet.
///
/// So the pod proves it instead of the host assuming it. `nucleus-egress-probe`
/// already existed and already shipped in the rootfs; it was run only by a CI
/// script against a CI-booted pod. This runs it for THIS pod.
///
/// # Spawned, not awaited — and what that measurement cost
///
/// Measured on real KVM (Lima, Firecracker host kernel), in a routed netns that
/// mirrors a real pod rather than an empty one:
///
///   * a genuine escape connects in **11-18 ms**;
///   * the probe under a DROP fence costs **1.01 s** at its default 500 ms
///     per-target timeout, because DROP makes connects hang rather than fail
///     fast (an empty netns returns ENETUNREACH instantly, which is why an
///     unrouted control looked cheap AND passed without any fence at all).
///
/// #2344 had just cut guest startup to ~0.7 s, so blocking here would have more
/// than doubled it. Instead the probe is spawned and NOT awaited: it writes its
/// verdict to stderr — the guest console — while the tool-proxy starts. The host
/// is already waiting for proxy health, which is longer than the probe takes, so
/// the attestation is free in the common case.
///
/// The timeout is still lowered to 150 ms, giving ~8x headroom over the observed
/// 18 ms escape and bounding the probe at ~0.31 s so it cannot outlive a short
/// boot. Raising it is safe; lowering it is not, because a shorter deadline
/// makes a slow-but-successful connect look like a denial — PASS is the
/// dangerous direction here.
fn attest_egress_confinement() {
    let spawned = GuestBin::EgressProbe
        .command()
        // Inherit stderr so the verdict lands on the console the node captures.
        .env("NUCLEUS_EGRESS_PROBE_TIMEOUT_MS", "150")
        .spawn();
    if let Err(err) = spawned {
        // Do NOT invent a verdict. The host fails closed on a missing PASS, so
        // saying nothing is the safe outcome; this only explains the absence.
        eprintln!("nucleus-egress-probe could not start: {err}");
    }
}

/// The only programs PID 1 starts: the guest layer's own.
///
/// guest-init used to run `ip` three times and `/bin/sh guest-net.sh` once —
/// programs the IMAGE supplied, as root, before the rootfs was sealed. Both are
/// now done in-process (`net`, `fence`), and what remains is closed over this
/// enum: there is no way to name another program from here, and
/// `the_only_programs_pid1_starts_are_the_guest_layers` fails the build's tests
/// if a `Command::new` appears anywhere else.
#[derive(Debug, Clone, Copy)]
enum GuestBin {
    /// The mediating runtime, exec'd in place of PID 1.
    Proxy,
    /// The egress confinement probe, spawned beside it.
    EgressProbe,
    /// CI-only lineage probe; workloads cannot open AF_VSOCK.
    #[cfg(feature = "ci-podlist-probe")]
    PodlistProbe,
}

impl GuestBin {
    fn path(self) -> &'static str {
        match self {
            Self::Proxy => PROXY_BIN,
            Self::EgressProbe => EGRESS_PROBE_BIN,
            #[cfg(feature = "ci-podlist-probe")]
            Self::PodlistProbe => guest_layout::PODLIST_PROBE_BIN,
        }
    }

    fn command(self) -> Command {
        Command::new(self.path())
    }
}

/// The launcher. It demands a `SealedProof`, which only `Boot<Sealed>::exec`
/// can mint, so no code path reaches the tool-proxy before the rootfs is
/// read-only (#2589). `exec(2)` does not return on success; the error is
/// returned so `run()` can fail the boot.
fn exec_proxy(
    _sealed: SealedProof,
    spec_path: &str,
    child_env: Vec<(std::ffi::OsString, std::ffi::OsString)>,
) -> std::io::Error {
    // Article 12 record-keeping ON for the live path (EU AI Act Art. 12): every
    // guest mediation verdict is recorded as guest testimony. The host signs
    // its own broker authorizations with a key that never enters this VM. The log
    // lives on the `/run` tmpfs: writable, root-owned before the uid drop (so the
    // workload cannot tamper), and NOT under the agent workspace (which the
    // proxy's own path check would refuse). The chain is session-derived when no
    // audit secret is configured — weaker than an operator secret, but present.
    // Scoped to this child: see `child_env` above.
    attest_egress_confinement();
    // Trusted instrumentation uses the sealed guest-layer binary. It is not
    // a workload exception, and is absent from default/release builds.
    #[cfg(feature = "ci-podlist-probe")]
    if let Err(err) = GuestBin::PodlistProbe.command().spawn() {
        // Missing PASS fails the host harness; never invent a successful probe.
        eprintln!("nucleus-podlist-probe could not start: {err}");
    }

    GuestBin::Proxy
        .command()
        .arg("--spec")
        .arg(spec_path)
        .arg("--art12-log")
        .arg("/run/nucleus/art12.jsonl")
        .envs(child_env)
        .exec()
}

/// Configure the guest interface from the node's `nucleus.net=` argument.
///
/// Best effort, as it always was: a pod whose network cannot be configured still
/// has vsock, and the host fence still stands. But every failure is now said,
/// with the step that failed, where the old `let _ = Command::new("ip")` calls
/// said nothing -- and on the rootfs this repository builds there was never an
/// `ip` to run, so every pod booted with `eth0` down.
fn configure_network(config: &NetConfig) {
    #[cfg(target_os = "linux")]
    match net::configure(config) {
        Ok(()) => eprintln!(
            "network configured: {} on {}",
            config.cidr(),
            net::GUEST_IFACE
        ),
        Err(err) => eprintln!("{err}; continuing without a guest network"),
    }
    if let Some(dns) = config.dns {
        write_resolv_conf(&net::resolv_conf(dns));
    }
}

/// Write `/etc/resolv.conf`, falling back to a tmpfs copy bind-mounted over it.
///
/// A real pod's rootfs drive is read-only, so the direct write fails there. The
/// copy lives on `/run` (tmpfs, mounted before this runs) and is bound over the
/// image's file; an image with no `/etc/resolv.conf` at all gets the direct
/// write or nothing, since a bind mount needs a target.
///
/// Mode 0644 explicitly: `run()` sets umask 077, so a freshly created file would
/// be readable by root alone and the workload, which runs unprivileged, would
/// resolve nothing.
fn write_resolv_conf(body: &str) {
    const ETC_RESOLV_CONF: &str = "/etc/resolv.conf";
    let write = |path: &str| -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, body)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o644))
    };
    let direct = match write(ETC_RESOLV_CONF) {
        Ok(()) => return,
        Err(err) => err,
    };
    let fallback = Path::new(RUN_RESOLV_CONF)
        .parent()
        .map_or(Ok(()), fs::create_dir_all)
        .and_then(|()| write(RUN_RESOLV_CONF))
        .map_err(|e| e.to_string())
        .and_then(|()| {
            mount_fs(
                RUN_RESOLV_CONF,
                ETC_RESOLV_CONF,
                "none",
                MsFlags::MS_BIND,
                None,
            )
        });
    if let Err(err) = fallback {
        eprintln!("resolver not configured: {ETC_RESOLV_CONF}: {direct}; tmpfs bind: {err}");
    }
}

/// Parse a secret from kernel command line (format: key=value)
fn parse_cmdline_secret(cmdline: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    for token in cmdline.split_whitespace() {
        if let Some(value) = token.strip_prefix(&prefix)
            && !value.is_empty()
        {
            return Some(value.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    /// PID 1 runs nothing from the image: every `Command::new` in this crate
    /// is the one inside `GuestBin::command`, plus the parity test's reference
    /// tool, which runs on a developer's host and never in a guest.
    ///
    /// Driven red by putting `Command::new("ip")` back into `configure_network`.
    #[test]
    fn the_only_programs_pid1_starts_are_the_guest_layers() {
        const SOURCES: [(&str, &str); 6] = [
            ("main.rs", include_str!("main.rs")),
            ("identity.rs", include_str!("identity.rs")),
            ("lib.rs", include_str!("lib.rs")),
            ("boot.rs", include_str!("boot.rs")),
            ("net.rs", include_str!("net.rs")),
            ("fence.rs", include_str!("fence.rs")),
        ];
        // Spelled in pieces so this test's own text is not a match.
        let needle = ["Command", "::new("].concat();
        let allowed = [
            ("main.rs", format!("{needle}self.path())")),
            (
                "fence.rs",
                format!("let out = std::process::{needle}\"iptables-legacy-save\")"),
            ),
        ];
        let mut found = Vec::new();
        for (file, text) in SOURCES {
            for line in text.lines().map(str::trim) {
                if line.contains(&needle) && !line.starts_with("//") {
                    found.push((file, line.to_string()));
                }
            }
        }
        assert_eq!(
            found,
            allowed.to_vec(),
            "a new program is started from PID 1"
        );
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| n.ends_with(".rs"))
            .collect();
        on_disk.sort();
        let mut scanned: Vec<String> = SOURCES.iter().map(|(f, _)| (*f).to_string()).collect();
        scanned.sort();
        assert_eq!(on_disk, scanned, "a source file is not scanned");
    }

    #[test]
    fn is_mountpoint_root_yes_fresh_dir_no() {
        assert!(super::is_mountpoint("/"));
        let dir = std::env::temp_dir().join(format!("guest-init-mp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(!super::is_mountpoint(dir.to_str().unwrap()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// **Every guest pseudo-filesystem is hardened, and `/tmp` and `/run`
    /// especially.**
    ///
    /// All five were mounted with `MsFlags::empty()` while `/work`, the data
    /// volume a few lines below, already carried `MS_NOSUID | MS_NODEV`. The
    /// pattern was known; the pseudo-filesystems missed it.
    ///
    /// Standard microVM practice is a read-only rootfs with writable layers
    /// marked nosuid/nodev/noexec. `/tmp` and `/run` are those writable layers
    /// and the classic staging ground for a dropped payload.
    ///
    /// Runs on any host because the table stores plain bools rather than
    /// `MsFlags` — a hardening table readable only on the machine it runs on is
    /// one nobody checks.
    /// The four symlinks are exactly the ones POSIX tooling assumes, and every
    /// one points into `/proc` — which is what makes them free and what makes
    /// `/proc` a prerequisite. A fifth entry pointing somewhere else would be a
    /// device the guest does not actually have.
    #[test]
    fn the_dev_symlinks_are_the_four_posix_ones_and_all_point_into_proc() {
        let links: Vec<&str> = super::DEV_FD_SYMLINKS.iter().map(|(l, _)| *l).collect();
        assert_eq!(
            links,
            vec!["/dev/fd", "/dev/stdin", "/dev/stdout", "/dev/stderr"],
            "these four are what bash process substitution and `/dev/std*` need"
        );
        for (link, target) in super::DEV_FD_SYMLINKS {
            assert!(link.starts_with("/dev/"), "{link} is not under /dev");
            assert!(
                target.starts_with("/proc/self/fd"),
                "{target} is not a /proc path, so it would need a real device"
            );
        }
        // /proc must be mounted before these resolve, and load-bearing means the
        // boot stops if it is not. If this fires, the symlinks became dangling.
        assert!(
            super::GUEST_MOUNTS
                .iter()
                .any(|m| m.target == "/proc" && m.load_bearing),
            "/proc must be a load-bearing mount or the /dev symlinks dangle"
        );
    }

    #[test]
    fn guest_mounts_are_hardened() {
        for m in super::GUEST_MOUNTS {
            assert!(
                m.nosuid,
                "{} must be nosuid — a setuid binary dropped there is a \
                 privilege-escalation primitive",
                m.target
            );
        }

        for target in ["/tmp", "/run"] {
            let m = super::GUEST_MOUNTS
                .iter()
                .find(|m| m.target == target)
                .unwrap_or_else(|| panic!("{target} must be in the mount table"));
            assert!(
                m.nodev && m.noexec,
                "{target} is writable: needs nodev + noexec"
            );
        }

        // /dev is the device tree, so nodev would defeat its purpose. Asserted
        // rather than left implicit, so flipping it reads as a deliberate change.
        let dev = super::GUEST_MOUNTS
            .iter()
            .find(|m| m.target == "/dev")
            .unwrap();
        assert!(
            !dev.nodev,
            "/dev must permit device nodes — it is the device tree"
        );
    }

    #[test]
    fn runtime_tmpfs_is_not_workload_writable_and_shared_tmp_is_sticky() {
        for (target, options) in [("/run", "mode=0755"), ("/tmp", "mode=1777")] {
            let mount = super::GUEST_MOUNTS
                .iter()
                .find(|m| m.target == target)
                .unwrap();
            assert_eq!(
                mount.fs.data(),
                Some(options),
                "{target} must set its root directory mode"
            );
        }
    }

    /// P3d (#2696): `/proc` is mounted `hidepid=invisible`, so a workload under
    /// its own uid cannot see PID 1 (the tool-proxy, root) at all.
    ///
    /// Checked on `data()`, the value `run()` hands to `mount(2)`, not on the
    /// variant alone: dropping the option from the call is the regression.
    #[test]
    fn proc_is_mounted_with_hidepid_invisible() {
        let proc = super::GUEST_MOUNTS
            .iter()
            .find(|m| m.target == "/proc")
            .expect("/proc must be in the mount table");
        assert_eq!(proc.fs.fstype(), "proc");
        assert_eq!(
            proc.fs.data(),
            Some("hidepid=invisible"),
            "/proc without hidepid lists PID 1 to the workload and serves it \
             /proc/1/cmdline (P3 spike, section 5)"
        );
        // `subset=pid` would also hide /proc/cmdline, which guest-init itself
        // reads after this mount. See `GuestFs::data`.
        assert!(
            !proc.fs.data().unwrap_or_default().contains("subset"),
            "subset=pid hides /proc/cmdline from guest-init"
        );
    }

    /// Options belong only to filesystems whose policy requires them. In
    /// particular the procfs hidepid option must never be passed to tmpfs.
    #[test]
    fn only_configured_filesystems_carry_mount_data() {
        for m in super::GUEST_MOUNTS {
            let configured = matches!(
                m.fs,
                super::GuestFs::Proc { .. } | super::GuestFs::Tmpfs { .. }
            );
            assert_eq!(
                m.fs.data().is_some(),
                configured,
                "{} ({}) has unexpected mount data {:?}",
                m.target,
                m.fs.fstype(),
                m.fs.data()
            );
        }
    }

    use super::*;

    #[test]
    fn parse_sandbox_token_from_cmdline() {
        let cmdline = "console=ttyS0 reboot=k nucleus.auth_secret=auth123 nucleus.approval_secret=appr456 nucleus.sandbox_token=sbx789";
        assert_eq!(
            parse_cmdline_secret(cmdline, "nucleus.sandbox_token"),
            Some("sbx789".to_string())
        );
    }

    #[test]
    fn parse_sandbox_token_missing() {
        let cmdline = "console=ttyS0 nucleus.auth_secret=auth123";
        assert_eq!(parse_cmdline_secret(cmdline, "nucleus.sandbox_token"), None);
    }

    #[test]
    fn parse_sandbox_token_empty_value() {
        let cmdline = "nucleus.sandbox_token=";
        assert_eq!(parse_cmdline_secret(cmdline, "nucleus.sandbox_token"), None);
    }

    /// The live-path token rides the cmdline hex-encoded; decoding it back must
    /// reproduce the EXACT JSON string the tool-proxy verify half parses. JSON
    /// contains `{`, `"`, `:`, `,` — all cmdline-hostile — which is why it is
    /// hex-wrapped; this asserts the wrapper round-trips losslessly and that the
    /// hex token is a single whitespace-delimited cmdline argument.
    #[test]
    fn task_token_hex_roundtrips_to_exact_json() {
        let token_json = r#"{"task_id":"pod-1","blocks":[{"claim":{"nonce":[1,2,3]}}]}"#;
        let token_hex = hex::encode(token_json.as_bytes());
        let nonce_hex = hex::encode([7u8; 16]);
        let issuer_hex = hex::encode([9u8; 32]);
        let cmdline = format!(
            "console=ttyS0 nucleus.auth_secret=a nucleus.task_token_hex={token_hex} \
             nucleus.task_token_nonce={nonce_hex} nucleus.task_token_issuer={issuer_hex}"
        );

        let parsed_hex = parse_cmdline_secret(&cmdline, "nucleus.task_token_hex")
            .expect("hex token must parse as a single cmdline arg");
        let decoded = String::from_utf8(hex::decode(&parsed_hex).unwrap()).unwrap();
        assert_eq!(
            decoded, token_json,
            "hex must decode back to the exact JSON"
        );

        assert_eq!(
            parse_cmdline_secret(&cmdline, "nucleus.task_token_nonce"),
            Some(nonce_hex)
        );
        assert_eq!(
            parse_cmdline_secret(&cmdline, "nucleus.task_token_issuer"),
            Some(issuer_hex)
        );
    }
}
