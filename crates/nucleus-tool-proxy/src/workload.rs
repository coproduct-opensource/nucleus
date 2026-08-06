//! Running a workload inside the pod, under the pod's own mediation.
//!
//! # The ordering is the guarantee
//!
//! A workload's entire value here is that every effect it attempts goes through
//! the kernel. If it started alongside the proxy — from the boot process, say —
//! there would be a window in which it is running and mediation is not, and
//! anything it did in that window would be both unmediated and unrecorded. The
//! window is short, which is exactly what makes it the kind of defect nobody
//! notices.
//!
//! So the proxy spawns the workload itself, after its listener is bound and its
//! sink chain is live. `spawn_workload` cannot be called before that, because it
//! takes the bound address as an argument — the address does not exist until the
//! server is up, so the ordering is a property of the signature rather than of
//! remembering.
//!
//! # Nucleus does not know what it is running
//!
//! `command`, `args` and `env` are opaque. A vendor-aware orchestrator supplies
//! the binary, its credentials through `credentials.env`, and any endpoint it
//! needs on the network allowlist. Nothing vendor-specific belongs here.

use std::collections::BTreeMap;

use nucleus_ifc_kernel::extracted::identity::{
    ident_may_deliver, mat_label, MaterialKind, Principal,
};
use nucleus_ifc_kernel::extracted::ifc_confidentiality::ConfLevel;
use nucleus_spec::WorkloadSpec;

/// Classify an environment-variable NAME as the identity-material kind the
/// extracted FM-5 model reasons about.
///
/// **This is the trusted half of the boundary, and it is trusted for a reason
/// Aeneas cannot change:** a `&str` is an opaque byte slice to Charon, so a
/// name→kind function cannot be extracted or proved. The *decision* it feeds —
/// `ident_may_deliver(kind, Workload)` — is extracted and carries ten theorems;
/// this map is pinned instead by the dual-classifier corpus test, which asserts
/// an independently-written oracle agrees with it over an enumerated key set.
///
/// The `_ => OrdinaryData` fallthrough is the one place a NEW secret hides: a
/// `NUCLEUS_*` variable added to the overlay without a case here would be
/// classified public and admitted. The corpus test exists to catch exactly
/// that, which is why it enumerates the `NUCLEUS_*` namespace rather than a
/// sample.
pub(crate) use nucleus_ifc_kernel::env_classifier::env_key_material;

/// Where an admitted env entry came from — kept in the launch receipt so an
/// auditor can see not just what crossed but why it was allowed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EnvSource {
    /// One of `INHERITED_BY_NAME`, taken from the runtime's own environment.
    InheritedByName,
    /// From the operator-written `spec.env`.
    SpecEnv,
    /// Injected by the runtime (the proxy URL and the workload's own HMAC).
    RuntimeInjected,
    /// An egress forwarder name/URL from `workload_egress_env`.
    Egress,
}

/// One classified environment entry: the name, the material kind the classifier
/// assigned, its confidentiality label, and its source. **Never the value.**
#[derive(Debug, Clone)]
pub(crate) struct ClassifiedEntry {
    pub(crate) key: String,
    pub(crate) material: MaterialKind,
    pub(crate) label: ConfLevel,
    pub(crate) source: EnvSource,
}

/// Attribute an env key to its source, given the spec that produced the overlay.
///
/// `workload_env` makes the runtime-injected pair win over `spec.env`, so a key
/// that is one of that pair is `RuntimeInjected` regardless of whether the spec
/// also named it — which is the correct attribution: the value that crossed is
/// the runtime's.
fn env_source(key: &str, spec: &WorkloadSpec) -> EnvSource {
    if key == "NUCLEUS_TOOL_PROXY_URL" || key == "NUCLEUS_TOOL_PROXY_AUTH_SECRET" {
        EnvSource::RuntimeInjected
    } else if key.starts_with("NUCLEUS_EGRESS_") {
        EnvSource::Egress
    } else if INHERITED_BY_NAME.contains(&key) {
        EnvSource::InheritedByName
    } else if spec.env.contains_key(key) {
        EnvSource::SpecEnv
    } else {
        // Not from any known channel — should be impossible, since `workload_env`
        // produces only these. Recorded as `SpecEnv` conservatively; the
        // admission check below runs on it regardless.
        EnvSource::SpecEnv
    }
}

/// The environment a workload is started with.
///
/// Split out as a pure function so the precedence below is testable without
/// spawning anything.
///
/// # Runtime variables win
///
/// The spec's `env` is merged UNDER the injected values. A spec that sets
/// `NUCLEUS_TOOL_PROXY_URL` itself would otherwise point its workload at some
/// other endpoint — mediating nothing while looking mediated — and a pod spec is
/// not necessarily written by the same party that owns the policy.
/// The only variables a workload inherits from the runtime, by name.
///
/// Deliberately tiny, and deliberately a list rather than a filter: a
/// deny-list of secret-looking names fails the moment somebody adds a secret
/// whose name does not look like one, which is exactly how the broker
/// capability got through in the first place.
///
/// Everything else a workload needs goes in `spec.env`, where an operator wrote
/// it down. `PATH` is here because a command resolved without one fails in a way
/// that looks like a missing binary rather than a missing variable; `HOME`,
/// `LANG` and `TZ` because tools misbehave in confusing ways without them and
/// none of the three can carry authority.
pub(crate) const INHERITED_BY_NAME: [&str; 4] = ["PATH", "HOME", "LANG", "TZ"];

#[must_use]
pub(crate) fn workload_env(
    spec: &WorkloadSpec,
    proxy_url: &str,
    auth_secret: &str,
    egress: &[nucleus_spec::CredentialedEgressSpec],
) -> BTreeMap<String, String> {
    let mut env = spec.env.clone();
    // Local forwarder addresses for each credentialed upstream. Names and URLs
    // only — the credential stays in the runtime, which is the point.
    env.extend(crate::egress::workload_egress_env(egress, proxy_url));
    env.insert("NUCLEUS_TOOL_PROXY_URL".to_string(), proxy_url.to_string());
    env.insert(
        "NUCLEUS_TOOL_PROXY_AUTH_SECRET".to_string(),
        auth_secret.to_string(),
    );
    env
}

/// A workload launch whose every environment entry has been classified against
/// the extracted FM-5 delivery relation and admitted. **The only value
/// [`spawn_admitted`] will spawn**, and constructible only by
/// [`WorkloadLaunch::admit`].
///
/// Affine, redacting, and scope-bound, following the `BrokerCapability` and
/// `DischargedBundle` precedents:
/// - `#[must_use]` — a plan admitted and never spawned is a workload that was
///   cleared to run and then dropped, which an operator should never do silently.
/// - not `Clone`/`Copy` — the classified inventory it carries is the exact data
///   the receipt is built from; copying it would let one admission back two
///   different launches.
/// - private fields, no public constructor — the env map inside was admitted by
///   `admit` and cannot be swapped for another after the check, which is the
///   confused-deputy remedy `DischargedBundle` added its scope binding for.
#[must_use = "an AdmittedWorkloadPlan that is never spawned is a workload that was admitted and not run"]
pub(crate) struct AdmittedWorkloadPlan {
    command: String,
    args: Vec<String>,
    work_dir: std::path::PathBuf,
    uid: Option<u32>,
    /// The exact env that will cross, already admitted. Paired with `classified`
    /// so the receipt reports the same set the admission checked.
    env: BTreeMap<String, String>,
    classified: Vec<ClassifiedEntry>,
}

// The plan carries secret VALUES in `env`; never let them reach a log via Debug.
impl std::fmt::Debug for AdmittedWorkloadPlan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdmittedWorkloadPlan")
            .field("command", &self.command)
            .field("env_entries", &self.classified.len())
            .field("uid", &self.uid)
            .finish_non_exhaustive()
    }
}

/// A workload the runtime declined to launch, with the reason.
#[derive(Debug)]
pub(crate) struct Refused(pub(crate) String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Build a launch from a spec and the runtime's mediation coordinates, then
/// admit it. Splitting `build`/`admit` from `spawn_admitted` is what makes the
/// admission a value: a plan cannot be spawned without having been admitted,
/// because [`spawn_admitted`] takes an [`AdmittedWorkloadPlan`] and only
/// [`WorkloadLaunch::admit`] produces one.
pub(crate) struct WorkloadLaunch {
    command: String,
    args: Vec<String>,
    work_dir: std::path::PathBuf,
    uid: Option<u32>,
    env: BTreeMap<String, String>,
    classified: Vec<ClassifiedEntry>,
    /// Whether credentialed egress is configured — folded in here so the uid
    /// coupling that used to live 300 lines away is a field of the thing being
    /// admitted, not an adjacent call a caller can forget.
    has_credentialed_egress: bool,
}

impl WorkloadLaunch {
    /// Assemble and classify. Takes the same inputs the old `spawn_workload`
    /// did; the env is produced by the pinned [`workload_env`] so the binding
    /// tests still describe the one env-assembly point.
    pub(crate) fn build(
        spec: &WorkloadSpec,
        proxy_url: &str,
        auth_secret: &str,
        work_dir: &std::path::Path,
        egress: &[nucleus_spec::CredentialedEgressSpec],
    ) -> Self {
        // Start from the by-name inheritance (resolved from the runtime's own
        // environment), then let `workload_env` win over it — the same
        // precedence the old `spawn_workload` applied by ordering its two loops.
        // Folding them together here means every entry the child gets, including
        // the inherited ones, is classified and admitted below.
        let mut env: BTreeMap<String, String> = BTreeMap::new();
        for key in INHERITED_BY_NAME {
            if let Ok(value) = std::env::var(key) {
                env.insert(key.to_string(), value);
            }
        }
        env.extend(workload_env(spec, proxy_url, auth_secret, egress));
        let classified = env
            .keys()
            .map(|key| {
                let material = env_key_material(key);
                ClassifiedEntry {
                    key: key.clone(),
                    material,
                    label: mat_label(material),
                    source: env_source(key, spec),
                }
            })
            .collect();
        Self {
            command: spec.command.clone(),
            args: spec.args.clone(),
            work_dir: work_dir.to_path_buf(),
            uid: spec.uid,
            env,
            classified,
            has_credentialed_egress: !egress.is_empty(),
        }
    }

    /// Admit the launch: every classified entry must be deliverable to the
    /// workload under the extracted relation, and the credentialed-egress uid
    /// coupling must hold. Refusal is fatal to the pod by the caller's choice.
    ///
    /// The admission check IS `ident_may_deliver(kind, Workload)` — the same
    /// function the FM-5 theorems are proven over. A `Secret`-labelled entry
    /// reaching this point is refused here rather than trusted to have been kept
    /// out upstream.
    pub(crate) fn admit(self) -> Result<AdmittedWorkloadPlan, Refused> {
        // The uid coupling, folded in from `reject_credential_readable_workload`.
        if self.has_credentialed_egress {
            match self.uid {
                Some(uid) if uid != nix_getuid() => {}
                Some(uid) => {
                    return Err(Refused(format!(
                        "the workload's uid ({uid}) is the runtime's own, so it can read the \
                         runtime's environment via /proc and obtain the credentialed-egress \
                         secret. Give the workload a distinct unprivileged uid."
                    )));
                }
                None => {
                    return Err(Refused(
                        "credentialed egress is configured but the workload has no `uid`, so it \
                         runs as the runtime's user and can read the credential from \
                         /proc/<pid>/environ. Set `workload.uid` to a distinct unprivileged uid."
                            .to_string(),
                    ));
                }
            }
        }

        // Every entry must be admissible to the workload under the proved
        // relation. This is the structural form of FM-5: not "we kept identity
        // material out", but "nothing that was not admitted can cross, because
        // the only spawn consumes a plan and the plan is only built here".
        for entry in &self.classified {
            if !ident_may_deliver(entry.material, Principal::Workload) {
                return Err(Refused(format!(
                    "environment variable `{}` classifies as {:?} ({:?}), which the FM-5 \
                     delivery relation refuses to the workload. It must not be placed on the \
                     workload's environment.",
                    entry.key, entry.material, entry.label
                )));
            }
        }

        Ok(AdmittedWorkloadPlan {
            command: self.command,
            args: self.args,
            work_dir: self.work_dir,
            uid: self.uid,
            env: self.env,
            classified: self.classified,
        })
    }
}

/// Spawn an admitted plan. **The only `Command::new` in the crate** — the
/// mediation gate's allowlist names this one line, so a second spawn anywhere in
/// the tool-proxy fails the build.
///
/// Returns the child AND a [`LaunchReceipt`] so "spawned without a receipt" is
/// unrepresentable, the way `start_if_configured` taking a `SocketAddr` makes
/// "spawned before mediation" unrepresentable.
///
/// # Errors
/// If the process cannot be started.
pub(crate) fn spawn_admitted(
    plan: AdmittedWorkloadPlan,
) -> std::io::Result<(tokio::process::Child, LaunchReceipt)> {
    let mut cmd = tokio::process::Command::new(&plan.command);
    cmd.args(&plan.args)
        .current_dir(&plan.work_dir)
        .kill_on_drop(true);

    // The environment is DECLARED, never inherited. `Command` passes the
    // parent's environment to the child unless told otherwise; the proxy's
    // environment holds the broker capability and every other identity value.
    // `env_clear` first, then only the admitted map (which already includes the
    // INHERITED_BY_NAME values, resolved in `WorkloadLaunch::build`).
    cmd.env_clear();
    for (k, v) in &plan.env {
        cmd.env(k, v);
    }

    // Stdio is DECLARED too. Inherited stdio was the quiet twin of inherited
    // env: stdin came from the node's controlling terminal, and stdout/stderr
    // wrote raw into the operator-facing pod log, unattributed. `null` stdin
    // (the workload has no console to read) and piped stdout/stderr (the proxy
    // captures and attributes them) close both.
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    // The privilege boundary is DECLARED on the Command, because std applies it
    // in the right window: `do_exec` runs setgid, the supplementary-group drop
    // (setgroups(0, NULL) — automatic when a uid is set, the parent is root,
    // and no explicit groups were given), and setuid BEFORE the `pre_exec`
    // closures (std/src/sys/process/unix/unix.rs). `gid` is set alongside `uid`
    // so the child does not keep the runtime's primary gid (root's 0 in the
    // guest) after its uid dropped. The run-5 boot proved the ordering the hard
    // way: a hook that tried setgroups itself ran as the ALREADY-dropped uid
    // and got EPERM.
    let hardened = plan.uid.is_some();
    if let Some(uid) = plan.uid {
        cmd.uid(uid);
        cmd.gid(uid);
    }
    // The async-signal-safe hardening hook, ALWAYS installed. It marks every
    // inherited fd above 0/1/2 close-on-exec (`close_range(..CLOEXEC)`) so
    // "only the child's own stdio crosses the exec" is true BY CONSTRUCTION,
    // not by trusting that every fd the parent holds happens to be CLOEXEC —
    // the runc CVE-2024-21626 lesson. When a uid is set it additionally applies
    // no_new_privs and rlimits — the self-restrictions an unprivileged process
    // may still make. Runs AFTER std's stdio dup2 and privilege drop.
    harden::apply(&mut cmd, plan.uid);

    tracing::info!(
        command = %plan.command,
        env_entries = plan.classified.len(),
        "starting pod workload under mediation (admitted)"
    );
    let child = cmd.spawn()?;
    let receipt = LaunchReceipt::from_admitted(&plan, hardened, child.id());
    Ok((child, receipt))
}

/// The async-signal-safe child-side hardening hook. Local to the tool-proxy
/// because `nucleus::HostSandbox` is `pub(crate)` to its own crate and does not
/// bound descriptors or rlimits this way. Mirrors that module's
/// audited-exception pattern: two `unsafe` blocks (the syscall sequence and the
/// `pre_exec` install), every call is async-signal-safe, and any `Err` fails
/// the spawn (fail-closed — the child never execs).
///
/// The privileged drops (setgid, setgroups, setuid) are NOT here: std's
/// `do_exec` performs them from `.uid()`/`.gid()` BEFORE the `pre_exec`
/// closures run, so this hook already executes as the dropped uid and may only
/// do what an unprivileged process can do to itself.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod harden {
    use std::io;

    const RLIMIT_NPROC_MAX: libc::rlim_t = 512;
    const RLIMIT_NOFILE_MAX: libc::rlim_t = 4096;
    const RLIMIT_FSIZE_MAX: libc::rlim_t = 8 * 1024 * 1024 * 1024; // 8 GiB
    const RLIMIT_CPU_SECS: libc::rlim_t = 3600;

    #[cfg(target_env = "gnu")]
    type RlimitResource = libc::__rlimit_resource_t;
    #[cfg(not(target_env = "gnu"))]
    type RlimitResource = libc::c_int;

    fn rlimit(limit: libc::rlim_t) -> libc::rlimit {
        libc::rlimit {
            rlim_cur: limit,
            rlim_max: limit,
        }
    }

    /// `CLOSE_RANGE_CLOEXEC` from uapi `linux/close_range.h` (kernel ≥ 5.11):
    /// mark the range close-on-exec instead of closing it now. Local constant
    /// because the `libc` crate's binding availability varies by target.
    const CLOSE_RANGE_CLOEXEC: libc::c_long = 1 << 2;

    /// Runs after fork, before exec. MUST be async-signal-safe: raw syscalls
    /// only, no allocation, no locks.
    ///
    /// Always condemns inherited fds above 2 (close-on-exec at the exec
    /// boundary); applies the unprivileged self-restrictions (no_new_privs,
    /// rlimits) when a uid is requested. One `unsafe` block for the whole
    /// sequence, deliberately: every call in it is a well-known
    /// async-signal-safe FFI syscall, and consolidating them keeps the crate's
    /// unsafe surface minimal (the exemplar `unsafe_blocks` ratchet).
    fn harden_child(uid: Option<u32>) -> io::Result<()> {
        // SAFETY: every call below is an async-signal-safe libc syscall taking
        // scalars or a pointer to a fully-initialized local `rlimit`; none
        // allocates or takes a lock, satisfying the `pre_exec` contract. A
        // `!= 0` return is an error and fails the spawn (fail-closed).
        unsafe {
            // Mark every fd from 3 up close-on-exec rather than closing it
            // HERE. This hook runs between fork and exec, a window in which
            // std still owns an internal CLOEXEC status pipe the child uses to
            // report a failed later step (or a failed exec) back to the
            // parent. Closing fds now severed that pipe, and when a later step
            // failed the child could only abort — the run-5 boot's
            // `fatal runtime error: assertion failed:
            // output.write(&bytes).is_ok()` (std unix.rs, the CLOEXEC-pipe
            // write) — an unreportable crash in place of a spawn error.
            // CLOSE_RANGE_CLOEXEC yields the identical post-exec closure —
            // nothing above 2 survives the exec — while leaving the pipe
            // usable before it (it is already CLOEXEC; re-flagging is a
            // no-op).
            //
            // Invoked as the raw `close_range` syscall, not
            // `libc::close_range`, because the latter is a glibc-only wrapper
            // in the `libc` crate and the guest rootfs is musl. ENOSYS
            // (pre-5.9, no syscall) is tolerated — std marks everything it
            // creates CLOEXEC, the fallback there. EINVAL (5.9–5.10: syscall
            // exists, flag does not) falls back to closing outright, accepting
            // the unreportable-failure trap on those kernels only; the pinned
            // guest kernel is newer. Any other error fails the spawn.
            if libc::syscall(
                libc::SYS_close_range,
                3 as libc::c_long,
                libc::c_uint::MAX as libc::c_long,
                CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                let err = io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::ENOSYS) => {}
                    Some(libc::EINVAL) => {
                        if libc::syscall(
                            libc::SYS_close_range,
                            3 as libc::c_long,
                            libc::c_uint::MAX as libc::c_long,
                            0 as libc::c_long,
                        ) != 0
                        {
                            let err = io::Error::last_os_error();
                            if err.raw_os_error() != Some(libc::ENOSYS) {
                                return Err(err);
                            }
                        }
                    }
                    _ => return Err(err),
                }
            }
            if uid.is_some() {
                // The child ALREADY runs as the dropped uid/gid here — std's
                // `do_exec` applied setgid, the supplementary-group drop, and
                // setuid before any `pre_exec` closure (see the declarations
                // on the Command in `spawn_admitted`). Attempting
                // setgroups/setgid at this point fails with EPERM, which is
                // exactly how the run-5 boot failed. What remains is what an
                // unprivileged process may do to itself:
                // No new privileges: defeats setuid/file-capability escalation.
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                for (resource, max) in [
                    (libc::RLIMIT_NPROC, RLIMIT_NPROC_MAX),
                    (libc::RLIMIT_NOFILE, RLIMIT_NOFILE_MAX),
                    (libc::RLIMIT_FSIZE, RLIMIT_FSIZE_MAX),
                    (libc::RLIMIT_CPU, RLIMIT_CPU_SECS),
                ] {
                    let rl = rlimit(max);
                    if libc::setrlimit(resource as RlimitResource, &rl) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
            }
        }
        Ok(())
    }

    pub(super) fn apply(cmd: &mut tokio::process::Command, uid: Option<u32>) {
        // SAFETY: `harden_child` only invokes async-signal-safe syscalls and
        // does not allocate.
        unsafe {
            cmd.pre_exec(move || harden_child(uid));
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod harden {
    pub(super) fn apply(_cmd: &mut tokio::process::Command, _uid: Option<u32>) {
        // No procfs / no CommandExt uid semantics off Linux; the guest is Linux.
    }
}

/// Refuse a pod that withholds a credential from a workload that could read it.
///
/// # Not a warning
///
/// `credentialed_egress` keeps the credential out of the workload's environment.
/// That achieves nothing if the workload runs as the runtime's user: Linux lets
/// same-uid processes read `/proc/<pid>/environ`, so the workload reads the
/// runtime's environment and takes it. The whole feature would be a comment.
///
/// So the two are coupled: configure credentialed egress and the workload MUST
/// have a distinct uid, or the pod does not start. A guarantee that holds only
/// when someone remembers a second setting is not one.
///
/// # Errors
/// When credentialed egress is configured and the workload shares the runtime's uid.
pub(crate) fn reject_credential_readable_workload(
    workload: Option<&WorkloadSpec>,
    egress: &[nucleus_spec::CredentialedEgressSpec],
) -> Result<(), String> {
    if egress.is_empty() {
        return Ok(());
    }
    let Some(w) = workload else {
        return Ok(());
    };
    match w.uid {
        Some(uid) if uid != nix_getuid() => Ok(()),
        Some(uid) => Err(format!(
            "the workload's uid ({uid}) is the runtime's own, so it can read the runtime's \
             environment via /proc and obtain the credentialed-egress secret. Give the workload a \
             distinct unprivileged uid."
        )),
        None => Err(
            "credentialed egress is configured but the workload has no `uid`, so it runs as the \
             runtime's user and can read the credential from /proc/<pid>/environ. Set \
             `workload.uid` to a distinct unprivileged uid."
                .to_string(),
        ),
    }
}

/// The runtime's own uid.
///
/// Read from the environment of the running process via `std`, so this needs no
/// new dependency — a credential-adjacent control is a poor place to widen the
/// dependency surface, and the LiteLLM compromise is the reminder why.
fn nix_getuid() -> u32 {
    std::os::unix::fs::MetadataExt::uid(&std::fs::metadata("/proc/self").unwrap_or_else(|_| {
        // Not Linux, or no procfs. Fall back to a value that cannot equal a
        // configured uid, so the check errs toward ACCEPTING an explicit
        // distinct uid rather than refusing every pod on a platform where it
        // cannot verify. The Linux guest is where this matters.
        std::fs::metadata(".").expect("cwd always stat-able")
    }))
}

/// A tamper-evident record of exactly what authority a workload launch handed
/// the child — the "resulting authority inventory". Modeled on
/// `portcullis::art12_record::Art12Record`: a schema version, a canonical
/// preimage joined with `|` (never `serde_json`, whose key order is unstable),
/// and a self-hash. Emitted by [`spawn_admitted`] and returned rather than
/// logged beside the spawn, so a launch without a receipt cannot happen.
///
/// It answers, without any other artifact: what environment crossed and why it
/// was allowed to (kind, label, source — never the value), what stdio the child
/// got, and what the uid boundary was.
#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct LaunchReceipt {
    pub(crate) schema_version: u32,
    /// The classified environment inventory. Never carries values.
    pub(crate) env: Vec<ReceiptEnvEntry>,
    /// stdin/stdout/stderr dispositions as set by `spawn_admitted`.
    pub(crate) stdio: [&'static str; 3],
    /// The uid boundary, three-valued so "no boundary" and "boundary not
    /// required" stay distinct (the `nucleus.dlc_admission` unarmed-vs-refused
    /// lesson): `distinct` (a uid different from the runtime's), `unset` (none).
    pub(crate) uid_boundary: &'static str,
    /// Whether the async-signal-safe hardening hook (groups dropped, gid set,
    /// no_new_privs, rlimits) was applied.
    pub(crate) hardened: bool,
    pub(crate) argv_len: usize,
    pub(crate) child_pid: Option<u32>,
    /// SHA-256 of the canonical preimage below, hex. Anchors the record.
    pub(crate) hash: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ReceiptEnvEntry {
    pub(crate) key: String,
    pub(crate) material: String,
    pub(crate) label: String,
    pub(crate) source: EnvSource,
}

impl LaunchReceipt {
    const SCHEMA_VERSION: u32 = 1;

    fn from_admitted(plan: &AdmittedWorkloadPlan, hardened: bool, child_pid: Option<u32>) -> Self {
        let env: Vec<ReceiptEnvEntry> = plan
            .classified
            .iter()
            .map(|c| ReceiptEnvEntry {
                key: c.key.clone(),
                material: format!("{:?}", c.material),
                label: format!("{:?}", c.label),
                source: c.source,
            })
            .collect();
        let stdio = ["null", "piped", "piped"];
        let uid_boundary = match plan.uid {
            Some(_) => "distinct",
            None => "unset",
        };
        let argv_len = plan.args.len();
        // Canonical preimage: field-ordered, `|`-joined, values excluded.
        // Reconstructed from the record's own fields, not serialized, so key
        // order and escaping cannot drift the hash.
        let mut preimage = format!(
            "v{}|cmd={}|argv={argv_len}|stdio={}|uid={uid_boundary}|hardened={hardened}",
            Self::SCHEMA_VERSION,
            plan.command,
            stdio.join(","),
        );
        for e in &env {
            preimage.push_str(&format!(
                "|env={}:{}:{}:{:?}",
                e.key, e.material, e.label, e.source
            ));
        }
        let hash = {
            use sha2::{Digest, Sha256};
            let digest = Sha256::digest(preimage.as_bytes());
            hex::encode(digest)
        };
        Self {
            schema_version: Self::SCHEMA_VERSION,
            env,
            stdio,
            uid_boundary,
            hardened,
            argv_len,
            child_pid,
            hash,
        }
    }

    /// Whether the inventory carries at least one `Internal`-labelled entry.
    ///
    /// **Non-vacuity by construction.** A workload admitted with a wholly
    /// `Public` environment is a broken pod, not a maximally secure one: it has
    /// no proxy HMAC and cannot reach the one policed interface. A receipt that
    /// cannot show its one legitimately-`Internal` entry is describing a launch
    /// that will not work, and the caller treats an empty-of-Internal inventory
    /// as a refusal rather than a success.
    pub(crate) fn carries_internal_entry(&self) -> bool {
        self.env.iter().any(|e| e.label == "Internal")
    }
}

/// Where the proxy's bound listener actually is — the value the workload's
/// `NUCLEUS_TOOL_PROXY_URL` is derived from.
///
/// An enum over the two transports the proxy serves on, because the vsock path
/// — the in-guest case, where the phase-2b boot gate runs — has no TCP
/// `SocketAddr` to point at. Each variant is built from a listener's LOCAL
/// address after bind, which preserves the ordering property the old
/// `SocketAddr` parameter carried: the workload starts only once its proxy's
/// socket exists.
pub(crate) enum BoundProxy {
    /// The host/TCP path: `TcpListener::local_addr()`.
    Tcp(std::net::SocketAddr),
    /// The in-guest path: the vsock listener's local `(cid, port)`. An in-guest
    /// client speaks vsock, not TCP, so the URL is `vsock://cid:port` — the
    /// same form the announce file uses.
    Vsock { cid: u32, port: u32 },
}

impl BoundProxy {
    fn url(&self) -> String {
        match self {
            Self::Tcp(addr) => format!("http://{addr}"),
            Self::Vsock { cid, port } => format!("vsock://{cid}:{port}"),
        }
    }
}

/// Start the pod's workload if the spec asks for one.
///
/// Called AFTER the listener is bound: it takes a [`BoundProxy`], whose variants
/// are built from a bound listener's local address — which does not exist until
/// the server socket is up — so the ordering is a property of the signature.
/// The returned handle must be held for the process lifetime —
/// `kill_on_drop` means dropping it kills the workload, which is the correct
/// coupling between a pod and the thing it exists to run.
///
/// Lives here rather than in `main` so the fatal-on-failure decision sits beside
/// the reasoning for it: a pod that was asked to run a workload and did not is
/// not a working pod, and returning success leaves an operator waiting for
/// output that never comes.
///
/// Returns the child AND its launch receipt. The whole path — build, admit,
/// spawn — is the only way to a workload child, and each step is a value the
/// next consumes, so none can be skipped.
///
/// # Errors
/// If a workload is configured and cannot be admitted or started.
pub(crate) fn start_if_configured(
    spec: &nucleus_spec::PodSpec,
    bound: BoundProxy,
    auth_secret: &str,
) -> Result<Option<(tokio::process::Child, LaunchReceipt)>, crate::ApiError> {
    let Some(w) = spec.spec.workload.as_ref() else {
        return Ok(None);
    };
    let url = bound.url();
    let plan = WorkloadLaunch::build(
        w,
        &url,
        auth_secret,
        &spec.spec.work_dir,
        &spec.spec.credentialed_egress,
    )
    .admit()
    .map_err(|e| {
        crate::ApiError::Spec(format!("refused to launch workload {:?}: {e}", w.command))
    })?;

    let (child, receipt) = spawn_admitted(plan).map_err(|e| {
        crate::ApiError::Spec(format!("failed to start workload {:?}: {e}", w.command))
    })?;

    if !receipt.carries_internal_entry() {
        // Non-vacuity: a workload with no Internal-labelled entry has no proxy
        // HMAC and cannot reach the mediated interface. Refuse rather than run a
        // pod that will fail opaquely later.
        let _ = child; // dropped → kill_on_drop stops it
        return Err(crate::ApiError::Spec(format!(
            "workload {:?} was admitted with a wholly public environment — no proxy \
             credential, so it cannot reach the mediated interface. This is a broken \
             launch, not a secure one.",
            w.command
        )));
    }

    tracing::info!(
        launch_receipt = %serde_json::to_string(&receipt).unwrap_or_default(),
        "workload launch receipt"
    );
    Ok(Some((child, receipt)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_with(env: &[(&str, &str)]) -> WorkloadSpec {
        WorkloadSpec {
            command: "agent".into(),
            args: vec!["--flag".into()],
            uid: None,
            env: env
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }
    }

    /// The workload is told where its mediating proxy is. Without this it has no
    /// way to reach the only interface that is policed.
    #[test]
    fn the_workload_is_pointed_at_the_proxy() {
        let env = workload_env(&spec_with(&[]), "http://127.0.0.1:8080", "s3cret", &[]);
        assert_eq!(
            env.get("NUCLEUS_TOOL_PROXY_URL").map(String::as_str),
            Some("http://127.0.0.1:8080")
        );
        assert_eq!(
            env.get("NUCLEUS_TOOL_PROXY_AUTH_SECRET")
                .map(String::as_str),
            Some("s3cret")
        );
    }

    /// **A spec cannot redirect its workload away from mediation.** Setting the
    /// proxy URL in `env` would otherwise point the agent at an endpoint that
    /// polices nothing, while every dashboard still says "mediated".
    #[test]
    fn a_spec_cannot_override_the_proxy_url() {
        let hostile = spec_with(&[
            ("NUCLEUS_TOOL_PROXY_URL", "http://attacker.invalid"),
            ("NUCLEUS_TOOL_PROXY_AUTH_SECRET", "not-the-real-one"),
        ]);
        let env = workload_env(&hostile, "http://127.0.0.1:8080", "s3cret", &[]);
        assert_eq!(
            env.get("NUCLEUS_TOOL_PROXY_URL").map(String::as_str),
            Some("http://127.0.0.1:8080"),
            "the runtime's proxy URL must win over anything the spec asks for"
        );
        assert_eq!(
            env.get("NUCLEUS_TOOL_PROXY_AUTH_SECRET")
                .map(String::as_str),
            Some("s3cret")
        );
    }

    /// **The capability does not reach a real child.** This is the property; the
    /// map-level test above is a necessary half of it.
    ///
    /// Spawns an actual process and reads the environment it actually got,
    /// because the defect this covers lives entirely in the gap between the map
    /// and the child: `Command` inherits the parent's environment, the proxy's
    /// environment holds the capability, and no amount of checking the overlay
    /// map can see that.
    #[tokio::test]
    async fn the_spawned_child_does_not_inherit_the_capability() {
        // Put the capability in THIS process's environment, exactly as
        // `guest-init` puts it in the proxy's before exec.
        std::env::set_var("NUCLEUS_TOOL_PROXY_BROKER_SECRET", "leaked-capability");
        std::env::set_var("NUCLEUS_TOOL_PROXY_BROKER_PORT", "1027");

        let dir = tempfile::tempdir().expect("tempdir");
        let f_env = dir.path().join("child.env");
        let f_fd = dir.path().join("child.fd");
        // The child dumps its inherited surface to FILES, not stdout: the point
        // is what the child actually GOT, and reading it back from disk avoids
        // any coupling to how the parent wired the pipes. The env dump caught the
        // original vacuity bug; the fd dump pins the "only 0/1/2 cross"
        // assumption that today rests entirely on std's implicit CLOEXEC and is
        // asserted nowhere else.
        let script = format!(
            "env > {}; ls /proc/self/fd > {} 2>/dev/null || true",
            f_env.display(),
            f_fd.display(),
        );
        let spec = WorkloadSpec {
            command: "/bin/sh".into(),
            args: vec!["-c".into(), script],
            uid: None,
            env: std::collections::BTreeMap::new(),
        };
        // Through the real path: build → admit → spawn_admitted. A plan that did
        // not classify-and-admit every entry could not be constructed.
        let plan = WorkloadLaunch::build(&spec, "http://127.0.0.1:8080", "s3cret", dir.path(), &[])
            .admit()
            .expect("a clean spec must admit");
        let (mut child, receipt) = spawn_admitted(plan).expect("sh must be spawnable");
        let status = child.wait().await.expect("child ran");
        assert!(status.success(), "the child must actually run: {status:?}");
        let observed = std::fs::read_to_string(&f_env).expect("the child wrote its environment");

        std::env::remove_var("NUCLEUS_TOOL_PROXY_BROKER_SECRET");
        std::env::remove_var("NUCLEUS_TOOL_PROXY_BROKER_PORT");

        assert!(
            !observed.contains("leaked-capability"),
            "the workload inherited the broker capability from the proxy's environment. \
             It can now sign broker frames directly, which is exactly what the capability \
             exists to prevent. Child environment was:\n{observed}"
        );
        assert!(
            !observed.contains("NUCLEUS_TOOL_PROXY_BROKER_PORT"),
            "the workload was told where the broker listens:\n{observed}"
        );

        // **The non-vacuity control.** A child with an EMPTY environment would
        // satisfy every assertion above while being completely broken, and
        // `env_clear` makes that failure one line away.
        assert!(
            observed.contains("NUCLEUS_TOOL_PROXY_URL"),
            "the workload must still be told where its proxy is, or the assertions \
             above are satisfied by a child that got nothing:\n{observed}"
        );
        assert!(
            observed.contains("PATH="),
            "PATH must survive the clear, or a workload cannot resolve its own \
             command:\n{observed}"
        );

        // The receipt reports the same inventory the admission checked, and it
        // carries the one legitimately-Internal entry (the proxy HMAC), so it is
        // not the empty-environment vacuous case.
        assert!(
            receipt.carries_internal_entry(),
            "the receipt must show the workload's own proxy credential, or the \
             launch is the broken empty-env case: {receipt:?}"
        );
        assert_eq!(receipt.stdio, ["null", "piped", "piped"]);

        // **File-descriptor surface**, Linux only (procfs). `spawn_admitted`'s
        // pre_exec `close_range(3, .., CLOEXEC)` condemns every inherited fd
        // above the child's own stdio, so after exec only 0/1/2 exist;
        // `ls /proc/self/fd` then opens the directory as one more fd, giving
        // exactly four entries. Any fd beyond that is a leak the close_range
        // was supposed to shut — the runc-CVE-2024-21626 shape. This runs in
        // the noisy cargo-test harness (which itself holds high, non-CLOEXEC
        // fds), so it also proves the close_range call actually fires rather
        // than relying on the parent's fds happening to be CLOEXEC.
        #[cfg(target_os = "linux")]
        {
            let fds = std::fs::read_to_string(&f_fd).unwrap_or_default();
            let count = fds.split_whitespace().filter(|s| !s.is_empty()).count();
            // Non-vacuity: stdio must be present, so the count is at least 3.
            assert!(
                count >= 3,
                "the child must have its three standard fds; got:\n{fds}"
            );
            assert!(
                count <= 4,
                "the workload inherited a file descriptor beyond its own stdio — \
                 close_range did not shut every parent fd. Open fds were:\n{fds}"
            );
        }
    }

    /// **`workload_env` does not SOURCE the capability from the runtime.**
    ///
    /// # This test was necessary and not sufficient, and the gap was a real hole
    ///
    /// It asserts a property of the overlay map. `spawn_workload` applies that
    /// map with `cmd.env(k, v)` — additive — on top of an environment the child
    /// INHERITS from the proxy, and the proxy's environment holds
    /// `NUCLEUS_TOOL_PROXY_BROKER_SECRET` because `nucleus-guest-init` sets it
    /// before exec. So the workload received the capability, this test passed,
    /// and the two facts had nothing to do with each other.
    ///
    /// Renamed to what it actually checks. The property people want is in
    /// `the_spawned_child_does_not_inherit_the_capability`, which asserts over a
    /// real child's environment.
    #[test]
    fn workload_env_does_not_source_the_capability_from_the_runtime() {
        let hostile = spec_with(&[("NUCLEUS_TOOL_PROXY_BROKER_SECRET", "stolen")]);
        let env = workload_env(&hostile, "http://127.0.0.1:8080", "s3cret", &[]);
        // A spec that names it gets it back — that value is the SPEC's, not the
        // runtime's, and the runtime never puts its own there. The property is
        // that nothing in `workload_env` SOURCES it from the runtime.
        assert_eq!(
            env.get("NUCLEUS_TOOL_PROXY_BROKER_SECRET")
                .map(String::as_str),
            Some("stolen"),
            "spec env passes through; the point is the runtime adds nothing here"
        );

        // With a clean spec, the key must be absent entirely.
        let env = workload_env(&spec_with(&[]), "http://127.0.0.1:8080", "s3cret", &[]);
        assert!(
            !env.contains_key("NUCLEUS_TOOL_PROXY_BROKER_SECRET"),
            "the runtime must never place its broker capability in the workload's environment"
        );
    }

    /// The control: ordinary spec env still reaches the workload, so the
    /// precedence above is not simply discarding what the spec asked for.
    #[test]
    fn ordinary_spec_env_is_passed_through() {
        let env = workload_env(
            &spec_with(&[("MODEL_ENDPOINT", "https://example.invalid")]),
            "u",
            "s",
            &[],
        );
        assert_eq!(
            env.get("MODEL_ENDPOINT").map(String::as_str),
            Some("https://example.invalid")
        );
    }

    fn egress_spec() -> nucleus_spec::CredentialedEgressSpec {
        nucleus_spec::CredentialedEgressSpec {
            name: "api".into(),
            upstream: "https://u.invalid".into(),
            credential_env: "CRED".into(),
            header: "authorization".into(),
            value_prefix: String::new(),
        }
    }

    /// **The guarantee is a uid boundary, not an environment variable.** A
    /// workload sharing the runtime's uid reads `/proc/<pid>/environ` and takes
    /// the credential, so credentialed egress without a distinct uid is a
    /// comment rather than a control.
    #[test]
    fn credentialed_egress_without_a_workload_uid_is_refused() {
        let err = reject_credential_readable_workload(Some(&spec_with(&[])), &[egress_spec()])
            .expect_err("a same-uid workload must be refused");
        assert!(err.contains("/proc"), "the mechanism must be named: {err}");
        assert!(err.contains("uid"), "and the fix: {err}");
    }

    /// The control: a distinct uid is accepted, so the check is not refusing
    /// every configuration.
    #[test]
    fn a_distinct_uid_is_accepted() {
        let mut w = spec_with(&[]);
        w.uid = Some(nix_getuid().wrapping_add(1));
        assert!(reject_credential_readable_workload(Some(&w), &[egress_spec()]).is_ok());
    }

    /// The runtime's OWN uid is not a boundary, even when written explicitly.
    #[test]
    fn the_runtimes_own_uid_is_not_a_boundary() {
        let mut w = spec_with(&[]);
        w.uid = Some(nix_getuid());
        assert!(reject_credential_readable_workload(Some(&w), &[egress_spec()]).is_err());
    }

    /// With no credential being withheld there is nothing to protect, so a
    /// shared uid is fine — the coupling is to credentialed egress, not a
    /// blanket rule.
    #[test]
    fn without_credentialed_egress_a_shared_uid_is_fine() {
        assert!(reject_credential_readable_workload(Some(&spec_with(&[])), &[]).is_ok());
    }

    // ── FM-5 binding: the extracted delivery model agrees with workload_env ──
    //
    // The Lean theorems in `IdentityMaterialNoninterferenceExtracted.lean` are
    // about `nucleus_ifc_kernel::extracted::identity`, not about this file.
    // These tests are the leg that binds the two: every variable the overlay
    // actually injects must be one the model calls deliverable to the
    // workload, and every identity variable the runtime holds must be one the
    // model refuses AND the overlay omits. Neither side proves the other; the
    // pointwise agreement is the claim.

    use nucleus_ifc_kernel::extracted::identity::{ident_may_deliver, MaterialKind, Principal};

    /// An INDEPENDENT oracle for the production `env_key_material` classifier —
    /// deliberately a different structure (an exact-match lookup table plus two
    /// prefix rules, not the production `match`) so that a careless joint edit
    /// of production-and-oracle is unlikely to keep them agreeing.
    ///
    /// The production classifier had to move out of the tests (the builder
    /// consults it on the live path), and the FM-5 docs warned that a classifier
    /// in production "would let the model and the mapping drift together". This
    /// oracle plus `the_production_classifier_agrees_with_the_independent_oracle`
    /// is the answer: the two are written apart and pinned to agree over an
    /// enumerated corpus, so drift in one reds the gate.
    fn material_for_env_key(key: &str) -> MaterialKind {
        const EXACT: &[(&str, MaterialKind)] = &[
            ("NUCLEUS_IDENTITY_CERT", MaterialKind::SvidCert),
            ("NUCLEUS_TASK_TOKEN", MaterialKind::TaskToken),
            ("NUCLEUS_TASK_TOKEN_NONCE", MaterialKind::TaskToken),
            ("NUCLEUS_TASK_TOKEN_ISSUER", MaterialKind::TaskToken),
            (
                "NUCLEUS_TOOL_PROXY_BROKER_SECRET",
                MaterialKind::BrokerSecret,
            ),
            ("NUCLEUS_TOOL_PROXY_BROKER_PORT", MaterialKind::BrokerSecret),
            (
                "NUCLEUS_TOOL_PROXY_APPROVAL_SECRET",
                MaterialKind::ApprovalSecret,
            ),
            ("NUCLEUS_SANDBOX_TOKEN", MaterialKind::SandboxToken),
            (
                "NUCLEUS_TOOL_PROXY_AUTH_SECRET",
                MaterialKind::ProxyAuthSecret,
            ),
        ];
        if let Some((_, kind)) = EXACT.iter().find(|(k, _)| *k == key) {
            return *kind;
        }
        if key.starts_with("NUCLEUS_DLC_") {
            return MaterialKind::DlcCredentials;
        }
        if key.starts_with("NUCLEUS_EGRESS_") {
            return MaterialKind::EgressEnv;
        }
        MaterialKind::OrdinaryData
    }

    /// The production classifier and the independent oracle must agree over an
    /// enumerated corpus that spans the whole `NUCLEUS_*` namespace the overlay
    /// can produce — plus a NOVEL `NUCLEUS_*` name, the one case that matters:
    /// a new variable the overlay could grow. Both must classify it the same.
    /// This catches classifier drift — a KNOWN secret reclassified in one place
    /// but not the other reds here.
    #[test]
    fn the_production_classifier_agrees_with_the_independent_oracle() {
        let corpus = [
            "NUCLEUS_IDENTITY_CERT",
            "NUCLEUS_TASK_TOKEN",
            "NUCLEUS_TASK_TOKEN_NONCE",
            "NUCLEUS_TASK_TOKEN_ISSUER",
            "NUCLEUS_TOOL_PROXY_BROKER_SECRET",
            "NUCLEUS_TOOL_PROXY_BROKER_PORT",
            "NUCLEUS_TOOL_PROXY_APPROVAL_SECRET",
            "NUCLEUS_SANDBOX_TOKEN",
            "NUCLEUS_TOOL_PROXY_AUTH_SECRET",
            "NUCLEUS_DLC_CREDENTIALS",
            "NUCLEUS_DLC_TRUSTED_KEYS",
            "NUCLEUS_DLC_ISSUER",
            "NUCLEUS_EGRESS_MODEL_API_URL",
            "NUCLEUS_TOOL_PROXY_URL",
            "PATH",
            "HOME",
            "ORDINARY",
            "NUCLEUS_SOME_FUTURE_NAME", // the novel-name case
        ];
        for key in corpus {
            assert_eq!(
                env_key_material(key),
                material_for_env_key(key),
                "production classifier and independent oracle disagree on `{key}` — \
                 one drifted from the other"
            );
        }
    }

    /// Every variable the overlay injects is one the model says the workload
    /// may receive. The non-vacuity control is the auth secret: the map must
    /// contain at least one *Internal*-labelled key, because a Public-only
    /// overlay would pass this test without exercising the ceiling at all.
    #[test]
    fn every_env_var_the_overlay_injects_is_model_deliverable_to_the_workload() {
        let env = workload_env(
            &spec_with(&[("ORDINARY", "1")]),
            "http://127.0.0.1:8080",
            "s3cret",
            &[egress_spec()],
        );
        for key in env.keys() {
            assert!(
                ident_may_deliver(material_for_env_key(key), Principal::Workload),
                "{key} is in the workload overlay but the FM-5 model refuses it — \
                 either the overlay leaks or the model is stale"
            );
        }
        assert!(
            env.contains_key("NUCLEUS_TOOL_PROXY_AUTH_SECRET"),
            "non-vacuity: the overlay must carry the one Internal-labelled key"
        );
        assert!(
            env.keys().any(|k| k.starts_with("NUCLEUS_EGRESS_")),
            "non-vacuity: the egress channel must be exercised"
        );
    }

    /// Every identity variable the runtime holds is refused by the model AND
    /// absent from the overlay. A spec that names one of these gets its own
    /// value passed through — same stance as
    /// `workload_env_does_not_source_the_capability_from_the_runtime`: the
    /// property is that the RUNTIME's copy never crosses, not that the names
    /// are unspeakable.
    #[test]
    fn every_identity_var_the_runtime_holds_is_refused_by_the_model_and_absent_from_the_overlay() {
        const IDENTITY_VARS: [&str; 10] = [
            "NUCLEUS_TOOL_PROXY_BROKER_SECRET",
            "NUCLEUS_TASK_TOKEN",
            "NUCLEUS_TASK_TOKEN_NONCE",
            "NUCLEUS_TASK_TOKEN_ISSUER",
            "NUCLEUS_TOOL_PROXY_APPROVAL_SECRET",
            "NUCLEUS_SANDBOX_TOKEN",
            "NUCLEUS_IDENTITY_CERT",
            "NUCLEUS_DLC_CREDENTIALS",
            "NUCLEUS_DLC_TRUSTED_KEYS",
            "NUCLEUS_DLC_ISSUER",
        ];
        let env = workload_env(
            &spec_with(&[]),
            "http://127.0.0.1:8080",
            "s3cret",
            &[egress_spec()],
        );
        for var in IDENTITY_VARS {
            assert!(
                !ident_may_deliver(material_for_env_key(var), Principal::Workload),
                "{var} must classify as identity material the model refuses"
            );
            assert!(
                !env.contains_key(var),
                "{var} must not appear in the workload overlay"
            );
        }
    }

    /// The second injection channel — the builder's by-name inheritance
    /// loop — is bound to the model too: everything on the allowlist must be
    /// deliverable. A secret-carrying name added there would fail here before
    /// it failed in a guest.
    #[test]
    fn the_inherited_by_name_allowlist_is_model_deliverable() {
        for key in INHERITED_BY_NAME {
            assert!(
                ident_may_deliver(material_for_env_key(key), Principal::Workload),
                "{key} is inherited by name but the FM-5 model refuses it"
            );
        }
    }
}
