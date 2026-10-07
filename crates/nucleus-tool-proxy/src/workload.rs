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
    MaterialKind, Principal, ident_may_deliver, mat_label,
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
    /// Injected by the runtime: the URL of the workload's door.
    RuntimeInjected,
    /// An egress forwarder name/URL from `workload_egress_env`.
    Egress,
    /// A default the runtime supplies and `spec.env` may override: `HOME`,
    /// pointed at [`workload_home`].
    RuntimeDefault,
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
/// `workload_env` makes the runtime-injected URL win over `spec.env`, so that
/// key is `RuntimeInjected` regardless of whether the spec also named it, which
/// is the correct attribution: the value that crossed is the runtime's.
fn env_source(key: &str, spec: &WorkloadSpec) -> EnvSource {
    if key == "NUCLEUS_TOOL_PROXY_URL" {
        EnvSource::RuntimeInjected
    } else if key.starts_with("NUCLEUS_EGRESS_") {
        EnvSource::Egress
    } else if INHERITED_BY_NAME.contains(&key) {
        EnvSource::InheritedByName
    } else if key == "HOME" && !spec.env.contains_key(key) {
        EnvSource::RuntimeDefault
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
/// that looks like a missing binary rather than a missing variable; `LANG` and
/// `TZ` because tools misbehave in confusing ways without them and neither can
/// carry authority.
///
/// `HOME` is NOT inherited any more. In a guest the runtime's `HOME` is `/`,
/// which is on the read-only rootfs, so every tool that writes a dotfile failed;
/// outside a guest it was the operator's own home directory. It is now
/// [`workload_home`], a directory on the workload's own scratch.
pub(crate) const INHERITED_BY_NAME: [&str; 3] = ["PATH", "LANG", "TZ"];

/// The workload's `HOME` when its spec sets none: `<work_dir>/.home`, which is
/// `/work/.home` in a guest (`nucleus_spec::guest_layout::WORKLOAD_HOME_NAME`).
///
/// Derived from the work dir rather than fixed, because the proxy also runs
/// outside a guest. [`spawn_admitted`] creates it and hands it to the workload
/// uid beside the work dir itself.
#[must_use]
pub(crate) fn workload_home(work_dir: &std::path::Path) -> std::path::PathBuf {
    work_dir.join(nucleus_spec::guest_layout::WORKLOAD_HOME_NAME)
}

/// The uid a workload runs as when its spec sets none. Deliberately a high,
/// unprivileged, non-root value: the guest runtime is root and holds every
/// per-pod secret in its environment, so the workload MUST run as a distinct
/// uid or it could read that environment via `/proc/<pid>/environ`. A pod may
/// override with `workload.uid`, but never to the runtime's own uid.
///
/// Test-only since #3120: production code no longer names a default uid at
/// all — `nucleus::ChildConfinement::workload` applies it, so the admission
/// and the spawn cannot disagree about it.
#[cfg(test)]
pub(crate) const DEFAULT_WORKLOAD_UID: u32 = nucleus::DEFAULT_CHILD_UID;

///
/// # No proxy credential crosses
///
/// The workload used to receive `NUCLEUS_TOOL_PROXY_AUTH_SECRET`, the HMAC key
/// of the proxy's shared-secret tier, as "its own credential". Any process that
/// held it could sign requests to that tier, and nothing tied a signed request
/// to the workload. Now the workload reaches the proxy through its own door
/// (`workload_door`), and it authenticates by being the workload's uid on that
/// socket, a fact the kernel reports. There is no secret to hand over, so this
/// function takes none, and [`WorkloadLaunch::admit`] refuses one that arrives
/// any other way (#3031 option B).
#[must_use]
pub(crate) fn workload_env(
    spec: &WorkloadSpec,
    door_url: &str,
    egress: &[nucleus_spec::CredentialedEgressSpec],
) -> BTreeMap<String, String> {
    let mut env = spec.env.clone();
    // Local forwarder addresses for each credentialed upstream. Names and URLs
    // only — the credential stays in the runtime, which is the point.
    env.extend(crate::egress::workload_egress_env(egress, door_url));
    env.insert("NUCLEUS_TOOL_PROXY_URL".to_string(), door_url.to_string());
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
    /// The uid boundary the admission decided, and the ONLY one the spawn
    /// applies (#3120): what was checked and what is enforced are this one
    /// value, so "admitted as separated, spawned at the runtime's uid" has no
    /// line of code that could express it.
    confinement: nucleus::ChildConfinement,
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
            .field("confinement", &self.confinement)
            .finish_non_exhaustive()
    }
}

/// Which uid the child will actually run as. Two cases, because they are
/// different claims: a dropped uid is a boundary, an inherited one is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunsAs {
    /// The runtime is root, so `spawn_admitted` drops the child to the admitted
    /// uid (the guest case).
    Dropped(u32),
    /// The declared bare host tier: a non-root runtime under
    /// `ContainmentMode::Unsandboxed`, whose operator opted in, runs the child
    /// as its own uid. The launch receipt reports this as `shared_unsandboxed`
    /// and not hardened. A runtime that cannot drop reaches no other case: the
    /// admission refuses it by name (#3120).
    Inherited(u32),
}

impl RunsAs {
    fn uid(self) -> u32 {
        match self {
            Self::Dropped(uid) | Self::Inherited(uid) => uid,
        }
    }
}

/// The uid the workload door admits: the uid the workload child actually runs
/// as.
///
/// Evidence, so its constructor is private (ADR 0007 C-1, C-2): only
/// [`AdmittedWorkloadPlan::door_uid`] mints one, from the same
/// [`AdmittedWorkloadPlan::runs_as`] that `spawn_admitted` drops the child to.
/// The door therefore cannot admit a uid other than the one the workload has.
/// That uid is `DEFAULT_WORKLOAD_UID` unless the pod's `workload.uid` names
/// another; it is never the runtime's own when the runtime is root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WorkloadUid(u32);

impl WorkloadUid {
    pub(crate) fn get(self) -> u32 {
        self.0
    }

    /// A door policy for a test that cannot run a real workload.
    #[cfg(test)]
    pub(crate) fn for_test(uid: u32) -> Self {
        Self(uid)
    }
}

impl AdmittedWorkloadPlan {
    /// The one decider of the child's uid, shared by `spawn_admitted` and the
    /// door (ADR 0007 G-1).
    pub(crate) fn runs_as(&self) -> RunsAs {
        // Read off the confinement the admission decided and the spawn
        // applies, so the door and the child cannot disagree (#3120).
        match self.confinement.child_uid() {
            nucleus::ChildUid::Distinct(uid) => RunsAs::Dropped(uid),
            nucleus::ChildUid::SharedWithRuntime => RunsAs::Inherited(nix_getuid()),
        }
    }

    /// The uid the workload door admits for this launch.
    pub(crate) fn door_uid(&self) -> WorkloadUid {
        WorkloadUid(self.runs_as().uid())
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
}

impl WorkloadLaunch {
    /// Assemble and classify. Takes the same inputs the old `spawn_workload`
    /// did; the env is produced by the pinned [`workload_env`] so the binding
    /// tests still describe the one env-assembly point.
    pub(crate) fn build(
        spec: &WorkloadSpec,
        door_url: &str,
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
        // Under `spec.env`, which `workload_env` extends over it: an operator
        // who names a HOME gets theirs.
        env.insert(
            "HOME".to_string(),
            workload_home(work_dir).to_string_lossy().into_owned(),
        );
        env.extend(workload_env(spec, door_url, egress));
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
    pub(crate) fn admit(
        self,
        containment: nucleus::ContainmentMode,
        opt_in: nucleus::UnsandboxedOptIn,
        landlock: nucleus::LandlockWaiver,
    ) -> Result<AdmittedWorkloadPlan, Refused> {
        // The workload must never run as the runtime's uid. The runtime holds
        // every per-pod secret in its own environment, and Linux lets a process
        // read `/proc/<pid>/environ` of any process sharing its uid — so a
        // same-uid workload reads the broker/task/approval/DLC secrets straight
        // out of the runtime. A distinct unprivileged uid is the boundary, and
        // it must hold for EVERY pod, not only when credentialed egress is
        // configured (this supersedes the egress-only coupling in
        // `reject_credential_readable_workload`, kept as a node-side pre-check).
        //
        // The decision is `nucleus::ChildConfinement::workload`, and the plan
        // carries its result to the spawn (#3120). It used to be two: this
        // function refused `uid == runtime`, and the spawn then dropped only
        // when the runtime was root — so on a non-root runtime a workload
        // admitted as "distinct" ran at the runtime's uid anyway. Now a uid
        // boundary this runtime cannot enforce is a refusal here, by name. The
        // one same-uid outcome is the declared bare host tier
        // (`ContainmentMode::Unsandboxed`, no `workload.uid`), which the
        // confinement reports as such and the spawn announces -- and only
        // with the operator's explicit `--unsandboxed` (owner decision 1,
        // 2026-10-02); without it the bare tier refuses by name too.
        let confinement =
            nucleus::ChildConfinement::workload(containment, self.uid, opt_in, landlock)
                .map_err(|e| Refused(e.to_string()))?;

        // Reserved-namespace fail-safe — closes the `_ => OrdinaryData`
        // fallthrough in `env_classifier`. A `NUCLEUS_*` key the classifier does
        // not recognise falls through to `OrdinaryData` (Public), which the
        // relation below happily delivers. So a future secret added to the
        // workload overlay WITHOUT a classifier arm would reach the workload
        // silently — and the dual-classifier corpus test cannot catch it,
        // because both classifiers share that same `OrdinaryData` default (a
        // differential check is blind to a shortcut both sides take). Refuse any
        // unrecognised reserved-namespace key here instead. The only public
        // value the runtime injects under this prefix is allowlisted; every
        // other `NUCLEUS_*` name must be classified deliberately (as a secret
        // material kind if it carries identity, or added to this allowlist if it
        // is genuinely public runtime config) before it may cross.
        const PUBLIC_RESERVED: &[&str] = &["NUCLEUS_TOOL_PROXY_URL"];
        for entry in &self.classified {
            if entry.key.starts_with("NUCLEUS_")
                && entry.material == MaterialKind::OrdinaryData
                && !PUBLIC_RESERVED.contains(&entry.key.as_str())
            {
                return Err(Refused(format!(
                    "environment variable `{}` is in the reserved `NUCLEUS_` namespace but the \
                     classifier does not recognise it, so it falls through to OrdinaryData \
                     (public) and would be delivered to the workload. Classify it in \
                     `env_classifier.rs` (a secret material kind if it carries identity, or add \
                     it to PUBLIC_RESERVED if it is genuinely public runtime config).",
                    entry.key
                )));
            }
        }

        // No proxy credential crosses, whoever supplied it. The FM-5 relation
        // still licenses `ProxyAuthSecret` to the workload (it is `Internal`),
        // because that is what the workload used to need; it needs nothing now
        // that it authenticates by its uid on the workload door, and a spec
        // that names the variable is either stale or trying to give the agent
        // a key to the host's shared-secret tier. This is the tighter rule,
        // applied on top of the relation, not instead of it.
        for entry in &self.classified {
            if entry.material == MaterialKind::ProxyAuthSecret {
                return Err(Refused(format!(
                    "environment variable `{}` is a proxy credential. The workload \
                     authenticates by its uid on the workload door and receives no \
                     credential for the proxy; remove it from the workload's env.",
                    entry.key
                )));
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
            confinement,
            env: self.env,
            classified: self.classified,
        })
    }
}

/// OS assumptions: KB-GUEST-PID-SHARED and KB-LINUX-CHILD-ISOLATION;
/// see docs/assumptions/kernel-behaviour.md.
///
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
#[expect(
    clippy::disallowed_methods,
    reason = "#1216: THE one sanctioned spawn; the mediation allowlist names this line"
)]
pub(crate) fn spawn_admitted(
    plan: AdmittedWorkloadPlan,
    rlimits: nucleus::AppliedRlimits,
    syscalls: portcullis::SeccompPolicy,
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

    // The privilege boundary: the SAME `nucleus::ChildConfinement` the
    // Executor gives every `/v1/run` child under MicroVM (ADR 0007 G-1 — one
    // decider, one mechanism; the copy that lived here is gone). It declares
    // the uid/gid drop on the Command, where std applies it before `chdir` and
    // before any `pre_exec` closure, and installs the async-signal-safe hook
    // that marks every inherited fd above 2 close-on-exec (the runc
    // CVE-2024-21626 lesson) and, once dropped, sets no_new_privs and the
    // `rlimits` the pod's policy produced (#2572).
    //
    // NOT re-decided here: the plan carries the confinement its admission
    // decided, and this applies exactly that (#3120). A runtime that cannot
    // drop never reaches this line with a separated plan — the admission
    // refused it by name. The one same-uid plan is the declared bare host
    // tier, announced below.
    let confinement = plan.confinement;
    if confinement.is_unsandboxed() {
        tracing::warn!(
            command = %plan.command,
            runtime_uid = nix_getuid(),
            "AUDIT: UNSANDBOXED workload — the bare host tier was declared and the operator \
             opted in (--unsandboxed), so the workload runs as the runtime's own uid and CAN \
             read the runtime's environment (every per-pod secret) via /proc/<pid>/environ. \
             Only a root runtime or a microVM separates it."
        );
        crate::console_line(&format!(
            "[workload] UNSANDBOXED: {:?} runs as the runtime's uid ({}) and can read its \
             secrets; this tier is not a uid boundary",
            plan.command,
            nix_getuid()
        ));
    }
    let drop_uid = confinement.drop_uid();
    // The default HOME, made before the chown below so the same best-effort
    // treatment covers both. Only when the admitted env still points at it: a
    // spec that chose its own HOME chose its own directory too.
    let home = workload_home(&plan.work_dir);
    let default_home = plan.env.get("HOME").map(std::path::Path::new) == Some(home.as_path());
    if default_home && let Err(e) = std::fs::create_dir_all(&home) {
        tracing::warn!(
            home = %home.display(),
            error = %e,
            "could not create the workload's HOME (expected when the scratch is read-only)"
        );
    }
    if default_home && let Err(e) = confinement.hand_over(&home) {
        tracing::warn!(
            home = %home.display(),
            uid = ?drop_uid,
            error = %e,
            "could not chown the workload's HOME to its uid"
        );
    }
    // Best-effort: hand the workload ownership of its work dir so the
    // unprivileged child can write its scratch. This is an ERGONOMIC aid, not
    // the security control — the uid drop is. It legitimately fails when the
    // work dir is read-only (a pod with no writable scratch drive, where
    // `/work` is on the read-only rootfs), and in that case the workload cannot
    // write it regardless, so the failure is not fatal: log it and proceed.
    if let Err(e) = confinement.hand_over(&plan.work_dir) {
        tracing::warn!(
            work_dir = %plan.work_dir.display(),
            uid = ?drop_uid,
            error = %e,
            "could not chown the workload work dir to its uid; the workload will run \
             without ownership of it (expected when the scratch is read-only)"
        );
    }
    // A ruleset that cannot be compiled refuses the spawn with its path and
    // reason (`NucleusError::LandlockRuleset`), which reaches the console as
    // the workload's start error; the pre_exec hook alone could carry back only
    // an errno (the x86_64 live boot showed "Not supported (os error 95)").
    confinement
        .preflight_filesystem()
        .map_err(std::io::Error::other)?;
    // What the hook does, as only `apply` can say it: the receipt's
    // `hardening` is this value, not a flag computed beside the spawn. It
    // carries the syscall classes the pod's lattice derived (#2907) as the
    // filter the hook actually installs.
    let hardening = confinement.apply(cmd.as_std_mut(), rlimits, syscalls);

    tracing::info!(
        command = %plan.command,
        env_entries = plan.classified.len(),
        "starting pod workload under mediation (admitted)"
    );
    let child = cmd.spawn()?;
    let receipt = LaunchReceipt::from_admitted(&plan, hardening, child.id());
    Ok((child, receipt))
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
pub(crate) fn nix_getuid() -> u32 {
    // One reader of "who is the runtime", shared with the confinement that
    // decides whether a child can be dropped (ADR 0007 G-1).
    nucleus::runtime_uid()
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
    /// The uid boundary the spawn actually applied, read off the plan's
    /// confinement — never off the requested uid. Before #3120 it read the
    /// request, so a non-root runtime that ran the workload at its own uid
    /// still recorded `distinct`.
    pub(crate) uid_boundary: UidBoundary,
    /// How the workload's filesystem was held, read off the plan's
    /// confinement (#2696 P3c): the Landlock ABI enforced, or the operator's
    /// waiver and what the kernel offered instead. In the hashed preimage, so
    /// a waived launch cannot share a hash with a confined one. The Landlock
    /// ruleset is installed by the same hook `hardening` reports; it is kept
    /// here rather than inside `hardening` so the fact is written once.
    pub(crate) filesystem: FilesystemBoundary,
    /// What the async-signal-safe hardening hook (fds above 2 close-on-exec,
    /// no_new_privs, the pod's rlimits, the Landlock ruleset `filesystem`
    /// names, the syscall filter) does to the child, as
    /// [`nucleus::ChildConfinement::apply`] reported it. The hardened case
    /// carries the applied limits and only `apply` can mint it (#2572).
    pub(crate) hardening: nucleus::SpawnHardening,
    pub(crate) argv_len: usize,
    pub(crate) child_pid: Option<u32>,
    /// SHA-256 of the authority-inventory preimage below. The resolved
    /// environment commitment is separate and covered by the execution signer.
    pub(crate) hash: String,
    /// Commit the resolved values actually passed to env_clear/env, separately
    /// from the authority inventory. Never expose those values in the receipt.
    pub(crate) environment: nucleus_spec::workload_result::EnvironmentIdentity,
}

/// How the workload's filesystem was held (#2696 P3c). Three values for the
/// three postures `nucleus::FilesystemConfinement` has; "the kernel could not
/// and nobody waived it" is a refusal at admission, never a value here.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub(crate) enum FilesystemBoundary {
    /// The guest layout's Landlock ruleset, at this ABI.
    Landlock { abi: u32 },
    /// No Landlock: the kernel offered `kernel`, and the operator waived it.
    WaivedNoLandlock { kernel: String },
    /// The containment does not hold the filesystem with Landlock (the bare
    /// tier, `HostHardened`).
    NotApplied,
}

impl FilesystemBoundary {
    fn of(fs: nucleus::FilesystemConfinement) -> Self {
        match fs {
            nucleus::FilesystemConfinement::Landlock { abi } => Self::Landlock { abi },
            nucleus::FilesystemConfinement::Waived { kernel } => Self::WaivedNoLandlock {
                kernel: kernel.to_string(),
            },
            nucleus::FilesystemConfinement::NotApplied => Self::NotApplied,
        }
    }

    /// The receipt preimage's spelling.
    fn preimage(&self) -> String {
        match self {
            Self::Landlock { abi } => format!("landlock:{abi}"),
            Self::WaivedNoLandlock { kernel } => format!("waived:{kernel}"),
            Self::NotApplied => "not_applied".to_string(),
        }
    }
}

/// Whether the workload runs under a uid other than the runtime's.
///
/// Two values, because there are two outcomes: the admission either decided a
/// uid drop, or the bare host tier was declared and the workload shares the
/// runtime's uid. "Wanted a boundary and could not have one" is a refusal at
/// admission, not a third value here (#3120).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UidBoundary {
    /// The workload was dropped to a uid that is not the runtime's.
    Distinct,
    /// The declared bare host tier: the workload runs as the runtime's uid
    /// and can read its environment.
    SharedUnsandboxed,
}

impl UidBoundary {
    /// The receipt preimage's spelling, equal to the serialized one.
    fn as_str(self) -> &'static str {
        match self {
            Self::Distinct => "distinct",
            Self::SharedUnsandboxed => "shared_unsandboxed",
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct ReceiptEnvEntry {
    pub(crate) key: String,
    pub(crate) material: String,
    pub(crate) label: String,
    pub(crate) source: EnvSource,
}

impl LaunchReceipt {
    /// 2: the preimage gained `fs=` (#2696 P3c).
    /// 3: the preimage gained `seccomp=`, the installed filter and the pod's
    /// derived syscall classes (#2907).
    const SCHEMA_VERSION: u32 = 3;

    fn from_admitted(
        plan: &AdmittedWorkloadPlan,
        hardening: nucleus::SpawnHardening,
        child_pid: Option<u32>,
    ) -> Self {
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
        let uid_boundary = match plan.confinement.child_uid() {
            nucleus::ChildUid::Distinct(_) => UidBoundary::Distinct,
            nucleus::ChildUid::SharedWithRuntime => UidBoundary::SharedUnsandboxed,
        };
        let filesystem = FilesystemBoundary::of(plan.confinement.filesystem());
        let argv_len = plan.args.len();
        let hardened = hardening.is_hardened();
        // Read off `hardening`, the one record of the filter (ADR 0007 G-1):
        // no hook means no filter, whatever the pod's policy derived.
        let seccomp = match hardening {
            nucleus::SpawnHardening::Hardened(h) => h.syscalls().canonical(),
            nucleus::SpawnHardening::Unhardened(_) => "none".to_string(),
        };
        // Canonical preimage: field-ordered, `|`-joined, values excluded.
        // Reconstructed from the record's own fields, not serialized, so key
        // order and escaping cannot drift the hash.
        let mut preimage = format!(
            "v{}|cmd={}|argv={argv_len}|stdio={}|uid={}|hardened={hardened}|fs={}|seccomp={seccomp}",
            Self::SCHEMA_VERSION,
            plan.command,
            stdio.join(","),
            uid_boundary.as_str(),
            filesystem.preimage(),
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
            filesystem,
            hardening,
            argv_len,
            child_pid,
            hash,
            environment: nucleus_spec::workload_result::EnvironmentIdentity::of(&plan.env),
        }
    }
}

/// The ceiling on the resource limits of every child this pod spawns — the
/// workload and every `/v1/run` command — derived from its spec (#2572). The
/// ONE place the spec's fields become a [`nucleus::RlimitPolicy`] (ADR 0007
/// G-1); the derivation rule is documented on `RlimitPolicy::for_pod`.
///
/// A spec with no `resources.cpu_cores` is the node's default size, which
/// leaves the CPU limit at the node ceiling: absent never means unlimited.
///
/// In a guest this reads the spec the tool-proxy was started with. On an
/// enforcing guest that is the host's per-pod spec; on a legacy guest it is the
/// image's template, whose ceiling is still at or below the node's.
pub(crate) fn rlimit_policy(spec: &nucleus_spec::PodSpecInner) -> nucleus::RlimitPolicy {
    nucleus::RlimitPolicy::for_pod(
        std::time::Duration::from_secs(spec.timeout_seconds),
        spec.resources.as_ref().and_then(|r| r.cpu_cores),
    )
}

/// Whether the pod declares any network egress (#2907): a host or DNS name
/// on its network allowlist, or a credentialed upstream (whose guest adapter
/// gives the workload a loopback origin). The ONE place the spec's fields
/// become a [`portcullis::NetworkEgress`]. No network section lists nothing,
/// as the node reads it (`NetworkSpec::nothing_listed`).
pub(crate) fn network_egress(spec: &nucleus_spec::PodSpecInner) -> portcullis::NetworkEgress {
    let listed = spec
        .network
        .as_ref()
        .is_some_and(|n| !n.allow.is_empty() || !n.dns_allow.is_empty());
    if listed || !spec.credentialed_egress.is_empty() {
        portcullis::NetworkEgress::Declared
    } else {
        portcullis::NetworkEgress::None
    }
}

/// The syscall classes every child this pod spawns is denied beyond the
/// workload denylist — the workload and every `/v1/run` command — derived
/// from its policy and its egress (#2907). The ONE place the spec becomes a
/// [`portcullis::SeccompPolicy`]; the rule is `SeccompPolicy::derive`'s.
/// Derived from the normalized lattice, which is the one the executor runs.
///
/// # Errors
/// The spec's policy does not resolve.
pub(crate) fn seccomp_policy(
    spec: &nucleus_spec::PodSpecInner,
) -> Result<portcullis::SeccompPolicy, crate::ApiError> {
    let lattice = spec
        .resolve_policy()
        .map_err(|e| crate::ApiError::Spec(e.to_string()))?
        .normalize();
    Ok(portcullis::SeccompPolicy::derive(
        &lattice,
        network_egress(spec),
    ))
}

/// Start the pod's workload if the spec asks for one.
///
/// # The order is the value flow
///
/// 1. The workload door is bound at `door_path`. Its URL exists only once the
///    socket does, and the workload's `NUCLEUS_TOOL_PROXY_URL` (and every
///    `NUCLEUS_EGRESS_*_URL`) is derived from that URL, so the workload cannot
///    be told about a door that is not there.
/// 2. The launch is built and admitted. The admitted plan is the only source of
///    the uid the door admits ([`AdmittedWorkloadPlan::door_uid`]).
/// 3. The door is served with that uid ([`crate::workload_door::UnservedDoor::serve`]
///    consumes the bound door), and only then is the child spawned.
///
/// So the door admits exactly the uid the child runs as, and it is serving
/// before the child can call it.
///
/// Called after the proxy's main listener is bound, as before: a workload never
/// starts in a pod whose host cannot yet reach its proxy.
///
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
    door_path: &std::path::Path,
    door_app: axum::Router,
    containment: nucleus::ContainmentMode,
    opt_in: nucleus::UnsandboxedOptIn,
    landlock: nucleus::LandlockWaiver,
) -> Result<Option<(tokio::process::Child, LaunchReceipt)>, crate::ApiError> {
    let Some(w) = spec.spec.workload.as_ref() else {
        return Ok(None);
    };
    let door = crate::workload_door::UnservedDoor::bind(door_path)?;
    let plan = WorkloadLaunch::build(
        w,
        &door.url(),
        &spec.spec.work_dir,
        &spec.spec.credentialed_egress,
    )
    .admit(containment, opt_in, landlock)
    .map_err(|e| {
        crate::ApiError::Spec(format!("refused to launch workload {:?}: {e}", w.command))
    })?;

    door.serve(door_app, plan.door_uid());

    let rlimits = rlimit_policy(&spec.spec).at_ceiling();
    let syscalls = seccomp_policy(&spec.spec)?;
    let (child, receipt) = spawn_admitted(plan, rlimits, syscalls).map_err(|e| {
        crate::ApiError::Spec(format!("failed to start workload {:?}: {e}", w.command))
    })?;

    tracing::info!(
        launch_receipt = %serde_json::to_string(&receipt).unwrap_or_default(),
        "workload launch receipt"
    );
    Ok(Some((child, receipt)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A door URL of the form the runtime injects.
    const DOOR: &str = "unix:///run/nucleus-door/workload.sock";

    /// The limits a test workload runs under: the node ceiling, as a pod with
    /// no `resources` gets.
    fn node_rlimits() -> nucleus::AppliedRlimits {
        nucleus::RlimitPolicy::node_ceiling().at_ceiling()
    }

    /// The derived policy that adds nothing to the denylist.
    fn nothing_derived() -> portcullis::SeccompPolicy {
        portcullis::SeccompPolicy::derive(
            &portcullis::PermissionLattice::permissive(),
            portcullis::NetworkEgress::Declared,
        )
    }

    /// #2572: the pod's rlimit ceiling comes from its spec. A declared core
    /// count bounds CPU-seconds by `timeout × cores`; no core count leaves
    /// the node ceiling, never unlimited.
    #[test]
    fn the_rlimit_policy_is_derived_from_the_pod_spec() {
        let pod = |extra: &str| -> nucleus_spec::PodSpec {
            serde_yaml::from_str(&format!(
                "apiVersion: nucleus/v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  \
                 timeout_seconds: 60\n{extra}"
            ))
            .expect("spec parses")
        };
        let cpu = |spec: &nucleus_spec::PodSpec| rlimit_policy(&spec.spec).ceiling().cpu_seconds;
        assert_eq!(cpu(&pod("  resources:\n    cpu_cores: 2\n")), 120);
        assert_eq!(cpu(&pod("  resources:\n    memory_mib: 512\n")), 3600);
        assert_eq!(cpu(&pod("")), 3600);
        assert_eq!(
            rlimit_policy(&pod("").spec).ceiling(),
            nucleus::RlimitVector::NODE_CEILING
        );
    }

    /// #2907: the pod's derived syscall classes come from its policy and its
    /// egress, one decider. `untrusted-model` with nothing listed loses exec
    /// and the internet socket; listing a host gives the socket back, never
    /// exec; `codegen` keeps exec; the probe pod's `demo` derives nothing.
    #[test]
    fn the_seccomp_policy_is_derived_from_the_pod_spec() {
        let canonical = |extra: &str| {
            let spec: nucleus_spec::PodSpec = serde_yaml::from_str(&format!(
                "apiVersion: nucleus/v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  \
                 timeout_seconds: 60\n{extra}"
            ))
            .expect("spec parses");
            seccomp_policy(&spec.spec)
                .unwrap_or_else(|e| panic!("{extra}: {e}"))
                .canonical()
        };
        let profile = |name: &str| format!("  policy:\n    type: profile\n    name: {name}\n");
        let untrusted = profile("untrusted-model");
        assert_eq!(canonical(&untrusted), "exec,inet_socket");
        assert_eq!(
            canonical(&format!("{untrusted}  network:\n    allow: []\n")),
            "exec,inet_socket"
        );
        assert_eq!(
            canonical(&format!(
                "{untrusted}  network:\n    allow: [\"example.com:443\"]\n"
            )),
            "exec"
        );
        assert_eq!(
            canonical(&format!(
                "{untrusted}  network:\n    dns_allow: [\"example.com\"]\n"
            )),
            "exec"
        );
        assert_eq!(canonical(&profile("codegen")), "inet_socket");
        assert_eq!(canonical(&profile("demo")), "none");
    }

    fn spec_with(env: &[(&str, &str)]) -> WorkloadSpec {
        WorkloadSpec {
            command: "agent".into(),
            artifacts: Default::default(),
            args: vec!["--flag".into()],
            uid: None,
            env: env
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }
    }

    /// `HOME` is the workload's own directory on its scratch, not the runtime's
    /// (`/` in a guest, read-only), and a spec that names one keeps it.
    #[test]
    fn home_defaults_under_the_work_dir_and_a_spec_may_override_it() {
        let work = std::path::Path::new("/work");
        let source_of = |launch: &WorkloadLaunch| {
            launch
                .classified
                .iter()
                .find(|e| e.key == "HOME")
                .map(|e| e.source)
        };

        let launch = WorkloadLaunch::build(&spec_with(&[]), "http://127.0.0.1:8080", work, &[]);
        assert_eq!(
            launch.env.get("HOME").map(String::as_str),
            Some("/work/.home")
        );
        assert_eq!(source_of(&launch), Some(EnvSource::RuntimeDefault));

        let launch = WorkloadLaunch::build(
            &spec_with(&[("HOME", "/elsewhere")]),
            "http://127.0.0.1:8080",
            work,
            &[],
        );
        assert_eq!(
            launch.env.get("HOME").map(String::as_str),
            Some("/elsewhere")
        );
        assert_eq!(source_of(&launch), Some(EnvSource::SpecEnv));
    }

    /// The default `HOME` exists by the time the workload runs: an unset or
    /// missing HOME fails ordinary tools in ways that read as the workload's bug.
    #[tokio::test]
    async fn the_default_home_exists_when_the_workload_starts() {
        let dir = tempfile::tempdir().unwrap();
        let mut spec = spec_with(&[]);
        spec.command = "/bin/sh".into();
        spec.args = vec![
            "-c".into(),
            "test -d \"$HOME\" && printf %s \"$HOME\"".into(),
        ];
        let plan = WorkloadLaunch::build(&spec, "http://127.0.0.1:8080", dir.path(), &[])
            .admit(HARNESS, OPTED_IN, NO_WAIVER)
            .unwrap();
        let (child, _receipt) = spawn_admitted(plan, node_rlimits(), nothing_derived()).unwrap();
        let output = child.wait_with_output().await.unwrap();
        assert!(output.status.success(), "HOME was not a directory");
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            dir.path().join(".home").to_string_lossy()
        );
    }

    /// The workload is told where its door is. Without this it has no way to
    /// reach the only interface that is policed.
    #[test]
    fn the_workload_is_pointed_at_its_door() {
        let env = workload_env(&spec_with(&[]), DOOR, &[]);
        assert_eq!(
            env.get("NUCLEUS_TOOL_PROXY_URL").map(String::as_str),
            Some(DOOR)
        );
    }

    /// **The workload's environment carries no proxy credential** (#3031
    /// option B). It authenticates by its uid on the door; a secret in its
    /// environment would be a second, weaker way in that any process holding it
    /// could use. Red on `main` before this change, where `workload_env`
    /// inserted `NUCLEUS_TOOL_PROXY_AUTH_SECRET`.
    #[test]
    fn the_workload_env_carries_no_proxy_credential() {
        let dir = tempfile::tempdir().expect("tempdir");
        let launch = WorkloadLaunch::build(&spec_with(&[]), DOOR, dir.path(), &[egress_spec()]);
        assert!(
            !launch.env.contains_key("NUCLEUS_TOOL_PROXY_AUTH_SECRET"),
            "the workload must not be handed the proxy's HMAC key"
        );
        for entry in &launch.classified {
            assert_ne!(
                entry.material,
                MaterialKind::ProxyAuthSecret,
                "`{}` is a proxy credential in the workload's environment",
                entry.key
            );
        }
        // Non-vacuity: the launch still names the door, so this is not the
        // empty-environment case passing by accident.
        assert_eq!(
            launch.env.get("NUCLEUS_TOOL_PROXY_URL").map(String::as_str),
            Some(DOOR)
        );
    }

    /// A spec cannot put a proxy credential back. The runtime no longer
    /// overwrites the name, so `admit` refuses it whoever supplied it.
    #[test]
    fn a_spec_supplied_proxy_credential_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let refused = WorkloadLaunch::build(
            &spec_with(&[("NUCLEUS_TOOL_PROXY_AUTH_SECRET", "not-the-real-one")]),
            DOOR,
            dir.path(),
            &[],
        )
        .admit(HARNESS, OPTED_IN, NO_WAIVER);
        let err = refused.expect_err("a proxy credential must not cross");
        assert!(err.to_string().contains("workload door"), "{err}");
    }

    /// **A spec cannot redirect its workload away from mediation.** Setting the
    /// proxy URL in `env` would otherwise point the agent at an endpoint that
    /// polices nothing, while every dashboard still says "mediated".
    #[test]
    fn a_spec_cannot_override_the_proxy_url() {
        let hostile = spec_with(&[("NUCLEUS_TOOL_PROXY_URL", "http://attacker.invalid")]);
        let env = workload_env(&hostile, DOOR, &[]);
        assert_eq!(
            env.get("NUCLEUS_TOOL_PROXY_URL").map(String::as_str),
            Some(DOOR),
            "the runtime's door URL must win over anything the spec asks for"
        );
    }

    /// The door uid is the uid the child runs as: the admitted uid when the
    /// runtime can drop to it, the runtime's own when it cannot. One decider,
    /// so the door cannot admit a uid the workload does not have.
    #[test]
    fn the_door_admits_the_uid_the_child_runs_as() {
        let dir = tempfile::tempdir().expect("tempdir");
        let plan = WorkloadLaunch::build(&spec_with(&[]), DOOR, dir.path(), &[])
            .admit(HARNESS, OPTED_IN, NO_WAIVER)
            .expect("a clean spec admits");
        let expected = if nix_getuid() == 0 {
            RunsAs::Dropped(DEFAULT_WORKLOAD_UID)
        } else {
            RunsAs::Inherited(nix_getuid())
        };
        assert_eq!(plan.runs_as(), expected);
        assert_eq!(plan.door_uid().get(), expected.uid());
    }

    /// **The reserved-namespace fail-safe.** An unrecognised `NUCLEUS_*`
    /// variable falls through the classifier to `OrdinaryData` (public) and
    /// would be delivered to the workload — the exact hole a future secret would
    /// slip through, and one the dual-classifier corpus test cannot catch
    /// because both classifiers share that `OrdinaryData` default. `admit` must
    /// refuse it at the boundary, where the fence actually bites.
    #[test]
    fn an_unclassified_reserved_namespace_key_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let url = "http://127.0.0.1:8080";

        // A novel NUCLEUS_* name the classifier does not recognise.
        let refused = WorkloadLaunch::build(
            &spec_with(&[("NUCLEUS_FUTURE_SECRET", "sensitive")]),
            url,
            dir.path(),
            &[],
        )
        .admit(HARNESS, OPTED_IN, NO_WAIVER);
        assert!(
            refused.is_err(),
            "an unclassified NUCLEUS_* key must be refused, not delivered as OrdinaryData"
        );

        // Control 1: the one public reserved name the runtime injects
        // (NUCLEUS_TOOL_PROXY_URL) is allowlisted and must still admit.
        assert!(
            WorkloadLaunch::build(&spec_with(&[]), url, dir.path(), &[])
                .admit(HARNESS, OPTED_IN, NO_WAIVER)
                .is_ok(),
            "NUCLEUS_TOOL_PROXY_URL is public runtime config and must still admit"
        );

        // Control 2: an ordinary (non-reserved) operator var is unaffected.
        assert!(
            WorkloadLaunch::build(
                &spec_with(&[("MY_APP_SETTING", "value")]),
                url,
                dir.path(),
                &[],
            )
            .admit(HARNESS, OPTED_IN, NO_WAIVER)
            .is_ok(),
            "a non-NUCLEUS_ operator var must be unaffected by the reserved-namespace fence"
        );
    }

    /// The containment the harness tests below declare: the bare host tier,
    /// the one posture in which a non-root harness may run a workload at all.
    /// Under a root harness it still drops, exactly as before #3120.
    const HARNESS: nucleus::ContainmentMode = nucleus::ContainmentMode::Unsandboxed;

    /// ...and the harness opts in to it explicitly, as `--unsandboxed` does
    /// (owner decision 1): declaring the mode alone is refused.
    const OPTED_IN: nucleus::UnsandboxedOptIn = nucleus::UnsandboxedOptIn::Explicit;
    /// No Landlock waiver: a test admitted under `MicroVM` on a kernel without
    /// Landlock is refused, exactly as in production.
    const NO_WAIVER: nucleus::LandlockWaiver = nucleus::LandlockWaiver::Absent;

    /// **The workload never runs as the runtime's uid — for EVERY pod, not only
    /// under credentialed egress.** The runtime holds every per-pod secret in
    /// its environment, and Linux lets a same-uid process read it via
    /// `/proc/<pid>/environ`. A pod that sets no `workload.uid` is assigned a
    /// distinct default uid rather than silently inheriting the runtime's —
    /// when the runtime can drop. When it cannot, the admission refuses BY NAME
    /// (#3120); it used to admit "distinct" and spawn at the runtime's uid.
    /// Each runtime uid asserts its own exact outcome.
    #[test]
    fn admit_assigns_a_distinct_default_uid_or_refuses_by_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let admitted = WorkloadLaunch::build(&spec_with(&[]), "u", dir.path(), &[]).admit(
            nucleus::ContainmentMode::MicroVM,
            OPTED_IN,
            NO_WAIVER,
        );
        match nix_getuid() {
            0 => assert_eq!(
                admitted
                    .expect("a root runtime admits")
                    .confinement
                    .child_uid(),
                nucleus::ChildUid::Distinct(DEFAULT_WORKLOAD_UID)
            ),
            _ => {
                let refused = admitted.expect_err("a non-root runtime cannot separate");
                assert!(
                    refused.0.contains("child separation unavailable"),
                    "refused by name: {refused}"
                );
            }
        }
    }

    /// **Owner decision 1 (2026-10-02), at the admission.** Declaring the
    /// bare host tier is not enough for a workload to run at a non-root
    /// runtime's uid: without the explicit opt-in the admission refuses BY
    /// NAME, naming `--unsandboxed`. Red before the decision: `admit` took no
    /// opt-in and admitted it. A root runtime drops with or without one.
    #[test]
    fn a_bare_tier_workload_without_the_opt_in_is_refused_by_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let admitted = WorkloadLaunch::build(&spec_with(&[]), "u", dir.path(), &[]).admit(
            HARNESS,
            nucleus::UnsandboxedOptIn::Absent,
            NO_WAIVER,
        );
        match nix_getuid() {
            0 => assert_eq!(
                admitted
                    .expect("a root runtime drops")
                    .confinement
                    .child_uid(),
                nucleus::ChildUid::Distinct(DEFAULT_WORKLOAD_UID)
            ),
            _ => {
                let refused = admitted.expect_err("no opt-in, no same-uid workload");
                assert!(
                    refused.0.contains("unsandboxed execution not opted in")
                        && refused.0.contains("--unsandboxed"),
                    "refused by name: {refused}"
                );
            }
        }
    }

    /// An explicit uid equal to the runtime's own re-opens the /proc/environ
    /// hole and must be refused — in every mode, the bare tier included.
    #[test]
    fn admit_refuses_a_workload_sharing_the_runtime_uid() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut spec = spec_with(&[]);
        spec.uid = Some(nix_getuid());
        for mode in [
            nucleus::ContainmentMode::Unsandboxed,
            nucleus::ContainmentMode::HostHardened,
            nucleus::ContainmentMode::MicroVM,
        ] {
            let refused = WorkloadLaunch::build(&spec, "u", dir.path(), &[])
                .admit(mode, OPTED_IN, NO_WAIVER)
                .expect_err("a workload sharing the runtime uid must be refused");
            assert!(
                refused.0.contains("shares the runtime's uid"),
                "{mode:?}: {refused}"
            );
        }
    }

    /// A distinct explicit uid is honoured exactly, or refused — never
    /// silently replaced by the runtime's (the bare tier included: only the
    /// unset default may collapse to it).
    #[test]
    fn admit_honours_an_explicit_distinct_uid_or_refuses_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut spec = spec_with(&[]);
        let distinct = nix_getuid().wrapping_add(4242);
        spec.uid = Some(distinct);
        for mode in [
            nucleus::ContainmentMode::Unsandboxed,
            nucleus::ContainmentMode::MicroVM,
        ] {
            let admitted =
                WorkloadLaunch::build(&spec, "u", dir.path(), &[]).admit(mode, OPTED_IN, NO_WAIVER);
            match nix_getuid() {
                0 => assert_eq!(
                    admitted
                        .expect("a root runtime drops")
                        .confinement
                        .child_uid(),
                    nucleus::ChildUid::Distinct(distinct)
                ),
                _ => assert!(
                    admitted.is_err_and(|r| r.0.contains("child separation unavailable")),
                    "{mode:?}: an explicit uid a non-root runtime cannot honour is refused"
                ),
            }
        }
    }

    /// Spawn `/bin/sh -c 'id -u; cat /proc/<this pid>/environ | wc -c'` as a
    /// workload admitted under `mode`; `Err` is the admission's refusal.
    #[cfg(target_os = "linux")]
    async fn spawn_uid_probe(
        mode: nucleus::ContainmentMode,
        opt_in: nucleus::UnsandboxedOptIn,
    ) -> Result<(String, usize, LaunchReceipt), Refused> {
        let dir = tempfile::tempdir().unwrap();
        let mut spec = spec_with(&[]);
        spec.command = "/bin/sh".into();
        spec.args = vec![
            "-c".into(),
            format!(
                "id -u; cat /proc/{}/environ 2>/dev/null | wc -c",
                std::process::id()
            ),
        ];
        let plan = WorkloadLaunch::build(&spec, "http://127.0.0.1:8080", dir.path(), &[])
            .admit(mode, opt_in, NO_WAIVER)?;
        let (child, receipt) = spawn_admitted(plan, node_rlimits(), nothing_derived()).unwrap();
        let out = child.wait_with_output().await.unwrap();
        let text = String::from_utf8_lossy(&out.stdout).to_string();
        let mut lines = text.lines();
        let uid = lines.next().unwrap_or_default().trim().to_string();
        let environ_bytes = lines
            .next()
            .and_then(|l| l.trim().parse().ok())
            .expect("wc printed a count");
        Ok((uid, environ_bytes, receipt))
    }

    /// **#3120 item 2, on a real spawn.** A workload admitted for a guest
    /// (`MicroVM`) never runs at the runtime's uid and never reads its
    /// environment. Red on the parent commit, as uid 1001: admitted with
    /// `uid_boundary=distinct`, `id -u` printed 1001, and the workload read
    /// 2006 bytes of the runtime's environ. Each runtime uid asserts its own
    /// exact outcome.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_guest_workload_never_runs_at_the_runtimes_uid() {
        let runtime = nix_getuid();
        assert!(
            std::fs::read(format!("/proc/{}/environ", std::process::id()))
                .is_ok_and(|b| !b.is_empty()),
            "positive control: the runtime reads its own environ"
        );
        match (
            runtime,
            spawn_uid_probe(nucleus::ContainmentMode::MicroVM, OPTED_IN).await,
        ) {
            (0, Ok((uid, environ_bytes, receipt))) => {
                assert_eq!(uid, DEFAULT_WORKLOAD_UID.to_string());
                assert_eq!(environ_bytes, 0, "the dropped workload read the environ");
                assert_eq!(receipt.uid_boundary, UidBoundary::Distinct);
            }
            (0, Err(refused)) => panic!("a root runtime must drop, not refuse: {refused}"),
            (_, Ok((uid, environ_bytes, _))) => panic!(
                "a non-root runtime ran a guest workload as uid {uid} and it read \
                 {environ_bytes} bytes of the runtime's environ"
            ),
            (_, Err(refused)) => assert!(
                refused.0.contains("child separation unavailable"),
                "refused by name: {refused}"
            ),
        }
    }

    /// The declared bare host tier is the ONE same-uid outcome, and it says
    /// so: the receipt records `shared_unsandboxed`, not `distinct`, and the
    /// workload really can read the runtime's environ — the posture is what it
    /// claims, in both directions. A root runtime drops even here.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn the_bare_tier_runs_at_the_runtimes_uid_and_says_so() {
        let runtime = nix_getuid();
        let (uid, environ_bytes, receipt) = spawn_uid_probe(HARNESS, OPTED_IN)
            .await
            .expect("the declared bare tier admits the default uid");
        if runtime == 0 {
            assert_eq!(uid, DEFAULT_WORKLOAD_UID.to_string());
            assert_eq!(environ_bytes, 0);
            assert_eq!(receipt.uid_boundary, UidBoundary::Distinct);
        } else {
            assert_eq!(uid, runtime.to_string());
            assert!(environ_bytes > 0, "a same-uid workload reads the environ");
            assert_eq!(receipt.uid_boundary, UidBoundary::SharedUnsandboxed);
            assert_eq!(
                receipt.hardening,
                nucleus::SpawnHardening::Unhardened(nucleus::Unhardened::DeclaredBareTier),
                "the bare tier claims no hardening"
            );
        }
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
        // SAFETY: edition 2024 makes env mutation unsafe -- it races any concurrent
        // reader. Sound here because this runs before any thread that reads the
        // environment is spawned.
        #[expect(
            clippy::disallowed_methods,
            reason = "ADR 0007 H-1: test-only process-global mutation"
        )]
        unsafe {
            std::env::set_var("NUCLEUS_TOOL_PROXY_BROKER_SECRET", "leaked-capability")
        };
        // SAFETY: edition 2024 makes env mutation unsafe -- it races any concurrent
        // reader. Sound here because this runs before any thread that reads the
        // environment is spawned.
        #[expect(
            clippy::disallowed_methods,
            reason = "ADR 0007 H-1: test-only process-global mutation"
        )]
        unsafe {
            std::env::set_var("NUCLEUS_TOOL_PROXY_BROKER_PORT", "1027")
        };

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
            artifacts: Default::default(),
            args: vec!["-c".into(), script],
            uid: None,
            env: std::collections::BTreeMap::new(),
        };
        // Through the real path: build → admit → spawn_admitted. A plan that did
        // not classify-and-admit every entry could not be constructed.
        let plan = WorkloadLaunch::build(&spec, "http://127.0.0.1:8080", dir.path(), &[])
            .admit(HARNESS, OPTED_IN, NO_WAIVER)
            .expect("a clean spec must admit");
        let (mut child, receipt) =
            spawn_admitted(plan, node_rlimits(), nothing_derived()).expect("sh must be spawnable");
        let status = child.wait().await.expect("child ran");
        assert!(status.success(), "the child must actually run: {status:?}");
        let observed = std::fs::read_to_string(&f_env).expect("the child wrote its environment");

        // SAFETY: edition 2024 makes env mutation unsafe -- it races any concurrent
        // reader. Sound here because this runs before any thread that reads the
        // environment is spawned.
        #[expect(
            clippy::disallowed_methods,
            reason = "ADR 0007 H-1: test-only process-global mutation"
        )]
        unsafe {
            std::env::remove_var("NUCLEUS_TOOL_PROXY_BROKER_SECRET")
        };
        // SAFETY: edition 2024 makes env mutation unsafe -- it races any concurrent
        // reader. Sound here because this runs before any thread that reads the
        // environment is spawned.
        #[expect(
            clippy::disallowed_methods,
            reason = "ADR 0007 H-1: test-only process-global mutation"
        )]
        unsafe {
            std::env::remove_var("NUCLEUS_TOOL_PROXY_BROKER_PORT")
        };

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

        // The receipt reports the same inventory the admission checked: the
        // door URL is in it, so it is not the empty-environment vacuous case.
        assert!(
            receipt.env.iter().any(
                |e| e.key == "NUCLEUS_TOOL_PROXY_URL" && e.source == EnvSource::RuntimeInjected
            ),
            "the receipt must show the door URL the runtime injected: {receipt:?}"
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
        //
        // Only where the confinement sweeps fds: a dropped workload. Since
        // #3120 a non-root harness runs the workload on the declared,
        // opted-in bare tier, which sweeps nothing by design (it is not a uid
        // boundary either); the same `ChildConfinement` mechanism is asserted
        // on a non-root runtime by
        // `nucleus::command::tests::a_confined_child_inherits_no_fd_beyond_its_stdio`.
        #[cfg(target_os = "linux")]
        {
            if receipt.hardening.is_hardened() {
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
        let env = workload_env(&hostile, "http://127.0.0.1:8080", &[]);
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
        let env = workload_env(&spec_with(&[]), "http://127.0.0.1:8080", &[]);
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
            effects: nucleus_spec::EffectTable::unclassified(),
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

    use nucleus_ifc_kernel::extracted::identity::{MaterialKind, Principal, ident_may_deliver};

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
    /// may receive. The overlay used to carry one *Internal* key, the proxy's
    /// HMAC secret; since the workload door it carries none, and everything it
    /// injects is Public. The non-vacuity controls are the door URL and the
    /// egress channel, which must both be present.
    #[test]
    fn every_env_var_the_overlay_injects_is_model_deliverable_to_the_workload() {
        let env = workload_env(
            &spec_with(&[("ORDINARY", "1")]),
            "http://127.0.0.1:8080",
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
            env.contains_key("NUCLEUS_TOOL_PROXY_URL"),
            "non-vacuity: the overlay must name the workload's door"
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
        let env = workload_env(&spec_with(&[]), "http://127.0.0.1:8080", &[egress_spec()]);
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
    #[tokio::test]
    async fn environment_commitment_matches_the_admitted_child_environment() {
        let dir = tempfile::tempdir().unwrap();
        let mut spec = spec_with(&[("PATH", "/usr/bin:/bin"), ("BUILD_INPUT", "pinned")]);
        spec.command = "/usr/bin/env".into();
        spec.args.clear();
        let plan = WorkloadLaunch::build(&spec, "http://127.0.0.1:8080", dir.path(), &[])
            .admit(HARNESS, OPTED_IN, NO_WAIVER)
            .unwrap();
        let (child, receipt) = spawn_admitted(plan, node_rlimits(), nothing_derived()).unwrap();
        let output = child.wait_with_output().await.unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        let actual: BTreeMap<String, String> = text
            .lines()
            .map(|line| {
                let (key, value) = line.split_once('=').unwrap();
                (key.to_owned(), value.to_owned())
            })
            .collect();
        assert_eq!(
            receipt.environment,
            nucleus_spec::workload_result::EnvironmentIdentity::of(&actual)
        );
    }
}
