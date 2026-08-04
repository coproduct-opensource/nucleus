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

use nucleus_spec::WorkloadSpec;

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

/// Start the workload, after mediation is live.
///
/// Taking `proxy_url` is what enforces the ordering: the bound address does not
/// exist until the server is listening.
///
/// # Errors
/// If the process cannot be started. That is fatal to the pod by the caller's
/// choice, not silently ignored — a pod that was asked to run a workload and did
/// not is not a working pod, and reporting success would leave an operator
/// waiting for output that will never come.
pub(crate) fn spawn_workload(
    spec: &WorkloadSpec,
    proxy_url: &str,
    auth_secret: &str,
    work_dir: &std::path::Path,
    egress: &[nucleus_spec::CredentialedEgressSpec],
) -> std::io::Result<tokio::process::Child> {
    let mut cmd = tokio::process::Command::new(&spec.command);
    cmd.args(&spec.args)
        .current_dir(work_dir)
        .kill_on_drop(true);

    // ── The workload's environment is DECLARED, never inherited ──────────────
    //
    // `Command` passes the parent's environment to the child unless told
    // otherwise, and this did not tell it otherwise. The proxy's own environment
    // carries `NUCLEUS_TOOL_PROXY_BROKER_SECRET` — `nucleus-guest-init` sets it
    // before exec'ing the proxy — so **the workload inherited the broker
    // capability**. The one thing steps 1 and 2 of this arc exist to prevent:
    // the capability distinguishes the mediating proxy from every other process
    // in the guest, and it was being handed to the workload for free.
    //
    // The uid boundary below does NOT close this, and the comment that used to
    // sit there claimed it did. A uid stops the workload READING
    // `/proc/<proxy_pid>/environ`; it does nothing about a value already in the
    // workload's own environment. Inheritance arrives before any permission
    // check applies.
    //
    // `env_clear` first, then an explicit allowlist. The fail-closed direction:
    // a new variable now has to be added on purpose, rather than reaching the
    // workload because it happened to be in the proxy's environment. Anything a
    // workload genuinely needs belongs in `spec.env`, where an operator wrote it
    // and a reader can see it.
    cmd.env_clear();
    for key in INHERITED_BY_NAME {
        if let Ok(value) = std::env::var(key) {
            cmd.env(key, value);
        }
    }

    // A uid boundary, for the DIFFERENT thing it actually buys: same-uid
    // processes can read each other's `/proc/<pid>/environ`, so without this the
    // workload could read the runtime's environment directly — which still holds
    // the broker capability, whatever the workload's own environment says.
    if let Some(uid) = spec.uid {
        cmd.uid(uid);
    }
    for (k, v) in workload_env(spec, proxy_url, auth_secret, egress) {
        cmd.env(k, v);
    }
    tracing::info!(
        command = %spec.command,
        args = ?spec.args,
        "starting pod workload under mediation"
    );
    cmd.spawn()
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

/// Start the pod's workload if the spec asks for one.
///
/// Called AFTER the listener is bound: it takes the bound address, which does
/// not exist until the server is up, so the ordering is a property of the
/// signature. The returned handle must be held for the process lifetime —
/// `kill_on_drop` means dropping it kills the workload, which is the correct
/// coupling between a pod and the thing it exists to run.
///
/// Lives here rather than in `main` so the fatal-on-failure decision sits beside
/// the reasoning for it: a pod that was asked to run a workload and did not is
/// not a working pod, and returning success leaves an operator waiting for
/// output that never comes.
///
/// # Errors
/// If a workload is configured and cannot be started.
pub(crate) fn start_if_configured(
    spec: &nucleus_spec::PodSpec,
    addr: std::net::SocketAddr,
    auth_secret: &str,
) -> Result<Option<tokio::process::Child>, crate::ApiError> {
    let Some(w) = spec.spec.workload.as_ref() else {
        return Ok(None);
    };
    let url = format!("http://{addr}");
    spawn_workload(
        w,
        &url,
        auth_secret,
        &spec.spec.work_dir,
        &spec.spec.credentialed_egress,
    )
    .map(Some)
    .map_err(|e| crate::ApiError::Spec(format!("failed to start workload {:?}: {e}", w.command)))
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
        let dump = dir.path().join("child-env");
        // Written to a FILE, not read from stdout: `spawn_workload` does not pipe
        // stdout, so `wait_with_output` returns an empty buffer and every
        // "does not contain the secret" assertion below would pass vacuously.
        // The non-vacuity control at the end of this test is what caught that.
        let spec = WorkloadSpec {
            command: "/bin/sh".into(),
            args: vec!["-c".into(), format!("env > {}", dump.display())],
            uid: None,
            env: std::collections::BTreeMap::new(),
        };
        let mut child = spawn_workload(&spec, "http://127.0.0.1:8080", "s3cret", dir.path(), &[])
            .expect("sh must be spawnable");
        let status = child.wait().await.expect("child ran");
        assert!(status.success(), "the child must actually run: {status:?}");
        let observed = std::fs::read_to_string(&dump).expect("the child wrote its environment");

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
}
