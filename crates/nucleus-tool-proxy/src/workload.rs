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
#[must_use]
pub(crate) fn workload_env(
    spec: &WorkloadSpec,
    proxy_url: &str,
    auth_secret: &str,
) -> BTreeMap<String, String> {
    let mut env = spec.env.clone();
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
) -> std::io::Result<tokio::process::Child> {
    let mut cmd = tokio::process::Command::new(&spec.command);
    cmd.args(&spec.args)
        .current_dir(work_dir)
        .kill_on_drop(true);
    for (k, v) in workload_env(spec, proxy_url, auth_secret) {
        cmd.env(k, v);
    }
    tracing::info!(
        command = %spec.command,
        args = ?spec.args,
        "starting pod workload under mediation"
    );
    cmd.spawn()
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
    spawn_workload(w, &url, auth_secret, &spec.spec.work_dir)
        .map(Some)
        .map_err(|e| {
            crate::ApiError::Spec(format!("failed to start workload {:?}: {e}", w.command))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec_with(env: &[(&str, &str)]) -> WorkloadSpec {
        WorkloadSpec {
            command: "agent".into(),
            args: vec!["--flag".into()],
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
        let env = workload_env(&spec_with(&[]), "http://127.0.0.1:8080", "s3cret");
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
        let env = workload_env(&hostile, "http://127.0.0.1:8080", "s3cret");
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

    /// The control: ordinary spec env still reaches the workload, so the
    /// precedence above is not simply discarding what the spec asked for.
    #[test]
    fn ordinary_spec_env_is_passed_through() {
        let env = workload_env(
            &spec_with(&[("MODEL_ENDPOINT", "https://example.invalid")]),
            "u",
            "s",
        );
        assert_eq!(
            env.get("MODEL_ENDPOINT").map(String::as_str),
            Some("https://example.invalid")
        );
    }
}
