use crate::*;

/// The environment a container pod is started with.
///
/// Split out of [`spawn_container_pod`] so what reaches the container's
/// tool-proxy can be read by a test without a Docker daemon: every other half
/// of that function needs one.
pub(crate) async fn container_env(
    state: &NodeState,
    spec: &PodSpec,
    id: Uuid,
    sandbox_token: &str,
    spec_yaml: &str,
    audit: Option<&audit_sink::credentials::AuditGrant>,
    memory: Option<&memory_provisioning::Grant>,
) -> Vec<String> {
    let mut env: Vec<String> = vec![format!("NUCLEUS_SANDBOX_TOKEN={sandbox_token}")];
    let proxy_mode = state.container_mediation.runs_tool_proxy();

    if proxy_mode {
        if let Some(grant) = memory {
            env.extend(grant.container_env());
        }
        // The transport's entries, approval authority included: a public key on the socket,
        // the shared secret only on the deprecated `tcp-hmac` transport.
        env.extend(container_transport::proxy_env(state));
        env.push("NUCLEUS_TOOL_PROXY_AUDIT_LOG=/data/pod/audit.log".to_string());
        art12_collector::provision_container_env(&mut env);

        // The audit sink admission resolved against the operator's `--audit-sinks` (#3131), and
        // the credential minted for exactly that destination (#3160). A container inherits
        // nothing from the node, so this is the only credential its uploader holds.
        if let Some(grant) = audit {
            for (key, value) in grant.proxy_env() {
                env.push(format!("{key}={value}"));
            }
        }

        // Live-path session capability token (see spawn_local_pod). Injected in
        // proxy mode — the only container mode that runs the tool-proxy sidecar.
        if let Some(minted) = pod_authority::mint_task_token_for_spec(state, spec, id).await {
            env.push(format!("NUCLEUS_TASK_TOKEN={}", minted.token_json));
            env.push(format!("NUCLEUS_TASK_TOKEN_NONCE={}", minted.nonce_hex));
            env.push(format!("NUCLEUS_TASK_TOKEN_ISSUER={}", minted.issuer_hex));
        }
        for (key, value) in state.authority.boot_env(id).await {
            env.push(format!("{key}={value}"));
        }
        // DLC-D verified admission from the PodSpec labels, through the same
        // declaration the local driver and the Firecracker workload API use.
        // This driver used to have no copy of the mapping at all, so a
        // container pod's dlc_* labels were accepted, listed by `nucleus node
        // pods`, and never reached the tool-proxy that enforces them (#2903).
        if let Some(dlc) = DlcProvisioning::from_labels(&spec.metadata.labels) {
            env.extend(dlc.env().map(|(key, value)| format!("{key}={value}")));
        }
    }

    // Pass credentials from PodSpec (if any)
    if let Some(ref creds) = spec.spec.credentials {
        for (key, val) in &creds.env {
            env.push(format!("{key}={val}"));
        }
    }

    // In direct mode, extract the task from the raw YAML (task is not in the typed
    // PodSpec struct — it's a free-form field that the tool-proxy/agent reads from YAML).
    if !proxy_mode
        && let Ok(raw) = serde_yaml::from_str::<serde_json::Value>(spec_yaml)
        && let Some(task) = raw
            .get("spec")
            .and_then(|s| s.get("task"))
            .and_then(|t| t.as_str())
    {
        env.push(format!("NUCLEUS_TASK={task}"));
    }
    env
}
