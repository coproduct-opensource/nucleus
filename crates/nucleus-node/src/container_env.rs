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
    spec_yaml: &str,
    audit: Option<&audit_sink::credentials::AuditGrant>,
    memory: Option<&memory_provisioning::Grant>,
) -> Vec<String> {
    // No sandbox token: the tier-3 proof it carried is deleted (#2446 step 3), and the
    // proxy's proof is the identity files `spawn_container_pod` provisions.
    let mut env: Vec<String> = Vec::new();
    let proxy_mode = state.container_mediation.runs_tool_proxy();

    if proxy_mode {
        if let Some(grant) = memory {
            env.extend(grant.container_env());
        }
        // The socket transport's entries, approval authority included: the node's public key.
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
        // DLC-D verified admission as admission recorded it (the labels', else the
        // node's own), the value the host's kernel decides with; the same record
        // the local driver and the Firecracker workload API deliver.
        // This driver used to have no copy of the mapping at all, so a
        // container pod's dlc_* labels were accepted, listed by `nucleus node
        // pods`, and never reached the tool-proxy that enforces them (#2903).
        if let Some(dlc) = state.authority.dlc(id).await {
            env.extend(dlc.env().map(|(key, value)| format!("{key}={value}")));
        }
        // Owner-decision material, bind-mounted read-only beside it (`decision_provisioning`).
        if let Some(decisions) = &state.decisions {
            env.extend(decisions.container_env());
        }
    }

    // No credential VALUE reaches a container's environment (#2906): `docker inspect`,
    // `/proc/<pid>/environ` and every child read it there. A mediated pod's credentialed calls
    // are the host broker's (`container_broker`), and `spec_posture::admit` refuses a container
    // spec carrying any `credentials.env` key but the unmediated task runner, which is a command
    // and is read here by name, for the one mode that runs it.
    if !proxy_mode
        && let Some(runner) = spec
            .spec
            .credentials
            .as_ref()
            .and_then(|creds| creds.env.get(container_broker::TASK_RUNNER))
    {
        env.push(format!("{}={runner}", container_broker::TASK_RUNNER));
    }

    // In direct mode, extract the task from the raw YAML (task is not in the typed
    // PodSpec struct — it's a free-form field that the tool-proxy/agent reads from YAML).
    if !proxy_mode
        && let Ok(raw) = nucleus_yaml::from_str::<serde_json::Value>(spec_yaml)
        && let Some(task) = raw
            .get("spec")
            .and_then(|s| s.get("task"))
            .and_then(|t| t.as_str())
    {
        env.push(format!("NUCLEUS_TASK={task}"));
    }
    env
}
