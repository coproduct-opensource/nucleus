use crate::pod_boot_identity::{self, Inputs};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

async fn prepare_for_test(
    st: &NodeState,
    dir: &std::path::Path,
    id: uuid::Uuid,
    socket: &std::path::Path,
) -> Result<pod_boot_identity::PreparedIdentity, crate::ApiError> {
    prepare_pod_for_test(st, dir, id, socket, serde_json::json!({}), None).await
}

async fn prepare_pod_for_test(
    st: &NodeState,
    dir: &std::path::Path,
    id: uuid::Uuid,
    socket: &std::path::Path,
    pod_spec: serde_json::Value,
    audit_creds: Option<crate::workload_api_vsock::AuditCredentials>,
) -> Result<pod_boot_identity::PreparedIdentity, crate::ApiError> {
    prepare_labelled_for_test(
        st,
        dir,
        id,
        socket,
        pod_spec,
        audit_creds,
        serde_json::json!({}),
    )
    .await
}

async fn prepare_labelled_for_test(
    st: &NodeState,
    dir: &std::path::Path,
    id: uuid::Uuid,
    socket: &std::path::Path,
    pod_spec: serde_json::Value,
    audit_creds: Option<crate::workload_api_vsock::AuditCredentials>,
    labels: serde_json::Value,
) -> Result<pod_boot_identity::PreparedIdentity, crate::ApiError> {
    let kernel = dir.join("kernel");
    let rootfs = dir.join("rootfs");
    std::fs::write(&kernel, b"test kernel").unwrap();
    std::fs::write(&rootfs, b"test rootfs").unwrap();
    let image: nucleus_spec::ImageSpec = serde_json::from_value(serde_json::json!({
        "kernel_path": kernel, "rootfs_path": rootfs,
    }))
    .unwrap();
    let spec: nucleus_spec::PodSpec = serde_json::from_value(serde_json::json!({
        "apiVersion": "nucleus/v1", "kind": "Pod",
        "metadata": {"name": "host-spec-before-vmm", "labels": labels}, "spec": pod_spec,
    }))
    .unwrap();
    let (serve, _verify) = crate::broker_launch::BrokerCapability::mint(id);
    pod_boot_identity::prepare(Inputs {
        state: st,
        pod_dir: dir,
        spec: &spec,
        image: &crate::rootfs_source::HostImage::resolve(&image).unwrap(),
        id,
        grant: &crate::net::IdentityGrant::Granted,
        vsock_path: socket,
        jail_owner: None,
        task_token: None,
        pod_certificate: None,
        broker_serve: serve,
        audit_creds,
        // Nothing was verified in this test, so nothing was measured. `Measured::default()`
        // is both `None`, which makes the attestation hash the files itself -- the honest
        // reading of "no pinned artifact was read".
        measured: crate::image_identity::Measured::default(),
    })
    .await
}

#[tokio::test]
async fn host_spec_is_served_before_spawn_and_launch_error_releases_identity() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let mut st = state(&dir);
    let manager =
        crate::identity::IdentityManager::new("test.local", std::time::Duration::from_secs(3600))
            .unwrap();
    st.identity_manager = Some(manager.clone());
    let id = uuid::Uuid::new_v4();
    let socket = dir.path().join("vsock");
    let ready = prepare_for_test(&st, dir.path(), id, &socket)
        .await
        .unwrap();
    let api = dir.path().join(format!("vsock_{}", crate::workload_api_vsock::DEFAULT_WORKLOAD_API_PORT));
    let mut stream = tokio::net::UnixStream::connect(&api).await.unwrap();
    stream.write_all(b"FETCH_POD_SPEC\n").await.unwrap();
    let mut response = String::new();
    tokio::io::BufReader::new(stream)
        .read_line(&mut response)
        .await
        .unwrap();
    assert!(response.contains("host-spec-before-vmm"), "{response}");
    assert!(manager.get_attestation(&id.to_string()).await.is_some());
    let spec = serde_json::from_value(serde_json::json!({
        "apiVersion": "nucleus/v1", "kind": "Pod",
        "metadata": {"name": "spawn-control"}, "spec": {},
    }))
    .unwrap();
    let ready = ready
        .with_broker(
            &st,
            &spec,
            &socket,
            id,
            crate::broker_launch::BrokerCapability::mint(id).1,
            None,
        )
        .await
        .unwrap()
        .with_network_meter(None)
        .await
        .unwrap();
    // A failure at the actual spawn call must clean both serving and registry.
    let mut command = tokio::process::Command::new(dir.path().join("missing-vmm"));
    assert!(ready.spawn(&mut command).is_err());
    drop(ready);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while api.exists() || manager.get_attestation(&id.to_string()).await.is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!manager.unregister_pod(&id.to_string()).await);
}

#[tokio::test]
async fn enforcing_broker_refusal_cleans_identity_before_spawn_is_available() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let mut st = state(&dir);
    st.broker_enforcing = crate::broker_rollout::HostSpecEnforcement::Required;
    let manager =
        crate::identity::IdentityManager::new("test.local", std::time::Duration::from_secs(3600))
            .unwrap();
    st.identity_manager = Some(manager.clone());
    let id = uuid::Uuid::new_v4();
    let socket = dir.path().join("vsock");
    let ready = prepare_for_test(&st, dir.path(), id, &socket)
        .await
        .unwrap();
    let spec = serde_json::from_value(serde_json::json!({
        "apiVersion": "nucleus/v1", "kind": "Pod",
        "metadata": {"name": "enforcing-refusal"},
        "spec": {"vsock": {"guest_cid": 3, "port": 5005}},
    }))
    .unwrap();
    let result = ready
        .with_broker(
            &st,
            &spec,
            &socket,
            id,
            crate::broker_launch::BrokerCapability::mint(id).1,
            None,
        )
        .await;
    assert!(
        matches!(result, Err(crate::ApiError::Driver(ref e)) if e.contains("this node issued the pod no certificate"))
    );
    let api = dir.path().join(format!("vsock_{}", crate::workload_api_vsock::DEFAULT_WORKLOAD_API_PORT));
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while api.exists() || manager.get_attestation(&id.to_string()).await.is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!manager.unregister_pod(&id.to_string()).await);
}

#[tokio::test]
async fn dropping_a_spawned_child_during_launch_terminates_the_process() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let st = state(&dir);
    let id = uuid::Uuid::new_v4();
    let socket = dir.path().join("vsock");
    let identity = prepare_for_test(&st, dir.path(), id, &socket)
        .await
        .unwrap();
    let spec = serde_json::from_value(serde_json::json!({
        "apiVersion": "nucleus/v1", "kind": "Pod",
        "metadata": {"name": "child-cleanup"}, "spec": {},
    }))
    .unwrap();
    let ready = identity
        .with_broker(
            &st,
            &spec,
            &socket,
            id,
            crate::broker_launch::BrokerCapability::mint(id).1,
            None,
        )
        .await
        .unwrap()
        .with_network_meter(None)
        .await
        .unwrap();
    let mut command = tokio::process::Command::new("/bin/sleep");
    command.arg("60");
    let child = ready.spawn(&mut command).unwrap();
    let pid = child.id().unwrap().to_string();
    let alive = |pid: &str| {
        std::process::Command::new("/bin/kill")
            .args(["-0", pid])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success()
    };
    assert!(alive(&pid), "control: child really started");
    drop(child);
    let stopped = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while alive(&pid) {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await;
    if stopped.is_err() {
        let _ = std::process::Command::new("/bin/kill")
            .args(["-KILL", &pid])
            .status();
    }
    assert!(stopped.is_ok(), "failed launch left child {pid} running");
}

/// Ask a prepared pod's workload API one line, as guest-init does, and return the reply.
async fn ask(dir: &std::path::Path, line: &[u8]) -> String {
    let api = dir.join(format!("vsock_{}", crate::workload_api_vsock::DEFAULT_WORKLOAD_API_PORT));
    let mut stream = tokio::net::UnixStream::connect(&api).await.unwrap();
    stream.write_all(line).await.unwrap();
    let mut response = String::new();
    tokio::io::BufReader::new(stream)
        .read_line(&mut response)
        .await
        .unwrap();
    response
}

#[tokio::test]
async fn enforced_host_spec_withholds_values_but_preserves_the_workload() {
    for enforcing in [false, true] {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let mut st = state(&dir);
        st.broker_enforcing = if enforcing {
            crate::broker_rollout::HostSpecEnforcement::Required
        } else {
            crate::broker_rollout::HostSpecEnforcement::Disabled(
                crate::broker_rollout::EnforcementDisabled::OperatorOptOut,
            )
        };
        st.identity_manager = Some(
            crate::identity::IdentityManager::new(
                "test.local",
                std::time::Duration::from_secs(3600),
            )
            .unwrap(),
        );
        let socket = dir.path().join("vsock");
        let _ready = prepare_pod_for_test(
            &st,
            dir.path(),
            uuid::Uuid::new_v4(),
            &socket,
            serde_json::json!({
                "credentials": {"env": {"LLM_API_TOKEN": "test-secret-not-for-guest"}},
                "workload": {"command": "/usr/bin/build-agent", "args": ["fix", "issue-7"]},
            }),
            None,
        )
        .await
        .unwrap();
        let response = ask(dir.path(), b"FETCH_POD_SPEC\n").await;
        let value: serde_json::Value = serde_json::from_str(&response).unwrap();
        let served: nucleus_spec::PodSpec =
            serde_yaml::from_str(value["spec"].as_str().expect("spec served")).unwrap();
        let credentials = served.spec.credentials.unwrap();
        if enforcing {
            assert!(
                !response.contains("test-secret-not-for-guest"),
                "credential reached the guest"
            );
            assert_eq!(credentials.env["LLM_API_TOKEN"], "");
        } else {
            assert_eq!(
                credentials.env["LLM_API_TOKEN"],
                "test-secret-not-for-guest"
            );
        }
        let workload = served.spec.workload.unwrap();
        assert_eq!(workload.command, "/usr/bin/build-agent");
        assert_eq!(workload.args, ["fix", "issue-7"]);
    }
}

/// #3160, the microVM driver. guest-init asks for the audit-sink credentials once, before the
/// workload exists, and exports what it gets to the tool-proxy. Red on #3155's head, which served
/// the node's own ambient key to every pod whose spec named an audit sink.
///
/// Both halves: a pod with a grant is served the minted credential and nothing of the node's; a
/// pod whose spec names a sink but that reached the bridge with no grant is served nothing.
#[tokio::test]
async fn the_ambient_key_is_never_served_to_a_guest() {
    use crate::audit_sink::credentials::fake;
    crate::audit_sink::ambient_fixture::plant();
    let grant = fake::grant(fake::target()).await;
    for creds in [Some(grant.served_credentials()), None] {
        let minted = creds.is_some();
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        let mut st = state(&dir);
        st.identity_manager = Some(
            crate::identity::IdentityManager::new(
                "test.local",
                std::time::Duration::from_secs(3600),
            )
            .unwrap(),
        );
        let socket = dir.path().join("vsock");
        let _ready = prepare_pod_for_test(
            &st,
            dir.path(),
            uuid::Uuid::new_v4(),
            &socket,
            serde_json::json!({"audit_sink": {"sink": "audit"}}),
            creds,
        )
        .await
        .unwrap();
        let reply = ask(dir.path(), b"FETCH_AUDIT_CREDENTIALS\n").await;
        assert!(
            !crate::audit_sink::ambient_fixture::leaks(&reply),
            "the node's ambient key was served to the guest (minted: {minted})"
        );
        if minted {
            // Non-vacuity: the reply is a credential, and it is the minted one.
            assert!(
                reply.contains(fake::MINTED_KEY_ID),
                "{minted}: no minted key served"
            );
            assert!(
                reply.contains(fake::MINTED_SECRET),
                "{minted}: no minted secret served"
            );
        } else {
            assert!(
                reply.contains("no audit credentials provisioned"),
                "a pod without a grant is told so: {reply}"
            );
        }
    }
}

#[tokio::test]
async fn unavailable_workload_api_refuses_before_vmm_spawn() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let mut st = state(&dir);
    st.identity_manager = Some(
        crate::identity::IdentityManager::new("test.local", std::time::Duration::from_secs(3600))
            .unwrap(),
    );
    let blocker = dir.path().join("file-not-directory");
    std::fs::write(&blocker, b"occupied").unwrap();
    let error = match prepare_for_test(
        &st,
        dir.path(),
        uuid::Uuid::new_v4(),
        &blocker.join("vsock"),
    )
    .await
    {
        Ok(_) => panic!("missing listener cannot authorize VMM spawn"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("workload API must be ready before VMM spawn"),
        "{error}"
    );
}

/// A Firecracker guest is served its own id and NO caller token. The token
/// authenticates only at the node's HTTP listener, which a Firecracker guest
/// cannot reach, so in the VM it would be an unconsumed bearer secret. Red on
/// main before this change, which served `derive_token(caller_secret, id)` here.
///
/// The reply keeps an empty `caller_token` string because every supported
/// guest-init (2.4.0 to 2.7.0) exports `NUCLEUS_POD_ID` only alongside one. So
/// this also pins that the id still arrives, and that it is this pod's.
#[tokio::test]
async fn a_firecracker_guest_is_served_its_id_and_no_caller_token() {
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let mut st = state(&dir);
    st.identity_manager = Some(
        crate::identity::IdentityManager::new("test.local", std::time::Duration::from_secs(3600))
            .unwrap(),
    );
    let id = uuid::Uuid::new_v4();
    let socket = dir.path().join("vsock");
    let _ready = prepare_for_test(&st, dir.path(), id, &socket)
        .await
        .unwrap();
    let reply = ask(dir.path(), b"FETCH_POD_CALLER_TOKEN\n").await;
    let value: serde_json::Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(
        value["caller_token"].as_str(),
        Some(""),
        "a Firecracker guest was served a caller token: {reply}"
    );
    let derived = crate::pod_caller_identity::derive_token(st.caller_secret.as_ref(), id);
    assert!(
        !reply.contains(&derived),
        "the derived caller token reached the guest: {reply}"
    );
    assert_eq!(value["pod_id"].as_str(), Some(id.to_string().as_str()));
}

/// A CA that signs only plainly: it takes `CaClient`'s default `sign_attested_csr`,
/// which drops the launch extension. What an injected CA that never opted in issues.
struct PlainOnlyCa(nucleus_identity::SelfSignedCa);

#[async_trait::async_trait]
impl nucleus_identity::CaClient for PlainOnlyCa {
    async fn sign_csr(
        &self,
        csr: &str,
        private_key: &str,
        identity: &nucleus_identity::Identity,
        ttl: std::time::Duration,
    ) -> nucleus_identity::Result<nucleus_identity::WorkloadCertificate> {
        self.0.sign_csr(csr, private_key, identity, ttl).await
    }

    async fn sign_csr_only(
        &self,
        csr: &str,
        identity: &nucleus_identity::Identity,
        ttl: std::time::Duration,
    ) -> nucleus_identity::Result<String> {
        self.0.sign_csr_only(csr, identity, ttl).await
    }

    fn trust_bundle(&self) -> &nucleus_identity::TrustBundle {
        self.0.trust_bundle()
    }

    fn trust_domain(&self) -> &str {
        self.0.trust_domain()
    }
}

fn eval_cell_label() -> serde_json::Value {
    serde_json::json!({ (nucleus_spec::isolation_profile::PROFILE_LABEL): "eval-cell" })
}

async fn prepare_profiled(
    st: &NodeState,
    dir: &std::path::Path,
    labels: serde_json::Value,
) -> Result<pod_boot_identity::PreparedIdentity, crate::ApiError> {
    let id = uuid::Uuid::new_v4();
    let socket = dir.join(format!("vsock-{id}"));
    prepare_labelled_for_test(
        st,
        dir,
        id,
        &socket,
        serde_json::json!({}),
        None,
        labels,
    )
    .await
}

/// ADR 0016 D3, wired: at boot an eval cell is served only a launch that
/// verifies, and each fallback a standard pod keeps is a refusal for it, by name.
/// Non-vacuous: the same eval cell on a node whose CA attests is prepared, and a
/// standard pod is prepared on every node.
#[tokio::test]
async fn an_eval_cell_boots_only_with_a_launch_that_verifies() {
    // No identity manager: the node issues no SVID at all.
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let st = state(&dir);
    let refused = match prepare_profiled(&st, dir.path(), eval_cell_label()).await {
        Ok(_) => panic!("an eval cell booted with no workload identity"),
        Err(e) => e.to_string(),
    };
    assert!(refused.contains("launch does not verify"), "{refused}");
    assert!(refused.contains("no workload identity"), "{refused}");
    prepare_profiled(&st, dir.path(), serde_json::json!({}))
        .await
        .expect("a standard pod boots without an identity, as before");

    // A CA that signs plainly: the SVID carries no launch.
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let mut st = state(&dir);
    let plain: std::sync::Arc<dyn nucleus_identity::CaClient> = std::sync::Arc::new(PlainOnlyCa(
        nucleus_identity::SelfSignedCa::new("test.local").unwrap(),
    ));
    st.identity_manager = Some(crate::identity::IdentityManager::with_ca(
        "test.local",
        std::time::Duration::from_secs(3600),
        plain,
    ));
    let refused = match prepare_profiled(&st, dir.path(), eval_cell_label()).await {
        Ok(_) => panic!("an eval cell booted with a plain SVID"),
        Err(e) => e.to_string(),
    };
    assert!(refused.contains("launch does not verify"), "{refused}");
    assert!(refused.contains("no parseable launch attestation"), "{refused}");
    prepare_profiled(&st, dir.path(), serde_json::json!({}))
        .await
        .expect("a standard pod keeps the plain-SVID fallback");

    // A CA that attests: the eval cell is prepared.
    let dir = tempfile::tempdir_in("/tmp").unwrap();
    let mut st = state(&dir);
    st.identity_manager = Some(
        crate::identity::IdentityManager::new("test.local", std::time::Duration::from_secs(3600))
            .unwrap(),
    );
    prepare_profiled(&st, dir.path(), eval_cell_label())
        .await
        .expect("an eval cell whose launch verifies boots");
}
