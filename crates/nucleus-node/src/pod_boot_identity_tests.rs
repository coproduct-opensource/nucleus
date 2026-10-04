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
        "metadata": {"name": "host-spec-before-vmm"}, "spec": pod_spec,
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
    let api = dir.path().join(format!("vsock_{}", st.identity_vsock_port));
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
    st.broker_enforcing = true;
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
        matches!(result, Err(crate::ApiError::Driver(ref e)) if e.contains("bakes the pod spec"))
    );
    let api = dir.path().join(format!("vsock_{}", st.identity_vsock_port));
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
async fn ask(st: &NodeState, dir: &std::path::Path, line: &[u8]) -> String {
    let api = dir.join(format!("vsock_{}", st.identity_vsock_port));
    let mut stream = tokio::net::UnixStream::connect(&api).await.unwrap();
    stream.write_all(line).await.unwrap();
    let mut response = String::new();
    tokio::io::BufReader::new(stream)
        .read_line(&mut response)
        .await
        .unwrap();
    response
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
        let reply = ask(&st, dir.path(), b"FETCH_AUDIT_CREDENTIALS\n").await;
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
