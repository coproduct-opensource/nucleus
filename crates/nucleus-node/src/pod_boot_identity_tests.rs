use crate::pod_boot_identity::{self, Inputs};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

async fn prepare_for_test(
    st: &NodeState,
    dir: &std::path::Path,
    id: uuid::Uuid,
    socket: &std::path::Path,
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
        "metadata": {"name": "host-spec-before-vmm"}, "spec": {},
    }))
    .unwrap();
    let (serve, _verify) = crate::broker_launch::BrokerCapability::mint(id);
    pod_boot_identity::prepare(Inputs {
        state: st,
        pod_dir: dir,
        spec: &spec,
        image: &image,
        id,
        grant: &crate::net::IdentityGrant::Granted,
        vsock_path: socket,
        jail_owner: None,
        task_token: None,
        pod_certificate: None,
        broker_serve: serve,
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
