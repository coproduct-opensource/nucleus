//! Drain this state directory's old containers before serving new admissions.
//! Runtime authorization history is not resumable, so recovery stops workloads
//! instead of assigning a fresh budget to processes from a previous node life.
use std::{collections::HashMap, path::Path};

use bollard::{
    Docker,
    models::ContainerSummary,
    query_parameters::{ListContainersOptions, RemoveContainerOptions},
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ApiError;

const OWNER: &str = "io.nucleus.node-state";
const POD: &str = "io.nucleus.pod-id";

fn owner(state_dir: &Path) -> Result<String, ApiError> {
    let path = state_dir.canonicalize()?;
    Ok(hex::encode(Sha256::digest(
        path.as_os_str().as_encoded_bytes(),
    )))
}

pub(crate) fn labels(state_dir: &Path, id: Uuid) -> Result<HashMap<String, String>, ApiError> {
    Ok(HashMap::from([
        (OWNER.into(), owner(state_dir)?),
        (POD.into(), id.to_string()),
    ]))
}

fn owned_pod(
    container: &ContainerSummary,
    pods: &Path,
    owner: &str,
) -> Result<Option<Uuid>, ApiError> {
    if let Some(marked_owner) = container
        .labels
        .as_ref()
        .and_then(|labels| labels.get(OWNER))
    {
        if marked_owner != owner {
            return Ok(None);
        }
        return container
            .labels
            .as_ref()
            .and_then(|labels| labels.get(POD))
            .and_then(|id| Uuid::parse_str(id).ok())
            .map(Some)
            .ok_or_else(|| ApiError::Driver("owned container has no valid pod identity".into()));
    }
    // Upgrade path for older unlabelled containers. The node has always bound
    // its own <state>/pods/<uuid> at this exact destination before create.
    for mount in container.mounts.iter().flatten() {
        if mount.typ.as_deref() != Some("bind") || mount.destination.as_deref() != Some("/data/pod")
        {
            continue;
        }
        let Some(source) = mount.source.as_deref().map(Path::new) else {
            continue;
        };
        if source.parent() != Some(pods) {
            continue;
        }
        let Some(id) = source
            .file_name()
            .and_then(|v| v.to_str())
            .and_then(|v| Uuid::parse_str(v).ok())
        else {
            continue;
        };
        if source.join("pod.yaml").is_file() {
            return Ok(Some(id));
        }
    }
    Ok(None)
}

/// Caller holds the state-directory lock and has not opened any API listeners.
/// Removal leaves host bind-mounted workspaces, logs and artifacts intact.
pub(crate) async fn drain(
    docker: &Docker,
    state_dir: &Path,
    authority: &crate::pod_authority::PodAuthority,
) -> Result<(), ApiError> {
    crate::container_intent::recover(docker, state_dir, authority).await?;
    let owner = owner(state_dir)?;
    let pods = state_dir.canonicalize()?.join("pods");
    let containers = docker
        .list_containers(Some(ListContainersOptions {
            all: true,
            ..Default::default()
        }))
        .await
        .map_err(|e| ApiError::Driver(format!("list containers for node recovery: {e}")))?;
    for container in containers {
        let Some(pod) = owned_pod(&container, &pods, &owner)? else {
            continue;
        };
        let id = container
            .id
            .filter(|id| !id.is_empty())
            .ok_or_else(|| ApiError::Driver("owned container has no Docker ID".into()))?;
        match docker
            .remove_container(
                &id,
                Some(RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await
        {
            Ok(())
            | Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => {}
            Err(error) => {
                return Err(ApiError::Driver(format!(
                    "container recovery could not remove {id}; refusing new admissions: {error}"
                )));
            }
        }
        crate::lifecycle::write_lifecycle_audit(
            &pods.join(pod.to_string()),
            "pod_recovered_stopped",
            &pod.to_string(),
            "previous node container removed; host workspace preserved",
        )
        .await;
        authority.release_child(pod).await;
    }
    Ok(())
}

#[cfg(all(test, feature = "local-driver"))]
mod tests {
    use super::*;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path_regex},
    };

    fn client(server: &MockServer) -> Docker {
        Docker::connect_with_http(&server.uri(), 2, bollard::API_DEFAULT_VERSION).unwrap()
    }

    #[tokio::test]
    async fn restart_removes_owned_and_legacy_containers_preserving_host_files() {
        let dir = tempfile::tempdir().unwrap();
        let _lock = crate::state_lock::acquire(dir.path()).unwrap();
        let state = crate::pod_api::handler_tests::state(&dir);
        let labelled = Uuid::new_v4();
        let legacy = Uuid::new_v4();
        let legacy_dir = dir
            .path()
            .canonicalize()
            .unwrap()
            .join("pods")
            .join(legacy.to_string());
        std::fs::create_dir_all(&legacy_dir).unwrap();
        std::fs::write(legacy_dir.join("pod.yaml"), "retained spec").unwrap();
        std::fs::write(legacy_dir.join("result.txt"), "retained result").unwrap();
        let other = tempfile::tempdir().unwrap();
        let server = MockServer::start().await;
        Mock::given(method("GET")).and(path_regex("/containers/json$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"Id":"owned", "Labels":labels(dir.path(),labelled).unwrap()},
                {"Id":"legacy", "Mounts":[{"Type":"bind","Source":legacy_dir,"Destination":"/data/pod"}]},
                {"Id":"other-node", "Labels":labels(other.path(),Uuid::new_v4()).unwrap()},
                {"Id":"unrelated", "Mounts":[]}
            ]))).expect(1).mount(&server).await;
        for id in ["owned", "legacy"] {
            Mock::given(method("DELETE"))
                .and(path_regex(format!("/containers/{id}$")))
                .respond_with(ResponseTemplate::new(204))
                .expect(1)
                .mount(&server)
                .await;
        }
        drain(&client(&server), dir.path(), &state.authority)
            .await
            .unwrap();
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
        assert_eq!(
            std::fs::read_to_string(legacy_dir.join("result.txt")).unwrap(),
            "retained result"
        );
        assert_eq!(
            std::fs::read_to_string(legacy_dir.join("pod.yaml")).unwrap(),
            "retained spec"
        );
        assert!(legacy_dir.join("lifecycle.log").is_file());
    }

    #[tokio::test]
    async fn recovery_waits_for_confirmed_removal_and_can_retry() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::pod_api::handler_tests::state(&dir);
        let pod = Uuid::new_v4();
        let server = MockServer::start().await;
        for status in [500, 404] {
            server.reset().await;
            Mock::given(method("GET"))
                .respond_with(ResponseTemplate::new(200).set_body_json(
                    serde_json::json!([{"Id":"owned","Labels":labels(dir.path(),pod).unwrap()}]),
                ))
                .mount(&server)
                .await;
            Mock::given(method("DELETE"))
                .respond_with(
                    ResponseTemplate::new(status)
                        .set_body_json(serde_json::json!({"message":"Docker fixture response"})),
                )
                .mount(&server)
                .await;
            let result = drain(&client(&server), dir.path(), &state.authority).await;
            let recorded = dir
                .path()
                .join("pods")
                .join(pod.to_string())
                .join("lifecycle.log")
                .exists();
            assert_eq!(result.is_ok(), status == 404);
            assert_eq!(recorded, status == 404);
        }
    }
}
