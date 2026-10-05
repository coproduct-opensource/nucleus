//! Durable create intent precedes the external Docker request. An observed
//! container ID is recorded before removal, so a crash after removal can settle
//! via 404 without confusing it with a create that has not appeared yet.
use crate::ApiError;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub(crate) struct Intent {
    state_dir: PathBuf,
    pub(crate) pod: Uuid,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    pod: Uuid,
    phase: Phase,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
enum Phase {
    Pending,
    /// Docker answered the create request; absence is now terminal.
    Replied,
    Observed {
        container_id: String,
    },
}

impl Intent {
    fn root(&self) -> PathBuf {
        self.state_dir.join("container-launches")
    }
    fn path(&self) -> PathBuf {
        self.root().join(format!("{}.json", self.pod))
    }
    pub(crate) fn name(&self) -> String {
        format!("nucleus-{}", self.pod)
    }

    pub(crate) async fn begin(state_dir: &Path, pod: Uuid) -> Result<Self, ApiError> {
        let intent = Self {
            state_dir: state_dir.canonicalize()?,
            pod,
        };
        let root = intent.root();
        let state = intent.state_dir.clone();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            std::fs::create_dir_all(root)?;
            std::fs::File::open(&state)?.sync_all()?;
            if let Some(parent) = state.parent() {
                std::fs::File::open(parent)?.sync_all()?;
            }
            Ok(())
        })
        .await
        .map_err(std::io::Error::other)??;
        intent.write(Phase::Pending).await?;
        Ok(intent)
    }

    async fn write(&self, phase: Phase) -> Result<(), ApiError> {
        let bytes = serde_json::to_vec(&Record {
            pod: self.pod,
            phase,
        })
        .map_err(std::io::Error::other)?;
        crate::pod_authority::write_whole(&self.path(), &bytes).await?;
        Ok(())
    }
    pub(crate) async fn replied(&self) -> Result<(), ApiError> {
        self.write(Phase::Replied).await
    }
    pub(crate) async fn observed(&self, id: &str) -> Result<(), ApiError> {
        if id.is_empty() {
            return Err(ApiError::Driver(
                "Docker returned an empty container ID".into(),
            ));
        }
        self.write(Phase::Observed {
            container_id: id.into(),
        })
        .await
    }
    pub(crate) async fn clear(&self) -> Result<(), ApiError> {
        let path = self.path();
        let root = self.root();
        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            std::fs::File::open(root)?.sync_all()
        })
        .await
        .map_err(std::io::Error::other)??;
        Ok(())
    }

    pub(crate) async fn cleanup(&self, docker: &bollard::Docker) -> Result<(), ApiError> {
        let bytes = match tokio::fs::read(self.path()).await {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return self.clear().await,
            Err(e) => return Err(e.into()),
        };
        let record: Record = serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
        if record.pod != self.pod {
            return Err(ApiError::Driver("container intent pod mismatch".into()));
        }
        let id = match record.phase {
            Phase::Observed { container_id } if !container_id.is_empty() => container_id,
            phase @ (Phase::Pending | Phase::Replied) => {
                match docker
                    .inspect_container(
                        &self.name(),
                        None::<bollard::query_parameters::InspectContainerOptions>,
                    )
                    .await
                {
                    Ok(info) => {
                        let expected =
                            crate::container_recovery::labels(&self.state_dir, self.pod)?;
                        let labels = info
                            .config
                            .and_then(|config| config.labels)
                            .unwrap_or_default();
                        if !expected
                            .iter()
                            .all(|(key, value)| labels.get(key) == Some(value))
                        {
                            return Err(ApiError::Driver(format!(
                                "container {} does not match launch ownership",
                                self.name()
                            )));
                        }
                        let id = info.id.filter(|id| !id.is_empty()).ok_or_else(|| {
                            ApiError::Driver("Docker inspection omitted container ID".into())
                        })?;
                        self.observed(&id).await?;
                        id
                    }
                    Err(bollard::errors::Error::DockerResponseServerError {
                        status_code: 404,
                        ..
                    }) if matches!(phase, Phase::Replied) => return self.clear().await,
                    Err(error) => {
                        return Err(ApiError::Driver(format!(
                            "unsettled container create {} ({}): {error}; launch record retained",
                            self.name(),
                            self.path().display()
                        )));
                    }
                }
            }
            Phase::Observed { .. } => {
                return Err(ApiError::Driver(
                    "empty container ID in launch record".into(),
                ));
            }
        };
        match docker
            .remove_container(
                &id,
                Some(bollard::query_parameters::RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await
        {
            Ok(())
            | Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => self.clear().await,
            Err(error) => Err(ApiError::Driver(format!(
                "container intent cleanup {id}: {error}"
            ))),
        }
    }
}

pub(crate) async fn recover(
    docker: &bollard::Docker,
    state_dir: &Path,
    authority: &crate::pod_authority::PodAuthority,
) -> Result<(), ApiError> {
    let mut entries = match tokio::fs::read_dir(state_dir.join("container-launches")).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension().and_then(|v| v.to_str()) != Some("json") {
            continue;
        }
        let pod = path
            .file_stem()
            .and_then(|v| v.to_str())
            .and_then(|v| Uuid::parse_str(v).ok())
            .ok_or_else(|| {
                ApiError::Driver(format!(
                    "invalid container launch record {}",
                    path.display()
                ))
            })?;
        Intent {
            state_dir: state_dir.into(),
            pod,
        }
        .cleanup(docker)
        .await?;
        crate::lifecycle::write_lifecycle_audit(
            &crate::lifecycle::pod_dir(state_dir, pod),
            "pod_recovered_stopped",
            &pod.to_string(),
            "durable container launch settled; host workspace preserved",
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

    fn client(server: &MockServer) -> bollard::Docker {
        bollard::Docker::connect_with_http(&server.uri(), 2, bollard::API_DEFAULT_VERSION).unwrap()
    }

    #[tokio::test]
    async fn restart_retains_unsettled_create_then_records_late_container_before_removal() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::pod_api::handler_tests::state(&dir);
        let intent = Intent::begin(dir.path(), Uuid::new_v4()).await.unwrap();
        let path = intent.path();
        let labels = crate::container_recovery::labels(dir.path(), intent.pod).unwrap();
        drop(intent); // Reconstruct entirely from disk, as a new node does.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(serde_json::json!({"message":"not yet created"})),
            )
            .mount(&server)
            .await;
        assert!(
            recover(&client(&server), dir.path(), &state.authority)
                .await
                .is_err()
        );
        assert!(path.is_file());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        server.reset().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"Id":"late-container", "Config":{"Labels":labels}}),
            ))
            .expect(1)
            .mount(&server)
            .await;
        let checkpoint = path.clone();
        Mock::given(method("DELETE")).and(path_regex("/containers/late-container$"))
            .respond_with(move |_: &wiremock::Request| {
                let record: Record = serde_json::from_slice(&std::fs::read(&checkpoint).unwrap()).unwrap();
                assert!(matches!(record.phase, Phase::Observed { container_id } if container_id == "late-container"));
                ResponseTemplate::new(204)
            }).expect(1).mount(&server).await;
        recover(&client(&server), dir.path(), &state.authority)
            .await
            .unwrap();
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn restart_after_confirmed_removal_can_settle_by_absence() {
        let dir = tempfile::tempdir().unwrap();
        let state = crate::pod_api::handler_tests::state(&dir);
        let intent = Intent::begin(dir.path(), Uuid::new_v4()).await.unwrap();
        intent.observed("already-removed").await.unwrap();
        let path = intent.path();
        drop(intent);
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .and(path_regex("/containers/already-removed$"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(serde_json::json!({"message":"No such container"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        recover(&client(&server), dir.path(), &state.authority)
            .await
            .unwrap();
        assert!(!path.exists());
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}
