//! Container capacity is released only after Docker confirms removal.
use crate::{ApiError, ContainerPod, PodState, Stop};

impl ContainerPod {
    pub(crate) async fn status(&self) -> PodState {
        // Return cached state if container was already cleaned up.
        if let Some(ref cached) = *self.cached_exit.lock().await {
            return cached.clone();
        }
        use bollard::query_parameters::InspectContainerOptions;
        match self
            .docker
            .inspect_container(&self.container_id, None::<InspectContainerOptions>)
            .await
        {
            Ok(info) => {
                let state = info.state.as_ref();
                let running = state.and_then(|s| s.running).unwrap_or(false);
                if running {
                    PodState::Running
                } else {
                    let exit_state = PodState::Exited {
                        code: state.and_then(|s| s.exit_code).map(|c| c as i32),
                    };
                    // Cache the terminal state so it survives container removal.
                    *self.cached_exit.lock().await = Some(exit_state.clone());
                    exit_state
                }
            }
            Err(e) => PodState::Error {
                message: e.to_string(),
            },
        }
    }

    pub(crate) async fn teardown(&self, stop: Stop) -> Result<(), ApiError> {
        if let Some(proxy) = self.signed_proxy.lock().await.take() {
            proxy.shutdown().await;
        }
        if stop == Stop::Kill {
            let _ = self
                .docker
                .stop_container(
                    &self.container_id,
                    Some(bollard::query_parameters::StopContainerOptions {
                        t: Some(5),
                        signal: Some("SIGTERM".to_string()),
                    }),
                )
                .await;
        }
        // Cache the exit state BEFORE removal, on both paths: once the container is
        // gone `status()` cannot inspect it and would report an error. Cancel used to
        // skip this, so a cancelled pod read as `Error` and the reaper audited its
        // exit as "No such container".
        if self.cached_exit.lock().await.is_none() {
            let _ = self.status().await;
        }
        let removed = self
            .docker
            .remove_container(
                &self.container_id,
                Some(bollard::query_parameters::RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                }),
            )
            .await;
        match removed {
            Ok(())
            | Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => {}
            Err(error) => {
                return Err(ApiError::Driver(format!(
                    "container {} removal failed; retaining resource reservation: {error}",
                    self.container_id
                )));
            }
        }
        self.permit.lock().await.take();
        Ok(())
    }
}

#[cfg(all(test, feature = "local-driver"))]
mod tests {
    use super::*;
    use std::{collections::HashSet, sync::Arc};
    use tokio::sync::{Mutex, Semaphore};
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

    async fn fixture(
        server: &MockServer,
    ) -> (
        tempfile::TempDir,
        crate::NodeState,
        uuid::Uuid,
        Arc<Semaphore>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::pod_api::handler_tests::state(&dir);
        state.node_capacity = crate::node_capacity::Capacity::new(640, 1);
        let id = crate::pod_api::handler_tests::register(&state, None).await;
        let pool = Arc::new(Semaphore::new(1));
        {
            let mut pods = state.pods.lock().await;
            let pod = Arc::get_mut(pods.get_mut(&id).unwrap()).unwrap();
            pod.cancel().await.unwrap();
            pod.driver_state = crate::DriverState::Container(Box::new(ContainerPod {
                container_id: "ordinary-container".into(),
                docker: bollard::Docker::connect_with_http(
                    &server.uri(),
                    2,
                    bollard::API_DEFAULT_VERSION,
                )
                .unwrap(),
                signed_proxy: Mutex::new(None),
                permit: Mutex::new(Some(pool.clone().acquire_owned().await.unwrap())),
                cached_exit: Mutex::new(Some(PodState::Exited { code: Some(0) })),
            }));
            *pod.capacity.lock().await = Some(state.node_capacity.reserve(&pod.spec).unwrap());
        }
        (dir, state, id, pool)
    }

    #[tokio::test]
    async fn reaper_retries_removal_before_releasing_capacity_or_recording_exit() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .respond_with(
                ResponseTemplate::new(500)
                    .set_body_json(serde_json::json!({"message":"temporarily unavailable"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let (dir, state, id, pool) = fixture(&server).await;
        let mut reaped = HashSet::new();
        crate::reap_once(&state, &mut reaped).await;
        assert!(!reaped.contains(&id));
        assert_eq!(pool.available_permits(), 0);
        let pod = state.pods.lock().await.get(&id).unwrap().clone();
        assert!(state.node_capacity.reserve(&pod.spec).is_err());
        assert!(!dir.path().join("lifecycle.log").exists());
        server.verify().await;
        server.reset().await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        crate::reap_once(&state, &mut reaped).await;
        crate::reap_once(&state, &mut reaped).await;
        assert!(reaped.contains(&id));
        assert_eq!(pool.available_permits(), 1);
        drop(state.node_capacity.reserve(&pod.spec).unwrap());
        let log = std::fs::read_to_string(dir.path().join("lifecycle.log")).unwrap();
        assert_eq!(log.lines().count(), 1);
    }

    #[tokio::test]
    async fn already_removed_container_returns_capacity() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .respond_with(
                ResponseTemplate::new(404)
                    .set_body_json(serde_json::json!({"message":"No such container"})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let (_dir, state, id, pool) = fixture(&server).await;
        let pod = state.pods.lock().await.get(&id).unwrap().clone();
        pod.cleanup_after_exit().await.unwrap();
        assert_eq!(pool.available_permits(), 1);
        drop(state.node_capacity.reserve(&pod.spec).unwrap());
    }
}
