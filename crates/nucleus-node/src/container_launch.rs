//! Docker requests can outlive a disconnected API caller. Keep the launch and
//! its reservations in a node-owned task until handoff or confirmed cleanup.
use crate::{ApiError, DriverKind, NodeState, PodSpec, pod_authority};
use uuid::Uuid;

type Result = std::result::Result<(Uuid, Option<String>), ApiError>;

pub(crate) async fn create(
    state: &NodeState,
    spec: PodSpec,
    parent: Option<Uuid>,
    raw: Option<String>,
    admission: pod_authority::Admission,
) -> Result {
    if !matches!(state.driver, DriverKind::Container) {
        return crate::create_pod_internal(state, spec, parent, raw, admission).await;
    }
    let state = state.clone();
    let (send, receive) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let result = crate::create_pod_internal(&state, spec, parent, raw, admission).await;
        // If the receiver disappeared before or after send, dropping Delivery
        // schedules cleanup. Accepting it is the only successful handoff.
        let _ = send.send(Delivery {
            result: Some(result),
            state,
        });
    });
    receive
        .await
        .map_err(|e| ApiError::Driver(format!("container launch task failed: {e}")))?
        .accept()
}

struct Delivery {
    result: Option<Result>,
    state: NodeState,
}
impl Delivery {
    fn accept(mut self) -> Result {
        self.result.take().expect("one delivery handoff")
    }
}
impl Drop for Delivery {
    fn drop(&mut self) {
        let Some(Ok((id, _))) = self.result.take() else {
            return;
        };
        let state = self.state.clone();
        tokio::spawn(async move {
            let pod = state.pods.lock().await.get(&id).cloned();
            if let Some(pod) = pod {
                loop {
                    match pod.cancel().await {
                        Ok(()) => {
                            state.authority.release_child(id).await;
                            break;
                        }
                        Err(error) => {
                            tracing::warn!(pod = %id, %error, "abandoned container launch cleanup will retry")
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        });
    }
}

/// What the node knows about the completed create request.
pub(crate) enum Outcome<'a> {
    Unknown,
    Replied,
    Created(&'a str),
}

/// Reservations remain owned until durable cleanup settles the external create.
pub(crate) async fn rollback(
    docker: &bollard::Docker,
    intent: &crate::container_intent::Intent,
    outcome: Outcome<'_>,
) {
    let mut outcome = Some(outcome);
    loop {
        let recorded = match &outcome {
            Some(Outcome::Replied) => intent.replied().await,
            Some(Outcome::Created(id)) => intent.observed(id).await,
            _ => Ok(()),
        };
        let cleaned = match recorded {
            Ok(()) => {
                outcome = None;
                intent.cleanup(docker).await
            }
            Err(error) => Err(error),
        };
        match cleaned {
            Ok(()) => return,
            Err(error) => {
                tracing::warn!(pod = %intent.pod, %error, "container launch rollback pending; retaining resource reservations")
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

#[cfg(all(test, feature = "local-driver"))]
mod tests {
    use super::*;
    use std::{sync::Arc, time::Duration};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path_regex},
    };

    async fn fixture(
        start_status: u16,
        memory_swap: i64,
        network_mode: Option<&str>,
    ) -> (
        tempfile::TempDir,
        MockServer,
        NodeState,
        PodSpec,
        pod_authority::Admission,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::pod_api::handler_tests::state(&dir);
        state.driver = DriverKind::Container;
        state.node_capacity = crate::node_capacity::Capacity::new(640, 1);
        state.container_pool = Some(Arc::new(tokio::sync::Semaphore::new(1)));
        state.container_mediation = crate::container_mediation::ContainerMediation::Unmediated;
        let work = dir.path().join("workspaces/project");
        std::fs::create_dir_all(&work).unwrap();
        let spec = serde_json::from_value(serde_json::json!({
            "apiVersion":"nucleus/v1", "kind":"Pod", "spec":{"work_dir":work}
        }))
        .unwrap();
        let admission = pod_authority::Admission {
            caller_spiffe_id: state.authority.root_minter().to_string(),
            caller_pod: None,
            header_cert: None,
        };
        let server = MockServer::start().await;
        state.docker = Some(Arc::new(
            bollard::Docker::connect_with_http(&server.uri(), 2, bollard::API_DEFAULT_VERSION)
                .unwrap(),
        ));
        Mock::given(method("POST"))
            .and(path_regex("/containers/create$"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_delay(Duration::from_millis(300))
                    .set_body_json(serde_json::json!({"Id":"created", "Warnings":[]})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex("/containers/created/start$"))
            .respond_with(
                ResponseTemplate::new(start_status)
                    .set_body_json(serde_json::json!({"message":"start response"})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex("/containers/created/stop$"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex("/containers/created/json$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"State":{"Running":false,"ExitCode":0},
                        "HostConfig":{"Memory":536870912,"MemorySwap":memory_swap,"NanoCpus":1000000000,"PidsLimit":4096,"NetworkMode":network_mode}})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path_regex("/containers/created/logs$"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(204).set_delay(Duration::from_millis(300)))
            .expect(1)
            .mount(&server)
            .await;
        (dir, server, state, spec, admission)
    }

    async fn saw(server: &MockServer, method: &str) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if server
                    .received_requests()
                    .await
                    .unwrap()
                    .iter()
                    .any(|request| request.method.as_str() == method)
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }

    fn held(state: &NodeState, spec: &PodSpec) {
        assert!(state.node_capacity.reserve(spec).is_err());
        assert_eq!(
            state.container_pool.as_ref().unwrap().available_permits(),
            0
        );
    }

    #[tokio::test]
    async fn caller_cancellation_keeps_launch_owned_until_removal() {
        let (_dir, server, state, spec, admission) = fixture(204, 536870912, Some("none")).await;
        let caller_state = state.clone();
        let request = spec.clone();
        let caller =
            tokio::spawn(
                async move { create(&caller_state, request, None, None, admission).await },
            );
        saw(&server, "POST").await;
        held(&state, &spec);
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        held(&state, &spec);
        saw(&server, "DELETE").await;
        held(&state, &spec);
        tokio::time::timeout(Duration::from_secs(10), async {
            while state.node_capacity.reserve(&spec).is_err() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            state.container_pool.as_ref().unwrap().available_permits(),
            1
        );
    }

    #[tokio::test]
    async fn failed_start_rolls_back_before_returning_capacity() {
        let (_dir, server, state, spec, admission) = fixture(500, 536870912, Some("none")).await;
        let caller_state = state.clone();
        let request = spec.clone();
        let caller =
            tokio::spawn(
                async move { create(&caller_state, request, None, None, admission).await },
            );
        saw(&server, "DELETE").await;
        held(&state, &spec);
        assert!(caller.await.unwrap().is_err());
        drop(state.node_capacity.reserve(&spec).unwrap());
        assert_eq!(
            state.container_pool.as_ref().unwrap().available_permits(),
            1
        );
    }

    #[tokio::test]
    async fn successful_handoff_retains_the_running_pod() {
        let (_dir, _server, state, spec, admission) = fixture(204, 536870912, Some("none")).await;
        let (id, _) = create(&state, spec.clone(), None, None, admission)
            .await
            .unwrap();
        held(&state, &spec);
        let pod = state.pods.lock().await.get(&id).unwrap().clone();
        pod.cancel().await.unwrap();
        drop(state.node_capacity.reserve(&spec).unwrap());
    }

    #[tokio::test]
    async fn daemon_rewritten_swap_limit_rolls_back_without_starting_workload() {
        let (_dir, server, state, spec, admission) = fixture(204, -1, Some("none")).await;
        let error = create(&state, spec.clone(), None, None, admission)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("required memory_swap"));
        assert!(
            !server
                .received_requests()
                .await
                .unwrap()
                .iter()
                .any(|request| request.url.path().ends_with("/start"))
        );
        drop(state.node_capacity.reserve(&spec).unwrap());
        assert_eq!(
            state.container_pool.as_ref().unwrap().available_permits(),
            1
        );
    }

    #[tokio::test]
    async fn network_configuration_mismatch_cleans_up_without_starting() {
        for mode in [None, Some("bridge"), Some("host")] {
            let (_dir, server, state, spec, admission) = fixture(204, 536870912, mode).await;
            let error = create(&state, spec.clone(), None, None, admission)
                .await
                .unwrap_err();
            assert!(error.to_string().contains("required network mode"));
            let requests = server.received_requests().await.unwrap();
            assert!(
                !requests
                    .iter()
                    .any(|request| request.url.path().ends_with("/start"))
            );
            assert!(
                requests
                    .iter()
                    .any(|request| request.method.as_str() == "DELETE")
            );
            drop(state.node_capacity.reserve(&spec).unwrap());
            assert_eq!(
                state.container_pool.as_ref().unwrap().available_permits(),
                1
            );
            assert_eq!(
                std::fs::read_dir(state.state_dir.join("container-launches"))
                    .unwrap()
                    .count(),
                0
            );
        }
    }

    #[tokio::test]
    async fn uncertain_create_waits_for_the_late_container_before_releasing() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let intent = crate::container_intent::Intent::begin(dir.path(), Uuid::new_v4())
            .await
            .unwrap();
        let labels = crate::container_recovery::labels(dir.path(), intent.pod).unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let counted = requests.clone();
        Mock::given(method("GET"))
            .respond_with(move |_: &wiremock::Request| {
                if counted.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(404)
                        .set_body_json(serde_json::json!({"message":"create still pending"}))
                } else {
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::json!({"Id":"late", "Config":{"Labels":labels}}))
                }
            })
            .expect(2)
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        let docker =
            bollard::Docker::connect_with_http(&server.uri(), 2, bollard::API_DEFAULT_VERSION)
                .unwrap();
        rollback(&docker, &intent, Outcome::Unknown).await;
        assert_eq!(requests.load(Ordering::SeqCst), 2);
    }
}
