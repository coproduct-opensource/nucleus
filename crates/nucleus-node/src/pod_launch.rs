//! Node-owned launch tasks retain resources across caller disconnection.
//! Handoff transfers responsibility to the caller; an abandoned handoff
//! tears down the registered pod and releases authority only after cleanup.
use crate::{ApiError, NodeState, PodSpec, pod_authority};
use uuid::Uuid;

type Result = std::result::Result<(Uuid, Option<String>), ApiError>;

pub(crate) async fn create(
    state: &NodeState,
    spec: PodSpec,
    parent: Option<Uuid>,
    raw: Option<String>,
    admission: pod_authority::Admission,
) -> Result {
    let state = state.clone();
    let (send, receive) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        // The drain's gate (`node_drain::Intake`), held until the pod is registered or the
        // launch has failed, so a shutdown cannot read the registry while this is in between.
        let result = match state.intake.admit().await {
            Ok(_admitted) => crate::create_pod_internal(&state, spec, parent, raw, admission).await,
            Err(refused) => Err(refused),
        };
        // If the receiver disappeared before or after send, dropping Delivery
        // schedules cleanup. Accepting it is the only successful handoff.
        let _ = send.send(Delivery {
            result: Some(result),
            state,
        });
    });
    receive
        .await
        .map_err(|e| ApiError::Driver(format!("pod launch task failed: {e}")))?
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
                            tracing::warn!(pod = %id, %error, "abandoned pod launch cleanup will retry")
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        });
    }
}

#[cfg(all(test, feature = "local-driver"))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    #[tokio::test]
    async fn caller_disconnect_during_local_boot_finishes_and_cleans_the_owned_launch() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::pod_api::handler_tests::state(&dir);
        state.node_capacity = crate::node_capacity::Capacity::new(640, 1);
        // Keep executable fixtures beside the test binary: /tmp can be noexec.
        let executable = std::env::current_exe().unwrap();
        let bin = tempfile::tempdir_in(executable.parent().unwrap()).unwrap();
        let proxy = bin.path().join("proxy");
        std::fs::write(
            &proxy,
            r#"#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--announce-path" ]; then shift; announce="$1"; fi
  shift
done
echo $$ > "$0.pid"
sleep 1
printf 'unix:///stand-in/proxy.sock\n' > "$announce"
exec sleep 30
"#,
        )
        .unwrap();
        std::fs::set_permissions(&proxy, std::fs::Permissions::from_mode(0o755)).unwrap();
        state.tool_proxy_path = proxy.clone();
        let work = state.state_dir.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let spec: PodSpec = serde_json::from_value(serde_json::json!({
            "apiVersion":"nucleus/v1", "kind":"Pod", "spec":{"work_dir":work}
        }))
        .unwrap();
        let root = pod_authority::Admission {
            caller_spiffe_id: state.authority.root_minter().into(),
            caller_pod: None,
            header_cert: None,
        };
        let parent = Uuid::new_v4();
        state
            .authority
            .admit_kept(&root, &spec, parent)
            .await
            .unwrap();
        let admission = pod_authority::Admission {
            caller_spiffe_id: format!("spiffe://nucleus.local/ns/pods/sa/{parent}"),
            caller_pod: Some(parent),
            header_cert: None,
        };
        let caller_state = state.clone();
        let requested = spec.clone();
        let request = tokio::spawn(async move {
            create(&caller_state, requested, Some(parent), None, admission).await
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !bin.path().join("proxy.pid").exists() {
                assert!(
                    !request.is_finished(),
                    "launch ended before starting its process"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        request.abort();
        assert!(request.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let pods: Vec<_> = state.pods.lock().await.values().cloned().collect();
                if let [pod] = pods.as_slice()
                    && matches!(pod.status().await, crate::PodState::Exited { .. })
                    && state.authority.live_children(parent).await == Some(0)
                {
                    drop(state.node_capacity.reserve(&spec).unwrap());
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("abandoned launch did not finish and release its resources");
    }
}
