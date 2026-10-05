//! Stop expired executions and retire resources after confirmed teardown.
use crate::{NodeState, PodHandle, PodState, clearing_receipt_collector, lifecycle};
use std::{path::Path, sync::Arc, time::Duration};
use tracing::{error, info};
use uuid::Uuid;

pub(crate) fn start_pod_reaper(state: NodeState) {
    tokio::spawn(async move {
        let mut reaped = std::collections::HashSet::new();
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            reap_once(&state, &mut reaped).await;
        }
    });
}

/// One pass of the pod reaper.
///
/// `reaped` is the reaper's own record of the pods it has already handled, and the
/// one thing that decides it. Exited pods stay in the registry (their status, logs
/// and receipts are still served), so without it every pass redid the exit: another
/// `pod_exited` lifecycle audit entry every 10 s — six for one exit on a live node —
/// and another identity release, which warned that the registry keys had drifted
/// apart because the first release had already removed them. The cascade is NOT
/// gated on it: a running child of any exited parent is cancelled on every pass, so
/// a cascade that failed is retried.
pub(crate) async fn reap_once(state: &NodeState, reaped: &mut std::collections::HashSet<Uuid>) {
    let pods: Vec<Arc<PodHandle>> = {
        let guard = state.pods.lock().await;
        guard.values().cloned().collect()
    };
    // Forget pods no longer registered, so the set is bounded by the registry.
    reaped.retain(|id| pods.iter().any(|p| p.id == *id));

    if pods.is_empty() {
        return;
    }

    // Collect IDs of exited/errored pods for cascading cancel
    let mut exited_ids = Vec::new();

    for pod in &pods {
        let mut pod_state = pod.status().await;
        if matches!(pod_state, PodState::Running)
            && tokio::time::Instant::now() >= pod.execution_deadline
        {
            if let Err(error) = pod.cancel().await {
                error!(pod = %pod.id, %error, "expired pod cancellation failed; retrying on next reaper pass");
                continue;
            }
            let pod_dir = pod.log_path.parent().unwrap_or(Path::new("."));
            lifecycle::write_lifecycle_audit(
                pod_dir,
                "pod_timed_out",
                &pod.id.to_string(),
                "execution deadline reached",
            )
            .await;
            pod_state = pod.status().await;
        }
        if matches!(pod_state, PodState::Exited { .. } | PodState::Error { .. }) {
            exited_ids.push(pod.id);
            if reaped.contains(&pod.id) {
                continue;
            }
            if let Err(error) = pod.cleanup_after_exit().await {
                error!(pod = %pod.id, %error, "pod cleanup failed; retrying on next reaper pass");
                continue;
            }
            reaped.insert(pod.id);
            // Write lifecycle audit for pod exit
            let detail = match &pod_state {
                PodState::Exited { code } => format!("exit_code={}", code.unwrap_or(-1)),
                PodState::Error { message } => format!("error={message}"),
                _ => "unknown".to_string(),
            };
            let pod_dir = pod.log_path.parent().unwrap_or(Path::new("."));
            lifecycle::write_lifecycle_audit(pod_dir, "pod_exited", &pod.id.to_string(), &detail)
                .await;

            let guest_spend =
                clearing_receipt_collector::guest_reported_spend(pod_dir, &pod.id.to_string());
            tracing::debug!(pod = %pod.id, ?guest_spend, "guest-reported spend; no budget credit");
            state.authority.release_child(pod.id).await;
        }
    }

    // Cascade cancel: kill children of exited parent pods
    if !exited_ids.is_empty() {
        for pod in &pods {
            if let Some(parent_id) = pod.parent_pod_id
                && exited_ids.contains(&parent_id)
            {
                let child_state = pod.status().await;
                if matches!(child_state, PodState::Running) {
                    info!(
                        "cascading cancel: killing child pod {} (parent {} exited)",
                        pod.id, parent_id
                    );
                    if let Err(e) = pod.cancel().await {
                        error!("failed to cascade cancel pod {}: {}", pod.id, e);
                    }
                }
            }
        }
    }
}

#[cfg(all(test, feature = "local-driver"))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn execution_deadline_stops_parent_cascades_and_returns_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = crate::pod_api::handler_tests::state(&dir);
        state.node_capacity = crate::node_capacity::Capacity::new(640, 1);
        let parent = crate::pod_api::handler_tests::register(&state, None).await;
        let child = crate::pod_api::handler_tests::register(&state, Some(parent)).await;
        let mut reaped = std::collections::HashSet::new();
        reap_once(&state, &mut reaped).await;
        assert!(reaped.is_empty());
        {
            let mut pods = state.pods.lock().await;
            let pod = Arc::get_mut(pods.get_mut(&parent).unwrap()).unwrap();
            *pod.capacity.get_mut() = Some(state.node_capacity.reserve(&pod.spec).unwrap());
            assert!(state.node_capacity.reserve(&pod.spec).is_err());
            // Advancing only this deadline avoids sleeping or changing the
            // wall clock used by unrelated authority and certificate checks.
            pod.execution_deadline = tokio::time::Instant::now();
        }
        reap_once(&state, &mut reaped).await;
        for id in [parent, child] {
            let pod = crate::pod_api::get_pod(&state, id).await.unwrap();
            assert!(matches!(pod.status().await, PodState::Exited { .. }));
        }
        let pod = crate::pod_api::get_pod(&state, parent).await.unwrap();
        drop(state.node_capacity.reserve(&pod.spec).unwrap());
        reap_once(&state, &mut reaped).await;
        assert_eq!(reaped.len(), 2);
        let events = std::fs::read_to_string(dir.path().join("lifecycle.log")).unwrap();
        assert_eq!(
            events
                .lines()
                .filter(|line| line.contains("\"pod_timed_out\""))
                .count(),
            1
        );
        assert_eq!(
            events
                .lines()
                .filter(|line| line.contains("\"pod_exited\""))
                .count(),
            2
        );
    }
}
