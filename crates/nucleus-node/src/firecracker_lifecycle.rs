//! Release Firecracker capacity only after observing process exit and cleanup.
use std::sync::atomic::Ordering;

use crate::{
    ApiError, FirecrackerPod, PodState, Stop, egress_link, firecracker_config, net, pod_receipt,
};

/// Only `stopped` constructs this witness, while holding the process lock.
/// Cleanup consumes it; a caller's `AlreadyExited` hint is not exit evidence.
#[must_use]
struct StoppedVm<'a> {
    pod: &'a FirecrackerPod,
}

impl FirecrackerPod {
    pub(crate) async fn status(&self) -> PodState {
        let mut child = self.child.lock().await;
        match child.try_wait() {
            Ok(Some(status)) => PodState::Exited {
                code: status.code(),
            },
            Ok(None) => PodState::Running,
            Err(err) => PodState::Error {
                message: err.to_string(),
            },
        }
    }

    async fn stopped(&self, stop: Stop) -> Result<StoppedVm<'_>, ApiError> {
        let mut child = self.child.lock().await;
        if stop == Stop::Kill {
            child.kill().await.map_err(ApiError::Io)?;
        }
        match child.try_wait().map_err(ApiError::Io)? {
            Some(_) => Ok(StoppedVm { pod: self }),
            None => Err(ApiError::Driver(
                "Firecracker process is still running; retaining its resources".into(),
            )),
        }
    }

    pub(crate) async fn teardown(&self, stop: Stop) -> Result<(), ApiError> {
        // Drain identity-backed effects before stopping the VMM.
        self.cleanup_identity().await;
        if let Some(proxy) = self.signed_proxy.lock().await.take() {
            proxy.shutdown().await;
        }
        {
            let mut dns = self.dns_proxy.lock().await;
            if let Some(proxy) = dns.as_mut() {
                proxy.child.kill().await.map_err(ApiError::Io)?;
            }
            dns.take();
        }
        self.drift_stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.drift_monitor.lock().await.take() {
            handle.abort();
        }
        self.stopped(stop).await?.cleanup().await
    }
}

impl StoppedVm<'_> {
    async fn cleanup(self) -> Result<(), ApiError> {
        let pod = self.pod;
        egress_link::shutdown(&pod.egress_link).await?;
        if let Some(bridge) = pod.bridge.lock().await.take() {
            bridge.shutdown().await;
        }
        {
            let mut plan = pod.net_plan.lock().await;
            if let Some(plan) = plan.as_mut() {
                net::cleanup_network(plan).await?;
                // The plan's namespace was included in confirmed cleanup.
                pod.netns.lock().await.take();
            } else {
                let mut name = pod.netns.lock().await;
                if let Some(name) = name.as_ref() {
                    net::cleanup_netns(name).await?;
                }
                name.take();
            }
            plan.take();
        }
        let mut placement = pod.direct_cgroup.lock().await;
        if let Some(group) = placement.as_mut() {
            group.cleanup().await?;
        }
        placement.take();
        if let Some(layout) = pod.jail.lock().await.take() {
            pod_receipt::preserve_exit_report(&layout, &pod.pod_dir);
            firecracker_config::cleanup_jail(&layout);
        }
        // Both the VMM exit and fallible cleanup have completed. The aggregate
        // capacity reservation is released by PodHandle after this returns.
        pod.permit.lock().await.take();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{path::Path, sync::Arc};
    use tokio::sync::{Mutex, Semaphore};

    async fn fixture(path: &Path) -> (FirecrackerPod, Arc<Semaphore>) {
        let pool = Arc::new(Semaphore::new(1));
        let child = tokio::process::Command::new("/bin/sleep")
            .arg("30")
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pod = FirecrackerPod {
            direct_cgroup: Mutex::new(None),
            pod_dir: path.to_owned(),
            child: Arc::new(Mutex::new(child)),
            bridge: Mutex::new(None),
            signed_proxy: Mutex::new(None),
            permit: Mutex::new(Some(pool.clone().acquire_owned().await.unwrap())),
            net_plan: Mutex::new(None),
            netns: Mutex::new(None),
            dns_proxy: Mutex::new(None),
            drift_monitor: Mutex::new(None),
            egress_link: Mutex::new(None),
            drift_stop: Arc::default(),
            identity: None,
            identity_manager: None,
            identity_registry_key: None,
            workload_api_bridge: Mutex::new(None),
            broker: Mutex::new(None),
            decide: Mutex::new(None),
            jail: Mutex::new(None),
            snapshot: None,
        };
        (pod, pool)
    }

    #[tokio::test]
    async fn observed_exit_is_required_before_returning_the_concurrency_slot() {
        let dir = tempfile::tempdir().unwrap();
        let (pod, pool) = fixture(dir.path()).await;
        assert_eq!(pool.available_permits(), 0);
        let error = pod.teardown(Stop::AlreadyExited).await.unwrap_err();
        assert!(error.to_string().contains("still running"));
        assert!(matches!(pod.status().await, PodState::Running));
        assert_eq!(pool.available_permits(), 0);
        pod.teardown(Stop::Kill).await.unwrap();
        assert!(matches!(pod.status().await, PodState::Exited { .. }));
        assert_eq!(pool.available_permits(), 1);
        pod.teardown(Stop::AlreadyExited).await.unwrap();
        assert_eq!(pool.available_permits(), 1);
    }

    #[tokio::test]
    async fn failed_cgroup_cleanup_keeps_the_slot_until_retry_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let (pod, pool) = fixture(dir.path()).await;
        let group = dir.path().join("group");
        let placement = crate::cgroup::Placement::create(&group).await.unwrap();
        let retained = group.join("retained");
        std::fs::write(&retained, b"cleanup still pending").unwrap();
        *pod.direct_cgroup.lock().await = Some(placement);
        assert!(pod.teardown(Stop::Kill).await.is_err());
        assert!(matches!(pod.status().await, PodState::Exited { .. }));
        assert_eq!(pool.available_permits(), 0);
        assert!(pod.direct_cgroup.lock().await.is_some());
        std::fs::remove_file(retained).unwrap();
        pod.teardown(Stop::AlreadyExited).await.unwrap();
        assert_eq!(pool.available_permits(), 1);
        assert!(!group.exists());
    }
}
