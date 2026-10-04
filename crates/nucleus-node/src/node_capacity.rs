//! Aggregate reservations, independent of per-pod cgroup ceilings.
use crate::{
    ApiError,
    pod_resources::{PodSize, VMM_OVERHEAD_MIB},
};
use std::sync::{Arc, Mutex};

#[derive(clap::Args, Debug)]
pub(crate) struct CapacityArgs {
    /// Total memory assigned to this node, before the host reserve (MiB).
    /// Defaults to Linux MemTotal; set explicitly on other hosts.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    node_memory_mib: Option<u64>,
    /// Total schedulable vCPUs; defaults to available parallelism.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    node_vcpus: Option<u32>,
    #[arg(long, default_value_t = 512)]
    host_reserve_memory_mib: u64,
    #[arg(long, default_value_t = 0)]
    host_reserve_vcpus: u32,
}
impl CapacityArgs {
    pub(crate) fn build(&self) -> Result<Capacity, ApiError> {
        let memory = match self.node_memory_mib {
            Some(value) => value,
            None => {
                let info = std::fs::read_to_string("/proc/meminfo").map_err(|e| {
                    ApiError::Driver(format!(
                        "set --node-memory-mib: host memory detection failed: {e}"
                    ))
                })?;
                info.lines()
                    .find_map(|line| line.strip_prefix("MemTotal:"))
                    .and_then(|v| v.split_whitespace().next())
                    .and_then(|v| v.parse::<u64>().ok())
                    .map(|kb| kb / 1024)
                    .ok_or_else(|| {
                        ApiError::Driver("set --node-memory-mib: MemTotal unavailable".into())
                    })?
            }
        };
        let memory = cgroup_memory_limit()?.map_or(memory, |limit| memory.min(limit));
        let cpus = match self.node_vcpus {
            Some(value) => value,
            None => u32::try_from(std::thread::available_parallelism()?.get())
                .map_err(|_| ApiError::Driver("host CPU count is unrepresentable".into()))?,
        };
        let memory = memory
            .checked_sub(self.host_reserve_memory_mib)
            .filter(|v| *v > 0)
            .ok_or_else(|| ApiError::Driver("host memory reserve leaves no pod capacity".into()))?;
        let cpus = cpus
            .checked_sub(self.host_reserve_vcpus)
            .filter(|v| *v > 0)
            .ok_or_else(|| ApiError::Driver("host CPU reserve leaves no pod capacity".into()))?;
        Ok(Capacity::new(memory, cpus))
    }
}

/// The node may run in a delegated cgroup. Every visible ancestor limits the
/// same memory, so use the smallest finite ceiling rather than host MemTotal.
fn cgroup_memory_limit() -> Result<Option<u64>, ApiError> {
    if !cfg!(target_os = "linux") {
        return Ok(None);
    }
    let membership = std::fs::read_to_string("/proc/self/cgroup")?;
    let Some(relative) = membership.lines().find_map(|line| line.strip_prefix("0::")) else {
        return Ok(None);
    };
    let root = std::path::Path::new("/sys/fs/cgroup");
    let relative = std::path::Path::new(relative.trim_start_matches('/'));
    if relative
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(ApiError::Driver(
            "node cgroup is outside the visible hierarchy".into(),
        ));
    }
    let mut current = root.join(relative);
    let mut limit: Option<u64> = None;
    while current.starts_with(root) {
        match std::fs::read_to_string(current.join("memory.max")) {
            Ok(value) if value.trim() == "max" => {}
            Ok(value) => {
                let mib = value
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| ApiError::Driver("invalid cgroup memory.max".into()))?
                    / (1024 * 1024);
                limit = Some(limit.map_or(mib, |prior| prior.min(mib)));
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        current.pop();
    }
    Ok(limit)
}

#[derive(Clone, Debug)]
pub(crate) struct Capacity(Arc<Mutex<Available>>);
#[derive(Debug)]
struct Available {
    memory_mib: u64,
    vcpus: u32,
}
impl Capacity {
    pub(crate) fn new(memory_mib: u64, vcpus: u32) -> Self {
        Self(Arc::new(Mutex::new(Available { memory_mib, vcpus })))
    }
    pub(crate) fn reserve(&self, spec: &nucleus_spec::PodSpec) -> Result<Reservation, ApiError> {
        let size = PodSize::of(spec);
        let memory_mib = size
            .memory_mib()
            .checked_add(VMM_OVERHEAD_MIB)
            .ok_or_else(|| ApiError::InvalidSpec("pod memory plus overhead overflows".into()))?;
        let vcpus = size.vcpus();
        let mut available = self.0.lock().map_err(|_| {
            ApiError::SupervisorUnavailable("node capacity lock unavailable".into())
        })?;
        if memory_mib > available.memory_mib || vcpus > available.vcpus {
            return Err(ApiError::SupervisorUnavailable(format!(
                "node capacity exhausted: requested {memory_mib} MiB including overhead and {vcpus} vCPUs; available {} MiB and {} vCPUs",
                available.memory_mib, available.vcpus
            )));
        }
        available.memory_mib -= memory_mib;
        available.vcpus -= vcpus;
        Ok(Reservation {
            capacity: self.clone(),
            memory_mib,
            vcpus,
        })
    }
}

/// Ownership moves from the create future to the running pod. Cancellation or
/// failed launch drops it; a registered pod releases only after teardown.
#[must_use]
#[derive(Debug)]
pub(crate) struct Reservation {
    capacity: Capacity,
    memory_mib: u64,
    vcpus: u32,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if let Ok(mut available) = self.capacity.0.lock() {
            available.memory_mib += self.memory_mib;
            available.vcpus += self.vcpus;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn spec() -> nucleus_spec::PodSpec {
        serde_json::from_str(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{}}"#).unwrap()
    }
    #[test]
    fn concurrent_reservations_conserve_capacity_and_return_it_on_drop() {
        let capacity = Capacity::new(1280, 2);
        let held = std::thread::scope(|scope| {
            let tasks: Vec<_> = (0..8)
                .map(|_| {
                    let capacity = capacity.clone();
                    scope.spawn(move || capacity.reserve(&spec()))
                })
                .collect();
            tasks
                .into_iter()
                .filter_map(|t| t.join().unwrap().ok())
                .collect::<Vec<_>>()
        });
        assert_eq!(held.len(), 2);
        assert!(capacity.reserve(&spec()).is_err());
        drop(held);
        let first = capacity.reserve(&spec()).unwrap();
        let second = capacity.reserve(&spec()).unwrap();
        drop((first, second));
    }
    #[test]
    fn host_reserves_and_cpu_capacity_are_applied() {
        let args = CapacityArgs {
            node_memory_mib: Some(1792),
            node_vcpus: Some(3),
            host_reserve_memory_mib: 512,
            host_reserve_vcpus: 2,
        };
        let capacity = args.build().unwrap();
        let held = capacity.reserve(&spec()).unwrap();
        assert!(capacity.reserve(&spec()).is_err());
        drop(held);
        assert!(capacity.reserve(&spec()).is_ok());
    }
}
