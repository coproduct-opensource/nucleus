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
    /// Capped by visible cgroup v2 quotas, rounded down to whole CPUs.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..))]
    node_vcpus: Option<u32>,
    #[arg(long, default_value_t = 512)]
    host_reserve_memory_mib: u64,
    #[arg(long, default_value_t = 0)]
    host_reserve_vcpus: u32,
}
impl CapacityArgs {
    pub(crate) fn build(&self) -> Result<Capacity, ApiError> {
        self.build_with_limits(cgroup_limits()?)
    }

    fn build_with_limits(&self, limits: CgroupLimits) -> Result<Capacity, ApiError> {
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
        let memory = limits.memory_mib.map_or(memory, |limit| memory.min(limit));
        let cpus = match self.node_vcpus {
            Some(value) => value,
            None => u32::try_from(std::thread::available_parallelism()?.get())
                .map_err(|_| ApiError::Driver("host CPU count is unrepresentable".into()))?,
        };
        let cpus = limits.vcpus.map_or(cpus, |limit| cpus.min(limit));
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

/// Visible ancestor ceilings for a node in a delegated cgroup. CPU quotas are
/// rounded down: pod admission promises whole vCPUs, not fractional shares.
struct CgroupLimits {
    memory_mib: Option<u64>,
    vcpus: Option<u32>,
}
fn cgroup_limits() -> Result<CgroupLimits, ApiError> {
    if !cfg!(target_os = "linux") {
        return Ok(CgroupLimits {
            memory_mib: None,
            vcpus: None,
        });
    }
    let membership = std::fs::read_to_string("/proc/self/cgroup")?;
    read_cgroup_limits(std::path::Path::new("/sys/fs/cgroup"), &membership)
}

fn read_cgroup_limits(root: &std::path::Path, membership: &str) -> Result<CgroupLimits, ApiError> {
    let mut limits = CgroupLimits {
        memory_mib: None,
        vcpus: None,
    };
    let Some(relative) = membership.lines().find_map(|line| line.strip_prefix("0::")) else {
        return Ok(limits);
    };
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
    while current.starts_with(root) {
        if let Some(value) = read_limit(&current.join("memory.max"))? {
            if value.trim() != "max" {
                let mib = value
                    .trim()
                    .parse::<u64>()
                    .map_err(|_| ApiError::Driver("invalid cgroup memory.max".into()))?
                    / (1024 * 1024);
                limits.memory_mib = Some(limits.memory_mib.map_or(mib, |prior| prior.min(mib)));
            }
        }
        if let Some(value) = read_limit(&current.join("cpu.max"))? {
            if let Some(cpus) = cpu_quota(&value)? {
                limits.vcpus = Some(limits.vcpus.map_or(cpus, |prior| prior.min(cpus)));
            }
        }
        current.pop();
    }
    Ok(limits)
}

fn read_limit(path: &std::path::Path) -> Result<Option<String>, ApiError> {
    match std::fs::read_to_string(path) {
        Ok(value) => Ok(Some(value)),
        // A controller need not be enabled at every ancestor.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn cpu_quota(value: &str) -> Result<Option<u32>, ApiError> {
    let invalid = || ApiError::Driver("invalid cgroup cpu.max".into());
    let fields: Vec<_> = value.split_whitespace().collect();
    let [quota, period] = fields.as_slice() else {
        return Err(invalid());
    };
    let period = period.parse::<u64>().map_err(|_| invalid())?;
    if period == 0 {
        return Err(invalid());
    }
    if *quota == "max" {
        return Ok(None);
    }
    let quota = quota.parse::<u64>().map_err(|_| invalid())?;
    if quota == 0 {
        return Err(invalid());
    }
    // Larger quotas cannot constrain the u32 operator capacity.
    Ok(Some(u32::try_from(quota / period).unwrap_or(u32::MAX)))
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
    fn cpu_quotas_preserve_whole_cpu_capacity() {
        for (input, expected) in [
            ("max 100000", None),
            ("200000 100000", Some(2)),
            ("150000 100000", Some(1)),
            ("50000 100000", Some(0)),
        ] {
            assert_eq!(cpu_quota(input).unwrap(), expected);
        }
        for input in [
            "max",
            "1 0",
            "0 100000",
            "bad 100000",
            "100000 bad",
            "1 2 3",
        ] {
            assert!(cpu_quota(input).is_err(), "{input}");
        }
    }
    #[test]
    fn delegated_capacity_uses_tightest_visible_ancestor() {
        let dir = tempfile::tempdir().unwrap();
        let child = dir.path().join("parent/node");
        std::fs::create_dir_all(&child).unwrap();
        std::fs::write(dir.path().join("cpu.max"), "300000 100000").unwrap();
        std::fs::write(dir.path().join("parent/cpu.max"), "150000 100000").unwrap();
        std::fs::write(child.join("cpu.max"), "max 100000").unwrap();
        std::fs::write(dir.path().join("memory.max"), "8589934592").unwrap();
        std::fs::write(child.join("memory.max"), "4294967296").unwrap();
        let limits = read_cgroup_limits(dir.path(), "0::/parent/node\n").unwrap();
        assert_eq!(limits.vcpus, Some(1));
        assert_eq!(limits.memory_mib, Some(4096));
        let args = CapacityArgs {
            node_memory_mib: Some(4096),
            node_vcpus: Some(8),
            host_reserve_memory_mib: 0,
            host_reserve_vcpus: 0,
        };
        let capacity = args.build_with_limits(limits).unwrap();
        let held = capacity.reserve(&spec()).unwrap();
        assert!(capacity.reserve(&spec()).is_err());
        drop(held);
        assert!(capacity.reserve(&spec()).is_ok());
        std::fs::write(child.join("cpu.max"), "50000 100000").unwrap();
        assert_eq!(
            read_cgroup_limits(dir.path(), "0::/parent/node")
                .unwrap()
                .vcpus,
            Some(0)
        );
        assert!(
            args.build_with_limits(read_cgroup_limits(dir.path(), "0::/parent/node").unwrap())
                .is_err()
        );
        std::fs::write(child.join("cpu.max"), "unreadable quota").unwrap();
        assert!(read_cgroup_limits(dir.path(), "0::/parent/node").is_err());
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
        let capacity = args
            .build_with_limits(CgroupLimits {
                memory_mib: None,
                vcpus: None,
            })
            .unwrap();
        let held = capacity.reserve(&spec()).unwrap();
        assert!(capacity.reserve(&spec()).is_err());
        drop(held);
        assert!(capacity.reserve(&spec()).is_ok());
    }
}
