//! What one pod may take from its node: memory, vCPUs and huge pages (#3130).
//!
//! # The rule
//!
//! The node owns a per-pod ceiling for each resource, set by the operator and finite by default.
//! A spec asks for a size; [`admit`] (called by `spec_posture::admit`, the one create-time decider)
//! refuses by name a size above the ceiling. Nothing is clamped: a pod that silently got less than
//! it asked for would fail later for a reason its author cannot see (#3124, #3125). An absent field
//! means the node's default size, [`DEFAULT_MEMORY_MIB`] and [`DEFAULT_VCPUS`], which is what
//! Firecracker was always given for one.
//!
//! Every pod is then limited by a cgroup the NODE derives from that size ([`node_cgroup`]):
//! `memory.max`, `cpu.max` and `pids.max` (plus `hugetlb.2MB.max` when it asked for huge pages).
//! The spec's `cgroup` used to be the only limit, and it was optional, so a spec without one ran
//! its VMM with no memory, CPU or pids limit at all. A spec's `cgroup.settings` may now only
//! LOWER a node limit, or set another file of a resource controller. It may not raise a node
//! limit, lift one (`max`, `-1`), or write a core file (`cgroup.procs`, `cgroup.kill`, `tasks`,
//! `release_agent`) or a controller that grants rather than limits (`devices`).
//!
//! # The defaults, and why fixed rather than derived from the host
//!
//! `--max-pod-memory-mib 8192`, `--max-pod-vcpus 4`, `--pod-huge-pages refused`.
//!
//! - **Fixed, not a fraction of host capacity.** A refusal is a verdict an author reads and acts
//!   on; a ceiling derived from `/proc/meminfo` gives the same spec different verdicts on nodes
//!   with identical flags, and moves when a host is resized without anyone deciding it should.
//!   A fixed default is the same everywhere, and an operator who wants a host-sized ceiling says
//!   so with the flag.
//! - **8192 MiB** is the largest any measured workload on the reference builder declares
//!   (`lean-build`, `.gatehouse/pipeline.writ`), and 16x the default pod. **4 vCPUs**: a pod
//!   that needs more is one an operator should have chosen to run.
//! - **Huge pages are refused** until the operator offers them. They come from the hugetlbfs pool
//!   (`vm.nr_hugepages`) that every pod on the node shares, and hugetlb memory is not charged to
//!   `memory.max`, so the memory ceiling does not bound them. When offered, each pod's draw on the
//!   pool is bounded by `hugetlb.2MB.max` at its admitted memory size.
//!
//! # The cgroup values
//!
//! - `memory.max` is the guest size plus [`VMM_OVERHEAD_MIB`]. Guest RAM is a lazily faulted
//!   memfd charged to the VMM's cgroup as the guest touches it, so this is the line the host pays
//!   up to. Firecracker documents its own overhead at under 5 MiB; the margin also covers page
//!   cache from the pod's drives, which is reclaimable and charged to the same cgroup.
//! - `cpu.max` is `vcpus * 100ms` per `100ms` period: the pod's vCPU threads together get at most
//!   the CPUs it was admitted with.
//! - `pids.max` is [`VMM_PIDS_MAX`]: Firecracker runs one thread per vCPU (at most 32) plus a VMM
//!   and an API thread, and forks nothing.
//!
//! The container driver applies the same size as `HostConfig` (`memory`, `memory_swap`,
//! `nano_cpus`, `pids_limit`), where the pod's own processes are in the container.
//!
//! Aggregate memory and CPU admission lives in `node_capacity`: each launch
//! reserves its size plus VMM overhead until failed launch or completed teardown.

use nucleus_spec::{CgroupSetting, HugePages, PodSpec};

/// Guest memory for a pod that does not say: what Firecracker was always given.
pub(crate) const DEFAULT_MEMORY_MIB: u64 = 512;
/// vCPUs for a pod that does not say.
pub(crate) const DEFAULT_VCPUS: u32 = 1;
/// `--max-pod-memory-mib` when the operator does not say. See the module docs.
const DEFAULT_MAX_POD_MEMORY_MIB: u64 = 8192;
/// `--max-pod-vcpus` when the operator does not say.
const DEFAULT_MAX_POD_VCPUS: u32 = 4;
/// What the VMM process may use beyond the guest's memory. See the module docs.
pub(crate) const VMM_OVERHEAD_MIB: u64 = 128;
/// The VMM's task limit. See the module docs.
pub(crate) const VMM_PIDS_MAX: u64 = 64;
/// A container pod's task limit: the workload's own processes run in it.
pub(crate) const CONTAINER_PIDS_MAX: i64 = 4096;
/// The CFS period the node's CPU limit is expressed in, in microseconds.
const CPU_PERIOD_US: u64 = 100_000;
const MIB: u64 = 1024 * 1024;

/// Controllers whose files a spec may set. Every one LIMITS; `devices` and `freezer` are not here
/// because a write to them grants or stops rather than bounds, and the core `cgroup.*` interface
/// files (`procs`, `kill`, `subtree_control`) have no controller prefix at all.
const SPEC_SETTABLE_CONTROLLERS: &[&str] =
    &["cpu", "cpuset", "io", "blkio", "memory", "pids", "hugetlb"];

/// The operator's per-pod ceilings, flattened into `Args`.
#[derive(clap::Args, Debug, Clone)]
pub(crate) struct PodCeilingArgs {
    /// The most guest memory one pod may ask for, in MiB. A spec asking for more is refused at
    /// create. Finite by default; see `pod_resources.rs` for why 8192.
    #[arg(
        long = "max-pod-memory-mib",
        env = "NUCLEUS_NODE_MAX_POD_MEMORY_MIB",
        default_value_t = DEFAULT_MAX_POD_MEMORY_MIB,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    pub max_pod_memory_mib: u64,
    /// The most vCPUs one pod may ask for (1 to 32, Firecracker's limit). A spec asking for more
    /// is refused at create.
    #[arg(
        long = "max-pod-vcpus",
        env = "NUCLEUS_NODE_MAX_POD_VCPUS",
        default_value_t = DEFAULT_MAX_POD_VCPUS,
        value_parser = clap::value_parser!(u32).range(1..=32) // 32: Firecracker's own vCPU limit
    )]
    pub max_pod_vcpus: u32,
    /// Whether a pod may back its memory with 2 MiB huge pages from the node's shared hugetlbfs
    /// pool. Refused by default: the pool is the operator's to hand out.
    #[arg(
        long = "pod-huge-pages",
        env = "NUCLEUS_NODE_POD_HUGE_PAGES",
        value_enum,
        default_value = "refused"
    )]
    pub pod_huge_pages: HugePagesOffer,
}

/// Whether this node lends its hugetlbfs pool to pods.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HugePagesOffer {
    /// A spec asking for huge pages is refused.
    Refused,
    /// A spec may ask; its draw is bounded by `hugetlb.2MB.max`.
    Offered,
}

/// The ceilings in force. No `Default`: a ceiling is a grant, and there is no neutral one.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PodCeilings {
    max_memory_mib: u64,
    max_vcpus: u32,
    huge_pages: HugePagesOffer,
}

impl PodCeilingArgs {
    pub(crate) fn ceilings(&self) -> PodCeilings {
        let Self {
            max_pod_memory_mib,
            max_pod_vcpus,
            pod_huge_pages,
        } = *self;
        PodCeilings {
            max_memory_mib: max_pod_memory_mib,
            max_vcpus: max_pod_vcpus,
            huge_pages: pod_huge_pages,
        }
    }
}

#[cfg(test)]
impl PodCeilings {
    /// The flag defaults, without parsing an argv.
    pub(crate) fn defaults() -> Self {
        Self::new(
            DEFAULT_MAX_POD_MEMORY_MIB,
            DEFAULT_MAX_POD_VCPUS,
            HugePagesOffer::Refused,
        )
    }

    pub(crate) fn new(max_memory_mib: u64, max_vcpus: u32, huge_pages: HugePagesOffer) -> Self {
        Self {
            max_memory_mib,
            max_vcpus,
            huge_pages,
        }
    }
}

/// A pod's size: what its spec asked for, with the node's default for what it did not say.
///
/// The one place the defaults are applied, so the VM config, the cgroup and the container limits
/// read the same size (ADR 0007 G-1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PodSize {
    memory_mib: u64,
    vcpus: u32,
    huge_pages: Option<HugePages>,
}

impl PodSize {
    pub(crate) fn of(spec: &PodSpec) -> Self {
        let r = spec.spec.resources.as_ref();
        Self {
            memory_mib: r.and_then(|r| r.memory_mib).unwrap_or(DEFAULT_MEMORY_MIB),
            vcpus: r.and_then(|r| r.cpu_cores).unwrap_or(DEFAULT_VCPUS),
            huge_pages: r.and_then(|r| r.huge_pages),
        }
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn memory_mib(self) -> u64 {
        self.memory_mib
    }

    pub(crate) fn vcpus(self) -> u32 {
        self.vcpus
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn huge_pages(self) -> Option<HugePages> {
        self.huge_pages
    }

    /// The guest's memory in bytes.
    pub(crate) fn memory_bytes(self) -> u64 {
        self.memory_mib.saturating_mul(MIB)
    }

    /// `memory.max` for the VMM: the guest plus the VMM's own overhead.
    fn vmm_memory_bytes(self) -> u64 {
        self.memory_mib
            .saturating_add(VMM_OVERHEAD_MIB)
            .saturating_mul(MIB)
    }

    /// `hugetlb.2MB.max`: the guest's memory, rounded up to whole 2 MiB pages.
    fn hugetlb_bytes(self) -> u64 {
        self.memory_mib.div_ceil(2).saturating_mul(2 * MIB)
    }

    /// The CFS quota for the node's period.
    fn cpu_quota_us(self) -> u64 {
        u64::from(self.vcpus) * CPU_PERIOD_US
    }
}

/// Why a size or a cgroup setting was refused. Each names the field and the node's value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ResourceRefused {
    #[error(
        "resources.memory_mib {asked} is refused: this node admits 1 to {ceiling} MiB per pod \
         (--max-pod-memory-mib). A pod is never given less than it asked for."
    )]
    Memory { asked: u64, ceiling: u64 },
    #[error(
        "resources.cpu_cores {asked} is refused: this node admits 1 to {ceiling} vCPUs per pod \
         (--max-pod-vcpus). A pod is never given fewer than it asked for."
    )]
    Vcpus { asked: u32, ceiling: u32 },
    #[error(
        "resources.huge_pages is refused: this node does not offer huge pages (--pod-huge-pages). \
         They come from a hugetlbfs pool every pod on the node shares."
    )]
    HugePages,
    #[error(
        "cgroup.settings `{file}={value}` is refused: {why}. The node sets every pod's memory, \
         CPU and pids limits; a spec may only lower them."
    )]
    CgroupSetting {
        file: String,
        value: String,
        why: String,
    },
}

/// Refuse at create a size above the node's ceilings, or a cgroup setting that would raise or lift
/// a node limit. Called by `spec_posture::admit`.
pub(crate) fn admit(spec: &PodSpec, ceilings: &PodCeilings) -> Result<(), ResourceRefused> {
    let PodCeilings {
        max_memory_mib,
        max_vcpus,
        huge_pages,
    } = *ceilings;
    let size = PodSize::of(spec);
    if size.memory_mib == 0 || size.memory_mib > max_memory_mib {
        return Err(ResourceRefused::Memory {
            asked: size.memory_mib,
            ceiling: max_memory_mib,
        });
    }
    if size.vcpus == 0 || size.vcpus > max_vcpus {
        return Err(ResourceRefused::Vcpus {
            asked: size.vcpus,
            ceiling: max_vcpus,
        });
    }
    match (size.huge_pages, huge_pages) {
        (None, _) | (Some(HugePages::TwoMib), HugePagesOffer::Offered) => {}
        (Some(HugePages::TwoMib), HugePagesOffer::Refused) => {
            return Err(ResourceRefused::HugePages);
        }
    }
    if let Some(cgroup) = &spec.spec.cgroup {
        for setting in &cgroup.settings {
            spec_setting(setting, size)?;
        }
    }
    Ok(())
}

/// The cgroup hierarchy the host presents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CgroupVersion {
    V1,
    V2,
}

impl CgroupVersion {
    /// `/sys/fs/cgroup/cgroup.controllers` exists if and only if the unified v2 hierarchy is
    /// mounted there; a v1 host has per-controller directories instead.
    ///
    /// V2 when neither can be read: v2 is the modern default, and being wrong toward v2 fails
    /// loudly at launch (the jailer refuses) rather than placing a pod in a hierarchy nobody
    /// enforces.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn detect() -> Self {
        let root = std::path::Path::new("/sys/fs/cgroup");
        if !root.join("cgroup.controllers").exists() && root.join("cpu").is_dir() {
            Self::V1
        } else {
            Self::V2
        }
    }

    /// The jailer's `--cgroup-version` argument.
    pub(crate) fn as_arg(self) -> &'static str {
        match self {
            Self::V1 => "1",
            Self::V2 => "2",
        }
    }
}

/// A pod's cgroup limits, derived by the node. Minted only by [`node_cgroup`], so a launch cannot
/// be handed a cgroup that lacks the node's limits.
#[derive(Debug, Clone)]
pub(crate) struct NodeCgroup {
    version: CgroupVersion,
    settings: Vec<CgroupSetting>,
}

impl NodeCgroup {
    pub(crate) fn version(&self) -> CgroupVersion {
        self.version
    }

    /// In write order: the node's limits, each replaced in place by a spec value that lowers it,
    /// then the spec's other controller files.
    pub(crate) fn settings(&self) -> &[CgroupSetting] {
        &self.settings
    }

    /// The controllers the settings need enabled in every ancestor's `cgroup.subtree_control`.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn controllers(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for s in &self.settings {
            if let Some((c, _)) = s.file.split_once('.')
                && !out.contains(&c)
            {
                out.push(c);
            }
        }
        out
    }
}

/// The limits every pod's VMM runs under, merged with what its spec may add.
#[cfg(any(test, target_os = "linux"))]
pub(crate) fn node_cgroup(
    spec: &PodSpec,
    version: CgroupVersion,
) -> Result<NodeCgroup, ResourceRefused> {
    let size = PodSize::of(spec);
    let set = |file: &str, value: u64| CgroupSetting {
        file: file.to_string(),
        value: value.to_string(),
    };
    let mut settings = match version {
        CgroupVersion::V2 => vec![
            set("memory.max", size.vmm_memory_bytes()),
            set("memory.swap.max", 0),
            CgroupSetting {
                file: "cpu.max".to_string(),
                value: format!("{} {CPU_PERIOD_US}", size.cpu_quota_us()),
            },
            set("pids.max", VMM_PIDS_MAX),
        ],
        // The period is written before the quota: the kernel checks the quota against it.
        CgroupVersion::V1 => vec![
            set("memory.limit_in_bytes", size.vmm_memory_bytes()),
            // v1 bounds memory+swap together; memory must be set first.
            set("memory.memsw.limit_in_bytes", size.vmm_memory_bytes()),
            set("cpu.cfs_period_us", CPU_PERIOD_US),
            set("cpu.cfs_quota_us", size.cpu_quota_us()),
            set("pids.max", VMM_PIDS_MAX),
        ],
    };
    if size.huge_pages.is_some() {
        let file = match version {
            CgroupVersion::V2 => "hugetlb.2MB.max",
            CgroupVersion::V1 => "hugetlb.2MB.limit_in_bytes",
        };
        settings.push(set(file, size.hugetlb_bytes()));
    }
    if let Some(cgroup) = &spec.spec.cgroup {
        for setting in &cgroup.settings {
            spec_setting(setting, size)?;
            match settings.iter_mut().find(|s| s.file == setting.file) {
                Some(node) => node.value.clone_from(&setting.value),
                None => settings.push(setting.clone()),
            }
        }
    }
    Ok(NodeCgroup { version, settings })
}

/// What the node holds a file to, for the files whose limit it owns.
enum NodeLimit {
    /// A decimal count or byte value the spec may lower.
    AtMost(u64),
    /// `cpu.max`: `<quota> <period>`, at most `vcpus` CPUs.
    CpuMax(u32),
    /// The node's CFS period in v1, which the quota is measured against.
    NodeOnly,
}

fn node_limit(file: &str, size: PodSize) -> Option<NodeLimit> {
    Some(match file {
        "memory.max" | "memory.limit_in_bytes" | "memory.memsw.limit_in_bytes" => {
            NodeLimit::AtMost(size.vmm_memory_bytes())
        }
        "memory.swap.max" => NodeLimit::AtMost(0),
        "pids.max" => NodeLimit::AtMost(VMM_PIDS_MAX),
        "cpu.max" => NodeLimit::CpuMax(size.vcpus),
        "cpu.cfs_quota_us" => NodeLimit::AtMost(size.cpu_quota_us()),
        "cpu.cfs_period_us" => NodeLimit::NodeOnly,
        "hugetlb.2MB.max" | "hugetlb.2MB.limit_in_bytes" => NodeLimit::AtMost(
            // No huge pages asked for: the VMM draws nothing from the pool, so nothing above 0.
            size.huge_pages.map_or(0, |_| size.hugetlb_bytes()),
        ),
        _ => return None,
    })
}

/// A spec's cgroup setting, or the reason it may not be written.
fn spec_setting(setting: &CgroupSetting, size: PodSize) -> Result<(), ResourceRefused> {
    let CgroupSetting { file, value } = setting;
    let refuse = |why: String| ResourceRefused::CgroupSetting {
        file: file.clone(),
        value: value.clone(),
        why,
    };
    let controller = file.split_once('.').map(|(c, _)| c);
    if !controller.is_some_and(|c| SPEC_SETTABLE_CONTROLLERS.contains(&c)) {
        return Err(refuse(format!(
            "a spec may set only files of the {SPEC_SETTABLE_CONTROLLERS:?} controllers"
        )));
    }
    let decimal = |v: &str| -> Option<u64> {
        if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        v.parse().ok()
    };
    match node_limit(file, size) {
        None => Ok(()),
        Some(NodeLimit::NodeOnly) => Err(refuse(format!(
            "the node owns the CFS period ({CPU_PERIOD_US}us) its CPU limit is measured in"
        ))),
        Some(NodeLimit::AtMost(node)) => match decimal(value.trim()) {
            Some(v) if v <= node => Ok(()),
            Some(_) => Err(refuse(format!("the node's limit is {node}"))),
            None => Err(refuse(format!(
                "the value must be a plain decimal at most the node's {node} (`max`, `-1` and \
                 unit suffixes are not accepted)"
            ))),
        },
        Some(NodeLimit::CpuMax(vcpus)) => {
            let parsed = value
                .split_once(' ')
                .and_then(|(q, p)| Some((decimal(q)?, decimal(p)?)));
            match parsed {
                // quota/period <= vcpus, in integers.
                Some((q, p)) if p > 0 && u128::from(q) <= u128::from(vcpus) * u128::from(p) => {
                    Ok(())
                }
                _ => Err(refuse(format!(
                    "the value must be `<quota> <period>` in decimal microseconds, at most \
                     {vcpus} CPUs (the node's `{} {CPU_PERIOD_US}`)",
                    size.cpu_quota_us()
                ))),
            }
        }
    }
}

#[cfg(test)]
#[path = "pod_resources_tests.rs"]
mod tests;
