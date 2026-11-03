//! Service guests: long-lived microVMs the node's OPERATOR declares and the node keeps running.
//!
//! # How a service guest differs from a pod
//!
//! An ordinary pod is created by a caller of `POST /v1/pods`, runs one task, and ends at its
//! deadline. Its root filesystem is read-only, its writable disk is scratch that dies with it,
//! and it has no network interface unless its spec carries a network policy (`net::NetnsPlan`,
//! `firecracker_config::lower_network_interfaces`). A service guest adds three things, and every
//! one of them is an operator decision, never a spec author's:
//!
//! * **A persistent volume.** A writable block image that outlives each launch, for state such
//!   as a console's Olog stores. Its host path is DERIVED from the service name under the node's
//!   state directory ([`ServicePlan::volume`]); the operator states only a size, so no file can
//!   name a path outside that root.
//! * **A restart policy.** The node relaunches the guest after it exits, with capped backoff,
//!   and gives up (and says so) on a crash loop ([`RestartPolicy::decide`]).
//! * **Ingress.** A host TCP listener whose connections are carried into the guest over VSOCK,
//!   to a port the guest listens on ([`IngressEntry`]). Not a NIC: a service guest has no
//!   network interface at all, exactly like an ordinary pod with no policy. The registry
//!   refuses a service whose spec carries a network policy, so a NIC never comes with ingress.
//!
//! # Why the operator file, not the pod spec
//!
//! The pod spec SELECTS and the operator DEFINES (the same split as `upstreams.rs`). A public
//! listener and a disk that survives the pod are authority over the HOST, not over the guest:
//! any caller that could write them into a spec could publish a port on the node's address or
//! keep state past the end of its grant. So there is no spec field for either. The only
//! constructor of a [`ServicePlan`] reads this registry, which only the node's operator writes,
//! and nothing reachable from `POST /v1/pods` builds one. An ordinary pod therefore cannot get a
//! volume or an ingress port by any spec it can write.
//!
//! # What this does not do yet
//!
//! It decides; it does not launch. Stage 2 wires [`ServicePlan`] into the Firecracker launch
//! path (attach the volume drive, start the ingress bridges, run [`Supervisor`] against the real
//! launcher). Until then the node has no `--services` flag and no service guest runs.

// Not wired into the launch path yet (stage 2), so outside tests every item is dead.
#![cfg_attr(not(test), allow(dead_code))]

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

/// The largest persistent volume a service may declare, in MiB (1 TiB). A bound, not a target:
/// a typo of three zeros should be a refusal, not a disk-filling sparse file.
pub const MAX_VOLUME_MIB: u64 = 1024 * 1024;

/// Restarts within any rolling hour past which the node stops relaunching and reports a crash
/// loop, when the operator does not say. A guest that dies sixty times an hour is not serving.
pub const DEFAULT_MAX_RESTARTS_PER_HOUR: u32 = 30;

/// The name of a service: `[a-z0-9-]{1,32}`, starting with a letter.
///
/// Small on purpose. It becomes a directory name under the node's state root, a log field, and
/// (stage 2) a component of the guest's node-assigned identity, so it must be safe in all three
/// without escaping.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServiceName(String);

impl ServiceName {
    /// Parse a service name.
    ///
    /// # Errors
    /// Empty, longer than 32, not starting with a lower-case letter, or containing anything but
    /// `[a-z0-9-]`.
    pub fn new(name: &str) -> Result<Self, String> {
        let ok = !name.is_empty()
            && name.len() <= 32
            && name.as_bytes()[0].is_ascii_lowercase()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if ok {
            Ok(Self(name.to_owned()))
        } else {
            Err(format!(
                "service name {name:?} must be 1-32 of [a-z0-9-], starting with a letter"
            ))
        }
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ServiceName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// One ingress mapping: connections accepted on `listen` (on the host) are carried over VSOCK
/// to `guest_port` (in the guest). Bytes only: the node neither terminates TLS nor reads them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressEntry {
    /// The host address the node listens on.
    pub listen: SocketAddr,
    /// The VSOCK port the guest listens on.
    pub guest_port: u32,
}

/// When the node relaunches a service guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartPolicy {
    /// After every exit, clean or not.
    Always(Backoff),
    /// Only after an exit that was not clean.
    OnFailure(Backoff),
    /// Never: the guest runs once.
    Never,
}

/// How long the node waits before a relaunch, and when it stops trying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    /// The wait before the first relaunch after a quiet period.
    pub initial: Duration,
    /// The cap the doubling stops at.
    pub max: Duration,
    /// Relaunches allowed in any rolling hour before the node gives up.
    pub max_restarts_per_hour: u32,
}

/// How a launch ended, as the supervisor saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitKind {
    /// The guest exited by itself with success, or the node stopped it on request.
    Clean,
    /// Anything else: a non-zero exit, a VMM death, a launch that never came up.
    Failed,
}

/// What the supervisor does after an exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestartDecision {
    /// Relaunch after this long.
    RestartAfter(Duration),
    /// The policy says this exit is final.
    Stop,
    /// A crash loop: too many relaunches in the last hour. The node stops relaunching and must
    /// raise this as an alarm, not log it quietly.
    GiveUp {
        /// Why, for the alarm.
        reason: String,
    },
}

impl RestartPolicy {
    /// Decide what follows an exit of kind `exit` at `now`, given the instants of the previous
    /// relaunches (any order) and how many consecutive failures preceded this one.
    ///
    /// Pure, so the property "a crash loop ends in `GiveUp`, never in an unbounded relaunch" is
    /// a test, not a hope.
    #[must_use]
    pub fn decide(
        &self,
        exit: ExitKind,
        now: Duration,
        previous_restarts: &[Duration],
        consecutive_failures: u32,
    ) -> RestartDecision {
        let backoff = match (self, exit) {
            (Self::Never, _) | (Self::OnFailure(_), ExitKind::Clean) => {
                return RestartDecision::Stop;
            }
            (Self::Always(b) | Self::OnFailure(b), _) => b,
        };
        let hour = Duration::from_secs(3600);
        let recent = previous_restarts
            .iter()
            .filter(|t| now.saturating_sub(**t) < hour)
            .count();
        if recent >= backoff.max_restarts_per_hour as usize {
            return RestartDecision::GiveUp {
                reason: format!(
                    "{recent} relaunches in the last hour reach the limit of {}; not relaunching",
                    backoff.max_restarts_per_hour
                ),
            };
        }
        // initial * 2^(failures), capped; a clean exit under `Always` waits `initial`.
        let shift = match exit {
            ExitKind::Clean => 0,
            ExitKind::Failed => consecutive_failures.min(20),
        };
        let wait = backoff
            .initial
            .checked_mul(1u32 << shift)
            .unwrap_or(backoff.max)
            .min(backoff.max);
        RestartDecision::RestartAfter(wait)
    }
}

/// One declared service, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceEntry {
    /// Its name.
    pub name: ServiceName,
    /// The pod spec file the node launches it from (absolute; the operator's file).
    pub spec: PathBuf,
    /// The persistent volume's size in MiB, if it has one.
    pub volume_mib: Option<u64>,
    /// Its ingress mappings.
    pub ingress: Vec<IngressEntry>,
    /// When it is relaunched.
    pub restart: RestartPolicy,
}

/// The operator's service registry (`[[service]]` tables).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceRegistry {
    services: Vec<ServiceEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryFile {
    #[serde(default)]
    service: Vec<ServiceFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceFile {
    name: String,
    spec: PathBuf,
    #[serde(default)]
    volume: Option<VolumeFile>,
    #[serde(default)]
    ingress: Vec<IngressFile>,
    restart: RestartFile,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VolumeFile {
    size_mib: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IngressFile {
    listen: SocketAddr,
    guest_port: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestartFile {
    policy: RestartKind,
    #[serde(default)]
    initial_secs: Option<u64>,
    #[serde(default)]
    max_secs: Option<u64>,
    #[serde(default)]
    max_restarts_per_hour: Option<u32>,
}

#[derive(Deserialize, Clone, Copy)]
#[serde(rename_all = "kebab-case")]
enum RestartKind {
    Always,
    OnFailure,
    Never,
}

/// VSOCK ports the guest may not be asked to listen on for ingress: every port the node's own
/// host-side listeners use (`nucleus_ifc_kernel::VsockListener`). A guest port equal to one of
/// those is not a collision Firecracker would catch (the directions differ), but it is a
/// confusion no operator means, so it is refused rather than reasoned about.
fn reserved_ports() -> BTreeSet<u32> {
    nucleus_ifc_kernel::VsockListener::ALL
        .iter()
        .map(|l| l.port())
        .collect()
}

impl ServiceRegistry {
    /// Parse and validate a registry.
    ///
    /// Refuses, naming the service: a bad name or a name defined twice; a relative spec path;
    /// a volume of zero or above [`MAX_VOLUME_MIB`]; an ingress listen port of zero, or one
    /// address claimed twice (in one service or across two); a guest port of zero or one the
    /// node reserves; restart timings that are zero or inverted; a backoff on `never`.
    ///
    /// # Errors
    /// The first refusal.
    pub fn from_toml_str(text: &str) -> Result<Self, String> {
        let file: RegistryFile = toml::from_str(text).map_err(|e| e.to_string())?;
        let reserved = reserved_ports();
        let mut names = BTreeSet::new();
        let mut listens = BTreeSet::new();
        let mut services = Vec::with_capacity(file.service.len());
        for s in file.service {
            let name = ServiceName::new(&s.name)?;
            if !names.insert(name.clone()) {
                return Err(format!("service {name} is defined twice"));
            }
            if !s.spec.is_absolute() {
                return Err(format!("service {name}: spec must be an absolute path"));
            }
            let volume_mib = match s.volume {
                None => None,
                Some(VolumeFile { size_mib: 0 }) => {
                    return Err(format!("service {name}: volume size_mib must be above 0"));
                }
                Some(VolumeFile { size_mib }) if size_mib > MAX_VOLUME_MIB => {
                    return Err(format!(
                        "service {name}: volume size_mib {size_mib} is above {MAX_VOLUME_MIB}"
                    ));
                }
                Some(VolumeFile { size_mib }) => Some(size_mib),
            };
            let mut ingress = Vec::with_capacity(s.ingress.len());
            for i in s.ingress {
                if i.listen.port() == 0 {
                    return Err(format!(
                        "service {name}: ingress listen {} has port 0",
                        i.listen
                    ));
                }
                if !listens.insert(i.listen) {
                    return Err(format!(
                        "service {name}: ingress listen {} is claimed twice",
                        i.listen
                    ));
                }
                if i.guest_port == 0 || reserved.contains(&i.guest_port) {
                    return Err(format!(
                        "service {name}: ingress guest_port {} is reserved by the node",
                        i.guest_port
                    ));
                }
                ingress.push(IngressEntry {
                    listen: i.listen,
                    guest_port: i.guest_port,
                });
            }
            let restart = restart(&name, &s.restart)?;
            services.push(ServiceEntry {
                name,
                spec: s.spec,
                volume_mib,
                ingress,
                restart,
            });
        }
        Ok(Self { services })
    }

    /// Every declared service.
    #[must_use]
    pub fn services(&self) -> &[ServiceEntry] {
        &self.services
    }

    /// The launch plan for service `name`, with its volume under `state_dir`, once its spec has
    /// been read. `None` when no such service is declared.
    ///
    /// # Errors
    /// The spec carries a network policy (a NIC); its vsock port collides with an ingress port;
    /// or it has no vsock section, so ingress would have nowhere to go.
    pub fn plan(
        &self,
        name: &ServiceName,
        spec: &nucleus_spec::PodSpec,
        state_dir: &Path,
    ) -> Option<Result<ServicePlan, String>> {
        let entry = self.services.iter().find(|s| &s.name == name)?;
        Some(ServicePlan::new(entry, spec, state_dir))
    }
}

fn restart(name: &ServiceName, r: &RestartFile) -> Result<RestartPolicy, String> {
    let timings =
        r.initial_secs.is_some() || r.max_secs.is_some() || r.max_restarts_per_hour.is_some();
    let kind = r.policy;
    if matches!(kind, RestartKind::Never) {
        if timings {
            return Err(format!(
                "service {name}: restart policy `never` takes no backoff"
            ));
        }
        return Ok(RestartPolicy::Never);
    }
    let initial = r.initial_secs.unwrap_or(1);
    let max = r.max_secs.unwrap_or(300);
    let per_hour = r
        .max_restarts_per_hour
        .unwrap_or(DEFAULT_MAX_RESTARTS_PER_HOUR);
    if initial == 0 || max == 0 || per_hour == 0 || initial > max {
        return Err(format!(
            "service {name}: restart needs 0 < initial_secs <= max_secs and max_restarts_per_hour > 0"
        ));
    }
    let b = Backoff {
        initial: Duration::from_secs(initial),
        max: Duration::from_secs(max),
        max_restarts_per_hour: per_hour,
    };
    Ok(match kind {
        RestartKind::Always => RestartPolicy::Always(b),
        RestartKind::OnFailure => RestartPolicy::OnFailure(b),
        RestartKind::Never => RestartPolicy::Never,
    })
}

/// The persistent volume of one service: a host path the node derived. Only
/// [`ServicePlan::new`] constructs one, so only a registry entry can put a writable,
/// surviving drive on a guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceVolume {
    host_path: PathBuf,
    size_mib: u64,
}

impl ServiceVolume {
    /// The host file backing it.
    #[must_use]
    pub fn host_path(&self) -> &Path {
        &self.host_path
    }

    /// Its size in MiB.
    #[must_use]
    pub fn size_mib(&self) -> u64 {
        self.size_mib
    }
}

/// Everything the launch path needs to run one service guest, decided before anything runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePlan {
    name: ServiceName,
    volume: Option<ServiceVolume>,
    ingress: Vec<IngressEntry>,
    restart: RestartPolicy,
}

impl ServicePlan {
    fn new(
        entry: &ServiceEntry,
        spec: &nucleus_spec::PodSpec,
        state_dir: &Path,
    ) -> Result<Self, String> {
        let name = &entry.name;
        if spec.spec.network.is_some() {
            return Err(format!(
                "service {name}: its spec carries a network policy. A service guest has no \
                 network interface; its ingress rides VSOCK and its egress goes through the \
                 broker. Remove `network` from the spec."
            ));
        }
        if !spec.spec.credentialed_egress.is_empty() {
            return Err(format!(
                "service {name}: its spec names credentialed upstreams. A service guest's \
                 upstreams are its jobs' (`job_grant`), held in the node's job registry; a spec \
                 that also named them would be a second author of the same authority."
            ));
        }
        if !entry.ingress.is_empty() {
            let Some(vsock) = spec.spec.vsock.as_ref() else {
                return Err(format!(
                    "service {name}: ingress needs a vsock section in the spec"
                ));
            };
            if let Some(i) = entry.ingress.iter().find(|i| i.guest_port == vsock.port) {
                return Err(format!(
                    "service {name}: ingress guest_port {} is the spec's own vsock port",
                    i.guest_port
                ));
            }
        }
        Ok(Self {
            name: name.clone(),
            volume: entry.volume_mib.map(|size_mib| ServiceVolume {
                host_path: volume_path(state_dir, name),
                size_mib,
            }),
            ingress: entry.ingress.clone(),
            restart: entry.restart,
        })
    }

    /// The service's name.
    #[must_use]
    pub fn name(&self) -> &ServiceName {
        &self.name
    }

    /// The persistent volume, if any.
    #[must_use]
    pub fn volume(&self) -> Option<&ServiceVolume> {
        self.volume.as_ref()
    }

    /// The ingress mappings.
    #[must_use]
    pub fn ingress(&self) -> &[IngressEntry] {
        &self.ingress
    }

    /// The restart policy.
    #[must_use]
    pub fn restart(&self) -> RestartPolicy {
        self.restart
    }
}

/// `<state_dir>/services/<name>/volume.img`. A function of the name alone, which the name's
/// charset keeps inside `state_dir`.
#[must_use]
pub fn volume_path(state_dir: &Path, name: &ServiceName) -> PathBuf {
    state_dir
        .join("services")
        .join(name.as_str())
        .join("volume.img")
}

/// Start one ingress bridge per mapping in `plan`, each carrying its listener's connections to
/// the guest's port over the VMM's VSOCK socket `uds`. All or none, by construction: every
/// listener is bound before any bridge serves, so when one address cannot be bound the others are
/// dropped unserved and no connection was ever carried.
///
/// # Errors
/// A listener failed to bind.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) async fn start_ingress(
    plan: &ServicePlan,
    uds: &Path,
) -> std::io::Result<Vec<crate::vsock_bridge::VsockBridge>> {
    let mut bound = Vec::with_capacity(plan.ingress.len());
    for i in &plan.ingress {
        bound.push((tokio::net::TcpListener::bind(i.listen).await?, i.guest_port));
    }
    let mut started = Vec::with_capacity(bound.len());
    for (listener, port) in bound {
        started.push(crate::vsock_bridge::VsockBridge::serve(
            listener,
            uds.to_path_buf(),
            port,
        )?);
    }
    Ok(started)
}

/// What a supervisor needs from a launcher. The real one (stage 2) is the Firecracker launch
/// path; tests drive a fake.
#[allow(async_fn_in_trait)]
pub trait ServiceLauncher {
    /// Launch one life of the service and wait for it to end.
    async fn run_once(&self, plan: &ServicePlan) -> ExitKind;
    /// Wait `d` (a test's launcher advances a fake clock instead).
    async fn wait(&self, d: Duration);
    /// The supervisor's clock.
    fn now(&self) -> Duration;
}

/// Why a supervisor returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorEnd {
    /// The policy stopped it.
    Stopped,
    /// A crash loop; raise this.
    GaveUp(String),
}

/// Keeps one service guest running under its plan's restart policy.
pub struct Supervisor<'a, L: ServiceLauncher> {
    launcher: &'a L,
    plan: ServicePlan,
}

impl<'a, L: ServiceLauncher> Supervisor<'a, L> {
    /// A supervisor for `plan`.
    pub fn new(launcher: &'a L, plan: ServicePlan) -> Self {
        Self { launcher, plan }
    }

    /// Run until the restart policy stops or gives up. Returns how it ended and how many
    /// lives were launched.
    pub async fn run(&self) -> (SupervisorEnd, u32) {
        let mut restarts: Vec<Duration> = Vec::new();
        let mut failures = 0u32;
        let mut lives = 0u32;
        loop {
            lives = lives.saturating_add(1);
            let exit = self.launcher.run_once(&self.plan).await;
            failures = match exit {
                ExitKind::Clean => 0,
                ExitKind::Failed => failures.saturating_add(1),
            };
            let now = self.launcher.now();
            match self
                .plan
                .restart
                .decide(exit, now, &restarts, failures.saturating_sub(1))
            {
                RestartDecision::Stop => return (SupervisorEnd::Stopped, lives),
                RestartDecision::GiveUp { reason } => {
                    tracing::error!(service = %self.plan.name, %reason, "service guest crash loop");
                    return (SupervisorEnd::GaveUp(reason), lives);
                }
                RestartDecision::RestartAfter(d) => {
                    self.launcher.wait(d).await;
                    restarts.push(self.launcher.now());
                }
            }
        }
    }
}

#[cfg(test)]
#[path = "service_guest_tests.rs"]
mod tests;
