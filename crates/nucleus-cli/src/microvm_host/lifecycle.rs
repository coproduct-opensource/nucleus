//! The host container's lifecycle, and the witness that it is ready.
//!
//! [`host_state`] reads `container list --all --format json` into a
//! [`HostState`]. [`ensure_ready`] drives that state to running and mints a
//! [`MicroVmHost`] only once three independent things agree:
//!
//! 1. preflight found nothing unmet on the Mac;
//! 2. `nucleus-hostctl probe` inside the container opened `/dev/kvm` and
//!    created a VM (the authoritative nested-virtualization check);
//! 3. the node answered `/v1/health` over mTLS, with a client identity minted
//!    from the CA this module seeded.
//!
//! `MicroVmHost` has private fields and no other constructor, so holding one is
//! the evidence (ADR 0007 C-1).
//!
//! # Whose containers
//!
//! Every container this creates carries [`OWNER_LABEL`] set to its own name.
//! A container with the expected name but without that label belongs to
//! someone else: it is reported as [`StaleReason::NotOurs`] and never stopped,
//! started or deleted. The only way to act on a container is through an
//! [`Owned`], and only [`host_state`] makes one.

use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nucleus_spec::microvm_host::{
    self as pins, HOSTCTL, HostNames, NODE_PORT, NODE_STATE_DIR, OWNER_LABEL, RELAY_PORTS,
    REQUIRED_CAPS, SRV_MOUNT,
};
use serde::Deserialize;

use super::container_cli::{ContainerCli, Outcome, RunSpec};
use super::preflight::{self, KvmObservation, Unmet};

// ── ownership ───────────────────────────────────────────────────────

/// A container this installation created, as proved by its label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owned {
    name: String,
}

impl Owned {
    /// The container's name.
    pub fn name(&self) -> &str {
        &self.name
    }
}

// ── reading `container list` ───────────────────────────────────────

/// The fields of one `container list --all --format json` entry that are read.
#[derive(Debug, Deserialize)]
struct ListEntry {
    id: String,
    configuration: Configuration,
    status: Status,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Configuration {
    #[serde(default)]
    labels: BTreeMap<String, String>,
    #[serde(default)]
    virtualization: bool,
    #[serde(default)]
    use_init: bool,
    #[serde(default)]
    cap_add: Vec<String>,
    image: ImageRef,
    #[serde(default)]
    mounts: Vec<Mount>,
    #[serde(default)]
    published_ports: Vec<PublishedPort>,
}

#[derive(Debug, Deserialize)]
struct ImageRef {
    reference: String,
}

#[derive(Debug, Deserialize)]
struct Mount {
    destination: String,
    #[serde(rename = "type")]
    kind: serde_json::Value,
}

impl Mount {
    /// The volume name, when this mount is a named volume.
    fn volume(&self) -> Option<&str> {
        self.kind.pointer("/volume/name").and_then(|v| v.as_str())
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PublishedPort {
    container_port: u16,
    host_address: String,
    host_port: u16,
}

#[derive(Debug, Deserialize)]
struct Status {
    state: String,
}

/// The Mac-side ports a host container publishes, read back from the
/// container rather than remembered, so there is one record of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPorts {
    /// Where the node's API is on the Mac.
    pub node: u16,
    /// `(container port, Mac port)` for each relay slot, in slot order.
    pub relays: Vec<(u16, u16)>,
}

/// Why an existing container cannot be used as it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaleReason {
    /// It has our name and not our label. Never touched.
    NotOurs,
    /// Ours, but not started the way this build starts it. Safe to replace:
    /// the state lives on the volume.
    Drifted { owned: Owned, what: String },
    /// Ours, in a state that is neither running nor stopped. Left alone.
    Transitional { owned: Owned, state: String },
}

/// The host container, as `container list` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostState {
    Absent,
    Stopped(Owned),
    Running(Owned, HostPorts),
    Stale { reason: StaleReason },
}

/// What a host container is expected to look like.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    pub names: &'a HostNames,
    pub image: &'a str,
}

/// `docker.io/library/x:tag` and `x:tag` name the same image.
fn same_image(reported: &str, requested: &str) -> bool {
    let strip = |s: &str| s.trim_start_matches("docker.io/library/").to_string();
    strip(reported) == strip(requested)
}

/// Read the host container's state out of `container list --all --format
/// json`. `Err` when the output is not that list: "could not read the list"
/// is never "the container is absent" (ADR 0007 A-1).
pub fn host_state(list_json: &str, want: &Expected) -> Result<HostState, String> {
    let entries: Vec<ListEntry> =
        serde_json::from_str(list_json).map_err(|e| format!("unreadable `container list`: {e}"))?;
    let Some(e) = entries.into_iter().find(|e| e.id == want.names.container) else {
        return Ok(HostState::Absent);
    };
    if e.configuration.labels.get(OWNER_LABEL).map(String::as_str) != Some(want.names.container) {
        return Ok(HostState::Stale {
            reason: StaleReason::NotOurs,
        });
    }
    let owned = Owned { name: e.id.clone() };
    if let Some(what) = drift(&e.configuration, want) {
        return Ok(HostState::Stale {
            reason: StaleReason::Drifted { owned, what },
        });
    }
    match e.status.state.as_str() {
        "running" => match ports(&e.configuration) {
            Ok(p) => Ok(HostState::Running(owned, p)),
            Err(what) => Ok(HostState::Stale {
                reason: StaleReason::Drifted { owned, what },
            }),
        },
        "stopped" => Ok(HostState::Stopped(owned)),
        other => Ok(HostState::Stale {
            reason: StaleReason::Transitional {
                owned,
                state: other.to_string(),
            },
        }),
    }
}

/// The first way a configuration differs from what this build creates.
///
/// The kernel is not in the list output, so it cannot be checked here; the
/// in-container probe is what catches a host without KVM.
fn drift(c: &Configuration, want: &Expected) -> Option<String> {
    if c.use_init {
        return Some("runtime init prevents run-node from preparing cgroups as PID 1".into());
    }
    if !c.virtualization {
        return Some("started without --virtualization".into());
    }
    let missing: Vec<&str> = REQUIRED_CAPS
        .iter()
        .map(|cap| cap.name)
        .filter(|n| !c.cap_add.iter().any(|have| have == n))
        .collect();
    if !missing.is_empty() {
        return Some(format!("missing capabilities {missing:?}"));
    }
    if !same_image(&c.image.reference, want.image) {
        return Some(format!(
            "runs image {} instead of {}",
            c.image.reference, want.image
        ));
    }
    let volume_at_srv = c
        .mounts
        .iter()
        .any(|m| m.destination == SRV_MOUNT && m.volume() == Some(want.names.state_volume));
    if !volume_at_srv {
        return Some(format!(
            "does not mount {} at {SRV_MOUNT}",
            want.names.state_volume
        ));
    }
    None
}

fn ports(c: &Configuration) -> Result<HostPorts, String> {
    let on_loopback = |container: u16| {
        c.published_ports
            .iter()
            .find(|p| p.container_port == container)
            .map(|p| (p.host_address.as_str(), p.host_port))
    };
    let node = match on_loopback(NODE_PORT) {
        Some(("127.0.0.1", port)) => port,
        Some((addr, _)) => return Err(format!("node port published on {addr}, not 127.0.0.1")),
        None => return Err(format!("node port {NODE_PORT} is not published")),
    };
    let mut relays = Vec::new();
    for cp in RELAY_PORTS {
        match on_loopback(cp) {
            Some(("127.0.0.1", hp)) => relays.push((cp, hp)),
            Some((addr, _)) => return Err(format!("relay port {cp} published on {addr}")),
            None => return Err(format!("relay port {cp} is not published")),
        }
    }
    Ok(HostPorts { node, relays })
}

/// Volume names from `container volume list --format json`.
fn volume_names(json: &str) -> Result<Vec<String>, String> {
    let v: Vec<serde_json::Value> =
        serde_json::from_str(json).map_err(|e| format!("unreadable volume list: {e}"))?;
    Ok(v.iter()
        .filter_map(|e| {
            e.get("name")
                .or_else(|| e.pointer("/configuration/name"))
                .and_then(|n| n.as_str())
                .map(str::to_string)
        })
        .collect())
}

// ── the witness ─────────────────────────────────────────────────────

/// A running host container that has passed preflight, the in-container
/// probe and an mTLS health check. Only [`ensure_ready`] makes one.
///
/// Evidence (ADR 0007 C-1), not a one-shot right: one ready host serves every
/// session opened on it, so callers borrow it. It is therefore deliberately
/// NOT `must_use` -- `must_use` on a `!Clone` type declares affine intent
/// (C-4/C-5, measured by `cargo xtask convergence`), and borrowing it would
/// then break that claim. Dropping it unused is caught where it is made:
/// `ensure_ready` returns a `Result`, which is itself `must_use`.
#[derive(Debug)]
pub struct MicroVmHost {
    owned: Owned,
    ports: HostPorts,
    identity_dir: PathBuf,
    state_dir: PathBuf,
}

impl MicroVmHost {
    /// The container.
    pub fn container(&self) -> &Owned {
        &self.owned
    }

    /// The node's API on the Mac.
    pub fn node_url(&self) -> String {
        format!("https://127.0.0.1:{}", self.ports.node)
    }

    /// The published relay slots.
    pub fn relay_ports(&self) -> &[(u16, u16)] {
        &self.ports.relays
    }

    /// The CLI identity the node trusts.
    pub fn identity_dir(&self) -> &Path {
        &self.identity_dir
    }

    /// Where this installation keeps its host-side state (locks, audit log).
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }
}

/// Why no host was minted.
#[derive(Debug)]
pub enum Refusal {
    /// Something preflight or the probe checks is missing.
    Unmet(Vec<Unmet>),
    /// The L1 kernel is not built, or cannot host microVMs.
    Kernel(String),
    /// A container has our name and is not ours.
    NotOurs(String),
    /// Ours, and mid-transition; try again.
    Transitional(String),
    /// A `container` call did not do what it had to.
    Cli {
        action: &'static str,
        outcome: String,
    },
    /// The host-side state (identity, lock, env file) could not be prepared.
    State(String),
    /// The node never answered its health check.
    NodeUnhealthy(String),
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unmet(u) => {
                write!(f, "this Mac cannot host microVMs yet:")?;
                for x in u {
                    write!(f, "\n  - {x}")?;
                }
                Ok(())
            }
            Self::Kernel(e) => write!(f, "L1 kernel: {e}"),
            Self::NotOurs(n) => write!(
                f,
                "a container named {n} exists without the {OWNER_LABEL} label; nucleus will not \
                 touch it. Rename or remove it yourself"
            ),
            Self::Transitional(s) => write!(f, "the host container is {s}; try again shortly"),
            Self::Cli { action, outcome } => write!(f, "`container {action}` {outcome}"),
            Self::State(e) => write!(f, "host-side state: {e}"),
            Self::NodeUnhealthy(e) => write!(f, "the node did not become healthy: {e}"),
        }
    }
}

/// How to run a host.
#[derive(Debug, Clone)]
pub struct HostConfig {
    pub names: HostNames,
    /// An image reference already in the local store.
    pub image: String,
    /// The L1 kernel `Image`, with the build's `config` beside it.
    pub kernel: PathBuf,
    /// Host-side state: `ca/`, `identity/`, `node.env`, locks, the audit log.
    pub state_dir: PathBuf,
    pub cpus: u32,
    pub memory: String,
    pub trust_domain: String,
    /// How long the node may take to answer health after a start.
    pub ready_timeout: Duration,
}

impl HostConfig {
    fn ca_dir(&self) -> PathBuf {
        self.state_dir.join("ca")
    }
    fn identity_dir(&self) -> PathBuf {
        self.state_dir.join("identity")
    }
    fn env_file(&self) -> PathBuf {
        self.state_dir.join("node.env")
    }
    fn expected(&self) -> Expected<'_> {
        Expected {
            names: &self.names,
            image: &self.image,
        }
    }
}

/// Bring the host container up and prove it ready.
///
/// Blocking: run it off an async runtime's worker threads.
pub fn ensure_ready(cli: &ContainerCli, cfg: &HostConfig) -> Result<MicroVmHost, Refusal> {
    let unmet = preflight::unmet(&preflight::observe(cli));
    if !unmet.is_empty() {
        return Err(Refusal::Unmet(unmet));
    }
    check_kernel(&cfg.kernel)?;
    std::fs::create_dir_all(&cfg.state_dir).map_err(|e| Refusal::State(e.to_string()))?;
    let _lock = HostLock::acquire(&cfg.state_dir, cfg.ready_timeout)?;
    prepare_identity(cfg)?;
    let (owned, ports) = bring_up(cli, cfg)?;
    match preflight::kvm_from(&cli.exec(&owned, &[&pins::in_container_bin(HOSTCTL), "probe"])) {
        KvmObservation::Usable => {}
        KvmObservation::Unusable { reason } => {
            return Err(Refusal::Unmet(vec![Unmet::NestedVirtUnavailable {
                reason,
            }]));
        }
        KvmObservation::NotYetProbed => {
            return Err(Refusal::Unmet(vec![Unmet::NestedVirtUnavailable {
                reason: "the probe did not run".into(),
            }]));
        }
    }
    wait_healthy(
        cli,
        &owned,
        ports.node,
        &cfg.identity_dir(),
        cfg.ready_timeout,
    )?;
    Ok(MicroVmHost {
        owned,
        ports,
        identity_dir: cfg.identity_dir(),
        state_dir: cfg.state_dir.clone(),
    })
}

fn check_kernel(kernel: &Path) -> Result<(), Refusal> {
    if !kernel.is_file() {
        return Err(Refusal::Kernel(format!(
            "{} does not exist; build it from {}",
            kernel.display(),
            match pins::L1_KERNEL.source {
                pins::ArtifactSource::LocalBuild { containerfile } => containerfile,
                pins::ArtifactSource::Pinned { digest } => digest,
            }
        )));
    }
    let config = kernel.with_file_name("config");
    let text = std::fs::read_to_string(&config)
        .map_err(|e| Refusal::Kernel(format!("reading {}: {e}", config.display())))?;
    let missing: Vec<&str> = pins::missing_kernel_config(&text)
        .iter()
        .map(|s| s.symbol)
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(Refusal::Kernel(format!(
            "{} was built without {missing:?}",
            kernel.display()
        )))
    }
}

/// Start, create or replace the container until `container list` says it is
/// running as expected.
fn bring_up(cli: &ContainerCli, cfg: &HostConfig) -> Result<(Owned, HostPorts), Refusal> {
    // Two passes at most: act, then confirm.
    for _ in 0..2 {
        match observe_state(cli, cfg)? {
            HostState::Running(owned, ports) => return Ok((owned, ports)),
            HostState::Stopped(owned) => expect_ok("start", cli.start(&owned))?,
            HostState::Absent => create(cli, cfg)?,
            HostState::Stale {
                reason: StaleReason::Drifted { owned, what },
            } => {
                tracing::warn!(container = owned.name(), %what, "replacing a drifted host container");
                expect_ok("delete", cli.delete(&owned))?;
                create(cli, cfg)?;
            }
            HostState::Stale {
                reason: StaleReason::NotOurs,
            } => return Err(Refusal::NotOurs(cfg.names.container.to_string())),
            HostState::Stale {
                reason: StaleReason::Transitional { state, .. },
            } => return Err(Refusal::Transitional(state)),
        }
    }
    match observe_state(cli, cfg)? {
        HostState::Running(owned, ports) => Ok((owned, ports)),
        other => Err(Refusal::Cli {
            action: "start",
            outcome: format!("left the host {other:?}"),
        }),
    }
}

/// `container list` read into a [`HostState`].
pub fn observe_state(cli: &ContainerCli, cfg: &HostConfig) -> Result<HostState, Refusal> {
    let out = cli.list_all();
    let json = out.stdout().ok_or_else(|| Refusal::Cli {
        action: "list",
        outcome: out.describe(),
    })?;
    host_state(json, &cfg.expected()).map_err(|e| Refusal::Cli {
        action: "list",
        outcome: e,
    })
}

fn expect_ok(action: &'static str, out: Outcome) -> Result<(), Refusal> {
    if out.succeeded() {
        Ok(())
    } else {
        Err(Refusal::Cli {
            action,
            outcome: out.describe(),
        })
    }
}

fn create(cli: &ContainerCli, cfg: &HostConfig) -> Result<(), Refusal> {
    let vols = cli.volume_list();
    let names = vols
        .stdout()
        .ok_or_else(|| Refusal::Cli {
            action: "volume list",
            outcome: vols.describe(),
        })
        .and_then(|j| {
            volume_names(j).map_err(|e| Refusal::Cli {
                action: "volume list",
                outcome: e,
            })
        })?;
    if !names.iter().any(|n| n == cfg.names.state_volume) {
        expect_ok("volume create", cli.volume_create(cfg.names.state_volume))?;
    }
    let mut publish = vec![(free_port()?, NODE_PORT)];
    for cp in RELAY_PORTS {
        publish.push((free_port()?, cp));
    }
    let spec = RunSpec {
        name: cfg.names.container.to_string(),
        image: cfg.image.clone(),
        kernel: cfg.kernel.clone(),
        caps: REQUIRED_CAPS.iter().map(|c| c.name.to_string()).collect(),
        cpus: cfg.cpus,
        memory: cfg.memory.clone(),
        mounts: vec![
            (cfg.names.state_volume.to_string(), SRV_MOUNT.to_string()),
            (
                cfg.ca_dir().display().to_string(),
                format!("{NODE_STATE_DIR}/ca"),
            ),
        ],
        publish,
        env_file: cfg.env_file(),
    };
    expect_ok("run", cli.run(&spec))
}

/// A Mac port nothing is listening on right now. The kernel picks it; the
/// container is told it a moment later, and reads it back from the list.
fn free_port() -> Result<u16, Refusal> {
    std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .map_err(|e| Refusal::State(format!("finding a free port: {e}")))
}

// ── host-side state ─────────────────────────────────────────────────

/// The lock that serialises creating and restarting one host.
pub struct HostLock {
    _file: File,
}

impl HostLock {
    /// Take the lock, waiting up to `wait` for another holder.
    pub fn acquire(state_dir: &Path, wait: Duration) -> Result<Self, Refusal> {
        let path = state_dir.join("host.lock");
        let file = File::create(&path)
            .map_err(|e| Refusal::State(format!("opening {}: {e}", path.display())))?;
        let started = Instant::now();
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Self { _file: file }),
                Err(std::fs::TryLockError::WouldBlock) if started.elapsed() < wait => {
                    std::thread::sleep(Duration::from_millis(200));
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(Refusal::State(format!(
                        "{} is held by another nucleus process",
                        path.display()
                    )));
                }
                Err(std::fs::TryLockError::Error(e)) => {
                    return Err(Refusal::State(format!("locking {}: {e}", path.display())));
                }
            }
        }
    }
}

/// Seed the CA the node will load (mounted at `/srv/state/ca`), mint this
/// CLI's identity from it, and write the node's per-install secrets.
fn prepare_identity(cfg: &HostConfig) -> Result<(), Refusal> {
    use nucleus_identity::SelfSignedCa;
    let state = |e: String| Refusal::State(e);
    let ca_dir = cfg.ca_dir();
    let (cert, key) = (ca_dir.join("ca-cert.pem"), ca_dir.join("ca-key.pem"));
    let ca = if cert.is_file() && key.is_file() {
        let read =
            |p: &Path| std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()));
        SelfSignedCa::from_pem(
            &cfg.trust_domain,
            &read(&cert).map_err(state)?,
            &read(&key).map_err(state)?,
        )
        .map_err(|e| state(format!("the CA at {} is unreadable: {e}", ca_dir.display())))?
    } else {
        let ca = SelfSignedCa::new(&cfg.trust_domain)
            .map_err(|e| state(format!("generating a CA: {e}")))?;
        write_private(&cert, ca.root_cert_pem().as_bytes())?;
        write_private(&key, ca.root_key_pem().as_bytes())?;
        ca
    };
    if !cfg.identity_dir().join("cli-cert.pem").is_file() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| state(format!("starting a runtime: {e}")))?;
        rt.block_on(crate::provision::mint_cli_identity(
            &ca,
            &cfg.trust_domain,
            &cfg.identity_dir(),
        ))
        .map_err(|e| state(format!("minting the CLI identity: {e:#}")))?;
    }
    if !cfg.env_file().is_file() {
        write_private(&cfg.env_file(), node_env(&cfg.trust_domain).as_bytes())?;
    }
    Ok(())
}

/// Per-install node secrets, replacing the fixed development values the
/// image bakes in. Passed with `--env-file`, so they never appear in argv.
fn node_env(trust_domain: &str) -> String {
    use rand::RngExt;
    let secret = || {
        let mut b = [0u8; 32];
        rand::rng().fill(&mut b[..]);
        hex::encode(b)
    };
    format!(
        "NUCLEUS_NODE_AUTH_SECRET={}\nNUCLEUS_NODE_PROXY_AUTH_SECRET={}\n\
         NUCLEUS_NODE_PROXY_APPROVAL_SECRET={}\nNUCLEUS_IDENTITY_TRUST_DOMAIN={trust_domain}\n",
        secret(),
        secret(),
        secret()
    )
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Refusal> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| Refusal::State(format!("{}: {e}", dir.display())))?;
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| f.write_all(bytes))
        .map_err(|e| Refusal::State(format!("writing {}: {e}", path.display())))
}

/// Poll the node's `/v1/health` over mTLS until it answers 200.
pub fn wait_healthy(
    cli: &ContainerCli,
    owned: &Owned,
    node_port: u16,
    identity_dir: &Path,
    timeout: Duration,
) -> Result<Duration, Refusal> {
    let client = crate::provision::mtls_blocking_client_in(identity_dir)
        .map_err(|e| Refusal::State(format!("{e:#}")))?;
    let url = format!("https://127.0.0.1:{node_port}/v1/health");
    let started = Instant::now();
    let mut last = String::from("no attempt");
    while started.elapsed() < timeout {
        match client.get(&url).timeout(Duration::from_secs(5)).send() {
            Ok(r) if r.status().is_success() => return Ok(started.elapsed()),
            Ok(r) => last = format!("HTTP {}", r.status()),
            Err(e) => last = format!("{e:#}"),
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let logs = cli.logs(owned);
    let tail: Vec<&str> = logs
        .stdout()
        .unwrap_or_default()
        .lines()
        .rev()
        .take(10)
        .collect();
    Err(Refusal::NodeUnhealthy(format!(
        "{last} after {timeout:?}; node log tail:\n{}\n\
         If the node is listening inside the container, inspect `container system logs --last 5m` \
         for port-forwarding errors. `No route to host` from container-runtime-linux can require \
         enabling its Local Network access in macOS Privacy & Security settings.",
        tail.into_iter().rev().collect::<Vec<_>>().join("\n")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `container list --all --format json` for the `nucleus-dev` host that
    /// `ensure_ready` created on an M5 Pro (macOS 26.6.2, container 1.4.1) on
    /// 2026-09-29, captured by the live test. Home paths are shortened and the
    /// per-install secrets replaced. `useInit` updated to false on 2026-10-05:
    /// run-node now owns PID 1 for cgroup preparation. The stopped state differs only in
    /// `status.state` (and empty `status.networks`), measured on the same Mac.
    const RUNNING: &str = include_str!("fixtures/list-running.json");

    fn want() -> Expected<'static> {
        Expected {
            names: &HostNames::DEV,
            image: "nucleus-dev-microvm-host:local",
        }
    }

    fn with_state(state: &str) -> String {
        RUNNING.replace("\"state\": \"running\"", &format!("\"state\": \"{state}\""))
    }

    #[test]
    fn a_running_host_reads_as_running_with_its_ports() {
        let s = host_state(RUNNING, &want()).expect("parse");
        let HostState::Running(owned, ports) = s else {
            panic!("{s:?}")
        };
        assert_eq!(owned.name(), HostNames::DEV.container);
        assert_eq!(ports.node, 61110);
        assert_eq!(ports.relays.len(), RELAY_PORTS.len());
        assert_eq!(ports.relays.first(), Some(&(7101, 61111)));
    }

    #[test]
    fn a_stopped_host_reads_as_stopped() {
        let s = host_state(&with_state("stopped"), &want()).expect("parse");
        assert!(matches!(s, HostState::Stopped(_)), "{s:?}");
    }

    #[test]
    fn an_unknown_state_is_transitional_not_running() {
        let s = host_state(&with_state("stopping"), &want()).expect("parse");
        assert!(
            matches!(
                s,
                HostState::Stale {
                    reason: StaleReason::Transitional { .. }
                }
            ),
            "{s:?}"
        );
    }

    #[test]
    fn someone_elses_list_reads_as_absent() {
        // The real list on this Mac, which holds another project's container.
        let other = include_str!("fixtures/list-other.json");
        assert_eq!(host_state(other, &want()), Ok(HostState::Absent));
        assert_eq!(host_state("[]", &want()), Ok(HostState::Absent));
    }

    #[test]
    fn our_name_without_our_label_is_never_ours() {
        let unlabelled = RUNNING.replace(OWNER_LABEL, "org.example.other");
        assert_eq!(
            host_state(&unlabelled, &want()),
            Ok(HostState::Stale {
                reason: StaleReason::NotOurs
            })
        );
    }

    #[test]
    fn drift_is_named() {
        let cases = [
            ("\"useInit\": false", "\"useInit\": true", "PID 1"),
            (
                "\"virtualization\": true",
                "\"virtualization\": false",
                "virtualization",
            ),
            (
                "\"CAP_SYS_PTRACE\"",
                "\"CAP_SYS_RESOURCE\"",
                "CAP_SYS_PTRACE",
            ),
            (
                "\"reference\": \"nucleus-dev-microvm-host:local\"",
                "\"reference\": \"nucleus-dev-microvm-host:old\"",
                "image",
            ),
            (
                "\"destination\": \"/srv\"",
                "\"destination\": \"/data\"",
                "/srv",
            ),
        ];
        for (from, to, needle) in cases {
            let changed = RUNNING.replacen(from, to, 1);
            assert_ne!(changed, RUNNING, "fixture lacks {from}");
            match host_state(&changed, &want()) {
                Ok(HostState::Stale {
                    reason: StaleReason::Drifted { what, .. },
                }) => assert!(what.contains(needle), "{what}"),
                other => panic!("{from} -> {to}: {other:?}"),
            }
        }
    }

    #[test]
    fn a_node_port_off_loopback_is_drift() {
        let exposed = RUNNING.replacen(
            "\"hostAddress\": \"127.0.0.1\"",
            "\"hostAddress\": \"0.0.0.0\"",
            1,
        );
        assert!(matches!(
            host_state(&exposed, &want()),
            Ok(HostState::Stale {
                reason: StaleReason::Drifted { .. }
            })
        ));
    }

    #[test]
    fn an_unreadable_list_is_an_error_not_absent() {
        assert!(host_state("container: error", &want()).is_err());
    }

    #[test]
    fn volume_names_are_read() {
        // `container volume list --format json`, container 1.4.1, trimmed.
        let json = r#"[{"configuration":{"driver":"local","format":"ext4",
            "name":"nucleus-dev-microvm-host-srv"},"id":"nucleus-dev-microvm-host-srv"}]"#;
        assert_eq!(
            volume_names(json),
            Ok(vec!["nucleus-dev-microvm-host-srv".to_string()])
        );
        assert!(volume_names("nope").is_err());
    }

    #[test]
    fn a_kernel_without_kvm_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let image = dir.path().join("Image");
        assert!(matches!(check_kernel(&image), Err(Refusal::Kernel(_))));
        std::fs::write(&image, b"k").expect("write");
        std::fs::write(
            dir.path().join("config"),
            "# CONFIG_VIRTUALIZATION is not set\n",
        )
        .expect("write");
        match check_kernel(&image) {
            Err(Refusal::Kernel(e)) => assert!(e.contains("CONFIG_KVM"), "{e}"),
            other => panic!("{other:?}"),
        }
        let full: String = pins::L1_KERNEL
            .fragment
            .iter()
            .map(|s| format!("{s}\n"))
            .collect();
        std::fs::write(dir.path().join("config"), full).expect("write");
        assert!(check_kernel(&image).is_ok());
    }

    #[test]
    fn the_lock_excludes_a_second_holder() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = HostLock::acquire(dir.path(), Duration::ZERO).expect("first");
        assert!(HostLock::acquire(dir.path(), Duration::from_millis(300)).is_err());
        drop(first);
        assert!(HostLock::acquire(dir.path(), Duration::ZERO).is_ok());
    }

    #[test]
    fn node_secrets_are_per_install_and_private() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("node.env");
        write_private(&path, node_env("nucleus.local").as_bytes()).expect("write");
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_ne!(node_env("x"), node_env("x"));
        // The image's baked development value must never survive.
        assert!(!node_env("x").contains("00000000000000000000"));
        assert!(
            write_private(&path, b"again").is_err(),
            "must not overwrite"
        );
    }
}
