//! The node's half of the host egress proxy (ADR 0015, step E2).
//!
//! The proxy (`nucleus-egress-proxy`) is a separate, unprivileged process per
//! eval cell. It parses the guest's request and asks; this module answers.
//! It holds three things:
//!
//! * **The operator's egress routes** ([`EgressRoutes`]): the registry's
//!   `[[egress]]` tables, each an origin with the methods and paths it
//!   admits. The ACL is the operator's, never the caller's (ADR 0015 §2).
//! * **The decision service** ([`EgressDecider`]): for every `Decide` frame
//!   the proxy sends, it recomputes the action digest from the subject (C-2),
//!   parses the subject with the proxy's own summary parser (one spelling,
//!   G-1), checks the route, and then asks the pod's `PodPolicy` through
//!   `authorize_effect`, the same entry the broker's performs use, which
//!   records the allow in the host-signed journal before it returns. The
//!   decision id it mints is redeemed by value before the answer leaves
//!   (C-4). The proxy decides nothing.
//! * **The process** ([`EgressProxy`]): spawned per eval cell into a fresh
//!   network namespace as an unprivileged uid with no capabilities,
//!   `no_new_privs` and the workload syscall filter (`nucleus`'s
//!   `ChildConfinement::isolated_service`), its environment cleared, and its
//!   posture read back from `/proc/<pid>/status` by the proxy's own
//!   [`nucleus_egress_proxy::posture::check_status`] before the node relies
//!   on it. A proxy that cannot be confined is killed and the pod refused.
//!
//! # Not yet
//!
//! No guest reaches the proxy before E4 (the in-guest relay); the proxy's
//! namespace has no route out until E6 plumbs one, so in production it
//! refuses every name with `no_outbound_path`; TLS and credentials are E3.

// The spawn is reached from `spawn_firecracker_pod`, which is linux-only.
#![cfg_attr(all(not(test), not(target_os = "linux")), allow(dead_code))]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use nucleus_decision_protocol::host::{DecisionLedger, SeqGate};
use nucleus_decision_protocol::{DenyReason, GuestFrame, HostFrame, Seq, Verdict};
use nucleus_egress_proxy::request::{Method, Origin, parse_authority};
use nucleus_egress_proxy::summary::{self, Summary};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

use crate::host_decide::{ChannelError, PodPolicy, SharedPodPolicy};
use crate::upstreams::CallCharge;

// ── the operator's routes ───────────────────────────────────────────────────

/// One `[[egress]]` table of the upstream registry, as written.
///
/// ```toml
/// [[egress]]
/// name    = "docs"
/// origin  = "http://docs.example"     # http only until E3 terminates TLS
/// methods = ["GET", "HEAD"]
/// paths   = ["/v1/*", "/static/**"]   # `*` one segment; a final `**` any rest
/// call_charge_micro_usd = 0           # required: a missing price is never free
/// ```
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EgressFile {
    name: String,
    origin: String,
    methods: Vec<String>,
    paths: Vec<String>,
    call_charge_micro_usd: Option<u64>,
}

/// One operator-registered upstream an eval cell's proxy may be allowed to
/// reach, with what it admits. Constructed only by [`EgressRoutes::from_files`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EgressRoute {
    name: String,
    methods: BTreeSet<Method>,
    paths: Vec<PathPattern>,
    charge: CallCharge,
}

/// The routes, keyed by origin: two entries for one origin would make the
/// lookup depend on order, so the map refuses them at load (ADR 0007 G-3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EgressRoutes {
    by_origin: BTreeMap<Origin, EgressRoute>,
}

/// Written out rather than derived (ADR 0007 B-1), for the registry's own
/// `Default`: it is [`EgressRoutes::none`], which refuses every request, so
/// a default here grants nothing.
impl Default for EgressRoutes {
    fn default() -> Self {
        Self::none()
    }
}

/// A path rule: literal segments, `*` for exactly one non-empty segment, and
/// a final `**` for any remaining segments (none included).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathPattern {
    segments: Vec<PatternSegment>,
    rest: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PatternSegment {
    Literal(String),
    One,
}

impl PathPattern {
    fn parse(text: &str) -> Result<Self, String> {
        let rest_text = text
            .strip_prefix('/')
            .ok_or_else(|| format!("path {text:?} must start with '/'"))?;
        let mut parts: Vec<&str> = rest_text.split('/').collect();
        let rest = parts.last() == Some(&"**");
        if rest {
            parts.pop();
        }
        let mut segments = Vec::with_capacity(parts.len());
        for part in parts {
            if part == "*" {
                segments.push(PatternSegment::One);
            } else if part.is_empty() && !rest && segments.is_empty() && text == "/" {
                // "/" alone: the root, one empty segment.
                segments.push(PatternSegment::Literal(String::new()));
            } else {
                // A literal must itself be a path the proxy accepts, so a rule
                // can never name a path no request could carry.
                let probe = format!("/{part}");
                if part.is_empty()
                    || part.contains('*')
                    || nucleus_egress_proxy::request::check_path(&probe).is_err()
                {
                    return Err(format!(
                        "path {text:?}: segment {part:?} is not a literal or '*'"
                    ));
                }
                segments.push(PatternSegment::Literal(part.to_string()));
            }
        }
        Ok(Self { segments, rest })
    }

    fn matches(&self, path: &str) -> bool {
        let Some(tail) = path.strip_prefix('/') else {
            return false;
        };
        let request: Vec<&str> = tail.split('/').collect();
        if request.len() < self.segments.len()
            || (!self.rest && request.len() != self.segments.len())
        {
            return false;
        }
        self.segments.iter().zip(&request).all(|(p, r)| match p {
            PatternSegment::Literal(l) => l == r,
            PatternSegment::One => !r.is_empty(),
        })
    }
}

impl EgressRoutes {
    /// Validate the registry's `[[egress]]` tables. Every refusal names the
    /// entry; the node refuses to start on any, like the rest of the registry.
    pub(crate) fn from_files(files: Vec<EgressFile>) -> Result<Self, String> {
        let mut by_origin = BTreeMap::new();
        let mut names = BTreeSet::new();
        for file in files {
            let EgressFile {
                name,
                origin,
                methods,
                paths,
                call_charge_micro_usd,
            } = file;
            if name.trim().is_empty() || !names.insert(name.clone()) {
                return Err(format!("egress entry {name:?}: empty or repeated name"));
            }
            let authority = origin.strip_prefix("http://").ok_or_else(|| {
                format!(
                    "egress {name:?}: origin {origin:?} must be http://host[:port] \
                     (https needs the proxy's TLS termination, ADR 0015 E3)"
                )
            })?;
            let origin = parse_authority(authority)
                .map_err(|e| format!("egress {name:?}: origin {origin:?}: {e}"))?;
            if methods.is_empty() || paths.is_empty() {
                return Err(format!(
                    "egress {name:?}: methods and paths must each name at least one"
                ));
            }
            let methods = methods
                .iter()
                .map(|m| {
                    Method::from_token(m).ok_or_else(|| {
                        format!("egress {name:?}: method {m:?} is not one the proxy carries")
                    })
                })
                .collect::<Result<BTreeSet<_>, _>>()?;
            let paths = paths
                .iter()
                .map(|p| PathPattern::parse(p).map_err(|e| format!("egress {name:?}: {e}")))
                .collect::<Result<Vec<_>, _>>()?;
            let charge = CallCharge::operator(call_charge_micro_usd.ok_or_else(|| {
                format!("egress {name:?}: call_charge_micro_usd is required (a missing price is never free)")
            })?);
            let route = EgressRoute {
                name: name.clone(),
                methods,
                paths,
                charge,
            };
            if by_origin.insert(origin.clone(), route).is_some() {
                return Err(format!(
                    "egress {name:?}: origin {origin} is registered twice"
                ));
            }
        }
        Ok(Self { by_origin })
    }

    /// No routes: every request is [`DenyReason::NotRegistered`]. What a
    /// node without an `--upstreams` registry has.
    pub(crate) fn none() -> Self {
        Self {
            by_origin: BTreeMap::new(),
        }
    }

    /// How many routes there are.
    pub(crate) fn len(&self) -> usize {
        self.by_origin.len()
    }

    /// The route that admits `summary`, or why none does.
    ///
    /// # Errors
    /// [`DenyReason::NotRegistered`] for an origin no entry names;
    /// [`DenyReason::RouteRefused`] for a method or path its entry does not
    /// admit.
    pub(crate) fn route(&self, summary: &Summary) -> Result<&EgressRoute, DenyReason> {
        let route = self
            .by_origin
            .get(&summary.origin)
            .ok_or(DenyReason::NotRegistered)?;
        let admitted = route.methods.contains(&summary.method)
            && route.paths.iter().any(|p| p.matches(&summary.path));
        if admitted {
            Ok(route)
        } else {
            Err(DenyReason::RouteRefused)
        }
    }
}

// ── the decision service ────────────────────────────────────────────────────

/// What one `Decide` came to, for the log and for tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Decided {
    /// Allowed, journaled, and the id redeemed.
    Allowed { route: String, decision: u64 },
    /// Refused, with the reason the proxy was told and the host's detail.
    Refused { reason: DenyReason, detail: String },
}

/// Why the node closed a proxy's channel rather than answer. The proxy reads
/// a closed channel as no answer, so each of these is a refusal there.
#[derive(Debug)]
pub(crate) enum Close {
    /// The frame, its number, the ledger or the policy failed (shared with
    /// the guest's decision channel).
    Channel(ChannelError),
    /// A frame other than `Decide`: the proxy sends nothing else.
    NotDecide,
    /// A `Decide` for an operation other than the proxy's one.
    WrongOperation,
    /// The frame's digest is not the digest of its subject.
    DigestMismatch,
    /// The subject is not a canonical summary.
    Summary(summary::SummaryError),
}

impl std::fmt::Display for Close {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Close::Channel(e) => write!(f, "channel: {e:?}"),
            Close::NotDecide => f.write_str("a frame other than Decide"),
            Close::WrongOperation => f.write_str("a Decide for another operation"),
            Close::DigestMismatch => f.write_str("the digest is not the subject's"),
            Close::Summary(e) => write!(f, "the subject is not a canonical summary: {e:?}"),
        }
    }
}

impl From<ChannelError> for Close {
    fn from(e: ChannelError) -> Self {
        Close::Channel(e)
    }
}

/// One proxy's channel: the pod's policy, the routes, and this channel's own
/// numbering and ledger.
pub(crate) struct EgressDecider {
    pod: Uuid,
    routes: Arc<EgressRoutes>,
    policy: SharedPodPolicy,
    gate: SeqGate,
    ledger: DecisionLedger,
}

impl std::fmt::Debug for EgressDecider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressDecider")
            .field("pod", &self.pod)
            .field("routes", &self.routes.len())
            .finish_non_exhaustive()
    }
}

impl EgressDecider {
    pub(crate) fn new(
        pod: Uuid,
        routes: Arc<EgressRoutes>,
        policy: SharedPodPolicy,
        epoch: u64,
    ) -> Self {
        Self {
            pod,
            routes,
            policy,
            gate: SeqGate::new(),
            ledger: DecisionLedger::new(epoch),
        }
    }

    /// Answer one frame from the proxy.
    ///
    /// # Errors
    /// A [`Close`]: the channel ends and the proxy refuses what it asked.
    pub(crate) fn step(
        &mut self,
        frame: GuestFrame,
        now: u64,
    ) -> Result<(Vec<u8>, Decided), Close> {
        let GuestFrame::Decide {
            seq,
            op,
            subject,
            args_digest,
        } = frame
        else {
            return Err(Close::NotDecide);
        };
        self.gate
            .admit(seq)
            .map_err(|e| Close::Channel(ChannelError::Sequence(e)))?;
        if op != summary::OPERATION {
            return Err(Close::WrongOperation);
        }
        // C-2: the binding is the node's, computed from what it will decide.
        let digest = summary::digest(subject.as_str());
        if digest != args_digest {
            return Err(Close::DigestMismatch);
        }
        let summary = Summary::parse(subject.as_str()).map_err(Close::Summary)?;
        match self.decide(&summary, digest, now) {
            Ok(route) => self.allow(seq, digest, route),
            Err((reason, detail)) => {
                let reply = HostFrame::Verdict {
                    seq,
                    verdict: Verdict::Denied { reason },
                }
                .encode()
                .map_err(|e| Close::Channel(ChannelError::Encode(e)))?;
                Ok((reply, Decided::Refused { reason, detail }))
            }
        }
    }

    /// The decision: the operator's route, then the pod's policy. Only an
    /// `Ok` is an allow, and it has been journaled.
    fn decide(
        &self,
        summary: &Summary,
        digest: nucleus_decision_protocol::ArgsDigest,
        now: u64,
    ) -> Result<String, (DenyReason, String)> {
        let route = self.routes.route(summary).map_err(|reason| {
            (
                reason,
                format!("{} {}", summary.method.as_str(), summary.origin),
            )
        })?;
        let permit = {
            let mut policy = self.policy.lock().map_err(|_| {
                (
                    DenyReason::NotGranted,
                    "host policy unavailable".to_string(),
                )
            })?;
            policy
                .authorize_effect(
                    digest,
                    summary::OPERATION,
                    &summary.url(),
                    now,
                    route.charge,
                    false,
                )
                .map_err(|e| (DenyReason::NotGranted, e))?
        };
        // The response is web content: the pod's taint rises before the
        // proxy can relay a byte of it (ADR 0015 §2, ADR 0014 §3).
        PodPolicy::observe_response(&self.policy, now).map_err(|_| {
            (
                DenyReason::NotGranted,
                "host policy unavailable".to_string(),
            )
        })?;
        // The record is durable; the in-process right ends here. The proxy
        // performs on the verdict, not on a token.
        drop(permit);
        Ok(route.name.clone())
    }

    /// Mint the decision id, encode the allow, and redeem the id by value
    /// before the bytes leave (ADR 0015 §2, C-4).
    fn allow(
        &mut self,
        seq: Seq,
        digest: nucleus_decision_protocol::ArgsDigest,
        route: String,
    ) -> Result<(Vec<u8>, Decided), Close> {
        let decision_id = self
            .ledger
            .allow(digest)
            .map_err(|e| Close::Channel(ChannelError::Ledger(e)))?;
        let frame = HostFrame::Verdict {
            seq,
            verdict: Verdict::Allowed { decision_id },
        };
        let reply = frame
            .encode()
            .map_err(|e| Close::Channel(ChannelError::Encode(e)))?;
        let HostFrame::Verdict {
            seq: _,
            verdict: Verdict::Allowed { decision_id },
        } = frame
        else {
            return Err(Close::NotDecide);
        };
        let spent = self
            .ledger
            .consume(decision_id, digest)
            .map_err(|e| Close::Channel(ChannelError::Ledger(e)))?;
        Ok((
            reply,
            Decided::Allowed {
                route,
                decision: spent.decision(),
            },
        ))
    }
}

/// Serve one proxy's channel until it closes or a frame closes it.
pub(crate) async fn serve_decisions<S>(stream: S, mut decider: EgressDecider) -> Result<(), Close>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut r, mut w) = tokio::io::split(stream);
    loop {
        let Some(frame) = crate::host_decide::read_frame(&mut r).await? else {
            return Ok(());
        };
        let (reply, decided) = decider.step(frame, now_unix())?;
        match &decided {
            Decided::Allowed { route, decision } => {
                tracing::info!(pod = %decider.pod, route, decision, "egress request allowed");
            }
            Decided::Refused { reason, detail } => {
                tracing::info!(pod = %decider.pod, ?reason, detail, "egress request refused");
            }
        }
        w.write_all(&reply)
            .await
            .map_err(|e| Close::Channel(ChannelError::Io(e.kind())))?;
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ── the process ─────────────────────────────────────────────────────────────

/// Where the proxy writes its log, in the pod directory.
pub(crate) const PROXY_LOG: &str = "egress-proxy.log";

/// What the node needs to start one pod's proxy.
pub(crate) struct Launch<'a> {
    pub binary: &'a Path,
    pub vsock_path: &'a Path,
    pub pod_dir: &'a Path,
    /// Who the jailed VMM runs as, so Firecracker can connect the socket.
    pub jail_owner: Option<(u32, u32)>,
    /// Who the proxy runs as. Never 0.
    pub run_as: (u32, u32),
    pub decider: EgressDecider,
}

/// A running proxy, owned by its pod.
#[derive(Debug)]
pub(crate) struct EgressProxy {
    child: tokio::process::Child,
    decisions: tokio::task::JoinHandle<()>,
    socket_path: PathBuf,
}

impl EgressProxy {
    /// Bind the guest's socket, spawn the proxy confined, verify the
    /// confinement from outside, and serve its decisions.
    ///
    /// # Errors
    /// Any step, named. A proxy that started but is not confined as
    /// required is killed before this returns.
    pub(crate) async fn start(launch: Launch<'_>) -> Result<Self, String> {
        use std::os::fd::OwnedFd;
        use std::process::Stdio;

        let Launch {
            binary,
            vsock_path,
            pod_dir,
            jail_owner,
            run_as: (uid, gid),
            decider,
        } = launch;
        let (listener, socket_path) = crate::guest_socket::bind_guest_listener(
            vsock_path,
            nucleus_ifc_kernel::VsockListener::EgressProxy,
            jail_owner,
        )
        .map_err(|e| format!("egress proxy socket: {e}"))?;
        let listener = listener
            .into_std()
            .map_err(|e| format!("egress proxy socket: {e}"))?;
        let (node_end, proxy_end) = std::os::unix::net::UnixStream::pair()
            .map_err(|e| format!("egress proxy decision channel: {e}"))?;
        let log = std::fs::File::create(pod_dir.join(PROXY_LOG))
            .map_err(|e| format!("egress proxy log: {e}"))?;

        let mut cmd = std::process::Command::new(binary);
        for net in crate::net::NODE_DENY_FLOOR {
            cmd.arg("--deny-floor").arg(net.to_string());
        }
        cmd.env_clear()
            .current_dir("/")
            .stdin(Stdio::from(OwnedFd::from(listener)))
            .stdout(Stdio::from(OwnedFd::from(proxy_end)))
            .stderr(Stdio::from(log));
        let confinement = nucleus::ChildConfinement::isolated_service(uid, gid)
            .map_err(|e| format!("egress proxy confinement: {e}"))?;
        // The proxy never runs a program and does open inet sockets: exec is
        // denied on top of the denylist, inet is not.
        let caps = portcullis::CapabilityLattice {
            run_bash: portcullis::CapabilityLevel::Never,
            web_fetch: portcullis::CapabilityLevel::Always,
            ..portcullis::CapabilityLattice::default()
        };
        let syscalls = portcullis::SeccompPolicy::from_capabilities(
            &caps,
            portcullis::NetworkEgress::Declared,
        );
        match confinement.apply(
            &mut cmd,
            nucleus::RlimitPolicy::node_ceiling().at_ceiling(),
            syscalls,
        ) {
            nucleus::SpawnHardening::Hardened(_) => {}
            nucleus::SpawnHardening::Unhardened(why) => {
                return Err(format!("egress proxy cannot be hardened here: {why:?}"));
            }
        }
        let mut child = tokio::process::Command::from(cmd)
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("egress proxy spawn: {e}"))?;
        if let Err(e) = verify(&child) {
            let _ = child.start_kill();
            let _ = child.wait().await;
            return Err(format!("egress proxy not confined: {e}"));
        }
        let node_end = tokio::net::UnixStream::from_std({
            node_end
                .set_nonblocking(true)
                .map_err(|e| format!("egress proxy decision channel: {e}"))?;
            node_end
        })
        .map_err(|e| format!("egress proxy decision channel: {e}"))?;
        let decisions = tokio::spawn(async move {
            if let Err(e) = serve_decisions(node_end, decider).await {
                tracing::warn!(error = %e, "egress proxy decision channel closed by the node");
            }
        });
        Ok(Self {
            child,
            decisions,
            socket_path,
        })
    }

    /// Kill the proxy, stop its decisions, unlink its socket.
    pub(crate) async fn shutdown(mut self) {
        let _ = self.child.start_kill();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), self.child.wait()).await;
        self.decisions.abort();
        let _ = tokio::fs::remove_file(&self.socket_path).await;
    }
}

/// Whether this node starts egress proxies, and as whom. Two named cases, not
/// an `Option` (ADR 0007 B-2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProxyConfig {
    /// `--egress-proxy-bin` unset: no proxy. No guest reaches one before E4.
    NotConfigured,
    /// Start this binary for every eval cell, as `uid`:`gid`.
    Binary { path: PathBuf, uid: u32, gid: u32 },
}

impl ProxyConfig {
    pub(crate) fn from_flags(path: Option<PathBuf>, uid: u32, gid: u32) -> Self {
        match path {
            None => ProxyConfig::NotConfigured,
            Some(path) => ProxyConfig::Binary { path, uid, gid },
        }
    }
}

/// Start the pod's egress proxy if it is an eval cell and the node has one.
///
/// # Errors
/// For an eval cell on a node that has a proxy: anything that stops it
/// starting confined. The pod is refused; it never runs with a proxy that is
/// weaker than this module says.
#[cfg(target_os = "linux")]
pub(crate) async fn start_for_pod(
    state: &crate::NodeState,
    spec: &nucleus_spec::PodSpec,
    pod: Uuid,
    vsock_path: &Path,
    pod_dir: &Path,
    jail_owner: Option<(u32, u32)>,
) -> Result<Option<EgressProxy>, crate::ApiError> {
    use nucleus_spec::isolation_profile::IsolationProfile;
    let profile = IsolationProfile::of(spec)
        .map_err(|e| crate::ApiError::Driver(format!("egress proxy: {e}")))?;
    let (binary, uid, gid) = match (profile, &state.egress_proxy) {
        (IsolationProfile::Standard, _) => return Ok(None),
        (IsolationProfile::EvalCell, ProxyConfig::NotConfigured) => {
            tracing::info!(pod = %pod, "no --egress-proxy-bin: this eval cell gets no egress proxy (E2)");
            return Ok(None);
        }
        (IsolationProfile::EvalCell, ProxyConfig::Binary { path, uid, gid }) => (path, *uid, *gid),
    };
    let refuse = |why: String| crate::ApiError::Driver(format!("eval cell refused: {why}"));
    let policy = state
        .authority
        .host_policy(pod)
        .await
        .map_err(|e| refuse(format!("egress proxy has no pod policy: {e}")))?;
    let epoch = state
        .decision_epochs
        .next()
        .map_err(|_| refuse("the node has no decision epochs left".into()))?;
    let decider = EgressDecider::new(pod, state.authority.egress_routes(), policy, epoch);
    let proxy = EgressProxy::start(Launch {
        binary,
        vsock_path,
        pod_dir,
        jail_owner,
        run_as: (uid, gid),
        decider,
    })
    .await
    .map_err(refuse)?;
    tracing::info!(pod = %pod, socket = %proxy.socket_path.display(), "egress proxy confined and listening");
    Ok(Some(proxy))
}

/// The proxy's confinement, read from the kernel: its status through the
/// proxy's own reader, and a network namespace that is not the node's.
fn verify(child: &tokio::process::Child) -> Result<(), String> {
    let pid = child.id().ok_or("the proxy exited at once")?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|e| format!("/proc/{pid}/status: {e}"))?;
    nucleus_egress_proxy::posture::check_status(&status).map_err(|e| e.to_string())?;
    let own = std::fs::read_link("/proc/self/ns/net").map_err(|e| e.to_string())?;
    let theirs = std::fs::read_link(format!("/proc/{pid}/ns/net")).map_err(|e| e.to_string())?;
    if own == theirs {
        return Err("it shares the node's network namespace".into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "egress_proxy_tests.rs"]
mod tests;
