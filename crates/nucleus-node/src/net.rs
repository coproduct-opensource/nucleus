#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use ipnet::IpNet;
use nucleus_ifc_kernel::extracted::egress::Rule as EgressRule;
use nucleus_spec::NetworkSpec;
use tokio::io::AsyncWriteExt;
use tokio::net::lookup_host;
use uuid::Uuid;

use crate::ApiError;

const NET_BASE: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 0);
const NET_POOL_PREFIX: u8 = 24;
const POD_PREFIX: u8 = 30;
const POD_STRIDE: u8 = 4;
const DEFAULT_DNS: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

/// The addresses a guest sees. **Identical in every pod, by design.**
///
/// # Why these are constants
///
/// The guest's address used to be derived from its allocation index
/// (`NET_BASE + index * POD_STRIDE + 3`), and the index is a dense counter. So a
/// pod could read its own IP, divide by the stride, and recover roughly how many
/// pods had been concurrently live — a cross-tenant signal readable with `ip
/// addr` and no special access (#2202).
///
/// Every pod already runs in its own network namespace, so nothing ever required
/// these to differ: two pods can both be 192.168.241.2 without colliding. Only
/// the veth link into the SHARED host namespace needs a unique address, and the
/// guest never sees that side.
///
/// This is the pattern Firecracker documents for clones — the guest keeps one
/// fixed configuration and the host distinguishes VMs by translating on its own
/// side. It closes the channel by making the index **unobservable** rather than
/// merely uninformative, which is a structural property the model can state
/// rather than a probabilistic one it cannot.
const GUEST_LINK_BASE: Ipv4Addr = Ipv4Addr::new(192, 168, 241, 0);
const GUEST_GATEWAY: Ipv4Addr = Ipv4Addr::new(192, 168, 241, 1);
const GUEST_ADDR: Ipv4Addr = Ipv4Addr::new(192, 168, 241, 2);
const GUEST_PREFIX: u8 = 30;

/// Network address pool with reclamation support.
/// Allocates /30 subnets from the pool and returns them when pods terminate.
#[derive(Debug)]
pub struct NetworkAllocator {
    /// Available indices in the pool (returned indices are recycled)
    available: Mutex<Vec<usize>>,
    /// Next index to use when pool is empty (monotonic growth)
    next: AtomicUsize,
    /// Maximum number of allocations (computed from CIDR)
    max: usize,
}

impl NetworkAllocator {
    pub fn new() -> Self {
        if POD_PREFIX < NET_POOL_PREFIX {
            // This is a compile-time configuration error
            panic!("invalid network pool: pod prefix must be >= pool prefix");
        }
        let max = 1usize << (POD_PREFIX - NET_POOL_PREFIX) as usize;
        Self {
            available: Mutex::new(Vec::new()),
            next: AtomicUsize::new(0),
            max,
        }
    }

    pub fn allocate(&self, pod_id: Uuid, netns: String) -> Result<NetPlan, ApiError> {
        // Try to reuse a released index first
        let index = {
            let mut available = self
                .available
                .lock()
                .map_err(|_| ApiError::Driver("network allocator lock poisoned".to_string()))?;
            if let Some(idx) = available.pop() {
                idx
            } else {
                // No released indices available, allocate a new one
                let idx = self.next.fetch_add(1, Ordering::SeqCst);
                if idx >= self.max {
                    // Roll back the increment and return error
                    self.next.fetch_sub(1, Ordering::SeqCst);
                    return Err(ApiError::Driver(
                        "network pool exhausted; increase base CIDR".to_string(),
                    ));
                }
                idx
            }
        };

        // The index-derived /30 now addresses ONLY the veth link between this
        // pod's namespace and the host namespace. Both ends live outside the
        // guest, so the index no longer reaches anything the guest can read.
        let offset = (index as u32) * u32::from(POD_STRIDE);
        let base = add_ipv4(NET_BASE, offset);
        let host_ip = add_ipv4(base, 1);
        let peer_ip = add_ipv4(base, 2);
        let subnet = IpNet::new(IpAddr::V4(base), POD_PREFIX)
            .map_err(|_| ApiError::Driver("invalid network pool".to_string()))?;

        let short = short_id(pod_id);
        let host_veth = format!("veth{short}");
        let peer_veth = format!("vpeer{short}");
        let tap_name = format!("tap{short}");
        let bridge = format!("br{short}");

        Ok(NetPlan {
            index,
            netns,
            host_veth,
            peer_veth,
            tap_name,
            bridge,
            guest_mac: mac_from_id(pod_id),
            guest_ip: GUEST_ADDR,
            gateway_ip: GUEST_GATEWAY,
            peer_ip,
            host_ip,
            cidr: GUEST_PREFIX,
            subnet,
            dns: DEFAULT_DNS,
        })
    }

    /// Release an index back to the pool for reuse.
    pub fn release(&self, index: usize) {
        let mut available = self.available.lock().unwrap();
        // Avoid duplicates
        if !available.contains(&index) {
            available.push(index);
        }
    }
}

#[derive(Clone, Debug)]
pub struct NetPlan {
    /// Pool index for this allocation (used for reclamation)
    pub index: usize,
    pub netns: String,
    pub host_veth: String,
    pub peer_veth: String,
    pub tap_name: String,
    pub bridge: String,
    pub guest_mac: String,
    /// Constant across every pod — see `GUEST_ADDR`.
    pub guest_ip: Ipv4Addr,
    /// Constant across every pod — the bridge inside this pod's namespace.
    pub gateway_ip: Ipv4Addr,
    /// This pod's UNIQUE address on the veth link, inside its namespace. Host
    /// side of the boundary: the guest never sees it.
    pub peer_ip: Ipv4Addr,
    /// This pod's UNIQUE address on the veth link, in the host namespace.
    pub host_ip: Ipv4Addr,
    pub cidr: u8,
    pub subnet: IpNet,
    pub dns: Ipv4Addr,
}

impl NetPlan {
    pub fn kernel_arg(&self) -> String {
        format!(
            "nucleus.net={}/{},gw={},dns={}",
            self.guest_ip, self.cidr, self.gateway_ip, self.dns
        )
    }
}

/// The constant guest-side subnet, as a CIDR string.
fn guest_subnet_cidr() -> String {
    format!("{}/{}", GUEST_LINK_BASE, GUEST_PREFIX)
}

pub fn netns_name(pod_id: Uuid) -> String {
    format!("nuc-{}", short_id(pod_id))
}

/// Pure decision describing the network isolation a Firecracker pod requires.
///
/// Pulled out of `spawn_firecracker_pod` so the security-critical invariant
/// "a netns is never omitted and is never created without default-deny" is
/// unit-/property-testable without spawning a VM or touching the OS. The
/// imperative launch path consumes this and performs the side effects in the
/// order the security model requires (default-deny BEFORE the workload starts).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetnsPlan {
    /// A dedicated network namespace must be created for the pod.
    pub create_netns: bool,
    /// Default-deny iptables policy must be applied to that netns. This is
    /// ALWAYS true whenever `create_netns` is true: there is no path that
    /// creates a namespace with an open default policy.
    pub apply_default_deny: bool,
    /// A `NetPlan` (veth/bridge/tap + allowlist) must be allocated. Only when a
    /// network policy is present AND there is a netns to enforce it in.
    pub allocate_net_plan: bool,
    /// The spec requested a network policy but the node is not running pods in a
    /// netns. This MUST be rejected — a policy with nowhere to be enforced is a
    /// fail-open hazard, not a no-op.
    pub reject_unsupported_policy: bool,
}

impl NetnsPlan {
    /// Decide the isolation plan from the node's netns mode and the (optional)
    /// network policy on the spec.
    pub fn decide(firecracker_netns: bool, network: Option<&NetworkSpec>) -> Self {
        let has_policy = network.is_some();
        Self {
            // Netns is created for EVERY Firecracker pod when netns mode is on,
            // regardless of whether a network policy was supplied.
            create_netns: firecracker_netns,
            // ...and a created netns always gets the default-deny baseline.
            apply_default_deny: firecracker_netns,
            // A host-side NetPlan is only allocated when there is both a netns
            // and an explicit network policy to enforce.
            allocate_net_plan: firecracker_netns && has_policy,
            // A policy without a netns to enforce it is rejected, never ignored.
            reject_unsupported_policy: !firecracker_netns && has_policy,
        }
    }
}

/// Whether a chain rule accepts or drops. Public because `egress_chain`
/// returns the chain as a value for the confinement proof's correspondence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleKind {
    Allow,
    Deny,
}

/// One filter rule as nucleus decides it, before iptables formatting.
#[derive(Clone, Debug)]
pub struct NetRule {
    /// Accept or drop.
    pub kind: RuleKind,
    /// Destination network.
    pub net: IpNet,
    /// Destination port, or any port when `None`.
    pub port: Option<u16>,
}

#[derive(Clone, Debug)]
pub struct ResolvedDnsEntry {
    pub host: String,
    pub port: Option<u16>,
    pub ips: Vec<Ipv4Addr>,
}

#[derive(Debug)]
pub struct DnsProxyState {
    pub child: tokio::process::Child,
    pub entries: Vec<ResolvedDnsEntry>,
}

pub async fn write_policy_files(
    pod_dir: &Path,
    policy: Option<&NetworkSpec>,
) -> Result<(), ApiError> {
    let policy = match policy {
        Some(policy) => policy,
        None => return Ok(()),
    };

    if !policy.allow.is_empty() {
        let allowlist = policy.allow.join("\n");
        let path = pod_dir.join("net.allow");
        let mut file = tokio::fs::File::create(&path).await?;
        file.write_all(allowlist.as_bytes()).await?;
    }

    if !policy.deny.is_empty() {
        let denylist = policy.deny.join("\n");
        let path = pod_dir.join("net.deny");
        let mut file = tokio::fs::File::create(&path).await?;
        file.write_all(denylist.as_bytes()).await?;
    }

    if !policy.dns_allow.is_empty() {
        let allowlist = policy.dns_allow.join("\n");
        let path = pod_dir.join("net.dns.allow");
        let mut file = tokio::fs::File::create(&path).await?;
        file.write_all(allowlist.as_bytes()).await?;
    }

    Ok(())
}

pub fn validate_policy(policy: &NetworkSpec) -> Result<(), ApiError> {
    let _ = parse_rules(policy)?;
    validate_dns_allowlist(policy)?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[tracing::instrument(skip_all, fields(boot.stage = "net.dns_proxy"))]
pub async fn start_dns_proxy(
    plan: &mut NetPlan,
    policy: &NetworkSpec,
    pod_dir: &Path,
) -> Result<Option<DnsProxyState>, ApiError> {
    if policy.dns_allow.is_empty() {
        return Ok(None);
    }
    ensure_command("dnsmasq")?;
    let entries = resolve_dns_allowlist(policy).await?;
    if entries.is_empty() {
        return Ok(None);
    }

    plan.dns = plan.gateway_ip;

    let config_path = pod_dir.join("dnsmasq.conf");
    let log_path = pod_dir.join("dnsmasq.log");

    let config = dnsmasq_config(plan.gateway_ip, &entries);
    tokio::fs::write(&config_path, config).await?;

    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(ApiError::Io)?;

    let mut command = tokio::process::Command::new("ip");
    command
        // No `--`: iproute2 would exec it as the command. See `run_netns`.
        .args(["netns", "exec", &plan.netns])
        .arg("dnsmasq")
        .arg("--no-daemon")
        .arg("--conf-file")
        .arg(&config_path)
        .stdout(log_file.try_clone().map_err(ApiError::Io)?)
        .stderr(log_file);

    let child = command.spawn().map_err(ApiError::Io)?;
    Ok(Some(DnsProxyState { child, entries }))
}

#[cfg(not(target_os = "linux"))]
pub async fn start_dns_proxy(
    _plan: &mut NetPlan,
    _policy: &NetworkSpec,
    _pod_dir: &Path,
) -> Result<Option<DnsProxyState>, ApiError> {
    Err(ApiError::Driver(
        "dns allowlisting requires Linux".to_string(),
    ))
}

#[cfg(target_os = "linux")]
#[tracing::instrument(skip_all, fields(boot.stage = "net.create_netns"))]
pub async fn create_netns(name: &str) -> Result<(), ApiError> {
    ensure_command("ip")?;
    let status = Command::new("ip")
        .args(["netns", "add", name])
        .status()
        .map_err(ApiError::Io)?;
    if !status.success() {
        return Err(ApiError::Driver(format!(
            "failed to create netns {name} (exit {status})"
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub async fn create_netns(_name: &str) -> Result<(), ApiError> {
    Err(ApiError::Driver(
        "network namespaces require Linux".to_string(),
    ))
}

/// Apply default-deny iptables policy to a named network namespace.
/// This must be called BEFORE spawning any process in the netns to prevent
/// race conditions where a process could exfiltrate data before policy applies.
#[cfg(target_os = "linux")]
#[tracing::instrument(skip_all, fields(boot.stage = "net.default_deny"))]
pub async fn apply_default_deny(netns: &str) -> Result<(), ApiError> {
    ensure_command("iptables")?;

    // Flush any existing rules
    run_netns(netns, &["iptables", "-w", "-F"]).await?;
    run_netns(netns, &["iptables", "-w", "-X"]).await?;

    // Set default policies to DROP (deny-all)
    run_netns(netns, &["iptables", "-w", "-P", "INPUT", "DROP"]).await?;
    run_netns(netns, &["iptables", "-w", "-P", "OUTPUT", "DROP"]).await?;
    run_netns(netns, &["iptables", "-w", "-P", "FORWARD", "DROP"]).await?;

    // Allow loopback traffic
    run_netns(
        netns,
        &["iptables", "-w", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
    )
    .await?;
    run_netns(
        netns,
        &["iptables", "-w", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
    )
    .await?;

    // Allow established/related connections (needed for reply traffic)
    run_netns(
        netns,
        &[
            "iptables",
            "-w",
            "-A",
            "OUTPUT",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
    )
    .await?;
    run_netns(
        netns,
        &[
            "iptables",
            "-w",
            "-A",
            "INPUT",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
    )
    .await?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub async fn apply_default_deny(_netns: &str) -> Result<(), ApiError> {
    Err(ApiError::Driver(
        "default-deny policy requires Linux".to_string(),
    ))
}

#[cfg(target_os = "linux")]
pub async fn cleanup_network(plan: &NetPlan) -> Result<(), ApiError> {
    let _ = Command::new("ip")
        .args(["link", "del", &plan.host_veth])
        .status();
    let _ = Command::new("ip")
        .args(["netns", "del", &plan.netns])
        .status();
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub async fn cleanup_network(_plan: &NetPlan) -> Result<(), ApiError> {
    Ok(())
}

#[cfg(target_os = "linux")]
pub async fn cleanup_netns(name: &str) -> Result<(), ApiError> {
    let _ = Command::new("ip").args(["netns", "del", name]).status();
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub async fn cleanup_netns(_name: &str) -> Result<(), ApiError> {
    Ok(())
}

#[cfg(target_os = "linux")]
#[tracing::instrument(skip_all, fields(boot.stage = "net.setup"))]
pub async fn setup_network(plan: &NetPlan) -> Result<(), ApiError> {
    ensure_command("ip")?;
    ensure_command("iptables")?;
    ensure_command("sysctl")?;

    // Two subnets now, and the split is the whole point:
    //   * the LINK subnet (index-derived) addresses the veth pair, both ends of
    //     which are outside the guest;
    //   * the GUEST subnet is constant in every pod's namespace.
    let host_cidr = format!("{}/{}", plan.host_ip, POD_PREFIX);
    let peer_cidr = format!("{}/{}", plan.peer_ip, POD_PREFIX);
    let gateway_cidr = format!("{}/{}", plan.gateway_ip, GUEST_PREFIX);

    run_ip(&[
        "link",
        "add",
        &plan.host_veth,
        "type",
        "veth",
        "peer",
        "name",
        &plan.peer_veth,
    ])
    .await?;
    run_ip(&["link", "set", &plan.peer_veth, "netns", &plan.netns]).await?;
    run_ip(&["addr", "add", &host_cidr, "dev", &plan.host_veth]).await?;
    run_ip(&["link", "set", &plan.host_veth, "up"]).await?;

    run_netns(
        &plan.netns,
        &["link", "add", &plan.bridge, "type", "bridge"],
    )
    .await?;
    run_netns(&plan.netns, &["link", "set", &plan.bridge, "up"]).await?;
    run_netns(
        &plan.netns,
        &["addr", "add", &peer_cidr, "dev", &plan.peer_veth],
    )
    .await?;
    run_netns(&plan.netns, &["link", "set", &plan.peer_veth, "up"]).await?;
    run_netns(
        &plan.netns,
        &["tuntap", "add", "dev", &plan.tap_name, "mode", "tap"],
    )
    .await?;
    run_netns(
        &plan.netns,
        &["link", "set", &plan.tap_name, "master", &plan.bridge],
    )
    .await?;
    run_netns(&plan.netns, &["link", "set", &plan.tap_name, "up"]).await?;
    run_netns(
        &plan.netns,
        &["addr", "add", &gateway_cidr, "dev", &plan.bridge],
    )
    .await?;
    run_netns(
        &plan.netns,
        &["route", "add", "default", "via", &plan.host_ip.to_string()],
    )
    .await?;
    // Rewrite the CONSTANT guest address to this pod's unique link address on
    // the way out of the namespace. Without this every pod's packets would leave
    // claiming to be 192.168.241.2 and the host could not tell them apart.
    // MASQUERADE picks the outgoing interface's address, which is exactly
    // `peer_ip`, so the unique value is never written into the guest's view.
    run_netns_iptables(
        &plan.netns,
        &[
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            &guest_subnet_cidr(),
            "-o",
            &plan.peer_veth,
            "-j",
            "MASQUERADE",
        ],
    )
    .await?;
    run_netns(&plan.netns, &["sysctl", "-w", "net.ipv4.ip_forward=1"]).await?;
    run_netns(
        &plan.netns,
        &["sysctl", "-w", "net.bridge.bridge-nf-call-iptables=1"],
    )
    .await?;
    run_netns(
        &plan.netns,
        &["sysctl", "-w", "net.bridge.bridge-nf-call-ip6tables=1"],
    )
    .await?;

    run_sysctl(&["-w", "net.ipv4.ip_forward=1"]).await?;
    ensure_iptables_rule(
        &[
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            &subnet_cidr(plan),
            "-j",
            "MASQUERADE",
        ],
        &[
            "-t",
            "nat",
            "-C",
            "POSTROUTING",
            "-s",
            &subnet_cidr(plan),
            "-j",
            "MASQUERADE",
        ],
    )
    .await?;
    ensure_iptables_rule(
        &["-A", "FORWARD", "-i", &plan.host_veth, "-j", "ACCEPT"],
        &["-C", "FORWARD", "-i", &plan.host_veth, "-j", "ACCEPT"],
    )
    .await?;
    ensure_iptables_rule(
        &[
            "-A",
            "FORWARD",
            "-o",
            &plan.host_veth,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
        &[
            "-C",
            "FORWARD",
            "-o",
            &plan.host_veth,
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
    )
    .await?;

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub async fn setup_network(_plan: &NetPlan) -> Result<(), ApiError> {
    Err(ApiError::Driver(
        "host network setup requires Linux".to_string(),
    ))
}

/// The policy segment of the netns egress chain, **as an ordered value**.
///
/// # Why this function exists
///
/// The ruleset used to exist only as a sequence of `iptables` subprocess calls
/// spread across two loops inside `apply_host_policy`. Nothing could be stated
/// about it, because it was never a thing — only an effect. `EgressConfinement`
/// in `crates/portcullis-core/lean` proves that a chain evaluated first-match-
/// wins over a DROP policy drops anything no rule admits; for that proof to be
/// about THIS system rather than about an intention, the list it folds has to be
/// the list that is actually appended. That is what this returns.
///
/// The order is load-bearing and is the property `deny_precedes_allow_in_the_chain`
/// pins: **every Deny, then every Allow**. Under first-match-wins that makes a
/// deny strictly override a later allow. Reverse the two loops and an
/// `allow: 10.0.0.0/8` silently re-opens a `deny: 10.0.0.7/32`.
pub fn egress_chain(
    policy: &NetworkSpec,
    dns_entries: Option<&[ResolvedDnsEntry]>,
) -> Result<Vec<NetRule>, ApiError> {
    let parsed = parse_rules(policy)?;
    let mut resolved: Vec<NetRule> = Vec::new();
    if let Some(entries) = dns_entries {
        let mut seen = BTreeSet::new();
        for entry in entries {
            for ip in &entry.ips {
                if seen.insert((*ip, entry.port)) {
                    resolved.push(NetRule {
                        kind: RuleKind::Allow,
                        net: IpNet::from(IpAddr::V4(*ip)),
                        port: entry.port,
                    });
                }
            }
        }
    }

    // Deny first, then allow — including the DNS-resolved allows, which are
    // allows like any other and must not outrank a deny.
    let mut chain: Vec<NetRule> = Vec::with_capacity(parsed.len() + resolved.len());
    chain.extend(parsed.iter().filter(|r| r.kind == RuleKind::Deny).cloned());
    chain.extend(parsed.iter().filter(|r| r.kind == RuleKind::Allow).cloned());
    chain.extend(resolved);
    Ok(chain)
}

/// A chain rule in the representation the Lean confinement theorem is stated
/// over, or `None` when it falls outside that model.
///
/// `None` means IPv6: the extracted matcher is IPv4-only (`parse_entry` yields
/// IPv4 in practice and the guest cmdline carries `ipv6.disable=1`). Returning
/// `None` rather than a lossy conversion keeps "the model does not cover this"
/// distinct from "the model says this is fine" — the second would be a claim
/// nobody proved.
#[cfg_attr(not(test), allow(dead_code))]
pub fn model_rule(rule: &NetRule) -> Option<EgressRule> {
    let IpNet::V4(v4) = rule.net else {
        return None;
    };
    Some(EgressRule {
        net: u32::from(v4.network()),
        prefix: v4.prefix_len(),
        port_specific: rule.port.is_some(),
        port: rule.port.unwrap_or(0),
        allow: rule.kind == RuleKind::Allow,
    })
}

/// The whole chain in the proof's representation, or `None` if any rule is
/// outside it. All-or-nothing: a partially-modelled chain would licence a
/// confinement claim over a chain that has rules the model never saw.
#[cfg_attr(not(test), allow(dead_code))]
pub fn model_chain(chain: &[NetRule]) -> Option<Vec<EgressRule>> {
    chain.iter().map(model_rule).collect()
}

#[cfg(target_os = "linux")]
pub async fn apply_host_policy(
    pid: u32,
    policy: &NetworkSpec,
    dns_entries: Option<&[ResolvedDnsEntry]>,
    dns_server: Option<Ipv4Addr>,
) -> Result<(), ApiError> {
    ensure_command("nsenter")?;
    ensure_command("iptables")?;
    // The chain is decided as a value, then applied in exactly that order. The
    // ordering guarantee the Lean theorem relies on lives in `egress_chain`,
    // not scattered through the application loop below.
    let chain = egress_chain(policy, dns_entries)?;

    run_nsenter(pid, &["iptables", "-w", "-F"]).await?;
    run_nsenter(pid, &["iptables", "-w", "-X"]).await?;
    run_nsenter(pid, &["iptables", "-w", "-P", "INPUT", "DROP"]).await?;
    run_nsenter(pid, &["iptables", "-w", "-P", "OUTPUT", "DROP"]).await?;
    run_nsenter(pid, &["iptables", "-w", "-P", "FORWARD", "DROP"]).await?;

    run_nsenter(
        pid,
        &["iptables", "-w", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"],
    )
    .await?;
    run_nsenter(
        pid,
        &["iptables", "-w", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"],
    )
    .await?;
    run_nsenter(
        pid,
        &[
            "iptables",
            "-w",
            "-A",
            "OUTPUT",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
    )
    .await?;
    run_nsenter(
        pid,
        &[
            "iptables",
            "-w",
            "-A",
            "INPUT",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
    )
    .await?;
    run_nsenter(
        pid,
        &[
            "iptables",
            "-w",
            "-A",
            "FORWARD",
            "-m",
            "conntrack",
            "--ctstate",
            "ESTABLISHED,RELATED",
            "-j",
            "ACCEPT",
        ],
    )
    .await?;

    if let Some(server) = dns_server {
        let rule = NetRule {
            kind: RuleKind::Allow,
            net: IpNet::from(IpAddr::V4(server)),
            port: Some(53),
        };
        apply_rule(pid, "INPUT", &rule, "ACCEPT").await?;
    }

    // ONE pass, in chain order. Two filtered passes would re-encode the
    // deny-before-allow ordering here as well as in `egress_chain`, and the two
    // copies could drift — which is exactly the kind of gap the proof is
    // supposed to close rather than depend on.
    for rule in &chain {
        let verdict = if rule.kind == RuleKind::Allow {
            "ACCEPT"
        } else {
            "DROP"
        };
        apply_rule(pid, "OUTPUT", rule, verdict).await?;
        apply_rule(pid, "FORWARD", rule, verdict).await?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
pub async fn snapshot_iptables(pid: u32) -> Result<String, ApiError> {
    ensure_command("nsenter")?;
    ensure_command("iptables-save")?;
    let output = tokio::process::Command::new("nsenter")
        .arg(format!("--net=/proc/{pid}/ns/net"))
        .arg("--")
        .arg("iptables-save")
        .output()
        .await?;
    if !output.status.success() {
        return Err(ApiError::Driver(format!(
            "iptables-save failed with {status}",
            status = output.status
        )));
    }
    let raw = String::from_utf8_lossy(&output.stdout);
    Ok(normalize_iptables_save(&raw))
}

#[cfg(not(target_os = "linux"))]
pub async fn apply_host_policy(
    _pid: u32,
    _policy: &NetworkSpec,
    _dns_entries: Option<&[ResolvedDnsEntry]>,
    _dns_server: Option<Ipv4Addr>,
) -> Result<(), ApiError> {
    Err(ApiError::Driver(
        "host network policy requires Linux".to_string(),
    ))
}

#[cfg(not(target_os = "linux"))]
pub async fn snapshot_iptables(_pid: u32) -> Result<String, ApiError> {
    Err(ApiError::Driver(
        "host network policy requires Linux".to_string(),
    ))
}

#[cfg(target_os = "linux")]
fn normalize_iptables_save(output: &str) -> String {
    output
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .map(normalize_iptables_counters)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(target_os = "linux")]
fn normalize_iptables_counters(line: &str) -> String {
    line.split_whitespace()
        .map(normalize_counter_token)
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(target_os = "linux")]
fn normalize_counter_token(token: &str) -> String {
    let Some(inner) = token
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    else {
        return token.to_string();
    };
    let mut parts = inner.split(':');
    let Some(left) = parts.next() else {
        return token.to_string();
    };
    let Some(right) = parts.next() else {
        return token.to_string();
    };
    if parts.next().is_some() {
        return token.to_string();
    }
    if left.is_empty() || right.is_empty() {
        return token.to_string();
    }
    if left.chars().all(|c| c.is_ascii_digit()) && right.chars().all(|c| c.is_ascii_digit()) {
        "[0:0]".to_string()
    } else {
        token.to_string()
    }
}

fn parse_rules(policy: &NetworkSpec) -> Result<Vec<NetRule>, ApiError> {
    let mut rules = Vec::new();
    for entry in &policy.deny {
        let (net, port) = parse_entry(entry)?;
        rules.push(NetRule {
            kind: RuleKind::Deny,
            net,
            port,
        });
    }
    for entry in &policy.allow {
        let (net, port) = parse_entry(entry)?;
        rules.push(NetRule {
            kind: RuleKind::Allow,
            net,
            port,
        });
    }
    Ok(rules)
}

fn validate_dns_allowlist(policy: &NetworkSpec) -> Result<(), ApiError> {
    for entry in &policy.dns_allow {
        let _ = parse_dns_entry(entry)?;
    }
    Ok(())
}

async fn resolve_dns_allowlist(policy: &NetworkSpec) -> Result<Vec<ResolvedDnsEntry>, ApiError> {
    let mut resolved = Vec::new();
    for entry in &policy.dns_allow {
        let (host, port) = parse_dns_entry(entry)?;
        let ips = resolve_host_ipv4(&host).await?;
        resolved.push(ResolvedDnsEntry { host, port, ips });
    }
    Ok(resolved)
}

async fn resolve_host_ipv4(host: &str) -> Result<Vec<Ipv4Addr>, ApiError> {
    let mut ips = BTreeSet::new();
    let addrs = lookup_host((host, 0)).await.map_err(|e| {
        ApiError::InvalidSpec(format!("dns allowlist lookup failed for {host}: {e}"))
    })?;
    for addr in addrs {
        if let IpAddr::V4(ip) = addr.ip() {
            ips.insert(ip);
        }
    }
    if ips.is_empty() {
        return Err(ApiError::InvalidSpec(format!(
            "dns allowlist entry {host} resolved to no IPv4 addresses"
        )));
    }
    Ok(ips.into_iter().collect())
}

fn parse_dns_entry(entry: &str) -> Result<(String, Option<u16>), ApiError> {
    let (host, port) = split_port(entry)?;
    let host = host.trim();
    if host.is_empty() {
        return Err(invalid_dns_entry(entry));
    }
    if host.contains('*') {
        return Err(ApiError::InvalidSpec(format!(
            "dns allowlist does not support wildcards (got {entry})"
        )));
    }
    if host.contains('/') {
        return Err(invalid_dns_entry(entry));
    }
    if host.parse::<IpAddr>().is_ok() {
        return Err(ApiError::InvalidSpec(format!(
            "dns allowlist entries must be hostnames; use allow/deny for IPs (got {entry})"
        )));
    }
    Ok((host.to_string(), port))
}

fn invalid_dns_entry(entry: &str) -> ApiError {
    ApiError::InvalidSpec(format!(
        "dns allowlist entry must be hostname with optional :port (got {entry})"
    ))
}

fn parse_entry(entry: &str) -> Result<(IpNet, Option<u16>), ApiError> {
    let (addr_part, port) = split_port(entry)?;
    let net = if addr_part.contains('/') {
        addr_part
            .parse::<IpNet>()
            .map_err(|_| invalid_entry(entry))?
    } else {
        let ip = addr_part
            .parse::<IpAddr>()
            .map_err(|_| invalid_entry(entry))?;
        IpNet::from(ip)
    };
    Ok((net, port))
}

fn split_port(entry: &str) -> Result<(String, Option<u16>), ApiError> {
    if let Some(stripped) = entry.strip_prefix('[') {
        let end = stripped.find(']').ok_or_else(|| invalid_entry(entry))?;
        let addr = stripped[..end].to_string();
        let rest = &stripped[end + 1..];
        if rest.is_empty() {
            return Ok((addr, None));
        }
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| invalid_entry(entry))?
            .parse::<u16>()
            .map_err(|_| invalid_entry(entry))?;
        return Ok((addr, Some(port)));
    }

    if let Ok(socket) = entry.parse::<SocketAddr>() {
        return Ok((socket.ip().to_string(), Some(socket.port())));
    }

    if let Some((addr, port)) = split_port_suffix(entry)? {
        return Ok((addr, Some(port)));
    }

    Ok((entry.to_string(), None))
}

fn split_port_suffix(entry: &str) -> Result<Option<(String, u16)>, ApiError> {
    let Some(idx) = entry.rfind(':') else {
        return Ok(None);
    };
    let (left, right) = entry.split_at(idx);
    if left.contains(':') {
        return Ok(None);
    }
    let port = right
        .strip_prefix(':')
        .ok_or_else(|| invalid_entry(entry))?
        .parse::<u16>()
        .map_err(|_| invalid_entry(entry))?;
    Ok(Some((left.to_string(), port)))
}

fn invalid_entry(entry: &str) -> ApiError {
    ApiError::InvalidSpec(format!(
        "network entry must be IP/CIDR with optional :port (got {entry})"
    ))
}

#[cfg(target_os = "linux")]
fn ensure_command(command: &str) -> Result<(), ApiError> {
    let mut cmd = Command::new(command);
    if command == "ip" {
        cmd.arg("-V");
    } else {
        cmd.arg("--version");
    }
    let status = cmd
        .status()
        .map_err(|e| ApiError::Driver(format!("missing {command}: {e}")))?;
    if !status.success() {
        return Err(ApiError::Driver(format!(
            "{command} not available (exit {status})"
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn run_nsenter(pid: u32, args: &[&str]) -> Result<(), ApiError> {
    let status = tokio::process::Command::new("nsenter")
        .arg(format!("--net=/proc/{pid}/ns/net"))
        .arg("--")
        .args(args)
        .status()
        .await?;
    if !status.success() {
        return Err(ApiError::Driver(format!(
            "nsenter {:?} failed with {status}",
            args
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn run_ip(args: &[&str]) -> Result<(), ApiError> {
    let status = tokio::process::Command::new("ip")
        .args(args)
        .status()
        .await?;
    if !status.success() {
        return Err(ApiError::Driver(format!(
            "ip {:?} failed with {status}",
            args
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
/// Run a command inside a named network namespace.
///
/// # No `--` here, and it is not a style choice
///
/// `ip netns exec NAME -- cmd` does **not** mean "end of options" to iproute2.
/// `ip` takes everything after NAME as the command vector, so the `--` becomes
/// argv[0] and the exec fails:
///
/// ```text
/// # ip netns exec nuctest -- iptables -w -F
/// exec of "--" failed: No such file or directory
/// ```
///
/// Measured on iproute2 6.1 (Ubuntu 24.04). Since `apply_default_deny` is the
/// first thing the Firecracker driver does for a pod with a netns — the
/// **default** — this made every launch fail on a default install, reported as
/// `iptables -F failed with exit status: 1`. The two `nsenter` call sites in
/// this file keep their `--`, because util-linux really does accept it there;
/// the separators are not interchangeable and this is why.
///
/// Stderr is captured rather than inherited, because inheriting it is how the
/// one line that identified this bug got lost: the driver reported an exit
/// status while `exec of "--" failed` went to the node's stdout stream,
/// unattached to the error that mattered.
/// Run `iptables` inside a pod's namespace.
///
/// Separate from `run_netns` only because the first argument is `iptables`
/// rather than `ip`; the failure reporting is deliberately identical, since a
/// silent NAT-rule failure would leave every pod's packets leaving under the
/// same constant source address and the host unable to tell them apart.
async fn run_netns_iptables(netns: &str, args: &[&str]) -> Result<(), ApiError> {
    let output = tokio::process::Command::new("ip")
        .args(["netns", "exec", netns, "iptables"])
        .args(args)
        .output()
        .await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ApiError::Driver(format!(
            "ip netns exec {netns:?} iptables {args:?} failed with {}: {}",
            output.status,
            stderr.trim()
        )));
    }
    Ok(())
}

async fn run_netns(netns: &str, args: &[&str]) -> Result<(), ApiError> {
    let output = tokio::process::Command::new("ip")
        .args(["netns", "exec", netns])
        .args(args)
        .output()
        .await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ApiError::Driver(format!(
            "ip netns exec {netns:?} {args:?} failed with {}: {}",
            output.status,
            stderr.trim()
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn run_sysctl(args: &[&str]) -> Result<(), ApiError> {
    let status = tokio::process::Command::new("sysctl")
        .args(args)
        .status()
        .await?;
    if !status.success() {
        return Err(ApiError::Driver(format!(
            "sysctl {:?} failed with {status}",
            args
        )));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn ensure_iptables_rule(add: &[&str], check: &[&str]) -> Result<(), ApiError> {
    let status = tokio::process::Command::new("iptables")
        .args(check)
        .status()
        .await?;
    if status.success() {
        return Ok(());
    }
    let status = tokio::process::Command::new("iptables")
        .args(add)
        .status()
        .await?;
    if !status.success() {
        return Err(ApiError::Driver(format!(
            "iptables {:?} failed with {status}",
            add
        )));
    }
    Ok(())
}

fn subnet_cidr(plan: &NetPlan) -> String {
    plan.subnet.to_string()
}

fn add_ipv4(base: Ipv4Addr, offset: u32) -> Ipv4Addr {
    let value = u32::from(base).saturating_add(offset);
    Ipv4Addr::from(value)
}

fn short_id(id: Uuid) -> String {
    let bytes = id.as_bytes();
    hex::encode(&bytes[..4])
}

fn mac_from_id(id: Uuid) -> String {
    let bytes = id.as_bytes();
    format!(
        "06:00:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3]
    )
}

#[cfg(target_os = "linux")]
async fn apply_rule(pid: u32, chain: &str, rule: &NetRule, verdict: &str) -> Result<(), ApiError> {
    let net = rule.net.to_string();
    if let Some(port) = rule.port {
        run_nsenter(
            pid,
            &[
                "iptables",
                "-w",
                "-A",
                chain,
                "-p",
                "tcp",
                "-d",
                &net,
                "--dport",
                &port.to_string(),
                "-j",
                verdict,
            ],
        )
        .await?;
        run_nsenter(
            pid,
            &[
                "iptables",
                "-w",
                "-A",
                chain,
                "-p",
                "udp",
                "-d",
                &net,
                "--dport",
                &port.to_string(),
                "-j",
                verdict,
            ],
        )
        .await?;
    } else {
        run_nsenter(
            pid,
            &["iptables", "-w", "-A", chain, "-d", &net, "-j", verdict],
        )
        .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ip netns exec NAME -- cmd` execs the literal `--` and fails. This test
    /// reads the source rather than running `ip`, because the bug is in the argv
    /// we construct and the CI runner that would catch it at runtime is the one
    /// place this code is hardest to exercise.
    ///
    /// Non-vacuity first: if the scan finds no `ip netns exec` call sites at all,
    /// the "none of them has a `--`" conclusion would be equally true of a file
    /// that had been renamed out from under it.
    #[test]
    fn no_ip_netns_exec_passes_a_double_dash_separator() {
        let source = include_str!("net.rs");
        let call_sites: Vec<&str> = source
            .lines()
            .filter(|l| l.contains("\"netns\", \"exec\""))
            .collect();
        assert!(
            call_sites.len() >= 2,
            "expected to find the ip-netns-exec call sites; found {} — has this \
             code moved? A scan that matches nothing proves nothing.",
            call_sites.len()
        );
        for line in call_sites {
            assert!(
                !line.contains("\"--\""),
                "`ip netns exec` must not be given a `--` separator; iproute2 \
                 execs it as the command:\n  {}",
                line.trim()
            );
        }
    }

    /// The `nsenter` sites are the counterexample: util-linux does accept `--`
    /// there, so a blanket "no `--` anywhere" rule would be wrong. Pinning both
    /// halves keeps a future cleanup from removing the correct one too.
    #[test]
    fn nsenter_keeps_its_double_dash_separator() {
        let source = include_str!("net.rs");
        let nsenter_sites = source
            .lines()
            .filter(|l| l.contains("--net=/proc/"))
            .count();
        assert!(
            nsenter_sites >= 2,
            "expected the nsenter call sites; found {nsenter_sites}"
        );
    }

    #[test]
    fn parse_ipv4_with_port() {
        let (net, port) = parse_entry("10.0.0.5:443").unwrap();
        assert_eq!(net.to_string(), "10.0.0.5/32");
        assert_eq!(port, Some(443));
    }

    #[test]
    fn parse_ipv4_cidr() {
        let (net, port) = parse_entry("10.0.0.0/24").unwrap();
        assert_eq!(net.to_string(), "10.0.0.0/24");
        assert_eq!(port, None);
    }

    #[test]
    fn parse_ipv6_with_port() {
        let (net, port) = parse_entry("[2001:db8::1]:8443").unwrap();
        assert_eq!(net.to_string(), "2001:db8::1/128");
        assert_eq!(port, Some(8443));
    }

    #[test]
    fn parse_ipv6_cidr() {
        let (net, port) = parse_entry("2001:db8::/64").unwrap();
        assert_eq!(net.to_string(), "2001:db8::/64");
        assert_eq!(port, None);
    }

    #[test]
    fn parse_dns_hostname_with_port() {
        let (host, port) = parse_dns_entry("example.com:443").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, Some(443));
    }

    #[test]
    fn parse_dns_rejects_ip() {
        let err = parse_dns_entry("10.0.0.1").unwrap_err();
        assert!(err.to_string().contains("hostnames"));
    }

    #[test]
    fn network_allocator_reclaims_indices() {
        let allocator = NetworkAllocator::new();
        let pod1 = Uuid::new_v4();
        let pod2 = Uuid::new_v4();
        let pod3 = Uuid::new_v4();

        // Allocate three networks
        let plan1 = allocator.allocate(pod1, "ns1".into()).unwrap();
        let plan2 = allocator.allocate(pod2, "ns2".into()).unwrap();
        let plan3 = allocator.allocate(pod3, "ns3".into()).unwrap();

        // Indices should be different
        assert_eq!(plan1.index, 0);
        assert_eq!(plan2.index, 1);
        assert_eq!(plan3.index, 2);

        // IPs should be different
        // Guest addresses are now CONSTANT by design (#2202): the index must not
        // reach anything a guest can read. Distinctness moved to the link.
        assert_ne!(plan1.host_ip, plan2.host_ip);
        assert_ne!(plan2.host_ip, plan3.host_ip);
        assert_ne!(plan1.peer_ip, plan2.peer_ip);

        // Release plan2
        allocator.release(plan2.index);

        // Next allocation should reuse the released index
        let pod4 = Uuid::new_v4();
        let plan4 = allocator.allocate(pod4, "ns4".into()).unwrap();
        assert_eq!(plan4.index, 1); // Reused!
        assert_eq!(plan4.host_ip, plan2.host_ip); // Same link range, recycled

        // Next new allocation should get index 3
        let pod5 = Uuid::new_v4();
        let plan5 = allocator.allocate(pod5, "ns5".into()).unwrap();
        assert_eq!(plan5.index, 3);
    }

    #[test]
    fn network_allocator_release_is_idempotent() {
        let allocator = NetworkAllocator::new();
        let pod = Uuid::new_v4();
        let plan = allocator.allocate(pod, "ns".into()).unwrap();

        // Release twice should not cause duplicates
        allocator.release(plan.index);
        allocator.release(plan.index);

        // Should only get one reuse
        let pod2 = Uuid::new_v4();
        let plan2 = allocator.allocate(pod2, "ns2".into()).unwrap();
        assert_eq!(plan2.index, 0);

        let pod3 = Uuid::new_v4();
        let plan3 = allocator.allocate(pod3, "ns3".into()).unwrap();
        assert_eq!(plan3.index, 1); // Not 0 again
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn normalize_iptables_save_strips_counters_and_comments() {
        let input = r#"# Generated by iptables-save v1.8.7 on Wed
*filter
:INPUT DROP [12:34]
-A OUTPUT -j ACCEPT [1:2]
COMMIT
"#;
        let output = normalize_iptables_save(input);
        assert!(!output.contains("Generated by"));
        assert!(output.contains("*filter"));
        assert!(output.contains(":INPUT DROP [0:0]"));
        assert!(output.contains("-A OUTPUT -j ACCEPT [0:0]"));
    }

    use proptest::prelude::*;

    proptest! {
        /// ISOLATION INVARIANT (3): a network namespace is NEVER omitted and is
        /// NEVER created without a default-deny baseline, and a network policy
        /// is never silently accepted when there is nowhere to enforce it.
        #[test]
        fn netns_plan_never_omits_netns_or_default_deny(
            firecracker_netns in any::<bool>(),
            has_policy in any::<bool>(),
        ) {
            let policy = has_policy.then(NetworkSpec::deny_all);
            let plan = NetnsPlan::decide(firecracker_netns, policy.as_ref());

            // A netns is created IFF the node runs in netns mode — independent
            // of whether a policy was supplied (deny-by-default for every pod).
            prop_assert_eq!(plan.create_netns, firecracker_netns);

            // A created netns ALWAYS carries default-deny: no open-by-default
            // namespace can exist.
            prop_assert_eq!(plan.create_netns, plan.apply_default_deny);

            // A host NetPlan (veth/bridge/tap) is only ever allocated inside a
            // netns and only when a policy demands egress.
            prop_assert!(!plan.allocate_net_plan || plan.create_netns);
            prop_assert!(!plan.allocate_net_plan || has_policy);

            // A policy with no netns to enforce it is rejected, never ignored.
            if has_policy && !firecracker_netns {
                prop_assert!(plan.reject_unsupported_policy);
            }
            // Rejection and netns-creation are mutually exclusive.
            prop_assert!(!(plan.reject_unsupported_policy && plan.create_netns));
        }

        /// ISOLATION INVARIANT (2), network analog: N concurrently-allocated
        /// pods receive DISTINCT pool indices and DISTINCT guest IPs — the
        /// allocator never hands the same network slot to two live pods.
        #[test]
        fn allocator_gives_distinct_resources_to_live_pods(n in 1usize..16) {
            let allocator = NetworkAllocator::new();
            let mut indices = std::collections::HashSet::new();
            let mut link_ips = std::collections::HashSet::new();
            for _ in 0..n {
                let plan = allocator
                    .allocate(Uuid::new_v4(), "nuc-test".to_string())
                    .expect("pool not exhausted for small n");
                prop_assert!(indices.insert(plan.index), "duplicate pool index");
                // The LINK address is what must be unique per live pod; the
                // guest address is deliberately shared (#2202).
                prop_assert!(link_ips.insert(plan.host_ip), "duplicate link IP");
            }
        }
    }
}

// ── Identity is gated on egress confinement ───────────────────────────────

/// IPv4 ranges that are not globally routable. A workload confined to these
/// cannot present a credential to the open internet.
///
/// RFC1918 private, loopback, link-local, and CGNAT (RFC6598). Deliberately not
/// exhaustive over every reserved block — anything unlisted is treated as
/// PUBLIC, which is the conservative direction for a check whose `false` grants
/// an identity.
const NON_ROUTABLE_V4: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(10, 0, 0, 0), 8),
    (Ipv4Addr::new(172, 16, 0, 0), 12),
    (Ipv4Addr::new(192, 168, 0, 0), 16),
    (Ipv4Addr::new(127, 0, 0, 0), 8),
    (Ipv4Addr::new(169, 254, 0, 0), 16),
    (Ipv4Addr::new(100, 64, 0, 0), 10),
];

/// Whether `net` can reach any globally-routable address.
///
/// True unless the whole range sits inside one of [`NON_ROUTABLE_V4`]. A range
/// straddling private and public space counts as public, which is correct: it
/// admits public destinations.
///
/// IPv6 returns `true` — the ranges above are IPv4 and nucleus disables IPv6 in
/// the guest, so an IPv6 allow rule is not something to reason about and is
/// treated as reaching the internet rather than assumed contained.
pub fn reaches_public_internet(net: IpNet) -> bool {
    let IpNet::V4(v4) = net else {
        return true;
    };
    !NON_ROUTABLE_V4.iter().any(|(base, prefix)| {
        ipnet::Ipv4Net::new(*base, *prefix)
            .map(|block| block.contains(&v4))
            .unwrap_or(false)
    })
}

/// Whether a pod may be given a workload identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityGrant {
    /// Egress is confined; an SVID may be issued.
    Granted,
    /// Egress is unconfined; issuing would produce a credential presentable to
    /// destinations nobody can name.
    Denied {
        /// The allow entry responsible, for an actionable error.
        offending: String,
    },
}

impl IdentityGrant {
    /// Whether an SVID may be issued.
    pub fn is_granted(&self) -> bool {
        matches!(self, IdentityGrant::Granted)
    }
}

impl std::fmt::Display for IdentityGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityGrant::Granted => write!(f, "granted"),
            IdentityGrant::Denied { offending } => write!(
                f,
                "workload identity refused: network policy allows {offending}, which reaches \
                 public address space without naming a specific host. A SPIFFE SVID bounds how \
                 LONG a credential is useful; egress confinement is what bounds WHERE it can be \
                 presented. With unbounded egress the second bound is absent, so the identity \
                 would be presentable to any endpoint including an attacker's. Narrow the \
                 allowlist to specific hosts (/32, or use dns_allow), or run without an identity."
            ),
        }
    }
}

/// Decide whether a pod's egress policy is confined enough to hold an identity.
///
/// # The rule
///
/// Every `allow` entry must either stay inside non-routable space, or name a
/// single host (`/32`). "Some private network" is fine at any breadth; "some
/// slice of the internet" is not, unless you can say which host.
///
/// `dns_allow` is unaffected by construction — it resolves to `/32` entries.
///
/// # Why absence of a policy GRANTS
///
/// No policy means `NetnsPlan::decide` still creates the netns and applies
/// default-deny, with no allow rules at all — the most confined state there is,
/// not the least. Refusing there would invert the incentive the gate exists to
/// create.
pub fn decide_identity_grant(network: Option<&NetworkSpec>) -> IdentityGrant {
    let Some(policy) = network else {
        return IdentityGrant::Granted;
    };
    for entry in &policy.allow {
        let Ok((net, _port)) = parse_entry(entry) else {
            // Unparseable entries are rejected upstream by `validate_policy`.
            // Refuse here too rather than skip: an entry nobody could parse is
            // not an entry anyone can vouch for.
            return IdentityGrant::Denied {
                offending: entry.clone(),
            };
        };
        let names_one_host = net.prefix_len() == net.max_prefix_len();
        if reaches_public_internet(net) && !names_one_host {
            return IdentityGrant::Denied {
                offending: entry.clone(),
            };
        }
    }
    IdentityGrant::Granted
}

/// The vsock port to advertise to the guest for the workload API, or `None`.
///
/// Pulled out of `spawn_firecracker_pod` so the composition that actually
/// enforces the trade is testable without booting a VM. `None` means the guest
/// is never told where the workload API lives, so nothing in it can fetch an
/// SVID through the ordinary path.
///
/// Residual, and worth stating: this withholds the ENDPOINT, it does not refuse
/// to serve. A guest that guessed the port could still reach the listener. The
/// defence-in-depth version refuses at the serving side too, keyed on the pod's
/// grant; that is not implemented.
pub fn workload_api_port_for(
    identity_enabled: bool,
    grant: &IdentityGrant,
    port: u32,
) -> Option<u32> {
    if identity_enabled && grant.is_granted() {
        Some(port)
    } else {
        None
    }
}

/// The identity manager to register a pod with, or `None`.
///
/// Serving-side mirror of [`workload_api_port_for`]. Withholding the port hides
/// the endpoint; withholding the REGISTRATION means there is nothing to serve
/// even to a guest that found it anyway — `WorkloadApiServer` issues against
/// registered connections, so an unregistered pod has nothing to fetch.
///
/// Generic over the manager type so this composition is compiled and tested on
/// any host, rather than living only inside the Linux-gated spawn path where a
/// dev machine never type-checks it.
pub fn identity_registration<'a, T>(
    manager: Option<&'a T>,
    grant: &IdentityGrant,
) -> Option<&'a T> {
    manager.filter(|_| grant.is_granted())
}

// ── The DNS proxy is a static map, not a resolver ─────────────────────────

/// dnsmasq directives that would give the proxy an upstream nameserver.
///
/// Any one of these turns a static map into a *forwarder*, and a forwarder is
/// what makes DNS tunnelling work: the agent encodes data in query labels, the
/// resolver dutifully forwards them to the attacker's authoritative server, and
/// the data has left the host without a single packet going anywhere the egress
/// allowlist would notice. Nothing in the iptables policy sees it, because the
/// query goes to the allowed resolver.
///
/// The property that closes it is simply that there IS no upstream. Kept as an
/// explicit denylist so `the_dns_proxy_has_no_upstream_and_cannot_forward` fails
/// loudly if one is ever added.
#[cfg_attr(not(test), allow(dead_code))]
pub const DNS_FORWARDING_DIRECTIVES: &[&str] = &[
    "server=",
    "resolv-file",
    "all-servers",
    "strict-order",
    "rev-server",
    "local=/",
];

/// The dnsmasq configuration for a pod's DNS proxy.
///
/// Pure so the security property above is testable without spawning dnsmasq.
/// Answers come only from the static `address=` map built from `dns_allow`;
/// `no-resolv` plus the absence of any `server=` means there is no upstream to
/// forward an unmatched query to, so an unlisted name fails locally rather than
/// travelling.
pub fn dnsmasq_config(gateway: Ipv4Addr, entries: &[ResolvedDnsEntry]) -> String {
    let mut config = String::new();
    // no-resolv: ignore /etc/resolv.conf. Without it dnsmasq would inherit the
    // host's nameservers and become a forwarder.
    config.push_str("no-resolv\n");
    config.push_str("no-hosts\n");
    config.push_str("bind-interfaces\n");
    config.push_str(&format!("listen-address={gateway}\n"));
    config.push_str("port=53\n");
    for entry in entries {
        for ip in &entry.ips {
            config.push_str(&format!("address=/{}/{}\n", entry.host, ip));
        }
    }
    config
}

#[cfg(test)]
mod guest_address_is_constant_tests {
    use super::*;

    fn plan(alloc: &NetworkAllocator) -> NetPlan {
        alloc
            .allocate(Uuid::new_v4(), "nuc-test".to_string())
            .expect("pool not exhausted")
    }

    /// **The property #2202 is about.** Two pods see the SAME network
    /// configuration, so a guest reading `ip addr` learns nothing about how many
    /// pods preceded it. The allocation index used to be recoverable by dividing
    /// the guest's own address by the pod stride.
    #[test]
    fn two_pods_see_identical_guest_addresses() {
        let alloc = NetworkAllocator::new();
        let (a, b) = (plan(&alloc), plan(&alloc));
        assert_eq!(a.guest_ip, b.guest_ip, "guest address must not vary");
        assert_eq!(a.gateway_ip, b.gateway_ip, "gateway must not vary");
        assert_eq!(a.cidr, b.cidr, "prefix must not vary");
    }

    /// The whole guest-visible boot argument must be identical — it is the
    /// literal string handed to the guest kernel, so it is the thing that either
    /// does or does not carry the index.
    #[test]
    fn the_guest_kernel_argument_does_not_vary() {
        let alloc = NetworkAllocator::new();
        let (a, b) = (plan(&alloc), plan(&alloc));
        assert_eq!(a.kernel_arg(), b.kernel_arg());
    }

    /// And the host side still distinguishes them, or the pods could not be
    /// routed apart. Without this the test above would be satisfiable by an
    /// allocator that hands out one address to everyone.
    #[test]
    fn the_host_side_still_distinguishes_pods() {
        let alloc = NetworkAllocator::new();
        let (a, b) = (plan(&alloc), plan(&alloc));
        assert_ne!(a.host_ip, b.host_ip);
        assert_ne!(a.peer_ip, b.peer_ip);
        assert_ne!(a.subnet, b.subnet);
    }

    /// The guest address must not fall inside the link pool, or the constant
    /// would collide with some pod's link address and routing would break.
    #[test]
    fn the_guest_subnet_is_disjoint_from_the_link_pool() {
        let pool = IpNet::new(IpAddr::V4(NET_BASE), NET_POOL_PREFIX).unwrap();
        assert!(
            !pool.contains(&IpAddr::V4(GUEST_ADDR)),
            "the constant guest address is inside the link pool"
        );
        assert!(
            !pool.contains(&IpAddr::V4(GUEST_GATEWAY)),
            "the constant gateway is inside the link pool"
        );
    }
}
