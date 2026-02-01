#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use ipnet::IpNet;
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

#[derive(Debug)]
pub struct NetworkAllocator {
    next: AtomicUsize,
}

impl NetworkAllocator {
    pub fn new() -> Self {
        Self {
            next: AtomicUsize::new(0),
        }
    }

    pub fn allocate(&self, pod_id: Uuid, netns: String) -> Result<NetPlan, ApiError> {
        let index = self.next.fetch_add(1, Ordering::SeqCst);
        if POD_PREFIX < NET_POOL_PREFIX {
            return Err(ApiError::Driver(
                "invalid network pool: pod prefix must be >= pool prefix".to_string(),
            ));
        }
        let max = 1usize << (POD_PREFIX - NET_POOL_PREFIX) as usize;
        if index >= max {
            return Err(ApiError::Driver(
                "network pool exhausted; increase base CIDR".to_string(),
            ));
        }
        let offset = (index as u32) * u32::from(POD_STRIDE);
        let base = add_ipv4(NET_BASE, offset);
        let host_ip = add_ipv4(base, 1);
        let gateway_ip = add_ipv4(base, 2);
        let guest_ip = add_ipv4(base, 3);
        let subnet = IpNet::new(IpAddr::V4(base), POD_PREFIX)
            .map_err(|_| ApiError::Driver("invalid network pool".to_string()))?;

        let short = short_id(pod_id);
        let host_veth = format!("veth{short}");
        let peer_veth = format!("vpeer{short}");
        let tap_name = format!("tap{short}");
        let bridge = format!("br{short}");

        Ok(NetPlan {
            netns,
            host_veth,
            peer_veth,
            tap_name,
            bridge,
            guest_mac: mac_from_id(pod_id),
            guest_ip,
            gateway_ip,
            host_ip,
            cidr: POD_PREFIX,
            subnet,
            dns: DEFAULT_DNS,
        })
    }
}

#[derive(Clone, Debug)]
pub struct NetPlan {
    pub netns: String,
    pub host_veth: String,
    pub peer_veth: String,
    pub tap_name: String,
    pub bridge: String,
    pub guest_mac: String,
    pub guest_ip: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
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

pub fn netns_name(pod_id: Uuid) -> String {
    format!("nuc-{}", short_id(pod_id))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuleKind {
    Allow,
    Deny,
}

#[derive(Clone, Debug)]
struct NetRule {
    kind: RuleKind,
    net: IpNet,
    port: Option<u16>,
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

    let mut config = String::new();
    config.push_str("no-resolv\n");
    config.push_str("no-hosts\n");
    config.push_str("bind-interfaces\n");
    config.push_str(&format!("listen-address={}\n", plan.gateway_ip));
    config.push_str("port=53\n");
    for entry in &entries {
        for ip in &entry.ips {
            config.push_str(&format!("address=/{}/{}\n", entry.host, ip));
        }
    }
    tokio::fs::write(&config_path, config).await?;

    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(ApiError::Io)?;

    let mut command = tokio::process::Command::new("ip");
    command
        .args(["netns", "exec", &plan.netns, "--"])
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
pub async fn setup_network(plan: &NetPlan) -> Result<(), ApiError> {
    ensure_command("ip")?;
    ensure_command("iptables")?;
    ensure_command("sysctl")?;

    let host_cidr = format!("{}/{}", plan.host_ip, plan.cidr);
    let gateway_cidr = format!("{}/{}", plan.gateway_ip, plan.cidr);

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
        &["link", "set", &plan.peer_veth, "master", &plan.bridge],
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

#[cfg(target_os = "linux")]
pub async fn apply_host_policy(
    pid: u32,
    policy: &NetworkSpec,
    dns_entries: Option<&[ResolvedDnsEntry]>,
    dns_server: Option<Ipv4Addr>,
) -> Result<(), ApiError> {
    ensure_command("nsenter")?;
    ensure_command("iptables")?;
    let mut rules = parse_rules(policy)?;
    if let Some(entries) = dns_entries {
        let mut seen = BTreeSet::new();
        for entry in entries {
            for ip in &entry.ips {
                let key = (*ip, entry.port);
                if seen.insert(key) {
                    rules.push(NetRule {
                        kind: RuleKind::Allow,
                        net: IpNet::from(IpAddr::V4(*ip)),
                        port: entry.port,
                    });
                }
            }
        }
    }

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

    for rule in rules.iter().filter(|rule| rule.kind == RuleKind::Deny) {
        apply_rule(pid, "OUTPUT", rule, "DROP").await?;
        apply_rule(pid, "FORWARD", rule, "DROP").await?;
    }
    for rule in rules.iter().filter(|rule| rule.kind == RuleKind::Allow) {
        apply_rule(pid, "OUTPUT", rule, "ACCEPT").await?;
        apply_rule(pid, "FORWARD", rule, "ACCEPT").await?;
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
    let addrs = lookup_host((host, 0))
        .await
        .map_err(|e| ApiError::InvalidSpec(format!("dns allowlist lookup failed for {host}: {e}")))?;
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
async fn run_netns(netns: &str, args: &[&str]) -> Result<(), ApiError> {
    let status = tokio::process::Command::new("ip")
        .args(["netns", "exec", netns, "--"])
        .args(args)
        .status()
        .await?;
    if !status.success() {
        return Err(ApiError::Driver(format!(
            "ip netns exec {netns:?} {:?} failed with {status}",
            args
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
}
