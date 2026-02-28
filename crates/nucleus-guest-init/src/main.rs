use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

mod identity;

#[cfg(target_os = "linux")]
use nix::mount::{mount, MsFlags};
#[cfg(target_os = "linux")]
use nix::sys::stat::umask;

#[cfg(not(target_os = "linux"))]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct MsFlags;

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
impl MsFlags {
    const MS_NOSUID: MsFlags = MsFlags;
    const MS_NODEV: MsFlags = MsFlags;
    const MS_REMOUNT: MsFlags = MsFlags;
    const MS_RDONLY: MsFlags = MsFlags;
    fn empty() -> MsFlags {
        MsFlags
    }
}

#[cfg(not(target_os = "linux"))]
impl std::ops::BitOr for MsFlags {
    type Output = MsFlags;
    fn bitor(self, _rhs: MsFlags) -> MsFlags {
        MsFlags
    }
}

const POD_SPEC_PATH: &str = "/etc/nucleus/pod.yaml";
const FALLBACK_POD_SPEC: &str = "/pod.yaml";
const PROXY_BIN: &str = "/usr/local/bin/nucleus-tool-proxy";
const GUEST_NET_SH: &str = "/usr/local/bin/guest-net.sh";

fn main() {
    if let Err(err) = run() {
        eprintln!("nucleus-guest-init error: {err}");
    }
}

fn run() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let _ = umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
    }

    ensure_dir("/etc/nucleus")?;
    ensure_dir("/work")?;

    mount_fs("proc", "/proc", "proc", MsFlags::empty(), None);
    mount_fs("sys", "/sys", "sysfs", MsFlags::empty(), None);
    mount_fs("dev", "/dev", "devtmpfs", MsFlags::empty(), None);
    mount_fs("tmpfs", "/tmp", "tmpfs", MsFlags::empty(), None);
    mount_fs("tmpfs", "/run", "tmpfs", MsFlags::empty(), None);

    if Path::new("/dev/vdb").exists() {
        mount_fs(
            "/dev/vdb",
            "/work",
            "ext4",
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            None,
        );
    }

    let spec_path = resolve_pod_spec()?;
    let net_config = parse_net_config("/proc/cmdline");

    if let Some(net) = net_config.as_ref() {
        configure_network(net);
    }

    if (Path::new("/etc/nucleus/net.allow").exists() || Path::new("/etc/nucleus/net.deny").exists())
        && Path::new(GUEST_NET_SH).exists()
    {
        let _ = Command::new(GUEST_NET_SH).status();
    }

    // Read secrets from kernel command line (preferred) or files (legacy/fallback)
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();

    // Fetch SPIFFE identity from host if configured
    if let Some(port) = identity::parse_workload_api_port(&cmdline) {
        match identity::fetch_identity(port) {
            Ok(spiffe_id) => {
                eprintln!("fetched identity: {spiffe_id}");
            }
            Err(err) => {
                eprintln!("failed to fetch identity: {err}");
                // Continue without identity - not fatal for now
            }
        }
    }

    let auth_secret = parse_cmdline_secret(&cmdline, "nucleus.auth_secret")
        .or_else(|| read_secret("/etc/nucleus/auth.secret"))
        .ok_or_else(|| {
            "missing auth secret (set nucleus.auth_secret in boot args or /etc/nucleus/auth.secret)"
                .to_string()
        })?;

    let approval_secret = parse_cmdline_secret(&cmdline, "nucleus.approval_secret")
        .or_else(|| read_secret("/etc/nucleus/approval.secret"))
        .ok_or_else(|| "missing approval secret (set nucleus.approval_secret in boot args or /etc/nucleus/approval.secret)".to_string())?;

    std::env::set_var("NUCLEUS_TOOL_PROXY_AUTH_SECRET", auth_secret);
    std::env::set_var("NUCLEUS_TOOL_PROXY_APPROVAL_SECRET", approval_secret);

    // Sandbox token is optional — Tier 3 fallback when SVID doesn't carry
    // an attestation OID. If absent, tool-proxy uses Tier 1 or Tier 2 proof.
    if let Some(sandbox_token) = parse_cmdline_secret(&cmdline, "nucleus.sandbox_token")
        .or_else(|| read_secret("/etc/nucleus/sandbox.token"))
    {
        std::env::set_var("NUCLEUS_SANDBOX_TOKEN", sandbox_token);
    }

    let audit_path = resolve_audit_path();
    std::env::set_var("NUCLEUS_TOOL_PROXY_AUDIT_LOG", audit_path.clone());
    std::env::set_var("NUCLEUS_TOOL_PROXY_BOOT_ACTOR", "guest-init");
    if let Some(report) = build_boot_report(&spec_path, net_config.as_ref(), &audit_path) {
        std::env::set_var("NUCLEUS_TOOL_PROXY_BOOT_REPORT", report);
    }

    remount_root_ro();

    exec_proxy(&spec_path);
    Ok(())
}

fn ensure_dir(path: &str) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|err| format!("create {path}: {err}"))
}

fn mount_fs(source: &str, target: &str, fstype: &str, flags: MsFlags, data: Option<&str>) {
    #[cfg(target_os = "linux")]
    {
        let data_bytes = data.map(|value| value.as_bytes());
        if let Err(err) = mount(Some(source), target, Some(fstype), flags, data_bytes) {
            eprintln!("mount {source} -> {target} ({fstype}) failed: {err}");
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (source, target, fstype, flags, data);
    }
}

fn remount_root_ro() {
    #[cfg(target_os = "linux")]
    {
        if let Err(err) = mount::<str, str, str, str>(
            None,
            "/",
            None,
            MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None,
        ) {
            eprintln!("remount / ro failed: {err}");
        }
    }
}

fn resolve_pod_spec() -> Result<String, String> {
    if Path::new(POD_SPEC_PATH).exists() {
        return Ok(POD_SPEC_PATH.to_string());
    }

    if Path::new(FALLBACK_POD_SPEC).exists() {
        if fs::copy(FALLBACK_POD_SPEC, POD_SPEC_PATH).is_ok() {
            return Ok(POD_SPEC_PATH.to_string());
        }
        return Ok(FALLBACK_POD_SPEC.to_string());
    }

    eprintln!("missing pod spec (expected {POD_SPEC_PATH} or {FALLBACK_POD_SPEC})");
    let _ = Command::new("/bin/sh").status();
    Err("pod spec missing".to_string())
}

fn read_secret(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn resolve_audit_path() -> String {
    if let Some(path) = read_secret("/etc/nucleus/audit.path") {
        return path;
    }
    if is_writable("/work") {
        let _ = fs::create_dir_all("/work/audit");
        return "/work/audit/nucleus-audit.log".to_string();
    }
    "/tmp/nucleus-audit.log".to_string()
}

fn build_boot_report(
    spec_path: &str,
    net_config: Option<&NetConfig>,
    audit_path: &str,
) -> Option<String> {
    let net_addr = net_config.map(|cfg| cfg.addr.as_str()).unwrap_or("");
    let net_gw = net_config
        .and_then(|cfg| cfg.gw)
        .map(|v| v.to_string())
        .unwrap_or_default();
    let net_dns = net_config
        .and_then(|cfg| cfg.dns)
        .map(|v| v.to_string())
        .unwrap_or_default();
    let auth_secret = Path::new("/etc/nucleus/auth.secret").exists();
    let approval_secret = Path::new("/etc/nucleus/approval.secret").exists();
    let sandbox_token = Path::new("/etc/nucleus/sandbox.token").exists();

    Some(format!(
        "{{\"spec_path\":\"{spec_path}\",\"net_addr\":\"{net_addr}\",\"net_gw\":\"{net_gw}\",\"net_dns\":\"{net_dns}\",\"audit_path\":\"{audit_path}\",\"auth_secret\":{auth_secret},\"approval_secret\":{approval_secret},\"sandbox_token\":{sandbox_token}}}"
    ))
}

fn is_writable(dir: &str) -> bool {
    let test_path = Path::new(dir).join(".nucleus_write_test");
    if fs::write(&test_path, b"test").is_ok() {
        let _ = fs::remove_file(test_path);
        return true;
    }
    false
}

fn exec_proxy(spec_path: &str) {
    let err = Command::new(PROXY_BIN).arg("--spec").arg(spec_path).exec();
    eprintln!("failed to exec {PROXY_BIN}: {err}");
}

#[derive(Debug)]
struct NetConfig {
    addr: String,
    gw: Option<Ipv4Addr>,
    dns: Option<Ipv4Addr>,
}

fn parse_net_config(cmdline_path: &str) -> Option<NetConfig> {
    let cmdline = fs::read_to_string(cmdline_path).ok()?;
    for token in cmdline.split_whitespace() {
        if let Some(value) = token.strip_prefix("nucleus.net=") {
            return parse_net_value(value);
        }
    }
    None
}

fn parse_net_value(value: &str) -> Option<NetConfig> {
    let mut parts = value.split(',');
    let addr = parts.next()?.trim();
    if !is_addr_cidr(addr) {
        return None;
    }
    let mut gw = None;
    let mut dns = None;
    for part in parts {
        if let Some(val) = part.strip_prefix("gw=") {
            gw = val.parse::<Ipv4Addr>().ok();
        } else if let Some(val) = part.strip_prefix("dns=") {
            dns = val.parse::<Ipv4Addr>().ok();
        }
    }
    Some(NetConfig {
        addr: addr.to_string(),
        gw,
        dns,
    })
}

fn is_addr_cidr(value: &str) -> bool {
    let mut parts = value.split('/');
    let ip = parts.next().unwrap_or("");
    let cidr = parts.next().unwrap_or("");
    ip.parse::<Ipv4Addr>().is_ok() && cidr.parse::<u8>().is_ok()
}

fn configure_network(config: &NetConfig) {
    if !command_exists("ip") {
        eprintln!("ip not found; skipping network config");
        return;
    }

    let _ = Command::new("ip")
        .args(["link", "set", "eth0", "up"])
        .status();
    let _ = Command::new("ip")
        .args(["addr", "add", &config.addr, "dev", "eth0"])
        .status();
    if let Some(gw) = config.gw {
        let _ = Command::new("ip")
            .args(["route", "add", "default", "via", &gw.to_string()])
            .status();
    }
    if let Some(dns) = config.dns {
        let _ = fs::write("/etc/resolv.conf", format!("nameserver {dns}\n"));
    }
}

fn command_exists(name: &str) -> bool {
    let mut cmd = Command::new(name);
    if name == "ip" {
        cmd.arg("-V");
    } else {
        cmd.arg("--version");
    }
    cmd.output().is_ok()
}

/// Parse a secret from kernel command line (format: key=value)
fn parse_cmdline_secret(cmdline: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    for token in cmdline.split_whitespace() {
        if let Some(value) = token.strip_prefix(&prefix) {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sandbox_token_from_cmdline() {
        let cmdline = "console=ttyS0 reboot=k nucleus.auth_secret=auth123 nucleus.approval_secret=appr456 nucleus.sandbox_token=sbx789";
        assert_eq!(
            parse_cmdline_secret(cmdline, "nucleus.sandbox_token"),
            Some("sbx789".to_string())
        );
    }

    #[test]
    fn parse_sandbox_token_missing() {
        let cmdline = "console=ttyS0 nucleus.auth_secret=auth123";
        assert_eq!(parse_cmdline_secret(cmdline, "nucleus.sandbox_token"), None);
    }

    #[test]
    fn parse_sandbox_token_empty_value() {
        let cmdline = "nucleus.sandbox_token=";
        assert_eq!(parse_cmdline_secret(cmdline, "nucleus.sandbox_token"), None);
    }
}
