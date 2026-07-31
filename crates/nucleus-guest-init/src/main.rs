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
    const MS_NOEXEC: MsFlags = MsFlags;
    const MS_NODEV: MsFlags = MsFlags;
    const MS_REMOUNT: MsFlags = MsFlags;
    const MS_RDONLY: MsFlags = MsFlags;
    fn empty() -> MsFlags {
        MsFlags
    }
}

#[cfg(not(target_os = "linux"))]
impl std::ops::BitOrAssign for MsFlags {
    fn bitor_assign(&mut self, _rhs: MsFlags) {}
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

    for m in GUEST_MOUNTS {
        mount_fs(m.source, m.target, m.fstype, m.ms_flags(), None);
    }

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
    let workload_api_port = identity::parse_workload_api_port(&cmdline);
    if let Some(port) = workload_api_port {
        match identity::fetch_identity(port) {
            Ok(spiffe_id) => {
                eprintln!("fetched identity: {spiffe_id}");
                // POINT THE PROXY AT WHAT WE JUST FETCHED.
                //
                // Without this the fetch is decorative: `fetch_identity` writes
                // the SVID to /etc/nucleus/identity, and the tool-proxy looks
                // for `--identity-cert` / `NUCLEUS_IDENTITY_CERT`, which nobody
                // set — so the cert existed on disk and Tier 1/2 still reported
                // "no identity cert" and the guest died as a naked process.
                //
                // Observed on real hardware once the workload API bridge started
                // early enough for the fetch to SUCCEED. Before that the fetch
                // always failed, so this gap was invisible: the pod died one
                // step earlier for a different reason.
                std::env::set_var("NUCLEUS_IDENTITY_CERT", identity::svid_cert_path());
            }
            Err(err) => {
                eprintln!("failed to fetch identity: {err}");
                // Continue without identity - not fatal for now
            }
        }
    }

    // Session capability token, preferred over the kernel command line.
    //
    // Fetching it here rather than reading `nucleus.task_token_hex` is what lets
    // the command-line copy go, and the command line is what blocks a snapshot
    // base: per-pod material baked into a boot artifact is inherited by every
    // clone restored from it. The token is not a secret — a scoped capability
    // plus a public issuer key — so this is about uniqueness surviving a
    // restore, not confidentiality.
    //
    // Synchronous, and before `exec_proxy`, so the values are in the environment
    // before anything reads them.
    let mut token_from_vsock = false;
    if let Some(port) = workload_api_port {
        match identity::fetch_task_token(port) {
            Ok(t) => {
                std::env::set_var("NUCLEUS_TASK_TOKEN", &t.token);
                std::env::set_var("NUCLEUS_TASK_TOKEN_NONCE", &t.nonce);
                std::env::set_var("NUCLEUS_TASK_TOKEN_ISSUER", &t.issuer);
                token_from_vsock = true;
                eprintln!("fetched session task token over vsock");
            }
            Err(err) => {
                // Not fatal, and deliberately so: the command-line path below is
                // still in place, so a node that has not been updated still
                // works. When the cmdline copy is removed this must become the
                // only source, and THEN a failure here should be fatal — the
                // tool-proxy would otherwise start with no token and fail closed
                // later, far from the cause.
                eprintln!("failed to fetch session task token over vsock: {err}");
            }
        }
    }

    // OPTIONAL. On the Firecracker path the tool-proxy is bound to a vsock
    // listener that accepts only the host (`pod_mgmt::peer_is_host`), and the
    // guest kernel — not the caller — sets the peer CID. The HMAC tier is
    // unreachable there, so requiring a key would put a world-readable secret
    // on /proc/cmdline for nothing. `enforce_hmac_key_quality` in the proxy
    // still refuses an empty key on every transport that can reach that tier.
    let auth_secret = parse_cmdline_secret(&cmdline, "nucleus.auth_secret")
        .or_else(|| read_secret("/etc/nucleus/auth.secret"));

    let approval_secret = parse_cmdline_secret(&cmdline, "nucleus.approval_secret")
        .or_else(|| read_secret("/etc/nucleus/approval.secret"))
        .ok_or_else(|| "missing approval secret (set nucleus.approval_secret in boot args or /etc/nucleus/approval.secret)".to_string())?;

    if let Some(auth_secret) = auth_secret {
        std::env::set_var("NUCLEUS_TOOL_PROXY_AUTH_SECRET", auth_secret);
    }
    std::env::set_var("NUCLEUS_TOOL_PROXY_APPROVAL_SECRET", approval_secret);

    // Sandbox token is optional — Tier 3 fallback when SVID doesn't carry
    // an attestation OID. If absent, tool-proxy uses Tier 1 or Tier 2 proof.
    // DLC-D verified-admission provisioning → the in-VM tool-proxy, over the
    // workload API like the task token (the cmdline lacks the capacity for a
    // credential set, and per-pod material must not bake into snapshot bases).
    // Unprovisioned is the ordinary case and stays quiet; the proxy is inert
    // without these.
    if let Some(port) = workload_api_port {
        match identity::fetch_dlc_admission(port) {
            Ok(Some(m)) => {
                std::env::set_var("NUCLEUS_DLC_TRUSTED_KEYS", &m.trusted_keys);
                std::env::set_var("NUCLEUS_DLC_ISSUER", &m.issuer);
                std::env::set_var("NUCLEUS_DLC_CREDENTIALS", &m.credentials);
                eprintln!("fetched DLC admission provisioning over the workload API");
            }
            Ok(None) => {}
            Err(err) => eprintln!("failed to fetch DLC admission provisioning: {err}"),
        }
    }

    if let Some(sandbox_token) = parse_cmdline_secret(&cmdline, "nucleus.sandbox_token")
        .or_else(|| read_secret("/etc/nucleus/sandbox.token"))
    {
        std::env::set_var("NUCLEUS_SANDBOX_TOKEN", sandbox_token);
    }

    // Live-path session capability token (optional). The node injects it on the
    // kernel cmdline as `nucleus.task_token_hex` (hex of the token JSON — the
    // cmdline is whitespace-delimited and quote-sensitive, so raw JSON is unsafe)
    // plus hex nonce/issuer. We decode the token back to the exact JSON string
    // the tool-proxy verify half expects and forward all three as env vars. If
    // the token is absent or the hex is malformed we simply do not set them —
    // the tool-proxy then records Missing/Invalid and fails closed.
    let cmdline_token = if token_from_vsock {
        None
    } else {
        parse_cmdline_secret(&cmdline, "nucleus.task_token_hex")
    };
    if let Some(token_hex) = cmdline_token {
        match hex::decode(&token_hex)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
        {
            Some(token_json) => {
                std::env::set_var("NUCLEUS_TASK_TOKEN", token_json);
                if let Some(nonce) = parse_cmdline_secret(&cmdline, "nucleus.task_token_nonce") {
                    std::env::set_var("NUCLEUS_TASK_TOKEN_NONCE", nonce);
                }
                if let Some(issuer) = parse_cmdline_secret(&cmdline, "nucleus.task_token_issuer") {
                    std::env::set_var("NUCLEUS_TASK_TOKEN_ISSUER", issuer);
                }
            }
            None => {
                eprintln!(
                    "nucleus-guest-init: nucleus.task_token_hex is not valid hex/UTF-8; \
                     skipping session token (tool-proxy will fail closed)"
                );
            }
        }
    }

    // S3 audit sink config (optional, passed via kernel args from nucleus-node)
    for (arg, env_var) in [
        (
            "nucleus.audit_s3_bucket",
            "NUCLEUS_TOOL_PROXY_AUDIT_S3_BUCKET",
        ),
        (
            "nucleus.audit_s3_prefix",
            "NUCLEUS_TOOL_PROXY_AUDIT_S3_PREFIX",
        ),
        (
            "nucleus.audit_s3_region",
            "NUCLEUS_TOOL_PROXY_AUDIT_S3_REGION",
        ),
        (
            "nucleus.audit_s3_endpoint",
            "NUCLEUS_TOOL_PROXY_AUDIT_S3_ENDPOINT",
        ),
    ] {
        if let Some(val) = parse_cmdline_secret(&cmdline, arg) {
            std::env::set_var(env_var, val);
        }
    }

    // AWS credentials for S3 audit sink (optional)
    for (arg, env_var) in [
        ("nucleus.aws_access_key_id", "AWS_ACCESS_KEY_ID"),
        ("nucleus.aws_secret_access_key", "AWS_SECRET_ACCESS_KEY"),
        ("nucleus.aws_session_token", "AWS_SESSION_TOKEN"),
        ("nucleus.aws_default_region", "AWS_DEFAULT_REGION"),
    ] {
        if let Some(val) = parse_cmdline_secret(&cmdline, arg) {
            std::env::set_var(env_var, val);
        }
    }

    let audit_path = resolve_audit_path();
    std::env::set_var("NUCLEUS_TOOL_PROXY_AUDIT_LOG", audit_path.clone());
    std::env::set_var("NUCLEUS_TOOL_PROXY_BOOT_ACTOR", "guest-init");
    if let Some(report) = build_boot_report(&spec_path, net_config.as_ref(), &audit_path) {
        std::env::set_var("NUCLEUS_TOOL_PROXY_BOOT_REPORT", report);
    }

    remount_root_ro()?;

    exec_proxy(&spec_path);
    Ok(())
}

/// One guest mount, with its hardening flags as PLAIN BOOLS.
///
/// Bools rather than `MsFlags` so the table is inspectable on any host — the
/// same reason `firecracker_config`'s lowering seams are not gated behind
/// `target_os = "linux"`. A hardening table that can only be read on the machine
/// it runs on is a hardening table nobody checks.
pub(crate) struct GuestMount {
    pub source: &'static str,
    pub target: &'static str,
    pub fstype: &'static str,
    /// SUID/SGID bits are not honoured — blocks a dropped setuid binary.
    pub nosuid: bool,
    /// Device nodes cannot be created — blocks a crafted /dev/mem or /dev/sda.
    pub nodev: bool,
    /// Binaries cannot be executed from here.
    pub noexec: bool,
}

impl GuestMount {
    fn ms_flags(&self) -> MsFlags {
        let mut f = MsFlags::empty();
        if self.nosuid {
            f |= MsFlags::MS_NOSUID;
        }
        if self.nodev {
            f |= MsFlags::MS_NODEV;
        }
        if self.noexec {
            f |= MsFlags::MS_NOEXEC;
        }
        f
    }
}

/// The guest's pseudo-filesystem mounts, hardened.
///
/// Every one of these was mounted with `MsFlags::empty()` — no nosuid, no
/// nodev, no noexec — while `/work`, the data volume mounted a few lines below,
/// already carried `MS_NOSUID | MS_NODEV`. The pattern was known and the
/// pseudo-filesystems simply missed it.
///
/// Standard practice for microVMs is a read-only rootfs with writable layers
/// marked noexec/nodev/nosuid. `/tmp` and `/run` are the writable tmpfs layers
/// and the classic staging ground for a dropped payload; `/proc` and `/sys`
/// have no business carrying setuid bits, device nodes or executables.
///
/// `/dev` keeps `nodev = false` for the obvious reason — it IS the device tree —
/// and keeps `noexec = false` deliberately rather than by omission: tightening a
/// mount the guest boots from, with no end-to-end test available here, risks the
/// mount failing and `mount_fs` continuing without it, which would be a worse
/// outcome than the flag's absence.
pub(crate) const GUEST_MOUNTS: &[GuestMount] = &[
    GuestMount {
        source: "proc",
        target: "/proc",
        fstype: "proc",
        nosuid: true,
        nodev: true,
        noexec: true,
    },
    GuestMount {
        source: "sys",
        target: "/sys",
        fstype: "sysfs",
        nosuid: true,
        nodev: true,
        noexec: true,
    },
    GuestMount {
        source: "dev",
        target: "/dev",
        fstype: "devtmpfs",
        nosuid: true,
        nodev: false,
        noexec: false,
    },
    GuestMount {
        source: "tmpfs",
        target: "/tmp",
        fstype: "tmpfs",
        nosuid: true,
        nodev: true,
        noexec: true,
    },
    GuestMount {
        source: "tmpfs",
        target: "/run",
        fstype: "tmpfs",
        nosuid: true,
        nodev: true,
        noexec: true,
    },
];

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

/// Remount the guest root read-only, and FAIL THE BOOT if it does not take.
///
/// This logged the failure and carried on, so a guest whose rootfs did not go
/// read-only booted anyway — silently losing the read-only-rootfs posture that
/// the whole image is built around, with nothing above it any the wiser.
///
/// The repo already states the rule for the analogous case one layer up, in
/// nucleus-node's seccomp verification: "a process whose seccomp filter cannot
/// be confirmed active is killed and the launch is aborted rather than left
/// running unconfined. The previous behavior only logged a warning and continued
/// (fail-open)." The same applies here. The Linux kernel itself panics rather
/// than continue when it cannot mount root.
///
/// Returning `Result` rather than panicking so the caller aborts BEFORE
/// `exec_proxy` — a controlled refusal with a legible message, not a panic
/// midway through boot.
fn remount_root_ro() -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        mount::<str, str, str, str>(
            None,
            "/",
            None,
            MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
            None,
        )
        .map_err(|err| {
            format!(
                "remount / read-only failed: {err} — refusing to start the \
                     workload rather than run it on a writable rootfs"
            )
        })?;
    }
    Ok(())
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

    /// **Every guest pseudo-filesystem is hardened, and `/tmp` and `/run`
    /// especially.**
    ///
    /// All five were mounted with `MsFlags::empty()` while `/work`, the data
    /// volume a few lines below, already carried `MS_NOSUID | MS_NODEV`. The
    /// pattern was known; the pseudo-filesystems missed it.
    ///
    /// Standard microVM practice is a read-only rootfs with writable layers
    /// marked nosuid/nodev/noexec. `/tmp` and `/run` are those writable layers
    /// and the classic staging ground for a dropped payload.
    ///
    /// Runs on any host because the table stores plain bools rather than
    /// `MsFlags` — a hardening table readable only on the machine it runs on is
    /// one nobody checks.
    #[test]
    fn guest_mounts_are_hardened() {
        for m in super::GUEST_MOUNTS {
            assert!(
                m.nosuid,
                "{} must be nosuid — a setuid binary dropped there is a \
                 privilege-escalation primitive",
                m.target
            );
        }

        for target in ["/tmp", "/run"] {
            let m = super::GUEST_MOUNTS
                .iter()
                .find(|m| m.target == target)
                .unwrap_or_else(|| panic!("{target} must be in the mount table"));
            assert!(
                m.nodev && m.noexec,
                "{target} is writable: needs nodev + noexec"
            );
        }

        // /dev is the device tree, so nodev would defeat its purpose. Asserted
        // rather than left implicit, so flipping it reads as a deliberate change.
        let dev = super::GUEST_MOUNTS
            .iter()
            .find(|m| m.target == "/dev")
            .unwrap();
        assert!(
            !dev.nodev,
            "/dev must permit device nodes — it is the device tree"
        );
    }

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

    /// The live-path token rides the cmdline hex-encoded; decoding it back must
    /// reproduce the EXACT JSON string the tool-proxy verify half parses. JSON
    /// contains `{`, `"`, `:`, `,` — all cmdline-hostile — which is why it is
    /// hex-wrapped; this asserts the wrapper round-trips losslessly and that the
    /// hex token is a single whitespace-delimited cmdline argument.
    #[test]
    fn task_token_hex_roundtrips_to_exact_json() {
        let token_json = r#"{"task_id":"pod-1","blocks":[{"claim":{"nonce":[1,2,3]}}]}"#;
        let token_hex = hex::encode(token_json.as_bytes());
        let nonce_hex = hex::encode([7u8; 16]);
        let issuer_hex = hex::encode([9u8; 32]);
        let cmdline = format!(
            "console=ttyS0 nucleus.auth_secret=a nucleus.task_token_hex={token_hex} \
             nucleus.task_token_nonce={nonce_hex} nucleus.task_token_issuer={issuer_hex}"
        );

        let parsed_hex = parse_cmdline_secret(&cmdline, "nucleus.task_token_hex")
            .expect("hex token must parse as a single cmdline arg");
        let decoded = String::from_utf8(hex::decode(&parsed_hex).unwrap()).unwrap();
        assert_eq!(
            decoded, token_json,
            "hex must decode back to the exact JSON"
        );

        assert_eq!(
            parse_cmdline_secret(&cmdline, "nucleus.task_token_nonce"),
            Some(nonce_hex)
        );
        assert_eq!(
            parse_cmdline_secret(&cmdline, "nucleus.task_token_issuer"),
            Some(issuer_hex)
        );
    }
}
