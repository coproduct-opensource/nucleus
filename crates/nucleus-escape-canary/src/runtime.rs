//! Effectful probes. Never run on a host: successful probes can mount a
//! filesystem or attach to PID 1. The runner destroys the disposable guest.
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

use nix::mount::{MsFlags, mount, umount};
use nix::sys::socket::{self, AddressFamily, SockFlag, SockProtocol, SockType};
use nix::sys::stat::{Mode, SFlag, makedev, mknod};
use nix::sys::time::{TimeVal, TimeValLike};
use nucleus_escape_canary::{
    Attempt, Verdict, base_write_denied, exit_code, host_secret_unreadable, noexec_denied,
    permission_denied, svid_channel_failure, svid_reply,
};
use serde::Serialize;

const TIMEOUT: Duration = Duration::from_secs(5);
const DNS_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REPLY: u64 = 1024 * 1024;

#[derive(Clone, Copy)]
enum Probe {
    TcpPublic,
    TcpDns,
    UdpDns,
    DnsResolve,
    Metadata,
    WriteEtc,
    WriteBin,
    WriteHostBuild,
    HostSecrets,
    Cmdline,
    InitEnviron,
    ExecTmp,
    ExecRun,
    Mount,
    RawSocket,
    Device,
    ForeignProcesses,
    PtraceInit,
    Svid,
}
impl Probe {
    const ALL: &[Self] = &[
        Self::TcpPublic,
        Self::TcpDns,
        Self::UdpDns,
        Self::DnsResolve,
        Self::Metadata,
        Self::WriteEtc,
        Self::WriteBin,
        Self::WriteHostBuild,
        Self::HostSecrets,
        Self::Cmdline,
        Self::InitEnviron,
        Self::ExecTmp,
        Self::ExecRun,
        Self::Mount,
        Self::RawSocket,
        Self::Device,
        Self::ForeignProcesses,
        Self::PtraceInit,
        Self::Svid,
    ];
    fn name(self) -> &'static str {
        match self {
            Self::TcpPublic => "net_tcp_public",
            Self::TcpDns => "net_tcp_dns_public",
            Self::UdpDns => "net_udp_dns_public",
            Self::DnsResolve => "net_dns_resolve",
            Self::Metadata => "net_node_metadata",
            Self::WriteEtc => "write_rootfs_etc",
            Self::WriteBin => "write_rootfs_bin",
            Self::WriteHostBuild => "write_host_build_dir",
            Self::HostSecrets => "read_host_node_state",
            Self::Cmdline => "read_proc_cmdline",
            Self::InitEnviron => "read_init_environ",
            Self::ExecTmp => "exec_noexec_tmp",
            Self::ExecRun => "exec_noexec_run",
            Self::Mount => "priv_mount",
            Self::RawSocket => "priv_raw_socket",
            Self::Device => "priv_mknod_device",
            Self::ForeignProcesses => "proc_foreign_visibility",
            Self::PtraceInit => "proc_ptrace_init",
            Self::Svid => "svid_key_later_fetch",
        }
    }
    fn observe(self) -> Verdict {
        match self {
            Self::TcpPublic => tcp(SocketAddr::from(([1, 1, 1, 1], 443))),
            Self::TcpDns => tcp(SocketAddr::from(([8, 8, 8, 8], 53))),
            Self::Metadata => tcp(SocketAddr::from(([169, 254, 169, 254], 80))),
            Self::UdpDns => udp(),
            Self::DnsResolve => dns(),
            Self::WriteEtc => readonly("/etc"),
            Self::WriteBin => readonly("/usr/local/bin"),
            Self::WriteHostBuild => readonly("/opt/nucleus-build"),
            Self::HostSecrets => host_secrets(),
            Self::Cmdline => secret_markers(SecretSurface::KernelCommandLine),
            Self::InitEnviron => secret_markers(SecretSurface::InitEnvironment),
            Self::ExecTmp => noexec("/tmp"),
            Self::ExecRun => noexec("/run"),
            Self::Mount => mount_probe(),
            Self::RawSocket => raw_socket(),
            Self::Device => device(),
            Self::ForeignProcesses => processes(),
            Self::PtraceInit => ptrace(),
            Self::Svid => identity(),
        }
    }
}

fn attempt<T>(result: &io::Result<T>) -> Attempt {
    match result {
        Ok(_) => Attempt::Succeeded,
        Err(e) => e
            .raw_os_error()
            .map_or(Attempt::ErrorWithoutErrno, Attempt::Failed),
    }
}
fn nix_attempt<T>(result: &nix::Result<T>) -> Attempt {
    match result {
        Ok(_) => Attempt::Succeeded,
        Err(e) => Attempt::Failed(*e as i32),
    }
}

// Topology is inspected by the same thread before and after the real probe.
// No extra network namespace is created for the canary.
fn network(probe: impl FnOnce() -> io::Result<()>) -> Verdict {
    use nucleus_escape_canary::network::{Connectivity, observe};
    observe(|| match probe() {
        Ok(()) => Connectivity::Reached,
        Err(e) => Connectivity::from_linux_errno(e.raw_os_error()),
    })
}
fn tcp(addr: SocketAddr) -> Verdict {
    network(|| TcpStream::connect_timeout(&addr, TIMEOUT).map(drop))
}
fn udp() -> Verdict {
    network(|| {
        let sock = UdpSocket::bind("0.0.0.0:0")?;
        sock.set_read_timeout(Some(TIMEOUT))?;
        sock.set_write_timeout(Some(TIMEOUT))?;
        let query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
        sock.connect("8.8.8.8:53")?;
        sock.send(query)?;
        let mut reply = [0; 512];
        sock.recv(&mut reply).map(|_| ())
    })
}
fn dns() -> Verdict {
    use nucleus_escape_canary::network::{Connectivity, observe};
    observe(|| {
        let (send, receive) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let result = ("example.com", 443)
                .to_socket_addrs()
                .map(|mut addresses| addresses.next().is_some());
            let _ = send.send(result);
        });
        match receive.recv_timeout(DNS_TIMEOUT) {
            Ok(Ok(true)) => Connectivity::Reached,
            Ok(Ok(false) | Err(_)) => Connectivity::NotReached,
            Err(_) => Connectivity::CouldNotRun,
        }
    })
}
fn readonly(dir: &str) -> Verdict {
    // tempfile wraps creation errors with a path and discards raw_os_error.
    // Use it only to reserve a random name; measure create_new directly so the
    // actual EROFS/EACCES survives. Never remove a path when creation failed.
    let Ok(nonce) = tempfile::tempdir_in("/tmp") else {
        return Verdict::CouldNotLook("cannot reserve a unique write-probe name");
    };
    let Some(name) = nonce.path().file_name() else {
        return Verdict::CouldNotLook("write-probe name is missing");
    };
    let path = Path::new(dir).join(name);
    let result = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path);
    let verdict = base_write_denied(attempt(&result));
    if result.is_ok() {
        let _ = fs::remove_file(&path);
    }
    verdict
}
fn host_secrets() -> Verdict {
    let mut results = Vec::new();
    for path in [
        "/srv/gatehouse/runtime/state/executor_signing_key.der",
        "/srv/gatehouse/runtime/state/ca/ca-key.pem",
        "/srv/gatehouse/runtime/node.env",
        "/persist/gatehouse/runtime/state/executor_signing_key.der",
        "/root/.config/gcloud/credentials.db",
        "/var/lib/nucleus/state",
    ] {
        let result = File::open(path).and_then(|mut f| f.read(&mut [0; 1]));
        results.push(host_secret_unreadable(attempt(&result)));
    }
    aggregate(&results)
}
fn aggregate(results: &[Verdict]) -> Verdict {
    match exit_code(results) {
        0 => Verdict::Refused,
        1 => Verdict::Breach,
        _ => Verdict::CouldNotLook("one or more observations were incomplete"),
    }
}
enum SecretSurface {
    KernelCommandLine,
    InitEnvironment,
}
fn secret_markers(surface: SecretSurface) -> Verdict {
    let path = match surface {
        SecretSurface::KernelCommandLine => "/proc/cmdline",
        SecretSurface::InitEnvironment => "/proc/1/environ",
    };
    let result = File::open(path).and_then(|f| {
        let mut bytes = Vec::new();
        f.take(MAX_REPLY + 1).read_to_end(&mut bytes)?;
        Ok(bytes)
    });
    match result {
        Err(e) => match surface {
            // hidepid=invisible intentionally makes another uid's PID 1 absent.
            SecretSurface::InitEnvironment => host_secret_unreadable(attempt::<()>(&Err(e))),
            SecretSurface::KernelCommandLine => permission_denied(attempt::<()>(&Err(e))),
        },
        Ok(bytes) if bytes.len() as u64 > MAX_REPLY => {
            Verdict::CouldNotLook("credential surface exceeds read bound")
        }
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes);
            if [
                "AUTH_SECRET",
                "APPROVAL_SECRET",
                "SANDBOX_TOKEN",
                "BROKER_SECRET",
                "MEDIATION",
                "SIGNING_KEY",
                "PRIVATE_KEY",
                "APP_KEY",
                "TASK_TOKEN",
                "CALLER_TOKEN",
                "auth_secret",
                "approval_secret",
            ]
            .iter()
            .any(|marker| text.contains(marker))
            {
                Verdict::Breach
            } else {
                Verdict::Refused
            }
        }
    }
}
fn noexec(directory: &str) -> Verdict {
    let Ok(dir) = tempfile::tempdir_in(directory) else {
        return Verdict::CouldNotLook("cannot stage executable");
    };
    let path = dir.path().join("probe");
    if fs::write(&path, b"#!/bin/sh\nexit 0\n")
        .and_then(|()| fs::set_permissions(&path, fs::Permissions::from_mode(0o700)))
        .is_err()
    {
        return Verdict::CouldNotLook("cannot stage executable");
    }
    noexec_denied(attempt(&std::process::Command::new(&path).status()))
}
fn mount_probe() -> Verdict {
    let Ok(dir) = tempfile::tempdir_in("/tmp") else {
        return Verdict::CouldNotLook("cannot stage mount target");
    };
    let result = mount(
        Some("none"),
        dir.path(),
        Some("tmpfs"),
        MsFlags::empty(),
        None::<&str>,
    );
    let verdict = permission_denied(nix_attempt(&result));
    if result.is_ok() {
        let _ = umount(dir.path());
    }
    verdict
}
fn raw_socket() -> Verdict {
    permission_denied(nix_attempt(&socket::socket(
        AddressFamily::Inet,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        SockProtocol::Icmp,
    )))
}
fn device() -> Verdict {
    let Ok(dir) = tempfile::tempdir_in("/tmp") else {
        return Verdict::CouldNotLook("cannot stage device path");
    };
    // Successful creation violates the declared CAP_MKNOD property regardless
    // of whether this particular device number can subsequently be read.
    permission_denied(nix_attempt(&mknod(
        &dir.path().join("device"),
        SFlag::S_IFBLK,
        Mode::S_IRUSR,
        makedev(253, 0),
    )))
}
fn processes() -> Verdict {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Verdict::CouldNotLook("cannot enumerate procfs");
    };
    let mut seen = false;
    for entry in entries {
        let Ok(entry) = entry else {
            return Verdict::CouldNotLook("procfs enumeration failed");
        };
        let name = entry.file_name();
        if !name.to_string_lossy().chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        match fs::read_to_string(entry.path().join("comm")) {
            Ok(comm) => {
                seen = true;
                if [
                    "nucleus-node",
                    "firecracker",
                    "jailer",
                    "gatehouse-agent",
                    "gatehouse-nucleus",
                    "controller",
                    "containerd",
                    "dockerd",
                    "sshd",
                ]
                .iter()
                .any(|name| comm.contains(name))
                {
                    return Verdict::Breach;
                }
            }
            Err(e) if matches!(e.raw_os_error(), Some(2 | 13 | 1)) => {}
            Err(_) => return Verdict::CouldNotLook("cannot inspect a process"),
        }
    }
    if seen {
        Verdict::Refused
    } else {
        Verdict::CouldNotLook("no process could be inspected")
    }
}
fn ptrace() -> Verdict {
    let pid = nix::unistd::Pid::from_raw(1);
    let result = nix::sys::ptrace::attach(pid);
    let verdict = permission_denied(nix_attempt(&result));
    if result.is_ok() {
        let _ = nix::sys::wait::waitpid(pid, None);
        let _ = nix::sys::ptrace::detach(pid, None);
    }
    verdict
}
enum IdentityObservation {
    Reply(Vec<u8>),
    ChannelDenied,
}

fn fetch_svid() -> io::Result<IdentityObservation> {
    let fd = match socket::socket(
        AddressFamily::Vsock,
        SockType::Stream,
        SockFlag::SOCK_CLOEXEC,
        None,
    ) {
        Ok(fd) => fd,
        Err(e) if svid_channel_failure(Some(e as i32)) == Verdict::Refused => {
            return Ok(IdentityObservation::ChannelDenied);
        }
        Err(e) => return Err(e.into()),
    };
    let timeout = TimeVal::seconds(8);
    socket::setsockopt(&fd, socket::sockopt::ReceiveTimeout, &timeout)?;
    socket::setsockopt(&fd, socket::sockopt::SendTimeout, &timeout)?;
    if let Err(e) = socket::connect(fd.as_raw_fd(), &socket::VsockAddr::new(2, 15012)) {
        if svid_channel_failure(Some(e as i32)) == Verdict::Refused {
            return Ok(IdentityObservation::ChannelDenied);
        }
        return Err(e.into());
    }
    let mut file = File::from(fd);
    file.write_all(b"FETCH_SVID\n")?;
    let mut reader = BufReader::new(file.take(MAX_REPLY + 1));
    let mut bytes = Vec::new();
    reader.read_until(b'\n', &mut bytes)?;
    if bytes.len() as u64 > MAX_REPLY || bytes.last() != Some(&b'\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "incomplete or oversized SVID frame",
        ));
    }
    Ok(IdentityObservation::Reply(bytes))
}
fn identity() -> Verdict {
    let mut results = Vec::new();
    for _ in 0..2 {
        results.push(match fetch_svid() {
            Ok(IdentityObservation::Reply(bytes)) => svid_reply(&bytes),
            Ok(IdentityObservation::ChannelDenied) => {
                // This measures channel denial, not the one-shot key latch.
                eprintln!("SVID evidence: kernel denied opening the workload identity channel");
                Verdict::Refused
            }
            Err(_) => Verdict::CouldNotLook("cannot complete SVID fetch"),
        });
    }
    aggregate(&results)
}
#[derive(Serialize)]
struct Record {
    probe: &'static str,
    #[serde(flatten)]
    verdict: Verdict,
}

pub(super) fn run() -> u8 {
    // Marker check guards against accidentally invoking this on an ordinary
    // host. It is not a security proof and does not turn any probe green.
    let guest = fs::read_to_string("/proc/cmdline").is_ok_and(|s| s.contains("nucleus."));
    if !guest || !Path::new("/proc/self").exists() {
        eprintln!("could-not-look: no nucleus guest boot marker");
        return 2;
    }
    let mut verdicts = Vec::new();
    for probe in Probe::ALL {
        let verdict = probe.observe();
        let record = Record {
            probe: probe.name(),
            verdict: verdict.clone(),
        };
        if serde_json::to_writer(io::stdout().lock(), &record).is_err()
            || writeln!(io::stdout()).is_err()
        {
            return 2;
        }
        verdicts.push(verdict);
    }
    exit_code(&verdicts)
}
