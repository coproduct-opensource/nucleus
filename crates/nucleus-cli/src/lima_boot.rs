//! Why a Lima VM that Lima calls "Running" cannot be reached.
//!
//! # The incident this encodes
//!
//! On 2026-09-16 the `nucleus-kvm` VM hung on every start. Lima reported
//! "running", SSH never came up, and after ten minutes `limactl start` gave up
//! with `did not receive an event with the running status`. It took about ninety
//! minutes to find the cause, because every signal read as "hung somewhere":
//!
//! - an unclean stop had left the root ext4 with a corrupted orphan list;
//! - the initramfs `fsck -a` refused to repair it and dropped to a BusyBox
//!   `(initramfs)` shell, waiting for a human;
//! - the cloud image sends its console to `ttyAMA0`, and Apple's VZ has no such
//!   UART, so `serialv.log` was EMPTY and the prompt was invisible.
//!
//! The two measurements that located it were cheap and came last: the VM
//! process had used ~2 s of CPU and then none (it was *waiting*, not
//! *working*), and the console, once made visible, printed
//! `RUN fsck MANUALLY`. This module takes those measurements first.
//!
//! # "Could not look" is not "looked and it was fine" (ADR 0007, A-1)
//!
//! `doctor` used to probe an unreachable VM over `limactl shell`, read each
//! failed probe as a missing component, and tell the user to recreate the VM —
//! a destructive fix for a VM that needed one `e2fsck`. Every probe here returns
//! a variant that says whether it looked; nothing unobserved becomes healthy.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// How long an SSH round-trip to a healthy local VM may take. Generous: a
/// reachable VM answers in well under a second.
const SSH_PROBE_TIMEOUT: Duration = Duration::from_secs(20);

/// Window over which the VM process's CPU time is sampled.
const CPU_SAMPLE_WINDOW: Duration = Duration::from_secs(4);

/// Below this much CPU across the window, the guest is waiting, not booting.
/// A booting or provisioning guest burns far more than this in four seconds.
const IDLE_CPU_MS: u64 = 60;

/// What Lima itself says about the instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    pub status: String,
    pub vm_type: String,
    pub dir: PathBuf,
}

/// A recognised reason a boot stopped, read from the guest console.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsoleFinding {
    /// The initramfs root fsck refused to repair and asked for a manual run.
    ManualFsck,
    /// The root device never appeared.
    RootDeviceMissing,
    /// The kernel panicked.
    KernelPanic,
    /// systemd dropped to emergency mode.
    EmergencyMode,
    /// Dropped to the initramfs shell for a reason not matched above.
    InitramfsShell,
}

/// Whether the VM process is doing anything, or whether we could not tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpuActivity {
    /// Used less than [`IDLE_CPU_MS`] over the window: waiting on something.
    Idle { cpu_ms: u64 },
    /// Still working: booting, provisioning, or looping.
    Busy { cpu_ms: u64 },
    /// Could not find or sample the process. NOT evidence of either.
    Unknown(String),
}

/// The verdict. Every variant but `Reachable` means in-VM checks cannot be run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootDiagnosis {
    /// SSH answers; in-VM checks are meaningful.
    Reachable,
    /// Lima says the VM is not running at all.
    NotRunning { status: String },
    /// The console says why the boot stopped.
    Console {
        finding: ConsoleFinding,
        excerpt: String,
    },
    /// Unreachable, nothing recognisable on the console, and the VM is idle:
    /// it is waiting at a prompt on a console Lima cannot show.
    SilentAndIdle { cpu: CpuActivity },
    /// Unreachable and still using CPU: probably still booting or provisioning.
    StillWorking { cpu: CpuActivity },
    /// Unreachable, and whether it is working could not be measured.
    Undetermined { cpu: CpuActivity },
}

/// Diagnose the named Lima VM. Takes a few seconds when the VM is unreachable.
pub fn diagnose(name: &str) -> BootDiagnosis {
    let instance = match lookup(name) {
        Ok(Some(i)) => i,
        Ok(None) => {
            return BootDiagnosis::NotRunning {
                status: "not found".to_string(),
            };
        }
        Err(e) => {
            return BootDiagnosis::Undetermined {
                cpu: CpuActivity::Unknown(format!("could not run limactl list: {e}")),
            };
        }
    };
    if instance.status != "Running" {
        return BootDiagnosis::NotRunning {
            status: instance.status,
        };
    }
    if ssh_reachable(name) {
        return BootDiagnosis::Reachable;
    }
    let console = read_console(&instance);
    let cpu = match classify_console(&console) {
        Some(_) => CpuActivity::Unknown("not sampled: the console was decisive".to_string()),
        None => sample_cpu(&instance),
    };
    decide(&console, cpu)
}

/// The decision, separated from the measurements so it can be tested.
fn decide(console: &str, cpu: CpuActivity) -> BootDiagnosis {
    if let Some((finding, excerpt)) = classify_console(console) {
        return BootDiagnosis::Console { finding, excerpt };
    }
    match cpu {
        CpuActivity::Idle { .. } => BootDiagnosis::SilentAndIdle { cpu },
        CpuActivity::Busy { .. } => BootDiagnosis::StillWorking { cpu },
        CpuActivity::Unknown(_) => BootDiagnosis::Undetermined { cpu },
    }
}

impl BootDiagnosis {
    /// One-line summary for a check row.
    pub fn summary(&self) -> String {
        match self {
            BootDiagnosis::Reachable => "reachable over SSH".to_string(),
            BootDiagnosis::NotRunning { status } => format!("not running ({status})"),
            BootDiagnosis::Console { finding, .. } => match finding {
                ConsoleFinding::ManualFsck => {
                    "boot stopped: root filesystem needs a manual fsck".to_string()
                }
                ConsoleFinding::RootDeviceMissing => {
                    "boot stopped: root device not found".to_string()
                }
                ConsoleFinding::KernelPanic => "boot stopped: kernel panic".to_string(),
                ConsoleFinding::EmergencyMode => "boot stopped: systemd emergency mode".to_string(),
                ConsoleFinding::InitramfsShell => "boot stopped at the initramfs shell".to_string(),
            },
            BootDiagnosis::SilentAndIdle { .. } => {
                "Lima says running, but the VM is unreachable and idle".to_string()
            }
            BootDiagnosis::StillWorking { .. } => {
                "unreachable but busy (still booting or provisioning?)".to_string()
            }
            BootDiagnosis::Undetermined { .. } => {
                "unreachable; could not tell whether it is booting".to_string()
            }
        }
    }

    /// What to do, as an indented multi-line block. Empty when nothing is needed.
    pub fn remedy(&self, name: &str) -> String {
        let dir = format!("~/.lima/{name}");
        match self {
            BootDiagnosis::Reachable => String::new(),
            BootDiagnosis::NotRunning { .. } => format!("  Start it: limactl start {name}"),
            BootDiagnosis::Console { finding, excerpt } => {
                let what = match finding {
                    ConsoleFinding::ManualFsck => format!(
                        "  The initramfs fsck refused to repair the root filesystem (usually\n  \
                         after an unclean stop) and is waiting at a shell nobody can reach.\n  \
                         VMs created by current `nucleus setup` repair this on their own\n  \
                         (fsck.repair=yes). To recover this one without losing it:\n    \
                         limactl stop -f {name}\n    \
                         cp -c {dir}/disk {dir}/disk.bak      # instant APFS clone\n    \
                         # from any Linux VM that mounts {dir} writable:\n    \
                         sudo losetup -P -f --show /path/to/{name}/disk\n    \
                         sudo e2fsck -fy /dev/loopNp1 && sudo e2fsck -fn /dev/loopNp1\n  \
                         Or discard it: nucleus setup --force"
                    ),
                    ConsoleFinding::RootDeviceMissing => format!(
                        "  The kernel could not find the root disk. Check {dir}/disk exists\n  \
                         and was not moved or truncated; otherwise: nucleus setup --force"
                    ),
                    ConsoleFinding::KernelPanic | ConsoleFinding::InitramfsShell => format!(
                        "  Read the full console: {dir}/serialv.log (VZ) or serial.log (QEMU)"
                    ),
                    ConsoleFinding::EmergencyMode => format!(
                        "  A unit required for boot failed; the console names it:\n  \
                         {dir}/serialv.log"
                    ),
                };
                format!("  Console: {excerpt}\n{what}")
            }
            // A URL, not a repo path: the binary is used outside a checkout.
            BootDiagnosis::SilentAndIdle { .. } => "  An idle, unreachable guest is waiting at a \
                 prompt on a console Lima\n  cannot show. On VMs created before `console=hvc0` \
                 was set, the usual\n  cause is an initramfs manual-fsck shell after an unclean \
                 stop. To read the\n  console and repair it: https://github.com/\
                 coproduct-opensource/nucleus/blob/main/docs/quickstart/lima-boot-recovery.md\n  \
                 Or discard the VM: nucleus setup --force"
                .to_string(),
            BootDiagnosis::StillWorking { .. } => format!(
                "  Give it a few minutes, then rerun `nucleus doctor`. First boot\n  \
                 provisioning can take several. Progress: {dir}/serialv.log"
            ),
            BootDiagnosis::Undetermined { cpu } => format!(
                "  Could not measure the VM process ({}).\n  \
                 Check: limactl list; tail {dir}/ha.stderr.log",
                match cpu {
                    CpuActivity::Unknown(why) => why.as_str(),
                    CpuActivity::Idle { .. } | CpuActivity::Busy { .. } => "sampled",
                }
            ),
        }
    }
}

fn lookup(name: &str) -> std::io::Result<Option<Instance>> {
    let out = Command::new("limactl")
        .args([
            "list",
            name,
            "--format",
            "{{.Status}}\t{{.VMType}}\t{{.Dir}}",
        ])
        .stderr(Stdio::null())
        .output()?;
    Ok(parse_instance(&String::from_utf8_lossy(&out.stdout)))
}

fn parse_instance(line: &str) -> Option<Instance> {
    let mut parts = line.trim().splitn(3, '\t');
    let (status, vm_type, dir) = (parts.next()?, parts.next()?, parts.next()?);
    if status.is_empty() || dir.is_empty() {
        return None;
    }
    Some(Instance {
        status: status.to_string(),
        vm_type: vm_type.to_string(),
        dir: PathBuf::from(dir),
    })
}

/// SSH answers within [`SSH_PROBE_TIMEOUT`]. A spawn failure or timeout is
/// "not reachable"; the caller then measures instead of assuming.
pub fn ssh_reachable(name: &str) -> bool {
    let child = Command::new("limactl")
        .args(["shell", "--workdir", "/", name, "--", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = child else {
        return false;
    };
    let deadline = Instant::now() + SSH_PROBE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

/// The tail of the guest console, or empty if there is none to read.
fn read_console(instance: &Instance) -> String {
    const TAIL_BYTES: u64 = 64 * 1024;
    // VZ exposes only the virtio console; QEMU also has the UART log.
    for file in ["serialv.log", "serial.log"] {
        if let Some(text) = read_tail(&instance.dir.join(file), TAIL_BYTES)
            && !text.trim().is_empty()
        {
            return text;
        }
    }
    String::new()
}

fn read_tail(path: &Path, max: u64) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    f.seek(SeekFrom::Start(len.saturating_sub(max))).ok()?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// Recognise why a boot stopped. Most specific first: a manual-fsck failure
/// also ends at the initramfs prompt, and the fsck line is the actionable one.
pub fn classify_console(text: &str) -> Option<(ConsoleFinding, String)> {
    const RULES: [(ConsoleFinding, &[&str]); 5] = [
        (
            ConsoleFinding::ManualFsck,
            // The plain-English line first: it names the device.
            &["requires a manual fsck", "RUN fsck MANUALLY"],
        ),
        (
            ConsoleFinding::RootDeviceMissing,
            &[
                "Gave up waiting for root",
                "does not exist.  Dropping to a shell",
            ],
        ),
        (ConsoleFinding::KernelPanic, &["Kernel panic - not syncing"]),
        (
            ConsoleFinding::EmergencyMode,
            &["You are in emergency mode"],
        ),
        (ConsoleFinding::InitramfsShell, &["(initramfs)"]),
    ];
    for (finding, needles) in RULES {
        for needle in needles {
            if let Some(line) = text.lines().rev().find(|l| l.contains(needle)) {
                return Some((finding, clean_line(line)));
            }
        }
    }
    None
}

/// Strip timestamps, ANSI escapes and carriage returns for a one-line excerpt.
fn clean_line(line: &str) -> String {
    let no_ansi: String = {
        let mut out = String::new();
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                // Skip a CSI sequence: ESC [ ... final byte in @..~
                if chars.peek() == Some(&'[') {
                    chars.next();
                    for d in chars.by_ref() {
                        if ('@'..='~').contains(&d) {
                            break;
                        }
                    }
                }
                continue;
            }
            if c != '\r' {
                out.push(c);
            }
        }
        out
    };
    let trimmed = no_ansi.trim();
    // "[    1.234567] message" -> "message"
    match trimmed.strip_prefix('[').and_then(|r| r.split_once(']')) {
        Some((stamp, rest)) if stamp.trim().parse::<f64>().is_ok() => rest.trim().to_string(),
        _ => trimmed.to_string(),
    }
}

/// Sample the VM process's CPU time twice, [`CPU_SAMPLE_WINDOW`] apart.
fn sample_cpu(instance: &Instance) -> CpuActivity {
    let pid = match find_vm_pid(instance) {
        Ok(pid) => pid,
        Err(why) => return CpuActivity::Unknown(why),
    };
    let Some(before) = cpu_ms_of(pid) else {
        return CpuActivity::Unknown(format!("could not read CPU time of pid {pid}"));
    };
    std::thread::sleep(CPU_SAMPLE_WINDOW);
    let Some(after) = cpu_ms_of(pid) else {
        return CpuActivity::Unknown(format!("pid {pid} exited while sampling"));
    };
    let cpu_ms = after.saturating_sub(before);
    if cpu_ms < IDLE_CPU_MS {
        CpuActivity::Idle { cpu_ms }
    } else {
        CpuActivity::Busy { cpu_ms }
    }
}

/// The process that runs the guest's vCPUs.
///
/// QEMU writes its own pid file. VZ does not: the guest runs in an XPC service
/// that launchd spawns, so it is not a child of Lima's hostagent. It is started
/// by the hostagent within a second or two, so it is matched by elapsed time.
fn find_vm_pid(instance: &Instance) -> Result<u32, String> {
    if instance.vm_type == "qemu" {
        let pidfile = instance.dir.join("qemu.pid");
        return std::fs::read_to_string(&pidfile)
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .ok_or_else(|| format!("no readable {}", pidfile.display()));
    }
    let ha_pid: u32 = std::fs::read_to_string(instance.dir.join("ha.pid"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| "no readable ha.pid".to_string())?;
    let out = Command::new("ps")
        .args(["-axo", "pid=,etime=,command="])
        .output()
        .map_err(|e| format!("could not run ps: {e}"))?;
    pick_vz_process(&String::from_utf8_lossy(&out.stdout), ha_pid)
}

/// Among VZ guest processes, the one whose age matches the hostagent's.
fn pick_vz_process(ps: &str, ha_pid: u32) -> Result<u32, String> {
    const VZ_SERVICE: &str = "com.apple.Virtualization.VirtualMachine";
    const MATCH_WITHIN_SECS: u64 = 5;
    let rows: Vec<(u32, u64, &str)> = ps
        .lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let pid = it.next()?.parse().ok()?;
            let etime = parse_etime(it.next()?)?;
            let cmd_start = l.find(char::is_alphabetic).unwrap_or(0);
            Some((pid, etime, &l[cmd_start..]))
        })
        .collect();
    let ha_age = rows
        .iter()
        .find(|(pid, _, _)| *pid == ha_pid)
        .map(|(_, age, _)| *age)
        .ok_or_else(|| format!("hostagent pid {ha_pid} is not running"))?;
    let candidates: Vec<u32> = rows
        .iter()
        .filter(|(_, age, cmd)| {
            cmd.contains(VZ_SERVICE) && ha_age.abs_diff(*age) <= MATCH_WITHIN_SECS
        })
        .map(|(pid, _, _)| *pid)
        .collect();
    match candidates.as_slice() {
        [pid] => Ok(*pid),
        [] => Err("no VZ guest process started with this VM's hostagent".to_string()),
        _ => Err(format!(
            "{} VZ guest processes started within {MATCH_WITHIN_SECS}s of this VM's \
             hostagent; cannot tell which is this VM",
            candidates.len()
        )),
    }
}

/// `ps` elapsed time: `[[dd-]hh:]mm:ss` -> seconds.
fn parse_etime(s: &str) -> Option<u64> {
    let (days, rest) = match s.split_once('-') {
        Some((d, r)) => (d.parse::<u64>().ok()?, r),
        None => (0, s),
    };
    let fields: Vec<u64> = rest
        .split(':')
        .map(|f| f.parse().ok())
        .collect::<Option<_>>()?;
    let (h, m, sec) = match fields.as_slice() {
        [m, s] => (0, *m, *s),
        [h, m, s] => (*h, *m, *s),
        _ => return None,
    };
    Some(days * 86_400 + h * 3_600 + m * 60 + sec)
}

fn cpu_ms_of(pid: u32) -> Option<u64> {
    let out = Command::new("ps")
        .args(["-o", "time=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    parse_cputime(String::from_utf8_lossy(&out.stdout).trim())
}

/// `ps` cumulative CPU time -> milliseconds. macOS prints `M:SS.cc` with the
/// minutes unbounded (`114:03.54`); Linux prints `[dd-]hh:mm:ss`.
fn parse_cputime(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let (days, rest) = match s.split_once('-') {
        Some((d, r)) => (d.parse::<u64>().ok()?, r),
        None => (0, s),
    };
    let fields: Vec<&str> = rest.split(':').collect();
    let secs_ms = |f: &str| -> Option<u64> {
        let (whole, frac) = f.split_once('.').unwrap_or((f, "0"));
        let frac_ms = format!("{frac:0<3}").get(..3)?.parse::<u64>().ok()?;
        Some(whole.parse::<u64>().ok()? * 1000 + frac_ms)
    };
    let ms = match fields.as_slice() {
        [m, s] => m.parse::<u64>().ok()? * 60_000 + secs_ms(s)?,
        [h, m, s] => {
            h.parse::<u64>().ok()? * 3_600_000 + m.parse::<u64>().ok()? * 60_000 + secs_ms(s)?
        }
        _ => return None,
    };
    Some(days * 86_400_000 + ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The console of the real 2026-09-16 failure, as printed once `console=hvc0`
    /// made it visible (trimmed; escape sequences kept as captured).
    const REAL_MANUAL_FSCK: &str = "\
Begin: Will now check root file system ... fsck from util-linux 2.39.3\r
[/usr/sbin/fsck.ext4 (1) -- /dev/vda1] fsck.ext4 -a -C0 /dev/vda1 \r
cloudimg-rootfs contains a file system with errors, check forced.\r
cloudimg-rootfs: Inodes that were part of a corrupted orphan linked list found.  \r
\r
cloudimg-rootfs: UNEXPECTED INCONSISTENCY; RUN fsck MANUALLY.\r
\t(i.e., without -a or -p options)\r
fsck exited with status code 4\r
done.\r
Failure: File system check of the root filesystem failed\r
The root filesystem on /dev/vda1 requires a manual fsck\r
\r
BusyBox v1.36.1 (Ubuntu 1:1.36.1-6ubuntu3.1) built-in shell (ash)\r
Enter 'help' for a list of built-in commands.\r
\r
(initramfs) \u{1b}[6n";

    /// Control first: a healthy boot's console must match nothing, or every
    /// finding below is vacuous.
    #[test]
    fn a_healthy_console_matches_nothing() {
        let healthy = "[    0.615605] usb usb2: SerialNumber: 0000:00:0b.0\r\n\
                       Ubuntu 24.04.4 LTS lima-nucleus hvc0\r\n\r\nlima-nucleus login: ";
        assert_eq!(classify_console(healthy), None);
        assert_eq!(classify_console(""), None);
    }

    #[test]
    fn the_real_failure_is_a_manual_fsck_not_merely_an_initramfs_shell() {
        let (finding, excerpt) = classify_console(REAL_MANUAL_FSCK).expect("must match");
        assert_eq!(finding, ConsoleFinding::ManualFsck);
        assert_eq!(
            excerpt,
            "The root filesystem on /dev/vda1 requires a manual fsck"
        );
    }

    #[test]
    fn a_bare_initramfs_prompt_is_still_recognised() {
        let text = "Begin: Running /scripts/local-premount ... done.\r\n(initramfs) \u{1b}[6n";
        assert_eq!(
            classify_console(text).map(|(f, _)| f),
            Some(ConsoleFinding::InitramfsShell)
        );
    }

    #[test]
    fn a_kernel_panic_excerpt_loses_its_timestamp() {
        let text = "[    2.000001] Kernel panic - not syncing: VFS: Unable to mount root fs\r\n";
        assert_eq!(
            classify_console(text),
            Some((
                ConsoleFinding::KernelPanic,
                "Kernel panic - not syncing: VFS: Unable to mount root fs".to_string()
            ))
        );
    }

    /// The console outranks CPU: a decisive console line is never overridden.
    #[test]
    fn the_console_decides_before_cpu_is_consulted() {
        assert!(matches!(
            decide(REAL_MANUAL_FSCK, CpuActivity::Busy { cpu_ms: 9_000 }),
            BootDiagnosis::Console {
                finding: ConsoleFinding::ManualFsck,
                ..
            }
        ));
    }

    /// A-1: a CPU sample that could not be taken is never read as idle or busy.
    #[test]
    fn an_unmeasured_silent_vm_is_undetermined_not_idle() {
        assert!(matches!(
            decide("", CpuActivity::Unknown("no ha.pid".into())),
            BootDiagnosis::Undetermined { .. }
        ));
        assert!(matches!(
            decide("", CpuActivity::Idle { cpu_ms: 0 }),
            BootDiagnosis::SilentAndIdle { .. }
        ));
        assert!(matches!(
            decide("", CpuActivity::Busy { cpu_ms: 800 }),
            BootDiagnosis::StillWorking { .. }
        ));
    }

    #[test]
    fn only_reachable_needs_no_remedy() {
        assert!(BootDiagnosis::Reachable.remedy("vm").is_empty());
        for d in [
            BootDiagnosis::NotRunning {
                status: "Stopped".into(),
            },
            BootDiagnosis::SilentAndIdle {
                cpu: CpuActivity::Idle { cpu_ms: 0 },
            },
            decide(REAL_MANUAL_FSCK, CpuActivity::Unknown(String::new())),
        ] {
            assert!(!d.remedy("vm").is_empty(), "{d:?} must say what to do");
        }
    }

    #[test]
    fn cputime_parses_the_macos_and_linux_shapes() {
        assert_eq!(parse_cputime("0:01.90"), Some(1_900));
        assert_eq!(parse_cputime("114:03.54"), Some(114 * 60_000 + 3_540));
        assert_eq!(parse_cputime("01:02:03"), Some(3_723_000));
        assert_eq!(parse_cputime("1-00:00:01"), Some(86_401_000));
        assert_eq!(parse_cputime(""), None);
        assert_eq!(parse_cputime("garbage"), None);
    }

    #[test]
    fn etime_parses_every_width() {
        assert_eq!(parse_etime("00:42"), Some(42));
        assert_eq!(parse_etime("13:36:24"), Some(13 * 3600 + 36 * 60 + 24));
        assert_eq!(parse_etime("2-01:00:00"), Some(2 * 86_400 + 3_600));
        assert_eq!(parse_etime("x"), None);
    }

    /// Rows shaped like the real `ps -axo pid=,etime=,command=` output, with two
    /// VZ guests running: only the one as old as the hostagent is this VM's.
    #[test]
    fn the_vz_guest_is_matched_to_its_own_hostagent() {
        let ps = "  85392    01:13 /opt/homebrew/bin/limactl hostagent --pidfile /x/ha.pid\n\
                  85511    01:12 /System/Library/Frameworks/Virtualization.framework/Versions/A/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine\n\
                  68518 11:53:49 /System/Library/Frameworks/Virtualization.framework/Versions/A/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine\n";
        assert_eq!(pick_vz_process(ps, 85392), Ok(85511));
        assert!(
            pick_vz_process(ps, 1).is_err(),
            "unknown hostagent must not guess"
        );
    }

    #[test]
    fn two_equally_old_vz_guests_are_ambiguous_not_guessed() {
        let vz = "com.apple.Virtualization.VirtualMachine";
        let ps = format!("10 01:00 limactl hostagent\n11 01:00 {vz}\n12 01:01 {vz}\n");
        assert!(pick_vz_process(&ps, 10).is_err());
    }

    /// Against a real Lima VM named by `LIMA_BOOT_LIVE_VM`, whose expected
    /// verdict is `LIMA_BOOT_LIVE_EXPECT` (`reachable`, `manual-fsck`, `idle`).
    /// Ignored: it needs a VM deliberately put in that state (see
    /// docs/quickstart/lima-boot-recovery.md for the corruption that produces
    /// `manual-fsck`).
    #[test]
    #[ignore = "needs a live Lima VM in a known state"]
    fn live_vm_matches_its_expected_verdict() {
        let vm = std::env::var("LIMA_BOOT_LIVE_VM").expect("LIMA_BOOT_LIVE_VM");
        let expect = std::env::var("LIMA_BOOT_LIVE_EXPECT").expect("LIMA_BOOT_LIVE_EXPECT");
        let got = diagnose(&vm);
        println!("{}\n{}", got.summary(), got.remedy(&vm));
        let ok = match expect.as_str() {
            "reachable" => matches!(got, BootDiagnosis::Reachable),
            "manual-fsck" => matches!(
                got,
                BootDiagnosis::Console {
                    finding: ConsoleFinding::ManualFsck,
                    ..
                }
            ),
            "idle" => matches!(got, BootDiagnosis::SilentAndIdle { .. }),
            other => panic!("unknown LIMA_BOOT_LIVE_EXPECT {other}"),
        };
        assert!(ok, "expected {expect}, got {got:?}");
    }

    #[test]
    fn instance_line_parses_and_rejects_empty() {
        assert_eq!(
            parse_instance("Running\tvz\t/Users/u/.lima/nucleus\n"),
            Some(Instance {
                status: "Running".into(),
                vm_type: "vz".into(),
                dir: PathBuf::from("/Users/u/.lima/nucleus"),
            })
        );
        assert_eq!(parse_instance(""), None);
    }
}
