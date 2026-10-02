# Spike: in-guest workload confinement (Landlock, seccomp, hidepid)

**Status:** measurement only, for P3 of the agent-in-pod programme (#2696). Nothing is wired in.
**Date:** 2026-10-02. **KVM host:** Lima `nucleus` VM (Ubuntu 24.04, kernel 6.8, nested
virtualisation on an Apple M5 Pro), Firecracker v1.16.1. **Probe build:** GCP
`nucleus-agent-build-2` (aarch64), `aarch64-unknown-linux-musl`, Rust 1.96.1.

**Verdict: GO with a kernel re-pin. No nucleus-built kernel is needed.**

- The pinned guest kernel (Firecracker CI `v1.13/.../vmlinux-6.1.141`) has
  **Landlock compiled out**, so Landlock is NO-GO on the current pin.
- Seccomp and hidepid are **GO on the current pin**. Both were measured working
  there today.
- Upstream Firecracker CI has enabled Landlock in its own guest configs since
  2026-09-01 for the 6.1 line, and since at least 2026-08-03 for 6.18. Its
  newest published builds boot under our Firecracker 1.16.1 and enforce a
  Landlock ruleset:
  - `6.1.186` reports Landlock ABI 2.
  - `6.18.51` reports Landlock ABI 7.
- So P3 needs a kernel *pin* change, plus a mirror of the kernel bytes, not a
  kernel *build*.

## 1. Kernel config: what the guest actually boots

Both pinned kernels were fetched, and their sha256 equals the `tier2_artifacts`
pins. The config was then pulled with `scripts/extract-ikconfig` (v6.1). Both
kernels have `CONFIG_IKCONFIG=y`.

| Option | aarch64 `6.1.141` (pin `69aa3308…`) | x86_64 `6.1.141` (pin `b36a4a1b…`) |
|---|---|---|
| `CONFIG_SECURITY_LANDLOCK` | **is not set** | **is not set** |
| `CONFIG_LSM` | `"lockdown,yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,bpf"`, no `landlock` | same |
| `CONFIG_SECURITY` / `CONFIG_SECURITYFS` | `y` / `y` | `y` / `y` |
| `CONFIG_SECURITY_PATH` | is not set | is not set |
| `CONFIG_SECURITY_YAMA` | is not set | is not set |
| `CONFIG_SECURITY_SELINUX` (default LSM) | `y`, no policy loaded | `y` |
| `CONFIG_SECCOMP` / `CONFIG_SECCOMP_FILTER` | `y` / `y` | `y` / `y` |
| `CONFIG_PROC_FS` | `y` (hidepid needs nothing else since 5.8) | `y` |
| `CONFIG_USER_NS` | `y` | `y` |
| `CONFIG_BPF_SYSCALL` / `CONFIG_BPF_UNPRIV_DEFAULT_OFF` | `y` / `y` | `y` / `y` |
| `CONFIG_VSOCKETS` / `CONFIG_VIRTIO_VSOCKETS` | `y` / `y` | `y` / `y` |
| `CONFIG_MODULES` | is not set, so Landlock cannot be loaded later | is not set |

Booted, the pinned kernel reports `/sys/kernel/security/lsm` = `capability,selinux`, and
`landlock_create_ruleset(NULL, 0, VERSION)` returns `ENOSYS`.

The pin cannot be fixed by moving to a newer *versioned* prefix:

- `v1.14` and `v1.15` (`6.1.155`) also have Landlock unset. Measured for aarch64
  v1.14 and v1.15, and for x86_64 v1.15.
- Upstream changed the config at its source instead.
  `resources/guest_configs/microvm-kernel-ci-aarch64-6.1.config` on Firecracker
  `main` has `CONFIG_SECURITY_LANDLOCK=y` with `landlock` first in `CONFIG_LSM`.
  At tag `firecracker-v1.13` it has neither.
- Those configs ship only under the bucket's **dated** prefixes
  (`firecracker-ci/YYYYMMDD-<sha>-0/`), each with a `.config` beside the image:

| Dated prefix (aarch64) | Landlock |
|---|---|
| 6.1 line, through `20260826-…/vmlinux-6.1.182` | not set |
| 6.1 line, `20260901-3522ac594856-0/vmlinux-6.1.182` onward | `y` |
| 6.18 line, every config checked from `20260803-…/vmlinux-6.18.39` | `y` |
| newest: `20260930-0dd90d4c672d-0/{aarch64,x86_64}/vmlinux-{6.1.186,6.18.51}` | `y` on both arches |

### Is the newer kernel a drop-in replacement?

A config diff of `6.1.141` against `6.1.186` (aarch64) turns up only three options
that are `=y` in the pin and not in the candidate:

- a distribution driver-update toggle
- `CRYPTO_MANAGER_DISABLE_TESTS`
- `GCC_ASM_GOTO_OUTPUT_WORKAROUND`, a removed symbol

None of them matters to nucleus. Everything nucleus depends on is still there:

- The legacy x_tables interface the egress fence speaks (`fence.rs`):
  `IP_NF_IPTABLES`, `IP_NF_FILTER` and `NETFILTER_XT_MATCH_CONNTRACK` stay `y`.
- vsock, virtio, ext4, seccomp and namespaces are unchanged.

The candidate *adds* `NF_TABLES=y`, which un-blocks the owner's original
nftables-over-netlink preference noted in `fence.rs`. It also adds
`CHECKPOINT_RESTORE=y` (`kcmp`, `/proc/<pid>/map_files`). That is mild. hidepid
covers `/proc`, and the P3 seccomp table should add `kcmp`.

For `6.18.51`, 73 pin options are not `=y`. Almost all are symbols renamed or
removed between 6.1 and 6.18. A 6.18 move is therefore a real upgrade that needs
the full Tier-2 regression (egress probe, vsock, identity), not a drop-in.

## 2. What a nucleus-owned kernel would cost (not recommended)

This was costed because Landlock might have been unavailable anywhere upstream.
It is available, so this is the fallback only. The project already has the
template: `docker/Containerfile.l1-kernel` (47 lines) rebuilds kernel.org 6.18.35
from an embedded config plus `docker/l1-kernel.fragment`.

The guest equivalent:

- **Config fragment:** 2 lines:
  - `CONFIG_SECURITY_LANDLOCK=y`
  - `CONFIG_LSM="landlock,lockdown,yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,bpf"`
- **Base config:** the pinned kernel's own embedded config, via `extract-ikconfig`,
  as the L1 build does.
- **Build:** per arch, `make Image` (arm64) or `make vmlinux` (x86_64), about 10–15
  min on 16 vCPU. This needs a release-workflow job per arch, or the GCP builder.
  It is not reproducible bit-for-bit without extra work (`KBUILD_BUILD_TIMESTAMP`,
  `KBUILD_BUILD_HOST`, and the toolchain pinned).
- **Pin:** replace the URL in `KERNEL_AARCH64` / `KERNEL_X86_64` with a nucleus
  release asset.
- **Ongoing:** we own CVE tracking for a kernel line forever. That ongoing cost is
  the reason to prefer upstream's build.

Estimate: one PR of about 150 lines (Containerfile, fragment, workflow job, pins),
plus the ongoing upkeep. **Re-pinning upstream's dated build costs the same pin
change, minus the build and the upkeep.**

## 3. Live measurement: Landlock, on real guests

`nucleus-workload-probe` was not reused. It asserts the FM-5 posture and would
need a rootfs rebuild. The probe here is a separate ~420-line static binary
(source in the appendix):

- It boots as `/init` on a bare ext4.
- PID 1 mounts `/proc`, a second proc instance at `/hproc` with `hidepid=2`,
  sysfs, securityfs and a tmpfs `/tmp`.
- It forks a child that drops to uid/gid 65534 (setgroups, setresgid, setresuid),
  the same uid `ChildConfinement` uses.
- Every restriction is preceded by a **control**: the same operation run
  unrestricted. A denial counts only where the control shows a different outcome.
- Boot command: `firecracker --no-api --config-file`, 1 vCPU, 256 MiB, with
  `console=ttyS0 reboot=k panic=1 init=/init`.

Image digests:

- probe `/init`: `206352d4…82d6`
- rootfs `0b4747c7…4653`
- `6.1.186` `5699d939…a6bd`
- `6.18.51` `064f0824…62d5`

| Measurement | `6.1.141` (pin) | `6.1.186` | `6.18.51` |
|---|---|---|---|
| `/sys/kernel/security/lsm` | `capability,selinux` | `capability,landlock,selinux` | `capability,landlock,selinux` |
| Landlock ABI | **unavailable (`ENOSYS`)** | **2** | **7** |
| control: write `/tmp/denied/ctl` as nobody | ok | ok | ok |
| ruleset: RO `/`, full access only beneath `/tmp/allowed` | n/a | create, add, restrict_self all ok | ok, plus net rule (connect :443 only) |
| write `/tmp/allowed/after` | n/a | ok | ok |
| write `/tmp/denied/after` | n/a | **`EACCES`** | **`EACCES`** |
| write `/tmp/after` (outside any rule) | n/a | **`EACCES`** | **`EACCES`** |
| read `/init` (RO rule) | n/a | ok | ok |
| TCP connect 127.0.0.1:9 (control: `ENETUNREACH`, lo down) | n/a | `ENETUNREACH` (ABI 2 has no net rules) | **`EACCES`** (Landlock net) |

A write-path restriction is **enforced** on both Landlock kernels, for a non-root
process under `no_new_privs`. The boot log confirms it: `LSM: initializing
lsm=capability,landlock,selinux` / `landlock: Up and running.`

What ABI 2 (any 6.1) does **not** give P3:

- No `TRUNCATE` (ABI 3). `truncate(2)`/`ftruncate` stay ungoverned, so a file
  DAC-writable by uid 65534 outside the allowed tree can be truncated, though not
  written.
- No `IOCTL_DEV` (ABI 5).
- No TCP bind/connect rules (ABI 4).
- No signal or abstract-unix scoping (ABI 6).

On 6.1 the network dimension stays with the egress fence plus seccomp. AF_VSOCK
needs seccomp on every ABI anyway, because Landlock net rules cover TCP only.

## 4. Live measurement: seccomp

The repo has **no** in-guest seccomp today. `seccompiler` is not a dependency,
and the seccomp references in `nucleus-node` concern Firecracker's own VMM filter.
`ChildConfinement`'s `pre_exec` hook (`crates/nucleus/src/hardening.rs`) sets
`no_new_privs`, rlimits and `CLOSE_RANGE_CLOEXEC`, which is the natural place for
the filter.

The probe hand-assembles a 62-instruction classic-BPF filter:

1. Check the arch (`AUDIT_ARCH_AARCH64`); kill on mismatch.
2. Return `ERRNO(4000)` for each of:
   - `ptrace`, `bpf`, `perf_event_open`
   - `mount`, `umount2`, `pivot_root`, `open_tree`, `move_mount`, `fsopen`,
     `fsconfig`, `fsmount`, `fspick`, `mount_setattr`
   - `unshare`, `setns`
   - `process_vm_{readv,writev}`, `userfaultfd`, `keyctl`, `add_key`
3. Deny `socket`/`socketpair` when `args[0] == AF_VSOCK`.
4. Deny `clone` when `args[0]` has any `CLONE_NEW*` bit (`0x7E020000`).
5. Return `ENOSYS` for `clone3`, whose flags sit behind a pointer.
6. Allow everything else.

Errno 4000 is a marker, so a denial can be attributed to the filter rather than
to DAC or capabilities.

Identical on all three kernels:

| Measurement (child uid 65534) | Control (no filter) | With filter |
|---|---|---|
| install filter **without** `no_new_privs` | — | **refused, `EACCES`** |
| install filter with `no_new_privs` | — | ok; `/proc/self/status` `Seccomp: 2`, `Seccomp_filters: 1` |
| `socket(AF_VSOCK, SOCK_STREAM)` | **ok** (fd 4) | **marker (filter)** |
| `socket(AF_INET, SOCK_STREAM)` | ok | ok |
| `unshare(CLONE_NEWUSER)` | **ok** | **marker** |
| raw `clone(CLONE_NEWUSER\|SIGCHLD)` | **ok** | **marker** |
| `ptrace(PTRACE_TRACEME)` | ok | **marker** |
| `bpf(BPF_MAP_CREATE)` | `EPERM` (unprivileged bpf already off: `unprivileged_bpf_disabled=2`) | **marker** |
| `mount(tmpfs)` | `EPERM` (no CAP_SYS_ADMIN) | **marker** |
| `clone3` | ok | `ENOSYS` |
| `fork()` | — | ok |
| `std::process::Command` spawn | — | ok; musl's spawn path survives the `clone3` → `ENOSYS` fallback |

Two of these controls matter most:

- **A non-root workload can open AF_VSOCK today:** fd 4, on every kernel.
- **It can create a user namespace today**, and with it a root-in-namespace
  capability set (`USER_NS=y`).

Both are live attack surface in the current guest, not hypothetical. The filter
closes both, and installing it as non-root requires `no_new_privs`, which
`ChildConfinement` already sets.

## 5. Live measurement: hidepid

| Child (uid 65534) reads… | plain `/proc` (what the guest mounts today) | `/proc` mounted `hidepid=2` |
|---|---|---|
| lists PID 1 | **yes** (all ~50 pids visible) | **no**; only its own pid listed |
| `/proc/1/cmdline` | **readable** | `ENOENT` |
| `/proc/1/environ` | `EACCES` (DAC; P0b's uid drop already holds) | `ENOENT` |
| `/proc/self/status` | ok | ok |

The guest's `/proc` comes from `GUEST_MOUNTS` in `nucleus-guest-init/src/main.rs`.
`GuestMount` has `nosuid`/`nodev`/`noexec` flags but **no mount-data field**, so
hidepid needs one more field.

`hidepid` does not touch `/proc/cmdline`, the kernel command line, which is
world-readable 0444. Today that line carries only public material:
`nucleus.approval_pubkeys`, `nucleus.workload_api_port`, `nucleus.net` and the
region (`firecracker_config.rs:1025-1067`). The secrets were moved off it. Keep it
that way.

## Recommended P3 PR shape

1. **P3a: kernel re-pin.** Done first and alone, because it is the risk.
   - Move `KERNEL_AARCH64` / `KERNEL_X86_64` to Firecracker CI
     `20260930-0dd90d4c672d-0/<arch>/vmlinux-6.1.186`, the same 6.1 line and a
     near-superset config.
   - **Mirror the bytes as a nucleus release asset** and pin that URL. The dated
     prefixes are CI output, and nothing promises they stay.
   - Update the other copies of the pin in the same PR:
     - `docker/Containerfile.microvm-host:68`
     - `scripts/lima/nucleus-gpu-*.yaml`
     - `scripts/firecracker/boot-harness.sh`
     - `fence.rs`'s doc
     - `docs/findings/microvm-host-apple-container.md`
   - Proof: the full Tier-2 boot (egress probe verdict, identity, workload result)
     on the new kernel.
   - Move to 6.18.51 (ABI 7) as a separate later PR, after its own Tier-2
     regression.
2. **P3b: seccomp.** It is independent of the kernel, so it can land first or in
   parallel.
   - Put a `WorkloadSyscallFilter` in `crates/nucleus` (`hardening.rs`), with one
     table (ADR F/G) holding the denied set above plus `kcmp`. Build it with the
     `seccompiler` crate (pure Rust, Apache-2.0, no libseccomp) or as the
     hand-built BPF shown here.
   - Precompile it in the parent; install it in `ChildConfinement`'s `pre_exec`
     after the uid drop and `no_new_privs`. std runs `pre_exec` after
     `setuid`/`setgid`, and installing the filter allocates nothing, so it
     satisfies the async-signal-safe contract.
   - Applies to both the workload and `/v1/run` children (one mechanism, as in
     #3119).
   - Red-first test (A-19): an in-guest probe that opens AF_VSOCK must go from
     fd to denied.
3. **P3c: Landlock from the PathLattice.** Depends on P3a.
   - Compile `portcullis::PathLattice` to a ruleset in the parent: create the
     ruleset, add the rules, and keep the fd (it is `O_CLOEXEC` and survives to
     `pre_exec`). Call only `landlock_restrict_self` in `pre_exec`.
   - **Fail closed, not best-effort.** An ABI below the declared minimum (2) must
     refuse the spawn with a named error. Silently skipping is the
     "could not look ⇒ fine" defect (ADR A).
   - Rights are derived from the measured ABI. TRUNCATE and IOCTL_DEV become
     handled when ABI is at least 3 or 5.
   - Report the ABI in the pod's attestation.
4. **P3d: hidepid.** Add a mount-data field to `GuestMount` and mount `/proc` with
   `hidepid=invisible` (= 2). Do not use `subset=pid`, which hides `/proc/sys`,
   `/proc/meminfo` and others that ordinary workloads read.
5. **Capability rows.** P3b, P3c and P3d are guest-side, so each adds a
   `GuestCapability` row (`NotYet`) in the same PR (see the node/guest skew rule
   in `tier2_artifacts`).
   - The kernel feature is *not* a rootfs property, and `GuestCapability` cannot
     express it.
   - Give guest-init a boot-time verdict line in the egress-probe pattern, e.g.
     `NUCLEUS_CONFINEMENT_PROBE: landlock_abi=<n> seccomp=ok hidepid=ok`.
   - The node refuses a pod that is required to be confined and whose console has
     no such verdict, or a verdict below the minimum.
   - This also catches a kernel/rootfs mismatch that a pin cannot express.

## Reproduce

- **Configs.** `curl` the pinned URLs and check sha256 against `tier2_artifacts`.
  Then run `extract-ikconfig vmlinux > config` and grep the options above. The
  dated prefixes list with `https://s3.amazonaws.com/spec.ccfc.min/?list-type=2&prefix=firecracker-ci/`,
  which is paginated (4 pages on 2026-10-02).
- **Probe.** On an aarch64 Linux builder:
  1. Place the appendix source at `src/main.rs` with `libc = "0.2"`, `panic = "abort"`
     and an empty `[workspace]`.
  2. `cargo build --release --target aarch64-unknown-linux-musl`.
  3. Stage `{dev,proc,sys,tmp,hproc}/` with the binary at `/init`.
  4. `mkfs.ext4 -F -d stage probe.ext4 16M`.
- **Boot.** On a KVM host with Firecracker 1.16.1:
  1. Write a config with `boot-source.kernel_image_path`, `boot_args`
     `console=ttyS0 reboot=k panic=1 init=/init`, the ext4 as a writable root
     drive, 1 vCPU and 256 MiB.
  2. `sudo firecracker --no-api --config-file fc.json --api-sock fc.sock`.
  3. `grep '^P3 '` the console.

<details>
<summary>Appendix: probe source (<code>src/main.rs</code>, sha256 <code>45b4dd83…e9e1</code>)</summary>

```rust
//! P3 spike probe. Runs as /init (PID 1, root) in a bare Firecracker guest,
//! forks a child that drops to uid 65534 like the nucleus workload, and
//! measures Landlock, seccomp and hidepid. Every denial is preceded by a
//! control showing the same operation succeeds (or fails differently) without
//! the restriction, so a "denied" verdict cannot be vacuous.
//!
//! Output lines: `P3 <key> <value>`.

use std::ffi::CString;
use std::io::Write;

const NOBODY: u32 = 65534;
/// Distinctive errno returned by the probe's seccomp filter, so a denial is
/// attributable to the filter and not to DAC / capability checks.
const MARK: u32 = 4000;

fn out(k: &str, v: impl std::fmt::Display) {
    let mut o = std::io::stdout().lock();
    let _ = writeln!(o, "P3 {k} {v}");
    let _ = o.flush();
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Child exit code for a failed call: 200 means "the seccomp filter's
/// marker errno", otherwise the errno itself (all < 200 here).
fn ecode() -> i32 {
    let e = errno();
    if e == MARK as i32 { 200 } else { e.clamp(1, 199) }
}

/// Render a raw syscall result: "ok" or "err=<errno>".
fn r(rc: libc::c_long) -> String {
    if rc >= 0 { format!("ok({rc})") } else { format!("err={}", errno()) }
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn mount(src: &str, dst: &str, fs: &str, flags: libc::c_ulong, data: &str) -> String {
    let _ = std::fs::create_dir_all(dst);
    let d = c(data);
    let rc = unsafe {
        libc::mount(c(src).as_ptr(), c(dst).as_ptr(), c(fs).as_ptr(), flags,
            if data.is_empty() { std::ptr::null() } else { d.as_ptr().cast() })
    };
    r(rc as libc::c_long)
}

/// Run `f` in a forked child; the child's exit status is returned.
fn in_child(f: impl FnOnce() -> i32) -> i32 {
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let code = f();
        unsafe { libc::_exit(code) };
    }
    let mut st = 0;
    unsafe { libc::waitpid(pid, &mut st, 0) };
    if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { 128 + libc::WTERMSIG(st) }
}

fn drop_to_nobody() {
    unsafe {
        let gid = NOBODY as libc::gid_t;
        assert_eq!(libc::setgroups(1, &gid), 0);
        assert_eq!(libc::setresgid(NOBODY, NOBODY, NOBODY), 0);
        assert_eq!(libc::setresuid(NOBODY, NOBODY, NOBODY), 0);
    }
}

fn try_write(path: &str) -> String {
    match std::fs::write(path, b"x") {
        Ok(()) => "ok".into(),
        Err(e) => format!("err={}", e.raw_os_error().unwrap_or(-1)),
    }
}

fn try_read(path: &str) -> String {
    match std::fs::read(path) {
        Ok(b) => format!("ok({}B)", b.len()),
        Err(e) => format!("err={}", e.raw_os_error().unwrap_or(-1)),
    }
}

fn proc_lists_pid1(root: &str) -> String {
    match std::fs::read_dir(root) {
        Ok(it) => {
            let names: Vec<String> =
                it.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
            let pids = names.iter().filter(|n| n.bytes().all(|b| b.is_ascii_digit())).count();
            format!("pid1_listed={} pid_entries={} entries={}",
                names.iter().any(|n| n == "1"), pids, names.len())
        }
        Err(e) => format!("err={}", e.raw_os_error().unwrap_or(-1)),
    }
}

fn vsock_socket() -> String {
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd >= 0 { unsafe { libc::close(fd) }; }
    r(fd as libc::c_long)
}

fn inet_socket() -> String {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if fd >= 0 { unsafe { libc::close(fd) }; }
    r(fd as libc::c_long)
}

fn tcp_connect(port: u16) -> String {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        if fd < 0 { return format!("socket err={}", errno()); }
        let mut sa: libc::sockaddr_in = std::mem::zeroed();
        sa.sin_family = libc::AF_INET as libc::sa_family_t;
        sa.sin_port = port.to_be();
        sa.sin_addr.s_addr = u32::from_be_bytes([127, 0, 0, 1]).to_be();
        let rc = libc::connect(fd, (&sa as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as u32);
        let s = r(rc as libc::c_long);
        libc::close(fd);
        s
    }
}

fn unshare_userns() -> String {
    // In a grandchild: a successful unshare changes the caller's state.
    let code = in_child(|| {
        let rc = unsafe { libc::unshare(libc::CLONE_NEWUSER) };
        if rc == 0 { 0 } else { ecode() }
    });
    if code == 0 { "ok".into() } else { format!("errcode={code}") }
}

fn ptrace_traceme() -> String {
    let code = in_child(|| {
        let rc = unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) };
        if rc == 0 { 0 } else { ecode() }
    });
    if code == 0 { "ok".into() } else { format!("errcode={code}") }
}

fn bpf_map_create() -> String {
    // BPF_MAP_CREATE (0) with an array map of one u32.
    #[repr(C)]
    struct Attr { map_type: u32, key_size: u32, value_size: u32, max_entries: u32, pad: [u8; 112] }
    let a = Attr { map_type: 2, key_size: 4, value_size: 4, max_entries: 1, pad: [0; 112] };
    let rc = unsafe { libc::syscall(libc::SYS_bpf, 0, &a as *const Attr, std::mem::size_of::<Attr>()) };
    if rc >= 0 { unsafe { libc::close(rc as i32) }; }
    r(rc)
}

fn mount_tmpfs_attempt() -> String {
    let rc = unsafe {
        libc::mount(c("none").as_ptr(), c("/tmp/allowed").as_ptr(), c("tmpfs").as_ptr(), 0, std::ptr::null())
    };
    r(rc as libc::c_long)
}

fn raw_clone_newuser() -> String {
    // Raw clone(2) with CLONE_NEWUSER|SIGCHLD; child exits at once.
    let code = in_child(|| unsafe {
        let pid = libc::syscall(libc::SYS_clone, (libc::CLONE_NEWUSER | libc::SIGCHLD) as libc::c_ulong, 0, 0, 0, 0);
        if pid == 0 { libc::_exit(0) }
        if pid < 0 { return ecode(); }
        let mut st = 0;
        libc::waitpid(pid as i32, &mut st, 0);
        0
    });
    if code == 0 { "ok".into() } else { format!("errcode={code}") }
}

fn clone3_attempt() -> String {
    let code = in_child(|| unsafe {
        let mut args = [0u64; 11]; // struct clone_args (v2, 88 bytes)
        args[4] = libc::SIGCHLD as u64; // exit_signal
        let pid = libc::syscall(libc::SYS_clone3, args.as_mut_ptr(), 88usize);
        if pid == 0 { libc::_exit(0) }
        if pid < 0 { return ecode(); }
        let mut st = 0;
        libc::waitpid(pid as i32, &mut st, 0);
        0
    });
    if code == 0 { "ok".into() } else { format!("errcode={code}") }
}

// ---------- Landlock (raw syscalls; numbers are identical on aarch64/x86_64) ----------
const SYS_LL_CREATE: libc::c_long = 444;
const SYS_LL_ADD: libc::c_long = 445;
const SYS_LL_RESTRICT: libc::c_long = 446;

#[repr(C)]
struct RulesetAttr { fs: u64, net: u64, scoped: u64 }
#[repr(C, packed)]
struct PathBeneath { allowed: u64, parent_fd: i32 }
#[repr(C)]
struct NetPort { allowed: u64, port: u64 }

fn ll_abi() -> libc::c_long {
    unsafe { libc::syscall(SYS_LL_CREATE, std::ptr::null::<u8>(), 0usize, 1u32) }
}

fn fs_bits(abi: i64) -> u64 {
    let mut b = (1u64 << 13) - 1; // v1: EXECUTE..MAKE_SYM
    if abi >= 2 { b |= 1 << 13; } // REFER
    if abi >= 3 { b |= 1 << 14; } // TRUNCATE
    if abi >= 5 { b |= 1 << 15; } // IOCTL_DEV
    b
}

fn ll_path_rule(rs: i32, path: &str, allowed: u64) -> String {
    let fd = unsafe { libc::open(c(path).as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 { return format!("open err={}", errno()); }
    let a = PathBeneath { allowed, parent_fd: fd };
    let rc = unsafe { libc::syscall(SYS_LL_ADD, rs, 1u32, &a as *const PathBeneath, 0u32) };
    unsafe { libc::close(fd) };
    r(rc)
}

/// Restrict the calling (already non-root, no_new_privs) process.
fn landlock(abi: i64) {
    let fs = fs_bits(abi);
    let net = if abi >= 4 { 0b11 } else { 0 };
    let scoped = if abi >= 6 { 0b11 } else { 0 };
    let size = if abi >= 6 { 24 } else if abi >= 4 { 16 } else { 8 };
    let attr = RulesetAttr { fs, net, scoped };
    let rs = unsafe { libc::syscall(SYS_LL_CREATE, &attr as *const RulesetAttr, size as usize, 0u32) };
    out("landlock.create_ruleset", r(rs));
    if rs < 0 { return; }
    let rs = rs as i32;
    // Read+execute everywhere, full access beneath /tmp/allowed only.
    let ro = 1 | (1 << 2) | (1 << 3);
    out("landlock.rule_root_ro", ll_path_rule(rs, "/", ro & fs));
    out("landlock.rule_tmp_allowed_rw", ll_path_rule(rs, "/tmp/allowed", fs));
    if abi >= 4 {
        let p = NetPort { allowed: 0b10, port: 443 }; // CONNECT_TCP to :443 only
        let rc = unsafe { libc::syscall(SYS_LL_ADD, rs, 2u32, &p as *const NetPort, 0u32) };
        out("landlock.rule_net_connect_443", r(rc));
    }
    let rc = unsafe { libc::syscall(SYS_LL_RESTRICT, rs, 0u32) };
    out("landlock.restrict_self", r(rc));
    unsafe { libc::close(rs) };
}

// ---------- seccomp (classic BPF, hand-built) ----------
#[repr(C)]
#[derive(Clone, Copy)]
struct Insn { code: u16, jt: u8, jf: u8, k: u32 }
#[repr(C)]
struct Prog { len: u16, filter: *const Insn }

const LD_W_ABS: u16 = 0x20; // BPF_LD|BPF_W|BPF_ABS
const JEQ_K: u16 = 0x15; // BPF_JMP|BPF_JEQ|BPF_K
const JSET_K: u16 = 0x45; // BPF_JMP|BPF_JSET|BPF_K
const RET_K: u16 = 0x06; // BPF_RET|BPF_K
const RET_ALLOW: u32 = 0x7fff_0000;
const RET_KILL_PROCESS: u32 = 0x8000_0000;
const RET_ERRNO: u32 = 0x0005_0000;

#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;

fn i(code: u16, jt: u8, jf: u8, k: u32) -> Insn { Insn { code, jt, jf, k } }

fn seccomp_program() -> Vec<Insn> {
    let deny = RET_ERRNO | MARK;
    let mut p = vec![
        i(LD_W_ABS, 0, 0, 4),            // arch
        i(JEQ_K, 1, 0, AUDIT_ARCH),
        i(RET_K, 0, 0, RET_KILL_PROCESS),
        i(LD_W_ABS, 0, 0, 0),            // nr
    ];
    let flat: [libc::c_long; 20] = [
        libc::SYS_ptrace, libc::SYS_bpf, libc::SYS_mount, libc::SYS_umount2, libc::SYS_unshare,
        libc::SYS_setns, libc::SYS_pivot_root, libc::SYS_open_tree, libc::SYS_move_mount,
        libc::SYS_fsopen, libc::SYS_fsconfig, libc::SYS_fsmount, libc::SYS_fspick,
        libc::SYS_mount_setattr, libc::SYS_process_vm_readv, libc::SYS_process_vm_writev,
        libc::SYS_perf_event_open, libc::SYS_userfaultfd, libc::SYS_keyctl, libc::SYS_add_key,
    ];
    for nr in flat {
        p.push(i(JEQ_K, 0, 1, nr as u32));
        p.push(i(RET_K, 0, 0, deny));
    }
    // socket(AF_VSOCK, ..) and socketpair(AF_VSOCK, ..)
    for nr in [libc::SYS_socket, libc::SYS_socketpair] {
        p.push(i(JEQ_K, 0, 4, nr as u32));
        p.push(i(LD_W_ABS, 0, 0, 16)); // args[0] low word
        p.push(i(JEQ_K, 0, 1, libc::AF_VSOCK as u32));
        p.push(i(RET_K, 0, 0, deny));
        p.push(i(RET_K, 0, 0, RET_ALLOW));
    }
    // clone(flags) with any CLONE_NEW* flag
    p.push(i(JEQ_K, 0, 4, libc::SYS_clone as u32));
    p.push(i(LD_W_ABS, 0, 0, 16));
    p.push(i(JSET_K, 0, 1, 0x7E02_0000));
    p.push(i(RET_K, 0, 0, deny));
    p.push(i(RET_K, 0, 0, RET_ALLOW));
    // clone3: flags live behind a pointer; force the libc fallback to clone.
    p.push(i(JEQ_K, 0, 1, libc::SYS_clone3 as u32));
    p.push(i(RET_K, 0, 0, RET_ERRNO | libc::ENOSYS as u32));
    p.push(i(RET_K, 0, 0, RET_ALLOW));
    p
}

fn install_seccomp() -> String {
    let prog = seccomp_program();
    let fprog = Prog { len: prog.len() as u16, filter: prog.as_ptr() };
    let rc = unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &fprog as *const Prog) };
    format!("{} insns={}", r(rc as libc::c_long), prog.len())
}

fn status_line(key: &str) -> String {
    std::fs::read_to_string("/proc/self/status").unwrap_or_default().lines()
        .find(|l| l.starts_with(key)).map(|l| l.split_whitespace().skip(1).collect::<Vec<_>>().join(" "))
        .unwrap_or_else(|| "?".into())
}

fn workload() -> i32 {
    drop_to_nobody();
    out("child.uid", unsafe { libc::getuid() });

    // ---- hidepid ----
    out("hidepid.plain_proc", proc_lists_pid1("/proc"));
    out("hidepid.plain_proc.pid1_cmdline", try_read("/proc/1/cmdline"));
    out("hidepid.plain_proc.pid1_environ", try_read("/proc/1/environ"));
    out("hidepid.hproc", proc_lists_pid1("/hproc"));
    out("hidepid.hproc.pid1_cmdline", try_read("/hproc/1/cmdline"));
    out("hidepid.hproc.pid1_environ", try_read("/hproc/1/environ"));
    out("hidepid.hproc.self_status", if try_read("/hproc/self/status").starts_with("ok") { "ok" } else { "err" });

    // ---- seccomp without no_new_privs (must be refused for non-root) ----
    let code = in_child(|| if install_seccomp().starts_with("ok") { 0 } else { ecode() });
    out("seccomp.install_without_nnp", if code == 0 { "ok".to_string() } else { format!("errcode={code}") });

    // ---- controls, before any restriction ----
    out("control.write_tmp_denied", try_write("/tmp/denied/ctl"));
    out("control.write_tmp_allowed", try_write("/tmp/allowed/ctl"));
    out("control.tcp_connect_9", tcp_connect(9));
    out("control.vsock_socket", vsock_socket());
    out("control.inet_socket", inet_socket());
    out("control.unshare_userns", unshare_userns());
    out("control.clone_newuser", raw_clone_newuser());
    out("control.ptrace_traceme", ptrace_traceme());
    out("control.bpf_map_create", bpf_map_create());
    out("control.mount_tmpfs", mount_tmpfs_attempt());
    out("control.clone3", clone3_attempt());

    // ---- no_new_privs ----
    let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    out("nnp.set", r(rc as libc::c_long));

    // ---- Landlock ----
    let abi = ll_abi();
    out("landlock.abi", if abi >= 0 { abi.to_string() } else { format!("unavailable err={}", errno()) });
    if abi > 0 {
        landlock(abi);
        out("landlock.write_tmp_allowed", try_write("/tmp/allowed/after"));
        out("landlock.write_tmp_denied", try_write("/tmp/denied/after"));
        out("landlock.write_tmp_root", try_write("/tmp/after"));
        out("landlock.read_init", try_read("/init"));
        out("landlock.tcp_connect_9", tcp_connect(9));
    }

    // ---- seccomp ----
    out("seccomp.install_with_nnp", install_seccomp());
    out("seccomp.status", status_line("Seccomp:"));
    out("seccomp.filters", status_line("Seccomp_filters:"));
    out("seccomp.vsock_socket", vsock_socket());
    out("seccomp.inet_socket", inet_socket());
    out("seccomp.unshare_userns", unshare_userns());
    out("seccomp.clone_newuser", raw_clone_newuser());
    out("seccomp.ptrace_traceme", ptrace_traceme());
    out("seccomp.bpf_map_create", bpf_map_create());
    out("seccomp.mount_tmpfs", mount_tmpfs_attempt());
    out("seccomp.clone3", clone3_attempt());
    let code = in_child(|| 7);
    out("seccomp.plain_fork", format!("child_exit={code}"));
    out("seccomp.std_command", match std::process::Command::new("/init").arg("--noop").status() {
        Ok(s) => format!("ok({:?})", s.code()),
        Err(e) => format!("err={}", e.raw_os_error().unwrap_or(-1)),
    });
    0
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--noop") {
        return;
    }
    // No /dev/console in the image: mount devtmpfs and point stdio at it.
    let _ = std::fs::create_dir_all("/dev");
    unsafe {
        libc::mount(c("devtmpfs").as_ptr(), c("/dev").as_ptr(), c("devtmpfs").as_ptr(), 0, std::ptr::null());
        let fd = libc::open(c("/dev/console").as_ptr(), libc::O_RDWR);
        if fd >= 0 { libc::dup2(fd, 0); libc::dup2(fd, 1); libc::dup2(fd, 2); }
    }
    out("begin", "1");
    out("mount.proc", mount("proc", "/proc", "proc", 0, ""));
    out("mount.hproc", mount("proc", "/hproc", "proc", 0, "hidepid=2"));
    out("mount.sys", mount("sysfs", "/sys", "sysfs", 0, ""));
    out("mount.securityfs", mount("securityfs", "/sys/kernel/security", "securityfs", 0, ""));
    out("mount.tmp", mount("tmpfs", "/tmp", "tmpfs", 0, "mode=1777"));
    out("kernel.release", std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default().trim());
    out("kernel.lsm", std::fs::read_to_string("/sys/kernel/security/lsm").unwrap_or_else(|e| format!("err {e}")));
    out("kernel.cmdline", std::fs::read_to_string("/proc/cmdline").unwrap_or_default().trim());
    out("kernel.unpriv_bpf_disabled", std::fs::read_to_string("/proc/sys/kernel/unprivileged_bpf_disabled").unwrap_or_default().trim());
    for d in ["/tmp/allowed", "/tmp/denied"] {
        std::fs::create_dir_all(d).unwrap();
        unsafe { libc::chown(c(d).as_ptr(), NOBODY, NOBODY) };
    }
    let code = in_child(workload);
    out("child.exit", code);
    out("end", "1");
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_AUTOBOOT);
    }
}
```

</details>
