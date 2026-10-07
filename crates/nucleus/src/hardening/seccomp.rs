//! The syscall filter a confined child installs: the workload denylist
//! (#2696 P3b).
//!
//! # Why a filter at all
//!
//! The uid drop (#3119) separates a child from the runtime's *files and
//! environment*. It does not take away the kernel interfaces every uid has.
//! The P3 spike (#3148, `docs/findings/p3-workload-confinement-spike.md`)
//! measured two of them open to an unprivileged workload on the guest kernel
//! pinned then (6.1.141), and identical on 6.1.186 and 6.18.51:
//!
//! * `socket(AF_VSOCK)` succeeds (fd 4). The vsock is the guest-to-host
//!   channel, and the host's listeners on it identify the POD, never a process
//!   inside it (vsock carries no peer credentials), so a workload that reaches
//!   them speaks with the pod's authority.
//! * `unshare(CLONE_NEWUSER)` succeeds, and with it a full capability set
//!   inside the new namespace: the doorway to most of the kernel's
//!   unprivileged-reachable attack surface.
//!
//! # Shape
//!
//! [`TABLE`] is the ONE statement of what every confined child is denied (ADR
//! 0007 F-1, G-1), and [`derived_rules`] the ONE statement of what each class
//! of a pod's derived [`SeccompPolicy`] adds (#2907). [`Program::workload`]
//! compiles their union, and the tests walk the same two tables. Each entry
//! carries its reason beside it.
//!
//! # The derived classes (#2907)
//!
//! `portcullis::SeccompPolicy` names the classes a pod's lattice takes away.
//! They are installed in the SAME program as the denylist, after its entries,
//! so a derived rule can only add a denial: every block either denies or falls
//! through to the next, and only the final instruction allows.
//!
//! * `Exec`: `execve` is denied, and `execveat` is denied unless its `dirfd`
//!   is the one descriptor the runtime starts the child through ([`ExecPin`]).
//!   The filter is installed before the child's own exec, so without the pin
//!   the child could never start. The pin is a descriptor number at or above
//!   the child's `RLIMIT_NOFILE`, which the hook sets (hard and soft) before
//!   the filter: once the pinned descriptor closes at exec (it is
//!   close-on-exec), no process under the filter can ever hold that number
//!   again. `dup2`, `fcntl(F_DUPFD)`, `open`, `pidfd_getfd` and `SCM_RIGHTS`
//!   all allocate below the limit, raising the hard limit needs
//!   `CAP_SYS_RESOURCE`, and a user namespace (where that capability would be
//!   granted) is refused by [`TABLE`]. So the pinned exec happens exactly once.
//! * `InetSocket`: `socket` and `socketpair` with `AF_INET` or `AF_INET6`.
//!
//! The program is built in the PARENT, before fork (it allocates). The child's
//! `pre_exec` hook only hands the finished instructions to `prctl`, which is
//! async-signal-safe. It is installed after the uid drop (std performs that
//! before any `pre_exec` closure) and after `no_new_privs`, without which the
//! kernel refuses an unprivileged filter with `EACCES`.
//!
//! A program that cannot be built (an architecture this file does not know)
//! is not a program that is skipped: the caller refuses the spawn (ADR 0007
//! A-1).
//!
//! # Layout of the program
//!
//! 1. Load `seccomp_data.arch`; anything but this build's native audit arch is
//!    `KILL_PROCESS`. A syscall under another ABI (32-bit compat) has other
//!    numbers, so the denylist would mean nothing for it.
//! 2. Load `seccomp_data.nr`. On x86_64, a number with the x32 bit set is
//!    denied: x32 shares `AUDIT_ARCH_X86_64`, so its calls would otherwise
//!    reach the table under numbers that match no entry.
//! 3. One block per [`TABLE`] entry, then one per [`derived_rules`] entry. A
//!    block that inspects an argument reloads the number and falls through
//!    when the argument does not match, so two blocks for one syscall
//!    (`socket` for `AF_VSOCK` and for `AF_INET`) compose as a union.
//! 4. Allow.
//!
//! Classic BPF reads `args[0]` 32 bits at a time; the rules below read only its
//! low word, which is correct for every argument rule: the kernel truncates
//! `socket`'s `domain` and `execveat`'s `dirfd` to `int`, and the legacy
//! `clone` uses only the low 32 bits of its flags (`lower_32_bits(clone_flags)`
//! in `kernel/fork.c`).

use std::fmt;
use std::mem::offset_of;

use libc::{c_int, c_long};
use portcullis::{SeccompPolicy, SyscallClass};

/// The errno a denied call fails with. `EPERM` is what the kernel itself
/// answers for an operation the caller is not permitted (and what an
/// unprivileged `unshare` gets where user namespaces are disabled), so
/// software that probes for a feature already handles it.
pub(crate) const DENIED_ERRNO: c_int = libc::EPERM;

/// Every `CLONE_NEW*` flag the legacy `clone` accepts. `CLONE_NEWTIME` is not
/// here: its bit (`0x80`) lies in `clone`'s `CSIGNAL` field, so it is only
/// expressible through `clone3` and `unshare`, which the table refuses whole.
const CLONE_NEW_ANY: c_int = libc::CLONE_NEWNS
    | libc::CLONE_NEWCGROUP
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUSER
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET;

/// What the filter does with one syscall number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rule {
    /// Always fails with [`DENIED_ERRNO`].
    Deny,
    /// Fails with [`DENIED_ERRNO`] when the low word of `args[0]` equals the
    /// value; otherwise the next block decides.
    DenyWhenArg0Is(c_int),
    /// Fails with [`DENIED_ERRNO`] when the low word of `args[0]` has any of
    /// these bits; otherwise the next block decides.
    DenyWhenArg0Has(c_int),
    /// Fails with [`DENIED_ERRNO`] unless the low word of `args[0]` equals the
    /// value; when it does, the next block decides. The exec pin.
    DenyUnlessArg0Is(c_int),
    /// Fails with `ENOSYS`: "this kernel has no such call". Used where the
    /// argument that matters is behind a pointer the filter cannot read, so
    /// libc falls back to a call the filter CAN inspect.
    Unimplemented,
}

/// The denylist: `(name, number, rule)`. ONE table (ADR 0007 F-1); the
/// program and the tests are both derived from it. Every number appears once.
///
/// What is NOT here, on purpose: `seccomp`/`prctl` (another filter can only
/// narrow this one), and ordinary process, file and network calls, which the
/// workload exists to make.
pub(crate) const TABLE: &[(&str, c_long, Rule)] = &[
    // -- The guest-to-host channel (measured open in #3148). --
    // The host's vsock listeners authenticate the pod, not the process: no
    // peer credentials cross a vsock. `socketpair` cannot make a vsock pair
    // today; it is listed so the family is closed at every entry point.
    (
        "socket",
        libc::SYS_socket,
        Rule::DenyWhenArg0Is(libc::AF_VSOCK),
    ),
    (
        "socketpair",
        libc::SYS_socketpair,
        Rule::DenyWhenArg0Is(libc::AF_VSOCK),
    ),
    // io_uring performs operations seccomp never sees: `IORING_OP_SOCKET`
    // (5.19+, so on every kernel we pin) would create the AF_VSOCK socket the
    // two rules above refuse. It is also a long-running source of kernel
    // privilege escalations. libuv and tokio fall back to threads without it.
    ("io_uring_setup", libc::SYS_io_uring_setup, Rule::Deny),
    ("io_uring_enter", libc::SYS_io_uring_enter, Rule::Deny),
    ("io_uring_register", libc::SYS_io_uring_register, Rule::Deny),
    // -- Namespaces (CLONE_NEWUSER measured open in #3148). --
    // A user namespace hands an unprivileged process a full capability set
    // inside it, which reaches netfilter, mount and the rest of the
    // CAP_SYS_ADMIN surface. Every `unshare` flag that matters is a namespace,
    // so `unshare` is refused whole; `setns` would join one created elsewhere.
    ("unshare", libc::SYS_unshare, Rule::Deny),
    ("setns", libc::SYS_setns, Rule::Deny),
    (
        "clone",
        libc::SYS_clone,
        Rule::DenyWhenArg0Has(CLONE_NEW_ANY),
    ),
    // `clone3` takes its flags in a struct behind a pointer, which BPF cannot
    // read. `ENOSYS` makes glibc, musl and std fall back to `clone`, which the
    // rule above inspects (measured in #3148: `std::process::Command` still
    // spawns).
    ("clone3", libc::SYS_clone3, Rule::Unimplemented),
    // -- Reaching into another process. --
    // Every confined child of one runtime shares one uid (65534), and the guest
    // kernel has no Yama, so same-uid ptrace is otherwise allowed: one child
    // could read or rewrite another's memory and descriptors. These are the
    // routes: ptrace itself, the cross-process memory copies, stealing an fd
    // through a pidfd, and kcmp (which compares kernel objects across
    // processes and leaks their identity; the spike's recommendation).
    ("ptrace", libc::SYS_ptrace, Rule::Deny),
    ("process_vm_readv", libc::SYS_process_vm_readv, Rule::Deny),
    ("process_vm_writev", libc::SYS_process_vm_writev, Rule::Deny),
    ("pidfd_getfd", libc::SYS_pidfd_getfd, Rule::Deny),
    ("kcmp", libc::SYS_kcmp, Rule::Deny),
    // -- Kernel attack surface a workload has no use for. --
    // bpf: unprivileged bpf is already off in the guest
    // (`unprivileged_bpf_disabled=2`), so this is the second wall, not the
    // first. perf_event_open: a side-channel and escalation source.
    // userfaultfd: the classic primitive for widening a kernel race.
    ("bpf", libc::SYS_bpf, Rule::Deny),
    ("perf_event_open", libc::SYS_perf_event_open, Rule::Deny),
    ("userfaultfd", libc::SYS_userfaultfd, Rule::Deny),
    // The kernel keyring is not namespaced: it is state shared across the
    // whole guest, outside the filesystem the rest of the confinement governs,
    // and a recurring escalation source.
    ("keyctl", libc::SYS_keyctl, Rule::Deny),
    ("add_key", libc::SYS_add_key, Rule::Deny),
    ("request_key", libc::SYS_request_key, Rule::Deny),
    // -- Mounts. --
    // A dropped child lacks CAP_SYS_ADMIN, so these fail today on the
    // capability check (measured EPERM). With user namespaces refused above
    // they stay unreachable; listing them makes that a second wall, not an
    // inference from the first.
    ("mount", libc::SYS_mount, Rule::Deny),
    ("umount2", libc::SYS_umount2, Rule::Deny),
    ("pivot_root", libc::SYS_pivot_root, Rule::Deny),
    ("open_tree", libc::SYS_open_tree, Rule::Deny),
    ("move_mount", libc::SYS_move_mount, Rule::Deny),
    ("fsopen", libc::SYS_fsopen, Rule::Deny),
    ("fsconfig", libc::SYS_fsconfig, Rule::Deny),
    ("fsmount", libc::SYS_fsmount, Rule::Deny),
    ("fspick", libc::SYS_fspick, Rule::Deny),
    ("mount_setattr", libc::SYS_mount_setattr, Rule::Deny),
    // -- Replacing or extending the kernel. --
    // Root-only (CAP_SYS_BOOT / CAP_SYS_MODULE), so a dropped child cannot
    // make them. Listed so that a regression in the uid drop does not also
    // hand out the kernel.
    ("kexec_load", libc::SYS_kexec_load, Rule::Deny),
    ("kexec_file_load", SYS_KEXEC_FILE_LOAD, Rule::Deny),
    ("init_module", libc::SYS_init_module, Rule::Deny),
    ("finit_module", libc::SYS_finit_module, Rule::Deny),
    ("delete_module", libc::SYS_delete_module, Rule::Deny),
];

/// The descriptor a child under a derived `Exec` denial is started through
/// (see the module docs). Decided in the parent: a number at or above the
/// child's `RLIMIT_NOFILE`. Only [`super::exec_pin`] builds one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExecPin(pub(crate) c_int);

/// What a derived policy's classes add to [`TABLE`]: ONE statement per class
/// (ADR 0007 F-1). Exhaustive over [`SyscallClass`] with no `_` arm (B-3).
///
/// # Errors
/// [`FilterError::ExecWithoutPin`] when `policy` denies `Exec` and no pin was
/// given: the child could not be started, so the spawn is refused.
pub(crate) fn derived_rules(
    policy: SeccompPolicy,
    pin: Option<ExecPin>,
) -> Result<Vec<(&'static str, c_long, Rule)>, FilterError> {
    let mut rules = Vec::new();
    for class in policy.denied() {
        match class {
            // `run_bash: never`. `execve` whole; `execveat` except on the pin,
            // the runtime's own one exec of the child.
            SyscallClass::Exec => {
                let ExecPin(fd) = pin.ok_or(FilterError::ExecWithoutPin)?;
                rules.push(("execve", libc::SYS_execve, Rule::Deny));
                rules.push(("execveat", libc::SYS_execveat, Rule::DenyUnlessArg0Is(fd)));
            }
            // `web_fetch: never` and no declared egress: no internet socket.
            // `socketpair` cannot make one today; listed so the family is
            // closed at both entry points, as `AF_VSOCK` is.
            SyscallClass::InetSocket => {
                for family in [libc::AF_INET, libc::AF_INET6] {
                    rules.push(("socket", libc::SYS_socket, Rule::DenyWhenArg0Is(family)));
                    rules.push((
                        "socketpair",
                        libc::SYS_socketpair,
                        Rule::DenyWhenArg0Is(family),
                    ));
                }
            }
        }
    }
    Ok(rules)
}

/// `kexec_file_load`. The `libc` crate's aarch64 musl module (the guest's
/// target) omits it; aarch64 takes it from `asm-generic/unistd.h`, where it is
/// 294 (`__NR_kexec_file_load`). Everywhere else, libc's own constant.
#[cfg(all(target_arch = "aarch64", target_env = "musl"))]
const SYS_KEXEC_FILE_LOAD: c_long = 294;
#[cfg(not(all(target_arch = "aarch64", target_env = "musl")))]
const SYS_KEXEC_FILE_LOAD: c_long = libc::SYS_kexec_file_load;

/// The x32 ABI marker in a syscall number (uapi `asm/unistd.h`).
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// Why the program could not be built. Each case refuses the spawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FilterError {
    /// This build's architecture has no audit-arch constant here, or is
    /// big-endian (the argument rules read the low word at the little-endian
    /// offset).
    #[allow(
        dead_code,
        reason = "constructed only when building for an architecture this file does not know"
    )]
    UnsupportedArch,
    /// A constant did not fit the field BPF gives it.
    Overflow(&'static str),
    /// The policy denies `Exec` and no [`ExecPin`] was given.
    ExecWithoutPin,
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterError::UnsupportedArch => write!(
                f,
                "no workload syscall filter for {} ({}-endian); a confined child cannot be \
                 spawned on this architecture",
                std::env::consts::ARCH,
                if cfg!(target_endian = "little") {
                    "little"
                } else {
                    "big"
                }
            ),
            FilterError::Overflow(what) => {
                write!(
                    f,
                    "workload syscall filter: {what} does not fit its BPF field"
                )
            }
            FilterError::ExecWithoutPin => write!(
                f,
                "the pod's policy denies exec (run_bash: never) and the child has no pinned \
                 descriptor to be started through"
            ),
        }
    }
}

/// `__AUDIT_ARCH_64BIT` and `__AUDIT_ARCH_LE` from uapi `linux/audit.h`. The
/// `libc` crate has the ELF machine numbers but not the audit arches, so the
/// arches are derived from them exactly as the header does:
/// `AUDIT_ARCH_X86_64 = EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE`.
const AUDIT_ARCH_64BIT: u32 = 0x8000_0000;
const AUDIT_ARCH_LE: u32 = 0x4000_0000;

/// A 64-bit little-endian audit arch for an ELF machine number.
fn audit_arch_64le(machine: u16) -> u32 {
    u32::from(machine) | AUDIT_ARCH_64BIT | AUDIT_ARCH_LE
}

/// The native audit arch, or a refusal.
fn audit_arch() -> Result<u32, FilterError> {
    #[cfg(all(target_arch = "x86_64", target_endian = "little"))]
    {
        Ok(audit_arch_64le(libc::EM_X86_64))
    }
    #[cfg(all(target_arch = "aarch64", target_endian = "little"))]
    {
        Ok(audit_arch_64le(libc::EM_AARCH64))
    }
    #[cfg(not(any(
        all(target_arch = "x86_64", target_endian = "little"),
        all(target_arch = "aarch64", target_endian = "little")
    )))]
    {
        Err(FilterError::UnsupportedArch)
    }
}

fn fit<T, U: TryFrom<T>>(v: T, what: &'static str) -> Result<U, FilterError> {
    U::try_from(v).map_err(|_| FilterError::Overflow(what))
}

/// The classic-BPF opcodes this program uses, derived from libc's uapi
/// constants rather than restated (ADR 0007 F).
#[derive(Clone, Copy)]
struct Ops {
    ld_w_abs: u16,
    jeq: u16,
    jset: u16,
    #[cfg(target_arch = "x86_64")]
    jge: u16,
    ret: u16,
}

impl Ops {
    fn new() -> Result<Self, FilterError> {
        Ok(Self {
            ld_w_abs: fit(
                libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
                "BPF_LD|BPF_W|BPF_ABS",
            )?,
            jeq: fit(
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                "BPF_JMP|BPF_JEQ|BPF_K",
            )?,
            jset: fit(
                libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K,
                "BPF_JMP|BPF_JSET|BPF_K",
            )?,
            #[cfg(target_arch = "x86_64")]
            jge: fit(
                libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K,
                "BPF_JMP|BPF_JGE|BPF_K",
            )?,
            ret: fit(libc::BPF_RET | libc::BPF_K, "BPF_RET|BPF_K")?,
        })
    }
}

fn insn(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// A compiled filter, ready for `PR_SET_SECCOMP`. Built in the parent; the
/// child only borrows it.
pub(crate) struct Program {
    insns: Vec<libc::sock_filter>,
    len: u16,
}

impl fmt::Debug for Program {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Program")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl Program {
    /// Compile [`TABLE`] and `policy`'s [`derived_rules`] for this
    /// architecture.
    ///
    /// # Errors
    /// [`FilterError`] when the architecture is unknown, a constant does not
    /// fit, or `policy` denies exec without a `pin`; the caller refuses the
    /// spawn.
    pub(crate) fn workload(
        policy: SeccompPolicy,
        pin: Option<ExecPin>,
    ) -> Result<Self, FilterError> {
        let derived = derived_rules(policy, pin)?;
        let arch = audit_arch()?;
        let op = Ops::new()?;
        let off_nr: u32 = fit(offset_of!(libc::seccomp_data, nr), "offsetof(nr)")?;
        let off_arch: u32 = fit(offset_of!(libc::seccomp_data, arch), "offsetof(arch)")?;
        // `args[0]`'s low word: the first u32 of `args` on a little-endian
        // target (`audit_arch` refused every other).
        let off_arg0: u32 = fit(offset_of!(libc::seccomp_data, args), "offsetof(args)")?;
        let errno: u32 = fit(DENIED_ERRNO, "EPERM")?;
        let enosys: u32 = fit(libc::ENOSYS, "ENOSYS")?;
        let allow = libc::SECCOMP_RET_ALLOW;
        let deny = libc::SECCOMP_RET_ERRNO | (errno & libc::SECCOMP_RET_DATA);
        let unimplemented = libc::SECCOMP_RET_ERRNO | (enosys & libc::SECCOMP_RET_DATA);

        let mut p = vec![
            insn(op.ld_w_abs, 0, 0, off_arch),
            insn(op.jeq, 1, 0, arch),
            insn(op.ret, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
            insn(op.ld_w_abs, 0, 0, off_nr),
        ];
        #[cfg(target_arch = "x86_64")]
        {
            p.push(insn(op.jge, 0, 1, X32_SYSCALL_BIT));
            p.push(insn(op.ret, 0, 0, deny));
        }
        for &(name, nr, rule) in TABLE.iter().chain(derived.iter()) {
            let nr: u32 = fit(nr, name)?;
            // An argument block: nr matches, so load arg0 and test it; the
            // test either reaches the `ret deny` or jumps over it to the
            // reload of nr, so the next block sees the number again. nr does
            // not match: skip the four instructions after the first.
            let arg_block = |test: u16, deny_on_match: bool, k: u32| {
                let (jt, jf) = if deny_on_match { (0, 1) } else { (1, 0) };
                [
                    insn(op.jeq, 0, 4, nr),
                    insn(op.ld_w_abs, 0, 0, off_arg0),
                    insn(test, jt, jf, k),
                    insn(op.ret, 0, 0, deny),
                    insn(op.ld_w_abs, 0, 0, off_nr),
                ]
            };
            match rule {
                Rule::Deny => {
                    p.push(insn(op.jeq, 0, 1, nr));
                    p.push(insn(op.ret, 0, 0, deny));
                }
                Rule::Unimplemented => {
                    p.push(insn(op.jeq, 0, 1, nr));
                    p.push(insn(op.ret, 0, 0, unimplemented));
                }
                Rule::DenyWhenArg0Is(value) => {
                    p.extend(arg_block(op.jeq, true, fit(value, name)?));
                }
                Rule::DenyWhenArg0Has(bits) => {
                    p.extend(arg_block(op.jset, true, fit(bits, name)?));
                }
                Rule::DenyUnlessArg0Is(value) => {
                    p.extend(arg_block(op.jeq, false, fit(value, name)?));
                }
            }
        }
        p.push(insn(op.ret, 0, 0, allow));

        let len: u16 = fit(p.len(), "program length")?;
        if usize::from(len) > usize::try_from(libc::BPF_MAXINSNS).unwrap_or(0) {
            return Err(FilterError::Overflow("program length (BPF_MAXINSNS)"));
        }
        Ok(Self { insns: p, len })
    }

    /// The `sock_fprog` for `prctl(PR_SET_SECCOMP, ..)`. Allocates nothing, so
    /// it may run in a `pre_exec` hook.
    pub(crate) fn fprog(&mut self) -> libc::sock_fprog {
        libc::sock_fprog {
            len: self.len,
            filter: self.insns.as_mut_ptr(),
        }
    }

    #[cfg(test)]
    pub(crate) fn insns(&self) -> &[libc::sock_filter] {
        &self.insns
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis::CapabilityLevel;

    /// A classic-BPF interpreter for exactly the opcodes [`Program`] emits,
    /// run over a synthetic `seccomp_data`. It is how every table entry is
    /// checked without a kernel; the live tests (`tests/child_seccomp.rs`) are
    /// how the kernel's verdict is checked.
    fn verdict(prog: &Program, arch: u32, nr: c_long, arg0: u64) -> u32 {
        let op = Ops::new().unwrap();
        let mut data = libc::seccomp_data {
            nr: c_int::try_from(nr).unwrap(),
            arch,
            instruction_pointer: 0,
            args: [0; 6],
        };
        data.args[0] = arg0;
        let word = |off: u32| -> u32 {
            match off {
                o if o == u32::try_from(offset_of!(libc::seccomp_data, nr)).unwrap() => {
                    u32::from_ne_bytes(data.nr.to_ne_bytes())
                }
                o if o == u32::try_from(offset_of!(libc::seccomp_data, arch)).unwrap() => data.arch,
                o if o == u32::try_from(offset_of!(libc::seccomp_data, args)).unwrap() => {
                    // Low word of args[0] on a little-endian target.
                    u32::try_from(data.args[0] & 0xFFFF_FFFF).unwrap()
                }
                other => panic!("the program reads an unexpected offset {other}"),
            }
        };
        let insns = prog.insns();
        let mut acc = 0u32;
        let mut pc = 0usize;
        loop {
            let i = insns[pc];
            let jump = |taken: bool| 1 + usize::from(if taken { i.jt } else { i.jf });
            pc += if i.code == op.ld_w_abs {
                acc = word(i.k);
                1
            } else if i.code == op.jeq {
                jump(acc == i.k)
            } else if i.code == op.jset {
                jump(acc & i.k != 0)
            } else if i.code == op.ret {
                return i.k;
            } else {
                #[cfg(target_arch = "x86_64")]
                if i.code == op.jge {
                    pc += jump(acc >= i.k);
                    continue;
                }
                panic!("unexpected opcode {:#x}", i.code)
            };
        }
    }

    fn native() -> u32 {
        audit_arch().unwrap()
    }

    /// The number restated for aarch64 musl is the one glibc's libc module
    /// carries for the same kernel table.
    #[cfg(all(target_arch = "aarch64", target_env = "gnu"))]
    #[test]
    fn the_restated_kexec_file_load_is_the_kernels() {
        assert_eq!(libc::SYS_kexec_file_load, 294);
    }

    /// The derived arches equal the uapi values (`linux/audit.h`).
    #[test]
    fn the_derived_audit_arches_are_the_kernels() {
        assert_eq!(audit_arch_64le(libc::EM_X86_64), 0xC000_003E);
        assert_eq!(audit_arch_64le(libc::EM_AARCH64), 0xC000_00B7);
    }

    fn deny() -> u32 {
        libc::SECCOMP_RET_ERRNO | u32::try_from(DENIED_ERRNO).unwrap()
    }

    /// A derived policy from the two capability levels the rule reads, with
    /// no declared egress.
    fn policy(run_bash: CapabilityLevel, web_fetch: CapabilityLevel) -> SeccompPolicy {
        let caps = portcullis::CapabilityLattice {
            run_bash,
            web_fetch,
            ..portcullis::CapabilityLattice::default()
        };
        SeccompPolicy::from_capabilities(&caps, portcullis::NetworkEgress::None)
    }

    /// The policy that derives nothing: the denylist alone.
    fn nothing() -> SeccompPolicy {
        policy(CapabilityLevel::Always, CapabilityLevel::Always)
    }

    /// Every derived policy the two classes can make.
    fn every_policy() -> [SeccompPolicy; 4] {
        use CapabilityLevel::{Always, Never};
        [
            policy(Always, Always),
            policy(Never, Always),
            policy(Always, Never),
            policy(Never, Never),
        ]
    }

    const PIN: ExecPin = ExecPin(4096);

    fn program() -> Program {
        Program::workload(nothing(), None).expect("the denylist compiles for this target")
    }

    fn derived(p: SeccompPolicy) -> Program {
        Program::workload(p, Some(PIN)).expect("the derived program compiles")
    }

    /// #2907: `run_bash: never` denies `execve` whole and `execveat` on any
    /// descriptor but the pin, and the pinned one is allowed: the runtime's
    /// own start of the child.
    #[test]
    fn a_derived_exec_denial_leaves_only_the_pinned_execveat() {
        let p = derived(policy(CapabilityLevel::Never, CapabilityLevel::Always));
        assert_eq!(verdict(&p, native(), libc::SYS_execve, 0), deny());
        let pin = u64::try_from(PIN.0).unwrap();
        assert_eq!(
            verdict(&p, native(), libc::SYS_execveat, pin),
            libc::SECCOMP_RET_ALLOW
        );
        for other in [
            0,
            3,
            pin - 1,
            pin + 1,
            u64::from(libc::AT_FDCWD.cast_unsigned()),
        ] {
            assert_eq!(
                verdict(&p, native(), libc::SYS_execveat, other),
                deny(),
                "execveat({other})"
            );
        }
        // Not the socket class: an internet socket is still allowed.
        let inet = u64::try_from(libc::AF_INET).unwrap();
        assert_eq!(
            verdict(&p, native(), libc::SYS_socket, inet),
            libc::SECCOMP_RET_ALLOW
        );
    }

    /// #2907: `web_fetch: never` with no egress denies both internet families
    /// at both entry points, and the union keeps `AF_VSOCK` denied and
    /// `AF_UNIX` (the workload door) allowed.
    #[test]
    fn a_derived_socket_denial_adds_the_internet_families_to_vsock() {
        let p = derived(policy(CapabilityLevel::Always, CapabilityLevel::Never));
        for nr in [libc::SYS_socket, libc::SYS_socketpair] {
            for family in [libc::AF_INET, libc::AF_INET6, libc::AF_VSOCK] {
                let family = u64::try_from(family).unwrap();
                assert_eq!(verdict(&p, native(), nr, family), deny(), "{nr}/{family}");
            }
            for family in [libc::AF_UNIX, libc::AF_NETLINK] {
                let family = u64::try_from(family).unwrap();
                assert_eq!(
                    verdict(&p, native(), nr, family),
                    libc::SECCOMP_RET_ALLOW,
                    "{nr}/{family}"
                );
            }
        }
        assert_eq!(
            verdict(&p, native(), libc::SYS_execve, 0),
            libc::SECCOMP_RET_ALLOW
        );
    }

    /// The union, never fewer: under every derived policy, every denylist
    /// entry still answers exactly as it does alone. A derived block that
    /// allowed on a mismatch (the shape the denylist's own blocks had before
    /// #2907) would let `socket` reach its second block never, and red here.
    #[test]
    fn every_derived_policy_keeps_every_denylist_entry() {
        let base = program();
        for pol in every_policy() {
            let p = derived(pol);
            for &(name, nr, rule) in TABLE {
                let args: &[u64] = match rule {
                    Rule::DenyWhenArg0Is(v) | Rule::DenyUnlessArg0Is(v) => {
                        &[0, u64::try_from(v).unwrap()]
                    }
                    Rule::DenyWhenArg0Has(bits) => &[0, u64::try_from(bits).unwrap()],
                    Rule::Deny | Rule::Unimplemented => &[0],
                };
                for &a in args {
                    let want = verdict(&base, native(), nr, a);
                    let got = verdict(&p, native(), nr, a);
                    // Only a derived class may change an answer, and only to a denial.
                    assert!(
                        got == want || got == deny(),
                        "{name}({a:#x}) under {}: {got:#x} vs {want:#x}",
                        pol.canonical()
                    );
                    if want != libc::SECCOMP_RET_ALLOW {
                        assert_eq!(got, want, "{name}({a:#x}) under {}", pol.canonical());
                    }
                }
            }
        }
    }

    /// The derived program is monotone in the policy: a policy that denies a
    /// superset of classes answers "allow" to a subset of calls, over every
    /// call this file's tests name.
    #[test]
    fn a_tighter_policy_allows_no_call_a_looser_one_denies() {
        let pin = u64::try_from(PIN.0).unwrap();
        let calls: Vec<(c_long, u64)> = [
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_socket,
            libc::SYS_socketpair,
            libc::SYS_read,
            libc::SYS_clone,
        ]
        .into_iter()
        .flat_map(|nr| {
            [0, pin, 3]
                .into_iter()
                .chain(
                    [libc::AF_INET, libc::AF_INET6, libc::AF_UNIX, libc::AF_VSOCK]
                        .map(|f| u64::try_from(f).unwrap()),
                )
                .map(move |a| (nr, a))
        })
        .collect();
        for tight in every_policy() {
            for loose in every_policy() {
                if !tight.at_least_as_tight_as(&loose) {
                    continue;
                }
                let (pt, pl) = (derived(tight), derived(loose));
                for &(nr, a) in &calls {
                    if verdict(&pl, native(), nr, a) != libc::SECCOMP_RET_ALLOW {
                        assert_ne!(
                            verdict(&pt, native(), nr, a),
                            libc::SECCOMP_RET_ALLOW,
                            "{nr}({a}): {} allows what {} denies",
                            tight.canonical(),
                            loose.canonical()
                        );
                    }
                }
            }
        }
    }

    /// Exec denied with nothing to start the child through is a refusal,
    /// never a program without the class.
    #[test]
    fn an_exec_denial_without_a_pin_is_refused() {
        assert_eq!(
            Program::workload(
                policy(CapabilityLevel::Never, CapabilityLevel::Always),
                None
            )
            .map(drop),
            Err(FilterError::ExecWithoutPin)
        );
        // Without the class, a pin is not needed.
        assert!(
            Program::workload(
                policy(CapabilityLevel::Always, CapabilityLevel::Never),
                None
            )
            .is_ok()
        );
    }

    #[test]
    fn every_number_in_the_table_appears_once() {
        let mut seen = std::collections::BTreeSet::new();
        for &(name, nr, _) in TABLE {
            assert!(seen.insert(nr), "{name} ({nr}) is listed twice");
        }
    }

    #[test]
    fn every_unconditional_entry_is_denied_with_the_filters_errno() {
        let p = program();
        for &(name, nr, rule) in TABLE {
            match rule {
                Rule::Deny => assert_eq!(verdict(&p, native(), nr, 0), deny(), "{name}"),
                Rule::Unimplemented => assert_eq!(
                    verdict(&p, native(), nr, 0),
                    libc::SECCOMP_RET_ERRNO | u32::try_from(libc::ENOSYS).unwrap(),
                    "{name}"
                ),
                Rule::DenyWhenArg0Is(_) | Rule::DenyWhenArg0Has(_) | Rule::DenyUnlessArg0Is(_) => {}
            }
        }
    }

    #[test]
    fn a_vsock_socket_is_denied_and_every_other_family_is_not() {
        let p = program();
        let vsock = u64::try_from(libc::AF_VSOCK).unwrap();
        for nr in [libc::SYS_socket, libc::SYS_socketpair] {
            assert_eq!(verdict(&p, native(), nr, vsock), deny());
            // The kernel truncates `domain` to int: junk in the high word
            // still means AF_VSOCK, and is still denied.
            assert_eq!(verdict(&p, native(), nr, vsock | 0xdead_0000_0000), deny());
            for family in [
                libc::AF_UNIX,
                libc::AF_INET,
                libc::AF_INET6,
                libc::AF_NETLINK,
            ] {
                let family = u64::try_from(family).unwrap();
                assert_eq!(verdict(&p, native(), nr, family), libc::SECCOMP_RET_ALLOW);
            }
        }
    }

    #[test]
    fn clone_with_any_new_namespace_is_denied_and_fork_and_threads_are_not() {
        let p = program();
        for flag in [
            libc::CLONE_NEWNS,
            libc::CLONE_NEWCGROUP,
            libc::CLONE_NEWUTS,
            libc::CLONE_NEWIPC,
            libc::CLONE_NEWUSER,
            libc::CLONE_NEWPID,
            libc::CLONE_NEWNET,
        ] {
            let flags = u64::try_from(flag | libc::SIGCHLD).unwrap();
            assert_eq!(
                verdict(&p, native(), libc::SYS_clone, flags),
                deny(),
                "{flag:#x}"
            );
        }
        let fork = libc::SIGCHLD;
        let vfork = libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD;
        let thread = libc::CLONE_VM
            | libc::CLONE_FS
            | libc::CLONE_FILES
            | libc::CLONE_SIGHAND
            | libc::CLONE_THREAD
            | libc::CLONE_SYSVSEM
            | libc::CLONE_SETTLS
            | libc::CLONE_PARENT_SETTID
            | libc::CLONE_CHILD_CLEARTID;
        for flags in [fork, vfork, thread] {
            let flags = u64::try_from(flags).unwrap();
            assert_eq!(
                verdict(&p, native(), libc::SYS_clone, flags),
                libc::SECCOMP_RET_ALLOW,
                "{flags:#x}"
            );
        }
    }

    #[test]
    fn ordinary_calls_are_allowed() {
        let p = program();
        for nr in [
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_openat,
            libc::SYS_close,
            libc::SYS_execve,
            libc::SYS_connect,
            libc::SYS_wait4,
            libc::SYS_exit_group,
        ] {
            assert_eq!(
                verdict(&p, native(), nr, 0),
                libc::SECCOMP_RET_ALLOW,
                "{nr}"
            );
        }
    }

    #[test]
    fn a_foreign_abi_is_killed() {
        let p = program();
        // 32-bit ARM and i386 (`EM_* | __AUDIT_ARCH_LE`, no 64-bit bit),
        // and the other 64-bit arch.
        let arm = u32::from(libc::EM_ARM) | AUDIT_ARCH_LE;
        let i386 = u32::from(libc::EM_386) | AUDIT_ARCH_LE;
        let other64 = if cfg!(target_arch = "x86_64") {
            audit_arch_64le(libc::EM_AARCH64)
        } else {
            audit_arch_64le(libc::EM_X86_64)
        };
        for arch in [arm, i386, other64, 0] {
            assert_eq!(
                verdict(&p, arch, libc::SYS_read, 0),
                libc::SECCOMP_RET_KILL_PROCESS,
                "{arch:#x}"
            );
        }
    }

    /// x32 shares x86_64's audit arch; without this rule `ptrace | X32_BIT`
    /// would match no table entry and be allowed.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn an_x32_number_is_denied() {
        let p = program();
        let x32_ptrace = libc::SYS_ptrace | c_long::from(X32_SYSCALL_BIT);
        assert_eq!(verdict(&p, native(), x32_ptrace, 0), deny());
    }
}
