//! Starting a child whose policy denies exec (#2907).
//!
//! A pod whose lattice says `run_bash: never` has its children's `execve`
//! denied by the syscall filter (`seccomp.rs`, `SyscallClass::Exec`). The
//! filter is installed in the `pre_exec` hook, BEFORE the child's own exec, so
//! std's `execvp` would be denied too and the child could never start.
//!
//! The hook therefore starts the child itself, with one `execveat` on a
//! descriptor the parent opened: the [`PinnedExec`]. The filter allows
//! `execveat` on exactly that descriptor number and on no other, and the
//! number is chosen at or above the child's `RLIMIT_NOFILE`, which the hook
//! sets (soft and hard) before the filter. The descriptor is close-on-exec, so
//! after this one exec no process under the filter can hold that number again
//! (see `seccomp.rs`'s module docs for why each route to it is closed).
//!
//! Everything here allocates, so it runs in the PARENT, before the fork. The
//! child only reads [`PinnedExec::execveat_args`] and makes one raw syscall,
//! in the hook's audited `unsafe` block. Nothing in this file is `unsafe`.
//!
//! # What the parent decides
//!
//! * The program, resolved the way `execvp` would: as given when it contains a
//!   `/` (relative to the command's working directory), otherwise the first
//!   executable regular file of that name on the declared `PATH`.
//! * The argv: the program as given, then the command's arguments.
//! * The environment: exactly what the command declared. The command's
//!   inheritance is cleared here so std's view and the pinned exec's agree;
//!   both callers (the workload launch and the Executor) already clear it.
//! * A `#!` script is refused by name. The kernel would run its interpreter
//!   with the script as `/dev/fd/<n>`, which the close-on-exec pin has closed,
//!   and an interpreter that runs anything else is denied by the same filter.

use std::ffi::{CString, OsStr};
use std::io::{self, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use libc::c_int;

use super::seccomp::ExecPin;

/// `execvp`'s search path when the environment names none (musl's and
/// glibc's default).
const DEFAULT_PATH: &[u8] = b"/usr/local/bin:/bin:/usr/bin";

/// A child's one sanctioned exec, prepared in the parent.
pub(crate) struct PinnedExec {
    /// The program, opened `O_PATH | O_CLOEXEC`, at a number at or above the
    /// child's `RLIMIT_NOFILE`.
    fd: OwnedFd,
    /// Kept alive for the addresses below.
    _argv: Vec<CString>,
    _envp: Vec<CString>,
    /// NUL-terminated pointer arrays, held as addresses so this value is
    /// `Send + Sync` (a `pre_exec` closure must be). Each address points into
    /// a `CString` above, whose heap buffer does not move.
    argv: Vec<usize>,
    envp: Vec<usize>,
}

impl PinnedExec {
    /// Resolve and open `cmd`'s program and freeze its argv and environment,
    /// with the descriptor placed at or above `nofile`, the limit the hook
    /// will set.
    ///
    /// # Errors
    /// The program cannot be found or opened, is a `#!` script, an argument
    /// or variable holds a NUL, `nofile` is not a descriptor number, or the
    /// runtime cannot make room for a descriptor that high.
    pub(crate) fn prepare(cmd: &mut std::process::Command, nofile: u64) -> io::Result<Self> {
        let floor = c_int::try_from(nofile).map_err(|_| {
            io::Error::other(format!("RLIMIT_NOFILE {nofile} is not a descriptor number"))
        })?;
        let program = cmd.get_program().to_owned();
        let envs: Vec<(std::ffi::OsString, std::ffi::OsString)> = cmd
            .get_envs()
            .filter_map(|(k, v)| v.map(|v| (k.to_owned(), v.to_owned())))
            .collect();
        cmd.env_clear();
        for (k, v) in &envs {
            cmd.env(k, v);
        }
        let path_env = envs
            .iter()
            .find(|(k, _)| k.as_bytes() == b"PATH")
            .map(|(_, v)| v.as_os_str());
        let path = resolve(&program, cmd.get_current_dir(), path_env)?;
        refuse_script(&path)?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open(&path)?;
        let fd = dup_at_or_above(&file, floor)?;

        let cstring = |bytes: &[u8]| {
            CString::new(bytes).map_err(|_| io::Error::other("an argument or variable holds a NUL"))
        };
        let argv: Vec<CString> = std::iter::once(program.as_os_str())
            .chain(cmd.get_args())
            .map(|a| cstring(a.as_bytes()))
            .collect::<io::Result<_>>()?;
        let envp: Vec<CString> = envs
            .iter()
            .map(|(k, v)| cstring(&[k.as_bytes(), b"=", v.as_bytes()].concat()))
            .collect::<io::Result<_>>()?;
        let addrs = |v: &[CString]| -> Vec<usize> {
            v.iter()
                .map(|c| c.as_ptr().addr())
                .chain(std::iter::once(0))
                .collect()
        };
        Ok(Self {
            argv: addrs(&argv),
            envp: addrs(&envp),
            fd,
            _argv: argv,
            _envp: envp,
        })
    }

    /// The descriptor number the filter pins `execveat` to.
    pub(crate) fn pin(&self) -> ExecPin {
        ExecPin(self.fd.as_raw_fd())
    }

    /// What the child's `execveat` takes: the pinned descriptor and the
    /// NUL-terminated argv and envp arrays (as addresses of `CString`s this
    /// value keeps alive). Allocates nothing, so the hook may call it; the
    /// syscall itself is in the hook's one audited `unsafe` block.
    pub(crate) fn execveat_args(&self) -> (c_int, *const usize, *const usize) {
        (self.fd.as_raw_fd(), self.argv.as_ptr(), self.envp.as_ptr())
    }
}

/// `execvp`'s resolution, done in the parent.
fn resolve(program: &OsStr, cwd: Option<&Path>, path_env: Option<&OsStr>) -> io::Result<PathBuf> {
    let p = Path::new(program);
    if program.as_bytes().contains(&b'/') {
        return Ok(match cwd {
            Some(dir) if p.is_relative() => dir.join(p),
            Some(_) | None => p.to_path_buf(),
        });
    }
    let search = path_env.map_or(DEFAULT_PATH, OsStrExt::as_bytes);
    for dir in search.split(|b| *b == b':') {
        let dir = if dir.is_empty() {
            Path::new(".")
        } else {
            Path::new(OsStr::from_bytes(dir))
        };
        let candidate = dir.join(p);
        let candidate = match (cwd, candidate.is_relative()) {
            (Some(c), true) => c.join(candidate),
            (Some(_) | None, _) => candidate,
        };
        if std::fs::metadata(&candidate)
            .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        {
            return Ok(candidate);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "{} is not an executable file on the declared PATH",
            p.display()
        ),
    ))
}

/// A `#!` script cannot be started through the pin (module docs).
/// Unreadable is not refused here: the exec itself checks permission.
fn refuse_script(path: &Path) -> io::Result<()> {
    let mut magic = [0u8; 2];
    let is_script = std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .is_ok()
        && magic == *b"#!";
    if is_script {
        return Err(io::Error::other(format!(
            "{} is a #! script; under a policy that denies exec (run_bash: never) the program \
             must be one the kernel loads directly — name the interpreter as the command",
            path.display()
        )));
    }
    Ok(())
}

/// Concurrent spawns each hold a pin until their `spawn` returns, so the
/// runtime keeps room for this many above the floor.
const PIN_ROOM: u64 = 1024;

/// Duplicate `file` close-on-exec at the lowest free number at or above
/// `floor`, first raising this process's own `RLIMIT_NOFILE` to leave
/// [`PIN_ROOM`] numbers above `floor` (a root runtime may raise the hard
/// limit; any runtime may raise the soft one up to it). Through `rustix`, so
/// no `unsafe` here.
fn dup_at_or_above(file: &std::fs::File, floor: c_int) -> io::Result<OwnedFd> {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
    let need = u64::try_from(floor)
        .map_err(|_| io::Error::other("negative descriptor floor"))?
        .saturating_add(1);
    let room = need.saturating_add(PIN_ROOM);
    let now = getrlimit(Resource::Nofile);
    // `None` is RLIM_INFINITY.
    let (cur, max) = (
        now.current.unwrap_or(u64::MAX),
        now.maximum.unwrap_or(u64::MAX),
    );
    if cur < room {
        // The full room, raising the hard limit if this runtime may;
        // failing that, everything the hard limit already allows.
        let full = Rlimit {
            current: Some(room),
            maximum: Some(max.max(room)),
        };
        let up_to_hard = Rlimit {
            current: now.maximum,
            maximum: now.maximum,
        };
        let raised = setrlimit(Resource::Nofile, full).or_else(|e| {
            if max >= need {
                setrlimit(Resource::Nofile, up_to_hard)
            } else {
                Err(e)
            }
        });
        if let Err(e) = raised {
            return Err(io::Error::other(format!(
                "the runtime cannot hold a descriptor at {floor} (RLIMIT_NOFILE {cur}/{max}): {e}"
            )));
        }
    }
    Ok(rustix::io::fcntl_dupfd_cloexec(file, floor)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_program_with_a_slash_is_taken_as_given_relative_to_the_cwd() {
        let cwd = Path::new("/work");
        assert_eq!(
            resolve(OsStr::new("/bin/sh"), Some(cwd), None).unwrap(),
            PathBuf::from("/bin/sh")
        );
        assert_eq!(
            resolve(OsStr::new("./x"), Some(cwd), None).unwrap(),
            PathBuf::from("/work/./x")
        );
    }

    #[test]
    fn a_bare_name_is_searched_on_the_declared_path_only() {
        let sh = resolve(
            OsStr::new("sh"),
            None,
            Some(OsStr::new("/nonexistent:/bin")),
        );
        assert_eq!(sh.unwrap(), PathBuf::from("/bin/sh"));
        let missing = resolve(OsStr::new("sh"), None, Some(OsStr::new("/nonexistent")));
        assert_eq!(missing.unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn a_script_is_refused_by_name_and_a_binary_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("s");
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
        let err = refuse_script(&script).unwrap_err().to_string();
        assert!(err.contains("#! script"), "{err}");
        let me = std::env::current_exe().unwrap();
        refuse_script(&me).expect("an ELF test binary is not a script");
    }

    /// The pin lands at or above the floor, and the environment the exec
    /// gets is exactly the declared one, inheritance cleared.
    #[test]
    fn the_pin_is_at_or_above_the_floor_and_the_env_is_the_declared_one() {
        let mut cmd = std::process::Command::new("/bin/true");
        cmd.arg("x").env("A", "1");
        let pinned = PinnedExec::prepare(&mut cmd, 1500).expect("prepare");
        assert!(pinned.pin().0 >= 1500, "{:?}", pinned.pin());
        assert_eq!(pinned.argv.len(), 3, "program, one argument, NUL");
        assert_eq!(pinned.envp.len(), 2, "one variable, NUL");
        let envs: Vec<_> = cmd.get_envs().collect();
        assert_eq!(envs, [(OsStr::new("A"), Some(OsStr::new("1")))]);
    }
}
