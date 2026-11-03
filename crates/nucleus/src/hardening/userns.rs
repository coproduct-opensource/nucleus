//! The separated bare tier's child-side step (Program C, C2): enter a user
//! namespace whose only mapping is the child's subordinate host ids, and
//! confirm it. See `subordinate.rs` for the contract this realizes.
//!
//! Everything here runs in the forked child between fork and exec, so it is
//! async-signal-safe: `rustix`'s raw syscalls on descriptors and buffers this
//! process already owns, no allocation, no lock. Nothing here is `unsafe`.
//! The three calls that must be (`fork`, `unshare`, `execve`) and the ambient
//! clear are made in `imp::harden_child`'s one audited block, which calls the
//! steps below in order:
//!
//! 1. [`go_pipe`]: a close-on-exec pipe;
//! 2. per helper, `fork`; the helper runs [`Go::wait`] and
//!    [`helper_argv`], then `execve`s `newuidmap` / `newgidmap` on its parent;
//! 3. `unshare(CLONE_NEWUSER)`;
//! 4. [`finish`]: release (or abandon) the helpers, reap them, drop the
//!    supplementary groups and become the subordinate gid and uid;
//! 5. clear the ambient capabilities;
//! 6. [`confirm`]: both maps read back as exactly `id id 1`.
//!
//! The helpers are forked BEFORE the `unshare`, so they stay in the parent's
//! user namespace, where the setuid helpers have the privilege to write the
//! maps. A helper that reads EOF instead of its byte exits without mapping.

use std::ffi::{CStr, CString};
use std::io;

use rustix::fd::OwnedFd;
use rustix::process::{Pid, WaitOptions};

use super::SubordinateIds;

/// The one-id maps of a subordinate child, prepared in the parent:
/// `<helper> <pid> <id> <id> 1` for `newuidmap` and `newgidmap`. The pid slot
/// (index 1) is filled by each helper in its own stack ([`helper_argv`]),
/// since the child's pid is known only after the fork.
pub(super) struct UserNsMap {
    uid: u32,
    gid: u32,
    /// Kept alive for the addresses below; a `CString`'s heap buffer does
    /// not move when the struct does.
    _uid: CString,
    _gid: CString,
    /// NUL-terminated pointer arrays held as addresses, so the closure is
    /// `Send + Sync` (as `PinnedExec` does).
    argvs: [[usize; 6]; 2],
}

impl UserNsMap {
    pub(super) fn prepare(ids: SubordinateIds) -> Self {
        let helpers = ids.helpers();
        let digits = |id: u32| CString::new(id.to_string()).unwrap_or_default();
        let (uid, gid) = (digits(ids.uid()), digits(ids.gid()));
        let one = c"1".as_ptr() as usize;
        let argv = |helper: &CStr, id: &CString| {
            let id = id.as_ptr() as usize;
            [helper.as_ptr() as usize, 0, id, id, one, 0]
        };
        Self {
            uid: ids.uid(),
            gid: ids.gid(),
            argvs: [argv(helpers.uidmap, &uid), argv(helpers.gidmap, &gid)],
            _uid: uid,
            _gid: gid,
        }
    }

    /// The two helpers' argv templates, `newuidmap` first.
    pub(super) fn argvs(&self) -> &[[usize; 6]; 2] {
        &self.argvs
    }
}

/// The pipe the helpers wait on: one byte each, written only after the
/// `unshare` succeeded.
pub(super) struct Go {
    read: OwnedFd,
    write: Option<OwnedFd>,
}

/// Step 1: the helpers' pipe, close-on-exec.
pub(super) fn go_pipe() -> io::Result<Go> {
    let (read, write) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC)?;
    Ok(Go {
        read,
        write: Some(write),
    })
}

impl Go {
    /// In a helper: close this copy's write end (so the hook's own close is
    /// an EOF here), then wait for one byte. `false` on EOF or an error.
    pub(super) fn wait(&mut self) -> bool {
        drop(self.write.take());
        let mut byte = [0u8; 1];
        loop {
            match rustix::io::read(&self.read, &mut byte) {
                Ok(1) => return true,
                Err(rustix::io::Errno::INTR) => {}
                Ok(_) | Err(_) => return false,
            }
        }
    }
}

/// In a helper: its argv, with its parent's (the child's) pid in slot 1,
/// written in decimal into `digits`. `None` when the parent is gone.
pub(super) fn helper_argv(template: &[usize; 6], digits: &mut [u8; 16]) -> Option<[usize; 6]> {
    let parent = u32::try_from(Pid::as_raw(rustix::process::getppid())).ok()?;
    if parent <= 1 {
        return None;
    }
    let mut argv = *template;
    argv[1] = decimal(parent, digits);
    Some(argv)
}

/// `n` in decimal, NUL-terminated, at the end of `buf`; the address of its
/// first digit.
fn decimal(mut n: u32, buf: &mut [u8; 16]) -> usize {
    let mut i = buf.len() - 1;
    buf[i] = 0;
    loop {
        i -= 1;
        buf[i] = b'0' + u8::try_from(n % 10).unwrap_or(0);
        n /= 10;
        if n == 0 {
            break;
        }
    }
    buf[i..].as_ptr() as usize
}

/// Step 4: release the helpers if the namespace exists (else abandon them,
/// which they read as EOF), reap both (each must exit 0), then drop every
/// supplementary group (host credentials the namespace does not map, which
/// file access would still use) and become the subordinate gid and uid.
pub(super) fn finish(
    map: &UserNsMap,
    mut go: Go,
    helpers: [Option<i32>; 2],
    unshared: io::Result<()>,
) -> io::Result<()> {
    drop(go.read);
    let released = match (&unshared, go.write.take()) {
        (Ok(()), Some(write)) => rustix::io::write(&write, &[1u8; 2]).map(|n| n == 2),
        (Ok(()) | Err(_), _) => Ok(false),
    };
    let mut mapped = true;
    for pid in helpers.into_iter().flatten() {
        let Some(pid) = Pid::from_raw(pid) else {
            mapped = false;
            continue;
        };
        let exited = loop {
            match rustix::process::waitpid(Some(pid), WaitOptions::empty()) {
                Err(rustix::io::Errno::INTR) => {}
                other => break other,
            }
        };
        match exited {
            Ok(Some((_, status))) if status.exit_status() == Some(0) => {}
            Ok(_) | Err(_) => mapped = false,
        }
    }
    unshared?;
    if !released? || !mapped {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    rustix::thread::set_thread_groups(&[])?;
    let gid = rustix::process::Gid::from_raw(map.gid);
    rustix::thread::set_thread_res_gid(gid, gid, gid)?;
    let uid = rustix::process::Uid::from_raw(map.uid);
    rustix::thread::set_thread_res_uid(uid, uid, uid)?;
    Ok(())
}

/// Step 6: the realization, read back rather than assumed. Each map must be
/// exactly `id id 1` ([`super::map_is_exactly`]), so this process is the
/// subordinate id on the host and nothing else is mapped.
pub(super) fn confirm(map: &UserNsMap) -> io::Result<()> {
    if map_reads_exactly(c"/proc/self/uid_map", map.uid)
        && map_reads_exactly(c"/proc/self/gid_map", map.gid)
    {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(libc::EPERM))
    }
}

fn map_reads_exactly(path: &CStr, id: u32) -> bool {
    use rustix::fs::{Mode, OFlags};
    let Ok(fd) = rustix::fs::open(path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()) else {
        return false;
    };
    let mut buf = [0u8; 256];
    match rustix::io::read(&fd, &mut buf) {
        Ok(n) if n < buf.len() => super::map_is_exactly(&buf[..n], id),
        Ok(_) | Err(_) => false,
    }
}
