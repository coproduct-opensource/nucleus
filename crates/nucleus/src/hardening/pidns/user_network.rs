//! The workload's private user and network namespace, inside its own PID
//! namespace: the parent's preparation and the workload's half of the map
//! exchange (the init's half is in `pidns::enter`, beside the rest of it).
//!
//! The order and why it is this one, and what a receipt then claims, are in
//! `docs/findings/workload-user-network-namespace.md`. In short: the workload,
//! dropped, unshares a user and a network namespace (`pidns::enter`); here it
//! asks the init for its map, reads the map back from the kernel, and sheds
//! every capability. Each step takes the previous one's value
//! ([`super::Unshared`] → [`super::Mapped`] → [`super::Placed`]), so none can
//! run out of order (ADR 0007 D-1).
//!
//! No `unsafe` here: the exchange, the read-back and the capability calls are
//! `rustix`'s safe wrappers, which allocate nothing and take no lock, so they
//! keep the `pre_exec` contract.

use std::ffi::CStr;
use std::io;

/// The workload's one request: "map me".
pub(super) const REQUEST: u8 = b'm';
/// The init wrote the map.
pub(super) const GRANTED: u8 = b'g';
/// The init refused: the namespace was not the outer uid's, or a write failed.
pub(super) const REFUSED: u8 = b'r';

/// One workload's map, prepared in the parent: the outer uid, the inner uid
/// and the line `inner outer 1` the init writes to `uid_map` and `gid_map`,
/// formatted here, never after the fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::hardening) struct Mapping {
    outer: u32,
    inner: u32,
    loopback: bool,
    line: [u8; 32],
    len: usize,
}

impl Mapping {
    /// The map of `inner` onto `outer`, with `lo` raised or not.
    pub(in crate::hardening) fn new(outer: u32, inner: u32, loopback: bool) -> Self {
        // At most "4294967295 4294967295 1\n", 24 bytes.
        let text = format!("{inner} {outer} 1\n");
        let mut line = [0; 32];
        line[..text.len()].copy_from_slice(text.as_bytes());
        Self {
            outer,
            inner,
            loopback,
            line,
            len: text.len(),
        }
    }

    pub(super) fn outer(&self) -> u32 {
        self.outer
    }

    pub(super) fn loopback(&self) -> bool {
        self.loopback
    }

    pub(super) fn line(&self) -> &[u8] {
        &self.line[..self.len]
    }
}

impl super::Inside for Mapping {
    type Entered = super::Unshared;
    fn mapping(&self) -> Option<&Mapping> {
        Some(self)
    }
    fn entered(self, channel: Option<std::os::fd::OwnedFd>) -> io::Result<super::Unshared> {
        channel
            .map(|channel| super::Unshared {
                channel,
                mapping: self,
            })
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))
    }
}

impl super::Unshared {
    /// Ask the init for the map, and believe it only once the kernel shows it:
    /// `uid_map` and `gid_map` each exactly `inner outer 1`, `setgroups`
    /// denied, and the real and effective uid and gid `inner`.
    ///
    /// # Errors
    /// `EPIPE` when the init is gone (on the request, or no answer: the
    /// closed-mapper refusal), `EACCES` when it refused or the kernel's
    /// answer is not the map asked for, or the errno of a read.
    pub(in crate::hardening) fn map(self) -> io::Result<super::Mapped> {
        let Self { channel, mapping } = self;
        // std reset SIGPIPE before this hook: a closed channel must come
        // back as an error through std's status pipe, not kill the child.
        if rustix::net::send(&channel, &[REQUEST], rustix::net::SendFlags::NOSIGNAL)? != 1 {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        let mut answer = [0u8; 1];
        let read = loop {
            match rustix::io::read(&channel, &mut answer) {
                Err(rustix::io::Errno::INTR) => {}
                other => break other,
            }
        }?;
        drop(channel);
        match (read, answer[0]) {
            (1, GRANTED) => {}
            (1, _) => return Err(io::Error::from_raw_os_error(libc::EACCES)),
            _ => return Err(io::Error::from_raw_os_error(libc::EPIPE)),
        }
        let mut buf = [0u8; 128];
        let expected = Some((mapping.inner, mapping.outer, 1));
        for map in [c"/proc/self/uid_map", c"/proc/self/gid_map"] {
            let len = read_small(map, &mut buf)?;
            if parse_map(&buf[..len]) != expected {
                return Err(io::Error::from_raw_os_error(libc::EACCES));
            }
        }
        let len = read_small(c"/proc/self/setgroups", &mut buf)?;
        let ids = [
            rustix::process::getuid().as_raw(),
            rustix::process::geteuid().as_raw(),
            rustix::process::getgid().as_raw(),
            rustix::process::getegid().as_raw(),
        ];
        if buf[..len].trim_ascii() != b"deny" || ids.iter().any(|&id| id != mapping.inner) {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        Ok(super::Mapped { _sealed: () })
    }
}

impl super::Mapped {
    /// Lock `SECBIT_NOROOT`, so an exec at inner uid 0 gains nothing, then
    /// clear the ambient, effective, permitted and inheritable sets, and read
    /// them back empty.
    ///
    /// # Errors
    /// The kernel's errno, or `EACCES` when the read-back is not empty.
    pub(in crate::hardening) fn shed_capabilities(self) -> io::Result<super::Placed> {
        use rustix::thread::{CapabilitiesSecureBits as Bits, CapabilitySet, CapabilitySets};
        let locked = Bits::NO_ROOT | Bits::NO_ROOT_LOCKED;
        rustix::thread::set_capabilities_secure_bits(locked)?;
        rustix::thread::clear_ambient_capability_set()?;
        rustix::thread::set_capabilities(
            None,
            CapabilitySets {
                effective: CapabilitySet::empty(),
                permitted: CapabilitySet::empty(),
                inheritable: CapabilitySet::empty(),
            },
        )?;
        let held = rustix::thread::capabilities(None)?;
        if !held.effective.is_empty()
            || !held.permitted.is_empty()
            || !held.inheritable.is_empty()
            || !rustix::thread::capabilities_secure_bits()?.contains(locked)
        {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        Ok(super::Placed { _sealed: () })
    }
}

/// A small `/proc` file into `buf`, without allocating. `EFBIG` when it does
/// not fit: a map longer than one line is not the map asked for.
fn read_small(path: &CStr, buf: &mut [u8; 128]) -> io::Result<usize> {
    use rustix::fs::{Mode, OFlags};
    let file = rustix::fs::open(path, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())?;
    let mut len = 0;
    loop {
        let Some(rest) = buf.get_mut(len..).filter(|rest| !rest.is_empty()) else {
            return Err(io::Error::from_raw_os_error(libc::EFBIG));
        };
        match rustix::io::read(&file, rest) {
            Ok(0) => return Ok(len),
            Ok(n) => len += n,
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(e.into()),
        }
    }
}

/// One `uid_map`/`gid_map` entry, `inside outside count`, and nothing else.
/// The kernel pads each field (`%10u`), and an unmapped namespace's map is
/// empty, which is `None`.
fn parse_map(bytes: &[u8]) -> Option<(u32, u32, u32)> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut fields = text.split_ascii_whitespace().map(str::parse::<u32>);
    let entry = (
        fields.next()?.ok()?,
        fields.next()?.ok()?,
        fields.next()?.ok()?,
    );
    fields.next().is_none().then_some(entry)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parent formats exactly one line, for any pair of ids.
    #[test]
    fn the_map_is_one_line_formatted_in_the_parent() {
        for (outer, inner) in [(65534, 0), (65534, 1001), (u32::MAX - 1, u32::MAX - 1)] {
            let mapping = Mapping::new(outer, inner, true);
            assert_eq!(mapping.line(), format!("{inner} {outer} 1\n").as_bytes());
            assert_eq!((mapping.outer(), mapping.loopback()), (outer, true));
        }
    }

    /// The read-back accepts the kernel's padded single entry and nothing
    /// else: not an empty (unmapped) map, not a second entry, not a short one.
    #[test]
    fn the_read_back_accepts_exactly_one_entry() {
        assert_eq!(
            parse_map(b"         0      65534          1\n"),
            Some((0, 65534, 1))
        );
        assert_eq!(parse_map(b"1001 65534 1\n"), Some((1001, 65534, 1)));
        for bad in [
            &b""[..],
            b"0 65534\n",
            b"0 65534 1\n1 100000 1\n",
            b"0 65534 x\n",
            b"\xff",
        ] {
            assert_eq!(parse_map(bad), None, "{bad:?}");
        }
    }
}
