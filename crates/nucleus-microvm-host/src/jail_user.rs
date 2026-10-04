//! The unprivileged principal a jailed VMM drops to: the jail user.
//!
//! Two programs have to agree on it. The node drops each pod's Firecracker to
//! it, and refuses a written-through disk the jail user cannot already read and
//! write (#3152: it no longer chowns a placed file, because a hard link is the
//! caller's own inode). `nucleus-hostctl seed` makes exactly that disk, so it
//! must hand the disk to the same principal.
//!
//! The node decides the value (`--jailer-uid` / `--jailer-gid`); nothing here
//! restates it. What is written once, here, is the type and the environment
//! variables the value is read from, so `seed` run beside a node reads the
//! node's own configuration rather than a second copy of the number (ADR 0007
//! G-1).

use std::num::NonZeroU32;

/// Where the node, and `seed`, read the jail user's uid from.
pub const UID_ENV: &str = "NUCLEUS_JAILER_UID";
/// Where the node, and `seed`, read the jail user's gid from.
pub const GID_ENV: &str = "NUCLEUS_JAILER_GID";

/// The uid/gid the jailed VMM drops to: the principal every jail-ownership
/// check is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JailUser {
    pub uid: u32,
    pub gid: u32,
}

/// A jailer uid that cannot represent root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonRootUid(NonZeroU32);

impl NonRootUid {
    pub fn new(uid: u32) -> Result<Self, &'static str> {
        NonZeroU32::new(uid)
            .map(Self)
            .ok_or("JailerRootUid: jailer uid must not be zero")
    }

    pub fn get(self) -> u32 {
        self.0.get()
    }
}

impl std::str::FromStr for NonRootUid {
    type Err = String;
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let uid = value.parse::<u32>().map_err(|e| e.to_string())?;
        Self::new(uid).map_err(str::to_owned)
    }
}

impl std::fmt::Display for NonRootUid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.get().fmt(f)
    }
}
