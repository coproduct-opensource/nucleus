//! What a child of this proxy can reach (#3454, #3461).
//!
//! The proxy's children are every `/v1/run` command, the pod's workload and its companion.
//! Landlock does not hold them off the proxy's own files: the child ruleset
//! is the guest layout's, and it applies only under `MicroVM`. What does
//! hold them off is the uid, together with what the proxy did to itself:
//!
//! * A child at **another uid** (a root runtime drops every child) can still
//!   reach a held file. It can own the file or a directory above it. It can
//!   reach it through group or other bits. It can be the uid that
//!   `--peer-uids` admits on the front door.
//! * A child at **the proxy's own uid** (the declared bare host tier, or a
//!   `Restricted` child of a non-root runtime) can open every file the proxy
//!   can. It can also open `/proc/<proxy>/environ`, unless the runtime sealed
//!   itself (`nucleus::seal_runtime`).
//! * **Any** process on the host can read `/proc/<proxy>/cmdline`, so a
//!   secret passed as a flag is reachable by every child, whatever its uid.
//!
//! [`ChildReach`] is the one decider of those questions (ADR 0007 G-1). It
//! answers them for the uids the spawn deciders give the children, not for a
//! restatement of those uids. [`ChildReach::admit`] refuses, by name, the
//! first held item a child could reach. The census of what is held is
//! `secret_census::held`.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nucleus::{ChildUid, EnvironmentReach, RuntimeSeal};

/// Who this proxy's children run as, asked of the deciders their spawns ask
/// (#3454, ADR 0007 G-1): `ChildConfinement::for_containment` for every
/// `/v1/run` child and `ChildConfinement::workload` for the pod's workload and its companion,
/// with the inputs the spawns pass. Evidence (C-1): minted only by
/// [`Self::of`], so a held item is checked against the uids the children
/// get, not against a restatement of them.
pub(crate) struct ChildReach {
    children: Vec<ChildUid>,
}

/// Why the proxy holds something, which decides what a child must not do to
/// it and whether the bare host tier may hold it at all. No `_` arm reads
/// this (B-3): a new class must say both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Exposure {
    /// Reading it grants authority beyond this session: a private key, a
    /// shared secret, a bearer credential. No separated child may read or
    /// replace it. On the bare host tier: in the environment only while the
    /// runtime is sealed; on the command line never; in a launcher's file as
    /// the named, declared exposure (see `bare_tier_may_hold`).
    Secret,
    /// Authority that outlives this process: a ledger, a replay record, a
    /// journal, trust roots. No child may write or replace it. The bare host
    /// tier may not hold one at all.
    Durable,
    /// This session's own records and startup inputs: the spec, the audit
    /// log, the announce file. No separated child may write or replace them.
    /// On the bare host tier they are the declared exposure that
    /// `--unsandboxed` names: a child at the proxy's own uid writes what the
    /// proxy writes.
    Session,
}

/// Where a held item lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum At {
    /// A file or directory (it may not exist yet; the proxy creates it).
    Path(PathBuf),
    /// This process's environment, under the item's name.
    Env,
    /// This process's command line, as the item's flag.
    Argv,
    /// A uid that `--listen-unix` admits besides the proxy's own.
    FrontDoorPeer(u32),
}

/// One thing the proxy holds or reads, by the name an operator gave it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Held {
    /// The flag or environment variable that names it.
    pub(crate) name: &'static str,
    pub(crate) exposure: Exposure,
    pub(crate) at: At,
}

impl ChildReach {
    pub(crate) fn of(
        workload: Option<&nucleus_spec::WorkloadSpec>,
        containment: nucleus::ContainmentMode,
        opt_in: nucleus::UnsandboxedOptIn,
        landlock: nucleus::LandlockWaiver,
    ) -> Self {
        let run = nucleus::ChildConfinement::for_containment(containment, opt_in, landlock);
        let decide = |uid| nucleus::ChildConfinement::workload(containment, uid, opt_in, landlock);
        // The workload, and its companion (#3430), admitted by the same
        // decider with `Some(companion.uid)` (`WorkloadLaunch::companion`).
        let companion = workload
            .and_then(|w| w.companion.as_ref())
            .map(|c| decide(Some(c.uid)));
        let workload = workload.map(|w| decide(w.uid));
        // A refusal is not a lookup that failed (A-1): the spawn asks the same
        // decider with the same inputs and is refused by it, so that child
        // never exists and reaches nothing.
        let children = std::iter::once(run)
            .chain(workload)
            .chain(companion)
            .filter_map(Result::ok)
            .map(|c| c.child_uid())
            .collect();
        Self { children }
    }

    /// Children that run as exactly these uids (the tests).
    #[cfg(test)]
    pub(crate) fn for_test(children: Vec<ChildUid>) -> Self {
        Self { children }
    }

    /// Refuse, by name, a journal part (`what`) owned by `owner` that a child
    /// could reach: any child at the runtime's own uid (it can open the
    /// journal outright), or a child that is `owner` (owning the directory it
    /// can unlink or replace the journal; owning the file it can read it).
    /// The journal checks its own mode is private before it asks, so this is
    /// [`Self::admit`]'s rule for a `Durable` path with the mode bits already
    /// settled. No `_` arm (B-3): a new `ChildUid` must say what it reaches.
    pub(crate) fn excludes(&self, what: &str, owner: u32) -> Result<(), String> {
        for child in &self.children {
            match *child {
                ChildUid::SharedWithRuntime => {
                    return Err(
                        "a child of this proxy runs at the proxy's own uid (the bare host tier), \
                         so it could read and append the journal directly; persistent memory \
                         requires children separated from the proxy's uid"
                            .into(),
                    );
                }
                ChildUid::Distinct(uid) if uid == owner => {
                    return Err(format!(
                        "the journal's {what} is owned by uid {uid}, which a child of this proxy \
                         runs as, so that child could replace or read the journal"
                    ));
                }
                ChildUid::Distinct(_) => {}
            }
        }
        Ok(())
    }

    /// Refuse, by name, the first held item a child of this proxy could
    /// reach (#3461). `seal` is what the runtime did to itself, so the
    /// environment counts as closed to a same-uid child only once the
    /// kernel confirmed it.
    pub(crate) fn admit(&self, held: &[Held], seal: &RuntimeSeal) -> Result<(), String> {
        for item in held {
            for child in &self.children {
                if let Some(how) = reach(*child, item, seal.environment()) {
                    return Err(format!(
                        "{} ({}) {how}; refusing to start holding it",
                        item.name,
                        item.exposure.noun()
                    ));
                }
            }
        }
        Ok(())
    }

    /// The held files a child at the proxy's own uid reaches and
    /// [`Self::admit`] lets the proxy hold anyway: the bare host tier's
    /// declared exposure, by name, for the banner `--unsandboxed` prints.
    /// Empty when no child shares the proxy's uid.
    pub(crate) fn declared<'a>(&self, held: &'a [Held]) -> Vec<&'a Held> {
        if !self.children.contains(&ChildUid::SharedWithRuntime) {
            return Vec::new();
        }
        held.iter()
            .filter(|item| match item.at {
                At::Path(_) | At::FrontDoorPeer(_) => item.exposure.bare_tier_may_hold(),
                At::Env | At::Argv => false,
            })
            .collect()
    }
}

impl Exposure {
    fn noun(self) -> &'static str {
        match self {
            Self::Secret => "a secret",
            Self::Durable => "durable authority",
            Self::Session => "this session's record or input",
        }
    }

    /// Whether a child that can READ it (not only write it) reaches it.
    fn confidential(self) -> bool {
        match self {
            Self::Secret => true,
            Self::Durable | Self::Session => false,
        }
    }

    /// Whether the bare host tier may hold it in a file. The bare tier never
    /// may hold durable authority: the proxy would go on trusting bytes its
    /// child could have written. A secret or session file it may hold, as
    /// the declared exposure that [`ChildReach::declared`] names. Such a file
    /// is the launcher's, written at this uid, so a child at this uid opens
    /// it whether or not the proxy reads it. Refusing would take away the
    /// pod, not the child's reach. (A separated child is held off both by
    /// the file's own ownership and bits.)
    fn bare_tier_may_hold(self) -> bool {
        match self {
            Self::Durable => false,
            Self::Secret | Self::Session => true,
        }
    }
}

const BARE_TIER: &str = "is reachable by a child of this proxy, which runs at the proxy's own uid \
                         (the bare host tier)";

/// One child, one held item: how the child reaches it, or `None`.
fn reach(child: ChildUid, item: &Held, environment: EnvironmentReach) -> Option<String> {
    match (&item.at, child) {
        (At::Argv, ChildUid::SharedWithRuntime | ChildUid::Distinct(_)) => Some(
            "is on this process's command line, which every process on the host can read \
             (/proc/<pid>/cmdline); pass it in the environment instead"
                .into(),
        ),
        // A process at another non-root uid cannot open this process's
        // `/proc/<pid>/environ` (a root runtime's children are never root).
        (At::Env, ChildUid::Distinct(_)) => None,
        (At::Env, ChildUid::SharedWithRuntime) => match environment {
            EnvironmentReach::ClosedToSameUid => None,
            EnvironmentReach::OpenToSameUid => Some(
                "is in this process's environment, which a child at the proxy's own uid can \
                 read here (the bare host tier, and the runtime could not seal itself)"
                    .into(),
            ),
        },
        (At::FrontDoorPeer(peer), ChildUid::Distinct(uid)) => (*peer == uid).then(|| {
            format!(
                "admits uid {uid} on --listen-unix, and a child of this proxy runs as uid {uid}, \
                 so that child would be served as the host"
            )
        }),
        (At::FrontDoorPeer(_) | At::Path(_), ChildUid::SharedWithRuntime) => {
            (!item.exposure.bare_tier_may_hold()).then(|| BARE_TIER.into())
        }
        (At::Path(path), ChildUid::Distinct(uid)) => path_reach(path, uid, item.exposure),
    }
}

/// How a child at `uid` (gid `uid`, no supplementary groups: what a dropped
/// child gets) reaches `path`, through the path as named and through the
/// path it resolves to. Anything that cannot be inspected counts as reached
/// (A-1: could not look is not fine).
fn path_reach(path: &Path, uid: u32, exposure: Exposure) -> Option<String> {
    let path = match std::path::absolute(path) {
        Ok(p) => p,
        Err(e) => return Some(format!("could not be inspected ({e})")),
    };
    if let Some(how) = chain_reach(&path, uid, exposure) {
        return Some(how);
    }
    // The deepest prefix that exists, resolved, with the rest re-attached:
    // a symlink anywhere above is followed to where the bytes really live.
    let mut existing = path.as_path();
    let mut rest = Vec::new();
    loop {
        match std::fs::symlink_metadata(existing) {
            Ok(_) => break,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let Some(name) = existing.file_name() else {
                    return Some(format!("could not be inspected at {}", existing.display()));
                };
                rest.push(name.to_owned());
                let Some(parent) = existing.parent() else {
                    return Some(format!("could not be inspected at {}", existing.display()));
                };
                existing = parent;
            }
            Err(e) => {
                return Some(format!(
                    "could not be inspected at {} ({e})",
                    existing.display()
                ));
            }
        }
    }
    let mut resolved = match existing.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            return Some(format!(
                "could not be inspected at {} ({e})",
                existing.display()
            ));
        }
    };
    if resolved.as_path() == existing {
        return None;
    }
    for name in rest.into_iter().rev() {
        resolved.push(name);
    }
    chain_reach(&resolved, uid, exposure)
}

/// Walk `path` from `/` down. A directory above it that the child owns, or
/// can write without the sticky bit, lets the child replace what is below.
/// The item itself, once it exists, is reached when the child owns it, can
/// write it, or (for a secret) can read it. A prefix that does not exist
/// yet ends the walk: the proxy creates the rest, in a directory already
/// checked, unless the child can write that directory at all, sticky or not,
/// because then it can create the missing name first.
fn chain_reach(path: &Path, uid: u32, exposure: Exposure) -> Option<String> {
    let mut prefixes: Vec<&Path> = path.ancestors().collect();
    prefixes.reverse();
    let last = prefixes.len().saturating_sub(1);
    let mut writable_above: Option<&Path> = None;
    for (i, prefix) in prefixes.into_iter().enumerate() {
        let meta = match std::fs::symlink_metadata(prefix) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return writable_above.map(|dir| {
                    format!(
                        "is not created yet, and a child at uid {uid} can write {}, so it can \
                         create {} first",
                        dir.display(),
                        prefix.display()
                    )
                });
            }
            Err(e) => {
                return Some(format!(
                    "could not be inspected at {} ({e})",
                    prefix.display()
                ));
            }
        };
        let at = prefix.display();
        if meta.uid() == uid {
            return Some(format!(
                "is reachable: uid {uid}, which a child runs as, owns {at}"
            ));
        }
        // A symlink's own mode bits mean nothing; where it points is walked
        // separately, resolved.
        if meta.file_type().is_symlink() {
            writable_above = None;
            continue;
        }
        let mode = meta.permissions().mode();
        let may = |bit: u32| mode & bit != 0 || (meta.gid() == uid && mode & (bit << 3) != 0);
        writable_above = may(0o002).then_some(prefix);
        if i < last {
            if may(0o002) && mode & 0o1000 == 0 {
                return Some(format!(
                    "is replaceable: a child at uid {uid} can write the directory {at}"
                ));
            }
        } else if may(0o002) {
            return Some(format!("is writable by a child at uid {uid} ({at})"));
        } else if exposure.confidential() && may(0o004) {
            return Some(format!("is readable by a child at uid {uid} ({at})"));
        }
    }
    None
}

#[cfg(test)]
mod alone;
#[cfg(test)]
#[path = "child_reach_tests.rs"]
mod tests;
