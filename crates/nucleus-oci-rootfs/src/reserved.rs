//! Guest paths the runtime owns, taken as an input.
//!
//! This crate holds no copy of the table (ADR 0007 G-1). The runtime's table
//! lives with the guest layout it describes (`nucleus_spec::guest_layout`), and
//! the caller passes it in; the only thing decided here is what each kind of
//! reservation means for an image layer:
//!
//! | kind | an image entry there | a whiteout reaching it |
//! |---|---|---|
//! | [`ReservedPath::Exact`] | refused | refused |
//! | [`ReservedPath::Prefix`] | refused below the dir; the dir only as a real dir | refused |
//! | [`ReservedPath::NamePrefix`] | refused | refused |
//! | [`ReservedPath::MustBeEmpty`] | below the dir: **dropped and reported**; the dir only as a real dir | below the dir: dropped and reported; the dir or above: applied |
//!
//! A must-be-empty directory is mounted over at boot, so nothing an image puts
//! in it is ever the guest's to read. Refusing it would refuse every common
//! base image (they all ship `/run/lock`); dropping it means that if a mount
//! ever fails, what shows through is nothing (owner decision, #3216).

use crate::error::{ImportError, lossy};
use crate::path::{self, Normalized};

/// One entry of the reserved-path table.
///
/// No `Default` (ADR 0007 B-1): every entry states how it claims its paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReservedPath {
    /// This path, and anything below it (which would make it exist), is the runtime's.
    Exact(Vec<u8>),
    /// Everything strictly below this directory is the runtime's. The directory
    /// itself may appear in an image, but only as a real directory.
    Prefix(Vec<u8>),
    /// Every path whose bytes begin with this name prefix is the runtime's:
    /// `usr/local/bin/nucleus-` claims `usr/local/bin/nucleus-mcp` and every
    /// future `nucleus-*` binary. Every directory above it must be a real
    /// directory. The final component may not be empty or `.`.
    NamePrefix(Vec<u8>),
    /// A directory the guest mounts over at boot. It may appear in an image
    /// only as a real directory; anything strictly below it is dropped and
    /// reported, never refused.
    MustBeEmpty(Vec<u8>),
}

/// A validated, non-empty reserved-path table.
#[derive(Clone, Debug)]
pub struct ReservedPaths {
    entries: Vec<ReservedPath>,
}

/// What the table says about an image entry, or about a path a whiteout removes.
///
/// Three outcomes, so never a `bool` (ADR 0007 A-1): "dropped" is neither
/// "refused" nor "the image's".
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Verdict<'a> {
    /// No entry claims it.
    Free,
    /// It lies inside a must-be-empty directory: drop it and report it.
    Emptied {
        /// The must-be-empty directory.
        reserved: &'a [u8],
    },
    /// It reaches reserved space: refuse the image.
    Refused {
        /// The reserved entry's anchor.
        reserved: &'a [u8],
    },
}

impl ReservedPaths {
    /// Validate a table. Leading/trailing `/` are dropped from directory and
    /// exact entries; an empty table, the root, a `..` component, or a name
    /// prefix whose final component is empty or `.` is refused.
    pub fn new(entries: impl IntoIterator<Item = ReservedPath>) -> Result<Self, ImportError> {
        let mut out = Vec::new();
        for entry in entries {
            let (raw, make): (Vec<u8>, fn(Vec<u8>) -> ReservedPath) = match entry {
                ReservedPath::Exact(p) => (p, ReservedPath::Exact),
                ReservedPath::Prefix(p) => (p, ReservedPath::Prefix),
                ReservedPath::NamePrefix(p) => {
                    // Normalizing `usr/local/bin/` or `usr/local/bin/.` would
                    // quietly turn a name prefix into a directory.
                    match p.rsplit(|b| *b == b'/').next() {
                        Some(last) if !last.is_empty() && last != b"." => {}
                        Some(_) | None => {
                            return Err(ImportError::InvalidReservedPath { path: lossy(&p) });
                        }
                    }
                    (p, ReservedPath::NamePrefix)
                }
                ReservedPath::MustBeEmpty(p) => (p, ReservedPath::MustBeEmpty),
            };
            match path::normalize(&raw, u64::MAX) {
                Ok(Normalized::Path(p)) => out.push(make(p)),
                Ok(Normalized::Root) | Err(_) => {
                    return Err(ImportError::InvalidReservedPath { path: lossy(&raw) });
                }
            }
        }
        if out.is_empty() {
            return Err(ImportError::EmptyReservedTable);
        }
        Ok(Self { entries: out })
    }

    /// The anchor path of an entry: the exact path, the directory, or the name prefix.
    fn anchor(entry: &ReservedPath) -> &[u8] {
        match entry {
            ReservedPath::Exact(p)
            | ReservedPath::Prefix(p)
            | ReservedPath::NamePrefix(p)
            | ReservedPath::MustBeEmpty(p) => p,
        }
    }

    /// Fold per-entry verdicts: any refusal wins, whatever the table order;
    /// then a drop; otherwise the path is the image's.
    fn decide<'a>(&'a self, per_entry: impl Fn(&'a ReservedPath) -> Verdict<'a>) -> Verdict<'a> {
        let mut emptied = None;
        for entry in &self.entries {
            match per_entry(entry) {
                Verdict::Refused { reserved } => return Verdict::Refused { reserved },
                Verdict::Emptied { reserved } => {
                    emptied.get_or_insert(reserved);
                }
                Verdict::Free => {}
            }
        }
        match emptied {
            Some(reserved) => Verdict::Emptied { reserved },
            None => Verdict::Free,
        }
    }

    /// What an image entry at `p` would do to reserved space.
    pub(crate) fn occupies(&self, p: &[u8]) -> Verdict<'_> {
        self.decide(|entry| {
            let reserved = Self::anchor(entry);
            let (claimed, emptied) = match entry {
                ReservedPath::Exact(e) => {
                    (p == e.as_slice() || path::is_strictly_under(p, e), false)
                }
                ReservedPath::Prefix(dir) => (path::is_strictly_under(p, dir), false),
                ReservedPath::NamePrefix(prefix) => (p.starts_with(prefix), false),
                ReservedPath::MustBeEmpty(dir) => (path::is_strictly_under(p, dir), true),
            };
            Self::verdict(claimed, emptied, reserved)
        })
    }

    /// What removing `p` and everything below it (a whiteout), or everything
    /// below it (an opaque marker), would do to reserved space.
    ///
    /// A must-be-empty directory never holds anything from the image, so a
    /// removal inside it removes nothing and is dropped; removing the
    /// directory itself, or something above it, takes nothing reserved with it.
    pub(crate) fn removal_reaches(&self, p: &[u8]) -> Verdict<'_> {
        self.decide(|entry| {
            let reserved = Self::anchor(entry);
            let (claimed, emptied) = match entry {
                ReservedPath::Exact(anchor) | ReservedPath::Prefix(anchor) => {
                    (path::related(p, anchor), false)
                }
                ReservedPath::NamePrefix(prefix) => {
                    // The prefix's own directory, anything above it, or a
                    // name the prefix claims.
                    let (parent, _) = path::split_last(prefix);
                    let reaches =
                        p.starts_with(prefix) || p == parent || path::is_strictly_under(parent, p);
                    (reaches, false)
                }
                ReservedPath::MustBeEmpty(dir) => (path::is_strictly_under(p, dir), true),
            };
            Self::verdict(claimed, emptied, reserved)
        })
    }

    fn verdict(claimed: bool, emptied: bool, reserved: &[u8]) -> Verdict<'_> {
        match (claimed, emptied) {
            (false, false | true) => Verdict::Free,
            (true, true) => Verdict::Emptied { reserved },
            (true, false) => Verdict::Refused { reserved },
        }
    }

    /// Every path that, if present in the flattened tree, must be a real directory,
    /// paired with the reserved anchor that requires it.
    pub(crate) fn required_directories(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.entries.iter().flat_map(|entry| {
            let anchor = Self::anchor(entry);
            let own: Option<&[u8]> = match entry {
                ReservedPath::Exact(_) | ReservedPath::NamePrefix(_) => None,
                ReservedPath::Prefix(p) | ReservedPath::MustBeEmpty(p) => Some(p.as_slice()),
            };
            path::strict_ancestors(anchor)
                .chain(own)
                .map(move |dir| (dir, anchor))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> ReservedPaths {
        ReservedPaths::new([
            ReservedPath::Exact(b"/init".to_vec()),
            ReservedPath::Prefix(b"etc/nucleus/".to_vec()),
            ReservedPath::NamePrefix(b"/usr/local/bin/nucleus-".to_vec()),
            ReservedPath::MustBeEmpty(b"/run/".to_vec()),
        ])
        .unwrap()
    }

    fn refused(v: Verdict<'_>) -> bool {
        matches!(v, Verdict::Refused { .. })
    }

    fn emptied(v: Verdict<'_>) -> bool {
        matches!(v, Verdict::Emptied { .. })
    }

    #[test]
    fn occupancy() {
        let t = table();
        assert!(refused(t.occupies(b"init")));
        assert!(refused(t.occupies(b"init/x")));
        assert_eq!(
            t.occupies(b"etc/nucleus"),
            Verdict::Free,
            "the prefix dir itself is allowed"
        );
        assert!(refused(t.occupies(b"etc/nucleus/pod.yaml")));
        assert!(refused(t.occupies(b"usr/local/bin/nucleus-tool-proxy")));
        assert!(refused(t.occupies(b"usr/local/bin/nucleus-mcp")));
        assert!(refused(t.occupies(b"usr/local/bin/nucleus-x/y")));
        assert_eq!(t.occupies(b"usr/local/bin/other"), Verdict::Free);
        assert_eq!(t.occupies(b"usr/local/bin"), Verdict::Free);
        assert_eq!(t.occupies(b"initrd"), Verdict::Free);
    }

    #[test]
    fn must_be_empty_contents_are_emptied_not_refused() {
        let t = table();
        assert_eq!(
            t.occupies(b"run/lock"),
            Verdict::Emptied {
                reserved: b"run".as_slice()
            }
        );
        assert!(emptied(t.occupies(b"run/lock/x")));
        assert_eq!(
            t.occupies(b"run"),
            Verdict::Free,
            "the dir itself is allowed"
        );
        assert_eq!(t.occupies(b"runner"), Verdict::Free);
    }

    #[test]
    fn a_refusal_outranks_a_drop_whatever_the_table_order() {
        let t = ReservedPaths::new([
            ReservedPath::MustBeEmpty(b"run".to_vec()),
            ReservedPath::Exact(b"run/door".to_vec()),
        ])
        .unwrap();
        assert!(refused(t.occupies(b"run/door")));
        assert!(refused(t.removal_reaches(b"run/door")));
        assert!(emptied(t.occupies(b"run/other")));
    }

    #[test]
    fn removal() {
        let t = table();
        assert!(refused(t.removal_reaches(b"etc")));
        assert!(
            refused(t.removal_reaches(b"")),
            "an opaque root clears everything"
        );
        assert!(refused(t.removal_reaches(b"etc/nucleus")));
        assert_eq!(t.removal_reaches(b"etc/passwd"), Verdict::Free);
        // Name prefix: its directory, its ancestors and its names are reached.
        assert!(refused(t.removal_reaches(b"usr/local/bin")));
        assert!(refused(t.removal_reaches(b"usr")));
        assert!(refused(t.removal_reaches(b"usr/local/bin/nucleus-mcp")));
        assert_eq!(t.removal_reaches(b"usr/local/bin/other"), Verdict::Free);
        assert_eq!(t.removal_reaches(b"usr/local/lib"), Verdict::Free);
        // Must-be-empty: inside is dropped; the dir itself holds nothing reserved.
        assert!(emptied(t.removal_reaches(b"run/lock")));
        assert_eq!(t.removal_reaches(b"run"), Verdict::Free);
    }

    #[test]
    fn required_dirs() {
        let t = table();
        let dirs: Vec<&[u8]> = t.required_directories().map(|(d, _)| d).collect();
        assert!(dirs.contains(&&b"etc/nucleus"[..]));
        assert!(dirs.contains(&&b"usr/local/bin"[..]));
        assert!(dirs.contains(&&b"run"[..]));
        assert!(!dirs.contains(&&b"init"[..]));
        assert!(!dirs.contains(&&b"usr/local/bin/nucleus-"[..]));
    }

    #[test]
    fn refuses_empty_and_malformed_tables() {
        assert!(matches!(
            ReservedPaths::new([]),
            Err(ImportError::EmptyReservedTable)
        ));
        assert!(matches!(
            ReservedPaths::new([ReservedPath::Prefix(b"/".to_vec())]),
            Err(ImportError::InvalidReservedPath { .. })
        ));
        assert!(matches!(
            ReservedPaths::new([ReservedPath::Exact(b"a/../b".to_vec())]),
            Err(ImportError::InvalidReservedPath { .. })
        ));
        for bad in [&b"usr/local/bin/"[..], b"usr/local/bin/.", b"/", b"a/.."] {
            assert!(
                matches!(
                    ReservedPaths::new([ReservedPath::NamePrefix(bad.to_vec())]),
                    Err(ImportError::InvalidReservedPath { .. })
                ),
                "{bad:?}"
            );
        }
        assert!(matches!(
            ReservedPaths::new([ReservedPath::MustBeEmpty(b"/".to_vec())]),
            Err(ImportError::InvalidReservedPath { .. })
        ));
    }
}
