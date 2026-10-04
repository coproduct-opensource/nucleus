//! Guest paths the runtime owns, taken as an input.
//!
//! This crate holds no copy of the table (ADR 0007 G-1). The runtime's table
//! lives with the guest layout it describes, and the caller passes it in; the
//! only thing decided here is what "reserved" means for an image layer.

use crate::error::ImportError;
use crate::path::{self, Normalized};

/// One entry of the reserved-path table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReservedPath {
    /// This path, and anything below it (which would make it exist), is the runtime's.
    Exact(Vec<u8>),
    /// Everything strictly below this directory is the runtime's. The directory
    /// itself may appear in an image, but only as a real directory.
    Prefix(Vec<u8>),
}

/// A validated, non-empty reserved-path table.
#[derive(Clone, Debug)]
pub struct ReservedPaths {
    entries: Vec<ReservedPath>,
}

/// What a reserved entry says about a path.
pub(crate) struct Hit<'a> {
    pub(crate) reserved: &'a [u8],
}

impl ReservedPaths {
    /// Validate a table. Leading/trailing `/` are dropped; an empty table, the
    /// root, or a `..` component is refused.
    pub fn new(entries: impl IntoIterator<Item = ReservedPath>) -> Result<Self, ImportError> {
        let mut out = Vec::new();
        for entry in entries {
            let (raw, make): (Vec<u8>, fn(Vec<u8>) -> ReservedPath) = match entry {
                ReservedPath::Exact(p) => (p, ReservedPath::Exact),
                ReservedPath::Prefix(p) => (p, ReservedPath::Prefix),
            };
            match path::normalize(&raw, u64::MAX) {
                Ok(Normalized::Path(p)) => out.push(make(p)),
                Ok(Normalized::Root) | Err(_) => {
                    return Err(ImportError::InvalidReservedPath {
                        path: crate::error::lossy(&raw),
                    });
                }
            }
        }
        if out.is_empty() {
            return Err(ImportError::EmptyReservedTable);
        }
        Ok(Self { entries: out })
    }

    /// The anchor path of an entry: the exact path, or the prefix directory.
    fn anchor(entry: &ReservedPath) -> &[u8] {
        match entry {
            ReservedPath::Exact(p) | ReservedPath::Prefix(p) => p,
        }
    }

    /// An image entry at `p` would occupy reserved space.
    pub(crate) fn occupies(&self, p: &[u8]) -> Option<Hit<'_>> {
        self.entries.iter().find_map(|entry| {
            let hit = match entry {
                ReservedPath::Exact(e) => p == e.as_slice() || path::is_strictly_under(p, e),
                ReservedPath::Prefix(prefix) => path::is_strictly_under(p, prefix),
            };
            hit.then(|| Hit {
                reserved: Self::anchor(entry),
            })
        })
    }

    /// Removing `p` and everything below it (a whiteout), or everything below it
    /// (an opaque marker), would reach reserved space or a directory that must hold it.
    pub(crate) fn removal_reaches(&self, p: &[u8]) -> Option<Hit<'_>> {
        self.entries.iter().find_map(|entry| {
            let anchor = Self::anchor(entry);
            path::related(p, anchor).then_some(Hit { reserved: anchor })
        })
    }

    /// Every path that, if present in the flattened tree, must be a real directory,
    /// paired with the reserved anchor that requires it.
    pub(crate) fn required_directories(&self) -> impl Iterator<Item = (&[u8], &[u8])> {
        self.entries.iter().flat_map(|entry| {
            let anchor = Self::anchor(entry);
            let own: Option<&[u8]> = match entry {
                ReservedPath::Exact(_) => None,
                ReservedPath::Prefix(p) => Some(p.as_slice()),
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
            ReservedPath::Exact(b"usr/local/bin/nucleus-tool-proxy".to_vec()),
        ])
        .unwrap()
    }

    #[test]
    fn occupancy() {
        let t = table();
        assert!(t.occupies(b"init").is_some());
        assert!(t.occupies(b"init/x").is_some());
        assert!(
            t.occupies(b"etc/nucleus").is_none(),
            "the prefix dir itself is allowed"
        );
        assert!(t.occupies(b"etc/nucleus/pod.yaml").is_some());
        assert!(t.occupies(b"usr/local/bin/nucleus-tool-proxy").is_some());
        assert!(t.occupies(b"usr/local/bin/other").is_none());
        assert!(t.occupies(b"initrd").is_none());
    }

    #[test]
    fn removal() {
        let t = table();
        assert!(t.removal_reaches(b"etc").is_some());
        assert!(
            t.removal_reaches(b"").is_some(),
            "an opaque root clears everything"
        );
        assert!(t.removal_reaches(b"etc/nucleus").is_some());
        assert!(t.removal_reaches(b"etc/passwd").is_none());
    }

    #[test]
    fn required_dirs() {
        let t = table();
        let dirs: Vec<&[u8]> = t.required_directories().map(|(d, _)| d).collect();
        assert!(dirs.contains(&&b"etc/nucleus"[..]));
        assert!(dirs.contains(&&b"usr/local/bin"[..]));
        assert!(!dirs.contains(&&b"init"[..]));
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
    }
}
