//! A space's linear history, and the compare-and-swap commit onto its head.

use crate::candidate::ValidCandidate;
use crate::section::Section;

/// A version number: the state after that many commits. Version 0 is genesis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version(u8);

impl Version {
    /// The empty genesis version every history starts from.
    pub const GENESIS: Version = Version(0);

    /// Version `n`. Whether it EXISTS is a question for a [`History`].
    pub const fn new(n: u8) -> Version {
        Version(n)
    }

    /// The raw number.
    pub const fn number(self) -> u8 {
        self.0
    }
}

/// A committed version and its content, read from a [`History`].
///
/// The constructor is private: a snapshot is minted only by [`History::snapshot`],
/// so a candidate's base is always content the history really holds (ADR 0007 C-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    version: Version,
    section: Section,
}

impl Snapshot {
    /// Which version this is.
    pub const fn version(&self) -> Version {
        self.version
    }

    /// Its content.
    pub const fn section(&self) -> &Section {
        &self.section
    }

    /// A snapshot the history did not mint — tests only, to drive the per-key
    /// validation clauses over every base slot.
    #[cfg(test)]
    pub(crate) const fn for_test(version: Version, section: Section) -> Snapshot {
        Snapshot { version, section }
    }
}

/// Why a commit was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitRefusal {
    /// The candidate was validated over `generation`, but the head is now `head`:
    /// rebase — assemble over the new head and validate the WHOLE candidate again.
    StaleBase {
        /// The version the candidate was validated against.
        generation: Version,
        /// The current head.
        head: Version,
    },
    /// The finite history is full.
    Full {
        /// How many versions it holds.
        capacity: usize,
    },
}

/// A space's linear history: genesis, then one version per commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct History {
    versions: [Section; History::CAPACITY],
    head: Version,
}

impl History {
    /// How many versions (genesis included) the finite model holds.
    pub const CAPACITY: usize = 8;

    /// A history holding only the empty genesis version.
    pub const fn genesis() -> History {
        History {
            versions: [Section::EMPTY; History::CAPACITY],
            head: Version::GENESIS,
        }
    }

    /// The latest committed version.
    pub const fn head(&self) -> Version {
        self.head
    }

    /// The content of `version`, or `None` if it has not been committed. A version
    /// past the head is refused rather than read as empty: a binding pinned to a
    /// version that does not exist yet would see the next commit.
    pub fn snapshot(&self, version: Version) -> Option<Snapshot> {
        if version.0 > self.head.0 {
            return None;
        }
        self.versions
            .get(usize::from(version.0))
            .map(|section| Snapshot {
                version,
                section: *section,
            })
    }

    /// Commit `valid` as the next version — only onto the head it was validated
    /// against (compare-and-swap). Taken by value: one validation, one commit
    /// (ADR 0007 C-4).
    pub fn commit(&mut self, valid: ValidCandidate) -> Result<Version, CommitRefusal> {
        let (section, generation) = valid.into_parts();
        if generation != self.head {
            return Err(CommitRefusal::StaleBase {
                generation,
                head: self.head,
            });
        }
        let full = CommitRefusal::Full {
            capacity: History::CAPACITY,
        };
        let next = self.head.0.checked_add(1).ok_or(full)?;
        let slot = self.versions.get_mut(usize::from(next)).ok_or(full)?;
        *slot = section;
        self.head = Version(next);
        Ok(self.head)
    }
}
