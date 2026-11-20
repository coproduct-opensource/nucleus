//! Assembling patches over a pinned base, and validating the WHOLE result.

use crate::history::{Snapshot, Version};
use crate::section::{Entry, Key, Section};
use crate::view::LabelRank;

/// The per-key accumulator of an assembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SlotAcc {
    /// The entry the key holds so far.
    pub(crate) slot: Option<Entry>,
    /// Has a patch written this key yet?
    pub(crate) touched: bool,
    /// Did two patches write it differently?
    pub(crate) conflict: bool,
}

/// One patch's slot for one key. The first patch to write a key sets it; a later
/// patch writing a DIFFERENT entry marks the key conflicted. Never last-writer-wins.
pub(crate) fn step_slot(acc: SlotAcc, patch: Option<Entry>) -> SlotAcc {
    match (patch, acc.touched) {
        (None, _) => acc,
        (Some(entry), false) => SlotAcc {
            slot: Some(entry),
            touched: true,
            conflict: acc.conflict,
        },
        (Some(entry), true) => {
            if acc.slot == Some(entry) {
                acc
            } else {
                SlotAcc {
                    slot: acc.slot,
                    touched: true,
                    conflict: true,
                }
            }
        }
    }
}

/// Which keys two patches disagreed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Conflicts {
    k0: bool,
    k1: bool,
    k2: bool,
    k3: bool,
}

impl Conflicts {
    const NONE: Conflicts = Conflicts {
        k0: false,
        k1: false,
        k2: false,
        k3: false,
    };

    const fn get(&self, key: Key) -> bool {
        match key {
            Key::K0 => self.k0,
            Key::K1 => self.k1,
            Key::K2 => self.k2,
            Key::K3 => self.k3,
        }
    }

    fn set(&mut self, key: Key, conflict: bool) {
        match key {
            Key::K0 => self.k0 = conflict,
            Key::K1 => self.k1 = conflict,
            Key::K2 => self.k2 = conflict,
            Key::K3 => self.k3 = conflict,
        }
    }
}

/// Patches glued over a pinned base, not yet validated. Only
/// [`assemble_candidate`] builds one, and only [`validate_candidate`] turns one into
/// something a [`crate::History`] will commit.
#[derive(Debug, PartialEq, Eq)]
pub struct Candidate {
    base: Snapshot,
    merged: Section,
    conflicted: Conflicts,
}

impl Candidate {
    /// The pinned base the patches were glued over.
    pub const fn base(&self) -> &Snapshot {
        &self.base
    }

    /// The glued section.
    pub const fn merged(&self) -> &Section {
        &self.merged
    }

    /// Did two patches write `key` differently?
    pub const fn is_conflicted(&self, key: Key) -> bool {
        self.conflicted.get(key)
    }
}

/// Glue `patches`, in order, over `base`.
///
/// Where no patch writes a key, the base is kept; where patches write a key, the
/// candidate holds what they wrote; where two patches write it differently, the key
/// is marked conflicted (and keeps the first write) so validation refuses it.
#[must_use = "a candidate does nothing until it is validated"]
pub fn assemble_candidate(base: &Snapshot, patches: &[Section]) -> Candidate {
    let mut merged = Section::EMPTY;
    let mut conflicted = Conflicts::NONE;
    for key in Key::ALL {
        let mut acc = SlotAcc {
            slot: base.section().get(key),
            touched: false,
            conflict: false,
        };
        for patch in patches {
            acc = step_slot(acc, patch.get(key));
        }
        merged.set(key, acc.slot);
        conflicted.set(key, acc.conflict);
    }
    Candidate {
        base: *base,
        merged,
        conflicted,
    }
}

/// The whole-candidate invariants that are a parameter of the space. Label
/// monotonicity and keyed-conflict refusal are NOT parameters: they always hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invariants {
    /// The global additive quota: total units over every key of the candidate.
    pub quota: u16,
}

/// Why a candidate was refused, by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateRefusal {
    /// Two patches wrote `key` differently and nothing resolved it.
    KeyConflict {
        /// The key.
        key: Key,
    },
    /// The base held an entry under `key` and the candidate does not.
    EntryDropped {
        /// The key.
        key: Key,
    },
    /// The candidate would lower the stored label under `key`.
    LabelLowered {
        /// The key.
        key: Key,
        /// The stored label.
        from: LabelRank,
        /// The label the candidate carries.
        to: LabelRank,
    },
    /// The whole candidate spends more than the quota.
    QuotaExceeded {
        /// Units the candidate spends.
        total: u16,
        /// The quota.
        quota: u16,
    },
}

/// A candidate that passed whole-candidate validation, bound to the version it was
/// validated against.
///
/// Private constructor (minted only by [`validate_candidate`]), not `Clone`, and
/// consumed by [`crate::History::commit`] — which refuses it unless `generation` is
/// still the head. It is valid exactly as long as the state it was decided against.
#[must_use = "a validated candidate that is never committed is a publish that never happened"]
#[derive(Debug, PartialEq, Eq)]
pub struct ValidCandidate {
    section: Section,
    generation: Version,
}

impl ValidCandidate {
    /// The section that would be committed.
    pub const fn section(&self) -> &Section {
        &self.section
    }

    /// The head this candidate was validated against.
    pub const fn generation(&self) -> Version {
        self.generation
    }

    pub(crate) fn into_parts(self) -> (Section, Version) {
        (self.section, self.generation)
    }

    /// A candidate nothing validated — tests only, to drive `History::commit`'s CAS
    /// over every (generation, head) pair.
    #[cfg(test)]
    pub(crate) const fn for_test(section: Section, generation: Version) -> ValidCandidate {
        ValidCandidate {
            section,
            generation,
        }
    }
}

impl Candidate {
    /// A candidate with chosen per-key conflicts — tests only, to drive the per-key
    /// validation clauses exhaustively.
    #[cfg(test)]
    pub(crate) fn for_test(
        base: Snapshot,
        merged: Section,
        conflicted: [bool; Key::ALL.len()],
    ) -> Candidate {
        let mut flags = Conflicts::NONE;
        for (key, flag) in Key::ALL.into_iter().zip(conflicted) {
            flags.set(key, flag);
        }
        Candidate {
            base,
            merged,
            conflicted: flags,
        }
    }
}

/// Validate the WHOLE candidate.
///
/// Per key, in [`Key::ALL`] order: a conflicted key is refused, then a dropped entry,
/// then a lowered label. Then the global quota over every key. A candidate whose
/// patches agree on every overlap can still be refused here: overlap agreement is
/// not validity.
pub fn validate_candidate(
    candidate: Candidate,
    invariants: Invariants,
) -> Result<ValidCandidate, CandidateRefusal> {
    let mut total: u16 = 0;
    for key in Key::ALL {
        if candidate.is_conflicted(key) {
            return Err(CandidateRefusal::KeyConflict { key });
        }
        let merged = candidate.merged.get(key);
        match (candidate.base.section().get(key), merged) {
            (None, _) => {}
            (Some(_), None) => return Err(CandidateRefusal::EntryDropped { key }),
            (Some(stored), Some(next)) => {
                if !stored.label.at_most(next.label) {
                    return Err(CandidateRefusal::LabelLowered {
                        key,
                        from: stored.label,
                        to: next.label,
                    });
                }
            }
        }
        if let Some(entry) = merged {
            // Four keys of at most `Units::MAX` cannot overflow a u16; saturating
            // keeps the arithmetic total, and a saturated total exceeds any quota
            // below u16::MAX.
            total = total.saturating_add(u16::from(entry.units.get()));
        }
    }
    if total > invariants.quota {
        return Err(CandidateRefusal::QuotaExceeded {
            total,
            quota: invariants.quota,
        });
    }
    Ok(ValidCandidate {
        section: candidate.merged,
        generation: candidate.base.version(),
    })
}
