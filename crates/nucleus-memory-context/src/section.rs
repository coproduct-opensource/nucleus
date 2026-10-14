//! Sections: a keyed map of labelled entries, and what a view observes of one.

use crate::view::{LabelRank, ScopeAtom, View};

/// A key of the finite model. Each key belongs to one scope atom.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    /// First key of [`ScopeAtom::Ns0`].
    K0,
    /// Second key of [`ScopeAtom::Ns0`].
    K1,
    /// The key of [`ScopeAtom::Ns1`].
    K2,
    /// The key of [`ScopeAtom::Ns2`].
    K3,
}

impl Key {
    /// Every key, in the order refusals are reported.
    pub const ALL: [Key; 4] = [Key::K0, Key::K1, Key::K2, Key::K3];

    /// The scope atom this key lives in.
    pub const fn atom(self) -> ScopeAtom {
        match self {
            Key::K0 | Key::K1 => ScopeAtom::Ns0,
            Key::K2 => ScopeAtom::Ns1,
            Key::K3 => ScopeAtom::Ns2,
        }
    }
}

/// An opaque content id — the finite model's stand-in for a record's content hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValueId(u8);

impl ValueId {
    /// How many content ids the finite model has.
    pub const COUNT: u8 = 4;

    /// The id `id`, or `None` outside the model.
    pub const fn new(id: u8) -> Option<ValueId> {
        if id < Self::COUNT {
            Some(ValueId(id))
        } else {
            None
        }
    }

    /// The raw id.
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// The quota units one entry spends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Units(u8);

impl Units {
    /// The most units one entry may spend in the finite model.
    pub const MAX: u8 = 15;

    /// `units`, or `None` above [`Units::MAX`].
    pub const fn new(units: u8) -> Option<Units> {
        if units <= Self::MAX {
            Some(Units(units))
        } else {
            None
        }
    }

    /// The raw count.
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// One stored entry: its content, its label, and what it spends of the quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// The content id.
    pub value: ValueId,
    /// The entry's label.
    pub label: LabelRank,
    /// The quota units it spends.
    pub units: Units,
}

/// A keyed map from [`Key`] to at most one [`Entry`]. Uniqueness of a key is the
/// type (ADR 0007 G-3): there is one slot per key, by field, so a duplicate key is
/// not a value this type has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Section {
    k0: Option<Entry>,
    k1: Option<Entry>,
    k2: Option<Entry>,
    k3: Option<Entry>,
}

impl Section {
    /// No entry under any key.
    pub const EMPTY: Section = Section {
        k0: None,
        k1: None,
        k2: None,
        k3: None,
    };

    /// The entry under `key`.
    pub const fn get(&self, key: Key) -> Option<Entry> {
        match key {
            Key::K0 => self.k0,
            Key::K1 => self.k1,
            Key::K2 => self.k2,
            Key::K3 => self.k3,
        }
    }

    /// Set the slot under `key`.
    pub fn set(&mut self, key: Key, slot: Option<Entry>) {
        match key {
            Key::K0 => self.k0 = slot,
            Key::K1 => self.k1 = slot,
            Key::K2 => self.k2 = slot,
            Key::K3 => self.k3 = slot,
        }
    }

    /// This section with `entry` under `key`.
    pub fn with(mut self, key: Key, entry: Entry) -> Section {
        self.set(key, Some(entry));
        self
    }
}

/// Is `entry`, stored under `key`, visible through `view`?
pub(crate) const fn visible(view: View, key: Key, entry: Entry) -> bool {
    view.scope.contains(key.atom()) && entry.label.at_most(view.ceiling)
}

/// What `view` observes of `section`: every visible entry, unchanged — label
/// included, so an observation never lowers a label — and nothing else.
pub fn observe(section: &Section, view: View) -> Section {
    let mut seen = Section::EMPTY;
    for key in Key::ALL {
        if let Some(entry) = section.get(key) {
            if visible(view, key, entry) {
                seen.set(key, Some(entry));
            }
        }
    }
    seen
}

/// Whether two local sections agree where both write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overlap {
    /// Every key both write holds the same entry in each.
    Agree,
    /// The first key, in [`Key::ALL`] order, that both write differently.
    Conflict {
        /// The key.
        key: Key,
    },
}

/// Compare two local sections on their overlap.
///
/// Agreement here is a precondition for gluing, NOT validity: see
/// [`crate::validate_candidate`] and the budget counterexample in its tests.
pub fn compare_on_overlap(a: &Section, b: &Section) -> Overlap {
    for key in Key::ALL {
        if let (Some(x), Some(y)) = (a.get(key), b.get(key)) {
            if x != y {
                return Overlap::Conflict { key };
            }
        }
    }
    Overlap::Agree
}
