//! Views: a scope over a bounded set of atoms, and a label ceiling.

/// One scope atom of the finite model: a namespace or schema class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeAtom {
    /// The first namespace.
    Ns0,
    /// The second namespace.
    Ns1,
    /// The third namespace.
    Ns2,
}

impl ScopeAtom {
    /// Every atom, in bit order.
    pub const ALL: [ScopeAtom; 3] = [ScopeAtom::Ns0, ScopeAtom::Ns1, ScopeAtom::Ns2];

    /// This atom's bit in a [`Scope`].
    pub const fn bit(self) -> u8 {
        match self {
            ScopeAtom::Ns0 => 1,
            ScopeAtom::Ns1 => 2,
            ScopeAtom::Ns2 => 4,
        }
    }
}

/// A set of scope atoms — a fixed-size bitset. Only bits of real atoms can be set:
/// the constructor refuses any other bit, so "a scope wider than the model" is not a
/// value this type has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scope(u8);

impl Scope {
    /// Every atom's bit. `laws_tests::mask_is_every_atom` holds it to [`ScopeAtom::ALL`].
    const MASK: u8 = ScopeAtom::Ns0.bit() | ScopeAtom::Ns1.bit() | ScopeAtom::Ns2.bit();

    /// No atom.
    pub const EMPTY: Scope = Scope(0);

    /// Every atom.
    pub const FULL: Scope = Scope(Self::MASK);

    /// The scope with exactly these bits, or `None` if a bit names no atom.
    pub const fn from_bits(bits: u8) -> Option<Scope> {
        if bits & !Self::MASK == 0 {
            Some(Scope(bits))
        } else {
            None
        }
    }

    /// The raw bits.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// The scope holding one atom.
    pub const fn of(atom: ScopeAtom) -> Scope {
        Scope(atom.bit())
    }

    /// This scope plus `atom`.
    pub const fn with(self, atom: ScopeAtom) -> Scope {
        Scope(self.0 | atom.bit())
    }

    /// Does this scope hold `atom`?
    pub const fn contains(self, atom: ScopeAtom) -> bool {
        self.0 & atom.bit() != 0
    }

    /// Is every atom of `self` also in `other`?
    pub const fn is_subset_of(self, other: Scope) -> bool {
        self.0 & !other.0 == 0
    }

    /// Every scope of the finite model.
    pub fn all() -> impl Iterator<Item = Scope> {
        (0..=Self::MASK).filter_map(Scope::from_bits)
    }
}

/// A label rank: the confidentiality ceiling a view may see, and the label an entry
/// carries. Compared by an explicit [`rank`](LabelRank::rank), never a derived order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelRank {
    /// Anyone in scope may see it.
    Public,
    /// Internal to the tenant.
    Internal,
    /// The most restricted.
    Secret,
}

impl LabelRank {
    /// Every rank, lowest first.
    pub const ALL: [LabelRank; 3] = [LabelRank::Public, LabelRank::Internal, LabelRank::Secret];

    /// The explicit rank.
    pub const fn rank(self) -> u8 {
        match self {
            LabelRank::Public => 0,
            LabelRank::Internal => 1,
            LabelRank::Secret => 2,
        }
    }

    /// Is `self` no higher than `other`?
    pub const fn at_most(self, other: LabelRank) -> bool {
        self.rank() <= other.rank()
    }
}

/// What a run may see: which atoms, up to which label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct View {
    /// The scope atoms visible through this view.
    pub scope: Scope,
    /// The highest label visible through this view.
    pub ceiling: LabelRank,
}

impl View {
    /// Is `self` no wider than `wider`: a subset of its scope, and a ceiling no higher?
    pub const fn is_within(self, wider: View) -> bool {
        self.scope.is_subset_of(wider.scope) && self.ceiling.at_most(wider.ceiling)
    }

    /// Does this view see an entry in scope atom `atom` carrying label `label`? The one
    /// visibility decision: [`crate::observe`] asks it per key, and a store that maps
    /// its records onto atoms and ranks asks it per record.
    pub const fn admits(self, atom: ScopeAtom, label: LabelRank) -> bool {
        self.scope.contains(atom) && label.at_most(self.ceiling)
    }

    /// Every view of the finite model.
    pub fn all() -> impl Iterator<Item = View> {
        Scope::all().flat_map(|scope| {
            LabelRank::ALL
                .into_iter()
                .map(move |ceiling| View { scope, ceiling })
        })
    }
}

/// Narrow `view` to `narrower`.
///
/// Returns `narrower` when it is within `view`, and `None` — a refusal, never
/// "unrestricted" — when any atom or the ceiling would widen. A wider request is
/// refused rather than clipped, so a caller cannot mistake a clipped view for the one
/// it asked for. Restriction is not authorization: it can only take away.
pub const fn restrict(view: View, narrower: View) -> Option<View> {
    if narrower.is_within(view) {
        Some(narrower)
    } else {
        None
    }
}
