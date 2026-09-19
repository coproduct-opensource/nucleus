//! What a command reads and writes, declared once, and the sequencing laws DERIVED
//! from it.
//!
//! # Why
//!
//! Three commutation censuses — the guest API's, the pod API's, and the faces
//! between them — each measured which pairs of commands are order-dependent and
//! compared the result with a hand-written rule. The three rules were one fact in
//! three spellings: *two effects commute unless one writes what the other reads.*
//! That is Mazurkiewicz independence from read/write sets, and separation logic's
//! frame rule in its simplest form. Written three times, it could drift three ways
//! (ADR 0007 G-1).
//!
//! So each surface declares a [`Footprint`] per command — the resources it reads and
//! how it writes them — and the laws are derived:
//!
//! - **order-dependent** pairs, [`hollow_faces`]: `a` writes what `b` reads, or `b`
//!   writes what `a` reads;
//! - **non-idempotent** commands, [`not_idempotent`]: those that [`Access::Update`]
//!   something — read-modify-write, append, consume a one-shot — so doing it twice
//!   is not doing it once.
//!
//! The censuses still MEASURE both against the code, in both directions. A
//! footprint that under-declares shows up as a hollow face nobody derived; one that
//! over-declares, as a derived face that measured filled.
//!
//! # Scope is a read
//!
//! An effect that is only valid while its pod lives reads that pod's liveness: a
//! cancel writes it, so the two never commute. The barrier law from #2930 ("once a
//! pod is cancelled its guest is served nothing") is not a separate rule here; it is
//! what a guest command's footprint says.
//!
//! # What this does not claim
//!
//! Disjoint footprints imply commuting only if the footprints are honest, and that
//! is what the censuses check — over the states and letters they enumerate, not for
//! all programs.

use std::collections::BTreeSet;

/// How an effect touches one resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Access {
    /// Observes it; changes nothing.
    Read,
    /// Overwrites it with a value that does not depend on what was there: doing it
    /// twice is doing it once (a cancel, a latch that only goes one way).
    Set,
    /// Reads it and writes something that depends on what was there: an append, a
    /// counter, a one-shot consumed.
    Update,
}

/// The resources one effect reads and writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Footprint<R> {
    accesses: BTreeSet<(R, Access)>,
}

impl<R: Ord + Clone> Footprint<R> {
    /// Touches nothing.
    pub(crate) fn pure() -> Self {
        Self {
            accesses: BTreeSet::new(),
        }
    }

    pub(crate) fn read(mut self, r: R) -> Self {
        self.accesses.insert((r, Access::Read));
        self
    }

    pub(crate) fn set(mut self, r: R) -> Self {
        self.accesses.insert((r, Access::Set));
        self
    }

    pub(crate) fn update(mut self, r: R) -> Self {
        self.accesses.insert((r, Access::Update));
        self
    }

    fn read_set(&self) -> BTreeSet<&R> {
        self.accesses
            .iter()
            .filter(|(_, a)| matches!(a, Access::Read | Access::Update))
            .map(|(r, _)| r)
            .collect()
    }

    fn write_set(&self) -> BTreeSet<&R> {
        self.accesses
            .iter()
            .filter(|(_, a)| matches!(a, Access::Set | Access::Update))
            .map(|(r, _)| r)
            .collect()
    }

    /// Whether the two effects' order can be observed: one writes what the other
    /// reads.
    pub(crate) fn conflicts_with(&self, other: &Self) -> bool {
        !self.write_set().is_disjoint(&other.read_set())
            || !other.write_set().is_disjoint(&self.read_set())
    }

    /// Whether doing it twice is doing it once.
    pub(crate) fn idempotent(&self) -> bool {
        !self.accesses.iter().any(|(_, a)| *a == Access::Update)
    }
}

/// Every order-dependent pair of `letters`, as `(earlier, later)` in the order given.
pub(crate) fn hollow_faces<L: Copy + Ord, R: Ord + Clone>(
    letters: &[L],
    footprint: impl Fn(L) -> Footprint<R>,
) -> BTreeSet<(L, L)> {
    let prints: Vec<Footprint<R>> = letters.iter().map(|l| footprint(*l)).collect();
    let mut out = BTreeSet::new();
    for (i, a) in letters.iter().enumerate() {
        for (j, b) in letters.iter().enumerate().skip(i.saturating_add(1)) {
            if prints[i].conflicts_with(&prints[j]) {
                out.insert((*a, *b));
            }
        }
    }
    out
}

/// The letters that are not idempotent.
pub(crate) fn not_idempotent<L: Copy + Ord, R: Ord + Clone>(
    letters: &[L],
    footprint: impl Fn(L) -> Footprint<R>,
) -> BTreeSet<L> {
    letters
        .iter()
        .copied()
        .filter(|l| !footprint(*l).idempotent())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_write_conflicts_with_a_read_of_the_same_resource_and_nothing_else() {
        let set_a = Footprint::pure().set("a");
        assert!(set_a.conflicts_with(&Footprint::pure().read("a")));
        assert!(
            Footprint::pure().read("a").conflicts_with(&set_a),
            "symmetric"
        );
        assert!(
            !set_a.conflicts_with(&Footprint::pure().read("b")),
            "disjoint"
        );
        assert!(
            !set_a.conflicts_with(&Footprint::pure().set("a")),
            "two blind overwrites with fixed values commute"
        );
        assert!(
            !Footprint::pure()
                .read("a")
                .conflicts_with(&Footprint::pure().read("a")),
            "reads commute"
        );
    }

    #[test]
    fn an_update_reads_and_writes_so_it_conflicts_with_itself_and_is_not_idempotent() {
        let append = Footprint::pure().update("log");
        assert!(append.conflicts_with(&Footprint::pure().update("log")));
        assert!(!append.idempotent());
        assert!(Footprint::pure().set("latch").idempotent());
        assert!(Footprint::<&str>::pure().idempotent());
    }

    #[test]
    fn faces_are_the_conflicting_pairs_in_letter_order() {
        let letters = [0u8, 1, 2];
        let fp = |l: u8| match l {
            0 => Footprint::pure().set("x"),
            1 => Footprint::pure().read("x"),
            _ => Footprint::pure().update("y"),
        };
        assert_eq!(hollow_faces(&letters, fp), BTreeSet::from([(0, 1)]));
        assert_eq!(not_idempotent(&letters, fp), BTreeSet::from([2]));
    }
}
