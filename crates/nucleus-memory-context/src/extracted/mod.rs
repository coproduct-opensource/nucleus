//! Subset-safe, Aeneas-shaped slices of the memory-context kernel.
//!
//! Same convention as `nucleus_ifc_kernel::extracted`: each function here is a
//! flat restatement of one production decision — integers, `bool`s and `Copy`
//! structs only; no `String`, `Vec`, `BTreeMap`, closures, iterators or trait
//! objects; every comparison is on an explicit rank or field, never a derived
//! `PartialEq`/`Ord` (Aeneas emits a derived comparison as an opaque axiom).
//!
//! Each slice is bound to its production function by an EXHAUSTIVE parity test over
//! the finite domain (`crate::parity_tests`). Folds over keys and patches stay in
//! the production code; the Lean model (`MemoryContext.lean`) mirrors them by hand.
//!
//! NOT YET EXTRACTED. No Charon/Aeneas run consumes these roots yet; the Lean
//! model is hand-written. Wiring an extraction is a follow-up, and needs its own
//! workflow (the existing ones extract `nucleus-ifc-kernel` only).

pub mod admit;
pub mod assemble;
pub mod commit;
pub mod observe;
pub mod overlap;
pub mod validate;
pub mod view;

/// One key's slot, flat. `present == false` means "no entry"; the other fields are
/// then zero by convention and every function below ignores them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlatSlot {
    /// Is an entry present?
    pub present: bool,
    /// The entry's content id.
    pub value: u8,
    /// The entry's label rank.
    pub label: u8,
    /// The entry's quota units.
    pub units: u8,
}

/// The absent slot.
pub const ABSENT: FlatSlot = FlatSlot {
    present: false,
    value: 0,
    label: 0,
    units: 0,
};

/// Field-by-field equality, written out so the comparison is translated rather than
/// an opaque derived `eq`.
pub fn flat_slot_eq(a: FlatSlot, b: FlatSlot) -> bool {
    a.present == b.present && a.value == b.value && a.label == b.label && a.units == b.units
}

/// Production slot → flat slot. The production-side bridge, NOT an extraction root.
pub fn flat(slot: Option<crate::Entry>) -> FlatSlot {
    match slot {
        None => ABSENT,
        Some(entry) => FlatSlot {
            present: true,
            value: entry.value.get(),
            label: entry.label.rank(),
            units: entry.units.get(),
        },
    }
}
