//! Overlap agreement of one slot, flat. Mirrors the per-key clause of
//! `compare_on_overlap`; Lean: `slotsAgree`.

use super::{FlatSlot, flat_slot_eq};

/// Do two slots agree? Only when both are present can they disagree.
pub fn slots_agree(a: FlatSlot, b: FlatSlot) -> bool {
    if a.present && b.present {
        flat_slot_eq(a, b)
    } else {
        true
    }
}
