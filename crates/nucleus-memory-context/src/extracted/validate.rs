//! Whole-candidate validation, flat. Mirrors the per-key clauses and the quota of
//! `validate_candidate`; Lean: `checkSlot`, `total`, `validate`.

use super::FlatSlot;

/// The key passes.
pub const SLOT_OK: u8 = 0;
/// Two patches wrote the key differently.
pub const SLOT_CONFLICT: u8 = 1;
/// The base held an entry the candidate dropped.
pub const SLOT_DROPPED: u8 = 2;
/// The candidate lowers the stored label.
pub const SLOT_LOWERED: u8 = 3;

/// The per-key verdict, in the production order: conflict, dropped, lowered.
pub fn slot_check(conflict: bool, base: FlatSlot, merged: FlatSlot) -> u8 {
    if conflict {
        SLOT_CONFLICT
    } else if base.present && !merged.present {
        SLOT_DROPPED
    } else if base.present && merged.label < base.label {
        SLOT_LOWERED
    } else {
        SLOT_OK
    }
}

/// Add one slot's units to a running total, saturating.
pub fn add_units(total: u16, slot: FlatSlot) -> u16 {
    if slot.present {
        total.saturating_add(slot.units as u16)
    } else {
        total
    }
}

/// Does `total` fit the quota?
pub fn quota_admits(total: u16, quota: u16) -> bool {
    total <= quota
}
