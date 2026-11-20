//! Visibility of one slot, flat. Mirrors `section::visible`; Lean: `visible`,
//! `observeSlot`.

use super::{ABSENT, FlatSlot};

/// May a view `(scope, ceiling)` see an entry labelled `label` under a key whose
/// atom bit is `key_bit`?
pub fn slot_visible(scope: u8, ceiling: u8, key_bit: u8, label: u8) -> bool {
    scope & key_bit != 0 && label <= ceiling
}

/// What a view observes of one slot: the slot unchanged if visible, else absent.
pub fn observe_slot(scope: u8, ceiling: u8, key_bit: u8, slot: FlatSlot) -> FlatSlot {
    if slot.present && slot_visible(scope, ceiling, key_bit, slot.label) {
        slot
    } else {
        ABSENT
    }
}
