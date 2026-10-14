//! One assembly step for one key, flat. Mirrors `candidate::step_slot`; Lean:
//! `SlotAcc`, `stepSlot`.

use super::{FlatSlot, flat_slot_eq};

/// The per-key accumulator of an assembly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlatAcc {
    /// The slot so far.
    pub slot: FlatSlot,
    /// Has a patch written this key yet?
    pub touched: bool,
    /// Did two patches write it differently?
    pub conflict: bool,
}

/// Fold one patch's slot into the accumulator.
pub fn step_slot(acc: FlatAcc, patch: FlatSlot) -> FlatAcc {
    if !patch.present {
        acc
    } else if !acc.touched {
        FlatAcc {
            slot: patch,
            touched: true,
            conflict: acc.conflict,
        }
    } else if flat_slot_eq(acc.slot, patch) {
        acc
    } else {
        FlatAcc {
            slot: acc.slot,
            touched: true,
            conflict: true,
        }
    }
}
