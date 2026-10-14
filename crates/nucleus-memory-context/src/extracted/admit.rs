//! Admission, flat. Mirrors `crate::admit`; Lean: `admit`.

/// Admitted.
pub const ADMITTED: u8 = 0;
/// Minted in another epoch.
pub const FOREIGN_EPOCH: u8 = 1;
/// Past `not_after`.
pub const EXPIRED: u8 = 2;

/// The admission verdict: the epoch first, then expiry.
pub fn admit_code(binding_epoch: u32, not_after: u64, current_epoch: u32, now: u64) -> u8 {
    if binding_epoch != current_epoch {
        FOREIGN_EPOCH
    } else if not_after < now {
        EXPIRED
    } else {
        ADMITTED
    }
}
