//! The compare-and-swap commit, flat. Mirrors `History::commit`; Lean: `commit`.

/// Committed.
pub const COMMITTED: u8 = 0;
/// The candidate's generation is not the head.
pub const STALE_BASE: u8 = 1;
/// The finite history is full.
pub const FULL: u8 = 2;

/// The commit verdict for a candidate validated over `generation`, onto a history
/// whose head is `head`, holding at most `capacity` versions (genesis included).
pub fn commit_code(generation: u8, head: u8, capacity: u8) -> u8 {
    if generation != head {
        return STALE_BASE;
    }
    match head.checked_add(1) {
        None => FULL,
        Some(next) => {
            if next < capacity {
                COMMITTED
            } else {
                FULL
            }
        }
    }
}
