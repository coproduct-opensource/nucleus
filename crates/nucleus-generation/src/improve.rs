//! The improvement order: did a generation move its own namespace strictly forward?
//!
//! Owner decision, 2026-10-26: **each generation must improve.** Holding every number steady is
//! not enough, because a stream allowed to idle can idle forever without failing its own rule.
//! So the order is strict:
//!
//! * no pre-existing metric may regress, unless the owner's signed waiver names it;
//! * at least one pre-existing `Higher` or `Lower` metric must strictly improve, and **this is
//!   not waivable**;
//! * a `Guard` may not fall, and its rising never counts;
//! * a metric introduced by this generation cannot be its improvement, or adding a trivially
//!   improvable metric would satisfy the rule.
//!
//! What it does not decide: whether the numbers are honest. That is the ledger gate's binding to
//! a verified execution artifact, in [`crate::verify`].

use std::collections::BTreeMap;

use crate::record::Direction;

/// One metric's movement under its direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Movement {
    /// Strictly better.
    Improved,
    /// Not worse, and not a counted improvement (equal, or a guard that rose).
    Held,
    /// Strictly worse.
    Regressed,
}

/// How one metric moved.
pub fn movement(direction: Direction, before: i64, after: i64) -> Movement {
    use std::cmp::Ordering::{Equal, Greater, Less};
    match (direction, after.cmp(&before)) {
        (_, Equal) => Movement::Held,
        (Direction::Higher, Greater) | (Direction::Lower, Less) => Movement::Improved,
        (Direction::Higher, Less) | (Direction::Lower, Greater) | (Direction::Guard, Less) => {
            Movement::Regressed
        }
        (Direction::Guard, Greater) => Movement::Held,
    }
}

/// Every pre-existing metric's movement, by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judgement {
    /// Metrics that strictly improved.
    pub improved: Vec<String>,
    /// Metrics that regressed.
    pub regressed: Vec<String>,
}

/// Compare `after` against `before` for every metric named in `before`, under `directions`.
///
/// Returns `Err(name)` for a metric `before` has and `after` lacks, or one with no direction:
/// a vanished measurement is not a held one.
pub fn judge(
    directions: &BTreeMap<String, Direction>,
    before: &BTreeMap<String, i64>,
    after: &BTreeMap<String, i64>,
) -> Result<Judgement, String> {
    let mut improved = Vec::new();
    let mut regressed = Vec::new();
    for (name, old) in before {
        let Some(new) = after.get(name) else {
            return Err(name.clone());
        };
        let Some(direction) = directions.get(name) else {
            return Err(name.clone());
        };
        match movement(*direction, *old, *new) {
            Movement::Improved => improved.push(name.clone()),
            Movement::Held => {}
            Movement::Regressed => regressed.push(name.clone()),
        }
    }
    Ok(Judgement {
        improved,
        regressed,
    })
}
