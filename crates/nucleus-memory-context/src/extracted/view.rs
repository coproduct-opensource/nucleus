//! Restriction, flat. Mirrors `crate::restrict` and `View::is_within`; Lean:
//! `MemoryContext.subsetB`, `View.le`, `restrict`.

/// Is every bit of `narrow` also in `wide`? Written as `narrow & wide == narrow`,
/// the Lean `subsetB`, where production writes `narrow & !wide == 0`.
pub fn scope_subset(narrow: u8, wide: u8) -> bool {
    narrow & wide == narrow
}

/// Is label rank `a` no higher than `b`?
pub fn rank_le(a: u8, b: u8) -> bool {
    a <= b
}

/// Does `restrict(view, narrower)` admit `narrower`? A view is `(scope bits, ceiling rank)`.
pub fn restrict_admits(
    view_scope: u8,
    view_ceiling: u8,
    narrower_scope: u8,
    narrower_ceiling: u8,
) -> bool {
    scope_subset(narrower_scope, view_scope) && rank_le(narrower_ceiling, view_ceiling)
}
