/-
  Unwinding non-interference for the FlowTracker DAG fold — D1, milestone M1.

  Self-contained (NO Mathlib import) so it kernel-checks fast and locally; the
  instantiation over the Mathlib-backed `IFCLabel` lattice is M1b (CI-bound).

  Proves the multi-hop / UNBOUNDED result that enumeration cannot: in a
  provenance DAG whose node labels are joins over their parents
  (`FlowTracker::observe_with_parents`, the fold landed in PR #1904), a sink whose
  ceiling admits a *descendant's* label admits *every ancestor's* label — and the
  security-facing contrapositive: a source the sink would reject can never be
  laundered through any chain of descendants to reach that sink.

  Structure (per docs/rfcs/multi-hop-noninterference-unwinding.md §5):
    single-step unwinding conditions (the fold dominates base + each parent)
      → reachability = reflexive-transitive closure of the per-edge flow
      → multi-hop unwinding theorem (admit propagates to ancestors)
      → non-interference (contrapositive).
-/

namespace UnwindingNoninterference

/-- The minimal order-theoretic kit the unwinding argument needs: a partial order
    with a join that is an upper bound of its arguments. The IFC label lattice
    (`IFCSemilatticeProofs`, a `Lattice`/`OrderBot`/`OrderTop`) is an instance;
    M1b instantiates over it so the theorem applies to the real gate. -/
class JoinOrder (α : Type _) where
  le : α → α → Prop
  le_refl : ∀ a : α, le a a
  le_trans : ∀ {a b c : α}, le a b → le b c → le a c
  join : α → α → α
  le_join_left : ∀ a b : α, le a (join a b)
  le_join_right : ∀ a b : α, le b (join a b)

namespace JoinOrder
variable {α : Type _} [JoinOrder α]

/-- Fold a node's parents into its base (intrinsic) label:
    `foldJoin intrinsic parents = intrinsic ⊔ ⨆ parents`.
    Mirrors the `FlowTracker` per-node label computation (PR #1904). -/
def foldJoin (base : α) : List α → α
  | [] => base
  | x :: xs => foldJoin (join base x) xs

/-- SINGLE-STEP unwinding condition (1): the base flows into the fold. -/
theorem le_foldJoin_base (base : α) (xs : List α) : le base (foldJoin base xs) := by
  induction xs generalizing base with
  | nil => exact le_refl base
  | cons x xs ih => exact le_trans (le_join_left base x) (ih (join base x))

/-- SINGLE-STEP unwinding condition (2): every parent flows into the fold — the
    child's label dominates each parent (taint propagates forward, never lost). -/
theorem mem_le_foldJoin (base : α) (xs : List α) :
    ∀ x, x ∈ xs → le x (foldJoin base xs) := by
  induction xs generalizing base with
  | nil => intro x h; simp at h
  | cons y ys ih =>
    intro x h
    rw [List.mem_cons] at h
    cases h with
    | inl heq => subst heq; exact le_trans (le_join_right base x) (le_foldJoin_base (join base x) ys)
    | inr htl => exact ih (join base y) x htl

/-- Reachability: the reflexive-transitive closure of the per-edge flow `le`
    (a flow edge is `parent ≤ child`). An ancestor reaches its descendants. -/
inductive Reaches : α → α → Prop
  | refl (a : α) : Reaches a a
  | step {a b c : α} : le a b → Reaches b c → Reaches a c

/-- Reachability collapses to `le` — a preorder is its own transitive closure. -/
theorem reaches_le {a b : α} : Reaches a b → le a b
  | .refl a => le_refl a
  | .step hab hbc => le_trans hab (reaches_le hbc)

/-- The fold induces flow edges: every parent reaches the folded child node.
    This is the bridge from the single-step conditions to multi-hop reachability. -/
theorem reaches_of_mem_foldJoin (base : α) (xs : List α) {x : α} (h : x ∈ xs) :
    Reaches x (foldJoin base xs) :=
  .step (mem_le_foldJoin base xs x h) (.refl _)

/-- MULTI-HOP UNWINDING THEOREM. If a sink's ceiling admits a node reachable from
    `source` along any number of flow edges, it admits `source` too. Unbounded in
    the chain length — the result enumeration cannot give. -/
theorem unwinding_admit_propagates {source node ceiling : α}
    (reach : Reaches source node) (admit : le node ceiling) : le source ceiling :=
  le_trans (reaches_le reach) admit

/-- NON-INTERFERENCE (the security-facing contrapositive): a `source` the sink
    would reject can never be laundered through descendants to reach that sink. -/
theorem unwinding_noninterference {source node ceiling : α}
    (reach : Reaches source node) (blocked : ¬ le source ceiling) : ¬ le node ceiling :=
  fun admit => blocked (unwinding_admit_propagates reach admit)

end JoinOrder

/-- Non-vacuity witness: a concrete `JoinOrder` (ℕ with `≤` and `max`-by-if),
    Mathlib-free, so the theorems above are not vacuously about an empty class. -/
instance : JoinOrder Nat where
  le := Nat.le
  le_refl := Nat.le_refl
  le_trans := Nat.le_trans
  join a b := if a ≤ b then b else a
  le_join_left a b := by
    by_cases h : a ≤ b
    · rw [if_pos h]; exact h
    · rw [if_neg h]; exact Nat.le_refl a
  le_join_right a b := by
    by_cases h : a ≤ b
    · rw [if_pos h]; exact Nat.le_refl b
    · rw [if_neg h]; exact Nat.le_of_lt (Nat.lt_of_not_le h)

open JoinOrder in
/-- Non-vacuous multi-hop instance: source 5 reaches node 7, a ceiling-4 sink
    rejects 5, hence (by the theorem, not by hand) rejects 7. Distinct
    source/node/ceiling — a genuine implication, not a trivial reflexive one. -/
example : ¬ JoinOrder.le (7 : Nat) 4 :=
  unwinding_noninterference (source := (5 : Nat)) (node := 7) (ceiling := 4)
    (.step (show (5 : Nat) ≤ 7 by decide) (.refl 7))
    (show ¬ (5 : Nat) ≤ 4 by decide)

-- The unwinding theorem is fully CONSTRUCTIVE — it depends on NO axioms (not even
-- `propext`/`Quot.sound`, and no proof-hole or `ofReduceBool` axioms). The
-- strongest possible footprint; the `#guard_msgs` gate below fails the build the
-- moment a future change weakens it (the M1 axiom-footprint gate, RFC §9).
/-- info: 'UnwindingNoninterference.JoinOrder.unwinding_noninterference' does not depend on any axioms -/
#guard_msgs in
#print axioms JoinOrder.unwinding_noninterference

end UnwindingNoninterference
