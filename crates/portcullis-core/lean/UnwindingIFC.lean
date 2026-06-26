/-
  Multi-hop non-interference for the REAL IFC label lattice — D1, milestone M1b.

  M1 (`UnwindingNoninterference`) proved the unwinding theorem abstractly over a
  minimal `JoinOrder`. M1b discharges the assumption that the production IFC label
  type IS such an order, by exhibiting the instance from the Mathlib-backed
  `IFCSemilatticeProofs` lattice (`IFCLabel2`: a `Lattice`/`SemilatticeSup`), and
  re-states the theorem specialized to it. The result therefore applies to the
  actual label algebra the gate uses — not just an abstract order.

  This file imports Mathlib (via `IFCSemilatticeProofs`), so it is CI-verified,
  not local (Mathlib builds time out locally). See
  docs/rfcs/multi-hop-noninterference-unwinding.md §6.
-/
import IFCSemilatticeProofs
import UnwindingNoninterference

namespace UnwindingIFC

open IFCSemilatticeProofs UnwindingNoninterference

/-- The production IFC label lattice is a `JoinOrder`: its information-flow order
    `≤` (Biba — conf covariant, integ contravariant) is a partial order, and its
    `⊔` (the IFC join) is the least upper bound. So the unwinding theorem applies
    to the real label type. The join's `le_sup_left/right` come from the
    `SemilatticeSup IFCLabel2` instance (`IFCSemilatticeProofs`). -/
instance : JoinOrder IFCLabel2 where
  le := (· ≤ ·)
  le_refl a := _root_.le_refl a
  le_trans h₁ h₂ := _root_.le_trans h₁ h₂
  join := (· ⊔ ·)
  le_join_left _ _ := _root_.le_sup_left
  le_join_right _ _ := _root_.le_sup_right

/-- MULTI-HOP NON-INTERFERENCE for IFC labels (the M1b headline). A `source`
    label that a sink would reject (its label does not flow to the sink ceiling)
    can never be laundered — through a provenance chain/DAG of ANY length whose
    node labels are IFC joins over parents — to reach that sink. The abstract
    unwinding theorem, now binding the real `IFCLabel2` algebra. -/
theorem ifc_multihop_noninterference {source node ceiling : IFCLabel2}
    (reach : JoinOrder.Reaches source node) (blocked : ¬ source ≤ ceiling) :
    ¬ node ≤ ceiling :=
  JoinOrder.unwinding_noninterference reach blocked

/-- Dually: a sink that admits a descendant's label admits every ancestor's. -/
theorem ifc_admit_propagates {source node ceiling : IFCLabel2}
    (reach : JoinOrder.Reaches source node) (adm : node ≤ ceiling) :
    source ≤ ceiling :=
  JoinOrder.unwinding_admit_propagates reach adm

/-- The fold induces the flow edges: a node built as an IFC join over parents is
    reached by each parent (taint propagates forward into the child). This is the
    bridge from `FlowTracker`'s per-node fold (PR #1904) to `Reaches`. -/
theorem ifc_parent_reaches_child (base : IFCLabel2) (parents : List IFCLabel2)
    {p : IFCLabel2} (hp : p ∈ parents) :
    JoinOrder.Reaches p (JoinOrder.foldJoin base parents) :=
  JoinOrder.reaches_of_mem_foldJoin base parents hp

end UnwindingIFC
