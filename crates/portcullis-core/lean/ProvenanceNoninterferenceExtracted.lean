/-
  Provenance Noninterference — proven OVER the Aeneas-EXTRACTED enforcement core.
  The source-set axis: the FIFTH and final extracted `flows_to` conjunct, and the
  only bitset (powerset lattice) axis. With this, ALL FIVE gating conjuncts of the
  production `IFCLabel::flows_to` are machine-checked over real Rust.

  **STATUS: to be verified by CI.** The `aeneas-ifc-scoped` job extracts the
  provenance functions (`EXTRACT_ROOTS` includes
  `ifc_provenance::{punion, psubset, prun_step}`) and builds this file
  (`lake build ProvenanceNoninterferenceExtracted`). The `#print axioms` audit at
  the bottom must print, for BOTH theorems, `[propext, Classical.choice,
  Quot.sound]` — no `sorryAx`, no Aeneas `*External`; the gate reads
  `/tmp/lake-prov-ifc.log`. In particular NO `Lean.ofReduceBool`: the bitvector
  facts are proved by `BitVec` extensionality + `Bool` case analysis, NOT
  `bv_decide`/`native_decide` (which would add that axiom).

  # The lattice (powerset under ⊆, via u8 bitmasks)

  `ProvenanceSet` is a `u8` bitset over six sources. `punion` is bitwise OR
  (combining data ADDS sources — the set only grows), and the `flows_to` conjunct
  is `psubset a ceiling := (a &&& ceiling) = a` (every source bit of `a` is in
  `ceiling`). Monotonicity is set growth: the fold only unions in more sources, so
  a source once present is never removed, and a datum carrying a source the sink
  does not accept can never be admitted over any op sequence.

  # Ground truth + scope boundary

  The generated defs mirror production by the EXHAUSTIVE parity tests in
  `src/extracted/ifc_provenance.rs` (over the full 6-bit mask domain).
  `IFCLabel::flows_to` is a five-axis conjunction; this theorem is the PROVENANCE
  conjunct only — sound because one false conjunct makes the whole `flows_to`
  false. The fold `prun` is hand-written Lean over the GENERATED step.
-/

import PortcullisCoreIFC.Types
import PortcullisCoreIFC.Funs

open Aeneas Aeneas.Std Result ControlFlow Error

set_option maxHeartbeats 1000000

namespace ProvenanceNoninterferenceExtracted

/-- Subset predicate on `U8`, matching the generated `psubset` body
    (`(a &&& ceiling) = a`). -/
def sub (a c : Std.U8) : Prop := a &&& c = a

/-- `U8` bitwise ops reduce to `BitVec` ops on the `.bv` field (definitional). -/
@[simp] theorem and_bv (a b : Std.U8) : (a &&& b).bv = a.bv &&& b.bv := rfl
@[simp] theorem or_bv (a b : Std.U8) : (a ||| b).bv = a.bv ||| b.bv := rfl

/-- `U8` equality reduces to `.bv` equality (structure with a single `bv` field). -/
theorem u8_eq_iff_bv (a b : Std.U8) : a = b ↔ a.bv = b.bv := by
  cases a; cases b; simp

/-- The single bridge: `sub` on `U8` is the `BitVec` subset equation. -/
theorem sub_iff_bv (a c : Std.U8) : sub a c ↔ a.bv &&& c.bv = a.bv := by
  simp only [sub, u8_eq_iff_bv, and_bv]

/-- **Absorption**: `a ⊆ (a ||| b)`. The running set always contains the starting
    set. Proved by `BitVec` extensionality + `Bool` case analysis (no `bv_decide`). -/
theorem sub_or_left (a b : Std.U8) : sub a (a ||| b) := by
  rw [sub_iff_bv]
  show a.bv &&& (a.bv ||| b.bv) = a.bv
  ext i
  simp only [BitVec.getElem_and, BitVec.getElem_or]
  cases a.bv[i] <;> simp

/-- **Transitivity**: `a ⊆ b → b ⊆ c → a ⊆ c`. Proved by `BitVec` extensionality:
    from the per-bit implications `a[i] → b[i]` and `b[i] → c[i]`. -/
theorem sub_trans {a b c : Std.U8} (h1 : sub a b) (h2 : sub b c) : sub a c := by
  rw [sub_iff_bv] at h1 h2 ⊢
  ext i
  have p1 := congrArg (fun x => x[i]) h1
  have p2 := congrArg (fun x => x[i]) h2
  simp only [BitVec.getElem_and] at p1 p2 ⊢
  revert p1 p2
  cases a.bv[i] <;> cases b.bv[i] <;> cases c.bv[i] <;> simp

/-- The generated `punion` always succeeds and returns the bitwise OR. -/
theorem punion_ok (a b : Std.U8) :
    nucleus_ifc_kernel.extracted.ifc_provenance.punion a b = ok (a ||| b) := by
  rfl

/-- The generated `psubset` returns `ok true` exactly when `sub a c` holds. -/
theorem psubset_true_iff (a c : Std.U8) :
    nucleus_ifc_kernel.extracted.ifc_provenance.psubset a c = ok true ↔ sub a c := by
  unfold nucleus_ifc_kernel.extracted.ifc_provenance.psubset sub
  simp [bind_tc_ok, lift]

/-- Fold the GENERATED `prun_step` over an operation list, threading the running
    effective provenance. The fold is hand-written Lean; each step IS the
    generated-from-Rust `prun_step` (= generated `punion`). -/
def prun : List Std.U8 → Std.U8 → Std.U8
  | [], eff => eff
  | src :: rest, eff =>
      prun rest
        (match nucleus_ifc_kernel.extracted.ifc_provenance.prun_step eff src with
         | ok r => r
         | _ => eff)

/-- The generated `prun_step` reduces to the generated `punion` result. -/
theorem prun_step_ok (eff src : Std.U8) :
    nucleus_ifc_kernel.extracted.ifc_provenance.prun_step eff src = ok (eff ||| src) := by
  unfold nucleus_ifc_kernel.extracted.ifc_provenance.prun_step
  rw [punion_ok]

/-- **Global composition.** Over ANY operation sequence, the running effective
    provenance CONTAINS the starting provenance — the fold only unions in more
    sources. Structural induction; the cons step combines `sub_or_left` with the
    IH by transitivity. -/
theorem prun_grows : ∀ (ops : List Std.U8) (eff : Std.U8), sub eff (prun ops eff) := by
  intro ops
  induction ops with
  | nil =>
      intro eff; rw [sub_iff_bv]; show eff.bv &&& eff.bv = eff.bv
      ext i; simp only [BitVec.getElem_and]; cases eff.bv[i] <;> simp
  | cons src rest ih =>
      intro eff
      simp only [prun]
      have hstep : (match nucleus_ifc_kernel.extracted.ifc_provenance.prun_step eff src with
                    | ok r => r | _ => eff) = eff ||| src := by
        rw [prun_step_ok]
      rw [hstep]
      exact sub_trans (sub_or_left eff src) (ih (eff ||| src))

/-- Admission holds iff the generated `psubset` returns `ok true`. -/
def padmitted (eff ceiling : Std.U8) : Prop :=
    nucleus_ifc_kernel.extracted.ifc_provenance.psubset eff ceiling = ok true

/-- **Provenance-axis noninterference (main theorem), over the GENERATED defs.**
    If the session's effective provenance already fails the sink's ceiling
    (`¬ sub eff ceiling` — it already carries a source the sink does not accept),
    then over ANY operation sequence the sink is NEVER admitted by the GENERATED
    `psubset`. The fold only ADDS sources, so it cannot recover admission. -/
theorem provenance_sink_never_admitted
    (eff ceiling : Std.U8) (ops : List Std.U8)
    (h_blocked : ¬ sub eff ceiling) :
    ¬ padmitted (prun ops eff) ceiling := by
  intro h_admit
  unfold padmitted at h_admit
  rw [psubset_true_iff] at h_admit
  -- h_admit : sub (prun ops eff) ceiling ; and eff ⊆ prun ops eff
  exact h_blocked (sub_trans (prun_grows ops eff) h_admit)

/-- **Instantiation: a forbidden source can NEVER be laundered.** If the session
    already carries a source bit `s` that the sink's ceiling does not accept
    (`¬ sub s0 ceiling` for the starting label `s0`), it is never admitted over
    any op sequence. Concretely for the WEB source (bit 2 = `4#u8`) and a
    USER-only sink (`1#u8`): WEB data never reaches a sink that omits WEB. -/
theorem web_source_never_reaches_web_free_sink (ops : List Std.U8) :
    ¬ padmitted (prun ops 4#u8) 1#u8 := by
  apply provenance_sink_never_admitted
  -- ¬ sub 4#u8 1#u8 : (4 &&& 1) = 4 is false
  rw [sub_iff_bv]
  decide

end ProvenanceNoninterferenceExtracted

/-
  Axiom audit. EXPECTED: [propext, Quot.sound, Classical.choice]. The bitvector
  facts (`sub_or_left`, `sub_trans`) are proved by `BitVec` extensionality + `Bool`
  case analysis, so they add NO `Lean.ofReduceBool` (which `bv_decide` /
  `native_decide` would). The extracted `ifc_provenance` uses only total `u8`
  bitwise ops, so there is no opaque `*External` axiom.
-/
#print axioms ProvenanceNoninterferenceExtracted.provenance_sink_never_admitted
#print axioms ProvenanceNoninterferenceExtracted.web_source_never_reaches_web_free_sink
