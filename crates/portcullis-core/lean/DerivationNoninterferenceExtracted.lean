/-
  Derivation Noninterference — proven OVER the Aeneas-EXTRACTED enforcement core.
  The determinism-provenance axis: the FOURTH extracted `flows_to` conjunct
  (after integrity, confidentiality, authority) and the first that is a genuine
  LATTICE (a diamond) rather than a total-order chain.

  **STATUS: to be verified by CI.** The `aeneas-ifc-scoped` job extracts the
  derivation functions (`EXTRACT_ROOTS` includes
  `ifc_derivation::{djoin, dleq, drun_step}`) and builds this file
  (`lake build DerivationNoninterferenceExtracted`). The `#print axioms` audit at
  the bottom must print, for BOTH theorems, `[propext, Classical.choice,
  Quot.sound]` — no `sorryAx`, no Aeneas `*External`; the `Assert clean axiom
  set` gate reads `/tmp/lake-deriv-ifc.log`.

  The chain:

      crates/nucleus-ifc-kernel/src/extracted/ifc_derivation.rs   (real Rust)
        --charon (scoped, --start-from)-->  nucleus_ifc_kernel.llbc
        --aeneas -backend lean -split-files-->
          generated-ifc/PortcullisCoreIFC/{Types,Funs}.lean   (THIS file's deps)
        --(this file)-->  derivation noninterference over THOSE generated defs.

  # The lattice (why this is not a chain proof)

  `DerivationClass` is the diamond `Deterministic < {AIDerived, HumanPromoted} <
  Mixed < OpaqueExternal`. `djoin` is the least upper bound (combining data moves
  UP toward "less reproducible"), and `dleq a b := djoin a b == b` is the induced
  order. So the monotonicity argument is over the lattice order directly (not a
  numeric rank + `omega`): the fold only moves UP, so if a source already exceeds
  a sink's ceiling it can never be brought back down. The main theorem: AI-derived
  / opaque data can never reach a sink that requires `Deterministic`
  (reproducible) provenance — the crate's "no silent cleansing" invariant, made a
  noninterference statement over any op sequence.

  # Ground truth + scope boundary

  The generated defs mirror production by the EXHAUSTIVE 5×5 parity tests in
  `src/extracted/ifc_derivation.rs`. `IFCLabel::flows_to` is a five-axis
  conjunction; this theorem is the DERIVATION conjunct only — sound because one
  false conjunct makes the whole `flows_to` false. The fold `drun` is hand-written
  Lean over the GENERATED step.
-/

import PortcullisCoreIFC.Types
import PortcullisCoreIFC.Funs

open Aeneas Aeneas.Std Result ControlFlow Error

set_option maxHeartbeats 1000000

namespace DerivationNoninterferenceExtracted

/-- Short alias for the Aeneas-generated derivation enum (from real Rust). -/
abbrev DC := nucleus_ifc_kernel.extracted.ifc_derivation.DerivationClass

-- Decidable equality on the generated enum, so `decide` can discharge the
-- finite lattice facts below. Derived (no extra axioms). Stated on the full type
-- name (a doc-comment cannot precede a `deriving instance` command).
deriving instance DecidableEq for nucleus_ifc_kernel.extracted.ifc_derivation.DerivationClass

/-- Pure-Lean mirror of the generated `djoin` (the lattice LUB), transcribing the
    same match arms. Used to state monotonicity without a numeric rank. -/
def joinP : DC → DC → DC
  | .Deterministic, x => x
  | x, .Deterministic => x
  | .OpaqueExternal, _ => .OpaqueExternal
  | _, .OpaqueExternal => .OpaqueExternal
  | .AIDerived, .AIDerived => .AIDerived
  | .HumanPromoted, .HumanPromoted => .HumanPromoted
  | .Mixed, .Mixed => .Mixed
  | _, _ => .Mixed

/-- The generated `djoin` always succeeds and returns `joinP`. 25 concrete pairs,
    each reducing the generated `match`. -/
theorem djoin_ok (a b : DC) :
    nucleus_ifc_kernel.extracted.ifc_derivation.djoin a b = ok (joinP a b) := by
  cases a <;> cases b <;> rfl

/-- The lattice order induced by the join: `a ⊑ b` iff `joinP a b = b`. -/
def leqP (a b : DC) : Prop := joinP a b = b

instance (a b : DC) : Decidable (leqP a b) := inferInstanceAs (Decidable (joinP a b = b))

/-- Reflexivity (idempotence of the join). -/
theorem leqP_refl (a : DC) : leqP a a := by cases a <;> decide

/-- Transitivity of the lattice order (finite, 125 cases). -/
theorem leqP_trans {a b c : DC} (h1 : leqP a b) (h2 : leqP b c) : leqP a c := by
  cases a <;> cases b <;> cases c <;>
    first
      | decide
      | simp_all [leqP, joinP]

/-- `joinP a b` is an upper bound of `a` (the fold only moves UP). -/
theorem leqP_join_left (a b : DC) : leqP a (joinP a b) := by cases a <;> cases b <;> decide

/-- The generated `dleq` returns `ok true` exactly when the pure lattice order
    holds. Both sides are concrete after the 25-way split. -/
theorem dleq_true_iff (a b : DC) :
    nucleus_ifc_kernel.extracted.ifc_derivation.dleq a b = ok true ↔ leqP a b := by
  cases a <;> cases b <;>
    simp only [nucleus_ifc_kernel.extracted.ifc_derivation.dleq,
               nucleus_ifc_kernel.extracted.ifc_derivation.djoin,
               nucleus_ifc_kernel.extracted.ifc_derivation.DerivationClass.Insts.CoreCmpPartialEqDerivationClass.eq,
               leqP, joinP, bind_tc_ok, Result.ok.injEq, decide_eq_true_eq] <;>
    decide

/-- Fold the GENERATED `drun_step` over an operation list, threading the running
    effective derivation. The fold is hand-written Lean; each step IS the
    generated-from-Rust `drun_step` (= generated `djoin`). -/
def drun : List DC → DC → DC
  | [], eff => eff
  | src :: rest, eff =>
      drun rest
        (match nucleus_ifc_kernel.extracted.ifc_derivation.drun_step eff src with
         | ok r => r
         | _ => eff)

/-- The generated `drun_step` reduces to the generated `djoin` result. -/
theorem drun_step_ok (eff src : DC) :
    nucleus_ifc_kernel.extracted.ifc_derivation.drun_step eff src = ok (joinP eff src) := by
  unfold nucleus_ifc_kernel.extracted.ifc_derivation.drun_step
  rw [djoin_ok]

/-- **Global composition.** Over ANY operation sequence, the running effective
    derivation is ⊒ the starting derivation — the fold only moves UP the lattice.
    Structural induction; the cons step combines `leqP_join_left` with the IH by
    transitivity. -/
theorem drun_raises : ∀ (ops : List DC) (eff : DC), leqP eff (drun ops eff) := by
  intro ops
  induction ops with
  | nil => intro eff; simpa [drun] using leqP_refl eff
  | cons src rest ih =>
      intro eff
      simp only [drun]
      have hstep : (match nucleus_ifc_kernel.extracted.ifc_derivation.drun_step eff src with
                    | ok r => r | _ => eff) = joinP eff src := by
        rw [drun_step_ok]
      rw [hstep]
      exact leqP_trans (leqP_join_left eff src) (ih (joinP eff src))

/-- Admission holds iff the generated `dleq` returns `ok true`. -/
def dadmitted (eff ceiling : DC) : Prop :=
    nucleus_ifc_kernel.extracted.ifc_derivation.dleq eff ceiling = ok true

/-- **Derivation-axis noninterference (main theorem), over the GENERATED defs.**
    If the session's effective derivation already fails the sink's ceiling
    (`¬ leqP eff ceiling` — it is already too un-reproducible), then over ANY
    operation sequence the sink is NEVER admitted by the GENERATED `dleq`. The
    fold only moves UP, so it cannot recover admission. -/
theorem derivation_sink_never_admitted
    (eff ceiling : DC) (ops : List DC)
    (h_blocked : ¬ leqP eff ceiling) :
    ¬ dadmitted (drun ops eff) ceiling := by
  intro h_admit
  unfold dadmitted at h_admit
  rw [dleq_true_iff] at h_admit
  -- h_admit : leqP (drun ops eff) ceiling
  have h_raise : leqP eff (drun ops eff) := drun_raises ops eff
  exact h_blocked (leqP_trans h_raise h_admit)

/-- **Instantiation: AI-derived data can NEVER reach a Deterministic sink**, over
    the GENERATED defs. A session whose effective derivation is `AIDerived`
    (LLM-generated, not reproducible) is never admitted at a sink that requires
    `Deterministic` provenance, over ANY operation sequence — the "no silent
    cleansing" invariant as noninterference. Non-vacuous: `¬ leqP AIDerived
    Deterministic` holds by `decide`. -/
theorem ai_derived_never_reaches_deterministic (ops : List DC) :
    ¬ dadmitted (drun ops .AIDerived) .Deterministic := by
  apply derivation_sink_never_admitted
  decide

end DerivationNoninterferenceExtracted

/-
  Axiom audit. EXPECTED: [propext, Quot.sound, Classical.choice]. Anything else —
  `sorryAx` or an Aeneas `*External` opaque axiom — MUST fail review. The
  extracted `ifc_derivation` uses derived `PartialEq` (translated by Aeneas to a
  concrete `read_discriminant` comparison, no opaque axiom); the finite lattice
  facts use `decide`/`simp` (kernel-checked, NOT `native_decide`, so no
  `Lean.ofReduceBool`).
-/
#print axioms DerivationNoninterferenceExtracted.derivation_sink_never_admitted
#print axioms DerivationNoninterferenceExtracted.ai_derived_never_reaches_deterministic
