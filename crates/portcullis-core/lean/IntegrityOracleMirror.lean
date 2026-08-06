/-
  The INTEGRITY oracles, mirrored in plain Lean — the second axis of the
  reference pod machine (Machine v3, gate 1).

  # Why a second axis

  Machine v1 and v2 are confidentiality-only: a floating `ConfLevel` that JOINS
  (combining data raises secrecy) and a flows-to that is `≤` (no read up). The
  shipped kernel has a second, ORTHOGONAL axis, and it runs the other way:

      confidentiality   Public 0 < Internal 1 < Secret 2     join = max   flows: a ≤ ceiling
      integrity     Adversarial 0 < Untrusted 1 < Trusted 2  meet = MIN   flows: a ≥ ceiling

  Combining data LOWERS integrity (`imeet`) exactly as it RAISES confidentiality
  (`cjoin`), and the two flows-to relations point in opposite directions. That
  asymmetry is where a two-axis unwinding proof is most likely to break, and it
  is the reason the v3 gate is worth running rather than assuming.

  These mirrors are plain Lean (no Aeneas monad, no Mathlib) so they port to the
  iris v4.32 substrate, and each carries a faithfulness theorem against the
  extracted function that ships. As with the confidentiality mirrors, the copies
  living in `capability-primitive/iris` are checked separately by that repo's
  Gate 4c — a proof here cannot see a file in another repository.
-/

import PortcullisCoreIdentity.Types
import PortcullisCoreIdentity.Funs

open Aeneas Aeneas.Std Result

namespace IntegrityOracleMirror

open nucleus_ifc_kernel

abbrev Integ := extracted.ifc_integrity.IntegLevel

/-- Plain-Lean mirror of the extracted integrity rank. Adversarial is the BOTTOM
    (least trusted); the discriminants are the trust order. -/
def mirrorIrank : Integ → Nat
  | .Adversarial => 0
  | .Untrusted => 1
  | .Trusted => 2

/- As on the confidentiality side, no standalone faithfulness theorem for the
   rank: the extracted `irank` returns an Aeneas `Std.U8` and a portable mirror
   must return `Nat`, so equating them threads a scalar conversion that adds TCB
   without adding assurance. The rank is pinned by the two composites below,
   which are exhaustive over all argument pairs. -/

/-- Plain-Lean mirror of the extracted integrity MEET. Combining data takes the
    LEAST trusted input — the dual of the confidentiality join. -/
def mirrorImeet (a b : Integ) : Integ :=
  if mirrorIrank a ≤ mirrorIrank b then a else b

/-- **Faithfulness of the integrity meet.** -/
theorem imeet_faithful (a b : Integ) :
    ok (mirrorImeet a b) = extracted.ifc_integrity.imeet a b := by
  cases a <;> cases b <;> rfl

/-- Plain-Lean mirror of the extracted integrity flows-to: data of integrity `a`
    may reach a sink requiring `ceiling` iff it is AT LEAST as trusted. Note the
    direction — `≥`, where confidentiality's is `≤`. -/
def mirrorIflows (a ceiling : Integ) : Bool := mirrorIrank a ≥ mirrorIrank ceiling

/-- **Faithfulness of integrity flows-to.** -/
theorem iflows_faithful (a ceiling : Integ) :
    ok (mirrorIflows a ceiling) = extracted.ifc_integrity.iflows_to a ceiling := by
  cases a <;> cases ceiling <;> rfl

/-- Plain-Lean mirror of the extracted per-operation integrity fold step, which
    the extraction defines to be exactly `imeet`. -/
def mirrorIrunStep (eff src : Integ) : Integ := mirrorImeet eff src

/-- **Faithfulness of the fold step.** -/
theorem irun_step_faithful (eff src : Integ) :
    ok (mirrorIrunStep eff src) = extracted.ifc_integrity.irun_step eff src := by
  cases eff <;> cases src <;> rfl

/-! ## The structural fact the v3 machine needs

The confidentiality unwinding rides on `cflows (cjoin a b) c = cflows a c && cflows b c`
— the join decomposes below a ceiling. The integrity axis needs the DUAL, and it is
not obvious that reversing both the order and the operation preserves it. It does,
and here is why, proved rather than assumed: `min a b ≥ c` iff `a ≥ c` and `b ≥ c`. -/

/-- **The meet decomposes above a floor** — the integrity analogue of
    `cflows_cjoin_iff`, and the lemma a two-axis unwinding proof needs. -/
theorem iflows_imeet_iff (a b c : Integ) :
    mirrorIflows (mirrorImeet a b) c = (mirrorIflows a c && mirrorIflows b c) := by
  cases a <;> cases b <;> cases c <;> rfl

/-- **The two axes really do disagree.** Not decoration: this is the anti-vacuity
    witness for the claim that integrity is a genuinely new dimension rather than
    confidentiality renamed. If both axes agreed everywhere, the v3 machine would
    be v2 with extra syntax. `Untrusted` data may reach an `Adversarial` sink
    (downgrading trust is fine) but NOT a `Trusted` one — the opposite pattern to
    confidentiality, where `Internal` may reach `Secret` but not `Public`. -/
theorem axes_point_opposite_ways :
    mirrorIflows .Untrusted .Adversarial = true
  ∧ mirrorIflows .Untrusted .Trusted = false := by
  constructor <;> rfl

end IntegrityOracleMirror
