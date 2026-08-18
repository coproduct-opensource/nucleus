import GkatSumQuotientProofs

/-!
# Support lemmas for emitted certificate files

Generated instance proofs (see `GkatCertPilotProofs` for the hand-written prototype) need to
compute halt guards and steps of concrete automata at a SYMBOLIC valuation `W : Unit → X →
Bool`.  The pilot did this with per-structure `rfl` sub-lemmas, which an emitter cannot easily
name.  Over a single primitive test the general fact suffices: a valuation only ever
contributes the one bit `W () x`, so every `bval` and every `autStep` equals its value at the
CONSTANT valuation carrying that bit — and once the bit is cased to a literal, the constant
valuation makes the whole computation a closed term, closable by `rfl` at any structure.

    bval_unit    :  bval W g x = bval (fun _ _ => W () x) g ()
    autStep_unit :  autStep W aut s x = autStep (fun _ _ => W () x) aut s ()

Emitted state lemmas are then uniformly `rw [autStep_unit, h]; rfl`.
-/

namespace GkatCertSupport

open GkatSyntax GkatGS GkatKleene

variable {X S : Type}

theorem bval_unit (W : Unit → X → Bool) (x : X) (g : BExp Unit) :
    bval W g x = bval (fun _ (_ : Unit) => W () x) g () := by
  induction g with
  | zero => rfl
  | one => rfl
  | prim t => cases t; rfl
  | not b ih => show (! bval W b x) = _; rw [ih]; rfl
  | and b c ihb ihc => show (bval W b x && bval W c x) = _; rw [ihb, ihc]; rfl
  | or b c ihb ihc => show (bval W b x || bval W c x) = _; rw [ihb, ihc]; rfl

theorem firstMatch_unit {A : Type} (W : Unit → X → Bool) (x : X)
    (L : List (BExp Unit × A × S)) :
    firstMatch W x L = firstMatch (fun _ (_ : Unit) => W () x) () L := by
  induction L with
  | nil => rfl
  | cons hd tl ih =>
      obtain ⟨g, q, s'⟩ := hd
      show (if bval W g x then _ else _) = (if bval _ g () then _ else _)
      rw [bval_unit W x g]
      by_cases hg : bval (fun _ (_ : Unit) => W () x) g ()
      · rw [if_pos hg, if_pos hg]
      · rw [if_neg hg, if_neg hg]; exact ih

theorem autStep_unit {A : Type} (aut : GAut S A Unit) (W : Unit → X → Bool) (x : X) (s : S) :
    autStep W aut s x = autStep (fun _ (_ : Unit) => W () x) aut s () :=
  firstMatch_unit W x (aut.trans s)

theorem bval_hlt_unit {A : Type} (aut : GAut S A Unit) (W : Unit → X → Bool) (x : X) (s : S) :
    bval W (aut.hlt s) x = bval (fun _ (_ : Unit) => W () x) (aut.hlt s) () :=
  bval_unit W x (aut.hlt s)

#print axioms autStep_unit
#print axioms bval_hlt_unit

end GkatCertSupport
