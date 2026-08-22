import GkatSumQuotientProofs

/-!
# Support lemmas for emitted certificates over TWO primitive tests

The `GkatCertSupport` lemmas reduce symbolic valuations to a constant one for `Tst = Unit`
(one primitive, one bit).  The NA=4 frontier (the subset-parking instances found by the
sampled forge) lives at `Tst = Bool` — two primitives, so a valuation contributes exactly
two bits `W true x` and `W false x`, and every `bval`/`autStep` equals its value at the
constant valuation carrying those bits.  Emitted state lemmas become

    rw [autStep_bool, h1, h2]; rfl

with the four-way case split `cases h1 : W true a <;> cases h2 : W false a`.
-/

namespace GkatCertSupportBool

open GkatSyntax GkatGS GkatKleene

variable {X S : Type}

theorem bval_bool (W : Bool → X → Bool) (x : X) (g : BExp Bool) :
    bval W g x = bval (fun b (_ : Unit) => cond b (W true x) (W false x)) g () := by
  induction g with
  | zero => rfl
  | one => rfl
  | prim t => cases t <;> rfl
  | not b ih => show (! bval W b x) = _; rw [ih]; rfl
  | and b c ihb ihc => show (bval W b x && bval W c x) = _; rw [ihb, ihc]; rfl
  | or b c ihb ihc => show (bval W b x || bval W c x) = _; rw [ihb, ihc]; rfl

theorem firstMatch_bool {A : Type} (W : Bool → X → Bool) (x : X)
    (L : List (BExp Bool × A × S)) :
    firstMatch W x L =
      firstMatch (fun b (_ : Unit) => cond b (W true x) (W false x)) () L := by
  induction L with
  | nil => rfl
  | cons hd tl ih =>
      obtain ⟨g, q, s'⟩ := hd
      show (if bval W g x then _ else _) = (if bval _ g () then _ else _)
      rw [bval_bool W x g]
      by_cases hg : bval (fun b (_ : Unit) => cond b (W true x) (W false x)) g ()
      · rw [if_pos hg, if_pos hg]
      · rw [if_neg hg, if_neg hg]; exact ih

theorem autStep_bool {A : Type} (aut : GAut S A Bool) (W : Bool → X → Bool) (x : X) (s : S) :
    autStep W aut s x =
      autStep (fun b (_ : Unit) => cond b (W true x) (W false x)) aut s () :=
  firstMatch_bool W x (aut.trans s)

theorem bval_hlt_bool {A : Type} (aut : GAut S A Bool) (W : Bool → X → Bool) (x : X) (s : S) :
    bval W (aut.hlt s) x =
      bval (fun b (_ : Unit) => cond b (W true x) (W false x)) (aut.hlt s) () :=
  bval_bool W x (aut.hlt s)

#print axioms autStep_bool
#print axioms bval_hlt_bool

end GkatCertSupportBool
