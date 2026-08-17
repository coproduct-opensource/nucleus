import GkatSumQuotientProofs

/-!
# The gap, closed: a solvable quotient where no syntax-generated one exists

`GkatCollapseRefutation.not_commonSyntacticCollapse` refutes the cospan route on the pair

    e = p ; while b do p        f = (if b then 1 else p) ; while b do p

by showing determinism pins the quotient of `Me + Mf` to two states and no THOMPSON automaton
has that shape.  `GkatSumQuotient.gapAut_solvable` shows the two-state shape is nonetheless
solvable.  What was missing was the identification: that the pinned quotient really is that
shape.  This supplies it, so the two halves join into a theorem rather than an argument.

The consequence is that `SumQuotientSolvable` HOLDS on the pair that refutes
`CommonSyntacticCollapse` — the swapped conjunct is strictly weaker, and strictly weaker
exactly where it needs to be.
-/

namespace GkatGapWitness

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatCollapseRefutation
open GkatSumQuotient

abbrev eAut := (certifiedThompson Act Tst eProg).aut.toGAut
abbrev fAut := (certifiedThompson Act Tst fProg).aut.toGAut

variable {X : Type} (W : Tst → X → Bool) (x : X)

/-! ## The two automata, computed at a general valuation

    Every state of `Me` reduces, and so do `Mf`'s interior states.  `Mf`'s START does not yet:
    `fProg = (if b then 1 else p) ; while b do p` puts an `ite` on the left of a `seq`, so its
    initial transition list is an APPEND of two mapped lists, and `firstMatch` does not reduce
    through the append by `simp`/`rfl` here.  Those three obligations — `f_none_hlt`,
    `f_none_step` at `b`, and at `¬b` — are what remain before the witness closes. -/

private theorem pA_hlt : bval W ((certifiedThompson Act Tst pA).aut.core.hlt ()) x = true := rfl
private theorem bT_val : bval W bT x = W () x := rfl

theorem e_none_hlt : bval W (eAut.hlt none) x = false := rfl
theorem e_mid_hlt : bval W (eAut.hlt (some (Sum.inl ()))) x = !(W () x) := rfl
theorem e_loop_hlt : bval W (eAut.hlt (some (Sum.inr ()))) x = !(W () x) := rfl
theorem f_mid_hlt : bval W (fAut.hlt (some (Sum.inl (Sum.inr ())))) x = !(W () x) := rfl
theorem f_loop_hlt : bval W (fAut.hlt (some (Sum.inr ()))) x = !(W () x) := rfl

theorem e_none_step : autStep W eAut none x = some ((), some (Sum.inl ())) := rfl

theorem e_mid_step (h : W () x = true) :
    autStep W eAut (some (Sum.inl ())) x = some ((), some (Sum.inr ())) := by
  show (if bval W _ x then _ else _) = _
  simp only [bval, pA_hlt, bT_val, h, Bool.and_true, Bool.true_and, if_pos]
  rfl

theorem e_loop_step (h : W () x = true) :
    autStep W eAut (some (Sum.inr ())) x = some ((), some (Sum.inr ())) := by
  show (if bval W _ x then _ else _) = _
  simp only [bval, pA_hlt, bT_val, h, Bool.and_true, Bool.true_and, if_pos]
  rfl

theorem f_mid_step (h : W () x = true) :
    autStep W fAut (some (Sum.inl (Sum.inr ()))) x = some ((), some (Sum.inr ())) := by
  show (if bval W _ x then _ else _) = _
  simp only [bval, pA_hlt, bT_val, h, Bool.and_true, Bool.true_and, if_pos]
  rfl

theorem f_loop_step (h : W () x = true) :
    autStep W fAut (some (Sum.inr ())) x = some ((), some (Sum.inr ())) := by
  show (if bval W _ x then _ else _) = _
  simp only [bval, pA_hlt, bT_val, h, Bool.and_true, Bool.true_and, if_pos]
  rfl

end GkatGapWitness
