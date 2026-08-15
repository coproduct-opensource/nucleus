import GkatGuardedStringProofs
import GkatUAIndependenceProofs

/-!
# No guard-pullback witness exists for a genuine action (the model side of (E))

`GkatUAIndep.ua2_of_pullback` shows UA₂ follows from base + UA₁ **once a guard-pullback
witness `c` exists** with `e·(b?x:y) ≡ c?(e·x):(e·y)`. This file shows the witness does
**not** exist in GKAT's free syntax for a genuine action and a genuine guard — the
`wp`-inexpressibility made concrete inside the corpus's own guarded-string model.

The mechanism is exactly the one behind `GkatGS.left_distrib_not_gkat_theorem`: a
guarded-string action `p` may step to **any** end atom, so "the value of `b` after `p`"
is not a function of the start atom, hence not any start-atom guard `c`. Probing the
witness at `(x,y)=(1,0)` and using `GkatGS.sound` turns this into a hard non-theorem.

This is the model half of the independence skeleton
`UA₂ ⊢? ⟹ ∃ syntactic c, Pullback ⟹ (soundness) c definable in the den model — impossible`.
It does **not** by itself prove UA independent — the converse `UA₂ ⟹ ∃c` (step (E)) is
still open — but it discharges the step that a witness, if forced, would be refuted.
-/

namespace GkatPullbackWitness

open GkatSyntax GkatGS GkatUAIndep

/-- The guarded-string valuation making the single primitive test read its atom
    (`Atom = Bool`): the "action moves to a free end atom" witness world. -/
def V0 : Unit → Bool → Bool := fun _ a => a

/-- `den` of the probe-`(1,0)` left side on a one-step string: accepts iff the end
    atom is `true` (the guard `prim ()` read *after* the action). -/
theorem den_lhs (a bb : Bool) :
    den V0 (.seq (.act ()) (.ite (.prim ()) (.test .one) (.test .zero)))
        (a, [((), bb)]) ↔ bb = true := by
  constructor
  · intro h
    obtain ⟨l1, l2, hsplit, hact, hM⟩ := h
    obtain ⟨x, y, hxy⟩ := hact
    simp only [Prod.mk.injEq] at hxy
    obtain ⟨_, hl1⟩ := hxy; subst hl1
    simp only [List.cons_append, List.nil_append, List.cons.injEq, Prod.mk.injEq,
      true_and, and_true] at hsplit
    obtain ⟨hby, hl2⟩ := hsplit; subst hl2
    simp only [lastAtom] at hM
    obtain ⟨hbv, _⟩ | ⟨_, hz⟩ := hM
    · simp only [bval, V0] at hbv; rw [hby]; exact hbv
    · obtain ⟨htz, _⟩ := hz; simp [bval] at htz
  · rintro rfl
    refine ⟨[((), true)], [], rfl, ⟨a, true, rfl⟩, ?_⟩
    simp only [lastAtom]
    exact Or.inl ⟨rfl, rfl, rfl⟩

/-- `den` of the probe-`(1,0)` right side on a one-step string: accepts iff `c` holds
    at the *start* atom (the guard `c` read *before* the action). -/
theorem den_rhs (c : BExp Unit) (a bb : Bool) :
    den V0 (.ite c (.seq (.act ()) (.test .one)) (.seq (.act ()) (.test .zero)))
        (a, [((), bb)]) ↔ bval V0 c a = true := by
  constructor
  · intro h
    obtain ⟨hc, _⟩ | ⟨_, hz⟩ := h
    · exact hc
    · obtain ⟨l1, l2, _, _, htz, _⟩ := hz; simp [bval] at htz
  · intro hc
    refine Or.inl ⟨hc, ?_⟩
    refine ⟨[((), bb)], [], rfl, ⟨a, bb, rfl⟩, ?_⟩
    simp only [lastAtom]
    exact ⟨rfl, rfl⟩

/-- **No guard-pullback witness for a genuine action.** There is no GKAT test `c` making
    the action `p = act ()` natural across the branch on `prim ()`: the required witness
    would have to read, at the start atom, the value of `prim ()` at the (free) end atom.
    Proven by probing the `Pullback` at `(1,0)` and refuting with `GkatGS.sound` in `V0`. -/
theorem no_pullback_witness :
    ¬ ∃ c : BExp Unit, Pullback (Exp.act () : Exp Unit Unit) (BExp.prim ()) c := by
  rintro ⟨c, hpb⟩
  have hden := sound V0 (hpb (.test .one) (.test .zero))
  by_cases hc : bval V0 c true = true
  · -- witness accepts start atom `true`, so RHS accepts (true,[(p,false)]) but LHS does not
    have := (hden (true, [((), false)]))
    rw [den_lhs, den_rhs] at this
    simp only [hc] at this
    exact absurd (this.mpr trivial) (by decide)
  · by_cases hc2 : bval V0 c false = true
    · have := (hden (false, [((), false)]))
      rw [den_lhs, den_rhs] at this
      simp only [hc2] at this
      exact absurd (this.mpr trivial) (by decide)
    · -- c holds nowhere: RHS empty, but LHS accepts (true,[(p,true)])
      have := (hden (true, [((), true)]))
      rw [den_lhs, den_rhs] at this
      simp only [Bool.not_eq_true] at hc
      rw [hc] at this
      exact absurd (this.mp rfl) (by simp)

#print axioms no_pullback_witness

end GkatPullbackWitness
