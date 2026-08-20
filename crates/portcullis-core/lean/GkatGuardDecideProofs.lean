import GkatPlanExistenceProofs

/-! # Decidable guard satisfiability — the de-choice keystone

    `bval` at the generic valuation depends only on the primitive tests
    occurring in the guard.  Over a decidable test alphabet, that makes
    guard satisfiability and refutability at generic atoms DECIDABLE by
    finite Boolean enumeration — computably, with no choice.  Every
    classical case split on guard degeneracy in the completeness ladder
    can then run on this instance instead of `Classical.em`. -/

namespace GkatGuardDecide

open GkatSyntax GkatGS GkatPlanExistence

variable {A T : Type}

/-- The primitive tests occurring in a guard. -/
def testsOf : BExp T → List T
  | .zero => []
  | .one => []
  | .prim t => [t]
  | .and b c => testsOf b ++ testsOf c
  | .or b c => testsOf b ++ testsOf c
  | .not b => testsOf b

/-- Point-update of an atom. -/
def override [DecidableEq T] (α : T → Bool) (t : T) (v : Bool) :
    T → Bool :=
  fun s => if s = t then v else α s

/-- All Boolean assignments over a finite test list. -/
def enumAtoms [DecidableEq T] : List T → List (T → Bool)
  | [] => [fun _ => false]
  | t :: ts =>
      (enumAtoms ts).map (fun α => override α t true)
        ++ (enumAtoms ts).map (fun α => override α t false)

/-- **FINITE SUPPORT**: generic evaluation sees only the occurring
    tests. -/
theorem bval_testsOf {g : BExp T} {α β : T → Bool}
    (h : ∀ t ∈ testsOf g, α t = β t) :
    bval (genW T) g α = bval (genW T) g β := by
  induction g with
  | zero => rfl
  | one => rfl
  | prim t =>
      show α t = β t
      exact h t (List.mem_cons_self ..)
  | and b c ihb ihc =>
      show (bval (genW T) b α && bval (genW T) c α)
        = (bval (genW T) b β && bval (genW T) c β)
      rw [ihb (fun t ht => h t (List.mem_append.mpr (Or.inl ht))),
          ihc (fun t ht => h t (List.mem_append.mpr (Or.inr ht)))]
  | or b c ihb ihc =>
      show (bval (genW T) b α || bval (genW T) c α)
        = (bval (genW T) b β || bval (genW T) c β)
      rw [ihb (fun t ht => h t (List.mem_append.mpr (Or.inl ht))),
          ihc (fun t ht => h t (List.mem_append.mpr (Or.inr ht)))]
  | not b ihb =>
      show (!bval (genW T) b α) = (!bval (genW T) b β)
      rw [ihb h]

/-- The enumeration realizes every atom on the listed tests. -/
theorem enumAtoms_complete [DecidableEq T] :
    ∀ (ts : List T) (α : T → Bool),
      ∃ β ∈ enumAtoms ts, ∀ t ∈ ts, β t = α t := by
  intro ts
  induction ts with
  | nil =>
      intro α
      refine ⟨fun _ => false, List.mem_cons_self .., ?_⟩
      intro t ht
      exact nomatch ht
  | cons t ts ih =>
      intro α
      obtain ⟨β, hmem, hagree⟩ := ih α
      refine ⟨override β t (α t), ?_, ?_⟩
      · cases hv : α t with
        | true =>
            exact List.mem_append.mpr (Or.inl (List.mem_map.mpr
              ⟨β, hmem, rfl⟩))
        | false =>
            exact List.mem_append.mpr (Or.inr (List.mem_map.mpr
              ⟨β, hmem, rfl⟩))
      · intro s hs
        rcases List.mem_cons.mp hs with hst | hsts
        · show (if s = t then α t else β s) = α s
          rw [if_pos hst, hst]
        · show (if s = t then α t else β s) = α s
          by_cases hst : s = t
          · rw [if_pos hst, hst]
          · rw [if_neg hst]
            exact hagree s hsts

/-- **DECIDABLE SATISFIABILITY** at generic atoms — computable, no
    choice. -/
instance guardSatDecidable [DecidableEq T] (g : BExp T) :
    Decidable (∃ α : T → Bool, bval (genW T) g α = true) :=
  decidable_of_iff
    (∃ β ∈ enumAtoms (testsOf g), bval (genW T) g β = true)
    (by
      constructor
      · rintro ⟨β, -, hb⟩
        exact ⟨β, hb⟩
      · rintro ⟨α, hα⟩
        obtain ⟨β, hmem, hagree⟩ := enumAtoms_complete (testsOf g) α
        refine ⟨β, hmem, ?_⟩
        rw [bval_testsOf (g := g) (fun t ht => hagree t ht)]
        exact hα)

/-- **DECIDABLE REFUTABILITY** at generic atoms. -/
instance guardRefDecidable [DecidableEq T] (g : BExp T) :
    Decidable (∃ α : T → Bool, bval (genW T) g α = false) :=
  decidable_of_iff
    (∃ β ∈ enumAtoms (testsOf g), bval (genW T) g β = false)
    (by
      constructor
      · rintro ⟨β, -, hb⟩
        exact ⟨β, hb⟩
      · rintro ⟨α, hα⟩
        obtain ⟨β, hmem, hagree⟩ := enumAtoms_complete (testsOf g) α
        refine ⟨β, hmem, ?_⟩
        rw [bval_testsOf (g := g) (fun t ht => hagree t ht)]
        exact hα)

#print axioms guardSatDecidable
#print axioms guardRefDecidable

end GkatGuardDecide
