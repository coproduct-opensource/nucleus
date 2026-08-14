import GkatGuardedStringProofs

/-!
# The coalgebraic derivative: `den` factors through a one-step `next`

The equational (Salomaa + Uniqueness-Axiom) completeness of GKAT is open, but the
**coalgebraic** account is settled and decidable: expression equivalence is
bisimilarity of the derivative automaton (Smolka et al. POPL'20, near-linear time),
and the cyclic proof system of Rooduijn–Silva–Kozen (IJCAR 2024) is sound, complete
for the language model, and decidable. Both rest on the **fundamental theorem of
derivatives**: an expression's language is determined by whether it can *halt now*
and its *one-step residual* `next`.

This file machine-checks that theorem over the guarded-string model for the
**loop-free fragment** (the finite-behaviour core), giving the coalgebra `⟨halt?,
next⟩` that decision procedures iterate:

  * `den_nil`  : `⟦e⟧` accepts `(a,[])` ↔ `E(e)` at `a`   (halt-now; = `den_empty_E`),
  * `den_cons` : `⟦e⟧` accepts `(a,(q,a')::w)` ↔ `next e a = some (q,e')` and `⟦e'⟧`
                 accepts `(a',w)` — the residual `e'` again loop-free, so it iterates,
  * `next_halt_exclusive` : GKAT determinism — halt-now and step-now are mutually
                 exclusive, so `⟨E, next⟩` is a genuine deterministic coalgebra.

`den_cons` is by structural induction on the loop-free expression; the `seq` case
turns on `next_halt_exclusive` to pick the branch. Extending past loops needs a
well-founded induction over `InLoop` and is the natural next step.

Axioms `[propext]`, `sorryAx`-free.
-/

namespace GkatDeriv

open GkatSyntax GkatGS

variable {A T Atom : Type} (V : T → Atom → Bool)

/-- The loop-free fragment: if/then/else, sequencing, tests, actions — no `while`. -/
inductive LoopFree : Exp A T → Prop
  | act (p : A) : LoopFree (.act p)
  | test (t : BExp T) : LoopFree (.test t)
  | seq {e f : Exp A T} : LoopFree e → LoopFree f → LoopFree (.seq e f)
  | ite {b : BExp T} {e f : Exp A T} : LoopFree e → LoopFree f → LoopFree (.ite b e f)

/-- The **one-step derivative**: at atom `a`, the unique `(action, residual)` the
    expression performs, or `none` if it cannot step. `wh`'s clause is a placeholder
    never reached under `LoopFree`. -/
def next : Exp A T → Atom → Option (A × Exp A T)
  | .act p,    _ => some (p, .test .one)
  | .test _,   _ => none
  | .seq e f,  a => match next e a with
      | some (p, e') => some (p, .seq e' f)
      | none         => if bval V (E e) a then next f a else none
  | .ite b e f, a => if bval V b a then next e a else next f a
  | .wh _ _,   _ => none

/-- **Determinism.** A loop-free expression that steps at `a` cannot halt at `a`. -/
theorem next_halt_exclusive {e : Exp A T} (hlf : LoopFree e) (a : Atom) :
    ∀ x : A × Exp A T, next V e a = some x → bval V (E e) a = false := by
  induction hlf with
  | act p => intro _ _; rfl
  | test t => intro x h; simp [next] at h
  | @seq e f _ _ ihe ihf =>
      intro x h; simp only [next] at h; simp only [E, bval]
      cases hne : next V e a with
      | some pe => simp [ihe pe hne]
      | none =>
          rw [hne] at h
          by_cases hE : bval V (E e) a = true
          · rw [if_pos hE] at h; simp [hE, ihf x h]
          · simp [(by simpa using hE : bval V (E e) a = false)]
  | @ite b e f _ _ ihe ihf =>
      intro x h; simp only [next] at h; simp only [E, bval]
      by_cases hb : bval V b a = true
      · rw [if_pos hb] at h; simp [hb, ihe x h]
      · have hbf : bval V b a = false := by simpa using hb
        rw [if_neg hb] at h; simp [hbf, ihf x h]

/-- The residual of a loop-free expression is loop-free, so `⟨E, next⟩` iterates. -/
theorem next_lf {e : Exp A T} (hlf : LoopFree e) {a : Atom} {q : A} {e' : Exp A T} :
    next V e a = some (q, e') → LoopFree e' := by
  induction hlf generalizing q e' with
  | act p => intro h; rw [next, Option.some.injEq, Prod.mk.injEq] at h; rw [← h.2]; exact LoopFree.test _
  | test t => intro h; simp [next] at h
  | @seq e f hle hlf ihe ihf =>
      intro h; simp only [next] at h
      cases hne : next V e a with
      | some pe =>
          rw [hne] at h; obtain ⟨p0, e0⟩ := pe
          rw [Option.some.injEq, Prod.mk.injEq] at h
          rw [← h.2]; exact LoopFree.seq (ihe hne) hlf
      | none =>
          rw [hne] at h
          by_cases hE : bval V (E e) a = true
          · rw [if_pos hE] at h; exact ihf h
          · rw [if_neg hE] at h; simp at h
  | @ite b e f hle hlf ihe ihf =>
      intro h; simp only [next] at h
      by_cases hb : bval V b a = true
      · rw [if_pos hb] at h; exact ihe h
      · rw [if_neg hb] at h; exact ihf h

/-- **Halt-now** (`= den_empty_E`): `⟦e⟧` accepts `(a,[])` iff `E(e)` at `a`. -/
theorem den_nil (e : Exp A T) (a : Atom) :
    den V e (a, []) ↔ bval V (E e) a = true := den_empty_E V e a

/-- **The fundamental theorem of derivatives (loop-free).** `⟦e⟧` accepts
    `(a,(q,a')::w)` iff `e` steps at `a` via `q` to a loop-free residual `e'` with
    `⟦e'⟧` accepting `(a',w)`. -/
theorem den_cons {e : Exp A T} (hlf : LoopFree e) (a : Atom) (q : A) (a' : Atom)
    (w : List (A × Atom)) :
    den V e (a, (q, a') :: w) ↔
      ∃ e', next V e a = some (q, e') ∧ LoopFree e' ∧ den V e' (a', w) := by
  induction hlf generalizing a q a' w with
  | act p =>
      simp only [next]
      constructor
      · rintro ⟨x, y, h⟩
        injection h with ha hlist; injection hlist with hpair hw; injection hpair with hq hy
        subst hw; subst hq
        exact ⟨.test .one, rfl, LoopFree.test _, rfl, rfl⟩
      · rintro ⟨e', h, _, hd⟩
        rw [Option.some.injEq, Prod.mk.injEq] at h
        obtain ⟨rfl, rfl⟩ := h
        obtain ⟨_, rfl⟩ := hd
        exact ⟨a, a', rfl⟩
  | test t =>
      simp only [next]
      constructor
      · rintro ⟨_, h⟩; exact absurd h (by simp)
      · rintro ⟨_, h, _, _⟩; exact absurd h (by simp)
  | @seq e f hle hlf ihe ihf =>
      simp only [den_seq]
      constructor
      · rintro ⟨l1, l2, hl, hde, hdf⟩
        cases l1 with
        | nil =>
            rw [List.nil_append] at hl; subst hl
            have hEe : bval V (E e) a = true := (den_nil V e a).mp hde
            have hne : next V e a = none := by
              cases hn : next V e a with
              | none => rfl
              | some x => simp [next_halt_exclusive V hle a x hn] at hEe
            obtain ⟨f', hnf, hlf', hdf'⟩ := (ihf a q a' w).mp hdf
            exact ⟨f', by simp [next, hne, hEe, hnf], hlf', hdf'⟩
        | cons hd tl =>
            obtain ⟨hhd, htl⟩ : hd = (q, a') ∧ tl ++ l2 = w := by
              simpa [List.cons_append] using hl.symm
            subst hhd
            obtain ⟨e0, hne, hle0, hde0⟩ := (ihe a q a' tl).mp hde
            refine ⟨.seq e0 f, by simp [next, hne], LoopFree.seq hle0 hlf, ?_⟩
            exact ⟨tl, l2, htl.symm, hde0, by simpa [lastAtom] using hdf⟩
      · rintro ⟨e', hnext, hlf', hd⟩
        simp only [next] at hnext
        cases hne : next V e a with
        | some pe =>
            rw [hne] at hnext; obtain ⟨p0, e0⟩ := pe
            rw [Option.some.injEq, Prod.mk.injEq] at hnext
            obtain ⟨rfl, rfl⟩ := hnext
            have hle0 : LoopFree e0 := next_lf V hle hne
            obtain ⟨m1, m2, hw, hde0, hdf⟩ := (den_seq V e0 f (a', w)).mp hd
            refine ⟨(p0, a') :: m1, m2, ?_,
              (ihe a p0 a' m1).mpr ⟨e0, hne, hle0, hde0⟩, by simpa [lastAtom] using hdf⟩
            have hw2 : w = m1 ++ m2 := hw
            show (p0, a') :: w = (p0, a') :: m1 ++ m2
            simp [hw2]
        | none =>
            rw [hne] at hnext
            by_cases hE : bval V (E e) a = true
            · rw [if_pos hE] at hnext
              have hdf : den V f (a, (q, a') :: w) := (ihf a q a' w).mpr ⟨e', hnext, hlf', hd⟩
              exact ⟨[], (q, a') :: w, rfl, (den_nil V e a).mpr hE, by simpa [lastAtom] using hdf⟩
            · rw [if_neg hE] at hnext; simp at hnext
  | @ite b e f hle hlf ihe ihf =>
      have hn : next V (.ite b e f) a = if bval V b a then next V e a else next V f a := rfl
      rw [den_ite, hn]
      by_cases hb : bval V b a = true
      · rw [if_pos hb]
        constructor
        · rintro (⟨_, hde⟩ | ⟨hbf, _⟩)
          · exact (ihe a q a' w).mp hde
          · rw [hb] at hbf; exact absurd hbf (by simp)
        · intro h; exact Or.inl ⟨hb, (ihe a q a' w).mpr h⟩
      · have hbf : bval V b a = false := by simpa using hb
        rw [if_neg hb]
        constructor
        · rintro (⟨hbt, _⟩ | ⟨_, hdf⟩)
          · rw [hbf] at hbt; exact absurd hbt (by simp)
          · exact (ihf a q a' w).mp hdf
        · intro h; exact Or.inr ⟨hbf, (ihf a q a' w).mpr h⟩

#print axioms den_cons
#print axioms next_halt_exclusive

end GkatDeriv
