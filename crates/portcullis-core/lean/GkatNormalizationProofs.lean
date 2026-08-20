import GkatPlanExistenceProofs

/-! # S0: the normalization bridge — the interface algebra

    `NormalizationBridge` needs, per program, a provably-equivalent program whose
    Thompson automaton has no silent transitions.  Following the skip-free GKAT
    reduction (Kappé–Schmid–Silva, FoSSaCS'23) adapted to full GKAT with tests:
    prune each expression to its successfully-terminating branches, with `s3`
    (early termination, `e·0 ≡ 0`) making the pruning provable.

    With tests, deadness is ATOM-INDEXED: a subterm is dead only relative to the
    guard describing the atoms that can reach it.  This file builds the
    interface algebra:

    * `outG g e` — the OUTPUT GUARD of `g?·e`: the tightest test its accepted
      strings' last atoms satisfy.
    * `outG_emits` — the emission theorem: `g?·e ≡ g?·(e·(outG g e)?)` in the
      finite axioms.  This is the engine: it lets emptiness propagate through
      `seq` (the continuation's input guard is the head's output guard), which is
      exactly what pruning and, later, Thompson silent-freeness need.

    Loops are handled SOUNDLY but not tightly: `outG` over-approximates a loop's
    output by `1` (emission against `1` is `s5`), and `prune` does not descend into
    loop bodies (rewriting a body under the loop guard needs the guardedness
    normalization, the next stratum).  Both spine theorems are therefore
    UNCONDITIONAL over all of GKAT.  The first tight loop fact is proved below:
    a PRODUCTIVE loop provably emits its exit guard (`wh_emits_exit`, via `w3_ba`
    and `else_guard_test` — no UA). -/

namespace GkatNormalization

open GkatSyntax GkatGS GkatFaithful GkatGuardedAlgebra GkatResidue
open GkatRingSupport GkatRingPlan

variable {A T : Type}

open Classical in
/-- The output guard of `g?·e`: the last atoms of its accepted strings.  An action
    resets the interface (`1` if anything reaches it, `0` if nothing does); tests
    conjoin; `seq` composes; `ite` splits the input guard and joins.  The `wh`
    case is the SOUND over-approximation `1` (tightening it is the loop
    stratum). -/
noncomputable def outG : BExp T → Exp A T → BExp T
  | g, .test b => .and g b
  | g, .act _ => if GuardEmpty g then .zero else .one
  | g, .seq e f => outG (outG g e) f
  | g, .ite b e f => .or (outG (.and g b) e) (outG (.and g (.not b)) f)
  | _, .wh _ _ => .one

/-- Tests widen along guard implication: `o? ≡ o?·o'?` when `o ⟹ o'`. -/
theorem test_widen {o o' : BExp T} (himp : GuardImplies o o') :
    EquivBA (.test o : Exp A T) (.seq (.test o) (.test o')) := by
  refine EquivBA.trans (EquivBA.baTest (b := o) (c := .and o o') ?_)
    (EquivBA.symm (EquivBA.s6 o o'))
  intro X W x
  show bval W o x = (bval W o x && bval W o' x)
  cases ho : bval W o x
  · rfl
  · rw [himp X W x ho]; rfl

/-- Emission is monotone in the emitted guard. -/
theorem emission_weaken {h o o' : BExp T} {e : Exp A T}
    (himp : GuardImplies o o')
    (hem : EquivBA (.seq (.test h) e) (.seq (.test h) (.seq e (.test o)))) :
    EquivBA (.seq (.test h) e) (.seq (.test h) (.seq e (.test o'))) := by
  refine EquivBA.trans hem ?_
  refine EquivBA.trans
    (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
      (EquivBA.seq_c (EquivBA.base (Equiv.refl e)) (test_widen himp))) ?_
  -- h?·(e·(o?·o'?)) ≡ (h?·(e·o?))·o'? ≡ (h?·e)·o'? ≡ h?·(e·o'?)
  refine EquivBA.trans
    (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
      (seq_assoc' e (.test o) (.test o'))) ?_
  refine EquivBA.trans (seq_assoc' (.test h) (.seq e (.test o)) (.test o')) ?_
  refine EquivBA.trans (EquivBA.seq_c (EquivBA.symm hem)
    (EquivBA.base (Equiv.refl _))) ?_
  exact EquivBA.base (Equiv.s1 (.test h) e (.test o'))

theorem himp_or_left (b c : BExp T) : GuardImplies b (.or b c) := by
  intro X W x h
  show (bval W b x || bval W c x) = true
  rw [h]; rfl

theorem himp_or_right (b c : BExp T) : GuardImplies c (.or b c) := by
  intro X W x h
  show (bval W b x || bval W c x) = true
  rw [h]
  cases bval W b x <;> rfl

/-- **THE EMISSION THEOREM**: running `g?·e` establishes `outG g e` — provably,
    in the finite axioms, for every GKAT program. -/
theorem outG_emits (e : Exp A T) :
    ∀ g : BExp T,
      EquivBA (.seq (.test g) e) (.seq (.test g) (.seq e (.test (outG g e)))) := by
  induction e with
  | act p =>
      intro g
      by_cases hE : GuardEmpty g
      · rw [show outG g (Exp.act p : Exp A T) = BExp.zero by
          unfold outG; exact if_pos hE]
        exact EquivBA.trans (test_empty_absorb hE _)
          (EquivBA.symm (test_empty_absorb hE _))
      · rw [show outG g (Exp.act p : Exp A T) = BExp.one by
          unfold outG; exact if_neg hE]
        exact EquivBA.symm (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
          (EquivBA.base (Equiv.s5 (.act p))))
  | test b =>
      intro g
      show EquivBA (.seq (.test g) (.test b))
        (.seq (.test g) (.seq (.test b) (.test (.and g b))))
      -- g?·b? ≡ (g∧b)? ≡ (g∧b)?·(g∧b)? ≡ (g?·b?)·(g∧b)? ≡ g?·(b?·(g∧b)?)
      refine EquivBA.trans (EquivBA.s6 g b) ?_
      refine EquivBA.trans (EquivBA.symm (test_test (.and g b))) ?_
      refine EquivBA.trans (EquivBA.seq_c (EquivBA.symm (EquivBA.s6 g b))
        (EquivBA.base (Equiv.refl _))) ?_
      exact EquivBA.base (Equiv.s1 (.test g) (.test b) (.test (.and g b)))
  | seq e f ihe ihf =>
      intro g
      show EquivBA (.seq (.test g) (.seq e f))
        (.seq (.test g) (.seq (.seq e f) (.test (outG (outG g e) f))))
      -- through: (g?·e)·f, emit oe, reassociate, emit out after f, run backwards
      refine EquivBA.trans (seq_assoc' (.test g) e f) ?_
      refine EquivBA.trans (EquivBA.seq_c (ihe g) (EquivBA.base (Equiv.refl f))) ?_
      refine EquivBA.trans (EquivBA.seq_c
        (seq_assoc' (.test g) e (.test (outG g e)))
        (EquivBA.base (Equiv.refl f))) ?_
      refine EquivBA.trans (EquivBA.base
        (Equiv.s1 (.seq (.test g) e) (.test (outG g e)) f)) ?_
      refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (ihf (outG g e))) ?_
      refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (seq_assoc' (.test (outG g e)) f (.test (outG (outG g e) f)))) ?_
      refine EquivBA.trans (seq_assoc' (.seq (.test g) e)
        (.seq (.test (outG g e)) f) (.test (outG (outG g e) f))) ?_
      refine EquivBA.trans (EquivBA.seq_c
        (EquivBA.trans
          (EquivBA.trans
            (seq_assoc' (.seq (.test g) e) (.test (outG g e)) f)
            (EquivBA.seq_c
              (EquivBA.trans
                (EquivBA.base (Equiv.s1 (.test g) e (.test (outG g e))))
                (EquivBA.symm (ihe g)))
              (EquivBA.base (Equiv.refl f))))
          (EquivBA.base (Equiv.s1 (.test g) e f)))
        (EquivBA.base (Equiv.refl _))) ?_
      exact EquivBA.base (Equiv.s1 (.test g) (.seq e f) (.test (outG (outG g e) f)))
  | ite b e f ihe ihf =>
      intro g
      show EquivBA (.seq (.test g) (.ite b e f))
        (.seq (.test g) (.seq (.ite b e f)
          (.test (.or (outG (.and g b) e) (outG (.and g (.not b)) f)))))
      -- both sides normalize to ite (g∧b) (e·out?) (g?·(f·out?))
      have arm1 : EquivBA (.seq (.test (.and g b)) e)
          (.seq (.test (.and g b)) (.seq e
            (.test (.or (outG (.and g b) e) (outG (.and g (.not b)) f))))) :=
        emission_weaken (himp_or_left _ _) (ihe (.and g b))
      -- inside the else guard, `g?·X` tightens to `(g∧¬b)?·X`
      have hconv : ∀ X : Exp A T, EquivBA
          (.seq (.test (.not (.and g b))) (.seq (.test g) X))
          (.seq (.test (.and g (.not b))) X) := by
        intro X
        refine EquivBA.trans (seq_assoc' (.test (.not (.and g b))) (.test g) X) ?_
        refine EquivBA.seq_c ?_ (EquivBA.base (Equiv.refl X))
        refine EquivBA.trans (EquivBA.s6 (.not (.and g b)) g) ?_
        refine EquivBA.baTest ?_
        intro Y W x
        show (!(bval W g x && bval W b x) && bval W g x)
          = (bval W g x && !(bval W b x))
        cases bval W g x <;> cases bval W b x <;> rfl
      have arm2 : EquivBA
          (.seq (.test (.not (.and g b))) (.seq (.test g) f))
          (.seq (.test (.not (.and g b))) (.seq (.test g) (.seq f
            (.test (.or (outG (.and g b) e) (outG (.and g (.not b)) f)))))) :=
        EquivBA.trans (hconv f)
          (EquivBA.trans
            (emission_weaken (himp_or_right _ _) (ihf (.and g (.not b))))
            (EquivBA.symm (hconv (.seq f (.test _)))))
      have hL : EquivBA (.seq (.test g) (.ite b e f))
          (.ite (.and g b)
            (.seq e (.test (.or (outG (.and g b) e) (outG (.and g (.not b)) f))))
            (.seq (.test g) (.seq f
              (.test (.or (outG (.and g b) e) (outG (.and g (.not b)) f)))))) := by
        refine EquivBA.trans (test_seq_ite g b e f) ?_
        refine EquivBA.trans (EquivBA.base (Equiv.u4 (.and g b) e _)) ?_
        refine EquivBA.trans (EquivBA.ite_c arm1 (EquivBA.base (Equiv.refl _))) ?_
        refine EquivBA.trans (EquivBA.symm
          (EquivBA.base (Equiv.u4 (.and g b) _ _))) ?_
        exact ite_congr_under_else arm2
      have hR : EquivBA
          (.seq (.test g) (.seq (.ite b e f)
            (.test (.or (outG (.and g b) e) (outG (.and g (.not b)) f)))))
          (.ite (.and g b)
            (.seq e (.test (.or (outG (.and g b) e) (outG (.and g (.not b)) f))))
            (.seq (.test g) (.seq f
              (.test (.or (outG (.and g b) e) (outG (.and g (.not b)) f)))))) := by
        refine EquivBA.trans (seq_assoc' (.test g) (.ite b e f) (.test _)) ?_
        refine EquivBA.trans (EquivBA.seq_c (test_seq_ite g b e f)
          (EquivBA.base (Equiv.refl _))) ?_
        refine EquivBA.trans (EquivBA.symm (EquivBA.base
          (Equiv.u5 (.and g b) e (.seq (.test g) f) (.test _)))) ?_
        exact EquivBA.ite_c (EquivBA.base (Equiv.refl _))
          (EquivBA.base (Equiv.s1 (.test g) f (.test _)))
      exact EquivBA.trans hL (EquivBA.symm hR)
  | wh b e _ =>
      intro g
      rw [show outG g (Exp.wh b e : Exp A T) = BExp.one from rfl]
      exact EquivBA.symm (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (EquivBA.base (Equiv.s5 (.wh b e))))

#print axioms outG_emits

/-! ## Pruning: cut every dead branch, provably -/

/-- Inside the else guard of `ite (g∧b)`, the assertion `g?` tightens to `(g∧¬b)?`. -/
theorem else_tighten (g b : BExp T) (X : Exp A T) : EquivBA
    (.seq (.test (.not (.and g b))) (.seq (.test g) X))
    (.seq (.test (.and g (.not b))) X) := by
  refine EquivBA.trans (seq_assoc' (.test (.not (.and g b))) (.test g) X) ?_
  refine EquivBA.seq_c ?_ (EquivBA.base (Equiv.refl X))
  refine EquivBA.trans (EquivBA.s6 (.not (.and g b)) g) ?_
  refine EquivBA.baTest ?_
  intro Y W x
  show (!(bval W g x && bval W b x) && bval W g x)
    = (bval W g x && !(bval W b x))
  cases bval W g x <;> cases bval W b x <;> rfl

/-- Rewriting a sequential TAIL under the head's emitted output guard. -/
theorem tail_rewrite {g oe : BExp T} {e f f' : Exp A T}
    (hem : EquivBA (.seq (.test g) e) (.seq (.test g) (.seq e (.test oe))))
    (hf : EquivBA (.seq (.test oe) f) (.seq (.test oe) f')) :
    EquivBA (.seq (.test g) (.seq e f)) (.seq (.test g) (.seq e f')) := by
  refine EquivBA.trans (seq_assoc' (.test g) e f) ?_
  refine EquivBA.trans (EquivBA.seq_c hem (EquivBA.base (Equiv.refl f))) ?_
  refine EquivBA.trans (EquivBA.seq_c (seq_assoc' (.test g) e (.test oe))
    (EquivBA.base (Equiv.refl f))) ?_
  refine EquivBA.trans (EquivBA.base (Equiv.s1 (.seq (.test g) e) (.test oe) f)) ?_
  refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hf) ?_
  refine EquivBA.trans (EquivBA.symm
    (EquivBA.base (Equiv.s1 (.seq (.test g) e) (.test oe) f'))) ?_
  refine EquivBA.trans (EquivBA.seq_c
    (EquivBA.symm (seq_assoc' (.test g) e (.test oe)))
    (EquivBA.base (Equiv.refl f'))) ?_
  refine EquivBA.trans (EquivBA.seq_c (EquivBA.symm hem)
    (EquivBA.base (Equiv.refl f'))) ?_
  exact EquivBA.base (Equiv.s1 (.test g) e f')

/-- A semantically empty guard's test is provably `0?`. -/
theorem guard_zero_test {c : BExp T} (h : GuardEmpty c) :
    EquivBA (.test c : Exp A T) (.test .zero) :=
  EquivBA.baTest (fun X W x => h X W x)

open Classical in
/-- Prune `e` to its successfully-terminating branches, relative to the input
    guard `g`.  Returns literally `0?` on empty behaviours so deadness propagates
    syntactically.  Loop bodies are not descended into (the loop stratum). -/
noncomputable def prune : BExp T → Exp A T → Exp A T
  | g, .test b => if GuardEmpty (.and g b) then .test .zero else .test b
  | g, .act p => if GuardEmpty g then .test .zero else .act p
  | g, .seq e f =>
      if prune g e = .test .zero ∨ prune (outG g e) f = .test .zero
      then .test .zero
      else .seq (prune g e) (prune (outG g e) f)
  | g, .ite b e f =>
      if prune (.and g b) e = .test .zero ∧ prune (.and g (.not b)) f = .test .zero
      then .test .zero
      else .ite b (prune (.and g b) e) (prune (.and g (.not b)) f)
  | g, .wh b e => if GuardEmpty g then .test .zero else .wh b e

open Classical in
/-- **THE PRUNING THEOREM**: pruning is provable in the finite axioms, under the
    input guard, for every GKAT program. -/
theorem prune_equiv (e : Exp A T) :
    ∀ g : BExp T,
      EquivBA (.seq (.test g) e) (.seq (.test g) (prune g e)) := by
  induction e with
  | act p =>
      intro g
      by_cases hE : GuardEmpty g
      · rw [show prune g (Exp.act p : Exp A T) = .test .zero by
          unfold prune; exact if_pos hE]
        exact EquivBA.trans (test_empty_absorb hE _)
          (EquivBA.symm (test_empty_absorb hE _))
      · rw [show prune g (Exp.act p : Exp A T) = .act p by
          unfold prune; exact if_neg hE]
        exact EquivBA.base (Equiv.refl _)
  | test b =>
      intro g
      by_cases hE : GuardEmpty (.and g b)
      · rw [show prune g (Exp.test b : Exp A T) = .test .zero by
          unfold prune; exact if_pos hE]
        refine EquivBA.trans (EquivBA.s6 g b) ?_
        refine EquivBA.trans (guard_zero_test hE) ?_
        refine EquivBA.symm ?_
        refine EquivBA.trans (EquivBA.s6 g .zero) ?_
        exact guard_zero_test (fun X W x => by
          show (bval W g x && false) = false
          cases bval W g x <;> rfl)
      · rw [show prune g (Exp.test b : Exp A T) = .test b by
          unfold prune; exact if_neg hE]
        exact EquivBA.base (Equiv.refl _)
  | seq e f ihe ihf =>
      intro g
      have main : EquivBA (.seq (.test g) (.seq e f))
          (.seq (.test g) (.seq (prune g e) (prune (outG g e) f))) := by
        refine EquivBA.trans (tail_rewrite (outG_emits e g) (ihf (outG g e))) ?_
        refine EquivBA.trans (seq_assoc' (.test g) e (prune (outG g e) f)) ?_
        refine EquivBA.trans (EquivBA.seq_c (ihe g)
          (EquivBA.base (Equiv.refl _))) ?_
        exact EquivBA.base (Equiv.s1 (.test g) (prune g e) (prune (outG g e) f))
      by_cases hz : prune g e = .test .zero ∨ prune (outG g e) f = .test .zero
      · rw [show prune g (Exp.seq e f : Exp A T) = .test .zero by
          unfold prune; exact if_pos hz]
        refine EquivBA.trans main ?_
        refine EquivBA.seq_c (EquivBA.base (Equiv.refl _)) ?_
        cases hz with
        | inl h1 =>
            rw [h1]
            exact EquivBA.base (Equiv.s2 _)
        | inr h2 =>
            rw [h2]
            exact EquivBA.base (Equiv.s3 _)
      · have heq : prune g (Exp.seq e f : Exp A T)
            = if prune g e = Exp.test BExp.zero
                ∨ prune (outG g e) f = Exp.test BExp.zero
              then Exp.test BExp.zero
              else Exp.seq (prune g e) (prune (outG g e) f) := rfl
        rw [heq, if_neg hz]
        exact main
  | ite b e f ihe ihf =>
      intro g
      have main : EquivBA (.seq (.test g) (.ite b e f))
          (.seq (.test g)
            (.ite b (prune (.and g b) e) (prune (.and g (.not b)) f))) := by
        refine EquivBA.trans (test_seq_ite g b e f) ?_
        refine EquivBA.trans (EquivBA.base (Equiv.u4 (.and g b) e _)) ?_
        refine EquivBA.trans (EquivBA.ite_c (ihe (.and g b))
          (EquivBA.base (Equiv.refl _))) ?_
        refine EquivBA.trans (EquivBA.symm
          (EquivBA.base (Equiv.u4 (.and g b) _ _))) ?_
        refine EquivBA.trans (ite_congr_under_else
          (EquivBA.trans (else_tighten g b f)
            (EquivBA.trans (ihf (.and g (.not b)))
              (EquivBA.symm (else_tighten g b (prune (.and g (.not b)) f)))))) ?_
        exact EquivBA.symm (test_seq_ite g b
          (prune (.and g b) e) (prune (.and g (.not b)) f))
      by_cases hz : prune (.and g b) e = .test .zero
          ∧ prune (.and g (.not b)) f = .test .zero
      · rw [show prune g (Exp.ite b e f : Exp A T) = .test .zero by
          unfold prune; exact if_pos hz]
        refine EquivBA.trans main ?_
        refine EquivBA.seq_c (EquivBA.base (Equiv.refl _)) ?_
        rw [hz.1, hz.2]
        exact EquivBA.base (Equiv.u1 b (.test .zero))
      · have heq : prune g (Exp.ite b e f : Exp A T)
            = if prune (.and g b) e = Exp.test BExp.zero
                ∧ prune (.and g (.not b)) f = Exp.test BExp.zero
              then Exp.test BExp.zero
              else Exp.ite b (prune (.and g b) e) (prune (.and g (.not b)) f) := rfl
        rw [heq, if_neg hz]
        exact main
  | wh b e _ =>
      intro g
      by_cases hE : GuardEmpty g
      · rw [show prune g (Exp.wh b e : Exp A T) = .test .zero by
          unfold prune; exact if_pos hE]
        exact EquivBA.trans (test_empty_absorb hE _)
          (EquivBA.symm (test_empty_absorb hE _))
      · rw [show prune g (Exp.wh b e : Exp A T) = .wh b e by
          unfold prune; exact if_neg hE]
        exact EquivBA.base (Equiv.refl _)

#print axioms prune_equiv

/-- The unguarded corollary: `e ≡ prune 1 e`, for EVERY GKAT program. -/
theorem prune_equiv_top (e : Exp A T) :
    EquivBA e (prune .one e) :=
  EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.s4 e)))
    (EquivBA.trans (prune_equiv e .one)
      (EquivBA.base (Equiv.s4 (prune .one e))))

#print axioms prune_equiv_top

/-! ## The first tight loop fact: productive loops emit their exit guard -/

/-- **Exit emission for productive loops**: when the body is strictly productive
    (`E e ≡ 0`, the `w3` side condition), the loop provably ends in `¬b` — the
    tight output guard, with no input-guard fixpoint needed.  `w1` unrolls, the
    else arm strengthens from `1?` to `(¬b)?` (`else_guard_test`), and `w3_ba`
    refolds against the strengthened continuation.  No UA. -/
theorem wh_emits_exit {b : BExp T} {e : Exp A T}
    (hprod : EquivBA (.test (E e) : Exp A T) (.test .zero)) :
    EquivBA (.wh b e) (.seq (.wh b e) (.test (.not b))) :=
  EquivBA.w3_ba hprod
    (EquivBA.trans (EquivBA.base (Equiv.w1 b e))
      (GkatSumQuotient.else_guard_test b (.seq e (.wh b e))))

#print axioms wh_emits_exit

end GkatNormalization
