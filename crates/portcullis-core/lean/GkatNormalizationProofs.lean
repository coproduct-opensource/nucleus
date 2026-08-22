import GkatPlanExistenceProofs
import GkatDeadExitElimProofs

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

/-! ## The shared kit -/

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

/-! ## Test-bodied loops collapse — the first unguarded-loop elimination -/

/-- **All pure-test loop bodies collapse**: `wh b (c?) ≡ (¬b)?`, for EVERY `c` —
    including the divergent `wh 1 (1?) ≡ 0?` at `b = 1`.  `w2` first identifies
    all test bodies with each other (`c? ≡ ite c 1? 1? / c?·1?` both ways), and
    `w3_ba` then eliminates the `0?`-bodied loop, whose body is vacuously
    productive.  No UA. -/
theorem wh_test_collapse (b c : BExp T) :
    EquivBA (.wh b (.test c) : Exp A T) (.test (.not b)) := by
  -- wh b (c?) ≡ wh b (1?)
  have h1 : EquivBA (.wh b (.test c) : Exp A T) (.wh b (.test .one)) := by
    refine EquivBA.trans (EquivBA.wh_c (EquivBA.symm
      (EquivBA.base (Equiv.s5 (.test c))))) ?_
    refine EquivBA.trans (EquivBA.symm
      (EquivBA.base (Equiv.w2 b c (.test .one)))) ?_
    exact EquivBA.wh_c (EquivBA.base (Equiv.u1 c (.test .one)))
  -- wh b (1?) ≡ wh b (0?)
  have h2 : EquivBA (.wh b (.test .one) : Exp A T) (.wh b (.test .zero)) := by
    refine EquivBA.trans (EquivBA.wh_c (EquivBA.symm
      (EquivBA.base (Equiv.u1 .zero (.test .one))))) ?_
    refine EquivBA.trans (EquivBA.base (Equiv.w2 b .zero (.test .one))) ?_
    exact EquivBA.wh_c (EquivBA.base (Equiv.s5 (.test .zero)))
  -- (¬b)? solves the 0?-bodied equation …
  have h3 : EquivBA (.test (.not b) : Exp A T)
      (.ite b (.seq (.test .zero) (.test (.not b))) (.test .one)) := by
    refine EquivBA.symm ?_
    refine EquivBA.trans (EquivBA.ite_c
      (EquivBA.base (Equiv.s2 (.test (.not b))))
      (EquivBA.base (Equiv.refl _))) ?_
    refine EquivBA.trans (EquivBA.base (Equiv.u2 b (.test .zero) (.test .one))) ?_
    refine EquivBA.trans (EquivBA.symm
      (test_seq_as_ite (.not b) (.test .one))) ?_
    exact EquivBA.base (Equiv.s5 (.test (.not b)))
  -- … so w3_ba folds it: (¬b)? ≡ (wh b 0?)·1?
  have h4 : EquivBA (.test (.not b) : Exp A T)
      (.seq (.wh b (.test .zero)) (.test .one)) :=
    EquivBA.w3_ba (EquivBA.base (Equiv.refl _)) h3
  refine EquivBA.trans h1 (EquivBA.trans h2 ?_)
  refine EquivBA.trans (EquivBA.symm
    (EquivBA.base (Equiv.s5 (.wh b (.test .zero))))) ?_
  exact EquivBA.symm h4

#print axioms wh_test_collapse

/-! ## The guardedness keystone: the fundamental theorem + productive loops

    POPL'20 (Smolka et al.) Theorem 3.7 / Lemma 3.9, made GUARD-STRUCTURAL: the
    paper's `D(e)` is an atom-indexed guarded sum; here it is a plain expression
    built by recursion, so no atom-enumeration machinery is needed.  The loop
    case of `dPart` bakes the productive body in, which dissolves the paper's
    tightening identity `¬E(e)·D(e) ≡ D(e)` entirely.  The FT induction's loop
    case uses Productive Loop FOR THE BODY (the induction hypothesis), so the
    mutual dependency is stratified, not circular. -/

/-- The structural productive part: `e` minus its empty-string behaviour. -/
def dPart : Exp A T → Exp A T
  | .test _ => .test .zero
  | .act p => .act p
  | .ite c e f => .ite c (dPart e) (dPart f)
  | .seq e f => .ite (E e) (dPart f) (.seq (dPart e) f)
  | .wh c e => .seq (.seq (.test (.not (E e))) (dPart e))
      (.wh c (.seq (.test (.not (E e))) (dPart e)))

/-- The productive part is strictly productive. -/
theorem dPart_E_empty (e : Exp A T) : GuardEmpty (E (dPart e)) := by
  induction e with
  | act p => intro X W x; rfl
  | test b => intro X W x; rfl
  | seq e f ihe ihf =>
      intro X W x
      show (bval W (E e) x && bval W (E (dPart f)) x
        || !bval W (E e) x && (bval W (E (dPart e)) x && bval W (E f) x)) = false
      rw [ihe X W x, ihf X W x]
      cases bval W (E e) x <;> rfl
  | ite c e f ihe ihf =>
      intro X W x
      show (bval W c x && bval W (E (dPart e)) x
        || !bval W c x && bval W (E (dPart f)) x) = false
      rw [ihe X W x, ihf X W x]
      cases bval W c x <;> rfl
  | wh c e ihe =>
      intro X W x
      show ((!bval W (E e) x && bval W (E (dPart e)) x) && !bval W c x) = false
      rw [ihe X W x]
      cases bval W (E e) x <;> rfl

/-- **THE FUNDAMENTAL THEOREM of GKAT** (structural form): every program is its
    termination test guarding `1?`, else its strictly productive part. -/
theorem fundamental (e : Exp A T) :
    EquivBA e (.ite (E e) (.test .one) (dPart e)) := by
  induction e with
  | test b =>
      show EquivBA (.test b) (.ite b (.test .one) (.test .zero))
      refine EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.s5 (.test b)))) ?_
      exact test_seq_as_ite b (.test .one)
  | act p =>
      show EquivBA (.act p) (.ite .zero (.test .one) (.act p))
      exact EquivBA.symm
        (GkatDeadExitElim.ite_zero_guard _ _ (fun X W x => rfl))
  | seq e f ihe ihf =>
      show EquivBA (.seq e f)
        (.ite (.and (E e) (E f)) (.test .one)
          (.ite (E e) (dPart f) (.seq (dPart e) f)))
      refine EquivBA.trans (EquivBA.seq_c ihe (EquivBA.base (Equiv.refl f))) ?_
      refine EquivBA.trans (EquivBA.symm (EquivBA.base
        (Equiv.u5 (E e) (.test .one) (dPart e) f))) ?_
      refine EquivBA.trans (EquivBA.ite_c (EquivBA.base (Equiv.s4 f))
        (EquivBA.base (Equiv.refl _))) ?_
      refine EquivBA.trans (EquivBA.ite_c ihf (EquivBA.base (Equiv.refl _))) ?_
      refine EquivBA.trans (EquivBA.base
        (Equiv.u3 (E f) (E e) (.test .one) (dPart f) (.seq (dPart e) f))) ?_
      exact EquivBA.ite_guard (fun X W x => by
        show (bval W (E f) x && bval W (E e) x)
          = (bval W (E e) x && bval W (E f) x)
        cases bval W (E f) x <;> cases bval W (E e) x <;> rfl)
  | ite c e f ihe ihf =>
      show EquivBA (.ite c e f)
        (.ite (.or (.and c (E e)) (.and (.not c) (E f))) (.test .one)
          (.ite c (dPart e) (dPart f)))
      refine EquivBA.trans (EquivBA.ite_c ihe ihf) ?_
      refine EquivBA.trans (EquivBA.base
        (Equiv.u3 (E e) c (.test .one) (dPart e)
          (.ite (E f) (.test .one) (dPart f)))) ?_
      have hinner : EquivBA
          (.ite c (dPart e) (.ite (E f) (.test .one) (dPart f)))
          (.ite (.and (E f) (.not c)) (.test .one)
            (.ite c (dPart e) (dPart f))) := by
        refine EquivBA.trans (EquivBA.base (Equiv.u2 c (dPart e) _)) ?_
        refine EquivBA.trans (EquivBA.base
          (Equiv.u3 (E f) (.not c) (.test .one) (dPart f) (dPart e))) ?_
        exact EquivBA.ite_c (EquivBA.base (Equiv.refl _))
          (EquivBA.symm (EquivBA.base (Equiv.u2 c (dPart e) (dPart f))))
      refine EquivBA.trans
        (EquivBA.ite_c (EquivBA.base (Equiv.refl _)) hinner) ?_
      refine EquivBA.trans (EquivBA.symm (ite_or_split (.and (E e) c)
        (.and (E f) (.not c)) (.test .one) (.ite c (dPart e) (dPart f)))) ?_
      exact EquivBA.ite_guard (fun X W x => by
        show (bval W (E e) x && bval W c x || bval W (E f) x && !bval W c x)
          = (bval W c x && bval W (E e) x || !bval W c x && bval W (E f) x)
        cases bval W c x <;> cases bval W (E e) x <;> cases bval W (E f) x <;> rfl)
  | wh c e ihe =>
      show EquivBA (.wh c e)
        (.ite (.not c) (.test .one)
          (.seq (.seq (.test (.not (E e))) (dPart e))
            (.wh c (.seq (.test (.not (E e))) (dPart e)))))
      have hpl : EquivBA (.wh c e)
          (.wh c (.seq (.test (.not (E e))) (dPart e))) := by
        refine EquivBA.trans (EquivBA.wh_c ihe) ?_
        refine EquivBA.trans (EquivBA.wh_c (EquivBA.base
          (Equiv.u2 (E e) (.test .one) (dPart e)))) ?_
        exact EquivBA.base (Equiv.w2 c (.not (E e)) (dPart e))
      refine EquivBA.trans hpl ?_
      refine EquivBA.trans (EquivBA.base (Equiv.w1 c _)) ?_
      exact EquivBA.base (Equiv.u2 c _ (.test .one))

#print axioms fundamental

/-- **PRODUCTIVE LOOP** (POPL'20 Lemma 3.9): every loop is provably a loop with
    a strictly productive body — `w2` strips the termination part exposed by the
    fundamental theorem. -/
theorem productive_loop (c : BExp T) (e : Exp A T) :
    EquivBA (.wh c e) (.wh c (.seq (.test (.not (E e))) (dPart e))) := by
  refine EquivBA.trans (EquivBA.wh_c (fundamental e)) ?_
  refine EquivBA.trans (EquivBA.wh_c (EquivBA.base
    (Equiv.u2 (E e) (.test .one) (dPart e)))) ?_
  exact EquivBA.base (Equiv.w2 c (.not (E e)) (dPart e))

/-- The replacement body really is strictly productive. -/
theorem productive_body_empty (e : Exp A T) :
    GuardEmpty (E (.seq (.test (.not (E e))) (dPart e) : Exp A T)) := by
  intro X W x
  show (!bval W (E e) x && bval W (E (dPart e)) x) = false
  rw [dPart_E_empty e X W x]
  cases bval W (E e) x <;> rfl

/-- **THE GUARDEDNESS NORMALIZATION**: every loop body is provably replaceable
    by a strictly productive one — the keystone the loop stratum was queued
    behind. -/
theorem guardedness_normalization (c : BExp T) (e : Exp A T) :
    ∃ ê : Exp A T, EquivBA (.wh c e) (.wh c ê) ∧ GuardEmpty (E ê) :=
  ⟨_, productive_loop c e, productive_body_empty e⟩

#print axioms guardedness_normalization

/-! ## Unlocked corollaries -/

/-- Exit emission with NO productivity hypothesis: every loop provably ends in
    its exit guard. -/
theorem wh_emits_exit_all (b : BExp T) (e : Exp A T) :
    EquivBA (.wh b e) (.seq (.wh b e) (.test (.not b))) := by
  refine EquivBA.trans (productive_loop b e) ?_
  refine EquivBA.trans
    (wh_emits_exit (guard_zero_test (productive_body_empty e))) ?_
  exact EquivBA.seq_c (EquivBA.symm (productive_loop b e))
    (EquivBA.base (Equiv.refl _))

/-- **The unguarded divergent loop is `0`** — for EVERY body, no side
    conditions: `wh 1 e ≡ 0?`. -/
theorem wh_one_zero (e : Exp A T) :
    EquivBA (.wh .one e) (.test .zero) := by
  refine EquivBA.trans (wh_emits_exit_all .one e) ?_
  refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
    (EquivBA.baTest (b := .not .one) (c := .zero) (fun X W x => rfl))) ?_
  exact EquivBA.base (Equiv.s3 _)

#print axioms wh_emits_exit_all
#print axioms wh_one_zero

open Classical in
/-- The output guard of `g?·e`: the last atoms of its accepted strings.  An action
    resets the interface (`1` if anything reaches it, `0` if nothing does); tests
    conjoin; `seq` composes; `ite` splits the input guard and joins.  A loop's
    output is its exit guard `¬b` (`wh_emits_exit_all`) — sound and, by
    determinism, the best guard obtainable without reachable-exit analysis. -/
noncomputable def outG : BExp T → Exp A T → BExp T
  | g, .test b => .and g b
  | g, .act _ => if GuardEmpty g then .zero else .one
  | g, .seq e f => outG (outG g e) f
  | g, .ite b e f => .or (outG (.and g b) e) (outG (.and g (.not b)) f)
  | _, .wh b _ => .not b

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
      rw [show outG g (Exp.wh b e : Exp A T) = BExp.not b from rfl]
      exact EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (wh_emits_exit_all b e)

#print axioms outG_emits

/-! ## Pruning: cut every dead branch, provably -/

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


/-! ## Pruning descends through loop bodies -/

/-- **Loop-body congruence under the guard** (derived, no UA): bodies that agree
    under `b` give equal loops, provided the replacement is strictly productive.
    `w1` unrolls, `u4`-style guard insertion applies the agreement, and `w3_ba`
    refolds against the replacement body. -/
theorem wh_congr_under_guard {b : BExp T} {X Y : Exp A T}
    (hprodY : EquivBA (.test (E Y) : Exp A T) (.test .zero))
    (hb : EquivBA (.seq (.test b) X) (.seq (.test b) Y)) :
    EquivBA (.wh b X) (.wh b Y) := by
  have hstep : EquivBA (.wh b X) (.ite b (.seq Y (.wh b X)) (.test .one)) := by
    refine EquivBA.trans (EquivBA.base (Equiv.w1 b X)) ?_
    refine ite_congr_under_guard ?_
    refine EquivBA.trans (seq_assoc' (.test b) X (.wh b X)) ?_
    refine EquivBA.trans (EquivBA.seq_c hb (EquivBA.base (Equiv.refl _))) ?_
    exact EquivBA.base (Equiv.s1 (.test b) Y (.wh b X))
  refine EquivBA.trans (EquivBA.w3_ba hprodY hstep) ?_
  exact EquivBA.base (Equiv.s5 (.wh b Y))

open Classical in
/-- Pruning can only SHRINK the termination test. -/
theorem prune_E_implies (u : Exp A T) :
    ∀ g : BExp T, GuardImplies (E (prune g u)) (E u) := by
  induction u with
  | act p =>
      intro g X W x h
      by_cases hE : GuardEmpty g
      · rw [show prune g (Exp.act p : Exp A T) = .test .zero by
          unfold prune; exact if_pos hE] at h
        exact Bool.noConfusion h
      · rw [show prune g (Exp.act p : Exp A T) = .act p by
          unfold prune; exact if_neg hE] at h
        exact h
  | test b =>
      intro g X W x h
      by_cases hE : GuardEmpty (.and g b)
      · rw [show prune g (Exp.test b : Exp A T) = .test .zero by
          unfold prune; exact if_pos hE] at h
        exact Bool.noConfusion h
      · rw [show prune g (Exp.test b : Exp A T) = .test b by
          unfold prune; exact if_neg hE] at h
        exact h
  | seq e f ihe ihf =>
      intro g X W x h
      by_cases hz : prune g e = Exp.test BExp.zero
          ∨ prune (outG g e) f = Exp.test BExp.zero
      · rw [show prune g (Exp.seq e f : Exp A T) = .test .zero by
          unfold prune; exact if_pos hz] at h
        exact Bool.noConfusion h
      · have heq : prune g (Exp.seq e f : Exp A T)
            = if prune g e = Exp.test BExp.zero
                ∨ prune (outG g e) f = Exp.test BExp.zero
              then Exp.test BExp.zero
              else Exp.seq (prune g e) (prune (outG g e) f) := rfl
        rw [heq, if_neg hz] at h
        have h' : (bval W (E (prune g e)) x
            && bval W (E (prune (outG g e) f)) x) = true := h
        show (bval W (E e) x && bval W (E f) x) = true
        cases he : bval W (E (prune g e)) x with
        | false => rw [he] at h'; exact Bool.noConfusion h'
        | true =>
            cases hf : bval W (E (prune (outG g e) f)) x with
            | false => rw [he, hf] at h'; exact Bool.noConfusion h'
            | true =>
                rw [ihe g X W x he, ihf (outG g e) X W x hf]
                rfl
  | ite b e f ihe ihf =>
      intro g X W x h
      by_cases hz : prune (.and g b) e = Exp.test BExp.zero
          ∧ prune (.and g (.not b)) f = Exp.test BExp.zero
      · rw [show prune g (Exp.ite b e f : Exp A T) = .test .zero by
          unfold prune; exact if_pos hz] at h
        exact Bool.noConfusion h
      · have heq : prune g (Exp.ite b e f : Exp A T)
            = if prune (.and g b) e = Exp.test BExp.zero
                ∧ prune (.and g (.not b)) f = Exp.test BExp.zero
              then Exp.test BExp.zero
              else Exp.ite b (prune (.and g b) e)
                (prune (.and g (.not b)) f) := rfl
        rw [heq, if_neg hz] at h
        have h' : (bval W b x && bval W (E (prune (.and g b) e)) x
            || !bval W b x && bval W (E (prune (.and g (.not b)) f)) x)
              = true := h
        show (bval W b x && bval W (E e) x
          || !bval W b x && bval W (E f) x) = true
        cases hb : bval W b x with
        | true =>
            rw [hb] at h'
            cases he : bval W (E (prune (.and g b) e)) x with
            | false => rw [he] at h'; exact Bool.noConfusion h'
            | true => rw [ihe (.and g b) X W x he]; rfl
        | false =>
            rw [hb] at h'
            cases hf : bval W (E (prune (.and g (.not b)) f)) x with
            | false => rw [hf] at h'; exact Bool.noConfusion h'
            | true => rw [ihf (.and g (.not b)) X W x hf]; rfl
  | wh b e _ =>
      intro g X W x h
      by_cases hE : GuardEmpty g
      · rw [show prune g (Exp.wh b e : Exp A T) = .test .zero by
          unfold prune; exact if_pos hE] at h
        exact Bool.noConfusion h
      · rw [show prune g (Exp.wh b e : Exp A T) = .wh b e by
          unfold prune; exact if_neg hE] at h
        exact h

/-- **PRUNING DESCENDS THROUGH LOOPS**: every loop is provably the loop of its
    normalized-then-pruned body — productive normalization (`productive_loop`)
    followed by pruning under the loop guard, glued by the loop-body
    congruence. -/
theorem wh_prune_body (b : BExp T) (e : Exp A T) :
    EquivBA (.wh b e)
      (.wh b (prune b (.seq (.test (.not (E e))) (dPart e)))) := by
  refine EquivBA.trans (productive_loop b e) ?_
  refine wh_congr_under_guard (guard_zero_test ?_)
    (prune_equiv (.seq (.test (.not (E e))) (dPart e)) b)
  intro X W x
  cases hpb : bval W
      (E (prune b (.seq (.test (.not (E e))) (dPart e)))) x with
  | false => rfl
  | true =>
      have h1 := prune_E_implies (.seq (.test (.not (E e))) (dPart e)) b X W x hpb
      have h2 := productive_body_empty e X W x
      rw [h1] at h2
      exact Bool.noConfusion h2

#print axioms wh_congr_under_guard
#print axioms wh_prune_body

end GkatNormalization
