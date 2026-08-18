import GkatResidueProofs

/-!
# The residue as a family — a general loop guard, and the core at the top of a loop body

`GkatResidueProofs` proves pairs #3 and #2 of the eight open instances with the loop guard
written literally as `¬b`.  That is an accident of how the harness happened to number the two
atoms, and it costs half the residue: printed in full, the eight are

    #1  e = C ; ((p;p) ; C)^(g)                     f = ( p ; ((A ; p) +_g b?) )^(g)
    #2  e = ( p ; (((A ; p^(g)) ; p) +_g b?) )^(g)  f = ( p ; (((A;C)^(g) ; p) +_g b?) )^(g)
    #3  e = ( p ; ((A ; p^(g))     +_g p ) )^(g)    f = ( p ; ((A;C)^(g)     +_g p ) )^(g)
    #4  e = ((A ; p^(g)) ; q)^(g)                   f = ((A ; C) ; (q +_c b?))^(g)
    #5  = #3 with the two atoms exchanged
    #6  e = ((A ; p^(g)) ; q)^(g)                   f = ((A;C)^(g) ; q)^(g)
    #7  = #1 with the two atoms exchanged
    #8  e = ( p ; ((p ; (p^(g) ; A)) +_g c?) )^(g)  f = ( p ; (((A;C)^(g) ; p) +_g c?) )^(g)

so #5 is #3 under an exchange of atoms and #7 is #1 under the same exchange.  Nothing in the
derivation cares which atom is which, and this file makes that structural rather than
incidental: every lemma takes the loop guard `g` and the branch guard `c` as *independent*
parameters, related only by the semantic hypothesis `c = ¬g`.  Both #3 and #5 are then
instances of one theorem — #3 at `g := ¬b, c := b`, #5 at `g := b, c := ¬b` — and no
double-negation bookkeeping appears anywhere.

The second thing here is #6, which needs the core equality in a genuinely new position.  In #2
and #3 the core sits inside a guarded choice, where `U4` makes the guard available for free.
In #6 it sits at the *top of a loop body*, where nothing hands you the guard — you have to take
it, which is what `wh_restrict_body` is for.  `wh_congr_under_guard` packages that: two loop
bodies that agree once the guard is asserted give equal loops, provided both are productive.

#8 is the third thing, and it needs the guard at the OTHER end.  Its two sides put `A` in
different places: `f` has it under the loop guard, where `A ≡ p` because the then arm fails;
`e` has it after an inner loop, where `A ≡ p` for the opposite reason — the loop has exited, so
`¬g` holds and the else arm is selected.  `wh_exit` supplies that second reading.

`wh_exit` is NOT new.  Smolka et al. note exactly this consequence of W3 — "the loop condition
is false when a loop ends", `e^(b) ≡ e^(b) · b̄` — in the original GKAT paper.  It was rederived
here because the corpus did not have it, not because it was unknown, and the derivation below
is presumably theirs rediscovered.

#1 and #7 fall to W3 used as what it is — a uniqueness principle for ONE unknown.  See the
section below.

Remaining after this file: **#4 alone**.  Substituting the core equality into it reduces it to

    (K^(g)) ; Y  looped on g     ≡     (K ; (Y +_c 1))  looped on g          (K = A;C)

i.e. `while g { (while g K); Y }  ≡  while g { K; if ¬g then Y }` — LOOP FUSION, the inner
loop absorbed into the outer one.  Attempting it by the #1 route does not close: assuming the
right side satisfies the left's equation reduces, under the guard, to the same statement again,
so a single application of W3 cannot discharge it.  What that argument needs is a simultaneous
equation in the two unknowns `Z` and `K^(g);Y;Z` — a 2-unknown system, which is UA_2.  That is
suggestive but NOT a proof that #4 requires UA: it shows one route fails, not that all do.
-/

namespace GkatResidueFamily

open GkatSyntax GkatGS GkatFaithful GkatGuardedAlgebra GkatCyclicK GkatRefines GkatResidue

variable {A T : Type}

/-! ## Two Boolean shims -/

/-- A choice on an unsatisfiable guard is its else arm. -/
theorem ite_unsat {z : BExp T} (e f : Exp A T)
    (hz : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W z x = false) :
    EquivBA (.ite z e f) f :=
  EquivBA.trans (EquivBA.base (Equiv.u2 z e f))
    (ite_taut f e (fun X W x => by
      show (!bval W z x) = true
      rw [hz X W x]; rfl))

/-- Two tests that agree under a guard may be exchanged in that guard's then arm. -/
theorem ite_then_test_gen {z c₁ c₂ : BExp T} (X : Exp A T)
    (hz : ∀ (Y : Type) (W : T → Y → Bool) (x : Y),
      (bval W z x && bval W c₁ x) = (bval W z x && bval W c₂ x)) :
    EquivBA (.ite z (.test c₁) X) (.ite z (.test c₂) X) :=
  EquivBA.trans (EquivBA.base (Equiv.u4 z (.test c₁) X))
    (EquivBA.trans
      (EquivBA.ite_c
        (EquivBA.trans (EquivBA.s6 z c₁)
          (EquivBA.trans
            (show EquivBA (.test (.and z c₁) : Exp A T) (.test (.and z c₂)) from
              EquivBA.baTest hz)
            (EquivBA.symm (EquivBA.s6 z c₂))))
        (EquivBA.base (Equiv.refl X)))
      (EquivBA.symm (EquivBA.base (Equiv.u4 z (.test c₂) X))))

/-! ## The core, with the loop guard as a parameter

    Throughout, `g` is the loop guard, `c` is the guard of `A` and `C`, and `hgc` says `c` is
    `¬g` semantically.  Nothing requires them to be syntactically complementary. -/

section Core

variable {g c : BExp T} {p : Exp A T}

/-- `D = p +_g 1`, the second factor of `expK g p 1`. -/
def resDg (g : BExp T) (p : Exp A T) : Exp A T := .ite g p (.test .one)

theorem expKg_one (g : BExp T) (p : Exp A T) : expK g p 1 = .seq p (resDg g p) := rfl

/-- `C ≡ D`: under `c` the tests `c` and `1` agree, and `¬c` is `g`. -/
theorem resC_eq_resDg
    (hgc : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W c x = !bval W g x) :
    EquivBA (resC c p) (resDg g p) :=
  EquivBA.trans
    (ite_then_test_gen p (fun _ W x => by
      cases h : bval W c x <;> rfl))
    (EquivBA.trans (EquivBA.base (Equiv.u2 c (.test .one) p))
      (EquivBA.ite_guard (fun X W x => by
        show (!bval W c x) = bval W g x
        rw [hgc X W x]; cases bval W g x <;> rfl)))

/-- An assertion of `g` selects the else arm of a choice on `c`. -/
theorem test_seq_ite_else_gen
    (hgc : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W c x = !bval W g x)
    (e f : Exp A T) :
    EquivBA (.seq (.test g) (.ite c e f)) (.seq (.test g) f) :=
  EquivBA.trans (test_seq_ite g c e f)
    (ite_unsat e (.seq (.test g) f) (fun X W x => by
      show (bval W g x && bval W c x) = false
      rw [hgc X W x]; cases bval W g x <;> rfl))

/-- `A ; C ≡ g? · (p ; D)` — the body of the coarse loop is the body of `expK g p 1`,
    asserted under the loop guard. -/
theorem resA_seq_resC_gen
    (hgc : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W c x = !bval W g x) :
    EquivBA (.seq (resA c p) (resC c p)) (.seq (.test g) (.seq p (resDg g p))) := by
  refine EquivBA.trans
    (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (resC_eq_resDg hgc)) ?_
  refine EquivBA.trans
    (EquivBA.seq_c
      (EquivBA.trans (EquivBA.base (Equiv.u2 c (.test .zero) p))
        (EquivBA.ite_guard (fun X W x => by
          show (!bval W c x) = bval W g x
          rw [hgc X W x]; cases bval W g x <;> rfl)))
      (EquivBA.base (Equiv.refl _))) ?_
  refine EquivBA.trans (ite_seq_right g p (.test .zero) (resDg g p)) ?_
  exact EquivBA.trans
    (EquivBA.ite_c (EquivBA.base (Equiv.refl _)) (EquivBA.base (Equiv.s2 _)))
    (ite_zero_else g (.seq p (resDg g p)))

/-- `(A ; C)^(g) ≡ p^(g)` — the granularity law at a general guard. -/
theorem wh_resA_resC_gen
    (hgc : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W c x = !bval W g x)
    (hEp : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E p) x = false) :
    EquivBA (.wh g (.seq (resA c p) (resC c p))) (.wh g p) :=
  wh_cyc_body (n := 1) (resA_seq_resC_gen hgc) hEp

/-- **The core.**  Under `g`, running `A` and then the fine loop is the coarse loop. -/
theorem guarded_core_gen
    (hgc : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W c x = !bval W g x)
    (hEp : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E p) x = false) :
    EquivBA (.seq (.test g) (.seq (resA c p) (.wh g p)))
      (.seq (.test g) (.wh g (.seq (resA c p) (resC c p)))) := by
  have hL : EquivBA (.seq (.test g) (.seq (resA c p) (.wh g p)))
      (.seq (.test g) (.seq p (.wh g p))) :=
    EquivBA.trans (EquivBA.symm (seq_assoc _ _ _))
      (EquivBA.trans
        (EquivBA.seq_c (test_seq_ite_else_gen hgc (.test .zero) p)
          (EquivBA.base (Equiv.refl _)))
        (seq_assoc _ _ _))
  have hR : EquivBA (.seq (.test g) (.wh g p)) (.seq (.test g) (.seq p (.wh g p))) :=
    EquivBA.trans
      (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (EquivBA.base (Equiv.w1 g p)))
      (test_seq_ite_of_implies (b := g) (z := g) _ _ (fun _ _ _ h => h))
  exact EquivBA.trans (EquivBA.trans hL (EquivBA.symm hR))
    (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) (EquivBA.symm (wh_resA_resC_gen hgc hEp)))

end Core

/-! ## Productivity bookkeeping -/

/-- `A` is productive whenever `p` is: the then arm fails and the else arm is `p`. -/
theorem E_resA {c : BExp T} {p : Exp A T}
    (hEp : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E p) x = false)
    (X : Type) (W : T → X → Bool) (x : X) : bval W (E (resA c p)) x = false := by
  show ((bval W c x && false) || (!bval W c x && bval W (E p) x)) = false
  rw [hEp X W x]; cases bval W c x <;> rfl

/-- A sequence is productive if its first factor is. -/
theorem E_seq_left {X' Y : Exp A T}
    (h : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E X') x = false)
    (X : Type) (W : T → X → Bool) (x : X) : bval W (E (.seq X' Y)) x = false := by
  show (bval W (E X') x && _) = false
  rw [h X W x]; rfl

/-- A sequence is productive if its second factor is. -/
theorem E_seq_right {X' Y : Exp A T}
    (h : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E Y) x = false)
    (X : Type) (W : T → X → Bool) (x : X) : bval W (E (.seq X' Y)) x = false := by
  show (_ && bval W (E Y) x) = false
  rw [h X W x]; cases bval W (E X') x <;> rfl

/-! ## The core at the top of a loop body -/

/-- **Congruence for loop bodies, under the loop's own guard.**

    Inside a guarded choice `U4` hands you the guard for nothing.  At the top of a loop body
    nothing does, and this is the lemma that takes it: `wh_restrict_body` installs the
    assertion on both sides, the hypothesis exchanges the bodies underneath it, and it is
    removed again.  Both bodies must be productive, which is where `w3` is used and why the
    productivity shims above exist. -/
theorem wh_congr_under_guard {g : BExp T} {X' Y : Exp A T}
    (h : EquivBA (.seq (.test g) X') (.seq (.test g) Y))
    (hX : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E X') x = false)
    (hY : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E Y) x = false) :
    EquivBA (.wh g X') (.wh g Y) :=
  EquivBA.trans (wh_restrict_body (EquivBA.baTest hX))
    (EquivBA.trans (EquivBA.wh_c h)
      (EquivBA.symm (wh_restrict_body (EquivBA.baTest hY))))

/-! ## Exit from a loop

    Everything so far used the guard where it HOLDS — at the top of a body, inside a choice.
    #8 needs the other end: on exit from `e^(g)` the guard has FAILED, and that fact has to be
    available as an assertion the algebra can use. -/

/-- Under `¬g` the test `h` and the test `1` agree, so a loop's exit branch may use either. -/
theorem ite_else_test_gen {g h : BExp T} (X : Exp A T)
    (hgh : ∀ (Y : Type) (W : T → Y → Bool) (x : Y), bval W h x = !bval W g x) :
    EquivBA (.ite g X (.test h)) (.ite g X (.test .one)) :=
  EquivBA.trans (EquivBA.base (Equiv.u2 g X (.test h)))
    (EquivBA.trans
      (ite_then_test_gen X (fun Y W x => by
        show ((!bval W g x) && bval W h x) = ((!bval W g x) && true)
        rw [hgh Y W x]; cases bval W g x <;> rfl))
      (EquivBA.symm (EquivBA.base (Equiv.u2 g X (.test .one)))))

/-- **On exit from a loop the guard has failed:** `e^(g) ≡ e^(g) · h?` whenever `h = ¬g` and
    `e` is productive.

    Same shape as `wh_restrict_body`, and the same reason it works.  `e^(g) · h?` is shown to
    solve the Salomaa equation for `e^(g)` — W1 unrolls, U5 pushes the assertion through the
    choice, S4 clears it from the exit arm, and `ite_else_test_gen` rewrites what is left to
    `1` because the exit arm is reached only under `¬g`.  `w3` then identifies the solution,
    which is where productivity is spent. -/
theorem wh_exit {g h : BExp T} {e : Exp A T}
    (hgh : ∀ (Y : Type) (W : T → Y → Bool) (x : Y), bval W h x = !bval W g x)
    (hE : ∀ (Y : Type) (W : T → Y → Bool) (x : Y), bval W (E e) x = false) :
    EquivBA (.wh g e : Exp A T) (.seq (.wh g e) (.test h)) := by
  have hsol : EquivBA (.seq (.wh g e) (.test h) : Exp A T)
      (.ite g (.seq e (.seq (.wh g e) (.test h))) (.test .one)) := by
    refine EquivBA.trans
      (EquivBA.seq_c (EquivBA.base (Equiv.w1 g e)) (EquivBA.base (Equiv.refl _))) ?_
    refine EquivBA.trans (ite_seq_right g (.seq e (.wh g e)) (.test .one) (.test h)) ?_
    refine EquivBA.trans
      (EquivBA.ite_c (seq_assoc _ _ _) (EquivBA.base (Equiv.s4 _))) ?_
    exact ite_else_test_gen _ hgh
  exact EquivBA.symm (EquivBA.trans (EquivBA.w3_ba (EquivBA.baTest hE) hsol) (seq_one _))

/-- Under the loop guard, `A` is just `p` — in front of any continuation. -/
theorem guarded_resA_is_p {g c : BExp T} {p : Exp A T}
    (hgc : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W c x = !bval W g x)
    (Y : Exp A T) :
    EquivBA (.seq (.test g) (.seq (resA c p) Y)) (.seq (.test g) (.seq p Y)) :=
  EquivBA.trans (EquivBA.symm (seq_assoc _ _ _))
    (EquivBA.trans
      (EquivBA.seq_c (test_seq_ite_else_gen hgc (.test .zero) p) (EquivBA.base (Equiv.refl Y)))
      (seq_assoc _ _ _))

/-! ## The pairs -/

section Pairs

variable {g c : BExp T} {p : Exp A T}

/-- **Pairs #3 and #5.**  One theorem at a general loop guard; #3 is `g := ¬b, c := b` and
    #5 is `g := b, c := ¬b`.  The else arm `Z` is arbitrary — it never enters the derivation. -/
theorem residue_pair_three_five
    (hgc : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W c x = !bval W g x)
    (hEp : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E p) x = false)
    (Z : Exp A T) :
    EquivBA
      (.wh g (.seq p (.ite g (.seq (resA c p) (.wh g p)) Z)))
      (.wh g (.seq p (.ite g (.wh g (.seq (resA c p) (resC c p))) Z))) :=
  EquivBA.wh_c (EquivBA.seq_c (EquivBA.base (Equiv.refl p))
    (ite_congr_under_guard (guarded_core_gen hgc hEp)))

/-- **Pair #2, at a general loop guard** — the same core with a continuation `q`. -/
theorem residue_pair_two_gen
    (hgc : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W c x = !bval W g x)
    (hEp : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E p) x = false)
    (q Z : Exp A T) :
    EquivBA
      (.wh g (.seq p (.ite g (.seq (.seq (resA c p) (.wh g p)) q) Z)))
      (.wh g (.seq p (.ite g (.seq (.wh g (.seq (resA c p) (resC c p))) q) Z))) :=
  EquivBA.wh_c (EquivBA.seq_c (EquivBA.base (Equiv.refl p))
    (ite_congr_under_guard (seq_under_guard q (guarded_core_gen hgc hEp))))

/-- **Pair #6.**  The same core, now at the top of the loop body rather than inside a choice.
    `q` must be productive — otherwise the right-hand body could halt immediately, and `w3`
    would not apply to it. -/
theorem residue_pair_six
    (hgc : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W c x = !bval W g x)
    (hEp : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E p) x = false)
    (q : Exp A T)
    (hEq : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E q) x = false) :
    EquivBA
      (.wh g (.seq (.seq (resA c p) (.wh g p)) q))
      (.wh g (.seq (.wh g (.seq (resA c p) (resC c p))) q)) :=
  wh_congr_under_guard (seq_under_guard q (guarded_core_gen hgc hEp))
    (E_seq_left (E_seq_left (E_resA hEp)))
    (E_seq_right hEq)

/-- **Pair #8.**  The one member whose two sides put `A` in different places: `f` has it under
    the loop guard, where `A ≡ p`, while `e` has it AFTER an inner loop, where `A ≡ p` for the
    opposite reason — the loop has exited, so `¬g` holds and `A`'s else arm is selected.  Both
    readings are needed, and `wh_exit` supplies the second. -/
theorem residue_pair_eight
    (hgc : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W c x = !bval W g x)
    (hEp : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E p) x = false)
    (Z : Exp A T) :
    EquivBA
      (.wh g (.seq p (.ite g (.seq p (.seq (.wh g p) (resA g p))) Z)))
      (.wh g (.seq p (.ite g (.seq (.wh g (.seq (resA c p) (resC c p))) p) Z))) := by
  have hcg : ∀ (Y : Type) (W : T → Y → Bool) (x : Y), bval W g x = !bval W c x := by
    intro Y W x; rw [hgc Y W x]; cases bval W g x <;> rfl
  have hA : EquivBA (.wh g p : Exp A T) (.seq (.wh g p) (.test c)) := wh_exit hgc hEp
  -- after the inner loop ¬g holds, so A's else arm is taken
  have step1 : EquivBA (.seq (.wh g p) (resA g p)) (.seq (.wh g p) p) :=
    EquivBA.trans (EquivBA.seq_c hA (EquivBA.base (Equiv.refl _)))
      (EquivBA.trans (seq_assoc _ _ _)
        (EquivBA.trans
          (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
            (test_seq_ite_else_gen hcg (.test .zero) p))
          (EquivBA.trans (EquivBA.symm (seq_assoc _ _ _))
            (EquivBA.seq_c (EquivBA.symm hA) (EquivBA.base (Equiv.refl _))))))
  have step12 : EquivBA (.seq p (.seq (.wh g p) (resA g p))) (.seq (.seq p (.wh g p)) p) :=
    EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl p)) step1)
      (EquivBA.symm (seq_assoc p (.wh g p) p))
  have core : EquivBA (.seq (.test g) (.seq (.seq p (.wh g p)) p))
      (.seq (.test g) (.seq (.wh g (.seq (resA c p) (resC c p))) p)) :=
    EquivBA.trans (seq_under_guard p (EquivBA.symm (guarded_resA_is_p hgc (.wh g p))))
      (seq_under_guard p (guarded_core_gen hgc hEp))
  exact EquivBA.wh_c (EquivBA.seq_c (EquivBA.base (Equiv.refl p))
    (ite_congr_under_guard
      (EquivBA.trans
        (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) step12) core)))

end Pairs

/-- Pair #6 exactly as the harness produced it: `p` an action and `q = A' ; C`, which is
    productive because its first factor is. -/
theorem residue_pair_six_act (b : BExp T) (a : A) :
    EquivBA
      (.wh (.not b) (.seq (.seq (resA b (.act a)) (.wh (.not b) (.act a)))
        (.seq (resA (.not b) (.act a)) (resC b (.act a)))))
      (.wh (.not b) (.seq (.wh (.not b) (.seq (resA b (.act a)) (resC b (.act a))))
        (.seq (resA (.not b) (.act a)) (resC b (.act a))))) :=
  residue_pair_six
    (fun _ W x => by
      show bval W b x = !(!bval W b x)
      cases bval W b x <;> rfl)
    (fun _ _ _ => rfl) _ (E_seq_left (E_resA (fun _ _ _ => rfl)))

/-- Pair #5 — #3 with the two atoms exchanged, so the loop guard is `b` and the branch guard
    is `¬b`.  Nothing but the instantiation changes. -/
theorem residue_pair_five_act (b : BExp T) (a : A) :
    EquivBA
      (.wh b (.seq (.act a)
        (.ite b (.seq (resA (.not b) (.act a)) (.wh b (.act a))) (.act a))))
      (.wh b (.seq (.act a)
        (.ite b (.wh b (.seq (resA (.not b) (.act a)) (resC (.not b) (.act a)))) (.act a)))) :=
  residue_pair_three_five (fun _ _ _ => rfl) (fun _ _ _ => rfl) _


/-! ## Pair #1, by solving the other side's equation

    #1 and #7 are not top-level loops: `e` is `C ; ((p;p) ; C)^(g)`, a loop with a factor in
    front of it, and no amount of body-congruence reaches that from `f = (p ; (p;p +_g c?))^(g)`.
    In Kleene algebra the identity relating them is loop rotation, `x(yx)* = (xy)*x`, which is
    not among W1–W3 and not among the refinement moves either.

    It is not needed.  W3 says a productive Salomaa equation has ONE solution, so it is enough
    to show that `e` — with its factor in front — satisfies the equation `f` satisfies.  Unrolling
    `e` once puts its leading `C` and the loop's first turn together, and what comes out is
    exactly `f`'s body applied to `e`.  W3 then identifies them.

    This is the uniqueness axiom's job being done by the single-unknown axiom that is already
    finite.  UA generalises W3 to systems of `n` unknowns; here one unknown suffices, because
    the two programs share a single equation rather than a system. -/

section PairOne

variable {g c : BExp T} {p : Exp A T}

/-- A choice on `g` nested in another `g`-choice's else arm is unreachable. -/
theorem ite_else_ite_same (Y X Z : Exp A T) :
    EquivBA (.ite g Y (.ite g X Z)) (.ite g Y Z) := by
  have hng : ∀ (Y' : Type) (W : T → Y' → Bool) (x : Y'),
      bval W g x = !bval W (.not g) x := by
    intro Y' W x
    show bval W g x = !(!bval W g x)
    cases bval W g x <;> rfl
  exact EquivBA.trans (ite_restrict_else g Y (.ite g X Z))
    (EquivBA.trans
      (EquivBA.ite_c (EquivBA.base (Equiv.refl Y)) (test_seq_ite_else_gen hng X Z))
      (EquivBA.symm (ite_restrict_else g Y Z)))

/-- **Pair #1 (and #7, its atom-exchange).**  `C ; ((p;p);C)^(g) ≡ (p ; ((p;p) +_g c?))^(g)`. -/
theorem residue_pair_one
    (hgc : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W c x = !bval W g x)
    (hEp : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W (E p) x = false) :
    EquivBA
      (.seq (resDg g p) (.wh g (.seq (.seq p p) (resDg g p))))
      (.wh g (.seq p (.ite g (.seq p p) (.test c)))) := by
  have hcg : ∀ (Y : Type) (W : T → Y → Bool) (x : Y), bval W g x = !bval W c x := by
    intro Y W x; rw [hgc Y W x]; cases bval W g x <;> rfl
  -- abbreviations, spelled out because the terms recur
  have hW : EquivBA (.wh g (.seq (.seq p p) (resDg g p)) : Exp A T)
      (.ite g (.seq (.seq (.seq p p) (resDg g p))
        (.wh g (.seq (.seq p p) (resDg g p)))) (.test .one)) :=
    EquivBA.base (Equiv.w1 g _)
  -- the else arm of both sides collapses: under c the loop exits and C is a skip
  have hElse : EquivBA
      (.seq (.test c) (.seq (resDg g p) (.wh g (.seq (.seq p p) (resDg g p)))))
      (.test c) := by
    refine EquivBA.trans (EquivBA.symm (seq_assoc _ _ _)) ?_
    refine EquivBA.trans
      (EquivBA.seq_c
        (EquivBA.trans (test_seq_ite_else_gen hcg p (.test .one)) (seq_one _))
        (EquivBA.base (Equiv.refl _))) ?_
    exact EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hW)
      (EquivBA.trans (test_seq_ite_else_gen hcg _ (.test .one)) (seq_one _))
  -- LHS: unroll the loop, push C through the choice, drop the unreachable nested arm
  have hL : EquivBA (.seq (resDg g p) (.wh g (.seq (.seq p p) (resDg g p))))
      (.ite g (.seq p (.ite g (.seq (.seq (.seq p p) (resDg g p))
        (.wh g (.seq (.seq p p) (resDg g p)))) (.test .one))) (.test .one)) := by
    refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hW) ?_
    refine EquivBA.trans (ite_seq_right g p (.test .one) _) ?_
    refine EquivBA.trans
      (EquivBA.ite_c (EquivBA.base (Equiv.refl _)) (EquivBA.base (Equiv.s4 _))) ?_
    exact ite_else_ite_same _ _ _
  -- RHS: f's body applied to e reduces to the very same thing
  have hR : EquivBA
      (.seq (.seq p (.ite g (.seq p p) (.test c)))
        (.seq (resDg g p) (.wh g (.seq (.seq p p) (resDg g p)))))
      (.seq p (.ite g (.seq (.seq (.seq p p) (resDg g p))
        (.wh g (.seq (.seq p p) (resDg g p)))) (.test .one))) := by
    refine EquivBA.trans (seq_assoc _ _ _) ?_
    refine EquivBA.seq_c (EquivBA.base (Equiv.refl p)) ?_
    refine EquivBA.trans (ite_seq_right g (.seq p p) (.test c) _) ?_
    refine EquivBA.trans
      (EquivBA.ite_c (EquivBA.symm (seq_assoc _ _ _)) hElse) ?_
    exact ite_else_test_gen _ hgc
  have hsol : EquivBA (.seq (resDg g p) (.wh g (.seq (.seq p p) (resDg g p))))
      (.ite g (.seq (.seq p (.ite g (.seq p p) (.test c)))
        (.seq (resDg g p) (.wh g (.seq (.seq p p) (resDg g p))))) (.test .one)) :=
    EquivBA.trans hL (EquivBA.ite_c (EquivBA.symm hR) (EquivBA.base (Equiv.refl _)))
  exact EquivBA.trans (EquivBA.w3_ba (EquivBA.baTest (E_seq_left hEp)) hsol) (seq_one _)

end PairOne

#print axioms ite_unsat
#print axioms ite_then_test_gen
#print axioms guarded_core_gen
#print axioms wh_congr_under_guard
#print axioms residue_pair_three_five
#print axioms residue_pair_six
#print axioms residue_pair_six_act
#print axioms wh_exit
#print axioms residue_pair_eight
#print axioms residue_pair_one
#print axioms residue_pair_five_act

end GkatResidueFamily
