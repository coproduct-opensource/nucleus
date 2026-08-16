import GkatLayeringProofs

/-!
# `CommonSyntacticCollapse` is false

`GkatCrystallizationProofs` reduces finite-axiom completeness to a *cospan*: any two
uniformly equivalent programs quotient onto the Thompson automaton of a third.  This file
refutes that reduction outright, by exhibiting a pair for which no third program exists.

The refutation has two halves.

**The structural half** (`no_selfloop_at_halting_entry`) is a five-case induction on the
Thompson constructors, and it is where the loop guard does its work.  No Thompson state can
be all three of: entered from the initial pseudostate at an atom `xf`, halting at `xf`, and
carrying a live self-loop.  `.act` has no outgoing transitions at all, so it cannot
self-loop; `.wh` guards its initial transitions by the loop guard while guarding its halt
by the *negation* of that guard, so the first two are already contradictory; `.ite` and
`.seq` merely pass the configuration down to a component.

**The arithmetic half** (`not_commonSyntacticCollapse`) forces that configuration.  Because
Thompson automata are deterministic, a quotient identifying the two starts is pinned: it
must send `δ_e w` and `δ_f w` to the same state for every trace `w`.  For the pair

    e = p ; while b do p        f = (if b then 1 else p) ; while b do p

that collapses all four action states onto one image `q₁` and both starts onto one image
`q₀`, so the quotient's whole image is `{q₀, q₁}`.  Surjectivity then forces the target
automaton to have exactly those two states — in particular its pseudostate is one of them —
and either choice contradicts the structural half.

Note what is *not* claimed.  `⊢ e = f` is derivable (`eProg_equivBA_fProg`, five steps from
W1 and the guarded-union axioms), which is what makes the pair a counterexample to the
reduction rather than to completeness: the cospan was sufficient, never necessary.  The
repair is `GkatCrystallization.CommonSyntacticRefinement`, which reverses the arrows.

Axioms: `[propext, Classical.choice, Quot.sound]`, `sorryAx`-free.
-/

namespace GkatCollapseRefutation

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatCrystallization

variable {A T : Type}

/-! ## Boolean-guard plumbing -/

private theorem bval_and_left {X : Type} {W : T → X → Bool} {b c : BExp T} {x : X}
    (h : bval W (BExp.and b c) x = true) : bval W b x = true := by
  change (bval W b x && bval W c x) = true at h
  cases hb : bval W b x with
  | true => rfl
  | false => rw [hb] at h; exact absurd h (by simp)

private theorem bval_and_right {X : Type} {W : T → X → Bool} {b c : BExp T} {x : X}
    (h : bval W (BExp.and b c) x = true) : bval W c x = true := by
  change (bval W b x && bval W c x) = true at h
  cases hc : bval W c x with
  | true => rfl
  | false => rw [hc] at h; cases bval W b x <;> exact absurd h (by simp)

private theorem sum_inl_ne_inr {α β : Type} {a : α} {b : β} :
    ¬ (Sum.inl a = Sum.inr b) := by simp

private theorem sum_inr_ne_inl {α β : Type} {a : α} {b : β} :
    ¬ (Sum.inr b = Sum.inl a) := by simp

private theorem bval_not_false {X : Type} {W : T → X → Bool} {b : BExp T} {x : X}
    (h : bval W (BExp.not b) x = true) : bval W b x = false := by
  change (!bval W b x) = true at h
  cases hb : bval W b x with
  | true => rw [hb] at h; exact absurd h (by simp)
  | false => rfl

/-! ## The structural half

    A Thompson state cannot combine a live self-loop with being entered, from the initial
    pseudostate, at an atom where it halts. -/

/-- **The loop guard forbids halting re-entry.**  For every program, no state `t` of its
    Thompson automaton is simultaneously

    * the target of an initial transition live at `xf`,
    * halting at `xf`, and
    * the target of one of its own transitions, live at `xt`.

    Induction on the constructors.  `.act` has no core transitions, so it cannot self-loop.
    `.wh` guards every initial transition by the loop guard and every halt by its negation,
    so its first two clauses already conflict.  `.ite` and `.seq` inherit. -/
theorem no_selfloop_at_halting_entry {X : Type} (W : T → X → Bool) (xt xf : X) :
    ∀ (program : Exp A T) (t : (certifiedThompson A T program).State),
      (∃ tr ∈ (certifiedThompson A T program).aut.initTrans,
        tr.2.2 = t ∧ bval W tr.1 xf = true) →
      bval W ((certifiedThompson A T program).aut.core.hlt t) xf = true →
      (∃ tr ∈ (certifiedThompson A T program).aut.core.trans t,
        tr.2.2 = t ∧ bval W tr.1 xt = true) →
      False := by
  intro program
  induction program with
  | test c => exact fun t _ _ _ => nomatch t
  | act a =>
      intro t _ _ hloop
      obtain ⟨tr, htr, _⟩ := hloop
      have hred : (certifiedThompson A T (.act a)).aut.core.trans t = [] := rfl
      rw [hred] at htr
      exact absurd htr (by simp)
  | ite g p q ihp ihq =>
      intro t hinit hhalt hloop
      have hinitRed : (certifiedThompson A T (.ite g p q)).aut.initTrans =
          ((certifiedThompson A T p).aut.initTrans.map (fun tr =>
            (BExp.and g tr.1, tr.2.1, Sum.inl tr.2.2))) ++
          ((certifiedThompson A T q).aut.initTrans.map (fun tr =>
            (BExp.and (BExp.not g) tr.1, tr.2.1, Sum.inr tr.2.2))) := rfl
      rw [hinitRed] at hinit
      obtain ⟨tr, htr, htgt, hval⟩ := hinit
      have htr2 := List.mem_append.mp htr
      cases t with
      | inl i =>
          rcases htr2 with hmem | hmem
          · obtain ⟨orig, horig, rfl⟩ := List.mem_map.mp hmem
            refine ihp i ⟨orig, horig, ?_, bval_and_right hval⟩ hhalt ?_
            · exact Sum.inl.inj htgt
            · obtain ⟨tr', htr', htgt', hval'⟩ := hloop
              have hred : (certifiedThompson A T (.ite g p q)).aut.core.trans (Sum.inl i) =
                  ((certifiedThompson A T p).aut.core.trans i).map (fun tr =>
                    (tr.1, tr.2.1, Sum.inl tr.2.2)) := rfl
              rw [hred] at htr'
              obtain ⟨orig', horig', rfl⟩ := List.mem_map.mp htr'
              exact ⟨orig', horig', Sum.inl.inj htgt', hval'⟩
          · obtain ⟨orig, _, rfl⟩ := List.mem_map.mp hmem
            exact sum_inr_ne_inl htgt
      | inr j =>
          rcases htr2 with hmem | hmem
          · obtain ⟨orig, _, rfl⟩ := List.mem_map.mp hmem
            exact sum_inl_ne_inr htgt
          · obtain ⟨orig, horig, rfl⟩ := List.mem_map.mp hmem
            refine ihq j ⟨orig, horig, ?_, bval_and_right hval⟩ hhalt ?_
            · exact Sum.inr.inj htgt
            · obtain ⟨tr', htr', htgt', hval'⟩ := hloop
              have hred : (certifiedThompson A T (.ite g p q)).aut.core.trans (Sum.inr j) =
                  ((certifiedThompson A T q).aut.core.trans j).map (fun tr =>
                    (tr.1, tr.2.1, Sum.inr tr.2.2)) := rfl
              rw [hred] at htr'
              obtain ⟨orig', horig', rfl⟩ := List.mem_map.mp htr'
              exact ⟨orig', horig', Sum.inr.inj htgt', hval'⟩
  | seq p q ihp ihq =>
      intro t hinit hhalt hloop
      have hinitRed : (certifiedThompson A T (.seq p q)).aut.initTrans =
          ((certifiedThompson A T p).aut.initTrans.map (fun tr =>
            (tr.1, tr.2.1, Sum.inl tr.2.2))) ++
          ((certifiedThompson A T q).aut.initTrans.map (fun tr =>
            (BExp.and (certifiedThompson A T p).aut.initHlt tr.1,
              tr.2.1, Sum.inr tr.2.2))) := rfl
      rw [hinitRed] at hinit
      obtain ⟨tr, htr, htgt, hval⟩ := hinit
      have htr2 := List.mem_append.mp htr
      cases t with
      | inl i =>
          rcases htr2 with hmem | hmem
          · obtain ⟨orig, horig, rfl⟩ := List.mem_map.mp hmem
            refine ihp i ⟨orig, horig, Sum.inl.inj htgt, hval⟩ ?_ ?_
            · have hred : (certifiedThompson A T (.seq p q)).aut.core.hlt (Sum.inl i) =
                  BExp.and ((certifiedThompson A T p).aut.core.hlt i)
                    (certifiedThompson A T q).aut.initHlt := rfl
              rw [hred] at hhalt
              exact bval_and_left hhalt
            · obtain ⟨tr', htr', htgt', hval'⟩ := hloop
              have hred : (certifiedThompson A T (.seq p q)).aut.core.trans (Sum.inl i) =
                  ((certifiedThompson A T p).aut.core.trans i).map (fun tr =>
                    (tr.1, tr.2.1, Sum.inl tr.2.2)) ++
                  ((certifiedThompson A T q).aut.initTrans.map (fun tr =>
                    (BExp.and ((certifiedThompson A T p).aut.core.hlt i) tr.1,
                      tr.2.1, Sum.inr tr.2.2))) := rfl
              rw [hred] at htr'
              rcases List.mem_append.mp htr' with hmem' | hmem'
              · obtain ⟨orig', horig', rfl⟩ := List.mem_map.mp hmem'
                exact ⟨orig', horig', Sum.inl.inj htgt', hval'⟩
              · obtain ⟨orig', _, rfl⟩ := List.mem_map.mp hmem'
                exact (sum_inr_ne_inl htgt').elim
          · obtain ⟨orig, _, rfl⟩ := List.mem_map.mp hmem
            exact sum_inr_ne_inl htgt
      | inr j =>
          rcases htr2 with hmem | hmem
          · obtain ⟨orig, _, rfl⟩ := List.mem_map.mp hmem
            exact sum_inl_ne_inr htgt
          · obtain ⟨orig, horig, rfl⟩ := List.mem_map.mp hmem
            refine ihq j ⟨orig, horig, Sum.inr.inj htgt, bval_and_right hval⟩ hhalt ?_
            obtain ⟨tr', htr', htgt', hval'⟩ := hloop
            have hred : (certifiedThompson A T (.seq p q)).aut.core.trans (Sum.inr j) =
                ((certifiedThompson A T q).aut.core.trans j).map (fun tr =>
                  (tr.1, tr.2.1, Sum.inr tr.2.2)) := rfl
            rw [hred] at htr'
            obtain ⟨orig', horig', rfl⟩ := List.mem_map.mp htr'
            exact ⟨orig', horig', Sum.inr.inj htgt', hval'⟩
  | wh g p _ =>
      intro t hinit hhalt _
      have hinitRed : (certifiedThompson A T (.wh g p)).aut.initTrans =
          (certifiedThompson A T p).aut.initTrans.map (fun tr =>
            (BExp.and g tr.1, tr.2)) := rfl
      rw [hinitRed] at hinit
      obtain ⟨tr, htr, _, hval⟩ := hinit
      obtain ⟨orig, _, rfl⟩ := List.mem_map.mp htr
      have hguard : bval W g xf = true := bval_and_left hval
      have hred : (certifiedThompson A T (.wh g p)).aut.core.hlt t =
          BExp.and ((certifiedThompson A T p).aut.core.hlt t) (BExp.not g) := rfl
      rw [hred] at hhalt
      have hnot : bval W g xf = false := bval_not_false (bval_and_right hhalt)
      rw [hguard] at hnot
      exact Bool.noConfusion hnot

/-! ## The pair

    One action and one test — the smallest setting the refutation lives in. -/

/-- The action alphabet: a single action `p`. -/
abbrev Act : Type := Unit
/-- The test alphabet: a single test `b`. -/
abbrev Tst : Type := Unit

/-- The primitive test `b`. -/
def bT : BExp Tst := .prim ()
/-- The primitive action `p`. -/
def pA : Exp Act Tst := .act ()
/-- `while b do p`. -/
def loopP : Exp Act Tst := .wh bT pA

/-- `e = p ; while b do p`. -/
def eProg : Exp Act Tst := .seq pA loopP

/-- `f = (if b then 1 else p) ; while b do p`. -/
def fProg : Exp Act Tst := .seq (.ite bT (.test .one) pA) loopP

/-- **The pair is provably equal**, in five steps: distribute the leading conditional over
    the sequence (U5), drop the unit prefix (S4), unroll the loop in the `b` branch (W1),
    collapse the nested `b`-conditional (which is where the guard does the work), and
    contract the now-identical branches (U1).

    This is what makes the pair a counterexample to the *reduction* rather than to
    completeness. -/
theorem fProg_equivBA_eProg : EquivBA fProg eProg :=
  EquivBA.trans
    (EquivBA.base (Equiv.symm (Equiv.u5 bT (.test .one) pA loopP)))
    (EquivBA.trans
      (EquivBA.ite_c (EquivBA.base (Equiv.s4 loopP)) (EquivBA.base (Equiv.refl _)))
      (EquivBA.trans
        (EquivBA.ite_c (EquivBA.base (Equiv.w1 bT pA)) (EquivBA.base (Equiv.refl _)))
        (EquivBA.trans
          (ite_under_implies_true (region := bT) (b := bT)
            (.seq pA loopP) (.test .one) (.seq pA loopP) (fun _ _ _ hx => hx))
          (EquivBA.base (Equiv.u1 bT eProg)))))

/-- Hence the two programs are uniformly language-equivalent, by soundness. -/
theorem eProg_uniform_equiv : UniformLanguageEquivalent eProg fProg := by
  intro X W gs
  exact sound_BA (V := W) (EquivBA.symm fProg_equivBA_eProg) gs

/-! ## Reading the two automata

    Both automata are small enough that every step and halt used below is a `rfl`.  The
    interpretation sends the single test to the atom itself, so `false` is the atom where
    `b` fails and `true` the atom where it holds. -/

/-- The interpretation: `b` holds exactly at the atom `true`. -/
def wB : Tst → Bool → Bool := fun _ x => x

theorem e_start_step (x : Bool) :
    autStep wB (certifiedThompson Act Tst eProg).aut.toGAut none x
      = some ((), some (Sum.inl ())) := rfl

theorem f_start_step_false :
    autStep wB (certifiedThompson Act Tst fProg).aut.toGAut none false
      = some ((), some (Sum.inl (Sum.inr ()))) := rfl

theorem f_start_step_true :
    autStep wB (certifiedThompson Act Tst fProg).aut.toGAut none true
      = some ((), some (Sum.inr ())) := rfl

theorem e_mid_step :
    autStep wB (certifiedThompson Act Tst eProg).aut.toGAut (some (Sum.inl ())) true
      = some ((), some (Sum.inr ())) := rfl

theorem f_mid_step :
    autStep wB (certifiedThompson Act Tst fProg).aut.toGAut
        (some (Sum.inl (Sum.inr ()))) true
      = some ((), some (Sum.inr ())) := rfl

theorem e_mid_halts :
    bval wB ((certifiedThompson Act Tst eProg).aut.toGAut.hlt (some (Sum.inl ()))) false
      = true := rfl

theorem e_start_not_halts :
    bval wB ((certifiedThompson Act Tst eProg).aut.toGAut.hlt none) false = false := rfl

/-! ## Transport along the quotient -/

private theorem push_inl {S₁ S₂ Q : Type} {aut₁ : GAut S₁ A T} {aut₂ : GAut S₂ A T}
    {quot : GAut Q A T} (π : UniformBehavioralGAutQuotient (sumGAut aut₁ aut₂) quot)
    {X : Type} (W : T → X → Bool) (s : S₁) (x : X) {a : A} {t : S₁}
    (hstep : autStep W aut₁ s x = some (a, t)) :
    autStep W quot (π.mapState (Sum.inl s)) x = some (a, π.mapState (Sum.inl t)) := by
  have hpush := π.autStep_eq W (Sum.inl s) x
  rw [autStep_sumGAut_inl, hstep] at hpush
  exact hpush.symm

private theorem push_inr {S₁ S₂ Q : Type} {aut₁ : GAut S₁ A T} {aut₂ : GAut S₂ A T}
    {quot : GAut Q A T} (π : UniformBehavioralGAutQuotient (sumGAut aut₁ aut₂) quot)
    {X : Type} (W : T → X → Bool) (s : S₂) (x : X) {a : A} {t : S₂}
    (hstep : autStep W aut₂ s x = some (a, t)) :
    autStep W quot (π.mapState (Sum.inr s)) x = some (a, π.mapState (Sum.inr t)) := by
  have hpush := π.autStep_eq W (Sum.inr s) x
  rw [autStep_sumGAut_inr, hstep] at hpush
  exact hpush.symm

private theorem step_target_eq {Q X : Type} {quot : GAut Q A T} {W : T → X → Bool}
    {q : Q} {x : X} {a a' : A} {t t' : Q}
    (h1 : autStep W quot q x = some (a, t))
    (h2 : autStep W quot q x = some (a', t')) : t = t' := by
  rw [h1] at h2
  exact congrArg Prod.snd (Option.some.inj h2)

/-! ## Reading a step of a Thompson automaton back as a transition -/

private theorem toGAut_step_some {S X : Type} (aut : InitializedGAut S A T)
    (W : T → X → Bool) (s : Option S) (x : X) {a : A} {t : Option S}
    (hstep : autStep W aut.toGAut s x = some (a, t)) : ∃ u, t = some u := by
  obtain ⟨g, hmem, _⟩ := firstMatch_some_mem W x (aut.toGAut.trans s) hstep
  cases s with
  | none =>
      obtain ⟨orig, _, heq⟩ := List.mem_map.mp hmem
      exact ⟨orig.2.2, (congrArg (fun z => z.2.2) heq).symm⟩
  | some v =>
      obtain ⟨orig, _, heq⟩ := List.mem_map.mp hmem
      exact ⟨orig.2.2, (congrArg (fun z => z.2.2) heq).symm⟩

private theorem toGAut_init_trans {S X : Type} (aut : InitializedGAut S A T)
    (W : T → X → Bool) (x : X) {a : A} {u : S}
    (hstep : autStep W aut.toGAut none x = some (a, some u)) :
    ∃ tr ∈ aut.initTrans, tr.2.2 = u ∧ bval W tr.1 x = true := by
  obtain ⟨g, hmem, hval⟩ := firstMatch_some_mem W x (aut.toGAut.trans none) hstep
  obtain ⟨orig, horig, heq⟩ := List.mem_map.mp hmem
  refine ⟨orig, horig, Option.some.inj (congrArg (fun z => z.2.2) heq), ?_⟩
  rw [(congrArg (fun z => z.1) heq : orig.1 = g)]
  exact hval

private theorem toGAut_core_trans {S X : Type} (aut : InitializedGAut S A T)
    (W : T → X → Bool) (x : X) {a : A} {u v : S}
    (hstep : autStep W aut.toGAut (some u) x = some (a, some v)) :
    ∃ tr ∈ aut.core.trans u, tr.2.2 = v ∧ bval W tr.1 x = true := by
  obtain ⟨g, hmem, hval⟩ := firstMatch_some_mem W x (aut.toGAut.trans (some u)) hstep
  obtain ⟨orig, horig, heq⟩ := List.mem_map.mp hmem
  refine ⟨orig, horig, Option.some.inj (congrArg (fun z => z.2.2) heq), ?_⟩
  rw [(congrArg (fun z => z.1) heq : orig.1 = g)]
  exact hval

/-! ## The refutation -/

/-- **`CommonSyntacticCollapse` is false.**

    Determinism pins the quotient: the two starts share an image `q₀`, and all four action
    states share an image `q₁`, so the quotient's entire image is `{q₀, q₁}`.  Surjectivity
    then puts the target's pseudostate in that pair.  If it is `q₁`, then `q₀` steps *into*
    the pseudostate, which no Thompson transition does.  If it is `q₀`, then `q₁ = some u`
    is entered from the pseudostate at the atom where `b` fails — where it also halts — and
    it carries a live self-loop, which `no_selfloop_at_halting_entry` forbids. -/
theorem not_commonSyntacticCollapse : ¬ CommonSyntacticCollapse Act Tst := by
  intro hcol
  obtain ⟨h, π, hstart⟩ := hcol eProg fProg eProg_uniform_equiv
  -- the two starts step together, at both atoms
  have hA : autStep wB (certifiedThompson Act Tst h).aut.toGAut
      (π.mapState (Sum.inl none)) false
      = some ((), π.mapState (Sum.inl (some (Sum.inl ())))) :=
    push_inl π wB none false (e_start_step false)
  have hA' : autStep wB (certifiedThompson Act Tst h).aut.toGAut
      (π.mapState (Sum.inl none)) true
      = some ((), π.mapState (Sum.inl (some (Sum.inl ())))) :=
    push_inl π wB none true (e_start_step true)
  have hB0 := push_inr π wB none false f_start_step_false
  have hC0 := push_inr π wB none true f_start_step_true
  rw [← hstart] at hB0 hC0
  -- so the `f`-side action states share the `e`-side image
  have hF1 : π.mapState (Sum.inr (some (Sum.inl (Sum.inr ()))))
      = π.mapState (Sum.inl (some (Sum.inl ()))) := step_target_eq hB0 hA
  have hF2 : π.mapState (Sum.inr (some (Sum.inr ())))
      = π.mapState (Sum.inl (some (Sum.inl ()))) := step_target_eq hC0 hA'
  -- the shared image carries a self-loop at the atom where `b` holds
  have hD := push_inr π wB (some (Sum.inl (Sum.inr ()))) true f_mid_step
  have hD2 : autStep wB (certifiedThompson Act Tst h).aut.toGAut
      (π.mapState (Sum.inl (some (Sum.inl ())))) true
      = some ((), π.mapState (Sum.inr (some (Sum.inr ())))) :=
    (congrArg (fun z => autStep wB (certifiedThompson Act Tst h).aut.toGAut z true)
      hF1).symm.trans hD
  have hloopStep : autStep wB (certifiedThompson Act Tst h).aut.toGAut
      (π.mapState (Sum.inl (some (Sum.inl ())))) true
      = some ((), π.mapState (Sum.inl (some (Sum.inl ())))) :=
    hD2.trans (congrArg (fun z => some ((), z)) hF2)
  -- and the `e`-side loop state lands there too
  have hE2 : π.mapState (Sum.inl (some (Sum.inr ())))
      = π.mapState (Sum.inl (some (Sum.inl ()))) :=
    step_target_eq (push_inl π wB (some (Sum.inl ())) true e_mid_step) hloopStep
  -- halting separates the two images
  have hh0 : bval wB ((certifiedThompson Act Tst h).aut.toGAut.hlt
      (π.mapState (Sum.inl none))) false = false :=
    (π.hlt_ba (Sum.inl none) Bool wB false).symm.trans e_start_not_halts
  have hh1 : bval wB ((certifiedThompson Act Tst h).aut.toGAut.hlt
      (π.mapState (Sum.inl (some (Sum.inl ()))))) false = true :=
    (π.hlt_ba (Sum.inl (some (Sum.inl ()))) Bool wB false).symm.trans e_mid_halts
  -- the image is exactly the two of them, so surjectivity places the pseudostate
  obtain ⟨s, _, hs⟩ := π.onto_states none (List.Mem.head _)
  have himg : π.mapState s = π.mapState (Sum.inl none) ∨
      π.mapState s = π.mapState (Sum.inl (some (Sum.inl ()))) := by
    cases s with
    | inl u =>
        cases u with
        | none => exact Or.inl rfl
        | some v =>
            cases v with
            | inl w => cases w; exact Or.inr rfl
            | inr w => cases w; exact Or.inr hE2
    | inr u =>
        cases u with
        | none => exact Or.inl hstart.symm
        | some v =>
            cases v with
            | inl w =>
                cases w with
                | inl z => exact nomatch z
                | inr z => cases z; exact Or.inr hF1
            | inr w => cases w; exact Or.inr hF2
  rcases himg with hcase | hcase
  · -- the pseudostate is `q₀`
    have hzero : π.mapState (Sum.inl none) = none := hcase.symm.trans hs
    obtain ⟨u, hu⟩ : ∃ u, π.mapState (Sum.inl (some (Sum.inl ()))) = some u := by
      cases hcv : π.mapState (Sum.inl (some (Sum.inl ()))) with
      | none =>
          exact absurd (hh0.symm.trans
            ((congrArg (fun z => bval wB
              ((certifiedThompson Act Tst h).aut.toGAut.hlt z) false)
              (hcv.trans hzero.symm)).symm.trans hh1)) (by simp)
      | some u => exact ⟨u, rfl⟩
    refine no_selfloop_at_halting_entry wB true false h u
      (toGAut_init_trans (a := ()) (certifiedThompson Act Tst h).aut wB false ?_) ?_
      (toGAut_core_trans (a := ()) (certifiedThompson Act Tst h).aut wB true ?_)
    · exact (congrArg (fun z => autStep wB (certifiedThompson Act Tst h).aut.toGAut z false)
        hzero).symm.trans (hA.trans (congrArg (fun z => some ((), z)) hu))
    · exact (congrArg (fun z => bval wB
        ((certifiedThompson Act Tst h).aut.toGAut.hlt z) false) hu).symm.trans hh1
    · exact (congrArg (fun z => autStep wB (certifiedThompson Act Tst h).aut.toGAut z true)
        hu).symm.trans (hloopStep.trans (congrArg (fun z => some ((), z)) hu))
  · -- the pseudostate is `q₁`: then `q₀` would step into it, which no Thompson step does
    have hone : π.mapState (Sum.inl (some (Sum.inl ()))) = none := hcase.symm.trans hs
    obtain ⟨v, hv⟩ := toGAut_step_some (a := ()) (certifiedThompson Act Tst h).aut wB
      (π.mapState (Sum.inl none)) false
      (hA.trans (congrArg (fun z => some ((), z)) hone))
    exact absurd hv (by simp)

#print axioms no_selfloop_at_halting_entry
#print axioms fProg_equivBA_eProg
#print axioms eProg_uniform_equiv
#print axioms not_commonSyntacticCollapse

/-- **What is and is not refuted.**  The pair is uniformly language-equivalent *and*
    provably equal from the finite axioms; what fails is only the collapse. -/
theorem collapse_refuted_completeness_untouched :
    UniformLanguageEquivalent eProg fProg ∧ EquivBA eProg fProg ∧
      ¬ CommonSyntacticCollapse Act Tst :=
  ⟨eProg_uniform_equiv, EquivBA.symm fProg_equivBA_eProg, not_commonSyntacticCollapse⟩

/-- The cospan reduction is therefore not merely unproven at this alphabet — it is
    *unusable*.  `completeness_of_common_syntactic_collapse` remains a theorem, and it
    remains vacuous: its hypothesis is false. -/
theorem collapse_route_is_vacuous :
    (CommonSyntacticCollapse Act Tst → FiniteAxiomsCompleteBA Act Tst) ∧
      ¬ CommonSyntacticCollapse Act Tst :=
  ⟨completeness_of_common_syntactic_collapse, not_commonSyntacticCollapse⟩

#print axioms collapse_refuted_completeness_untouched
#print axioms collapse_route_is_vacuous

end GkatCollapseRefutation
