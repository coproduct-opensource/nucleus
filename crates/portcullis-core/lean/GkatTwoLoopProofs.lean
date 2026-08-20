import GkatWalkedOrbitProofs
import GkatChainFragmentProofs

/-! # The two-loop fragment: genuinely nested cycles

    `wh b ((wh c q); r)` is the minimal genuinely nested program: its
    Thompson automaton has TWO interlocking cycles sharing states — the
    inner self-loop at the `wh c q` state and the outer 2-cycle through
    the `r` port.  The skip of the inner loop on re-entry lands on the
    port ITSELF, so the walked discipline holds; and with two core
    states every arm targets self-or-swap, trivializing the rank layer. -/

namespace GkatTwoLoop

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatSumQuotient
open GkatDecomp GkatPlanExistence GkatGuardedAlgebra GkatResidue
open GkatRingSupport GkatRingPlan GkatNormalization GkatTrim GkatCycle
open GkatLoopFree GkatAtomicLoop GkatChainLoop GkatOrbit
open GkatChainFragment GkatWalkedOrbit

variable {A T : Type}

/-- The two-loop body: an atomic inner loop, then one action. -/
def twoLoopBody (c : BExp T) (q r : A) : Exp A T :=
  .seq (.wh c (.act q)) (.act r)

/-- The two-loop program. -/
def twoLoop (b c : BExp T) (q r : A) : Exp A T :=
  .wh b (twoLoopBody c q r)

/-- Its loop automaton: `inl ()` is the inner state, `inr ()` the port. -/
def twoLoopAut (b c : BExp T) (q r : A) :
    InitializedGAut (Sum Unit Unit) A T :=
  loopInitialized b (certifiedThompson A T (twoLoopBody c q r)).aut

/-- The swap successor. -/
def twoNxt : Sum Unit Unit → Sum Unit Unit
  | .inl _ => .inr ()
  | .inr _ => .inl ()

/-- In a two-state space, every target is self or the swap. -/
theorem two_state_dec (s t : Sum Unit Unit) : t = s ∨ t = twoNxt s := by
  cases s with
  | inl u =>
      cases u
      cases t with
      | inl v => cases v; exact Or.inl rfl
      | inr v => cases v; exact Or.inr rfl
  | inr u =>
      cases u
      cases t with
      | inl v => cases v; exact Or.inr rfl
      | inr v => cases v; exact Or.inl rfl

/-- The swap has period two. -/
theorem twoNxt_period (s : Sum Unit Unit) :
    twoNxt (twoNxt s) = s := by
  cases s with
  | inl u => cases u; rfl
  | inr u => cases u; rfl

/-- The swap never fixes. -/
theorem twoNxt_nofix (s : Sum Unit Unit) : twoNxt s ≠ s := by
  cases s with
  | inl u => cases u; intro h; exact nomatch h
  | inr u => cases u; intro h; exact nomatch h

/-- **INTERIOR SILENCE**: the inner state never halts. -/
theorem twoLoop_hlt_inl (b c : BExp T) (q r : A) :
    ∀ α : T → Bool,
      bval (genW T) ((twoLoopAut b c q r).core.hlt (Sum.inl ())) α
        = false := by
  intro α
  show (((true && !(bval (genW T) c α)) && false)
    && !(bval (genW T) b α)) = false
  cases bval (genW T) c α <;> cases bval (genW T) b α <;> rfl

/-- **PORT EXIT**: the port halts exactly at `¬b`. -/
theorem twoLoop_hlt_inr (b c : BExp T) (q r : A) :
    ∀ α : T → Bool,
      bval (genW T) ((twoLoopAut b c q r).core.hlt (Sum.inr ())) α
        = !(bval (genW T) b α) := by
  intro α
  show (true && !(bval (genW T) b α)) = !(bval (genW T) b α)
  cases bval (genW T) b α <;> rfl

/-- **INNER SELF-STEP**: at a `c`-atom, the inner state loops. -/
theorem twoLoop_step_inl_self (b c : BExp T) (q r : A)
    (α : T → Bool) (hc : bval (genW T) c α = true) :
    firstMatch (genW T) α
        ((twoLoopAut b c q r).core.trans (Sum.inl ()))
      = some (q, Sum.inl ()) := by
  show (if (true && (bval (genW T) c α && true)) = true
    then some (q, Sum.inl ())
    else _) = some (q, Sum.inl ())
  rw [hc]
  rfl

/-- **INNER ADVANCE**: at a `¬c`-atom, the inner state advances to the
    port. -/
theorem twoLoop_step_inl_adv (b c : BExp T) (q r : A)
    (α : T → Bool) (hc : bval (genW T) c α = false) :
    firstMatch (genW T) α
        ((twoLoopAut b c q r).core.trans (Sum.inl ()))
      = some (r, Sum.inr ()) := by
  show (if (true && (bval (genW T) c α && true)) = true
    then some (q, Sum.inl ())
    else if ((true && !(bval (genW T) c α)) && true) = true
      then some (r, Sum.inr ())
      else _) = some (r, Sum.inr ())
  rw [hc]
  rfl

/-- **PORT FEEDBACK INTO THE INNER LOOP**: at a `b ∧ c`-atom. -/
theorem twoLoop_step_inr_feed (b c : BExp T) (q r : A)
    (α : T → Bool) (hb : bval (genW T) b α = true)
    (hc : bval (genW T) c α = true) :
    firstMatch (genW T) α
        ((twoLoopAut b c q r).core.trans (Sum.inr ()))
      = some (q, Sum.inl ()) := by
  show (if (true && (bval (genW T) b α
      && (bval (genW T) c α && true))) = true
    then some (q, Sum.inl ())
    else _) = some (q, Sum.inl ())
  rw [hb, hc]
  rfl

/-- **PORT SELF-STEP** (skipping the inner loop on re-entry): at a
    `b ∧ ¬c`-atom. -/
theorem twoLoop_step_inr_self (b c : BExp T) (q r : A)
    (α : T → Bool) (hb : bval (genW T) b α = true)
    (hc : bval (genW T) c α = false) :
    firstMatch (genW T) α
        ((twoLoopAut b c q r).core.trans (Sum.inr ()))
      = some (r, Sum.inr ()) := by
  show (if (true && (bval (genW T) b α
      && (bval (genW T) c α && true))) = true
    then some (q, Sum.inl ())
    else if (true && (bval (genW T) b α
        && (!(bval (genW T) c α) && true))) = true
      then some (r, Sum.inr ())
      else _) = some (r, Sum.inr ())
  rw [hb, hc]
  rfl

/-- **PORT REST**: at a `¬b`-atom the port takes no step. -/
theorem twoLoop_step_inr_none (b c : BExp T) (q r : A)
    (α : T → Bool) (hb : bval (genW T) b α = false) :
    firstMatch (genW T) α
        ((twoLoopAut b c q r).core.trans (Sum.inr ()))
      = none := by
  show (if (true && (bval (genW T) b α
      && (bval (genW T) c α && true))) = true
    then some (q, Sum.inl ())
    else if (true && (bval (genW T) b α
        && (!(bval (genW T) c α) && true))) = true
      then some (r, Sum.inr ())
      else none) = none
  rw [hb]
  cases bval (genW T) c α <;> rfl

#print axioms two_state_dec
#print axioms twoLoop_hlt_inl
#print axioms twoLoop_step_inl_adv
#print axioms twoLoop_step_inr_self

/-! ## Liveness and trim-level steps in the composite

    With `¬c` and `¬b` satisfiable, both states are live (inner advances
    at a `¬c`-atom, port exits at a `¬b`-atom); every arm target — being
    one of the two states — is live, so trimming is transparent and the
    concrete steps reach the trimmed sum. -/

open Classical in
/-- The port is live: exit at a `¬b`-atom. -/
theorem twoLoop_live_inr (b c : BExp T) (q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    Live (sumGAut (twoLoopAut b c q r).toGAut aut₂)
      (Sum.inl (some (Sum.inr ()))) := by
  obtain ⟨αb, hαb⟩ := hexitB
  refine ⟨αb, [], ?_⟩
  rw [autRun_sumGAut_inl,
    autRun_toGAut_some (start := Sum.inr ())]
  show bval (genW T)
    ((twoLoopAut b c q r).core.hlt (Sum.inr ())) αb = true
  rw [twoLoop_hlt_inr, hαb]
  rfl

open Classical in
/-- The inner state is live: advance at `¬c`, exit at `¬b`. -/
theorem twoLoop_live_inl (b c : BExp T) (q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    Live (sumGAut (twoLoopAut b c q r).toGAut aut₂)
      (Sum.inl (some (Sum.inl ()))) := by
  obtain ⟨αc, hαc⟩ := hexitC
  obtain ⟨αb, hαb⟩ := hexitB
  refine ⟨αc, [(r, αb)], ?_⟩
  rw [autRun_sumGAut_inl,
    autRun_toGAut_some (start := Sum.inr ())]
  refine ⟨Sum.inr (), ?_, ?_⟩
  · show firstMatch (genW T) αc
      ((twoLoopAut b c q r).core.trans (Sum.inl ()))
      = some (r, Sum.inr ())
    exact twoLoop_step_inl_adv b c q r αc hαc
  · show bval (genW T)
      ((twoLoopAut b c q r).core.hlt (Sum.inr ())) αb = true
    rw [twoLoop_hlt_inr, hαb]
    rfl

open Classical in
/-- Every state of the two-loop core is live (given the exits). -/
theorem twoLoop_live_all (b c : BExp T) (q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (s : Sum Unit Unit) :
    Live (sumGAut (twoLoopAut b c q r).toGAut aut₂)
      (Sum.inl (some s)) := by
  cases s with
  | inl u =>
      cases u
      exact twoLoop_live_inl b c q r aut₂ hexitC hexitB
  | inr u =>
      cases u
      exact twoLoop_live_inr b c q r aut₂ hexitB

open Classical in
/-- All composite arms at a two-loop core state have live targets. -/
theorem twoLoop_targets_live (b c : BExp T) (q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (s : Sum Unit Unit) :
    ∀ e ∈ (sumGAut (twoLoopAut b c q r).toGAut aut₂).trans
        (Sum.inl (some s)),
      Live (sumGAut (twoLoopAut b c q r).toGAut aut₂) e.2.2 := by
  intro e he
  obtain ⟨t₁, ht₁, heq₁⟩ := List.mem_map.mp he
  obtain ⟨t₀, ht₀, heq₀⟩ := List.mem_map.mp ht₁
  rw [← heq₁, ← heq₀]
  show Live _ (Sum.inl (some t₀.2.2))
  exact twoLoop_live_all b c q r aut₂ hexitC hexitB t₀.2.2

open Classical in
/-- Trim-level step at the inner state, `c`-atom: self. -/
theorem twoLoop_trim_step_inl_self (b c : BExp T) (q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hc : bval (genW T) c α = true) :
    autStep (genW T)
        (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
        (Sum.inl (some (Sum.inl ()))) α
      = some (q, Sum.inl (some (Sum.inl ()))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (twoLoop_targets_live b c q r aut₂ hexitC hexitB (Sum.inl ())) α]
  rw [autStep_sumGAut_inl, autStep_toGAut_some]
  rw [twoLoop_step_inl_self b c q r α hc]
  rfl

open Classical in
/-- Trim-level step at the inner state, `¬c`-atom: advance to the
    port. -/
theorem twoLoop_trim_step_inl_adv (b c : BExp T) (q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hc : bval (genW T) c α = false) :
    autStep (genW T)
        (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
        (Sum.inl (some (Sum.inl ()))) α
      = some (r, Sum.inl (some (Sum.inr ()))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (twoLoop_targets_live b c q r aut₂ hexitC hexitB (Sum.inl ())) α]
  rw [autStep_sumGAut_inl, autStep_toGAut_some]
  rw [twoLoop_step_inl_adv b c q r α hc]
  rfl

open Classical in
/-- Trim-level step at the port, `b ∧ c`-atom: feed the inner loop. -/
theorem twoLoop_trim_step_inr_feed (b c : BExp T) (q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hb : bval (genW T) b α = true)
    (hc : bval (genW T) c α = true) :
    autStep (genW T)
        (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
        (Sum.inl (some (Sum.inr ()))) α
      = some (q, Sum.inl (some (Sum.inl ()))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (twoLoop_targets_live b c q r aut₂ hexitC hexitB (Sum.inr ())) α]
  rw [autStep_sumGAut_inl, autStep_toGAut_some]
  rw [twoLoop_step_inr_feed b c q r α hb hc]
  rfl

open Classical in
/-- Trim-level step at the port, `b ∧ ¬c`-atom: the skip lands on the
    port itself. -/
theorem twoLoop_trim_step_inr_self (b c : BExp T) (q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hb : bval (genW T) b α = true)
    (hc : bval (genW T) c α = false) :
    autStep (genW T)
        (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
        (Sum.inl (some (Sum.inr ()))) α
      = some (r, Sum.inl (some (Sum.inr ()))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (twoLoop_targets_live b c q r aut₂ hexitC hexitB (Sum.inr ())) α]
  rw [autStep_sumGAut_inl, autStep_toGAut_some]
  rw [twoLoop_step_inr_self b c q r α hb hc]
  rfl

#print axioms twoLoop_live_all
#print axioms twoLoop_trim_step_inl_adv
#print axioms twoLoop_trim_step_inr_feed

/-! ## The orbit bundle facts

    The port-based 2-orbit: parity of the swap walk, period two,
    non-fixedness, the ε-word separation of the two classes (hence
    non-degeneracy and a genuine 2-class quotient period), interior
    silence, and descent-freeness via rank zero. -/

theorem twoNxt_iter (s : Sum Unit Unit) :
    ∀ j, nxtIter twoNxt j s = if j % 2 = 0 then s else twoNxt s := by
  intro j
  induction j with
  | zero => rfl
  | succ j ih =>
      show twoNxt (nxtIter twoNxt j s) = _
      rw [ih]
      rcases Nat.mod_two_eq_zero_or_one j with h | h
      · rw [if_pos h, if_neg (by omega)]
      · rw [if_neg (by rw [h]; omega), twoNxt_period,
          if_pos (by omega)]

open Classical in
/-- The two classes are ε-separated: the port accepts the empty word at
    a `¬b`-atom, the inner state never does. -/
theorem twoLoop_lang_ne (b c : BExp T) (q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    autLang (genW T)
        (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
        (Sum.inl (some (Sum.inl ())))
      ≠ autLang (genW T)
          (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
          (Sum.inl (some (Sum.inr ()))) := by
  obtain ⟨αb, hαb⟩ := hexitB
  intro h
  have hiff := iff_of_eq (congrFun h (αb, []))
  have hport : autRun (genW T)
      (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
      (Sum.inl (some (Sum.inr ()))) αb [] := by
    show bval (genW T)
      ((twoLoopAut b c q r).core.hlt (Sum.inr ())) αb = true
    rw [twoLoop_hlt_inr, hαb]
    rfl
  have hinner := hiff.mpr hport
  have hinner' : bval (genW T)
      ((twoLoopAut b c q r).core.hlt (Sum.inl ())) αb = true := hinner
  rw [twoLoop_hlt_inl] at hinner'
  exact nomatch hinner'

open Classical in
/-- Interior silence at the trimmed composite. -/
theorem twoLoop_noeps_inl (b c : BExp T) (q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T) :
    ∀ α : T → Bool,
      ¬ autRun (genW T)
          (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
          (Sum.inl (some (Sum.inl ()))) α [] := by
  intro α h
  have h' : bval (genW T)
      ((twoLoopAut b c q r).core.hlt (Sum.inl ())) α = true := h
  rw [twoLoop_hlt_inl] at h'
  exact nomatch h'

open Classical in
/-- The lifted successor on the left summand. -/
def twoNxtL {S₂ : Type} (g₂ : S₂ → S₂) :
    Sum (Option (Sum Unit Unit)) (Option S₂)
      → Sum (Option (Sum Unit Unit)) (Option S₂) :=
  Sum.elim (fun o => Sum.inl (o.map twoNxt))
    (fun o => Sum.inr (o.map g₂))

open Classical in
/-- Period two at the lifted port. -/
theorem twoLoop_hper {S₂ : Type} (g₂ : S₂ → S₂) :
    nxtIter (twoNxtL (S₂ := S₂) g₂) 2
        (Sum.inl (some (Sum.inr ())))
      = Sum.inl (some (Sum.inr ())) := by
  unfold twoNxtL
  rw [nxtIter_lift_inl]
  rw [twoNxt_iter]
  rfl

open Classical in
/-- No fixed points below the period. -/
theorem twoLoop_hnofix {S₂ : Type} (g₂ : S₂ → S₂) :
    ∀ j, j < 2 →
      twoNxtL (S₂ := S₂) g₂
          (nxtIter (twoNxtL (S₂ := S₂) g₂) j
            (Sum.inl (some (Sum.inr ()))))
        ≠ nxtIter (twoNxtL (S₂ := S₂) g₂) j
            (Sum.inl (some (Sum.inr ()))) := by
  intro j hj hcontra
  unfold twoNxtL at hcontra
  rw [nxtIter_lift_inl] at hcontra
  have h1 : twoNxt (nxtIter twoNxt j (Sum.inr ()))
      = nxtIter twoNxt j (Sum.inr ()) :=
    Option.some.inj (Sum.inl.inj hcontra)
  exact twoNxt_nofix _ h1

open Classical in
/-- **NON-DEGENERACY**: adjacent orbit languages differ — the walk
    alternates between the ε-separated classes. -/
theorem twoLoop_hnontriv (b c : BExp T) (q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T) (g₂ : S₂ → S₂)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    ∀ j : Nat,
      autLang (genW T)
          (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
          (nxtIter (twoNxtL (S₂ := S₂) g₂) (j + 1)
            (Sum.inl (some (Sum.inr ()))))
        ≠ autLang (genW T)
            (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
            (nxtIter (twoNxtL (S₂ := S₂) g₂) j
              (Sum.inl (some (Sum.inr ())))) := by
  intro j
  unfold twoNxtL
  rw [nxtIter_lift_inl, nxtIter_lift_inl, twoNxt_iter, twoNxt_iter]
  rcases Nat.mod_two_eq_zero_or_one j with h | h
  · rw [if_pos h, if_neg (by omega)]
    exact twoLoop_lang_ne b c q r aut₂ hexitB
  · rw [if_pos (by omega), if_neg (by omega)]
    exact (twoLoop_lang_ne b c q r aut₂ hexitB).symm

#print axioms twoNxt_iter
#print axioms twoLoop_lang_ne
#print axioms twoLoop_hnontriv

end GkatTwoLoop
