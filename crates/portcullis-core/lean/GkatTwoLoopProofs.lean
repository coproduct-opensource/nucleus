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

/-! ## Quotient period, descent-freeness, membership, and the init–port
    identification -/

open Classical in
/-- The rank on the composite: 1 at the two init pseudostates, 0 at all
    core states. -/
def twoRank {S₂ : Type} :
    Sum (Option (Sum Unit Unit)) (Option S₂) → Nat :=
  Sum.elim (fun o => if o.isSome then 0 else 1)
    (fun o => if o.isSome then 0 else 1)

open Classical in
/-- Core-class minimal ranks vanish. -/
theorem twoLoop_minRank_zero (b c : BExp T) (q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (x : Sum Unit Unit) :
    minRank (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
        (twoRank (S₂ := S₂))
        (bisimRep (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
          (Sum.inl (some x))) = 0 := by
  have h1 : autLang (genW T)
      (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
      (Sum.inl (some x))
      = autLang (genW T)
        (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
        (bisimRep (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
          (Sum.inl (some x))) :=
    (rep_lang (sumGAut (twoLoopAut b c q r).toGAut aut₂)
      (Sum.inl (some x))).symm
  have h2 := minRank_le
    (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
    (twoRank (S₂ := S₂)) h1
  have h3 : twoRank (S₂ := S₂) (Sum.inl (some x)) = 0 := rfl
  omega

open Classical in
/-- **DESCENT-FREENESS IS FREE**: no cleaned arm descends below rank
    zero. -/
theorem twoLoop_hnodesc (b c : BExp T) (q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T) (x : Sum Unit Unit) :
    ∀ e ∈ (cleanAut (bisimQuotAut
        (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂)))).trans
        (bisimRep (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
          (Sum.inl (some x))),
      ¬ minRank (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
          (twoRank (S₂ := S₂)) e.2.2
        < minRank (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
            (twoRank (S₂ := S₂))
            (bisimRep (trimAut
              (sumGAut (twoLoopAut b c q r).toGAut aut₂))
              (Sum.inl (some x))) := by
  intro e _ hcontra
  rw [twoLoop_minRank_zero] at hcontra
  exact Nat.not_lt_zero _ hcontra

open Classical in
/-- Core classes are quotient states. -/
theorem twoLoop_hstates (b c : BExp T) (q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T) (x : Sum Unit Unit) :
    bisimRep (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
        (Sum.inl (some x))
      ∈ (bisimQuotAut
          (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))).states := by
  refine List.mem_map.mpr ⟨Sum.inl (some x), ?_, rfl⟩
  refine List.mem_append.mpr (Or.inl (List.mem_map.mpr
    ⟨some x, ?_, rfl⟩))
  refine List.mem_cons.mpr (Or.inr (List.mem_map.mpr ⟨x, ?_, rfl⟩))
  show x ∈ (certifiedThompson A T (twoLoopBody c q r)).aut.core.states
  cases x with
  | inl u =>
      cases u
      exact List.mem_cons_self ..
  | inr u =>
      cases u
      exact List.mem_cons_of_mem _ (List.mem_cons_self ..)

open Classical in
/-- **QUOTIENT PERIOD TWO**: the two ε-separated classes make a genuine
    2-cycle. -/
theorem twoLoop_qperiod2 (b c : BExp T) (q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T) (g₂ : S₂ → S₂)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    2 ≤ qPeriod (sumGAut (twoLoopAut b c q r).toGAut aut₂)
        (twoNxtL (S₂ := S₂) g₂)
        (Sum.inl (some (Sum.inr ()))) 2 := by
  obtain ⟨h1, h2, h3, h4⟩ := qPeriod_spec
    (sumGAut (twoLoopAut b c q r).toGAut aut₂)
    (twoNxtL (S₂ := S₂) g₂)
    (Sum.inl (some (Sum.inr ()))) 2 (by omega)
    (twoLoop_hper (S₂ := S₂) g₂)
  generalize hqgen : qPeriod (sumGAut (twoLoopAut b c q r).toGAut aut₂)
      (twoNxtL (S₂ := S₂) g₂)
      (Sum.inl (some (Sum.inr ()))) 2 = qp at h1 h2 h3 h4 ⊢
  rcases Nat.lt_or_ge qp 2 with hlt | hge
  · exfalso
    have hqp1 : qp = 1 := by omega
    rw [hqp1] at h1
    have hn : nxtIter (twoNxtL (S₂ := S₂) g₂) 1
        (Sum.inl (some (Sum.inr ())))
        = Sum.inl (some (Sum.inl ())) := by
      show twoNxtL (S₂ := S₂) g₂ (Sum.inl (some (Sum.inr ()))) = _
      rfl
    rw [hn] at h1
    have hL : autLang (genW T)
        (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
        (Sum.inl (some (Sum.inl ())))
        = autLang (genW T)
          (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
          (Sum.inl (some (Sum.inr ()))) := by
      rw [← rep_lang (sumGAut (twoLoopAut b c q r).toGAut aut₂)
        (Sum.inl (some (Sum.inl ()))), h1,
        rep_lang (sumGAut (twoLoopAut b c q r).toGAut aut₂)]
    exact twoLoop_lang_ne b c q r aut₂ hexitB hL
  · exact hge

open Classical in
/-- Init step at a `b ∧ c`-atom: enter the inner loop. -/
theorem twoLoop_step_init_feed (b c : BExp T) (q r : A)
    (α : T → Bool) (hb : bval (genW T) b α = true)
    (hc : bval (genW T) c α = true) :
    firstMatch (genW T) α ((twoLoopAut b c q r).initTrans)
      = some (q, Sum.inl ()) := by
  show (if (bval (genW T) b α
      && (bval (genW T) c α && true)) = true
    then some (q, Sum.inl ())
    else _) = some (q, Sum.inl ())
  rw [hb, hc]
  rfl

open Classical in
/-- Init step at a `b ∧ ¬c`-atom: skip straight to the port. -/
theorem twoLoop_step_init_skip (b c : BExp T) (q r : A)
    (α : T → Bool) (hb : bval (genW T) b α = true)
    (hc : bval (genW T) c α = false) :
    firstMatch (genW T) α ((twoLoopAut b c q r).initTrans)
      = some (r, Sum.inr ()) := by
  show (if (bval (genW T) b α
      && (bval (genW T) c α && true)) = true
    then some (q, Sum.inl ())
    else if (bval (genW T) b α
        && (!(bval (genW T) c α) && true)) = true
      then some (r, Sum.inr ())
      else _) = some (r, Sum.inr ())
  rw [hb, hc]
  rfl

open Classical in
/-- Init rest at a `¬b`-atom. -/
theorem twoLoop_step_init_none (b c : BExp T) (q r : A)
    (α : T → Bool) (hb : bval (genW T) b α = false) :
    firstMatch (genW T) α ((twoLoopAut b c q r).initTrans)
      = none := by
  show (if (bval (genW T) b α
      && (bval (genW T) c α && true)) = true
    then some (q, Sum.inl ())
    else if (bval (genW T) b α
        && (!(bval (genW T) c α) && true)) = true
      then some (r, Sum.inr ())
      else none) = none
  rw [hb]
  cases bval (genW T) c α <;> rfl

#print axioms twoLoop_hnodesc
#print axioms twoLoop_hstates
#print axioms twoLoop_qperiod2

/-! ## Init–port identification and the cover -/

open Classical in
/-- All composite arms at the init pseudostate have live targets. -/
theorem twoLoop_targets_live_none (b c : BExp T) (q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    ∀ e ∈ (sumGAut (twoLoopAut b c q r).toGAut aut₂).trans
        (Sum.inl (none : Option (Sum Unit Unit))),
      Live (sumGAut (twoLoopAut b c q r).toGAut aut₂) e.2.2 := by
  intro e he
  obtain ⟨t₁, ht₁, heq₁⟩ := List.mem_map.mp he
  obtain ⟨t₀, ht₀, heq₀⟩ := List.mem_map.mp ht₁
  rw [← heq₁, ← heq₀]
  show Live _ (Sum.inl (some t₀.2.2))
  exact twoLoop_live_all b c q r aut₂ hexitC hexitB t₀.2.2

open Classical in
/-- **THE INIT–PORT IDENTIFICATION**: the initial pseudostate and the
    port have the same language in the trimmed composite. -/
theorem twoLoop_none_lang (b c : BExp T) (q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    autLang (genW T)
        (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
        (Sum.inl (none : Option (Sum Unit Unit)))
      = autLang (genW T)
          (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
          (Sum.inl (some (Sum.inr ()))) := by
  apply lang_eq_of_step_hlt
  · intro α
    rw [autStep_trimAut_all_live (genW T) _ _
      (twoLoop_targets_live_none b c q r aut₂ hexitC hexitB) α]
    rw [autStep_trimAut_all_live (genW T) _ _
      (twoLoop_targets_live b c q r aut₂ hexitC hexitB
        (Sum.inr ())) α]
    rw [autStep_sumGAut_inl, autStep_sumGAut_inl]
    rw [autStep_toGAut_none, autStep_toGAut_some]
    cases hb : bval (genW T) b α with
    | false =>
        rw [twoLoop_step_init_none b c q r α hb,
          twoLoop_step_inr_none b c q r α hb]
    | true =>
        cases hc : bval (genW T) c α with
        | true =>
            rw [twoLoop_step_init_feed b c q r α hb hc,
              twoLoop_step_inr_feed b c q r α hb hc]
        | false =>
            rw [twoLoop_step_init_skip b c q r α hb hc,
              twoLoop_step_inr_self b c q r α hb hc]
  · intro α
    show (!(bval (genW T) b α))
      = bval (genW T)
          ((twoLoopAut b c q r).core.hlt (Sum.inr ())) α
    rw [twoLoop_hlt_inr]

open Classical in
/-- **THE COVER** (left summand): every left class is on the port
    orbit. -/
theorem twoLoop_cover_inl (b c : BExp T) (q r : A)
    {S₂ : Type} (aut₂ : GAut (Option S₂) A T) (g₂ : S₂ → S₂)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (o : Option (Sum Unit Unit)) :
    InOrbit (sumGAut (twoLoopAut b c q r).toGAut aut₂)
      (twoNxtL (S₂ := S₂) g₂)
      (Sum.inl (some (Sum.inr ())))
      (bisimRep (trimAut (sumGAut (twoLoopAut b c q r).toGAut aut₂))
        (Sum.inl o)) := by
  cases o with
  | none =>
      refine ⟨0, ?_⟩
      exact (rep_lang_congr _
        (twoLoop_none_lang b c q r aut₂ hexitC hexitB)).symm.symm
  | some x =>
      cases x with
      | inr u =>
          cases u
          exact ⟨0, rfl⟩
      | inl u =>
          cases u
          refine ⟨1, ?_⟩
          have h1 : nxtIter (twoNxtL (S₂ := S₂) g₂) 1
              (Sum.inl (some (Sum.inr ())))
              = Sum.inl (some (Sum.inl ())) := rfl
          rw [h1]

#print axioms twoLoop_none_lang
#print axioms twoLoop_cover_inl

/-! ## Right-summand mirrors -/

open Classical in
theorem twoLoop_live_all_r (b c : BExp T) (q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (s : Sum Unit Unit) :
    Live (sumGAut aut₁ (twoLoopAut b c q r).toGAut)
      (Sum.inr (some s)) := by
  cases s with
  | inl u =>
      cases u
      obtain ⟨αc, hαc⟩ := hexitC
      obtain ⟨αb, hαb⟩ := hexitB
      refine ⟨αc, [(r, αb)], ?_⟩
      rw [autRun_sumGAut_inr,
        autRun_toGAut_some (start := Sum.inr ())]
      refine ⟨Sum.inr (), ?_, ?_⟩
      · exact twoLoop_step_inl_adv b c q r αc hαc
      · show bval (genW T)
          ((twoLoopAut b c q r).core.hlt (Sum.inr ())) αb = true
        rw [twoLoop_hlt_inr, hαb]
        rfl
  | inr u =>
      cases u
      obtain ⟨αb, hαb⟩ := hexitB
      refine ⟨αb, [], ?_⟩
      rw [autRun_sumGAut_inr,
        autRun_toGAut_some (start := Sum.inr ())]
      show bval (genW T)
        ((twoLoopAut b c q r).core.hlt (Sum.inr ())) αb = true
      rw [twoLoop_hlt_inr, hαb]
      rfl

open Classical in
theorem twoLoop_targets_live_r (b c : BExp T) (q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (s : Sum Unit Unit) :
    ∀ e ∈ (sumGAut aut₁ (twoLoopAut b c q r).toGAut).trans
        (Sum.inr (some s)),
      Live (sumGAut aut₁ (twoLoopAut b c q r).toGAut) e.2.2 := by
  intro e he
  obtain ⟨t₁, ht₁, heq₁⟩ := List.mem_map.mp he
  obtain ⟨t₀, ht₀, heq₀⟩ := List.mem_map.mp ht₁
  rw [← heq₁, ← heq₀]
  show Live _ (Sum.inr (some t₀.2.2))
  exact twoLoop_live_all_r b c q r aut₁ hexitC hexitB t₀.2.2

open Classical in
theorem twoLoop_targets_live_none_r (b c : BExp T) (q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    ∀ e ∈ (sumGAut aut₁ (twoLoopAut b c q r).toGAut).trans
        (Sum.inr (none : Option (Sum Unit Unit))),
      Live (sumGAut aut₁ (twoLoopAut b c q r).toGAut) e.2.2 := by
  intro e he
  obtain ⟨t₁, ht₁, heq₁⟩ := List.mem_map.mp he
  obtain ⟨t₀, ht₀, heq₀⟩ := List.mem_map.mp ht₁
  rw [← heq₁, ← heq₀]
  show Live _ (Sum.inr (some t₀.2.2))
  exact twoLoop_live_all_r b c q r aut₁ hexitC hexitB t₀.2.2

open Classical in
theorem twoLoop_trim_step_inl_self_r (b c : BExp T) (q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hc : bval (genW T) c α = true) :
    autStep (genW T)
        (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
        (Sum.inr (some (Sum.inl ()))) α
      = some (q, Sum.inr (some (Sum.inl ()))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (twoLoop_targets_live_r b c q r aut₁ hexitC hexitB
      (Sum.inl ())) α]
  rw [autStep_sumGAut_inr, autStep_toGAut_some]
  rw [twoLoop_step_inl_self b c q r α hc]
  rfl

open Classical in
theorem twoLoop_trim_step_inl_adv_r (b c : BExp T) (q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hc : bval (genW T) c α = false) :
    autStep (genW T)
        (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
        (Sum.inr (some (Sum.inl ()))) α
      = some (r, Sum.inr (some (Sum.inr ()))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (twoLoop_targets_live_r b c q r aut₁ hexitC hexitB
      (Sum.inl ())) α]
  rw [autStep_sumGAut_inr, autStep_toGAut_some]
  rw [twoLoop_step_inl_adv b c q r α hc]
  rfl

open Classical in
theorem twoLoop_trim_step_inr_feed_r (b c : BExp T) (q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (α : T → Bool) (hb : bval (genW T) b α = true)
    (hc : bval (genW T) c α = true) :
    autStep (genW T)
        (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
        (Sum.inr (some (Sum.inr ()))) α
      = some (q, Sum.inr (some (Sum.inl ()))) := by
  rw [autStep_trimAut_all_live (genW T) _ _
    (twoLoop_targets_live_r b c q r aut₁ hexitC hexitB
      (Sum.inr ())) α]
  rw [autStep_sumGAut_inr, autStep_toGAut_some]
  rw [twoLoop_step_inr_feed b c q r α hb hc]
  rfl

open Classical in
theorem twoLoop_none_lang_r (b c : BExp T) (q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    autLang (genW T)
        (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
        (Sum.inr (none : Option (Sum Unit Unit)))
      = autLang (genW T)
          (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
          (Sum.inr (some (Sum.inr ()))) := by
  apply lang_eq_of_step_hlt
  · intro α
    rw [autStep_trimAut_all_live (genW T) _ _
      (twoLoop_targets_live_none_r b c q r aut₁ hexitC hexitB) α]
    rw [autStep_trimAut_all_live (genW T) _ _
      (twoLoop_targets_live_r b c q r aut₁ hexitC hexitB
        (Sum.inr ())) α]
    rw [autStep_sumGAut_inr, autStep_sumGAut_inr]
    rw [autStep_toGAut_none, autStep_toGAut_some]
    cases hb : bval (genW T) b α with
    | false =>
        rw [twoLoop_step_init_none b c q r α hb,
          twoLoop_step_inr_none b c q r α hb]
    | true =>
        cases hc : bval (genW T) c α with
        | true =>
            rw [twoLoop_step_init_feed b c q r α hb hc,
              twoLoop_step_inr_feed b c q r α hb hc]
        | false =>
            rw [twoLoop_step_init_skip b c q r α hb hc,
              twoLoop_step_inr_self b c q r α hb hc]
  · intro α
    show (!(bval (genW T) b α))
      = bval (genW T)
          ((twoLoopAut b c q r).core.hlt (Sum.inr ())) α
    rw [twoLoop_hlt_inr]

open Classical in
/-- The right-summand successor lift. -/
def twoNxtR {S₁ : Type} (g₁ : S₁ → S₁) :
    Sum (Option S₁) (Option (Sum Unit Unit))
      → Sum (Option S₁) (Option (Sum Unit Unit)) :=
  Sum.elim (fun o => Sum.inl (o.map g₁))
    (fun o => Sum.inr (o.map twoNxt))

open Classical in
theorem twoLoop_cover_inr (b c : BExp T) (q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T) (g₁ : S₁ → S₁)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (o : Option (Sum Unit Unit)) :
    InOrbit (sumGAut aut₁ (twoLoopAut b c q r).toGAut)
      (twoNxtR (S₁ := S₁) g₁)
      (Sum.inr (some (Sum.inr ())))
      (bisimRep (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
        (Sum.inr o)) := by
  cases o with
  | none =>
      refine ⟨0, ?_⟩
      exact (rep_lang_congr _
        (twoLoop_none_lang_r b c q r aut₁ hexitC hexitB)).symm.symm
  | some x =>
      cases x with
      | inr u =>
          cases u
          exact ⟨0, rfl⟩
      | inl u =>
          cases u
          refine ⟨1, ?_⟩
          have h1 : nxtIter (twoNxtR (S₁ := S₁) g₁) 1
              (Sum.inr (some (Sum.inr ())))
              = Sum.inr (some (Sum.inl ())) := rfl
          rw [h1]

#print axioms twoLoop_none_lang_r
#print axioms twoLoop_cover_inr

/-! ## Right-summand orbit bundle -/

open Classical in
theorem twoLoop_hper_r {S₁ : Type} (g₁ : S₁ → S₁) :
    nxtIter (twoNxtR (S₁ := S₁) g₁) 2
        (Sum.inr (some (Sum.inr ())))
      = Sum.inr (some (Sum.inr ())) := by
  unfold twoNxtR
  rw [nxtIter_lift_inr]
  rw [twoNxt_iter]
  rfl

open Classical in
theorem twoLoop_hnofix_r {S₁ : Type} (g₁ : S₁ → S₁) :
    ∀ j, j < 2 →
      twoNxtR (S₁ := S₁) g₁
          (nxtIter (twoNxtR (S₁ := S₁) g₁) j
            (Sum.inr (some (Sum.inr ()))))
        ≠ nxtIter (twoNxtR (S₁ := S₁) g₁) j
            (Sum.inr (some (Sum.inr ()))) := by
  intro j hj hcontra
  unfold twoNxtR at hcontra
  rw [nxtIter_lift_inr] at hcontra
  have h1 : twoNxt (nxtIter twoNxt j (Sum.inr ()))
      = nxtIter twoNxt j (Sum.inr ()) :=
    Option.some.inj (Sum.inr.inj hcontra)
  exact twoNxt_nofix _ h1

open Classical in
theorem twoLoop_lang_ne_r (b c : BExp T) (q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    autLang (genW T)
        (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
        (Sum.inr (some (Sum.inl ())))
      ≠ autLang (genW T)
          (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
          (Sum.inr (some (Sum.inr ()))) := by
  obtain ⟨αb, hαb⟩ := hexitB
  intro h
  have hiff := iff_of_eq (congrFun h (αb, []))
  have hport : autRun (genW T)
      (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
      (Sum.inr (some (Sum.inr ()))) αb [] := by
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
theorem twoLoop_hnontriv_r (b c : BExp T) (q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T) (g₁ : S₁ → S₁)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    ∀ j : Nat,
      autLang (genW T)
          (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
          (nxtIter (twoNxtR (S₁ := S₁) g₁) (j + 1)
            (Sum.inr (some (Sum.inr ()))))
        ≠ autLang (genW T)
            (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
            (nxtIter (twoNxtR (S₁ := S₁) g₁) j
              (Sum.inr (some (Sum.inr ())))) := by
  intro j
  unfold twoNxtR
  rw [nxtIter_lift_inr, nxtIter_lift_inr, twoNxt_iter, twoNxt_iter]
  rcases Nat.mod_two_eq_zero_or_one j with h | h
  · rw [if_pos h, if_neg (by omega)]
    exact twoLoop_lang_ne_r b c q r aut₁ hexitB
  · rw [if_pos (by omega), if_neg (by omega)]
    exact (twoLoop_lang_ne_r b c q r aut₁ hexitB).symm

open Classical in
theorem twoLoop_qperiod2_r (b c : BExp T) (q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T) (g₁ : S₁ → S₁)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false) :
    2 ≤ qPeriod (sumGAut aut₁ (twoLoopAut b c q r).toGAut)
        (twoNxtR (S₁ := S₁) g₁)
        (Sum.inr (some (Sum.inr ()))) 2 := by
  obtain ⟨h1, h2, h3, h4⟩ := qPeriod_spec
    (sumGAut aut₁ (twoLoopAut b c q r).toGAut)
    (twoNxtR (S₁ := S₁) g₁)
    (Sum.inr (some (Sum.inr ()))) 2 (by omega)
    (twoLoop_hper_r (S₁ := S₁) g₁)
  generalize hqgen : qPeriod (sumGAut aut₁
      (twoLoopAut b c q r).toGAut)
      (twoNxtR (S₁ := S₁) g₁)
      (Sum.inr (some (Sum.inr ()))) 2 = qp at h1 h2 h3 h4 ⊢
  rcases Nat.lt_or_ge qp 2 with hlt | hge
  · exfalso
    have hqp1 : qp = 1 := by omega
    rw [hqp1] at h1
    have hn : nxtIter (twoNxtR (S₁ := S₁) g₁) 1
        (Sum.inr (some (Sum.inr ())))
        = Sum.inr (some (Sum.inl ())) := rfl
    rw [hn] at h1
    have hL : autLang (genW T)
        (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
        (Sum.inr (some (Sum.inl ())))
        = autLang (genW T)
          (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
          (Sum.inr (some (Sum.inr ()))) := by
      rw [← rep_lang (sumGAut aut₁ (twoLoopAut b c q r).toGAut)
        (Sum.inr (some (Sum.inl ()))), h1,
        rep_lang (sumGAut aut₁ (twoLoopAut b c q r).toGAut)]
    exact twoLoop_lang_ne_r b c q r aut₁ hexitB hL
  · exact hge

open Classical in
/-- The mirror rank (generic left summand). -/
def twoRankR {S₁ : Type} :
    Sum (Option S₁) (Option (Sum Unit Unit)) → Nat :=
  Sum.elim (fun o => if o.isSome then 0 else 1)
    (fun o => if o.isSome then 0 else 1)

open Classical in
theorem twoLoop_minRank_zero_r (b c : BExp T) (q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T)
    (x : Sum Unit Unit) :
    minRank (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
        (twoRankR (S₁ := S₁))
        (bisimRep (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
          (Sum.inr (some x))) = 0 := by
  have h1 : autLang (genW T)
      (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
      (Sum.inr (some x))
      = autLang (genW T)
        (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
        (bisimRep (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
          (Sum.inr (some x))) :=
    (rep_lang (sumGAut aut₁ (twoLoopAut b c q r).toGAut)
      (Sum.inr (some x))).symm
  have h2 := minRank_le
    (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
    (twoRankR (S₁ := S₁)) h1
  have h3 : twoRankR (S₁ := S₁) (Sum.inr (some x)) = 0 := rfl
  omega

open Classical in
theorem twoLoop_hnodesc_r (b c : BExp T) (q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T) (x : Sum Unit Unit) :
    ∀ e ∈ (cleanAut (bisimQuotAut
        (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut)))).trans
        (bisimRep (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
          (Sum.inr (some x))),
      ¬ minRank (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
          (twoRankR (S₁ := S₁)) e.2.2
        < minRank (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
            (twoRankR (S₁ := S₁))
            (bisimRep (trimAut
              (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
              (Sum.inr (some x))) := by
  intro e _ hcontra
  rw [twoLoop_minRank_zero_r] at hcontra
  exact Nat.not_lt_zero _ hcontra

open Classical in
theorem twoLoop_hstates_r (b c : BExp T) (q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T) (x : Sum Unit Unit) :
    bisimRep (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
        (Sum.inr (some x))
      ∈ (bisimQuotAut
          (trimAut (sumGAut aut₁
            (twoLoopAut b c q r).toGAut))).states := by
  refine List.mem_map.mpr ⟨Sum.inr (some x), ?_, rfl⟩
  refine List.mem_append.mpr (Or.inr (List.mem_map.mpr
    ⟨some x, ?_, rfl⟩))
  refine List.mem_cons.mpr (Or.inr (List.mem_map.mpr ⟨x, ?_, rfl⟩))
  show x ∈ (certifiedThompson A T (twoLoopBody c q r)).aut.core.states
  cases x with
  | inl u =>
      cases u
      exact List.mem_cons_self ..
  | inr u =>
      cases u
      exact List.mem_cons_of_mem _ (List.mem_cons_self ..)

open Classical in
theorem twoLoop_noeps_inl_r (b c : BExp T) (q r : A)
    {S₁ : Type} (aut₁ : GAut (Option S₁) A T) :
    ∀ α : T → Bool,
      ¬ autRun (genW T)
          (trimAut (sumGAut aut₁ (twoLoopAut b c q r).toGAut))
          (Sum.inr (some (Sum.inl ()))) α [] := by
  intro α h
  have h' : bval (genW T)
      ((twoLoopAut b c q r).core.hlt (Sum.inl ())) α = true := h
  rw [twoLoop_hlt_inl] at h'
  exact nomatch h'

#print axioms twoLoop_hnontriv_r
#print axioms twoLoop_qperiod2_r
#print axioms twoLoop_hnodesc_r

/-! ## THE FIFTH THEOREM

    The sum of two two-loop programs has a solvable canonical quotient,
    and uniformly equivalent two-loop programs are provably equal from
    the finite axioms — the first completeness theorem for genuinely
    nested cycles, no uniqueness axiom. -/

open Classical in
/-- Iterates of the port orbit normalize by parity (left). -/
private theorem twoLoop_iter_norm_l (j : Nat) :
    nxtIter (twoNxtL (S₂ := Sum Unit Unit) twoNxt) j
        (Sum.inl (some (Sum.inr ())))
      = Sum.inl (some (if j % 2 = 0 then Sum.inr () else Sum.inl ())) := by
  unfold twoNxtL
  rw [nxtIter_lift_inl, twoNxt_iter]
  rcases Nat.mod_two_eq_zero_or_one j with h | h
  · rw [if_pos h, if_pos h]
  · rw [if_neg (by omega), if_neg (by omega)]
    rfl

open Classical in
/-- Iterates of the port orbit normalize by parity (right). -/
private theorem twoLoop_iter_norm_r (j : Nat) :
    nxtIter (twoNxtR (S₁ := Sum Unit Unit) twoNxt) j
        (Sum.inr (some (Sum.inr ())))
      = Sum.inr (some (if j % 2 = 0 then Sum.inr () else Sum.inl ())) := by
  unfold twoNxtR
  rw [nxtIter_lift_inr, twoNxt_iter]
  rcases Nat.mod_two_eq_zero_or_one j with h | h
  · rw [if_pos h, if_pos h]
  · rw [if_neg (by omega), if_neg (by omega)]
    rfl

open Classical in
private theorem twoLoop_iter_norm_r' (j : Nat) :
    nxtIter (twoNxtL (S₂ := Sum Unit Unit) twoNxt) j
        ((Sum.inr (some (Sum.inr ()))
          : Sum (Option (Sum Unit Unit)) (Option (Sum Unit Unit))))
      = Sum.inr (some (if j % 2 = 0 then Sum.inr ()
          else Sum.inl ())) :=
  twoLoop_iter_norm_r j

open Classical in
/-- **SUMS OF TWO-LOOP PROGRAMS ARE SOLVABLE.** -/
theorem twoLoops_solvable (b₁ c₁ b₂ c₂ : BExp T) (q₁ r₁ q₂ r₂ : A)
    (hexitC₁ : ∃ α : T → Bool, bval (genW T) c₁ α = false)
    (hexitB₁ : ∃ α : T → Bool, bval (genW T) b₁ α = false)
    (hbc₁ : ∃ α : T → Bool,
      bval (genW T) b₁ α = true ∧ bval (genW T) c₁ α = true)
    (hexitC₂ : ∃ α : T → Bool, bval (genW T) c₂ α = false)
    (hexitB₂ : ∃ α : T → Bool, bval (genW T) b₂ α = false)
    (hbc₂ : ∃ α : T → Bool,
      bval (genW T) b₂ α = true ∧ bval (genW T) c₂ α = true) :
    ∃ qsol : Sum (Option (Sum Unit Unit)) (Option (Sum Unit Unit))
        → Exp A T,
      SolvesBA (bisimQuotAut (trimAut
        (sumGAut (twoLoopAut b₁ c₁ q₁ r₁).toGAut
          (twoLoopAut b₂ c₂ q₂ r₂).toGAut))) qsol := by
  refine walked_rankNxt_quot_solvesBA
    (sumGAut (twoLoopAut b₁ c₁ q₁ r₁).toGAut
      (twoLoopAut b₂ c₂ q₂ r₂).toGAut)
    (twoRank (S₂ := Sum Unit Unit))
    (twoNxtL (S₂ := Sum Unit Unit) twoNxt)
    ?_ ?_ ?_
    [((Sum.inl (some (Sum.inr ()))
        : Sum (Option (Sum Unit Unit)) (Option (Sum Unit Unit))), 2),
      (Sum.inr (some (Sum.inr ())), 2)]
    ?_ ?_
  · -- WalkedDec
    intro s e he _
    cases s with
    | inl o =>
        obtain ⟨t₁, ht₁, heq₁⟩ := List.mem_map.mp he
        cases o with
        | none =>
            obtain ⟨t₀, ht₀, heq₀⟩ := List.mem_map.mp ht₁
            refine Or.inr (Or.inr ?_)
            rw [← heq₁, ← heq₀]
            show twoRank (S₂ := Sum Unit Unit)
              (Sum.inl (some t₀.2.2)) < twoRank (S₂ := Sum Unit Unit)
                (Sum.inl none)
            show (0 : Nat) < 1
            omega
        | some x =>
            obtain ⟨t₀, ht₀, heq₀⟩ := List.mem_map.mp ht₁
            rw [← heq₁, ← heq₀]
            rcases two_state_dec x t₀.2.2 with h | h
            · exact Or.inl (by rw [h])
            · refine Or.inr (Or.inl ?_)
              show Sum.inl (some t₀.2.2)
                = Sum.inl (some (twoNxt x))
              rw [h]
    | inr o =>
        obtain ⟨t₁, ht₁, heq₁⟩ := List.mem_map.mp he
        cases o with
        | none =>
            obtain ⟨t₀, ht₀, heq₀⟩ := List.mem_map.mp ht₁
            refine Or.inr (Or.inr ?_)
            rw [← heq₁, ← heq₀]
            show (0 : Nat) < 1
            omega
        | some x =>
            obtain ⟨t₀, ht₀, heq₀⟩ := List.mem_map.mp ht₁
            rw [← heq₁, ← heq₀]
            rcases two_state_dec x t₀.2.2 with h | h
            · exact Or.inl (by rw [h])
            · refine Or.inr (Or.inl ?_)
              show Sum.inr (some t₀.2.2)
                = Sum.inr (some (twoNxt x))
              rw [h]
  · -- rank preserved
    intro s
    cases s with
    | inl o => cases o <;> rfl
    | inr o => cases o <;> rfl
  · -- hfire
    intro s _ hne
    cases s with
    | inl o =>
        cases o with
        | none => exact absurd rfl hne
        | some x =>
            cases x with
            | inl u =>
                cases u
                obtain ⟨αc, hαc⟩ := id hexitC₁
                exact ⟨αc, r₁, twoLoop_trim_step_inl_adv b₁ c₁ q₁ r₁ _
                  hexitC₁ hexitB₁ αc hαc⟩
            | inr u =>
                cases u
                obtain ⟨α, hb, hc⟩ := id hbc₁
                exact ⟨α, q₁, twoLoop_trim_step_inr_feed b₁ c₁ q₁ r₁ _
                  hexitC₁ hexitB₁ α hb hc⟩
    | inr o =>
        cases o with
        | none => exact absurd rfl hne
        | some x =>
            cases x with
            | inl u =>
                cases u
                obtain ⟨αc, hαc⟩ := id hexitC₂
                exact ⟨αc, r₂, twoLoop_trim_step_inl_adv_r b₂ c₂ q₂ r₂ _
                  hexitC₂ hexitB₂ αc hαc⟩
            | inr u =>
                cases u
                obtain ⟨α, hb, hc⟩ := id hbc₂
                exact ⟨α, q₂, twoLoop_trim_step_inr_feed_r b₂ c₂ q₂ r₂ _
                  hexitC₂ hexitB₂ α hb hc⟩
  · -- hos
    intro p hp
    rcases List.mem_cons.mp hp with hp1 | hp'
    · subst hp1
      refine ⟨by omega, twoLoop_hper (S₂ := Sum Unit Unit) twoNxt,
        live_trimAut (twoLoop_live_inr b₁ c₁ q₁ r₁ _ hexitB₁),
        twoLoop_hnofix (S₂ := Sum Unit Unit) twoNxt,
        fun w _ => Nat.zero_le _,
        twoLoop_hnontriv b₁ c₁ q₁ r₁ _ twoNxt hexitB₁,
        twoLoop_qperiod2 b₁ c₁ q₁ r₁ _ twoNxt hexitB₁,
        ?_, ?_, ?_⟩
      · intro j
        rw [twoLoop_iter_norm_l]
        rcases Nat.mod_two_eq_zero_or_one j with h | h
        · rw [if_pos h]
          exact twoLoop_hstates b₁ c₁ q₁ r₁ _ (Sum.inr ())
        · rw [if_neg (by omega)]
          exact twoLoop_hstates b₁ c₁ q₁ r₁ _ (Sum.inl ())
      · intro j hj1 hjq
        rw [twoLoop_iter_norm_l]
        rcases Nat.mod_two_eq_zero_or_one j with h | h
        · rw [if_pos h]
          exact twoLoop_hnodesc b₁ c₁ q₁ r₁ _ (Sum.inr ())
        · rw [if_neg (by omega)]
          exact twoLoop_hnodesc b₁ c₁ q₁ r₁ _ (Sum.inl ())
      · intro j hj1 hjq α
        have hq2 := (qPeriod_spec
          (sumGAut (twoLoopAut b₁ c₁ q₁ r₁).toGAut
            (twoLoopAut b₂ c₂ q₂ r₂).toGAut)
          (twoNxtL (S₂ := Sum Unit Unit) twoNxt)
          (Sum.inl (some (Sum.inr ()))) 2 (by omega)
          (twoLoop_hper (S₂ := Sum Unit Unit) twoNxt)).2.2.1
        have hjlt : j < 2 := Nat.lt_of_lt_of_le hjq hq2
        have hj2 : j = 1 := by omega
        subst hj2
        rw [show (1 : Nat) = 1 from rfl]
        have hn := twoLoop_iter_norm_l 1
        rw [hn]
        rw [if_neg (by omega)]
        exact twoLoop_noeps_inl b₁ c₁ q₁ r₁ _ α
    · rcases List.mem_cons.mp hp' with hp2 | hnil
      · subst hp2
        refine ⟨by omega, twoLoop_hper_r (S₁ := Sum Unit Unit) twoNxt,
          live_trimAut (twoLoop_live_all_r b₂ c₂ q₂ r₂ _ hexitC₂
            hexitB₂ (Sum.inr ())),
          twoLoop_hnofix_r (S₁ := Sum Unit Unit) twoNxt,
          fun w _ => Nat.zero_le _,
          twoLoop_hnontriv_r b₂ c₂ q₂ r₂ _ twoNxt hexitB₂,
          twoLoop_qperiod2_r b₂ c₂ q₂ r₂ _ twoNxt hexitB₂,
          ?_, ?_, ?_⟩
        · intro j
          rw [twoLoop_iter_norm_r' j]
          rcases Nat.mod_two_eq_zero_or_one j with h | h
          · rw [if_pos h]
            exact twoLoop_hstates_r b₂ c₂ q₂ r₂ _ (Sum.inr ())
          · rw [if_neg (by omega)]
            exact twoLoop_hstates_r b₂ c₂ q₂ r₂ _ (Sum.inl ())
        · intro j hj1 hjq
          rw [twoLoop_iter_norm_r' j]
          rcases Nat.mod_two_eq_zero_or_one j with h | h
          · rw [if_pos h]
            exact twoLoop_hnodesc_r b₂ c₂ q₂ r₂ _ (Sum.inr ())
          · rw [if_neg (by omega)]
            exact twoLoop_hnodesc_r b₂ c₂ q₂ r₂ _ (Sum.inl ())
        · intro j hj1 hjq α
          have hq2 := (qPeriod_spec
            (sumGAut (twoLoopAut b₁ c₁ q₁ r₁).toGAut
              (twoLoopAut b₂ c₂ q₂ r₂).toGAut)
            (twoNxtL (S₂ := Sum Unit Unit) twoNxt)
            (Sum.inr (some (Sum.inr ()))) 2 (by omega)
            (twoLoop_hper_r (S₁ := Sum Unit Unit) twoNxt)).2.2.1
          have hjlt : j < 2 := Nat.lt_of_lt_of_le hjq hq2
          have hj2 : j = 1 := by omega
          subst hj2
          rw [twoLoop_iter_norm_r' 1]
          rw [if_neg (by omega)]
          exact twoLoop_noeps_inl_r b₂ c₂ q₂ r₂ _ α
      · exact nomatch hnil
  · -- cover
    intro cc hcc
    obtain ⟨x, hx, hrep⟩ := List.mem_map.mp hcc
    rcases List.mem_append.mp hx with hL | hR
    · obtain ⟨o, ho, hoeq⟩ := List.mem_map.mp hL
      refine Or.inr ⟨_, List.mem_cons_self .., ?_⟩
      rw [← hrep, ← hoeq]
      exact twoLoop_cover_inl b₁ c₁ q₁ r₁ _ twoNxt hexitC₁ hexitB₁ o
    · obtain ⟨o, ho, hoeq⟩ := List.mem_map.mp hR
      refine Or.inr ⟨_, List.mem_cons.mpr
        (Or.inr (List.mem_cons_self ..)), ?_⟩
      rw [← hrep, ← hoeq]
      exact twoLoop_cover_inr b₂ c₂ q₂ r₂ _ twoNxt hexitC₂ hexitB₂ o

open Classical in
/-- **THE FIFTH UNCONDITIONAL COMPLETENESS THEOREM**: uniformly
    equivalent two-loop programs — genuinely NESTED cycles — are
    provably equal from the finite GKAT axioms alone.  No uniqueness
    axiom. -/
theorem twoloops_complete (b₁ c₁ b₂ c₂ : BExp T) (q₁ r₁ q₂ r₂ : A)
    (hexitC₁ : ∃ α : T → Bool, bval (genW T) c₁ α = false)
    (hexitB₁ : ∃ α : T → Bool, bval (genW T) b₁ α = false)
    (hbc₁ : ∃ α : T → Bool,
      bval (genW T) b₁ α = true ∧ bval (genW T) c₁ α = true)
    (hexitC₂ : ∃ α : T → Bool, bval (genW T) c₂ α = false)
    (hexitB₂ : ∃ α : T → Bool, bval (genW T) b₂ α = false)
    (hbc₂ : ∃ α : T → Bool,
      bval (genW T) b₂ α = true ∧ bval (genW T) c₂ α = true)
    (heq : UniformLanguageEquivalent
      (twoLoop b₁ c₁ q₁ r₁) (twoLoop b₂ c₂ q₂ r₂)) :
    EquivBA (twoLoop b₁ c₁ q₁ r₁) (twoLoop b₂ c₂ q₂ r₂) := by
  obtain ⟨qsol, hq⟩ := twoLoops_solvable b₁ c₁ b₂ c₂ q₁ r₁ q₂ r₂
    hexitC₁ hexitB₁ hbc₁ hexitC₂ hexitB₂ hbc₂
  exact equivBA_of_quot_solvesBA
    (twoLoop b₁ c₁ q₁ r₁) (twoLoop b₂ c₂ q₂ r₂) heq hq

#print axioms twoLoops_solvable
#print axioms twoloops_complete

end GkatTwoLoop
