import GkatOrbitProofs

/-! # The chain-loop fragment: spine shape of chain Thompson automata

    A `Chain` body is a sequence of actions.  Its Thompson automaton is a
    SPINE: a nonempty list of pairwise-distinct states where every interior
    state is silent (semantically empty halt), steps deterministically to
    its successor at every atom (a guard firing everywhere, all fired arms
    agreeing), and the last state halts everywhere with no outgoing arms.
    Entry (`ChainInit`) is likewise deterministic into the head.

    These are exactly the source-level facts the orbit glue consumes:
    `hstep_uniq`/`hnoeps` at interiors, `hfire`/`hdec` for the loop, and
    distinctness for `hnofix`. -/

namespace GkatChainFragment

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatSumQuotient
open GkatDecomp GkatPlanExistence GkatGuardedAlgebra GkatResidue
open GkatRingSupport GkatRingPlan GkatNormalization GkatTrim GkatCycle
open GkatLoopFree GkatAtomicLoop GkatChainLoop GkatOrbit

variable {S A T : Type}

/-- Chain bodies: sequences of actions. -/
inductive Chain : Exp A T → Prop where
  | act (p : A) : Chain (.act p)
  | seq {e f : Exp A T} : Chain e → Chain f → Chain (.seq e f)

/-- Entry shape of a chain automaton: no silent acceptance, and a
    deterministic entry into `first` — one arm firing everywhere, all
    fired arms agreeing. -/
structure ChainInit {S' : Type} (B : InitializedGAut S' A T)
    (first : S') : Prop where
  hlt_zero : ∀ α : T → Bool, bval (genW T) B.initHlt α = false
  real : ∃ t ∈ B.initTrans,
    (∀ α : T → Bool, bval (genW T) t.1 α = true) ∧ t.2.2 = first
  fired : ∀ t ∈ B.initTrans, ∀ α : T → Bool,
    bval (genW T) t.1 α = true → t.2.2 = first

/-- The spine shape: interior states are silent and step deterministically
    to their successor; the last state halts everywhere with no arms;
    states are pairwise distinct. -/
def ChainSpine {S' : Type} (B : InitializedGAut S' A T) :
    List S' → Prop
  | [] => False
  | [s] => B.core.trans s = []
      ∧ ∀ α : T → Bool, bval (genW T) (B.core.hlt s) α = true
  | s :: s' :: rest =>
      (∀ α : T → Bool, bval (genW T) (B.core.hlt s) α = false)
      ∧ (∃ t ∈ B.core.trans s,
          (∀ α : T → Bool, bval (genW T) t.1 α = true) ∧ t.2.2 = s')
      ∧ (∀ t ∈ B.core.trans s, ∀ α : T → Bool,
          bval (genW T) t.1 α = true → t.2.2 = s')
      ∧ s ∉ s' :: rest
      ∧ ChainSpine B (s' :: rest)

private theorem chainSpine_one {S' : Type} (B : InitializedGAut S' A T)
    (s : S') :
    ChainSpine B [s]
      = (B.core.trans s = []
        ∧ ∀ α : T → Bool, bval (genW T) (B.core.hlt s) α = true) := rfl

private theorem chainSpine_cons {S' : Type} (B : InitializedGAut S' A T)
    (s s' : S') (rest : List S') :
    ChainSpine B (s :: s' :: rest)
      = ((∀ α : T → Bool, bval (genW T) (B.core.hlt s) α = false)
        ∧ (∃ t ∈ B.core.trans s,
            (∀ α : T → Bool, bval (genW T) t.1 α = true) ∧ t.2.2 = s')
        ∧ (∀ t ∈ B.core.trans s, ∀ α : T → Bool,
            bval (genW T) t.1 α = true → t.2.2 = s')
        ∧ s ∉ s' :: rest
        ∧ ChainSpine B (s' :: rest)) := rfl

/-- The right summand of a sequential composition keeps its spine. -/
theorem chainSpine_seq_right {S₁ S₂ : Type}
    (L : InitializedGAut S₁ A T) (R : InitializedGAut S₂ A T) :
    ∀ sR : List S₂, ChainSpine R sR →
      ChainSpine (seqInitialized L R) (sR.map Sum.inr) := by
  intro sR
  induction sR with
  | nil => intro h; exact h.elim
  | cons r rest ih =>
      intro h
      cases rest with
      | nil =>
          obtain ⟨htr, hh⟩ := h
          rw [List.map_cons, List.map_nil, chainSpine_one]
          constructor
          · show (R.core.trans r).map _ = []
            rw [htr]
            rfl
          · intro α
            exact hh α
      | cons r' rest' =>
          obtain ⟨hh, ⟨t, ht, htg, htt⟩, hfired, hnm, htail⟩ := h
          rw [List.map_cons, List.map_cons, chainSpine_cons]
          refine ⟨fun α => hh α, ?_, ?_, ?_, ?_⟩
          · refine ⟨(t.1, t.2.1, Sum.inr t.2.2), ?_, htg, ?_⟩
            · show _ ∈ (R.core.trans r).map
                (fun tr => (tr.1, tr.2.1, Sum.inr tr.2.2))
              exact List.mem_map.mpr ⟨t, ht, rfl⟩
            · show Sum.inr t.2.2 = Sum.inr r'
              rw [htt]
          · intro t' ht' α hb
            obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp ht'
            rw [← heq] at hb ⊢
            show Sum.inr t₀.2.2 = Sum.inr r'
            rw [hfired t₀ ht₀ α hb]
          · intro hmem
            have hr : r ∈ r' :: rest' := by
              rcases List.mem_cons.mp hmem with heq | hmem'
              · exact List.mem_cons.mpr (Or.inl (Sum.inr.inj heq))
              · obtain ⟨x, hx, hxe⟩ := List.mem_map.mp hmem'
                have hxr : x = r := Sum.inr.inj hxe
                exact List.mem_cons.mpr (Or.inr (hxr ▸ hx))
            exact hnm hr
          · exact ih htail

#print axioms chainSpine_seq_right

open Classical in
/-- The left summand's spine, with its last state rewired into the right
    spine's head through the sequential glue. -/
theorem chainSpine_seq_left {S₁ S₂ : Type}
    (L : InitializedGAut S₁ A T) (R : InitializedGAut S₂ A T)
    {r : S₂} {sR : List S₂}
    (hR : ChainSpine R (r :: sR)) (hRi : ChainInit R r) :
    ∀ sL : List S₁, ChainSpine L sL →
      ChainSpine (seqInitialized L R)
        (sL.map Sum.inl ++ (r :: sR).map Sum.inr) := by
  intro sL
  induction sL with
  | nil => intro h; exact h.elim
  | cons l rest ih =>
      intro h
      cases rest with
      | nil =>
          obtain ⟨htr, hh⟩ := h
          show ChainSpine (seqInitialized L R)
            (Sum.inl l :: Sum.inr r :: sR.map Sum.inr)
          rw [chainSpine_cons]
          refine ⟨?_, ?_, ?_, ?_, ?_⟩
          · intro α
            show (bval (genW T) (L.core.hlt l) α
              && bval (genW T) R.initHlt α) = false
            rw [hRi.hlt_zero α]
            exact Bool.and_false _
          · obtain ⟨t, ht, htg, htt⟩ := hRi.real
            refine ⟨(.and (L.core.hlt l) t.1, t.2.1, Sum.inr t.2.2),
              ?_, ?_, ?_⟩
            · exact List.mem_append.mpr (Or.inr
                (List.mem_map.mpr ⟨t, ht, rfl⟩))
            · intro α
              show (bval (genW T) (L.core.hlt l) α
                && bval (genW T) t.1 α) = true
              rw [hh α, htg α]
              rfl
            · show Sum.inr t.2.2 = Sum.inr r
              rw [htt]
          · intro t' ht' α hb
            rcases List.mem_append.mp ht' with hL' | hR'
            · obtain ⟨x, hx, -⟩ := List.mem_map.mp hL'
              rw [htr] at hx
              exact nomatch hx
            · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hR'
              rw [← heq] at hb ⊢
              show Sum.inr t₀.2.2 = Sum.inr r
              have hb' : (bval (genW T) (L.core.hlt l) α
                  && bval (genW T) t₀.1 α) = true := hb
              rw [Bool.and_eq_true] at hb'
              rw [hRi.fired t₀ ht₀ α hb'.2]
          · intro hmem
            rcases List.mem_cons.mp hmem with heq | hmem'
            · exact nomatch heq
            · obtain ⟨x, hx, hxe⟩ := List.mem_map.mp hmem'
              exact nomatch hxe
          · exact chainSpine_seq_right L R (r :: sR) hR
      | cons l' restL =>
          obtain ⟨hh, ⟨t, ht, htg, htt⟩, hfired, hnm, htail⟩ := h
          show ChainSpine (seqInitialized L R)
            (Sum.inl l :: Sum.inl l' ::
              (restL.map Sum.inl ++ (r :: sR).map Sum.inr))
          rw [chainSpine_cons]
          refine ⟨?_, ?_, ?_, ?_, ?_⟩
          · intro α
            show (bval (genW T) (L.core.hlt l) α
              && bval (genW T) R.initHlt α) = false
            rw [hh α]
            rfl
          · refine ⟨(t.1, t.2.1, Sum.inl t.2.2), ?_, htg, ?_⟩
            · exact List.mem_append.mpr (Or.inl
                (List.mem_map.mpr ⟨t, ht, rfl⟩))
            · show Sum.inl t.2.2 = Sum.inl l'
              rw [htt]
          · intro t' ht' α hb
            rcases List.mem_append.mp ht' with hL' | hR'
            · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hL'
              rw [← heq] at hb ⊢
              show Sum.inl t₀.2.2 = Sum.inl l'
              rw [hfired t₀ ht₀ α hb]
            · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hR'
              rw [← heq] at hb
              have hb' : (bval (genW T) (L.core.hlt l) α
                  && bval (genW T) t₀.1 α) = true := hb
              rw [hh α] at hb'
              exact nomatch hb'
          · intro hmem
            rcases List.mem_cons.mp hmem with heq | hmem'
            · exact hnm (List.mem_cons.mpr
                (Or.inl (Sum.inl.inj heq)))
            · rcases List.mem_append.mp hmem' with hA | hB
              · obtain ⟨x, hx, hxe⟩ := List.mem_map.mp hA
                have hxl : x = l := Sum.inl.inj hxe
                exact hnm (List.mem_cons.mpr (Or.inr (hxl ▸ hx)))
              · obtain ⟨x, hx, hxe⟩ := List.mem_map.mp hB
                exact nomatch hxe
          · exact ih htail

open Classical in
/-- Entry survives sequential composition on the left. -/
theorem chainInit_seq {S₁ S₂ : Type}
    {L : InitializedGAut S₁ A T} {R : InitializedGAut S₂ A T}
    {firstL : S₁} (hL : ChainInit L firstL) :
    ChainInit (seqInitialized L R) (Sum.inl firstL) := by
  refine ⟨?_, ?_, ?_⟩
  · intro α
    show (bval (genW T) L.initHlt α && bval (genW T) R.initHlt α) = false
    rw [hL.hlt_zero α]
    rfl
  · obtain ⟨t, ht, htg, htt⟩ := hL.real
    refine ⟨(t.1, t.2.1, Sum.inl t.2.2), ?_, htg, ?_⟩
    · exact List.mem_append.mpr (Or.inl (List.mem_map.mpr ⟨t, ht, rfl⟩))
    · show Sum.inl t.2.2 = Sum.inl firstL
      rw [htt]
  · intro t' ht' α hb
    rcases List.mem_append.mp ht' with hL' | hR'
    · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hL'
      rw [← heq] at hb ⊢
      show Sum.inl t₀.2.2 = Sum.inl firstL
      rw [hL.fired t₀ ht₀ α hb]
    · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hR'
      rw [← heq] at hb
      have hb' : (bval (genW T) L.initHlt α
          && bval (genW T) t₀.1 α) = true := hb
      rw [hL.hlt_zero α] at hb'
      exact nomatch hb'

open Classical in
/-- **THE CHAIN SHAPE THEOREM**: every chain body's Thompson automaton is a
    spine with deterministic entry, and its states are exactly the spine. -/
theorem chain_shape {body : Exp A T} (h : Chain body) :
    ∃ (spine : List (certifiedThompson A T body).State)
      (first : (certifiedThompson A T body).State),
      spine.head? = some first
      ∧ ChainSpine (certifiedThompson A T body).aut spine
      ∧ ChainInit (certifiedThompson A T body).aut first
      ∧ (certifiedThompson A T body).aut.core.states = spine := by
  induction h with
  | act p =>
      refine ⟨[()], (), rfl, ⟨rfl, fun α => rfl⟩,
        ⟨fun α => rfl, ⟨(.one, p, ()), List.mem_cons_self ..,
          fun α => rfl, rfl⟩, ?_⟩, rfl⟩
      intro t ht α hb
      rfl
  | @seq e f he hf ihe ihf =>
      obtain ⟨sE, fE, hheadE, hspE, hinE, hstE⟩ := ihe
      obtain ⟨sF, fF, hheadF, hspF, hinF, hstF⟩ := ihf
      cases sF with
      | nil => exact nomatch hheadF
      | cons rF sF' =>
          have hfF : rF = fF := Option.some.inj hheadF
          subst hfF
          cases sE with
          | nil => exact nomatch hheadE
          | cons e0 sE' =>
              have he0 : e0 = fE := Option.some.inj hheadE
              refine ⟨(e0 :: sE').map Sum.inl ++ (rF :: sF').map Sum.inr,
                Sum.inl fE, ?_, ?_, ?_, ?_⟩
              · show some (Sum.inl e0) = some (Sum.inl fE)
                rw [he0]
              · exact chainSpine_seq_left _ _ hspF hinF (e0 :: sE') hspE
              · exact chainInit_seq hinE
              · show (certifiedThompson A T e).aut.core.states.map Sum.inl
                    ++ (certifiedThompson A T f).aut.core.states.map Sum.inr
                  = _
                rw [hstE, hstF]

#print axioms chain_shape

/-! ## The spine successor and its walk

    `spineNext wrap l` follows the spine and wraps at the end — the `nxt`
    function the orbit layer consumes.  Its walk is characterized
    positionally: stepping the `j`-th element yields the `j+1`-st, the last
    wraps, and iteration from the head or the port traverses the spine with
    period `l.length`. -/

open Classical in
/-- The successor along a list, wrapping to `wrap` at the end. -/
noncomputable def spineNext {S' : Type} (wrap : S') : List S' → S' → S'
  | [], s => s
  | [x], s => if s = x then wrap else s
  | x :: y :: t, s => if s = x then y else spineNext wrap (y :: t) s

open Classical in
private theorem spineNext_sing {S' : Type} (wrap x s : S') :
    spineNext wrap [x] s = if s = x then wrap else s := rfl

open Classical in
private theorem spineNext_cc {S' : Type} (wrap x y : S') (t : List S')
    (s : S') :
    spineNext wrap (x :: y :: t) s
      = if s = x then y else spineNext wrap (y :: t) s := rfl

open Classical in
/-- Head of a `ChainSpine` never recurs in its tail. -/
private theorem chainSpine_head_notin {S' : Type}
    {B : InitializedGAut S' A T} {x : S'} {t : List S'}
    (h : ChainSpine B (x :: t)) : x ∉ t := by
  cases t with
  | nil => intro hx; exact nomatch hx
  | cons y t' => exact h.2.2.2.1

open Classical in
/-- Tail of a nontrivial `ChainSpine` is a `ChainSpine`. -/
private theorem chainSpine_tail {S' : Type}
    {B : InitializedGAut S' A T} {x y : S'} {t : List S'}
    (h : ChainSpine B (x :: y :: t)) : ChainSpine B (y :: t) :=
  h.2.2.2.2

open Classical in
/-- **STEP CHARACTERIZATION**: the successor of the `j`-th spine element is
    the `j+1`-st. -/
theorem spineNext_at {S' : Type} {B : InitializedGAut S' A T}
    (wrap : S') :
    ∀ l : List S', ChainSpine B l → ∀ j (h1 : j + 1 < l.length),
      spineNext wrap l (l[j]'(by omega)) = l[j + 1]'h1 := by
  intro l
  induction l with
  | nil => intro _ j h1; exact nomatch h1
  | cons x t ih =>
      intro h j h1
      cases t with
      | nil =>
          exfalso
          have : j + 1 < 1 := h1
          omega
      | cons y t' =>
          cases j with
          | zero =>
              show spineNext wrap (x :: y :: t') x = y
              rw [spineNext_cc, if_pos rfl]
          | succ j =>
              have hmem : (y :: t')[j]'(by
                  have := h1
                  simp only [List.length_cons] at this ⊢
                  omega) ∈ y :: t' := List.getElem_mem _
              have hne : (y :: t')[j]'(by
                  have := h1
                  simp only [List.length_cons] at this ⊢
                  omega) ≠ x := by
                intro hcontra
                exact chainSpine_head_notin h (hcontra ▸ hmem)
              show spineNext wrap (x :: y :: t')
                  ((y :: t')[j]'(by
                    have := h1
                    simp only [List.length_cons] at this ⊢
                    omega)) = (y :: t')[j + 1]'(by
                    have := h1
                    simp only [List.length_cons] at this ⊢
                    omega)
              rw [spineNext_cc, if_neg hne]
              exact ih (chainSpine_tail h) j (by
                have := h1
                simp only [List.length_cons] at this ⊢
                omega)

open Classical in
/-- **WRAP CHARACTERIZATION**: the successor of the last spine element is
    `wrap`. -/
theorem spineNext_last {S' : Type} {B : InitializedGAut S' A T}
    (wrap : S') :
    ∀ l : List S', ChainSpine B l → ∀ (h : 0 < l.length),
      spineNext wrap l (l[l.length - 1]'(by omega)) = wrap := by
  intro l
  induction l with
  | nil => intro _ h; exact nomatch h
  | cons x t ih =>
      intro hsp h
      cases t with
      | nil =>
          show spineNext wrap [x] x = wrap
          rw [spineNext_sing, if_pos rfl]
      | cons y t' =>
          have hlen : (x :: y :: t').length - 1 = (y :: t').length := by
            simp only [List.length_cons]
            omega
          have hmem : (y :: t')[(y :: t').length - 1]'(by
              simp only [List.length_cons]; omega) ∈ y :: t' :=
            List.getElem_mem _
          have hne : (y :: t')[(y :: t').length - 1]'(by
              simp only [List.length_cons]; omega) ≠ x := by
            intro hcontra
            exact chainSpine_head_notin hsp (hcontra ▸ hmem)
          show spineNext wrap (x :: y :: t')
              ((x :: y :: t')[(x :: y :: t').length - 1]'(by omega)) = wrap
          have hidx : (x :: y :: t')[(x :: y :: t').length - 1]'(by
                omega)
              = (y :: t')[(y :: t').length - 1]'(by
                simp only [List.length_cons]; omega) := by
            have h2 : (x :: y :: t').length - 1
                = ((y :: t').length - 1) + 1 := by
              simp only [List.length_cons]
              omega
            simp only [h2, List.getElem_cons_succ]
          rw [hidx, spineNext_cc, if_neg hne]
          exact ih (chainSpine_tail hsp) (by simp only [List.length_cons]; omega)

open Classical in
/-- **ITERATION FROM THE HEAD**: `j` steps from the head land on the `j`-th
    element. -/
theorem spine_iter {S' : Type} {B : InitializedGAut S' A T}
    (wrap : S') {l : List S'} (hsp : ChainSpine B l) :
    ∀ j (h : j < l.length) (h0 : 0 < l.length),
      nxtIter (spineNext wrap l) j (l[0]'h0) = l[j]'h := by
  intro j
  induction j with
  | zero => intro h h0; rfl
  | succ j ih =>
      intro h h0
      show spineNext wrap l (nxtIter (spineNext wrap l) j (l[0]'h0))
        = l[j + 1]'h
      rw [ih (by omega) h0]
      exact spineNext_at wrap l hsp j h

open Classical in
/-- **PERIODICITY FROM THE HEAD**: the walk closes after `l.length`
    steps. -/
theorem spine_period {S' : Type} {B : InitializedGAut S' A T}
    (wrap : S') {l : List S'} (hsp : ChainSpine B l)
    (n : Nat) (hn : l.length = n + 1) :
    nxtIter (spineNext wrap l) (n + 1) (l[0]'(by omega))
      = spineNext wrap l (l[n]'(by omega)) := by
  show spineNext wrap l
      (nxtIter (spineNext wrap l) n (l[0]'(by omega))) = _
  rw [spine_iter wrap hsp n (by omega) (by omega)]

open Classical in
/-- **POSITIONAL DISTINCTNESS**: spine elements at distinct positions are
    distinct. -/
theorem spine_distinct {S' : Type} {B : InitializedGAut S' A T} :
    ∀ l : List S', ChainSpine B l → ∀ i j (hi : i < l.length)
      (hj : j < l.length), i < j → l[i]'hi ≠ l[j]'hj := by
  intro l
  induction l with
  | nil => intro _ i j hi; exact nomatch hi
  | cons x t ih =>
      intro hsp i j hi hj hij
      cases i with
      | zero =>
          cases j with
          | zero => omega
          | succ j =>
              show x ≠ t[j]'(by
                have := hj
                simp only [List.length_cons] at this
                omega)
              intro hcontra
              exact chainSpine_head_notin hsp
                (hcontra ▸ List.getElem_mem _)
      | succ i =>
          cases j with
          | zero => omega
          | succ j =>
              cases t with
              | nil =>
                  exfalso
                  have := hi
                  simp only [List.length_cons, List.length_nil] at this
                  omega
              | cons y t' =>
                  exact ih (chainSpine_tail hsp) i j (by
                      have := hi
                      simp only [List.length_cons] at this ⊢
                      omega) (by
                      have := hj
                      simp only [List.length_cons] at this ⊢
                      omega) (by omega)

#print axioms spine_iter
#print axioms spine_period
#print axioms spine_distinct

/-! ## Positional spine facts and the loop automaton's arm classification

    Extract the recursive `ChainSpine` facts positionally, then classify
    every arm and halt guard of `loopInitialized b B`: interior states are
    silent and step (only) to their spine successor; the port halts exactly
    at `¬b` and its fired arms feed back exactly to the head, with a real
    feedback arm firing precisely with `b`. -/

private theorem getElem_last_cons {S' : Type} (x y : S') (t' : List S') :
    (x :: y :: t')[(x :: y :: t').length - 1]'(by
      simp only [List.length_cons]; omega)
      = (y :: t')[(y :: t').length - 1]'(by
        simp only [List.length_cons]; omega) := by
  have h2 : (x :: y :: t').length - 1 = ((y :: t').length - 1) + 1 := by
    simp only [List.length_cons]
    omega
  simp only [h2, List.getElem_cons_succ]

open Classical in
theorem spine_hlt_int_at {S' : Type} {B : InitializedGAut S' A T} :
    ∀ l : List S', ChainSpine B l → ∀ j (h1 : j + 1 < l.length),
      ∀ α : T → Bool,
        bval (genW T) (B.core.hlt (l[j]'(by omega))) α = false := by
  intro l
  induction l with
  | nil => intro _ j h1; exact absurd h1 (by simp)
  | cons x t ih =>
      intro hsp j h1
      cases t with
      | nil =>
          exact absurd h1 (by
            simp only [List.length_cons, List.length_nil]
            omega)
      | cons y t' =>
          cases j with
          | zero => exact hsp.1
          | succ j =>
              exact ih (chainSpine_tail hsp) j (by
                simp only [List.length_cons] at h1 ⊢
                omega)

open Classical in
theorem spine_fired_at {S' : Type} {B : InitializedGAut S' A T} :
    ∀ l : List S', ChainSpine B l → ∀ j (h1 : j + 1 < l.length),
      ∀ t ∈ B.core.trans (l[j]'(by omega)), ∀ α : T → Bool,
        bval (genW T) t.1 α = true → t.2.2 = l[j + 1]'h1 := by
  intro l
  induction l with
  | nil => intro _ j h1; exact absurd h1 (by simp)
  | cons x t ih =>
      intro hsp j h1
      cases t with
      | nil =>
          exact absurd h1 (by
            simp only [List.length_cons, List.length_nil]
            omega)
      | cons y t' =>
          cases j with
          | zero => exact hsp.2.2.1
          | succ j =>
              exact ih (chainSpine_tail hsp) j (by
                simp only [List.length_cons] at h1 ⊢
                omega)

open Classical in
theorem spine_real_at {S' : Type} {B : InitializedGAut S' A T} :
    ∀ l : List S', ChainSpine B l → ∀ j (h1 : j + 1 < l.length),
      ∃ t ∈ B.core.trans (l[j]'(by omega)),
        (∀ α : T → Bool, bval (genW T) t.1 α = true)
        ∧ t.2.2 = l[j + 1]'h1 := by
  intro l
  induction l with
  | nil => intro _ j h1; exact absurd h1 (by simp)
  | cons x t ih =>
      intro hsp j h1
      cases t with
      | nil =>
          exact absurd h1 (by
            simp only [List.length_cons, List.length_nil]
            omega)
      | cons y t' =>
          cases j with
          | zero => exact hsp.2.1
          | succ j =>
              exact ih (chainSpine_tail hsp) j (by
                simp only [List.length_cons] at h1 ⊢
                omega)

open Classical in
theorem spine_last_nil {S' : Type} {B : InitializedGAut S' A T} :
    ∀ l : List S', ChainSpine B l → ∀ (h : 0 < l.length),
      B.core.trans (l[l.length - 1]'(by omega)) = [] := by
  intro l
  induction l with
  | nil => intro _ h; exact absurd h (by simp)
  | cons x t ih =>
      intro hsp h
      cases t with
      | nil => exact hsp.1
      | cons y t' =>
          rw [getElem_last_cons]
          exact ih (chainSpine_tail hsp) (by
            simp only [List.length_cons]
            omega)

open Classical in
theorem spine_hlt_last {S' : Type} {B : InitializedGAut S' A T} :
    ∀ l : List S', ChainSpine B l → ∀ (h : 0 < l.length),
      ∀ α : T → Bool,
        bval (genW T) (B.core.hlt (l[l.length - 1]'(by omega))) α
          = true := by
  intro l
  induction l with
  | nil => intro _ h; exact absurd h (by simp)
  | cons x t ih =>
      intro hsp h
      cases t with
      | nil => exact hsp.2
      | cons y t' =>
          rw [getElem_last_cons]
          exact ih (chainSpine_tail hsp) (by
            simp only [List.length_cons]
            omega)

open Classical in
/-- Interior loop states are silent. -/
theorem loop_hlt_int {S' : Type} {B : InitializedGAut S' A T}
    (b : BExp T) {l : List S'} (hsp : ChainSpine B l)
    (j : Nat) (h1 : j + 1 < l.length) :
    ∀ α : T → Bool,
      bval (genW T)
        ((loopInitialized b B).core.hlt (l[j]'(by omega))) α = false := by
  intro α
  show (bval (genW T) (B.core.hlt (l[j]'(by omega))) α
    && !(bval (genW T) b α)) = false
  rw [spine_hlt_int_at l hsp j h1 α]
  rfl

open Classical in
/-- The port halts exactly at `¬b`. -/
theorem loop_hlt_port {S' : Type} {B : InitializedGAut S' A T}
    (b : BExp T) {l : List S'} (hsp : ChainSpine B l)
    (h0 : 0 < l.length) :
    ∀ α : T → Bool,
      bval (genW T)
        ((loopInitialized b B).core.hlt (l[l.length - 1]'(by omega))) α
        = !(bval (genW T) b α) := by
  intro α
  show (bval (genW T) (B.core.hlt (l[l.length - 1]'(by omega))) α
    && !(bval (genW T) b α)) = !(bval (genW T) b α)
  rw [spine_hlt_last l hsp h0 α]
  exact Bool.true_and _

open Classical in
/-- Fired arms at interior loop states go to the spine successor. -/
theorem loop_arms_interior {S' : Type} {B : InitializedGAut S' A T}
    (b : BExp T) {l : List S'} (hsp : ChainSpine B l)
    (j : Nat) (h1 : j + 1 < l.length) :
    ∀ t ∈ (loopInitialized b B).core.trans (l[j]'(by omega)),
      ∀ α : T → Bool, bval (genW T) t.1 α = true →
        t.2.2 = l[j + 1]'h1 := by
  intro t ht α hb
  rcases List.mem_append.mp ht with hB | hF
  · exact spine_fired_at l hsp j h1 t hB α hb
  · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hF
    rw [← heq] at hb
    have hb' : (bval (genW T) (B.core.hlt (l[j]'(by omega))) α
        && bval (genW T) (.and b t₀.1) α) = true := hb
    rw [spine_hlt_int_at l hsp j h1 α] at hb'
    exact nomatch hb'

open Classical in
/-- Fired arms at the port feed back to the head. -/
theorem loop_arms_port {S' : Type} {B : InitializedGAut S' A T}
    (b : BExp T) {l : List S'} (hsp : ChainSpine B l) {first : S'}
    (hin : ChainInit B first) (h0 : 0 < l.length) :
    ∀ t ∈ (loopInitialized b B).core.trans (l[l.length - 1]'(by omega)),
      ∀ α : T → Bool, bval (genW T) t.1 α = true → t.2.2 = first := by
  intro t ht α hb
  rcases List.mem_append.mp ht with hB | hF
  · rw [spine_last_nil l hsp h0] at hB
    exact nomatch hB
  · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hF
    rw [← heq] at hb ⊢
    show t₀.2.2 = first
    have hb' : (bval (genW T) (B.core.hlt (l[l.length - 1]'(by omega))) α
        && (bval (genW T) b α && bval (genW T) t₀.1 α)) = true := hb
    rw [Bool.and_eq_true, Bool.and_eq_true] at hb'
    exact hin.fired t₀ ht₀ α hb'.2.2

open Classical in
/-- Interior real arm: fires everywhere, to the spine successor. -/
theorem loop_real_interior {S' : Type} {B : InitializedGAut S' A T}
    (b : BExp T) {l : List S'} (hsp : ChainSpine B l)
    (j : Nat) (h1 : j + 1 < l.length) :
    ∃ t ∈ (loopInitialized b B).core.trans (l[j]'(by omega)),
      (∀ α : T → Bool, bval (genW T) t.1 α = true)
      ∧ t.2.2 = l[j + 1]'h1 := by
  obtain ⟨t₀, ht₀, htg, htt⟩ := spine_real_at l hsp j h1
  exact ⟨t₀, List.mem_append.mpr (Or.inl ht₀), htg, htt⟩

open Classical in
/-- Port real feedback arm: fires exactly with `b`, to the head. -/
theorem loop_real_port {S' : Type} {B : InitializedGAut S' A T}
    (b : BExp T) {l : List S'} (hsp : ChainSpine B l) {first : S'}
    (hin : ChainInit B first) (h0 : 0 < l.length) :
    ∃ t ∈ (loopInitialized b B).core.trans (l[l.length - 1]'(by omega)),
      (∀ α : T → Bool, bval (genW T) t.1 α = bval (genW T) b α)
      ∧ t.2.2 = first := by
  obtain ⟨t₀, ht₀, htg, htt⟩ := hin.real
  refine ⟨(.and (B.core.hlt (l[l.length - 1]'(by omega)))
    (.and b t₀.1), t₀.2), ?_, ?_, htt⟩
  · exact List.mem_append.mpr (Or.inr (List.mem_map.mpr ⟨t₀, ht₀, rfl⟩))
  · intro α
    show (bval (genW T) (B.core.hlt (l[l.length - 1]'(by omega))) α
      && (bval (genW T) b α && bval (genW T) t₀.1 α))
      = bval (genW T) b α
    rw [spine_hlt_last l hsp h0 α, htg α, Bool.true_and, Bool.and_true]

#print axioms loop_arms_interior
#print axioms loop_arms_port
#print axioms loop_real_port

end GkatChainFragment
