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

/-! ## Consolidation and the Sum-level dichotomy

    Every value of a chain's state type is on the spine, so the positional
    arm facts consolidate into a single `spineNext` dichotomy, which lifts
    through `toGAut` (init state descends into the head) and `sumGAut`
    (tags ride along) to the fired-arm hypothesis of the orbit glue. -/

open Classical in
/-- Every value of a chain's state type lies on the state list. -/
theorem chain_exhaustive {body : Exp A T} (h : Chain body) :
    ∀ x : (certifiedThompson A T body).State,
      x ∈ (certifiedThompson A T body).aut.core.states := by
  induction h with
  | act p =>
      intro x
      show x ∈ [()]
      cases x
      exact List.mem_cons_self ..
  | @seq e f he hf ihe ihf =>
      intro x
      show x ∈ (certifiedThompson A T e).aut.core.states.map Sum.inl
        ++ (certifiedThompson A T f).aut.core.states.map Sum.inr
      cases x with
      | inl a =>
          exact List.mem_append.mpr
            (Or.inl (List.mem_map.mpr ⟨a, ihe a, rfl⟩))
      | inr a =>
          exact List.mem_append.mpr
            (Or.inr (List.mem_map.mpr ⟨a, ihf a, rfl⟩))

open Classical in
/-- **CONSOLIDATED LOOP DICHOTOMY**: every fired arm of the loop automaton
    follows `spineNext`. -/
theorem loop_arms_all {S' : Type} {B : InitializedGAut S' A T}
    (b : BExp T) {l : List S'} (hsp : ChainSpine B l) {first : S'}
    (hin : ChainInit B first) (hexh : ∀ x : S', x ∈ l) :
    ∀ s : S', ∀ t ∈ (loopInitialized b B).core.trans s,
      ∀ α : T → Bool, bval (genW T) t.1 α = true →
        t.2.2 = spineNext first l s := by
  intro s t ht α hb
  obtain ⟨j, hj, hjs⟩ := List.getElem_of_mem (hexh s)
  rcases Nat.lt_or_ge (j + 1) l.length with hint | hport
  · rw [← hjs] at ht ⊢
    rw [spineNext_at first l hsp j hint]
    exact loop_arms_interior b hsp j hint t ht α hb
  · have hj' : j = l.length - 1 := by omega
    subst hj'
    rw [← hjs] at ht ⊢
    rw [spineNext_last first l hsp (by omega)]
    exact loop_arms_port b hsp hin (by omega) t ht α hb

open Classical in
/-- Fired arms of the initialized loop automaton: the init state enters the
    head; core states follow `spineNext`. -/
theorem toGAut_chain_arms {S' : Type} {B : InitializedGAut S' A T}
    (b : BExp T) {l : List S'} (hsp : ChainSpine B l) {first : S'}
    (hin : ChainInit B first) (hexh : ∀ x : S', x ∈ l) :
    ∀ s : Option S', ∀ t ∈ (loopInitialized b B).toGAut.trans s,
      ∀ α : T → Bool, bval (genW T) t.1 α = true →
        (s = none ∧ t.2.2 = some first)
        ∨ (∃ u, s = some u ∧ t.2.2 = some (spineNext first l u)) := by
  intro s t ht α hb
  cases s with
  | none =>
      refine Or.inl ⟨rfl, ?_⟩
      obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp ht
      obtain ⟨t₁, ht₁, heq₁⟩ := List.mem_map.mp ht₀
      rw [← heq] at hb ⊢
      show some t₀.2.2 = some first
      rw [← heq₁] at hb ⊢
      show some t₁.2.2 = some first
      have hb' : (bval (genW T) b α && bval (genW T) t₁.1 α) = true := hb
      rw [Bool.and_eq_true] at hb'
      rw [hin.fired t₁ ht₁ α hb'.2]
  | some u =>
      refine Or.inr ⟨u, rfl, ?_⟩
      obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp ht
      rw [← heq] at hb ⊢
      show some t₀.2.2 = some (spineNext first l u)
      rw [loop_arms_all b hsp hin hexh u t₀ ht₀ α hb]

open Classical in
/-- **THE Σ-LEVEL FIRED DICHOTOMY** for a pair of chain loops: with rank 1
    on the two init states and 0 elsewhere, every fired arm follows the
    Sum-lifted spine successor or strictly descends. -/
theorem sum_chain_hdec {S₁ S₂ : Type}
    {B₁ : InitializedGAut S₁ A T} {B₂ : InitializedGAut S₂ A T}
    (b₁ b₂ : BExp T) {l₁ : List S₁} {l₂ : List S₂}
    (hsp₁ : ChainSpine B₁ l₁) (hsp₂ : ChainSpine B₂ l₂)
    {f₁ : S₁} {f₂ : S₂} (hin₁ : ChainInit B₁ f₁)
    (hin₂ : ChainInit B₂ f₂)
    (hexh₁ : ∀ x : S₁, x ∈ l₁) (hexh₂ : ∀ x : S₂, x ∈ l₂) :
    ∀ s, ∀ t ∈ (sumGAut (loopInitialized b₁ B₁).toGAut
        (loopInitialized b₂ B₂).toGAut).trans s,
      (∃ α : T → Bool, bval (genW T) t.1 α = true) →
      t.2.2 = Sum.elim
          (fun o => Sum.inl (o.map (spineNext f₁ l₁)))
          (fun o => Sum.inr (o.map (spineNext f₂ l₂))) s
      ∨ Sum.elim (fun o => if o.isSome then 0 else 1)
            (fun o => if o.isSome then 0 else 1) t.2.2
          < Sum.elim (fun o => if o.isSome then 0 else 1)
            (fun o => if o.isSome then 0 else 1) s := by
  intro s t ht hex
  obtain ⟨α, hb⟩ := hex
  cases s with
  | inl o =>
      obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp ht
      rw [← heq] at hb ⊢
      rcases toGAut_chain_arms b₁ hsp₁ hin₁ hexh₁ o t₀ ht₀ α hb with
        ⟨ho, htt⟩ | ⟨u, ho, htt⟩
      · subst ho
        refine Or.inr ?_
        rw [htt]
        show (0 : Nat) < 1
        omega
      · subst ho
        refine Or.inl ?_
        rw [htt]
        rfl
  | inr o =>
      obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp ht
      rw [← heq] at hb ⊢
      rcases toGAut_chain_arms b₂ hsp₂ hin₂ hexh₂ o t₀ ht₀ α hb with
        ⟨ho, htt⟩ | ⟨u, ho, htt⟩
      · subst ho
        refine Or.inr ?_
        rw [htt]
        show (0 : Nat) < 1
        omega
      · subst ho
        refine Or.inl ?_
        rw [htt]
        rfl

open Classical in
/-- The Sum-lifted spine successor preserves the 0/1 rank. -/
theorem sum_chain_nxt_rank {S₁ S₂ : Type}
    (g₁ : S₁ → S₁) (g₂ : S₂ → S₂) :
    ∀ s : Sum (Option S₁) (Option S₂),
      Sum.elim (fun o => if o.isSome then 0 else 1)
        (fun o => if o.isSome then 0 else 1)
        (Sum.elim (fun o => Sum.inl (o.map g₁))
          (fun o => Sum.inr (o.map g₂)) s)
      = Sum.elim (fun o => if o.isSome then 0 else 1)
          (fun o => if o.isSome then 0 else 1) s := by
  intro s
  cases s with
  | inl o => cases o <;> rfl
  | inr o => cases o <;> rfl

#print axioms chain_exhaustive
#print axioms sum_chain_hdec
#print axioms sum_chain_nxt_rank

/-! ## Trim transparency and run embeddings

    At a state whose arm targets are all live, trimming is invisible: no
    arm is dropped, the accumulated dead guard stays `0`, and the trimmed
    guards `g ∧ ¬0` fire exactly as `g`.  Runs embed across `sumGAut` and
    `toGAut` step by step — the transport that carries spine liveness and
    firing up to the composite the orbit glue works on. -/

open Classical in
private theorem trimList_cons₄ (aut : GAut S A T) (g : BExp T) (a : A)
    (t : S) (rest : List (BExp T × A × S)) (D : BExp T) :
    trimList aut ((g, a, t) :: rest) D
      = if Live aut t then (.and g (.not D), a, t) :: trimList aut rest D
        else trimList aut rest (.or D g) := rfl

open Classical in
private theorem fm_cons₄ {Atom : Type} (V : T → Atom → Bool) (x : Atom)
    (g : BExp T) (a : A) (t : S) (rest : List (BExp T × A × S)) :
    firstMatch V x ((g, a, t) :: rest)
      = if bval V g x = true then some (a, t)
        else firstMatch V x rest := rfl

open Classical in
/-- All-live trimming is an explicit guard conjunction. -/
theorem trimList_all_live (aut : GAut S A T) :
    ∀ (L : List (BExp T × A × S)) (D : BExp T),
      (∀ e ∈ L, Live aut e.2.2) →
      trimList aut L D
        = L.map (fun e => (.and e.1 (.not D), e.2.1, e.2.2)) := by
  intro L
  induction L with
  | nil => intro D _; rfl
  | cons hd rest ih =>
      intro D hall
      obtain ⟨g, a, t⟩ := hd
      rw [trimList_cons₄,
          if_pos (hall (g, a, t) (List.mem_cons_self ..)),
          ih D (fun e he => hall e (List.mem_cons_of_mem _ he))]
      rfl

open Classical in
/-- Conjoining `¬0` changes no firing. -/
theorem firstMatch_guard_conj_notzero {Atom : Type} (V : T → Atom → Bool)
    (x : Atom) :
    ∀ L : List (BExp T × A × S),
      firstMatch V x
          (L.map (fun e => ((.and e.1 (.not .zero) : BExp T),
            e.2.1, e.2.2)))
        = firstMatch V x L := by
  intro L
  induction L with
  | nil => rfl
  | cons hd rest ih =>
      obtain ⟨g, a, t⟩ := hd
      rw [List.map_cons, fm_cons₄, fm_cons₄]
      have hg : bval V (.and g (.not .zero)) x = bval V g x := by
        show (bval V g x && !(false : Bool)) = bval V g x
        cases bval V g x <;> rfl
      rw [hg, ih]

open Classical in
/-- **TRIM TRANSPARENCY**: at a state whose arm targets are all live, the
    trimmed automaton steps exactly as the raw automaton — at every
    valuation. -/
theorem autStep_trimAut_all_live {Atom : Type} (V : T → Atom → Bool)
    (aut : GAut S A T) (s : S)
    (hall : ∀ e ∈ aut.trans s, Live aut e.2.2) (x : Atom) :
    autStep V (trimAut aut) s x = autStep V aut s x := by
  show firstMatch V x (trimList aut (aut.trans s) .zero)
    = firstMatch V x (aut.trans s)
  rw [trimList_all_live aut (aut.trans s) .zero hall]
  exact firstMatch_guard_conj_notzero V x (aut.trans s)

open Classical in
/-- One-step behavior through `toGAut` at internal states. -/
theorem autStep_toGAut_some {S' Atom : Type} (V : T → Atom → Bool)
    (W : InitializedGAut S' A T) (u : S') (x : Atom) :
    autStep V W.toGAut (some u) x
      = (firstMatch V x (W.core.trans u)).map
          (fun o => (o.1, some o.2)) := by
  show firstMatch V x ((W.core.trans u).map
    (fun t => (t.1, t.2.1, some t.2.2))) = _
  exact firstMatch_map_target_to V x some (W.core.trans u)

open Classical in
/-- A left-summand run is a sum run. -/
theorem autRun_sumGAut_inl {S₁ S₂ Atom : Type} (V : T → Atom → Bool)
    (aut₁ : GAut S₁ A T) (aut₂ : GAut S₂ A T) :
    ∀ (w : List (A × Atom)) (s : S₁) (x : Atom),
      autRun V (sumGAut aut₁ aut₂) (Sum.inl s) x w
        ↔ autRun V aut₁ s x w := by
  intro w
  induction w with
  | nil => intro s x; exact Iff.rfl
  | cons qa w' ih =>
      intro s x
      obtain ⟨q, x'⟩ := qa
      constructor
      · rintro ⟨s', hstep, hrun⟩
        rw [autStep_sumGAut_inl] at hstep
        cases h1 : autStep V aut₁ s x with
        | none =>
            rw [h1] at hstep
            exact nomatch hstep
        | some o =>
            obtain ⟨a₀, t₀⟩ := o
            rw [h1] at hstep
            have hinj := Option.some.inj hstep
            rw [Prod.mk.injEq] at hinj
            obtain ⟨hq, hs'⟩ := hinj
            refine ⟨t₀, ?_, ?_⟩
            · have hq' : a₀ = q := hq
              rw [h1, hq']
            · rw [← hs'] at hrun
              exact (ih t₀ x').mp hrun
      · rintro ⟨t₀, hstep, hrun⟩
        refine ⟨Sum.inl t₀, ?_, ?_⟩
        · rw [autStep_sumGAut_inl, hstep]
          rfl
        · exact (ih t₀ x').mpr hrun

open Classical in
/-- A right-summand run is a sum run. -/
theorem autRun_sumGAut_inr {S₁ S₂ Atom : Type} (V : T → Atom → Bool)
    (aut₁ : GAut S₁ A T) (aut₂ : GAut S₂ A T) :
    ∀ (w : List (A × Atom)) (s : S₂) (x : Atom),
      autRun V (sumGAut aut₁ aut₂) (Sum.inr s) x w
        ↔ autRun V aut₂ s x w := by
  intro w
  induction w with
  | nil => intro s x; exact Iff.rfl
  | cons qa w' ih =>
      intro s x
      obtain ⟨q, x'⟩ := qa
      constructor
      · rintro ⟨s', hstep, hrun⟩
        rw [autStep_sumGAut_inr] at hstep
        cases h1 : autStep V aut₂ s x with
        | none =>
            rw [h1] at hstep
            exact nomatch hstep
        | some o =>
            obtain ⟨a₀, t₀⟩ := o
            rw [h1] at hstep
            have hinj := Option.some.inj hstep
            rw [Prod.mk.injEq] at hinj
            obtain ⟨hq, hs'⟩ := hinj
            refine ⟨t₀, ?_, ?_⟩
            · have hq' : a₀ = q := hq
              rw [h1, hq']
            · rw [← hs'] at hrun
              exact (ih t₀ x').mp hrun
      · rintro ⟨t₀, hstep, hrun⟩
        refine ⟨Sum.inr t₀, ?_, ?_⟩
        · rw [autStep_sumGAut_inr, hstep]
          rfl
        · exact (ih t₀ x').mpr hrun

open Classical in
/-- The core of an initialized automaton as a pointed automaton. -/
noncomputable def coreAut {S' : Type} (W : InitializedGAut S' A T)
    (start : S') : GAut S' A T where
  states := W.core.states
  hlt := W.core.hlt
  trans := W.core.trans
  start := start

open Classical in
/-- An internal run through `toGAut` is a core run. -/
theorem autRun_toGAut_some {S' Atom : Type} (V : T → Atom → Bool)
    (W : InitializedGAut S' A T) (start : S') :
    ∀ (w : List (A × Atom)) (u : S') (x : Atom),
      autRun V W.toGAut (some u) x w
        ↔ autRun V (coreAut W start) u x w := by
  intro w
  induction w with
  | nil => intro u x; exact Iff.rfl
  | cons qa w' ih =>
      intro u x
      obtain ⟨q, x'⟩ := qa
      constructor
      · rintro ⟨s', hstep, hrun⟩
        rw [autStep_toGAut_some] at hstep
        cases h1 : firstMatch V x (W.core.trans u) with
        | none =>
            rw [h1] at hstep
            exact nomatch hstep
        | some o =>
            obtain ⟨a₀, t₀⟩ := o
            rw [h1] at hstep
            have hinj := Option.some.inj hstep
            rw [Prod.mk.injEq] at hinj
            obtain ⟨hq, hs'⟩ := hinj
            refine ⟨t₀, ?_, ?_⟩
            · show firstMatch V x (W.core.trans u) = some (q, t₀)
              have hq' : a₀ = q := hq
              rw [h1, hq']
            · rw [← hs'] at hrun
              exact (ih t₀ x').mp hrun
      · rintro ⟨t₀, hstep, hrun⟩
        refine ⟨some t₀, ?_, ?_⟩
        · rw [autStep_toGAut_some]
          have hstep' : firstMatch V x (W.core.trans u) = some (q, t₀) :=
            hstep
          rw [hstep']
          rfl
        · exact (ih t₀ x').mpr hrun

#print axioms autStep_trimAut_all_live
#print axioms autRun_sumGAut_inl
#print axioms autRun_toGAut_some

/-! ## Deterministic steps and spine liveness

    The loop's interior steps deterministically at EVERY atom; the port
    feeds back under `b`.  With the exit satisfiable, every spine state
    runs forward to the port and exits — liveness, lifted through the
    embeddings to the composite sum automaton. -/

open Classical in
/-- A firing arm with all firing arms agreeing pins `firstMatch`. -/
theorem firstMatch_some_target {Atom : Type} (V : T → Atom → Bool)
    (x : Atom) :
    ∀ (L : List (BExp T × A × S)) (v : S),
      (∃ t ∈ L, bval V t.1 x = true) →
      (∀ t ∈ L, bval V t.1 x = true → t.2.2 = v) →
      ∃ a, firstMatch V x L = some (a, v) := by
  intro L
  induction L with
  | nil =>
      intro v hex _
      obtain ⟨t, ht, -⟩ := hex
      exact nomatch ht
  | cons hd rest ih =>
      intro v hex hall
      obtain ⟨g, a, t⟩ := hd
      by_cases hb : bval V g x = true
      · refine ⟨a, ?_⟩
        rw [fm_cons₄, if_pos hb]
        have htv : t = v := hall (g, a, t) (List.mem_cons_self ..) hb
        rw [htv]
      · obtain ⟨t', ht', hbt'⟩ := hex
        rcases List.mem_cons.mp ht' with heq | hmem
        · exfalso
          rw [heq] at hbt'
          exact hb hbt'
        · obtain ⟨a', hfm⟩ := ih v ⟨t', hmem, hbt'⟩
            (fun t'' ht'' hb'' =>
              hall t'' (List.mem_cons_of_mem _ ht'') hb'')
          refine ⟨a', ?_⟩
          rw [fm_cons₄, if_neg hb]
          exact hfm

open Classical in
/-- **DETERMINISTIC INTERIOR STEP**: at every atom, the loop steps from
    the `j`-th spine state to the `j+1`-st. -/
theorem loop_step_interior {S' : Type} {B : InitializedGAut S' A T}
    (b : BExp T) {l : List S'} (hsp : ChainSpine B l)
    (j : Nat) (h1 : j + 1 < l.length) :
    ∀ α : T → Bool, ∃ a : A,
      firstMatch (genW T) α
          ((loopInitialized b B).core.trans (l[j]'(by omega)))
        = some (a, l[j + 1]'h1) := by
  intro α
  obtain ⟨t, ht, htg, htt⟩ := loop_real_interior b hsp j h1
  exact firstMatch_some_target (genW T) α _ _
    ⟨t, ht, htg α⟩
    (fun t' ht' hb' => loop_arms_interior b hsp j h1 t' ht' α hb')

open Classical in
/-- **PORT STEP UNDER `b`**: the loop feeds back to the head. -/
theorem loop_step_port {S' : Type} {B : InitializedGAut S' A T}
    (b : BExp T) {l : List S'} (hsp : ChainSpine B l) {first : S'}
    (hin : ChainInit B first) (h0 : 0 < l.length)
    (α : T → Bool) (hb : bval (genW T) b α = true) :
    ∃ a : A,
      firstMatch (genW T) α
          ((loopInitialized b B).core.trans (l[l.length - 1]'(by omega)))
        = some (a, first) := by
  obtain ⟨t, ht, htg, htt⟩ := loop_real_port b hsp hin h0
  refine firstMatch_some_target (genW T) α _ _ ⟨t, ht, ?_⟩
    (fun t' ht' hb' => loop_arms_port b hsp hin h0 t' ht' α hb')
  rw [htg α]
  exact hb

open Classical in
/-- **SPINE LIVENESS** (core level): with the exit satisfiable, every
    spine state accepts a word — run forward to the port and exit. -/
theorem spine_live_core {S' : Type} {B : InitializedGAut S' A T}
    (b : BExp T) {l : List S'} (hsp : ChainSpine B l) (first : S')
    (hexit : ∃ α : T → Bool, bval (genW T) b α = false) :
    ∀ k j (hjk : j + k + 1 = l.length),
      ∃ (β : T → Bool) (w : List (A × (T → Bool))),
        autRun (genW T) (coreAut (loopInitialized b B) first)
          (l[j]'(by omega)) β w := by
  intro k
  induction k with
  | zero =>
      intro j hjk
      obtain ⟨αe, hαe⟩ := hexit
      refine ⟨αe, [], ?_⟩
      show bval (genW T)
        ((loopInitialized b B).core.hlt (l[j]'(by omega))) αe = true
      have hj : j = l.length - 1 := by omega
      subst hj
      rw [loop_hlt_port b hsp (by omega) αe, hαe]
      rfl
  | succ k ih =>
      intro j hjk
      obtain ⟨β, w, hrun⟩ := ih (j + 1) (by omega)
      obtain ⟨a, hstep⟩ := loop_step_interior b hsp j (by omega) β
      refine ⟨β, (a, β) :: w, ?_⟩
      exact ⟨l[j + 1]'(by omega), hstep, hrun⟩

open Classical in
/-- **SPINE LIVENESS IN THE COMPOSITE** (left summand). -/
theorem spine_live_sum_inl {S₁ S₂ : Type} {B : InitializedGAut S₁ A T}
    (b : BExp T) {l : List S₁} (hsp : ChainSpine B l) (first : S₁)
    (aut₂ : GAut (Option S₂) A T)
    (hexit : ∃ α : T → Bool, bval (genW T) b α = false) :
    ∀ j (hj : j < l.length),
      Live (sumGAut (loopInitialized b B).toGAut aut₂)
        (Sum.inl (some (l[j]'hj))) := by
  intro j hj
  obtain ⟨β, w, hrun⟩ := spine_live_core b hsp first hexit
    (l.length - 1 - j) j (by omega)
  refine ⟨β, w, ?_⟩
  rw [autRun_sumGAut_inl, autRun_toGAut_some (start := first)]
  exact hrun

open Classical in
/-- **SPINE LIVENESS IN THE COMPOSITE** (right summand). -/
theorem spine_live_sum_inr {S₁ S₂ : Type} {B : InitializedGAut S₂ A T}
    (b : BExp T) {l : List S₂} (hsp : ChainSpine B l) (first : S₂)
    (aut₁ : GAut (Option S₁) A T)
    (hexit : ∃ α : T → Bool, bval (genW T) b α = false) :
    ∀ j (hj : j < l.length),
      Live (sumGAut aut₁ (loopInitialized b B).toGAut)
        (Sum.inr (some (l[j]'hj))) := by
  intro j hj
  obtain ⟨β, w, hrun⟩ := spine_live_core b hsp first hexit
    (l.length - 1 - j) j (by omega)
  refine ⟨β, w, ?_⟩
  rw [autRun_sumGAut_inr, autRun_toGAut_some (start := first)]
  exact hrun

#print axioms loop_step_interior
#print axioms loop_step_port
#print axioms spine_live_sum_inl

/-! ## Trim-level steps in the composite

    All loop-arm targets stay on the spine (certificate structural facts),
    all spine states are live, so trimming is transparent at every loop
    state of the composite — the deterministic steps and the silent
    interiors reach the trimmed sum automaton, which is exactly where
    `rankNxt_quot_solvesBA`'s `hfire`, `hstep_uniq` (`interior_no_desc`),
    and `hnoeps` live. -/

open Classical in
/-- Loop-arm targets stay on the spine. -/
theorem loop_targets_spine {S' : Type} {B : InitializedGAut S' A T}
    (b : BExp T) {l : List S'}
    (hct : CoreTargetsListed B) (hit : InitTargetsListed B)
    (hstates : B.core.states = l) (hexh : ∀ x : S', x ∈ l) :
    ∀ x : S', ∀ t ∈ (loopInitialized b B).core.trans x, t.2.2 ∈ l := by
  intro x t ht
  rcases List.mem_append.mp ht with hB | hF
  · have := hct x (by rw [hstates]; exact hexh x) t hB
    rw [hstates] at this
    exact this
  · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hF
    have := hit t₀ ht₀
    rw [hstates] at this
    rw [← heq]
    exact this

open Classical in
/-- Any spine member is live in the composite (left summand). -/
theorem spine_mem_live_inl {S₁ S₂ : Type} {B : InitializedGAut S₁ A T}
    (b : BExp T) {l : List S₁} (hsp : ChainSpine B l) (first : S₁)
    (aut₂ : GAut (Option S₂) A T)
    (hexit : ∃ α : T → Bool, bval (genW T) b α = false)
    {x : S₁} (hx : x ∈ l) :
    Live (sumGAut (loopInitialized b B).toGAut aut₂)
      (Sum.inl (some x)) := by
  obtain ⟨j, hj, hjx⟩ := List.getElem_of_mem hx
  rw [← hjx]
  exact spine_live_sum_inl b hsp first aut₂ hexit j hj

open Classical in
/-- All composite arms at a loop state have live targets. -/
theorem sum_targets_live_inl {S₁ S₂ : Type} {B : InitializedGAut S₁ A T}
    (b : BExp T) {l : List S₁} (hsp : ChainSpine B l) (first : S₁)
    (aut₂ : GAut (Option S₂) A T)
    (hct : CoreTargetsListed B) (hit : InitTargetsListed B)
    (hstates : B.core.states = l) (hexh : ∀ x : S₁, x ∈ l)
    (hexit : ∃ α : T → Bool, bval (genW T) b α = false) (x : S₁) :
    ∀ e ∈ (sumGAut (loopInitialized b B).toGAut aut₂).trans
        (Sum.inl (some x)),
      Live (sumGAut (loopInitialized b B).toGAut aut₂) e.2.2 := by
  intro e he
  obtain ⟨t₁, ht₁, heq₁⟩ := List.mem_map.mp he
  obtain ⟨t₀, ht₀, heq₀⟩ := List.mem_map.mp ht₁
  rw [← heq₁, ← heq₀]
  show Live _ (Sum.inl (some t₀.2.2))
  exact spine_mem_live_inl b hsp first aut₂ hexit
    (loop_targets_spine b hct hit hstates hexh x t₀ ht₀)

open Classical in
/-- **TRIM-LEVEL INTERIOR STEP**: in the trimmed composite, interior loop
    states step deterministically to their successor at every atom. -/
theorem sum_chain_step_interior {S₁ S₂ : Type}
    {B : InitializedGAut S₁ A T}
    (b : BExp T) {l : List S₁} (hsp : ChainSpine B l) (first : S₁)
    (aut₂ : GAut (Option S₂) A T)
    (hct : CoreTargetsListed B) (hit : InitTargetsListed B)
    (hstates : B.core.states = l) (hexh : ∀ x : S₁, x ∈ l)
    (hexit : ∃ α : T → Bool, bval (genW T) b α = false)
    (j : Nat) (h1 : j + 1 < l.length) :
    ∀ α : T → Bool, ∃ a : A,
      autStep (genW T)
          (trimAut (sumGAut (loopInitialized b B).toGAut aut₂))
          (Sum.inl (some (l[j]'(by omega)))) α
        = some (a, Sum.inl (some (l[j + 1]'h1))) := by
  intro α
  obtain ⟨a, hstep⟩ := loop_step_interior b hsp j h1 α
  refine ⟨a, ?_⟩
  rw [autStep_trimAut_all_live (genW T) _ _
    (sum_targets_live_inl b hsp first aut₂ hct hit hstates hexh hexit
      (l[j]'(by omega))) α]
  rw [autStep_sumGAut_inl, autStep_toGAut_some]
  rw [show firstMatch (genW T) α
      ((loopInitialized b B).core.trans (l[j]'(by omega)))
    = some (a, l[j + 1]'h1) from hstep]
  rfl

open Classical in
/-- **TRIM-LEVEL PORT STEP**: under `b`, the trimmed composite feeds the
    port back to the head. -/
theorem sum_chain_step_port {S₁ S₂ : Type}
    {B : InitializedGAut S₁ A T}
    (b : BExp T) {l : List S₁} (hsp : ChainSpine B l) {first : S₁}
    (hin : ChainInit B first)
    (aut₂ : GAut (Option S₂) A T)
    (hct : CoreTargetsListed B) (hit : InitTargetsListed B)
    (hstates : B.core.states = l) (hexh : ∀ x : S₁, x ∈ l)
    (hexit : ∃ α : T → Bool, bval (genW T) b α = false)
    (h0 : 0 < l.length)
    (α : T → Bool) (hb : bval (genW T) b α = true) :
    ∃ a : A,
      autStep (genW T)
          (trimAut (sumGAut (loopInitialized b B).toGAut aut₂))
          (Sum.inl (some (l[l.length - 1]'(by omega)))) α
        = some (a, Sum.inl (some first)) := by
  obtain ⟨a, hstep⟩ := loop_step_port b hsp hin h0 α hb
  refine ⟨a, ?_⟩
  rw [autStep_trimAut_all_live (genW T) _ _
    (sum_targets_live_inl b hsp first aut₂ hct hit hstates hexh hexit
      (l[l.length - 1]'(by omega))) α]
  rw [autStep_sumGAut_inl, autStep_toGAut_some]
  rw [show firstMatch (genW T) α
      ((loopInitialized b B).core.trans (l[l.length - 1]'(by omega)))
    = some (a, first) from hstep]
  rfl

open Classical in
/-- **TRIM-LEVEL INTERIOR SILENCE**: interior loop states accept no empty
    word in the trimmed composite. -/
theorem sum_chain_noeps {S₁ S₂ : Type} {B : InitializedGAut S₁ A T}
    (b : BExp T) {l : List S₁} (hsp : ChainSpine B l)
    (aut₂ : GAut (Option S₂) A T)
    (j : Nat) (h1 : j + 1 < l.length) :
    ∀ α : T → Bool,
      ¬ autRun (genW T)
          (trimAut (sumGAut (loopInitialized b B).toGAut aut₂))
          (Sum.inl (some (l[j]'(by omega)))) α [] := by
  intro α h
  have h' : bval (genW T)
      ((loopInitialized b B).core.hlt (l[j]'(by omega))) α = true := h
  rw [loop_hlt_int b hsp j h1 α] at h'
  exact nomatch h'

#print axioms sum_chain_step_interior
#print axioms sum_chain_step_port
#print axioms sum_chain_noeps

/-! ## Port-based walks, lifts, and the composite `hfire`

    The orbit bundle is based at the PORT.  Iteration from the port walks
    the spine (`spine_iter_port`), closes after `length` steps, and never
    fixes below the period.  `nxtIter` commutes with the `Sum`/`Option`
    lift, and every composite state with a moving successor fires to it —
    the global `hfire` of `rankNxt_quot_solvesBA`. -/

open Classical in
theorem nxtIter_lift_inl {S₁ S₂ : Type} (g₁ : S₁ → S₁) (g₂ : S₂ → S₂) :
    ∀ (k : Nat) (x : S₁),
      nxtIter (Sum.elim (fun o : Option S₁ => Sum.inl (o.map g₁))
        (fun o : Option S₂ => Sum.inr (o.map g₂))) k (Sum.inl (some x))
        = Sum.inl (some (nxtIter g₁ k x)) := by
  intro k
  induction k with
  | zero => intro x; rfl
  | succ k ih =>
      intro x
      have h : nxtIter (Sum.elim
          (fun o : Option S₁ => Sum.inl (o.map g₁))
          (fun o : Option S₂ => Sum.inr (o.map g₂))) (k + 1)
          (Sum.inl (some x))
          = Sum.elim (fun o : Option S₁ => Sum.inl (o.map g₁))
            (fun o : Option S₂ => Sum.inr (o.map g₂))
            (nxtIter (Sum.elim
              (fun o : Option S₁ => Sum.inl (o.map g₁))
              (fun o : Option S₂ => Sum.inr (o.map g₂))) k
              (Sum.inl (some x))) := rfl
      rw [h, ih x]
      rfl

open Classical in
theorem nxtIter_lift_inr {S₁ S₂ : Type} (g₁ : S₁ → S₁) (g₂ : S₂ → S₂) :
    ∀ (k : Nat) (x : S₂),
      nxtIter (Sum.elim (fun o : Option S₁ => Sum.inl (o.map g₁))
        (fun o : Option S₂ => Sum.inr (o.map g₂))) k (Sum.inr (some x))
        = Sum.inr (some (nxtIter g₂ k x)) := by
  intro k
  induction k with
  | zero => intro x; rfl
  | succ k ih =>
      intro x
      have h : nxtIter (Sum.elim
          (fun o : Option S₁ => Sum.inl (o.map g₁))
          (fun o : Option S₂ => Sum.inr (o.map g₂))) (k + 1)
          (Sum.inr (some x))
          = Sum.elim (fun o : Option S₁ => Sum.inl (o.map g₁))
            (fun o : Option S₂ => Sum.inr (o.map g₂))
            (nxtIter (Sum.elim
              (fun o : Option S₁ => Sum.inl (o.map g₁))
              (fun o : Option S₂ => Sum.inr (o.map g₂))) k
              (Sum.inr (some x))) := rfl
      rw [h, ih x]
      rfl

open Classical in
/-- Iteration from the port walks the spine. -/
theorem spine_iter_port {S' : Type} {B : InitializedGAut S' A T}
    {l : List S'} (hsp : ChainSpine B l) {first : S'}
    (h0 : 0 < l.length) (hfl : l[0]'h0 = first) :
    ∀ j (hj : j < l.length),
      nxtIter (spineNext first l) (j + 1) (l[l.length - 1]'(by omega))
        = l[j]'hj := by
  intro j hj
  rw [show j + 1 = 1 + j from by omega, nxtIter_add]
  have h1 : nxtIter (spineNext first l) 1 (l[l.length - 1]'(by omega))
      = first := by
    show spineNext first l (l[l.length - 1]'(by omega)) = first
    exact spineNext_last first l hsp h0
  have h2 := spine_iter first hsp j hj h0
  rw [hfl] at h2
  rw [h1]
  exact h2

open Classical in
/-- The port's walk closes after `length` steps. -/
theorem spine_period_port {S' : Type} {B : InitializedGAut S' A T}
    {l : List S'} (hsp : ChainSpine B l) {first : S'}
    (h0 : 0 < l.length) (hfl : l[0]'h0 = first) :
    nxtIter (spineNext first l) l.length (l[l.length - 1]'(by omega))
      = l[l.length - 1]'(by omega) := by
  have h := spine_iter_port hsp h0 hfl (l.length - 1) (by omega)
  rw [show l.length - 1 + 1 = l.length from by omega] at h
  exact h

open Classical in
/-- Below the period, the port's walk never fixes. -/
theorem spine_nofix_port {S' : Type} {B : InitializedGAut S' A T}
    {l : List S'} (hsp : ChainSpine B l) {first : S'}
    (hlen2 : 2 ≤ l.length) (hfl : l[0]'(by omega) = first) :
    ∀ j, j < l.length →
      spineNext first l
          (nxtIter (spineNext first l) j (l[l.length - 1]'(by omega)))
        ≠ nxtIter (spineNext first l) j (l[l.length - 1]'(by omega)) := by
  intro j hj
  cases j with
  | zero =>
      show spineNext first l (l[l.length - 1]'(by omega))
        ≠ l[l.length - 1]'(by omega)
      rw [spineNext_last first l hsp (by omega), ← hfl]
      exact spine_distinct l hsp 0 (l.length - 1)
        (by omega) (by omega) (by omega)
  | succ j =>
      have hj1 : j + 1 < l.length := hj
      rw [spine_iter_port hsp (by omega) hfl j (by omega)]
      rw [spineNext_at first l hsp j hj1]
      exact (spine_distinct l hsp j (j + 1) (by omega) hj1
        (by omega)).symm

open Classical in
/-- Right-summand mirror: all composite arm targets at a loop state are
    live. -/
theorem sum_targets_live_inr {S₁ S₂ : Type} {B : InitializedGAut S₂ A T}
    (b : BExp T) {l : List S₂} (hsp : ChainSpine B l) (first : S₂)
    (aut₁ : GAut (Option S₁) A T)
    (hct : CoreTargetsListed B) (hit : InitTargetsListed B)
    (hstates : B.core.states = l) (hexh : ∀ x : S₂, x ∈ l)
    (hexit : ∃ α : T → Bool, bval (genW T) b α = false) (x : S₂) :
    ∀ e ∈ (sumGAut aut₁ (loopInitialized b B).toGAut).trans
        (Sum.inr (some x)),
      Live (sumGAut aut₁ (loopInitialized b B).toGAut) e.2.2 := by
  intro e he
  obtain ⟨t₁, ht₁, heq₁⟩ := List.mem_map.mp he
  obtain ⟨t₀, ht₀, heq₀⟩ := List.mem_map.mp ht₁
  rw [← heq₁, ← heq₀]
  show Live _ (Sum.inr (some t₀.2.2))
  have hmem := loop_targets_spine b hct hit hstates hexh x t₀ ht₀
  obtain ⟨j, hj, hjx⟩ := List.getElem_of_mem hmem
  rw [← hjx]
  exact spine_live_sum_inr b hsp first aut₁ hexit j hj

open Classical in
/-- Right-summand mirror of the trim-level interior step. -/
theorem sum_chain_step_interior_inr {S₁ S₂ : Type}
    {B : InitializedGAut S₂ A T}
    (b : BExp T) {l : List S₂} (hsp : ChainSpine B l) (first : S₂)
    (aut₁ : GAut (Option S₁) A T)
    (hct : CoreTargetsListed B) (hit : InitTargetsListed B)
    (hstates : B.core.states = l) (hexh : ∀ x : S₂, x ∈ l)
    (hexit : ∃ α : T → Bool, bval (genW T) b α = false)
    (j : Nat) (h1 : j + 1 < l.length) :
    ∀ α : T → Bool, ∃ a : A,
      autStep (genW T)
          (trimAut (sumGAut aut₁ (loopInitialized b B).toGAut))
          (Sum.inr (some (l[j]'(by omega)))) α
        = some (a, Sum.inr (some (l[j + 1]'h1))) := by
  intro α
  obtain ⟨a, hstep⟩ := loop_step_interior b hsp j h1 α
  refine ⟨a, ?_⟩
  rw [autStep_trimAut_all_live (genW T) _ _
    (sum_targets_live_inr b hsp first aut₁ hct hit hstates hexh hexit
      (l[j]'(by omega))) α]
  rw [autStep_sumGAut_inr, autStep_toGAut_some]
  rw [show firstMatch (genW T) α
      ((loopInitialized b B).core.trans (l[j]'(by omega)))
    = some (a, l[j + 1]'h1) from hstep]
  rfl

open Classical in
/-- Right-summand mirror of the trim-level port step. -/
theorem sum_chain_step_port_inr {S₁ S₂ : Type}
    {B : InitializedGAut S₂ A T}
    (b : BExp T) {l : List S₂} (hsp : ChainSpine B l) {first : S₂}
    (hin : ChainInit B first)
    (aut₁ : GAut (Option S₁) A T)
    (hct : CoreTargetsListed B) (hit : InitTargetsListed B)
    (hstates : B.core.states = l) (hexh : ∀ x : S₂, x ∈ l)
    (hexit : ∃ α : T → Bool, bval (genW T) b α = false)
    (h0 : 0 < l.length)
    (α : T → Bool) (hb : bval (genW T) b α = true) :
    ∃ a : A,
      autStep (genW T)
          (trimAut (sumGAut aut₁ (loopInitialized b B).toGAut))
          (Sum.inr (some (l[l.length - 1]'(by omega)))) α
        = some (a, Sum.inr (some first)) := by
  obtain ⟨a, hstep⟩ := loop_step_port b hsp hin h0 α hb
  refine ⟨a, ?_⟩
  rw [autStep_trimAut_all_live (genW T) _ _
    (sum_targets_live_inr b hsp first aut₁ hct hit hstates hexh hexit
      (l[l.length - 1]'(by omega))) α]
  rw [autStep_sumGAut_inr, autStep_toGAut_some]
  rw [show firstMatch (genW T) α
      ((loopInitialized b B).core.trans (l[l.length - 1]'(by omega)))
    = some (a, first) from hstep]
  rfl

open Classical in
/-- **THE COMPOSITE hfire**: every state with a moving lifted successor
    fires to it at some atom, in the trimmed composite. -/
theorem sum_chain_hfire {S₁ S₂ : Type}
    {B₁ : InitializedGAut S₁ A T} {B₂ : InitializedGAut S₂ A T}
    (b₁ b₂ : BExp T) {l₁ : List S₁} {l₂ : List S₂}
    (hsp₁ : ChainSpine B₁ l₁) (hsp₂ : ChainSpine B₂ l₂)
    {f₁ : S₁} {f₂ : S₂} (hin₁ : ChainInit B₁ f₁)
    (hin₂ : ChainInit B₂ f₂)
    (hct₁ : CoreTargetsListed B₁) (hit₁ : InitTargetsListed B₁)
    (hct₂ : CoreTargetsListed B₂) (hit₂ : InitTargetsListed B₂)
    (hstates₁ : B₁.core.states = l₁) (hstates₂ : B₂.core.states = l₂)
    (hexh₁ : ∀ x : S₁, x ∈ l₁) (hexh₂ : ∀ x : S₂, x ∈ l₂)
    (hexit₁ : ∃ α : T → Bool, bval (genW T) b₁ α = false)
    (hexit₂ : ∃ α : T → Bool, bval (genW T) b₂ α = false)
    (hbsat₁ : ∃ α : T → Bool, bval (genW T) b₁ α = true)
    (hbsat₂ : ∃ α : T → Bool, bval (genW T) b₂ α = true)
    (hfl₁ : ∀ (h : 0 < l₁.length), l₁[0]'h = f₁)
    (hfl₂ : ∀ (h : 0 < l₂.length), l₂[0]'h = f₂) :
    ∀ s, Live (trimAut (sumGAut (loopInitialized b₁ B₁).toGAut
        (loopInitialized b₂ B₂).toGAut)) s →
      Sum.elim (fun o => Sum.inl (o.map (spineNext f₁ l₁)))
        (fun o => Sum.inr (o.map (spineNext f₂ l₂))) s ≠ s →
      ∃ (α : T → Bool) (a : A),
        autStep (genW T)
            (trimAut (sumGAut (loopInitialized b₁ B₁).toGAut
              (loopInitialized b₂ B₂).toGAut)) s α
          = some (a, Sum.elim
              (fun o => Sum.inl (o.map (spineNext f₁ l₁)))
              (fun o => Sum.inr (o.map (spineNext f₂ l₂))) s) := by
  intro s hlive hne
  cases s with
  | inl o =>
      cases o with
      | none => exact absurd rfl hne
      | some x =>
          obtain ⟨j, hj, hjx⟩ := List.getElem_of_mem (hexh₁ x)
          subst hjx
          rcases Nat.lt_or_ge (j + 1) l₁.length with hint | hport
          · obtain ⟨a, hstep⟩ := sum_chain_step_interior b₁ hsp₁ f₁ _
              hct₁ hit₁ hstates₁ hexh₁ hexit₁ j hint (fun _ => true)
            refine ⟨fun _ => true, a, ?_⟩
            show _ = some (a, Sum.inl (some (spineNext f₁ l₁
              (l₁[j]'hj))))
            rw [spineNext_at f₁ l₁ hsp₁ j hint]
            exact hstep
          · have hj' : j = l₁.length - 1 := by omega
            subst hj'
            rcases Nat.lt_or_ge 1 l₁.length with hlen2 | hlen1
            · obtain ⟨α, hα⟩ := hbsat₁
              obtain ⟨a, hstep⟩ := sum_chain_step_port b₁ hsp₁ hin₁ _
                hct₁ hit₁ hstates₁ hexh₁ hexit₁ (by omega) α hα
              refine ⟨α, a, ?_⟩
              show _ = some (a, Sum.inl (some (spineNext f₁ l₁
                (l₁[l₁.length - 1]'hj))))
              rw [spineNext_last f₁ l₁ hsp₁ (by omega)]
              exact hstep
            · exfalso
              apply hne
              show Sum.inl (some (spineNext f₁ l₁
                (l₁[l₁.length - 1]'hj)))
                = Sum.inl (some (l₁[l₁.length - 1]'hj))
              rw [spineNext_last f₁ l₁ hsp₁ (by omega),
                ← hfl₁ (by omega)]
              have hidx : l₁.length - 1 = 0 := by omega
              simp only [hidx]
  | inr o =>
      cases o with
      | none => exact absurd rfl hne
      | some x =>
          obtain ⟨j, hj, hjx⟩ := List.getElem_of_mem (hexh₂ x)
          subst hjx
          rcases Nat.lt_or_ge (j + 1) l₂.length with hint | hport
          · obtain ⟨a, hstep⟩ := sum_chain_step_interior_inr b₂ hsp₂ f₂ _
              hct₂ hit₂ hstates₂ hexh₂ hexit₂ j hint (fun _ => true)
            refine ⟨fun _ => true, a, ?_⟩
            show _ = some (a, Sum.inr (some (spineNext f₂ l₂
              (l₂[j]'hj))))
            rw [spineNext_at f₂ l₂ hsp₂ j hint]
            exact hstep
          · have hj' : j = l₂.length - 1 := by omega
            subst hj'
            rcases Nat.lt_or_ge 1 l₂.length with hlen2 | hlen1
            · obtain ⟨α, hα⟩ := hbsat₂
              obtain ⟨a, hstep⟩ := sum_chain_step_port_inr b₂ hsp₂ hin₂ _
                hct₂ hit₂ hstates₂ hexh₂ hexit₂ (by omega) α hα
              refine ⟨α, a, ?_⟩
              show _ = some (a, Sum.inr (some (spineNext f₂ l₂
                (l₂[l₂.length - 1]'hj))))
              rw [spineNext_last f₂ l₂ hsp₂ (by omega)]
              exact hstep
            · exfalso
              apply hne
              show Sum.inr (some (spineNext f₂ l₂
                (l₂[l₂.length - 1]'hj)))
                = Sum.inr (some (l₂[l₂.length - 1]'hj))
              rw [spineNext_last f₂ l₂ hsp₂ (by omega),
                ← hfl₂ (by omega)]
              have hidx : l₂.length - 1 = 0 := by omega
              simp only [hidx]

#print axioms spine_iter_port
#print axioms spine_nofix_port
#print axioms sum_chain_hfire

/-! ## The init state IS the port

    The loop's initial pseudostate and its port agree on halting (`¬b`)
    and step identically at every atom (the port's body arms vanish, its
    feedback guards are the init guards under an always-true halt), so
    they have the same language — the identification the cover needs. -/

open Classical in
/-- Two states stepping and halting identically have the same language. -/
theorem lang_eq_of_step_hlt (aut : GAut S A T) {s t : S}
    (hstep : ∀ α : T → Bool,
      autStep (genW T) aut s α = autStep (genW T) aut t α)
    (hhlt : ∀ α : T → Bool,
      bval (genW T) (aut.hlt s) α = bval (genW T) (aut.hlt t) α) :
    autLang (genW T) aut s = autLang (genW T) aut t := by
  funext gs
  obtain ⟨α, w⟩ := gs
  apply propext
  cases w with
  | nil =>
      show (bval (genW T) (aut.hlt s) α = true)
        ↔ (bval (genW T) (aut.hlt t) α = true)
      rw [hhlt α]
  | cons qa w' =>
      obtain ⟨q, β⟩ := qa
      show (∃ s', autStep (genW T) aut s α = some (q, s')
          ∧ autRun (genW T) aut s' β w')
        ↔ (∃ s', autStep (genW T) aut t α = some (q, s')
          ∧ autRun (genW T) aut s' β w')
      rw [hstep α]

open Classical in
/-- One-step behavior through `toGAut` at the initial pseudostate. -/
theorem autStep_toGAut_none {S' Atom : Type} (V : T → Atom → Bool)
    (W : InitializedGAut S' A T) (x : Atom) :
    autStep V W.toGAut none x
      = (firstMatch V x W.initTrans).map (fun o => (o.1, some o.2)) := by
  show firstMatch V x (W.initTrans.map
    (fun t => (t.1, t.2.1, some t.2.2))) = _
  exact firstMatch_map_target_to V x some W.initTrans

open Classical in
/-- `firstMatch` only sees guard values: mapped lists with pointwise
    `bval`-equal guards match identically. -/
theorem firstMatch_map_guard_congr {Atom R : Type} (V : T → Atom → Bool)
    (x : Atom) (f g : (BExp T × A × R) → BExp T) :
    ∀ L : List (BExp T × A × R),
      (∀ t ∈ L, bval V (f t) x = bval V (g t) x) →
      firstMatch V x (L.map (fun t => (f t, t.2)))
        = firstMatch V x (L.map (fun t => (g t, t.2))) := by
  intro L
  induction L with
  | nil => intro _; rfl
  | cons hd rest ih =>
      intro h
      obtain ⟨gd, a, t⟩ := hd
      show (if bval V (f (gd, a, t)) x = true then some (a, t)
          else firstMatch V x (rest.map (fun t => (f t, t.2))))
        = (if bval V (g (gd, a, t)) x = true then some (a, t)
          else firstMatch V x (rest.map (fun t => (g t, t.2))))
      rw [h (gd, a, t) (List.mem_cons_self ..),
          ih (fun t' ht' => h t' (List.mem_cons_of_mem _ ht'))]

open Classical in
/-- All composite arms at the initial pseudostate have live targets. -/
theorem sum_targets_live_none_inl {S₁ S₂ : Type}
    {B : InitializedGAut S₁ A T}
    (b : BExp T) {l : List S₁} (hsp : ChainSpine B l) (first : S₁)
    (aut₂ : GAut (Option S₂) A T)
    (hit : InitTargetsListed B)
    (hstates : B.core.states = l)
    (hexit : ∃ α : T → Bool, bval (genW T) b α = false) :
    ∀ e ∈ (sumGAut (loopInitialized b B).toGAut aut₂).trans
        (Sum.inl (none : Option S₁)),
      Live (sumGAut (loopInitialized b B).toGAut aut₂) e.2.2 := by
  intro e he
  obtain ⟨t₁, ht₁, heq₁⟩ := List.mem_map.mp he
  obtain ⟨t₀, ht₀, heq₀⟩ := List.mem_map.mp ht₁
  obtain ⟨tB, htB, heqB⟩ := List.mem_map.mp ht₀
  rw [← heq₁, ← heq₀, ← heqB]
  show Live _ (Sum.inl (some tB.2.2))
  have hmem : tB.2.2 ∈ l := by
    have := hit tB htB
    rw [hstates] at this
    exact this
  exact spine_mem_live_inl b hsp first aut₂ hexit hmem

open Classical in
/-- **THE INIT–PORT IDENTIFICATION**: in the trimmed composite, the loop's
    initial pseudostate and its port have the same language. -/
theorem sum_chain_none_lang {S₁ S₂ : Type} {B : InitializedGAut S₁ A T}
    (b : BExp T) {l : List S₁} (hsp : ChainSpine B l) (first : S₁)
    (aut₂ : GAut (Option S₂) A T)
    (hct : CoreTargetsListed B) (hit : InitTargetsListed B)
    (hstates : B.core.states = l) (hexh : ∀ x : S₁, x ∈ l)
    (hexit : ∃ α : T → Bool, bval (genW T) b α = false)
    (h0 : 0 < l.length) :
    autLang (genW T)
        (trimAut (sumGAut (loopInitialized b B).toGAut aut₂))
        (Sum.inl (none : Option S₁))
      = autLang (genW T)
          (trimAut (sumGAut (loopInitialized b B).toGAut aut₂))
          (Sum.inl (some (l[l.length - 1]'(by omega)))) := by
  apply lang_eq_of_step_hlt
  · intro α
    rw [autStep_trimAut_all_live (genW T) _ _
      (sum_targets_live_none_inl b hsp first aut₂ hit hstates hexit) α]
    rw [autStep_trimAut_all_live (genW T) _ _
      (sum_targets_live_inl b hsp first aut₂ hct hit hstates hexh hexit
        (l[l.length - 1]'(by omega))) α]
    rw [autStep_sumGAut_inl, autStep_sumGAut_inl]
    rw [autStep_toGAut_none, autStep_toGAut_some]
    have hfm : firstMatch (genW T) α (loopInitialized b B).initTrans
        = firstMatch (genW T) α
          ((loopInitialized b B).core.trans
            (l[l.length - 1]'(by omega))) := by
      show firstMatch (genW T) α
          (B.initTrans.map (fun t => (.and b t.1, t.2)))
        = firstMatch (genW T) α
          (B.core.trans (l[l.length - 1]'(by omega))
            ++ B.initTrans.map (fun t =>
              (.and (B.core.hlt (l[l.length - 1]'(by omega)))
                (.and b t.1), t.2)))
      rw [spine_last_nil l hsp h0]
      show firstMatch (genW T) α
          (B.initTrans.map (fun t => ((.and b t.1 : BExp T), t.2)))
        = firstMatch (genW T) α
          (B.initTrans.map (fun t =>
            ((.and (B.core.hlt (l[l.length - 1]'(by omega)))
              (.and b t.1) : BExp T), t.2)))
      apply firstMatch_map_guard_congr
      intro t _
      show bval (genW T) (.and b t.1) α
        = (bval (genW T) (B.core.hlt (l[l.length - 1]'(by omega))) α
          && bval (genW T) (.and b t.1) α)
      rw [spine_hlt_last l hsp h0 α]
      rfl
    rw [hfm]
  · intro α
    show (!(bval (genW T) b α))
      = bval (genW T)
          ((loopInitialized b B).core.hlt
            (l[l.length - 1]'(by omega))) α
    rw [loop_hlt_port b hsp h0 α]

#print axioms lang_eq_of_step_hlt
#print axioms sum_chain_none_lang

/-! ## Orbit-bundle packaging: closure, membership, period, non-fixedness,
    and the genuine two-class period -/

open Classical in
/-- The spine is closed under its successor. -/
theorem spineNext_mem {S' : Type} {B : InitializedGAut S' A T}
    {l : List S'} (hsp : ChainSpine B l) {first : S'}
    (h0 : 0 < l.length) (hfl : l[0]'h0 = first)
    {x : S'} (hx : x ∈ l) : spineNext first l x ∈ l := by
  obtain ⟨j, hj, hjx⟩ := List.getElem_of_mem hx
  subst hjx
  rcases Nat.lt_or_ge (j + 1) l.length with hint | hport
  · rw [spineNext_at first l hsp j hint]
    exact List.getElem_mem _
  · have hj' : j = l.length - 1 := by omega
    subst hj'
    rw [spineNext_last first l hsp (by omega), ← hfl]
    exact List.getElem_mem _

open Classical in
/-- Iterates of the spine successor stay on the spine. -/
theorem spineNext_iter_mem {S' : Type} {B : InitializedGAut S' A T}
    {l : List S'} (hsp : ChainSpine B l) {first : S'}
    (h0 : 0 < l.length) (hfl : l[0]'h0 = first) :
    ∀ (k : Nat) {x : S'}, x ∈ l →
      nxtIter (spineNext first l) k x ∈ l := by
  intro k
  induction k with
  | zero => intro x hx; exact hx
  | succ k ih =>
      intro x hx
      show spineNext first l (nxtIter (spineNext first l) k x) ∈ l
      exact spineNext_mem hsp h0 hfl (ih hx)

open Classical in
/-- Spine members' classes are quotient states of the composite. -/
theorem sum_chain_states {S₁ S₂ : Type} {B : InitializedGAut S₁ A T}
    (b : BExp T) {l : List S₁} (hstates₁ : B.core.states = l)
    (aut₂ : GAut (Option S₂) A T)
    {x : S₁} (hx : x ∈ l) :
    bisimRep (trimAut (sumGAut (loopInitialized b B).toGAut aut₂))
        (Sum.inl (some x))
      ∈ (bisimQuotAut
          (trimAut (sumGAut (loopInitialized b B).toGAut aut₂))).states := by
  have hmem : Sum.inl (some x)
      ∈ (sumGAut (loopInitialized b B).toGAut aut₂).states := by
    refine List.mem_append.mpr (Or.inl (List.mem_map.mpr
      ⟨some x, ?_, rfl⟩))
    refine List.mem_cons.mpr (Or.inr (List.mem_map.mpr ⟨x, ?_, rfl⟩))
    show x ∈ B.core.states
    rw [hstates₁]
    exact hx
  exact List.mem_map.mpr ⟨Sum.inl (some x), hmem, rfl⟩

open Classical in
/-- The lifted period at the port. -/
theorem sum_chain_hper {S₁ S₂ : Type} {B : InitializedGAut S₁ A T}
    {l : List S₁} (hsp : ChainSpine B l) {first : S₁}
    (g₂ : S₂ → S₂) (h0 : 0 < l.length) (hfl : l[0]'h0 = first) :
    nxtIter (Sum.elim
        (fun o : Option S₁ => Sum.inl (o.map (spineNext first l)))
        (fun o : Option S₂ => Sum.inr (o.map g₂)))
      l.length (Sum.inl (some (l[l.length - 1]'(by omega))))
      = Sum.inl (some (l[l.length - 1]'(by omega))) := by
  rw [nxtIter_lift_inl]
  rw [spine_period_port hsp h0 hfl]

open Classical in
/-- The lifted walk never fixes below the period. -/
theorem sum_chain_hnofix {S₁ S₂ : Type} {B : InitializedGAut S₁ A T}
    {l : List S₁} (hsp : ChainSpine B l) {first : S₁}
    (g₂ : S₂ → S₂) (hlen2 : 2 ≤ l.length)
    (hfl : l[0]'(by omega) = first) :
    ∀ j, j < l.length →
      (Sum.elim
        (fun o : Option S₁ => Sum.inl (o.map (spineNext first l)))
        (fun o : Option S₂ => Sum.inr (o.map g₂)))
        (nxtIter (Sum.elim
          (fun o : Option S₁ => Sum.inl (o.map (spineNext first l)))
          (fun o : Option S₂ => Sum.inr (o.map g₂))) j
          (Sum.inl (some (l[l.length - 1]'(by omega)))))
      ≠ nxtIter (Sum.elim
          (fun o : Option S₁ => Sum.inl (o.map (spineNext first l)))
          (fun o : Option S₂ => Sum.inr (o.map g₂))) j
          (Sum.inl (some (l[l.length - 1]'(by omega)))) := by
  intro j hj hcontra
  rw [nxtIter_lift_inl] at hcontra
  have h1 : spineNext first l
      (nxtIter (spineNext first l) j (l[l.length - 1]'(by omega)))
      = nxtIter (spineNext first l) j (l[l.length - 1]'(by omega)) :=
    Option.some.inj (Sum.inl.inj hcontra)
  exact spine_nofix_port hsp hlen2 hfl j hj h1

open Classical in
/-- **A GENUINE TWO-CLASS CYCLE**: with at least two spine states and the
    exit satisfiable, the quotient period at the port is at least 2. -/
theorem sum_chain_qperiod2 {S₁ S₂ : Type} {B : InitializedGAut S₁ A T}
    (b : BExp T) {l : List S₁} (hsp : ChainSpine B l) {first : S₁}
    (aut₂ : GAut (Option S₂) A T) (g₂ : S₂ → S₂)
    (hlen2 : 2 ≤ l.length) (hfl : l[0]'(by omega) = first)
    (hexit : ∃ α : T → Bool, bval (genW T) b α = false) :
    2 ≤ qPeriod (sumGAut (loopInitialized b B).toGAut aut₂)
        (Sum.elim
          (fun o : Option S₁ => Sum.inl (o.map (spineNext first l)))
          (fun o : Option S₂ => Sum.inr (o.map g₂)))
        (Sum.inl (some (l[l.length - 1]'(by omega))))
        l.length := by
  obtain ⟨h1, h2, h3, h4⟩ := qPeriod_spec
    (sumGAut (loopInitialized b B).toGAut aut₂)
    (Sum.elim
      (fun o : Option S₁ => Sum.inl (o.map (spineNext first l)))
      (fun o : Option S₂ => Sum.inr (o.map g₂)))
    (Sum.inl (some (l[l.length - 1]'(by omega)))) l.length
    (by omega) (sum_chain_hper hsp g₂ (by omega) hfl)
  generalize hqgen : qPeriod (sumGAut (loopInitialized b B).toGAut aut₂)
      (Sum.elim
        (fun o : Option S₁ => Sum.inl (o.map (spineNext first l)))
        (fun o : Option S₂ => Sum.inr (o.map g₂)))
      (Sum.inl (some (l[l.length - 1]'(by omega))))
      l.length = qp at h1 h2 h3 h4 ⊢
  rcases Nat.lt_or_ge qp 2 with hlt | hge
  · exfalso
    have hqp1 : qp = 1 := by omega
    rw [hqp1] at h1
    have hn : nxtIter (Sum.elim
        (fun o : Option S₁ => Sum.inl (o.map (spineNext first l)))
        (fun o : Option S₂ => Sum.inr (o.map g₂))) 1
        (Sum.inl (some (l[l.length - 1]'(by omega))))
        = Sum.inl (some first) := by
      show Sum.inl ((some (l[l.length - 1]'(by omega))).map
        (spineNext first l)) = _
      show Sum.inl (some (spineNext first l
        (l[l.length - 1]'(by omega)))) = _
      rw [spineNext_last first l hsp (by omega)]
    rw [hn] at h1
    have hL : autLang (genW T)
        (trimAut (sumGAut (loopInitialized b B).toGAut aut₂))
        (Sum.inl (some first))
        = autLang (genW T)
          (trimAut (sumGAut (loopInitialized b B).toGAut aut₂))
          (Sum.inl (some (l[l.length - 1]'(by omega)))) := by
      rw [← rep_lang (sumGAut (loopInitialized b B).toGAut aut₂)
        (Sum.inl (some first)), h1,
        rep_lang (sumGAut (loopInitialized b B).toGAut aut₂)]
    obtain ⟨αe, hαe⟩ := hexit
    have hiff := iff_of_eq (congrFun hL (αe, []))
    have hport : autRun (genW T)
        (trimAut (sumGAut (loopInitialized b B).toGAut aut₂))
        (Sum.inl (some (l[l.length - 1]'(by omega)))) αe [] := by
      show bval (genW T)
        ((loopInitialized b B).core.hlt
          (l[l.length - 1]'(by omega))) αe = true
      rw [loop_hlt_port b hsp (by omega) αe, hαe]
      rfl
    have hfirst := hiff.mpr hport
    have hfirst' : bval (genW T)
        ((loopInitialized b B).core.hlt first) αe = true := hfirst
    rw [← hfl] at hfirst'
    rw [loop_hlt_int b hsp 0 (by omega) αe] at hfirst'
    exact nomatch hfirst'
  · exact hge

#print axioms sum_chain_states
#print axioms sum_chain_hper
#print axioms sum_chain_hnofix
#print axioms sum_chain_qperiod2

/-! ## The cover: every class is on a listed orbit

    Right-summand mirrors of the init–port identification, then the cover:
    each quotient state of the composite is the class of an init state
    (which IS the port class) or of a spine state (which is a port
    iterate) — of the left or right loop. -/

open Classical in
/-- Right mirror: init arms have live targets. -/
theorem sum_targets_live_none_inr {S₁ S₂ : Type}
    {B : InitializedGAut S₂ A T}
    (b : BExp T) {l : List S₂} (hsp : ChainSpine B l) (first : S₂)
    (aut₁ : GAut (Option S₁) A T)
    (hit : InitTargetsListed B)
    (hstates : B.core.states = l)
    (hexit : ∃ α : T → Bool, bval (genW T) b α = false) :
    ∀ e ∈ (sumGAut aut₁ (loopInitialized b B).toGAut).trans
        (Sum.inr (none : Option S₂)),
      Live (sumGAut aut₁ (loopInitialized b B).toGAut) e.2.2 := by
  intro e he
  obtain ⟨t₁, ht₁, heq₁⟩ := List.mem_map.mp he
  obtain ⟨t₀, ht₀, heq₀⟩ := List.mem_map.mp ht₁
  obtain ⟨tB, htB, heqB⟩ := List.mem_map.mp ht₀
  rw [← heq₁, ← heq₀, ← heqB]
  show Live _ (Sum.inr (some tB.2.2))
  have hmem : tB.2.2 ∈ l := by
    have := hit tB htB
    rw [hstates] at this
    exact this
  obtain ⟨j, hj, hjx⟩ := List.getElem_of_mem hmem
  rw [← hjx]
  exact spine_live_sum_inr b hsp first aut₁ hexit j hj

open Classical in
/-- Right mirror of the init–port identification. -/
theorem sum_chain_none_lang_inr {S₁ S₂ : Type}
    {B : InitializedGAut S₂ A T}
    (b : BExp T) {l : List S₂} (hsp : ChainSpine B l) (first : S₂)
    (aut₁ : GAut (Option S₁) A T)
    (hct : CoreTargetsListed B) (hit : InitTargetsListed B)
    (hstates : B.core.states = l) (hexh : ∀ x : S₂, x ∈ l)
    (hexit : ∃ α : T → Bool, bval (genW T) b α = false)
    (h0 : 0 < l.length) :
    autLang (genW T)
        (trimAut (sumGAut aut₁ (loopInitialized b B).toGAut))
        (Sum.inr (none : Option S₂))
      = autLang (genW T)
          (trimAut (sumGAut aut₁ (loopInitialized b B).toGAut))
          (Sum.inr (some (l[l.length - 1]'(by omega)))) := by
  apply lang_eq_of_step_hlt
  · intro α
    rw [autStep_trimAut_all_live (genW T) _ _
      (sum_targets_live_none_inr b hsp first aut₁ hit hstates hexit) α]
    rw [autStep_trimAut_all_live (genW T) _ _
      (sum_targets_live_inr b hsp first aut₁ hct hit hstates hexh hexit
        (l[l.length - 1]'(by omega))) α]
    rw [autStep_sumGAut_inr, autStep_sumGAut_inr]
    rw [autStep_toGAut_none, autStep_toGAut_some]
    have hfm : firstMatch (genW T) α (loopInitialized b B).initTrans
        = firstMatch (genW T) α
          ((loopInitialized b B).core.trans
            (l[l.length - 1]'(by omega))) := by
      show firstMatch (genW T) α
          (B.initTrans.map (fun t => (.and b t.1, t.2)))
        = firstMatch (genW T) α
          (B.core.trans (l[l.length - 1]'(by omega))
            ++ B.initTrans.map (fun t =>
              (.and (B.core.hlt (l[l.length - 1]'(by omega)))
                (.and b t.1), t.2)))
      rw [spine_last_nil l hsp h0]
      show firstMatch (genW T) α
          (B.initTrans.map (fun t => ((.and b t.1 : BExp T), t.2)))
        = firstMatch (genW T) α
          (B.initTrans.map (fun t =>
            ((.and (B.core.hlt (l[l.length - 1]'(by omega)))
              (.and b t.1) : BExp T), t.2)))
      apply firstMatch_map_guard_congr
      intro t _
      show bval (genW T) (.and b t.1) α
        = (bval (genW T) (B.core.hlt (l[l.length - 1]'(by omega))) α
          && bval (genW T) (.and b t.1) α)
      rw [spine_hlt_last l hsp h0 α]
      rfl
    rw [hfm]
  · intro α
    show (!(bval (genW T) b α))
      = bval (genW T)
          ((loopInitialized b B).core.hlt
            (l[l.length - 1]'(by omega))) α
    rw [loop_hlt_port b hsp h0 α]

open Classical in
/-- **THE COVER**: every quotient class of the chain-loop composite is on
    one of the two listed orbits. -/
theorem sum_chain_cover {S₁ S₂ : Type}
    {B₁ : InitializedGAut S₁ A T} {B₂ : InitializedGAut S₂ A T}
    (b₁ b₂ : BExp T) {l₁ : List S₁} {l₂ : List S₂}
    (hsp₁ : ChainSpine B₁ l₁) (hsp₂ : ChainSpine B₂ l₂)
    {f₁ : S₁} {f₂ : S₂}
    (hct₁ : CoreTargetsListed B₁) (hit₁ : InitTargetsListed B₁)
    (hct₂ : CoreTargetsListed B₂) (hit₂ : InitTargetsListed B₂)
    (hstates₁ : B₁.core.states = l₁) (hstates₂ : B₂.core.states = l₂)
    (hexh₁ : ∀ x : S₁, x ∈ l₁) (hexh₂ : ∀ x : S₂, x ∈ l₂)
    (hexit₁ : ∃ α : T → Bool, bval (genW T) b₁ α = false)
    (hexit₂ : ∃ α : T → Bool, bval (genW T) b₂ α = false)
    (h01 : 0 < l₁.length) (h02 : 0 < l₂.length)
    (hfl₁ : l₁[0]'h01 = f₁) (hfl₂ : l₂[0]'h02 = f₂) :
    ∀ c ∈ (cleanAut (bisimQuotAut (trimAut
        (sumGAut (loopInitialized b₁ B₁).toGAut
          (loopInitialized b₂ B₂).toGAut)))).states,
      ∃ p ∈ [((Sum.inl (some (l₁[l₁.length - 1]'(by omega)))
            : Sum (Option S₁) (Option S₂)), l₁.length),
          (Sum.inr (some (l₂[l₂.length - 1]'(by omega))), l₂.length)],
        InOrbit (sumGAut (loopInitialized b₁ B₁).toGAut
            (loopInitialized b₂ B₂).toGAut)
          (Sum.elim
            (fun o : Option S₁ => Sum.inl (o.map (spineNext f₁ l₁)))
            (fun o : Option S₂ => Sum.inr (o.map (spineNext f₂ l₂))))
          p.1 c := by
  intro c hc
  obtain ⟨x, hx, hrep⟩ := List.mem_map.mp hc
  rcases List.mem_append.mp hx with hL | hR
  · obtain ⟨o, ho, hoeq⟩ := List.mem_map.mp hL
    rcases List.mem_cons.mp ho with hnone | hsome
    · refine ⟨_, List.mem_cons_self .., 0, ?_⟩
      rw [← hrep, ← hoeq, hnone]
      exact (rep_lang_congr _
        (sum_chain_none_lang b₁ hsp₁ f₁ _ hct₁ hit₁ hstates₁ hexh₁
          hexit₁ h01)).symm.symm
    · obtain ⟨s, hs, hseq⟩ := List.mem_map.mp hsome
      have hsl : s ∈ l₁ := by
        rw [← hstates₁]
        exact hs
      obtain ⟨j, hj, hjs⟩ := List.getElem_of_mem hsl
      refine ⟨_, List.mem_cons_self .., j + 1, ?_⟩
      rw [← hrep, ← hoeq, ← hseq, ← hjs]
      have hn : nxtIter (Sum.elim
          (fun o : Option S₁ => Sum.inl (o.map (spineNext f₁ l₁)))
          (fun o : Option S₂ => Sum.inr (o.map (spineNext f₂ l₂))))
          (j + 1) (Sum.inl (some (l₁[l₁.length - 1]'(by omega))))
          = Sum.inl (some (l₁[j]'hj)) := by
        rw [nxtIter_lift_inl]
        rw [spine_iter_port hsp₁ h01 hfl₁ j hj]
      rw [hn]
  · obtain ⟨o, ho, hoeq⟩ := List.mem_map.mp hR
    rcases List.mem_cons.mp ho with hnone | hsome
    · refine ⟨_, List.mem_cons.mpr (Or.inr (List.mem_cons_self ..)),
        0, ?_⟩
      rw [← hrep, ← hoeq, hnone]
      exact rep_lang_congr _
        (sum_chain_none_lang_inr b₂ hsp₂ f₂ _ hct₂ hit₂ hstates₂ hexh₂
          hexit₂ h02)
    · obtain ⟨s, hs, hseq⟩ := List.mem_map.mp hsome
      have hsl : s ∈ l₂ := by
        rw [← hstates₂]
        exact hs
      obtain ⟨j, hj, hjs⟩ := List.getElem_of_mem hsl
      refine ⟨_, List.mem_cons.mpr (Or.inr (List.mem_cons_self ..)),
        j + 1, ?_⟩
      rw [← hrep, ← hoeq, ← hseq, ← hjs]
      have hn : nxtIter (Sum.elim
          (fun o : Option S₁ => Sum.inl (o.map (spineNext f₁ l₁)))
          (fun o : Option S₂ => Sum.inr (o.map (spineNext f₂ l₂))))
          (j + 1) (Sum.inr (some (l₂[l₂.length - 1]'(by omega))))
          = Sum.inr (some (l₂[j]'hj)) := by
        rw [nxtIter_lift_inr]
        rw [spine_iter_port hsp₂ h02 hfl₂ j hj]
      rw [hn]

#print axioms sum_chain_cover

/-! ## THE MASTER ASSEMBLY: sums of chain loops are solvable

    Instantiate the orbit glue with everything proved: the canonical
    quotient of the sum of two chain-loop Thompson automata is solvable —
    the existence half that, through `equivBA_of_quot_solvesBA`, decides
    `wh b₁ (p₁;…;pₙ) ≡ wh b₂ (q₁;…;qₘ)` from the finite axioms alone. -/

open Classical in
/-- Right mirror of trim-level interior silence. -/
theorem sum_chain_noeps_inr {S₁ S₂ : Type} {B : InitializedGAut S₂ A T}
    (b : BExp T) {l : List S₂} (hsp : ChainSpine B l)
    (aut₁ : GAut (Option S₁) A T)
    (j : Nat) (h1 : j + 1 < l.length) :
    ∀ α : T → Bool,
      ¬ autRun (genW T)
          (trimAut (sumGAut aut₁ (loopInitialized b B).toGAut))
          (Sum.inr (some (l[j]'(by omega)))) α [] := by
  intro α h
  have h' : bval (genW T)
      ((loopInitialized b B).core.hlt (l[j]'(by omega))) α = true := h
  rw [loop_hlt_int b hsp j h1 α] at h'
  exact nomatch h'

open Classical in
/-- **SUMS OF CHAIN LOOPS ARE SOLVABLE**: the canonical quotient of the
    sum of two chain-loop Thompson automata admits a syntactic solution,
    from the finite axioms alone. -/
theorem chain_loops_solvable {S₁ S₂ : Type}
    {B₁ : InitializedGAut S₁ A T} {B₂ : InitializedGAut S₂ A T}
    (b₁ b₂ : BExp T) {l₁ : List S₁} {l₂ : List S₂}
    (hsp₁ : ChainSpine B₁ l₁) (hsp₂ : ChainSpine B₂ l₂)
    {f₁ : S₁} {f₂ : S₂} (hin₁ : ChainInit B₁ f₁)
    (hin₂ : ChainInit B₂ f₂)
    (hct₁ : CoreTargetsListed B₁) (hit₁ : InitTargetsListed B₁)
    (hct₂ : CoreTargetsListed B₂) (hit₂ : InitTargetsListed B₂)
    (hstates₁ : B₁.core.states = l₁) (hstates₂ : B₂.core.states = l₂)
    (hexh₁ : ∀ x : S₁, x ∈ l₁) (hexh₂ : ∀ x : S₂, x ∈ l₂)
    (hexit₁ : ∃ α : T → Bool, bval (genW T) b₁ α = false)
    (hexit₂ : ∃ α : T → Bool, bval (genW T) b₂ α = false)
    (hbsat₁ : ∃ α : T → Bool, bval (genW T) b₁ α = true)
    (hbsat₂ : ∃ α : T → Bool, bval (genW T) b₂ α = true)
    (hlen2₁ : 2 ≤ l₁.length) (hlen2₂ : 2 ≤ l₂.length)
    (hfl₁ : l₁[0]'(by omega) = f₁) (hfl₂ : l₂[0]'(by omega) = f₂) :
    ∃ qsol : Sum (Option S₁) (Option S₂) → Exp A T,
      SolvesBA (bisimQuotAut (trimAut (sumGAut
        (loopInitialized b₁ B₁).toGAut
        (loopInitialized b₂ B₂).toGAut))) qsol := by
  refine rankNxt_quot_solvesBA
    (sumGAut (loopInitialized b₁ B₁).toGAut
      (loopInitialized b₂ B₂).toGAut)
    (Sum.elim (fun o : Option S₁ => if o.isSome then 0 else 1)
      (fun o : Option S₂ => if o.isSome then 0 else 1))
    (Sum.elim (fun o : Option S₁ => Sum.inl (o.map (spineNext f₁ l₁)))
      (fun o : Option S₂ => Sum.inr (o.map (spineNext f₂ l₂))))
    (sum_chain_hdec b₁ b₂ hsp₁ hsp₂ hin₁ hin₂ hexh₁ hexh₂)
    (sum_chain_nxt_rank (spineNext f₁ l₁) (spineNext f₂ l₂))
    (sum_chain_hfire b₁ b₂ hsp₁ hsp₂ hin₁ hin₂ hct₁ hit₁ hct₂ hit₂
      hstates₁ hstates₂ hexh₁ hexh₂ hexit₁ hexit₂ hbsat₁ hbsat₂
      (fun _ => hfl₁) (fun _ => hfl₂))
    [((Sum.inl (some (l₁[l₁.length - 1]'(by omega)))
        : Sum (Option S₁) (Option S₂)), l₁.length),
      (Sum.inr (some (l₂[l₂.length - 1]'(by omega))), l₂.length)]
    ?_ ?_
  · intro p hp
    rcases List.mem_cons.mp hp with hp1 | hp'
    · subst hp1
      obtain ⟨hq1, hq2, hq3, hq4⟩ := qPeriod_spec
        (sumGAut (loopInitialized b₁ B₁).toGAut
          (loopInitialized b₂ B₂).toGAut)
        (Sum.elim
          (fun o : Option S₁ => Sum.inl (o.map (spineNext f₁ l₁)))
          (fun o : Option S₂ => Sum.inr (o.map (spineNext f₂ l₂))))
        (Sum.inl (some (l₁[l₁.length - 1]'(by omega)))) l₁.length
        (by omega) (sum_chain_hper hsp₁ (spineNext f₂ l₂) (by omega)
          hfl₁)
      refine ⟨by omega,
        sum_chain_hper hsp₁ (spineNext f₂ l₂) (by omega) hfl₁,
        live_trimAut (spine_mem_live_inl b₁ hsp₁ f₁ _ hexit₁
          (List.getElem_mem _)),
        sum_chain_hnofix hsp₁ (spineNext f₂ l₂) hlen2₁ hfl₁,
        fun w _ => Nat.zero_le _,
        sum_chain_qperiod2 b₁ hsp₁ _ (spineNext f₂ l₂) hlen2₁ hfl₁
          hexit₁,
        ?_, ?_, ?_⟩
      · intro j
        rw [nxtIter_lift_inl]
        exact sum_chain_states b₁ hstates₁ _
          (spineNext_iter_mem hsp₁ (by omega) hfl₁ j
            (List.getElem_mem _))
      · intro j hj1 hjq
        have hjlen : j < l₁.length := Nat.lt_of_lt_of_le hjq hq3
        have hiter : nxtIter (Sum.elim
            (fun o : Option S₁ => Sum.inl (o.map (spineNext f₁ l₁)))
            (fun o : Option S₂ => Sum.inr (o.map (spineNext f₂ l₂)))) j
            (Sum.inl (some (l₁[l₁.length - 1]'(by omega))))
            = Sum.inl (some (l₁[j - 1]'(by omega))) := by
          rw [nxtIter_lift_inl]
          have h := spine_iter_port hsp₁ (by omega) hfl₁ (j - 1)
            (by omega)
          rw [show j - 1 + 1 = j from by omega] at h
          rw [h]
        refine interior_no_desc
          (sumGAut (loopInitialized b₁ B₁).toGAut
            (loopInitialized b₂ B₂).toGAut)
          (Sum.elim (fun o : Option S₁ => if o.isSome then 0 else 1)
            (fun o : Option S₂ => if o.isSome then 0 else 1))
          (Sum.elim
            (fun o : Option S₁ => Sum.inl (o.map (spineNext f₁ l₁)))
            (fun o : Option S₂ => Sum.inr (o.map (spineNext f₂ l₂))))
          (sum_chain_hdec b₁ b₂ hsp₁ hsp₂ hin₁ hin₂ hexh₁ hexh₂)
          (sum_chain_nxt_rank (spineNext f₁ l₁) (spineNext f₂ l₂))
          (sum_chain_hfire b₁ b₂ hsp₁ hsp₂ hin₁ hin₂ hct₁ hit₁ hct₂
            hit₂ hstates₁ hstates₂ hexh₁ hexh₂ hexit₁ hexit₂ hbsat₁
            hbsat₂ (fun _ => hfl₁) (fun _ => hfl₂))
          (by omega)
          (sum_chain_hper hsp₁ (spineNext f₂ l₂) (by omega) hfl₁)
          (live_trimAut (spine_mem_live_inl b₁ hsp₁ f₁ _ hexit₁
            (List.getElem_mem _)))
          (sum_chain_hnofix hsp₁ (spineNext f₂ l₂) hlen2₁ hfl₁)
          (fun w _ => Nat.zero_le _)
          j ?_
        intro α
        obtain ⟨a, hstep⟩ := sum_chain_step_interior b₁ hsp₁ f₁ _
          hct₁ hit₁ hstates₁ hexh₁ hexit₁ (j - 1) (by omega) α
        refine ⟨a, ?_⟩
        rw [hiter]
        have hiter2 : nxtIter (Sum.elim
            (fun o : Option S₁ => Sum.inl (o.map (spineNext f₁ l₁)))
            (fun o : Option S₂ => Sum.inr (o.map (spineNext f₂ l₂))))
            (j + 1)
            (Sum.inl (some (l₁[l₁.length - 1]'(by omega))))
            = Sum.inl (some (l₁[j]'(by omega))) := by
          rw [nxtIter_lift_inl]
          rw [spine_iter_port hsp₁ (by omega) hfl₁ j (by omega)]
        rw [hiter2]
        have hidx : j - 1 + 1 = j := by omega
        rw [show (l₁[j]'(by omega) : S₁)
            = l₁[j - 1 + 1]'(by omega) from by
          simp only [hidx]]
        exact hstep
      · intro j hj1 hjq α
        have hjlen : j < l₁.length := Nat.lt_of_lt_of_le hjq hq3
        have hiter : nxtIter (Sum.elim
            (fun o : Option S₁ => Sum.inl (o.map (spineNext f₁ l₁)))
            (fun o : Option S₂ => Sum.inr (o.map (spineNext f₂ l₂)))) j
            (Sum.inl (some (l₁[l₁.length - 1]'(by omega))))
            = Sum.inl (some (l₁[j - 1]'(by omega))) := by
          rw [nxtIter_lift_inl]
          have h := spine_iter_port hsp₁ (by omega) hfl₁ (j - 1)
            (by omega)
          rw [show j - 1 + 1 = j from by omega] at h
          rw [h]
        rw [hiter]
        exact sum_chain_noeps b₁ hsp₁ _ (j - 1) (by omega) α
    · rcases List.mem_cons.mp hp' with hp2 | hnil
      · subst hp2
        have hper2 : nxtIter (Sum.elim
            (fun o : Option S₁ => Sum.inl (o.map (spineNext f₁ l₁)))
            (fun o : Option S₂ => Sum.inr (o.map (spineNext f₂ l₂))))
            l₂.length (Sum.inr (some (l₂[l₂.length - 1]'(by omega))))
            = Sum.inr (some (l₂[l₂.length - 1]'(by omega))) := by
          rw [nxtIter_lift_inr]
          rw [spine_period_port hsp₂ (by omega) hfl₂]
        obtain ⟨hq1, hq2, hq3, hq4⟩ := qPeriod_spec
          (sumGAut (loopInitialized b₁ B₁).toGAut
            (loopInitialized b₂ B₂).toGAut)
          (Sum.elim
            (fun o : Option S₁ => Sum.inl (o.map (spineNext f₁ l₁)))
            (fun o : Option S₂ => Sum.inr (o.map (spineNext f₂ l₂))))
          (Sum.inr (some (l₂[l₂.length - 1]'(by omega)))) l₂.length
          (by omega) hper2
        refine ⟨by omega, hper2, ?_, ?_, fun w _ => Nat.zero_le _,
          ?_, ?_, ?_, ?_⟩
        · exact live_trimAut (spine_live_sum_inr b₂ hsp₂ f₂ _ hexit₂
            (l₂.length - 1) (by omega))
        · intro j hj hcontra
          rw [nxtIter_lift_inr] at hcontra
          exact spine_nofix_port hsp₂ hlen2₂ hfl₂ j hj
            (Option.some.inj (Sum.inr.inj hcontra))
        · obtain ⟨hs1, hs2, hs3, hs4⟩ := qPeriod_spec
            (sumGAut (loopInitialized b₁ B₁).toGAut
              (loopInitialized b₂ B₂).toGAut)
            (Sum.elim
              (fun o : Option S₁ => Sum.inl (o.map (spineNext f₁ l₁)))
              (fun o : Option S₂ =>
                Sum.inr (o.map (spineNext f₂ l₂))))
            (Sum.inr (some (l₂[l₂.length - 1]'(by omega)))) l₂.length
            (by omega) hper2
          -- qPeriod ≥ 2 for the right summand: mirror argument
          generalize hqgen : qPeriod
              (sumGAut (loopInitialized b₁ B₁).toGAut
                (loopInitialized b₂ B₂).toGAut)
              (Sum.elim
                (fun o : Option S₁ =>
                  Sum.inl (o.map (spineNext f₁ l₁)))
                (fun o : Option S₂ =>
                  Sum.inr (o.map (spineNext f₂ l₂))))
              (Sum.inr (some (l₂[l₂.length - 1]'(by omega))))
              l₂.length = qp at hs1 hs2 hs3 hs4 ⊢
          rcases Nat.lt_or_ge qp 2 with hlt | hge
          · exfalso
            have hqp1 : qp = 1 := by omega
            rw [hqp1] at hs1
            have hn : nxtIter (Sum.elim
                (fun o : Option S₁ =>
                  Sum.inl (o.map (spineNext f₁ l₁)))
                (fun o : Option S₂ =>
                  Sum.inr (o.map (spineNext f₂ l₂)))) 1
                (Sum.inr (some (l₂[l₂.length - 1]'(by omega))))
                = Sum.inr (some f₂) := by
              show Sum.inr (some (spineNext f₂ l₂
                (l₂[l₂.length - 1]'(by omega)))) = _
              rw [spineNext_last f₂ l₂ hsp₂ (by omega)]
            rw [hn] at hs1
            have hL : autLang (genW T)
                (trimAut (sumGAut (loopInitialized b₁ B₁).toGAut
                  (loopInitialized b₂ B₂).toGAut))
                (Sum.inr (some f₂))
                = autLang (genW T)
                  (trimAut (sumGAut (loopInitialized b₁ B₁).toGAut
                    (loopInitialized b₂ B₂).toGAut))
                  (Sum.inr (some (l₂[l₂.length - 1]'(by omega)))) := by
              rw [← rep_lang (sumGAut (loopInitialized b₁ B₁).toGAut
                (loopInitialized b₂ B₂).toGAut) (Sum.inr (some f₂)),
                hs1,
                rep_lang (sumGAut (loopInitialized b₁ B₁).toGAut
                  (loopInitialized b₂ B₂).toGAut)]
            obtain ⟨αe, hαe⟩ := hexit₂
            have hiff := iff_of_eq (congrFun hL (αe, []))
            have hport : autRun (genW T)
                (trimAut (sumGAut (loopInitialized b₁ B₁).toGAut
                  (loopInitialized b₂ B₂).toGAut))
                (Sum.inr (some (l₂[l₂.length - 1]'(by omega))))
                αe [] := by
              show bval (genW T)
                ((loopInitialized b₂ B₂).core.hlt
                  (l₂[l₂.length - 1]'(by omega))) αe = true
              rw [loop_hlt_port b₂ hsp₂ (by omega) αe, hαe]
              rfl
            have hf := hiff.mpr hport
            have hf' : bval (genW T)
                ((loopInitialized b₂ B₂).core.hlt f₂) αe = true := hf
            rw [← hfl₂] at hf'
            rw [loop_hlt_int b₂ hsp₂ 0 (by omega) αe] at hf'
            exact nomatch hf'
          · exact hge
        · intro j
          rw [nxtIter_lift_inr]
          exact List.mem_map.mpr ⟨Sum.inr (some
            (nxtIter (spineNext f₂ l₂) j
              (l₂[l₂.length - 1]'(by omega)))), by
            refine List.mem_append.mpr (Or.inr (List.mem_map.mpr
              ⟨some (nxtIter (spineNext f₂ l₂) j
                (l₂[l₂.length - 1]'(by omega))), ?_, rfl⟩))
            refine List.mem_cons.mpr (Or.inr (List.mem_map.mpr
              ⟨_, ?_, rfl⟩))
            show nxtIter (spineNext f₂ l₂) j
              (l₂[l₂.length - 1]'(by omega)) ∈ B₂.core.states
            rw [hstates₂]
            exact spineNext_iter_mem hsp₂ (by omega) hfl₂ j
              (List.getElem_mem _), rfl⟩
        · intro j hj1 hjq
          have hjlen : j < l₂.length := Nat.lt_of_lt_of_le hjq hq3
          have hiter : nxtIter (Sum.elim
              (fun o : Option S₁ => Sum.inl (o.map (spineNext f₁ l₁)))
              (fun o : Option S₂ =>
                Sum.inr (o.map (spineNext f₂ l₂)))) j
              (Sum.inr (some (l₂[l₂.length - 1]'(by omega))))
              = Sum.inr (some (l₂[j - 1]'(by omega))) := by
            rw [nxtIter_lift_inr]
            have h := spine_iter_port hsp₂ (by omega) hfl₂ (j - 1)
              (by omega)
            rw [show j - 1 + 1 = j from by omega] at h
            rw [h]
          refine interior_no_desc
            (sumGAut (loopInitialized b₁ B₁).toGAut
              (loopInitialized b₂ B₂).toGAut)
            (Sum.elim (fun o : Option S₁ => if o.isSome then 0 else 1)
              (fun o : Option S₂ => if o.isSome then 0 else 1))
            (Sum.elim
              (fun o : Option S₁ => Sum.inl (o.map (spineNext f₁ l₁)))
              (fun o : Option S₂ =>
                Sum.inr (o.map (spineNext f₂ l₂))))
            (sum_chain_hdec b₁ b₂ hsp₁ hsp₂ hin₁ hin₂ hexh₁ hexh₂)
            (sum_chain_nxt_rank (spineNext f₁ l₁) (spineNext f₂ l₂))
            (sum_chain_hfire b₁ b₂ hsp₁ hsp₂ hin₁ hin₂ hct₁ hit₁ hct₂
              hit₂ hstates₁ hstates₂ hexh₁ hexh₂ hexit₁ hexit₂ hbsat₁
              hbsat₂ (fun _ => hfl₁) (fun _ => hfl₂))
            (by omega)
            hper2
            (live_trimAut (spine_live_sum_inr b₂ hsp₂ f₂ _ hexit₂
              (l₂.length - 1) (by omega)))
            (by
              intro i hi hcontra
              rw [nxtIter_lift_inr] at hcontra
              exact spine_nofix_port hsp₂ hlen2₂ hfl₂ i hi
                (Option.some.inj (Sum.inr.inj hcontra)))
            (fun w _ => Nat.zero_le _)
            j ?_
          intro α
          obtain ⟨a, hstep⟩ := sum_chain_step_interior_inr b₂ hsp₂ f₂ _
            hct₂ hit₂ hstates₂ hexh₂ hexit₂ (j - 1) (by omega) α
          refine ⟨a, ?_⟩
          rw [hiter]
          have hiter2 : nxtIter (Sum.elim
              (fun o : Option S₁ => Sum.inl (o.map (spineNext f₁ l₁)))
              (fun o : Option S₂ =>
                Sum.inr (o.map (spineNext f₂ l₂)))) (j + 1)
              (Sum.inr (some (l₂[l₂.length - 1]'(by omega))))
              = Sum.inr (some (l₂[j]'(by omega))) := by
            rw [nxtIter_lift_inr]
            rw [spine_iter_port hsp₂ (by omega) hfl₂ j (by omega)]
          rw [hiter2]
          have hidx : j - 1 + 1 = j := by omega
          rw [show (l₂[j]'(by omega) : S₂)
              = l₂[j - 1 + 1]'(by omega) from by
            simp only [hidx]]
          exact hstep
        · intro j hj1 hjq α
          have hjlen : j < l₂.length := Nat.lt_of_lt_of_le hjq hq3
          have hiter : nxtIter (Sum.elim
              (fun o : Option S₁ => Sum.inl (o.map (spineNext f₁ l₁)))
              (fun o : Option S₂ =>
                Sum.inr (o.map (spineNext f₂ l₂)))) j
              (Sum.inr (some (l₂[l₂.length - 1]'(by omega))))
              = Sum.inr (some (l₂[j - 1]'(by omega))) := by
            rw [nxtIter_lift_inr]
            have h := spine_iter_port hsp₂ (by omega) hfl₂ (j - 1)
              (by omega)
            rw [show j - 1 + 1 = j from by omega] at h
            rw [h]
          rw [hiter]
          exact sum_chain_noeps_inr b₂ hsp₂ _ (j - 1) (by omega) α
      · exact nomatch hnil
  · intro c hc
    exact Or.inr (sum_chain_cover b₁ b₂ hsp₁ hsp₂ hct₁ hit₁ hct₂ hit₂
      hstates₁ hstates₂ hexh₁ hexh₂ hexit₁ hexit₂ (by omega) (by omega)
      hfl₁ hfl₂ c hc)

#print axioms chain_loops_solvable

/-! ## THE FOURTH UNCONDITIONAL COMPLETENESS THEOREM

    Two while loops over multi-action chain bodies, with nondegenerate
    guards, are provably equivalent from the FINITE axioms whenever they
    are uniformly language equivalent.  No uniqueness axiom.  This is the
    head-position Salomaa frontier with genuinely multi-action bodies —
    the stratum beyond `atomicloops_complete`. -/

open Classical in
private theorem chainSpine_ne_nil {S' : Type} {B : InitializedGAut S' A T}
    {l : List S'} (h : ChainSpine B l) : 0 < l.length := by
  cases l with
  | nil => exact h.elim
  | cons x t => simp

open Classical in
/-- Multi-action chains: at least one sequential composition. -/
inductive Chain2 : Exp A T → Prop where
  | seq {e f : Exp A T} : Chain e → Chain f → Chain2 (.seq e f)

open Classical in
private theorem chain_states_pos {body : Exp A T} (h : Chain body) :
    0 < (certifiedThompson A T body).aut.core.states.length := by
  obtain ⟨l, f, hhead, hsp, hin, hst⟩ := chain_shape h
  rw [hst]
  exact chainSpine_ne_nil hsp

open Classical in
private theorem chain2_states_two {body : Exp A T} (h : Chain2 body) :
    2 ≤ (certifiedThompson A T body).aut.core.states.length := by
  obtain ⟨he, hf⟩ := h
  show 2 ≤ ((certifiedThompson A T _).aut.core.states.map Sum.inl
    ++ (certifiedThompson A T _).aut.core.states.map Sum.inr).length
  rw [List.length_append, List.length_map, List.length_map]
  have h1 := chain_states_pos he
  have h2 := chain_states_pos hf
  omega

open Classical in
private theorem chain2_chain {body : Exp A T} (h : Chain2 body) :
    Chain body := by
  obtain ⟨he, hf⟩ := h
  exact Chain.seq he hf

open Classical in
/-- **CHAIN-LOOP COMPLETENESS (pair form)**: uniformly equivalent while
    loops over chain bodies with nondegenerate guards are provably equal
    from the finite axioms — no uniqueness axiom. -/
theorem chainloops_complete_pair (b₁ b₂ : BExp T) {body₁ body₂ : Exp A T}
    (hc₁ : Chain body₁) (hc₂ : Chain body₂)
    (hlen2₁ : 2 ≤ (certifiedThompson A T body₁).aut.core.states.length)
    (hlen2₂ : 2 ≤ (certifiedThompson A T body₂).aut.core.states.length)
    (hexit₁ : ∃ α : T → Bool, bval (genW T) b₁ α = false)
    (hexit₂ : ∃ α : T → Bool, bval (genW T) b₂ α = false)
    (hbsat₁ : ∃ α : T → Bool, bval (genW T) b₁ α = true)
    (hbsat₂ : ∃ α : T → Bool, bval (genW T) b₂ α = true)
    (heq : UniformLanguageEquivalent (.wh b₁ body₁) (.wh b₂ body₂)) :
    EquivBA (.wh b₁ body₁) (.wh b₂ body₂) := by
  obtain ⟨l₁, f₁, hhead₁, hsp₁, hin₁, hst₁⟩ := chain_shape hc₁
  obtain ⟨l₂, f₂, hhead₂, hsp₂, hin₂, hst₂⟩ := chain_shape hc₂
  rw [hst₁] at hlen2₁
  rw [hst₂] at hlen2₂
  have hexh₁ : ∀ x, x ∈ l₁ := by
    intro x
    rw [← hst₁]
    exact chain_exhaustive hc₁ x
  have hexh₂ : ∀ x, x ∈ l₂ := by
    intro x
    rw [← hst₂]
    exact chain_exhaustive hc₂ x
  have hfl₁ : l₁[0]'(by omega) = f₁ := by
    cases l₁ with
    | nil => exact nomatch hhead₁
    | cons x t => exact Option.some.inj hhead₁
  have hfl₂ : l₂[0]'(by omega) = f₂ := by
    cases l₂ with
    | nil => exact nomatch hhead₂
    | cons x t => exact Option.some.inj hhead₂
  obtain ⟨qsol, hq⟩ := chain_loops_solvable b₁ b₂ hsp₁ hsp₂ hin₁ hin₂
    (certifiedThompson A T body₁).structural.targets
    (certifiedThompson A T body₁).certificate.initTargets
    (certifiedThompson A T body₂).structural.targets
    (certifiedThompson A T body₂).certificate.initTargets
    hst₁ hst₂ hexh₁ hexh₂ hexit₁ hexit₂ hbsat₁ hbsat₂
    hlen2₁ hlen2₂ hfl₁ hfl₂
  exact equivBA_of_quot_solvesBA (.wh b₁ body₁) (.wh b₂ body₂) heq hq

open Classical in
/-- **THE FOURTH UNCONDITIONAL COMPLETENESS THEOREM**: uniformly
    equivalent while loops over MULTI-ACTION chain bodies with
    nondegenerate guards are provably equal from the finite GKAT axioms
    alone — the uniqueness axiom is eliminable on this stratum. -/
theorem chainloops_complete (b₁ b₂ : BExp T) {body₁ body₂ : Exp A T}
    (hc₁ : Chain2 body₁) (hc₂ : Chain2 body₂)
    (hexit₁ : ∃ α : T → Bool, bval (genW T) b₁ α = false)
    (hexit₂ : ∃ α : T → Bool, bval (genW T) b₂ α = false)
    (hbsat₁ : ∃ α : T → Bool, bval (genW T) b₁ α = true)
    (hbsat₂ : ∃ α : T → Bool, bval (genW T) b₂ α = true)
    (heq : UniformLanguageEquivalent (.wh b₁ body₁) (.wh b₂ body₂)) :
    EquivBA (.wh b₁ body₁) (.wh b₂ body₂) :=
  chainloops_complete_pair b₁ b₂ (chain2_chain hc₁) (chain2_chain hc₂)
    (chain2_states_two hc₁) (chain2_states_two hc₂)
    hexit₁ hexit₂ hbsat₁ hbsat₂ heq

#print axioms chainloops_complete

/-! ## Degenerate guards collapse

    A loop whose guard is semantically false is `skip`; one whose guard is
    semantically true is `abort`.  The `bval_gen` naturality upgrades
    generic-atom degeneracy to every valuation, where `wh_guard` swaps the
    guard for the literal and the S0 collapses finish. -/

open Classical in
/-- A guarded choice with literal-false guard is its else arm. -/
theorem ite_false (e f : Exp A T) :
    EquivBA (.ite .zero e f : Exp A T) f :=
  EquivBA.trans (EquivBA.base (Equiv.u4 .zero e f))
    (EquivBA.trans
      (EquivBA.ite_c (EquivBA.base (Equiv.s2 e))
        (EquivBA.base (Equiv.refl f)))
      (EquivBA.trans (ite_zero_then .zero f)
        (EquivBA.trans
          (EquivBA.seq_c
            (EquivBA.baTest (b := .not .zero) (c := .one)
              (fun X W x => rfl))
            (EquivBA.base (Equiv.refl f)))
          (EquivBA.base (Equiv.s4 f)))))

open Classical in
/-- A loop with literal-false guard is `skip`. -/
theorem wh_zero_skip (e : Exp A T) :
    EquivBA (.wh .zero e : Exp A T) (.test .one) :=
  EquivBA.trans (EquivBA.base (Equiv.w1 .zero e))
    (ite_false _ _)

open Classical in
/-- **SEMANTICALLY-TRUE GUARD ⟹ ABORT**: a loop whose guard holds at every
    generic atom is `assert false`. -/
theorem wh_guard_semantic_one {b : BExp T} (e : Exp A T)
    (h : ∀ α : T → Bool, bval (genW T) b α = true) :
    EquivBA (.wh b e : Exp A T) (.test .zero) := by
  -- transport-free: every loop ends in its exit guard, which here is `0`
  refine EquivBA.trans (wh_emits_exit_all b e) ?_
  refine EquivBA.trans (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
    (EquivBA.baTest (b := .not b) (c := .zero) ?_)) ?_
  · intro X W x
    show (!bval W b x) = bval W (.zero : BExp T) x
    rw [bval_gen W x b, h (fun t => W t x)]
    rfl
  · exact EquivBA.base (Equiv.s3 _)

open Classical in
/-- **SEMANTICALLY-FALSE GUARD ⟹ SKIP**: a loop whose guard fails at every
    generic atom is `skip`. -/
theorem wh_guard_semantic_zero {b : BExp T} (e : Exp A T)
    (h : ∀ α : T → Bool, bval (genW T) b α = false) :
    EquivBA (.wh b e : Exp A T) (.test .one) := by
  -- transport-free: `w1` moves the guard into an `ite`, where guard
  -- equality is admissible (GkatGuardTransport.ite_guard), and `ite_zero`
  -- finishes.  No loop-guard transport.
  refine EquivBA.trans (EquivBA.base (Equiv.w1 b e)) ?_
  refine EquivBA.trans (EquivBA.ite_guard (b := b) (c := .zero) ?_) ?_
  · intro X W x
    rw [bval_gen W x b, h (fun t => W t x)]
    rfl
  · exact EquivBA.base (GkatFaithful.ite_zero _ _)

#print axioms wh_guard_semantic_one
#print axioms wh_guard_semantic_zero

/-! ## The hypothesis-free closure

    Degenerate sides collapse to tests; tests compare by `baTest`; a test
    never equals a live loop (which denotes a word with an action); live
    sides meet `chainloops_complete`.  The guard hypotheses vanish. -/

open Classical in
private theorem bval_all_false {b : BExp T}
    (h : ¬ ∃ α : T → Bool, bval (genW T) b α = true) :
    ∀ α : T → Bool, bval (genW T) b α = false := by
  intro α
  cases hb : bval (genW T) b α with
  | false => rfl
  | true => exact absurd ⟨α, hb⟩ h

open Classical in
private theorem bval_all_true {b : BExp T}
    (h : ¬ ∃ α : T → Bool, bval (genW T) b α = false) :
    ∀ α : T → Bool, bval (genW T) b α = true := by
  intro α
  cases hb : bval (genW T) b α with
  | true => rfl
  | false => exact absurd ⟨α, hb⟩ h

open Classical in
/-- Soundness transport on the left. -/
theorem ule_congr_left {e e' f : Exp A T} (h : EquivBA e e')
    (hu : UniformLanguageEquivalent e f) :
    UniformLanguageEquivalent e' f :=
  fun X W gs => (sound_BA (V := W) h gs).symm.trans (hu X W gs)

open Classical in
/-- Soundness transport on the right. -/
theorem ule_congr_right {e f f' : Exp A T} (h : EquivBA f f')
    (hu : UniformLanguageEquivalent e f) :
    UniformLanguageEquivalent e f' :=
  fun X W gs => (hu X W gs).trans (sound_BA (V := W) h gs)

open Classical in
theorem ule_symm {e f : Exp A T} (hu : UniformLanguageEquivalent e f) :
    UniformLanguageEquivalent f e :=
  fun X W gs => (hu X W gs).symm

open Classical in
/-- Uniformly equivalent tests are provably equal. -/
theorem test_test_equiv {c₁ c₂ : BExp T}
    (hu : UniformLanguageEquivalent (.test c₁ : Exp A T) (.test c₂)) :
    EquivBA (.test c₁ : Exp A T) (.test c₂) := by
  refine EquivBA.baTest ?_
  intro X W x
  have h := hu X W (x, [])
  simp only [den_test] at h
  cases hb : bval W c₁ x with
  | true =>
      have := (h.mp ⟨hb, True.intro⟩).1
      rw [this]
  | false =>
      cases hb2 : bval W c₂ x with
      | false => rfl
      | true =>
          have := (h.mpr ⟨hb2, True.intro⟩).1
          rw [hb] at this
          exact nomatch this

open Classical in
/-- A chain denotes a word of its actions between ANY atoms. -/
theorem chain_den_word {body : Exp A T} (h : Chain body) :
    ∀ a target : T → Bool,
      ∃ l : List (A × (T → Bool)), l ≠ []
        ∧ den (genW T) body (a, l) ∧ lastAtom a l = target := by
  induction h with
  | act p =>
      intro a target
      refine ⟨[(p, target)], by simp, ⟨a, target, rfl⟩, rfl⟩
  | @seq e f he hf ihe ihf =>
      intro a target
      obtain ⟨l₁, h1ne, h1den, h1last⟩ := ihe a target
      obtain ⟨l₂, h2ne, h2den, h2last⟩ := ihf target target
      refine ⟨l₁ ++ l₂, ?_, ?_, ?_⟩
      · intro hcontra
        rcases List.append_eq_nil_iff.mp hcontra with ⟨h1, -⟩
        exact h1ne h1
      · refine ⟨l₁, l₂, rfl, h1den, ?_⟩
        rw [h1last]
        exact h2den
      · rw [lastAtom_append, h1last, h2last]

open Classical in
/-- A live chain loop denotes a word with at least one action. -/
theorem wh_chain_word {b : BExp T} {body : Exp A T} (hc : Chain body)
    {αb αe : T → Bool}
    (hb : bval (genW T) b αb = true)
    (he : bval (genW T) b αe = false) :
    ∃ gs : GS A (T → Bool), gs.2 ≠ []
      ∧ den (genW T) (.wh b body) gs := by
  obtain ⟨l, hne, hden, hlast⟩ := chain_den_word hc αb αe
  refine ⟨(αb, l ++ []), ?_, ?_⟩
  · simp only [List.append_nil]
    exact hne
  · exact InLoop.step αb l [] hb hden
      (by
        rw [hlast]
        exact InLoop.exit αe he)

open Classical in
/-- A test is never uniformly equivalent to a live chain loop. -/
theorem test_ne_liveloop {c b : BExp T} {body : Exp A T}
    (hc : Chain body)
    (hbsat : ∃ α : T → Bool, bval (genW T) b α = true)
    (hexit : ∃ α : T → Bool, bval (genW T) b α = false)
    (hu : UniformLanguageEquivalent (.test c : Exp A T) (.wh b body)) :
    False := by
  obtain ⟨αb, hb⟩ := hbsat
  obtain ⟨αe, he⟩ := hexit
  obtain ⟨gs, hne, hden⟩ := wh_chain_word hc hb he
  have := (hu (T → Bool) (genW T) gs).mpr hden
  exact hne this.2

open Classical in
/-- **THE HYPOTHESIS-FREE FOURTH THEOREM**: uniformly equivalent while
    loops over multi-action chain bodies are provably equal from the
    finite GKAT axioms — ARBITRARY guards, no uniqueness axiom. -/
theorem chainloops_complete_free (b₁ b₂ : BExp T)
    {body₁ body₂ : Exp A T}
    (hc₁ : Chain2 body₁) (hc₂ : Chain2 body₂)
    (heq : UniformLanguageEquivalent (.wh b₁ body₁) (.wh b₂ body₂)) :
    EquivBA (.wh b₁ body₁) (.wh b₂ body₂) := by
  rcases Classical.em (∃ α : T → Bool, bval (genW T) b₁ α = true)
    with hbsat₁ | hbdeg₁
  case inr =>
    have hcol₁ : EquivBA (.wh b₁ body₁ : Exp A T) (.test .one) :=
      wh_guard_semantic_zero body₁ (bval_all_false hbdeg₁)
    rcases Classical.em (∃ α : T → Bool, bval (genW T) b₂ α = true)
      with hbsat₂ | hbdeg₂
    case inr =>
      have hcol₂ : EquivBA (.wh b₂ body₂ : Exp A T) (.test .one) :=
        wh_guard_semantic_zero body₂ (bval_all_false hbdeg₂)
      exact EquivBA.trans hcol₁
        (EquivBA.trans
          (test_test_equiv (ule_congr_right hcol₂
            (ule_congr_left hcol₁ heq)))
          (EquivBA.symm hcol₂))
    case inl =>
      rcases Classical.em (∃ α : T → Bool, bval (genW T) b₂ α = false)
        with hexit₂ | hnexit₂
      case inr =>
        have hcol₂ : EquivBA (.wh b₂ body₂ : Exp A T) (.test .zero) :=
          wh_guard_semantic_one body₂ (bval_all_true hnexit₂)
        exact EquivBA.trans hcol₁
          (EquivBA.trans
            (test_test_equiv (ule_congr_right hcol₂
              (ule_congr_left hcol₁ heq)))
            (EquivBA.symm hcol₂))
      case inl =>
        exact absurd (ule_congr_left hcol₁ heq)
          (fun hu => test_ne_liveloop (chain2_chain hc₂) hbsat₂
            hexit₂ hu)
  case inl =>
    rcases Classical.em (∃ α : T → Bool, bval (genW T) b₁ α = false)
      with hexit₁ | hnexit₁
    case inr =>
      have hcol₁ : EquivBA (.wh b₁ body₁ : Exp A T) (.test .zero) :=
        wh_guard_semantic_one body₁ (bval_all_true hnexit₁)
      rcases Classical.em (∃ α : T → Bool, bval (genW T) b₂ α = true)
        with hbsat₂ | hbdeg₂
      case inr =>
        have hcol₂ : EquivBA (.wh b₂ body₂ : Exp A T) (.test .one) :=
          wh_guard_semantic_zero body₂ (bval_all_false hbdeg₂)
        exact EquivBA.trans hcol₁
          (EquivBA.trans
            (test_test_equiv (ule_congr_right hcol₂
              (ule_congr_left hcol₁ heq)))
            (EquivBA.symm hcol₂))
      case inl =>
        rcases Classical.em
          (∃ α : T → Bool, bval (genW T) b₂ α = false)
          with hexit₂ | hnexit₂
        case inr =>
          have hcol₂ : EquivBA (.wh b₂ body₂ : Exp A T)
              (.test .zero) :=
            wh_guard_semantic_one body₂ (bval_all_true hnexit₂)
          exact EquivBA.trans hcol₁
            (EquivBA.trans
              (test_test_equiv (ule_congr_right hcol₂
                (ule_congr_left hcol₁ heq)))
              (EquivBA.symm hcol₂))
        case inl =>
          exact absurd (ule_congr_left hcol₁ heq)
            (fun hu => test_ne_liveloop (chain2_chain hc₂) hbsat₂
              hexit₂ hu)
    case inl =>
      rcases Classical.em (∃ α : T → Bool, bval (genW T) b₂ α = true)
        with hbsat₂ | hbdeg₂
      case inr =>
        have hcol₂ : EquivBA (.wh b₂ body₂ : Exp A T) (.test .one) :=
          wh_guard_semantic_zero body₂ (bval_all_false hbdeg₂)
        exact absurd (ule_symm (ule_congr_right hcol₂ heq))
          (fun hu => test_ne_liveloop (chain2_chain hc₁) hbsat₁
            hexit₁ hu)
      case inl =>
        rcases Classical.em
          (∃ α : T → Bool, bval (genW T) b₂ α = false)
          with hexit₂ | hnexit₂
        case inr =>
          have hcol₂ : EquivBA (.wh b₂ body₂ : Exp A T)
              (.test .zero) :=
            wh_guard_semantic_one body₂ (bval_all_true hnexit₂)
          exact absurd (ule_symm (ule_congr_right hcol₂ heq))
            (fun hu => test_ne_liveloop (chain2_chain hc₁) hbsat₁
              hexit₁ hu)
        case inl =>
          exact chainloops_complete b₁ b₂ hc₁ hc₂ hexit₁ hexit₂
            hbsat₁ hbsat₂ heq

#print axioms chainloops_complete_free

end GkatChainFragment
