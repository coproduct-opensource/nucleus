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

end GkatChainFragment
