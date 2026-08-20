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

end GkatChainFragment
