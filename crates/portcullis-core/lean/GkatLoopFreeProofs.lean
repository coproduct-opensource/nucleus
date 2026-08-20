import GkatCycleProofs
import GkatTrimProofs

/-! # Loop-free completeness — the pipeline's first closed theorem

    Toward: UA-free completeness of the loop-free fragment of GKAT, with NO
    hypotheses.  The route:

    * loop-free Thompson automata carry structural ranks (arms strictly
      decrease), so all their runs are length-bounded;
    * the canonical quotient of a bounded automaton is ACYCLIC: a firing cycle
      would pump unboundedly long words (`maxlen` strictly decreases along
      cleaned arms), so after dropping never-firing arms (`cleanAut`) the
      quotient satisfies the singleton-SCC shape and `singleton_scc_roles`
      covers it;
    * `equivBA_of_quot_solvesBA` closes the pair.

    This file builds the semantic core: cleaning, run-length bounds, the
    `maxlen` rank, and the acyclicity engine (`bounded_quot_solvesBA`). -/

namespace GkatLoopFree

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatSumQuotient
open GkatDecomp GkatPlanExistence GkatGuardedAlgebra GkatResidue
open GkatRingSupport GkatRingPlan GkatNormalization GkatTrim GkatCycle

variable {S A T : Type}

/-- Prepending a step to a run. -/
theorem autRun_step {Atom : Type} {V : T → Atom → Bool} {aut : GAut S A T}
    {s s' : S} {x x' : Atom} {q : A} {w : List (A × Atom)}
    (h1 : autStep V aut s x = some (q, s'))
    (h2 : autRun V aut s' x' w) : autRun V aut s x ((q, x') :: w) :=
  ⟨s', h1, h2⟩

/-- A successful `firstMatch` returns an element of the list. -/
theorem firstMatch_mem {Atom : Type} (V : T → Atom → Bool) {x : Atom}
    {L : List (BExp T × A × S)} {y : A × S}
    (h : firstMatch V x L = some y) :
    ∃ e ∈ L, e.2.1 = y.1 ∧ e.2.2 = y.2 := by
  induction L with
  | nil => exact nomatch h
  | cons hd rest ih =>
      obtain ⟨g, a, t⟩ := hd
      rw [show firstMatch V x ((g, a, t) :: rest)
        = if bval V g x = true then some (a, t) else firstMatch V x rest
        from rfl] at h
      by_cases hg : bval V g x = true
      · rw [if_pos hg] at h
        have hp := Option.some.inj h
        exact ⟨(g, a, t), by simp, congrArg Prod.fst hp, congrArg Prod.snd hp⟩
      · rw [if_neg hg] at h
        obtain ⟨e, he, h1, h2⟩ := ih h
        exact ⟨e, by simp [he], h1, h2⟩

/-- Runs are bounded by any structural rank whose arms strictly decrease. -/
theorem run_len_le_rank {Atom : Type} {V : T → Atom → Bool} {aut : GAut S A T}
    {rank : S → Nat}
    (hdec : ∀ s, ∀ e ∈ aut.trans s, rank e.2.2 < rank s) :
    ∀ (l : List (A × Atom)) (s : S) (x : Atom),
      autRun V aut s x l → l.length ≤ rank s := by
  intro l
  induction l with
  | nil => intro s x _; exact Nat.zero_le _
  | cons p w ih =>
      intro s x hr
      obtain ⟨q, x'⟩ := p
      have hr' : ∃ s', autStep V aut s x = some (q, s')
          ∧ autRun V aut s' x' w := hr
      obtain ⟨s', hstep, hrun⟩ := hr'
      obtain ⟨e, he, -, ht⟩ := firstMatch_mem V hstep
      have hlt : rank s' < rank s := by
        have h0 := hdec s e he
        rw [ht] at h0
        exact h0
      have := ih s' x' hrun
      show w.length + 1 ≤ rank s
      omega

/-! ## Cleaning: drop never-firing arms -/

open Classical in
/-- Drop arms whose effective guard (own guard minus all earlier guards) is
    empty; they can never win `firstMatch`. -/
noncomputable def cleanList :
    List (BExp T × A × S) → BExp T → List (BExp T × A × S)
  | [], _ => []
  | (g, a, t) :: rest, D =>
      if GuardEmpty (.and g (.not D)) then cleanList rest (.or D g)
      else (g, a, t) :: cleanList rest (.or D g)

open Classical in
/-- The cleaned automaton: same states, halts, and one-step behaviour. -/
noncomputable def cleanAut (aut : GAut S A T) : GAut S A T where
  states := aut.states
  hlt := aut.hlt
  trans := fun s => cleanList (aut.trans s) .zero
  start := aut.start

open Classical in
private theorem cleanList_cons (g : BExp T) (a : A) (t : S)
    (rest : List (BExp T × A × S)) (D : BExp T) :
    cleanList ((g, a, t) :: rest) D
      = if GuardEmpty (.and g (.not D)) then cleanList rest (.or D g)
        else (g, a, t) :: cleanList rest (.or D g) := rfl

open Classical in
/-- Cleaning preserves `firstMatch` outside the accumulated guard. -/
theorem firstMatch_cleanList {Atom : Type} (V : T → Atom → Bool)
    (L : List (BExp T × A × S)) (D : BExp T) (x : Atom)
    (hD : bval V D x = false) :
    firstMatch V x (cleanList L D) = firstMatch V x L := by
  induction L generalizing D with
  | nil => rfl
  | cons hd rest ih =>
      obtain ⟨g, a, t⟩ := hd
      rw [cleanList_cons]
      by_cases hE : GuardEmpty (.and g (.not D))
      · rw [if_pos hE]
        have hg : bval V g x = false := by
          cases hgv : bval V g x with
          | false => rfl
          | true =>
              have := hE Atom V x
              rw [show bval V (.and g (.not D)) x
                = (bval V g x && !bval V D x) from rfl, hgv, hD] at this
              exact Bool.noConfusion this
        rw [show firstMatch V x ((g, a, t) :: rest)
          = if bval V g x = true then some (a, t) else firstMatch V x rest
          from rfl]
        rw [if_neg (by rw [hg]; exact fun h => Bool.noConfusion h)]
        refine ih (.or D g) ?_
        show (bval V D x || bval V g x) = false
        rw [hD, hg]; rfl
      · rw [if_neg hE]
        rw [show firstMatch V x ((g, a, t) :: cleanList rest (.or D g))
          = if bval V g x = true then some (a, t)
            else firstMatch V x (cleanList rest (.or D g)) from rfl]
        rw [show firstMatch V x ((g, a, t) :: rest)
          = if bval V g x = true then some (a, t) else firstMatch V x rest
          from rfl]
        by_cases hg : bval V g x = true
        · rw [if_pos hg, if_pos hg]
        · rw [if_neg hg, if_neg hg]
          refine ih (.or D g) ?_
          show (bval V D x || bval V g x) = false
          rw [hD]
          cases hgv : bval V g x with
          | true => exact absurd hgv hg
          | false => rfl

open Classical in
/-- Cleaning does not change one-step behaviour, at any valuation. -/
theorem autStep_cleanAut {Atom : Type} (V : T → Atom → Bool)
    (aut : GAut S A T) (s : S) (x : Atom) :
    autStep V (cleanAut aut) s x = autStep V aut s x :=
  firstMatch_cleanList V (aut.trans s) .zero x rfl

open Classical in
/-- Every cleaned arm wins `firstMatch` at some generic atom. -/
theorem cleanList_fires (aut : GAut S A T) :
    ∀ (L : List (BExp T × A × S)) (D : BExp T), ∀ e ∈ cleanList L D,
      ∃ α : T → Bool, bval (genW T) D α = false ∧
        firstMatch (genW T) α (cleanList L D) = some (e.2.1, e.2.2) := by
  intro L
  induction L with
  | nil => intro D e he; exact nomatch he
  | cons hd rest ih =>
      intro D e he
      obtain ⟨g, a, t⟩ := hd
      rw [cleanList_cons] at he
      by_cases hE : GuardEmpty (.and g (.not D))
      · rw [if_pos hE] at he
        obtain ⟨α, hα, hfm⟩ := ih (.or D g) e he
        have hDα : bval (genW T) D α = false := by
          have h' : (bval (genW T) D α || bval (genW T) g α) = false := hα
          cases hd2 : bval (genW T) D α with
          | false => rfl
          | true => rw [hd2] at h'; exact Bool.noConfusion h'
        refine ⟨α, hDα, ?_⟩
        rw [cleanList_cons, if_pos hE]
        exact hfm
      · rw [if_neg hE] at he
        rcases List.mem_cons.mp he with heq | hmem
        · -- the head arm: pick an atom in its effective guard
          have hne : ¬ (∀ (X : Type) (W : T → X → Bool) (x : X),
              bval W (.and g (.not D)) x = false) := hE
          have hex : ∃ α : T → Bool,
              bval (genW T) (.and g (.not D)) α = true := by
            rcases Classical.em (∃ α : T → Bool,
                bval (genW T) (.and g (.not D)) α = true) with hyes | hno
            · exact hyes
            · exfalso
              refine hne ?_
              intro X W x
              rw [bval_gen W x (.and g (.not D))]
              cases hb : bval (genW T) (.and g (.not D)) (fun u => W u x) with
              | false => rfl
              | true => exact absurd ⟨_, hb⟩ hno
          obtain ⟨α, hα⟩ := hex
          have hgα : bval (genW T) g α = true := by
            have h' : (bval (genW T) g α && !bval (genW T) D α) = true := hα
            cases hg2 : bval (genW T) g α with
            | true => rfl
            | false => rw [hg2] at h'; exact Bool.noConfusion h'
          have hDα : bval (genW T) D α = false := by
            have h' : (bval (genW T) g α && !bval (genW T) D α) = true := hα
            cases hd2 : bval (genW T) D α with
            | false => rfl
            | true =>
                rw [hgα, hd2] at h'
                exact Bool.noConfusion h'
          refine ⟨α, hDα, ?_⟩
          rw [cleanList_cons, if_neg hE, heq]
          show (if bval (genW T) g α = true then some (a, t)
            else firstMatch (genW T) α (cleanList rest (.or D g)))
            = some ((g, a, t).2.1, (g, a, t).2.2)
          rw [if_pos hgα]
        · obtain ⟨α, hα, hfm⟩ := ih (.or D g) e hmem
          have hDα : bval (genW T) D α = false := by
            have h' : (bval (genW T) D α || bval (genW T) g α) = false := hα
            cases hd2 : bval (genW T) D α with
            | false => rfl
            | true => rw [hd2] at h'; exact Bool.noConfusion h'
          have hgα : bval (genW T) g α = false := by
            have h' : (bval (genW T) D α || bval (genW T) g α) = false := hα
            cases hg2 : bval (genW T) g α with
            | false => rfl
            | true =>
                rw [hDα, hg2] at h'
                exact Bool.noConfusion h'
          refine ⟨α, hDα, ?_⟩
          rw [cleanList_cons, if_neg hE]
          show (if bval (genW T) g α = true then some (a, t)
            else firstMatch (genW T) α (cleanList rest (.or D g)))
            = some (e.2.1, e.2.2)
          rw [if_neg (by rw [hgα]; exact fun h => Bool.noConfusion h)]
          exact hfm

#print axioms cleanList_fires

open Classical in
/-- Cleaned runs are the original runs. -/
theorem autRun_cleanAut {Atom : Type} (V : T → Atom → Bool)
    (aut : GAut S A T) :
    ∀ (l : List (A × Atom)) (s : S) (x : Atom),
      autRun V (cleanAut aut) s x l ↔ autRun V aut s x l := by
  intro l
  induction l with
  | nil => intro s x; exact Iff.rfl
  | cons p w ih =>
      intro s x
      obtain ⟨q, x'⟩ := p
      constructor
      · intro hr
        obtain ⟨s', h1, h2⟩ : ∃ s', autStep V (cleanAut aut) s x = some (q, s')
            ∧ autRun V (cleanAut aut) s' x' w := hr
        rw [autStep_cleanAut] at h1
        exact ⟨s', h1, (ih s' x').mp h2⟩
      · intro hr
        obtain ⟨s', h1, h2⟩ : ∃ s', autStep V aut s x = some (q, s')
            ∧ autRun V aut s' x' w := hr
        exact ⟨s', by rw [autStep_cleanAut]; exact h1, (ih s' x').mpr h2⟩

open Classical in
/-- Cleaning is provable: the cleaned equation is the original equation. -/
theorem clean_fold_equiv (aut : GAut S A T) {sol : S → Exp A T} {hltG : BExp T} :
    ∀ (L : List (BExp T × A × S)) (D : BExp T),
    EquivBA (.seq (.test (.not D)) (foldTL sol hltG L))
      (.seq (.test (.not D)) (foldTL sol hltG (cleanList L D))) := by
  intro L
  induction L with
  | nil => intro D; exact EquivBA.base (Equiv.refl _)
  | cons hd rest ih =>
      intro D
      obtain ⟨g, a, t⟩ := hd
      rw [cleanList_cons]
      by_cases hE : GuardEmpty (.and g (.not D))
      · rw [if_pos hE]
        -- the arm's effective guard is empty: it disappears
        refine EquivBA.trans (test_seq_ite (.not D) g _ _) ?_
        refine EquivBA.trans (GkatDeadExitElim.ite_zero_guard _ _
          (fun X W x => by
            have h0 := hE X W x
            show (!bval W D x && bval W g x) = false
            have h0' : (bval W g x && !bval W D x) = false := h0
            cases hg : bval W g x with
            | false => cases bval W D x <;> rfl
            | true =>
                rw [hg] at h0'
                cases hd2 : bval W D x with
                | true => rfl
                | false => rw [hd2] at h0'; exact Bool.noConfusion h0')) ?_
        -- (¬D)? equals (¬(D∨g))? since g ⊆ D here
        refine EquivBA.trans (test_seq_guard_congr (b := .not D)
          (c := .not (.or D g)) _ (fun X W x => by
            have h0 := hE X W x
            show (!bval W D x) = (!(bval W D x || bval W g x))
            have h0' : (bval W g x && !bval W D x) = false := h0
            cases hd2 : bval W D x with
            | true => rfl
            | false =>
                rw [hd2] at h0'
                cases hg : bval W g x with
                | false => rfl
                | true => rw [hg] at h0'; exact Bool.noConfusion h0')) ?_
        refine EquivBA.trans (ih (.or D g)) ?_
        exact test_seq_guard_congr (b := .not (.or D g)) (c := .not D) _
          (fun X W x => by
            have h0 := hE X W x
            show (!(bval W D x || bval W g x)) = (!bval W D x)
            have h0' : (bval W g x && !bval W D x) = false := h0
            cases hd2 : bval W D x with
            | true => rfl
            | false =>
                rw [hd2] at h0'
                cases hg : bval W g x with
                | false => rfl
                | true => rw [hg] at h0'; exact Bool.noConfusion h0')
      · rw [if_neg hE]
        refine EquivBA.trans (test_seq_ite (.not D) g _ _) ?_
        refine EquivBA.trans (ite_congr_under_else
          (EquivBA.trans (else_tighten_or D g (foldTL sol hltG rest))
            (EquivBA.trans (ih (.or D g))
              (EquivBA.symm (else_tighten_or D g
                (foldTL sol hltG (cleanList rest (.or D g)))))))) ?_
        exact EquivBA.symm (test_seq_ite (.not D) g _ _)

open Classical in
/-- Solutions of the cleaned system solve the original system. -/
theorem solvesBA_unclean (aut : GAut S A T) {sol : S → Exp A T}
    (hsol : SolvesBA (cleanAut aut) sol) : SolvesBA aut sol := by
  intro s hs
  refine EquivBA.trans (hsol s hs) ?_
  refine EquivBA.symm ?_
  rw [eqRHS_foldTL]
  refine EquivBA.trans (EquivBA.symm (not_zero_strip _)) ?_
  refine EquivBA.trans (clean_fold_equiv aut (aut.trans s) .zero) ?_
  exact not_zero_strip _

open Classical in
private theorem trimList_cons'' (aut : GAut S A T) (g : BExp T) (a : A) (t : S)
    (rest : List (BExp T × A × S)) (D : BExp T) :
    trimList aut ((g, a, t) :: rest) D
      = if Live aut t then (.and g (.not D), a, t) :: trimList aut rest D
        else trimList aut rest (.or D g) := rfl

/-- Trimmed arms come from original arms (letter and target preserved). -/
theorem trimList_target_mem (aut : GAut S A T) :
    ∀ (L : List (BExp T × A × S)) (D : BExp T), ∀ e ∈ trimList aut L D,
      ∃ g₀, (g₀, e.2.1, e.2.2) ∈ L := by
  intro L
  induction L with
  | nil => intro D e he; exact nomatch he
  | cons hd rest ih =>
      intro D e he
      obtain ⟨g, a, t⟩ := hd
      rw [trimList_cons''] at he
      by_cases hl : Live aut t
      · rw [if_pos hl] at he
        rcases List.mem_cons.mp he with heq | hmem
        · subst heq
          exact ⟨g, by simp⟩
        · obtain ⟨g₀, hg₀⟩ := ih D e hmem
          exact ⟨g₀, by simp [hg₀]⟩
      · rw [if_neg hl] at he
        obtain ⟨g₀, hg₀⟩ := ih (.or D g) e he
        exact ⟨g₀, by simp [hg₀]⟩

/-- Trimmed arms have live targets. -/
theorem trimList_target_live (aut : GAut S A T) :
    ∀ (L : List (BExp T × A × S)) (D : BExp T), ∀ e ∈ trimList aut L D,
      Live aut e.2.2 := by
  intro L
  induction L with
  | nil => intro D e he; exact nomatch he
  | cons hd rest ih =>
      intro D e he
      obtain ⟨g, a, t⟩ := hd
      rw [trimList_cons''] at he
      by_cases hl : Live aut t
      · rw [if_pos hl] at he
        rcases List.mem_cons.mp he with heq | hmem
        · subst heq; exact hl
        · exact ih D e hmem
      · rw [if_neg hl] at he
        exact ih (.or D g) e he

/-- Membership bounds a fold-max. -/
theorem le_foldr_max : ∀ (l : List Nat) (n : Nat), n ∈ l →
    n ≤ l.foldr max 0 := by
  intro l
  induction l with
  | nil => intro n hn; exact nomatch hn
  | cons m rest ih =>
      intro n hn
      rcases List.mem_cons.mp hn with heq | hmem
      · subst heq
        exact Nat.le_max_left _ _
      · exact Nat.le_trans (ih n hmem) (Nat.le_max_right _ _)

/-! ## The semantic rank: exact maximum accepted length -/

open Classical in
/-- The largest accepted-word length `≤ b`. -/
noncomputable def maxlenB (aut : GAut S A T) (s : S) : Nat → Nat
  | 0 => 0
  | b + 1 =>
      if ∃ (α : T → Bool) (l : List (A × (T → Bool))),
          l.length = b + 1 ∧ autRun (genW T) aut s α l
      then b + 1 else maxlenB aut s b

open Classical in
private theorem maxlenB_succ (aut : GAut S A T) (s : S) (b : Nat) :
    maxlenB aut s (b + 1)
      = if ∃ (α : T → Bool) (l : List (A × (T → Bool))),
            l.length = b + 1 ∧ autRun (genW T) aut s α l
        then b + 1 else maxlenB aut s b := rfl

open Classical in
/-- Any accepted length within the budget is below the maximum. -/
theorem maxlenB_ge (aut : GAut S A T) (s : S) :
    ∀ (b : Nat) {α : T → Bool} {l : List (A × (T → Bool))},
      autRun (genW T) aut s α l → l.length ≤ b →
      l.length ≤ maxlenB aut s b := by
  intro b
  induction b with
  | zero => intro α l _ hle; exact hle
  | succ b ih =>
      intro α l hr hle
      rw [maxlenB_succ]
      by_cases hex : ∃ (α : T → Bool) (l : List (A × (T → Bool))),
          l.length = b + 1 ∧ autRun (genW T) aut s α l
      · rw [if_pos hex]
        exact hle
      · rw [if_neg hex]
        have hne : l.length ≠ b + 1 := by
          intro h
          exact hex ⟨α, l, h, hr⟩
        exact ih hr (by omega)

open Classical in
/-- On a live, budget-bounded state, the maximum is achieved. -/
theorem maxlenB_witness (aut : GAut S A T) (s : S)
    (hlive : ∃ (α : T → Bool) (l : List (A × (T → Bool))),
      autRun (genW T) aut s α l) :
    ∀ (b : Nat),
      (∀ (α : T → Bool) (l : List (A × (T → Bool))),
        autRun (genW T) aut s α l → l.length ≤ b) →
      ∃ (α : T → Bool) (l : List (A × (T → Bool))),
        l.length = maxlenB aut s b ∧ autRun (genW T) aut s α l := by
  intro b
  induction b with
  | zero =>
      intro hb
      obtain ⟨α, l, hr⟩ := hlive
      have h0 : maxlenB aut s 0 = 0 := rfl
      exact ⟨α, l, by rw [h0]; have := hb α l hr; omega, hr⟩
  | succ b ih =>
      intro hb
      rw [maxlenB_succ]
      by_cases hex : ∃ (α : T → Bool) (l : List (A × (T → Bool))),
          l.length = b + 1 ∧ autRun (genW T) aut s α l
      · rw [if_pos hex]
        obtain ⟨α, l, hlen, hr⟩ := hex
        exact ⟨α, l, hlen, hr⟩
      · rw [if_neg hex]
        refine ih ?_
        intro α l hr
        have := hb α l hr
        have hne : l.length ≠ b + 1 := fun h => hex ⟨α, l, h, hr⟩
        omega

#print axioms solvesBA_unclean
#print axioms maxlenB_witness

/-! ## The acyclicity engine -/

open Classical in
theorem cleanList_sub :
    ∀ (L : List (BExp T × A × S)) (D : BExp T), ∀ e ∈ cleanList L D,
      e ∈ L := by
  intro L
  induction L with
  | nil => intro D e he; exact nomatch he
  | cons hd rest ih =>
      intro D e he
      obtain ⟨g, a, t⟩ := hd
      rw [cleanList_cons] at he
      by_cases hE : GuardEmpty (.and g (.not (D)))
      · rw [if_pos hE] at he
        exact List.mem_cons_of_mem _ (ih (.or D g) e he)
      · rw [if_neg hE] at he
        rcases List.mem_cons.mp he with heq | hmem
        · exact heq ▸ List.mem_cons_self
        · exact List.mem_cons_of_mem _ (ih (.or D g) e hmem)

open Classical in
/-- Bisimilarity on the trim is a bisimulation INTO the canonical quotient. -/
theorem trim_quot_bisim (aut : GAut S A T) :
    GAutBisim (genW T) (trimAut aut) (bisimQuotAut (trimAut aut))
      (GenBisimilar (trimAut aut)) := by
  intro s q hR
  obtain ⟨h1, h2, h3⟩ := genBisimilar_bisim (trimAut aut) s q hR
  refine ⟨h1, ?_, ?_⟩
  · intro α a v hs
    obtain ⟨v', hq, hvv'⟩ := h2 α a v hs
    refine ⟨bisimRep (trimAut aut) v', ?_, ?_⟩
    · rw [bisimQuotAut_step, hq]
      rfl
    · exact hvv'.trans (bisimRep_bisim (trimAut aut) v')
  · intro α a u' hq
    rw [bisimQuotAut_step] at hq
    cases hstep : autStep (genW T) (trimAut aut) q α with
    | none => rw [hstep] at hq; exact nomatch hq
    | some y =>
        obtain ⟨a0, v'⟩ := y
        rw [hstep] at hq
        have hp : (a0, bisimRep (trimAut aut) v') = (a, u') :=
          Option.some.inj hq
        have ha : a0 = a := congrArg Prod.fst hp
        have hu : bisimRep (trimAut aut) v' = u' := congrArg Prod.snd hp
        subst ha; subst hu
        obtain ⟨v, hs, hvv'⟩ := h3 α a0 v' hstep
        exact ⟨v, hs, hvv'.trans (bisimRep_bisim (trimAut aut) v')⟩

open Classical in
/-- Quotient languages agree with trim languages at EVERY carrier element. -/
theorem quot_lang_eq (aut : GAut S A T) (c : S) :
    autLang (genW T) (bisimQuotAut (trimAut aut)) c
      = autLang (genW T) (trimAut aut) c :=
  (autLang_eq_of_gautBisim (trim_quot_bisim aut)
    (GenBisimilar.refl (trimAut aut) c)).symm

open Classical in
/-- **THE ACYCLICITY ENGINE**: the canonical quotient of a structurally ranked
    automaton is provably solvable — its cleaned form satisfies the
    singleton-SCC shape, because a firing arm strictly decreases the exact
    maximum accepted length. -/
theorem bounded_quot_solvesBA (aut : GAut S A T) (rank : S → Nat)
    (hdec : ∀ s, ∀ e ∈ aut.trans s, rank e.2.2 < rank s) :
    ∃ qsol : S → Exp A T,
      SolvesBA (bisimQuotAut (trimAut aut)) qsol := by
  -- trim arms still descend
  have hdecT : ∀ s, ∀ e ∈ (trimAut aut).trans s, rank e.2.2 < rank s := by
    intro s e he
    obtain ⟨g₀, hg₀⟩ := trimList_target_mem aut (aut.trans s) .zero e he
    exact hdec s (g₀, e.2.1, e.2.2) hg₀
  -- runs of the CLEANED QUOTIENT from any carrier element are rank-bounded
  have hrunQ : ∀ (c : S) (α : T → Bool) (l : List (A × (T → Bool))),
      autRun (genW T) (cleanAut (bisimQuotAut (trimAut aut))) c α l →
      l.length ≤ rank c := by
    intro c α l hr
    have h1 : autRun (genW T) (bisimQuotAut (trimAut aut)) c α l :=
      (autRun_cleanAut (genW T) _ l c α).mp hr
    have h2 : autRun (genW T) (trimAut aut) c α l :=
      (iff_of_eq (congrFun (quot_lang_eq aut c) (α, l))).mp h1
    exact run_len_le_rank hdecT l c α h2
  -- the semantic rank
  have hshape : ∀ c ∈ (cleanAut (bisimQuotAut (trimAut aut))).states,
      ∀ e ∈ (cleanAut (bisimQuotAut (trimAut aut))).trans c,
      e.2.2 = c ∨
        maxlenB (cleanAut (bisimQuotAut (trimAut aut))) e.2.2 (rank e.2.2)
          < maxlenB (cleanAut (bisimQuotAut (trimAut aut))) c (rank c) := by
    intro c _ e he
    by_cases hself : e.2.2 = c
    · exact Or.inl hself
    · refine Or.inr ?_
      -- the arm fires at some generic atom
      obtain ⟨α, -, hfm⟩ := cleanList_fires
        (bisimQuotAut (trimAut aut))
        ((bisimQuotAut (trimAut aut)).trans c) .zero e he
      have hstepC : autStep (genW T)
          (cleanAut (bisimQuotAut (trimAut aut))) c α
          = some (e.2.1, e.2.2) := hfm
      -- the target is live in the cleaned quotient
      have heQ : e ∈ (bisimQuotAut (trimAut aut)).trans c :=
        cleanList_sub _ .zero e he
      have htlive : ∃ (β : T → Bool) (w : List (A × (T → Bool))),
          autRun (genW T) (cleanAut (bisimQuotAut (trimAut aut)))
            e.2.2 β w := by
        -- e.2.2 = bisimRep of a live trim target
        obtain ⟨v', hv', hrep⟩ : ∃ v', v' ∈ (trimAut aut).trans c ∧
            bisimRep (trimAut aut) v'.2.2 = e.2.2 := by
          have : e ∈ ((trimAut aut).trans c).map
              (fun t => (t.1, t.2.1, bisimRep (trimAut aut) t.2.2)) := heQ
          obtain ⟨v', hv', heq⟩ := List.mem_map.mp this
          exact ⟨v', hv', congrArg (fun z => z.2.2) heq⟩
        have hlv : Live aut v'.2.2 :=
          trimList_target_live aut (aut.trans c) .zero v' hv'
        have hlvT : Live (trimAut aut) v'.2.2 := live_trimAut hlv
        have hlrep : Live (trimAut aut) (bisimRep (trimAut aut) v'.2.2) := by
          obtain ⟨β, w, hw⟩ := hlvT
          have hle : autLang (genW T) (trimAut aut) v'.2.2
              = autLang (genW T) (trimAut aut)
                (bisimRep (trimAut aut) v'.2.2) :=
            autLang_eq_of_gautBisim (genBisimilar_bisim (trimAut aut))
              (bisimRep_bisim (trimAut aut) v'.2.2)
          exact ⟨β, w, (iff_of_eq (congrFun hle (β, w))).mp hw⟩
        obtain ⟨β, w, hw⟩ := hlrep
        rw [hrep] at hw
        refine ⟨β, w, ?_⟩
        refine (autRun_cleanAut (genW T) _ w e.2.2 β).mpr ?_
        exact (iff_of_eq (congrFun (quot_lang_eq aut e.2.2) (β, w))).mpr hw
      -- witness the target's maximum, prepend, compare
      obtain ⟨β, w, hlen, hw⟩ := maxlenB_witness _ e.2.2 htlive (rank e.2.2)
        (fun β w hw => hrunQ e.2.2 β w hw)
      have hpre : autRun (genW T) (cleanAut (bisimQuotAut (trimAut aut)))
          c α ((e.2.1, β) :: w) := autRun_step hstepC hw
      have hble : ((e.2.1, β) :: w).length ≤ rank c := hrunQ c α _ hpre
      have hge := maxlenB_ge _ c (rank c) hpre hble
      have : w.length + 1
          ≤ maxlenB (cleanAut (bisimQuotAut (trimAut aut))) c (rank c) := hge
      omega
  obtain ⟨qsol, hroles⟩ := singleton_scc_roles
    (cleanAut (bisimQuotAut (trimAut aut)))
    (fun c => maxlenB (cleanAut (bisimQuotAut (trimAut aut))) c (rank c))
    hshape
  exact ⟨qsol, solvesBA_unclean _ (decomp_solves _ _ hroles)⟩

#print axioms bounded_quot_solvesBA

/-! ## Structural ranks for loop-free Thompson automata -/

/-- The loop-free fragment. -/
inductive LoopFree : Exp A T → Prop where
  | act (p : A) : LoopFree (.act p)
  | test (b : BExp T) : LoopFree (.test b)
  | seq {e f : Exp A T} : LoopFree e → LoopFree f → LoopFree (.seq e f)
  | ite (b : BExp T) {e f : Exp A T} :
      LoopFree e → LoopFree f → LoopFree (.ite b e f)

/-- A ranked initialized automaton: initial arms land under `top`, core arms
    strictly descend, and all states sit under `top`. -/
structure InitRanked {S' : Type} (aut : InitializedGAut S' A T)
    (r : S' → Nat) (top : Nat) : Prop where
  init : ∀ t ∈ aut.initTrans, r t.2.2 < top
  core : ∀ s, ∀ t ∈ aut.core.trans s, r t.2.2 < r s
  bound : ∀ s, r s < top

/-- Loop-free Thompson automata are ranked. -/
theorem loopFree_initRanked {e : Exp A T} (h : LoopFree e) :
    ∃ (r : (certifiedThompson A T e).State → Nat) (top : Nat),
      InitRanked (certifiedThompson A T e).aut r top := by
  induction h with
  | act p =>
      refine ⟨fun _ => 0, 1, ⟨?_, ?_, ?_⟩⟩
      · intro t ht
        rcases List.mem_cons.mp ht with heq | hmem
        · subst heq; exact Nat.zero_lt_one
        · exact nomatch hmem
      · intro s t ht
        exact nomatch ht
      · intro _; exact Nat.zero_lt_one
  | test b =>
      refine ⟨fun _ => 0, 1, ⟨?_, ?_, ?_⟩⟩
      · intro t ht; exact nomatch ht
      · intro s; exact nomatch s
      · intro s; exact nomatch s
  | @seq e f _ _ ihe ihf =>
      obtain ⟨r₁, t₁, h₁⟩ := ihe
      obtain ⟨r₂, t₂, h₂⟩ := ihf
      refine ⟨Sum.elim (fun s => r₁ s + t₂) r₂, t₁ + t₂, ⟨?_, ?_, ?_⟩⟩
      · intro t ht
        rcases List.mem_append.mp ht with hL | hR
        · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hL
          rw [← heq]
          have := h₁.init t₀ ht₀
          show r₁ t₀.2.2 + t₂ < t₁ + t₂
          omega
        · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hR
          rw [← heq]
          have := h₂.init t₀ ht₀
          have := h₂.bound t₀.2.2
          show r₂ t₀.2.2 < t₁ + t₂
          omega
      · intro s t ht
        cases s with
        | inl u =>
            rcases List.mem_append.mp ht with hL | hR
            · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hL
              rw [← heq]
              have := h₁.core u t₀ ht₀
              show r₁ t₀.2.2 + t₂ < r₁ u + t₂
              omega
            · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hR
              rw [← heq]
              have := h₂.init t₀ ht₀
              show r₂ t₀.2.2 < r₁ u + t₂
              omega
        | inr u =>
            obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp ht
            rw [← heq]
            have := h₂.core u t₀ ht₀
            show r₂ t₀.2.2 < r₂ u
            omega
      · intro s
        cases s with
        | inl u =>
            have := h₁.bound u
            show r₁ u + t₂ < t₁ + t₂
            omega
        | inr u =>
            have := h₂.bound u
            show r₂ u < t₁ + t₂
            omega
  | @ite b e f _ _ ihe ihf =>
      obtain ⟨r₁, t₁, h₁⟩ := ihe
      obtain ⟨r₂, t₂, h₂⟩ := ihf
      refine ⟨Sum.elim r₁ r₂, t₁ + t₂, ⟨?_, ?_, ?_⟩⟩
      · intro t ht
        rcases List.mem_append.mp ht with hL | hR
        · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hL
          rw [← heq]
          have := h₁.init t₀ ht₀
          show r₁ t₀.2.2 < t₁ + t₂
          omega
        · obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp hR
          rw [← heq]
          have := h₂.init t₀ ht₀
          show r₂ t₀.2.2 < t₁ + t₂
          omega
      · intro s t ht
        cases s with
        | inl u =>
            obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp ht
            rw [← heq]
            have := h₁.core u t₀ ht₀
            show r₁ t₀.2.2 < r₁ u
            omega
        | inr u =>
            obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp ht
            rw [← heq]
            have := h₂.core u t₀ ht₀
            show r₂ t₀.2.2 < r₂ u
            omega
      · intro s
        cases s with
        | inl u =>
            have := h₁.bound u
            show r₁ u < t₁ + t₂
            omega
        | inr u =>
            have := h₂.bound u
            show r₂ u < t₁ + t₂
            omega

/-- Lift a ranked initialized automaton to its closed form. -/
def optRank {S' : Type} (r : S' → Nat) (top : Nat) : Option S' → Nat
  | none => top
  | some s => r s

theorem toGAut_ranked {S' : Type} {aut : InitializedGAut S' A T}
    {r : S' → Nat} {top : Nat} (h : InitRanked aut r top) :
    ∀ s, ∀ e ∈ aut.toGAut.trans s,
      optRank r top e.2.2 < optRank r top s := by
  intro s e he
  cases s with
  | none =>
      obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp he
      rw [← heq]
      exact h.init t₀ ht₀
  | some u =>
      obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp he
      rw [← heq]
      exact h.core u t₀ ht₀

theorem sumGAut_ranked {S₁ S₂ : Type} {aut₁ : GAut S₁ A T}
    {aut₂ : GAut S₂ A T} {rk₁ : S₁ → Nat} {rk₂ : S₂ → Nat}
    (h₁ : ∀ s, ∀ e ∈ aut₁.trans s, rk₁ e.2.2 < rk₁ s)
    (h₂ : ∀ s, ∀ e ∈ aut₂.trans s, rk₂ e.2.2 < rk₂ s) :
    ∀ s, ∀ e ∈ (sumGAut aut₁ aut₂).trans s,
      Sum.elim rk₁ rk₂ e.2.2 < Sum.elim rk₁ rk₂ s := by
  intro s e he
  cases s with
  | inl u =>
      obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp he
      rw [← heq]
      exact h₁ u t₀ ht₀
  | inr u =>
      obtain ⟨t₀, ht₀, heq⟩ := List.mem_map.mp he
      rw [← heq]
      exact h₂ u t₀ ht₀

open GkatSumQuotient in
/-- **LOOP-FREE COMPLETENESS** — the pipeline's first closed theorem: the
    finite GKAT axioms with the test Boolean algebra are complete for
    uniformly-language-equivalent LOOP-FREE programs.  No uniqueness axiom, no
    hypotheses: the trimmed sum is ranked, its canonical quotient is therefore
    acyclic, `singleton_scc_roles` covers it, and the rewired summit chain
    closes the pair. -/
theorem loopfree_complete (e f : Exp A T) (he : LoopFree e) (hf : LoopFree f)
    (heq : UniformLanguageEquivalent e f) : EquivBA e f := by
  obtain ⟨r₁, t₁, h₁⟩ := loopFree_initRanked he
  obtain ⟨r₂, t₂, h₂⟩ := loopFree_initRanked hf
  obtain ⟨qsol, hq⟩ := bounded_quot_solvesBA (SUMof A T e f)
    (Sum.elim (optRank r₁ t₁) (optRank r₂ t₂))
    (sumGAut_ranked (toGAut_ranked h₁) (toGAut_ranked h₂))
  exact equivBA_of_quot_solvesBA e f heq hq

#print axioms loopfree_complete

end GkatLoopFree
