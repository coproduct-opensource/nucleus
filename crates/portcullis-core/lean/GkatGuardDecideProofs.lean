import GkatPlanExistenceProofs

/-! # Decidable guard satisfiability — the de-choice keystone

    `bval` at the generic valuation depends only on the primitive tests
    occurring in the guard.  Over a decidable test alphabet, that makes
    guard satisfiability and refutability at generic atoms DECIDABLE by
    finite Boolean enumeration — computably, with no choice.  Every
    classical case split on guard degeneracy in the completeness ladder
    can then run on this instance instead of `Classical.em`. -/

namespace GkatGuardDecide

open GkatSyntax GkatGS GkatPlanExistence

variable {S A T : Type}

/-- The primitive tests occurring in a guard. -/
def testsOf : BExp T → List T
  | .zero => []
  | .one => []
  | .prim t => [t]
  | .and b c => testsOf b ++ testsOf c
  | .or b c => testsOf b ++ testsOf c
  | .not b => testsOf b

/-- Point-update of an atom. -/
def override [DecidableEq T] (α : T → Bool) (t : T) (v : Bool) :
    T → Bool :=
  fun s => if s = t then v else α s

/-- All Boolean assignments over a finite test list. -/
def enumAtoms [DecidableEq T] : List T → List (T → Bool)
  | [] => [fun _ => false]
  | t :: ts =>
      (enumAtoms ts).map (fun α => override α t true)
        ++ (enumAtoms ts).map (fun α => override α t false)

/-- **FINITE SUPPORT**: generic evaluation sees only the occurring
    tests. -/
theorem bval_testsOf {g : BExp T} {α β : T → Bool}
    (h : ∀ t ∈ testsOf g, α t = β t) :
    bval (genW T) g α = bval (genW T) g β := by
  induction g with
  | zero => rfl
  | one => rfl
  | prim t =>
      show α t = β t
      exact h t (List.mem_cons_self ..)
  | and b c ihb ihc =>
      show (bval (genW T) b α && bval (genW T) c α)
        = (bval (genW T) b β && bval (genW T) c β)
      rw [ihb (fun t ht => h t (List.mem_append.mpr (Or.inl ht))),
          ihc (fun t ht => h t (List.mem_append.mpr (Or.inr ht)))]
  | or b c ihb ihc =>
      show (bval (genW T) b α || bval (genW T) c α)
        = (bval (genW T) b β || bval (genW T) c β)
      rw [ihb (fun t ht => h t (List.mem_append.mpr (Or.inl ht))),
          ihc (fun t ht => h t (List.mem_append.mpr (Or.inr ht)))]
  | not b ihb =>
      show (!bval (genW T) b α) = (!bval (genW T) b β)
      rw [ihb h]

/-- The enumeration realizes every atom on the listed tests. -/
theorem enumAtoms_complete [DecidableEq T] :
    ∀ (ts : List T) (α : T → Bool),
      ∃ β ∈ enumAtoms ts, ∀ t ∈ ts, β t = α t := by
  intro ts
  induction ts with
  | nil =>
      intro α
      refine ⟨fun _ => false, List.mem_cons_self .., ?_⟩
      intro t ht
      exact nomatch ht
  | cons t ts ih =>
      intro α
      obtain ⟨β, hmem, hagree⟩ := ih α
      refine ⟨override β t (α t), ?_, ?_⟩
      · cases hv : α t with
        | true =>
            exact List.mem_append.mpr (Or.inl (List.mem_map.mpr
              ⟨β, hmem, rfl⟩))
        | false =>
            exact List.mem_append.mpr (Or.inr (List.mem_map.mpr
              ⟨β, hmem, rfl⟩))
      · intro s hs
        rcases List.mem_cons.mp hs with hst | hsts
        · show (if s = t then α t else β s) = α s
          rw [if_pos hst, hst]
        · show (if s = t then α t else β s) = α s
          by_cases hst : s = t
          · rw [if_pos hst, hst]
          · rw [if_neg hst]
            exact hagree s hsts

/-- **DECIDABLE SATISFIABILITY** at generic atoms — computable, no
    choice. -/
instance guardSatDecidable [DecidableEq T] (g : BExp T) :
    Decidable (∃ α : T → Bool, bval (genW T) g α = true) :=
  decidable_of_iff
    (∃ β ∈ enumAtoms (testsOf g), bval (genW T) g β = true)
    (by
      constructor
      · rintro ⟨β, -, hb⟩
        exact ⟨β, hb⟩
      · rintro ⟨α, hα⟩
        obtain ⟨β, hmem, hagree⟩ := enumAtoms_complete (testsOf g) α
        refine ⟨β, hmem, ?_⟩
        rw [bval_testsOf (g := g) (fun t ht => hagree t ht)]
        exact hα)

/-- **DECIDABLE REFUTABILITY** at generic atoms. -/
instance guardRefDecidable [DecidableEq T] (g : BExp T) :
    Decidable (∃ α : T → Bool, bval (genW T) g α = false) :=
  decidable_of_iff
    (∃ β ∈ enumAtoms (testsOf g), bval (genW T) g β = false)
    (by
      constructor
      · rintro ⟨β, -, hb⟩
        exact ⟨β, hb⟩
      · rintro ⟨α, hα⟩
        obtain ⟨β, hmem, hagree⟩ := enumAtoms_complete (testsOf g) α
        refine ⟨β, hmem, ?_⟩
        rw [bval_testsOf (g := g) (fun t ht => hagree t ht)]
        exact hα)

#print axioms guardSatDecidable
#print axioms guardRefDecidable

/-! ## Bounded liveness, decidably

    `firstMatch` decomposes into DISJOINT effective guards (each arm's
    guard conjoined with the negation of all earlier ones), so "some atom
    steps here" is guard satisfiability.  `liveWithin n` — acceptance
    reachable within `n` steps — is then decidable by structural
    recursion, and implies `Live`. -/

open GkatKleene

/-- Arms with their effective (first-match) guards: each guard conjoined
    with the negation of the accumulated earlier guards. -/
def effList : List (BExp T × A × S) → BExp T → List (BExp T × A × S)
  | [], _ => []
  | (g, a, t) :: rest, D =>
      (.and g (.not D), a, t) :: effList rest (.or D g)

private theorem effList_cons (g : BExp T) (a : A) (t : S)
    (rest : List (BExp T × A × S)) (D : BExp T) :
    effList ((g, a, t) :: rest) D
      = (.and g (.not D), a, t) :: effList rest (.or D g) := rfl

/-- A firing effective guard refutes its accumulated prefix. -/
theorem effList_guard_refutes {Atom : Type} (V : T → Atom → Bool)
    (x : Atom) :
    ∀ (L : List (BExp T × A × S)) (D : BExp T),
      ∀ e ∈ effList L D, bval V e.1 x = true → bval V D x = false := by
  intro L
  induction L with
  | nil => intro D e he; exact nomatch he
  | cons hd rest ih =>
      intro D e he hb
      obtain ⟨g, a, t⟩ := hd
      rw [effList_cons] at he
      rcases List.mem_cons.mp he with heq | hmem
      · subst heq
        have hb' : (bval V g x && !(bval V D x)) = true := hb
        rw [Bool.and_eq_true] at hb'
        cases hD : bval V D x with
        | false => rfl
        | true =>
            rw [hD] at hb'
            exact nomatch hb'.2
      · have := ih (.or D g) e hmem hb
        have hor : (bval V D x || bval V g x) = false := this
        cases hD : bval V D x with
        | false => rfl
        | true =>
            rw [hD] at hor
            exact nomatch hor

/-- A firing effective arm IS the first match. -/
theorem effList_fires {Atom : Type} (V : T → Atom → Bool) (x : Atom) :
    ∀ (L : List (BExp T × A × S)) (D : BExp T),
      bval V D x = false →
      ∀ e ∈ effList L D, bval V e.1 x = true →
        firstMatch V x L = some (e.2.1, e.2.2) := by
  intro L
  induction L with
  | nil => intro D _ e he; exact nomatch he
  | cons hd rest ih =>
      intro D hD e he hb
      obtain ⟨g, a, t⟩ := hd
      rw [effList_cons] at he
      rcases List.mem_cons.mp he with heq | hmem
      · subst heq
        have hb' : (bval V g x && !(bval V D x)) = true := hb
        rw [Bool.and_eq_true] at hb'
        show (if bval V g x = true then some (a, t)
          else firstMatch V x rest) = some (a, t)
        rw [if_pos hb'.1]
      · have hDg : (bval V D x || bval V g x) = false :=
          effList_guard_refutes V x rest (.or D g) e hmem hb
        have hg : bval V g x = false := by
          cases hg : bval V g x with
          | false => rfl
          | true =>
              rw [hg, hD] at hDg
              exact nomatch hDg
        show (if bval V g x = true then some (a, t)
          else firstMatch V x rest) = some (e.2.1, e.2.2)
        rw [if_neg (by rw [hg]; exact Bool.false_ne_true)]
        exact ih (.or D g) hDg e hmem hb

/-- Acceptance reachable within `n` steps. -/
def liveWithin (aut : GAut S A T) : Nat → S → Prop
  | 0, s => ∃ α : T → Bool, bval (genW T) (aut.hlt s) α = true
  | n + 1, s =>
      (∃ α : T → Bool, bval (genW T) (aut.hlt s) α = true)
      ∨ ∃ e ∈ effList (aut.trans s) .zero,
          (∃ α : T → Bool, bval (genW T) e.1 α = true)
          ∧ liveWithin aut n e.2.2

private theorem liveWithin_zero (aut : GAut S A T) (s : S) :
    liveWithin aut 0 s
      = ∃ α : T → Bool, bval (genW T) (aut.hlt s) α = true := rfl

private theorem liveWithin_succ (aut : GAut S A T) (n : Nat) (s : S) :
    liveWithin aut (n + 1) s
      = ((∃ α : T → Bool, bval (genW T) (aut.hlt s) α = true)
        ∨ ∃ e ∈ effList (aut.trans s) .zero,
            (∃ α : T → Bool, bval (genW T) e.1 α = true)
            ∧ liveWithin aut n e.2.2) := rfl

/-- Hand-rolled decidable bounded existential over a list. -/
def decideExMem {γ : Type} {P : γ → Prop}
    (dec : ∀ e : γ, Decidable (P e)) :
    (L : List γ) → Decidable (∃ e ∈ L, P e)
  | [] => isFalse (by rintro ⟨e, he, -⟩; exact nomatch he)
  | x :: xs =>
      match dec x with
      | isTrue h => isTrue ⟨x, List.mem_cons_self .., h⟩
      | isFalse hx =>
          match decideExMem dec xs with
          | isTrue h =>
              isTrue (by
                obtain ⟨e, he, hp⟩ := h
                exact ⟨e, List.mem_cons_of_mem _ he, hp⟩)
          | isFalse hxs =>
              isFalse (by
                rintro ⟨e, he, hp⟩
                rcases List.mem_cons.mp he with heq | hm
                · exact hx (heq ▸ hp)
                · exact hxs ⟨e, hm, hp⟩)

/-- **DECIDABLE BOUNDED LIVENESS** — computable, no choice. -/
def liveWithinDec [DecidableEq T] (aut : GAut S A T) :
    (n : Nat) → (s : S) → Decidable (liveWithin aut n s)
  | 0, s => guardSatDecidable (aut.hlt s)
  | n + 1, s =>
      @instDecidableOr _ _ (guardSatDecidable (aut.hlt s))
        (decideExMem (fun e =>
          @instDecidableAnd _ _ (guardSatDecidable e.1)
            (liveWithinDec aut n e.2.2)) (effList (aut.trans s) .zero))

/-- Bounded liveness is liveness. -/
theorem liveWithin_live (aut : GAut S A T) :
    ∀ (n : Nat) (s : S), liveWithin aut n s → Live aut s := by
  intro n
  induction n with
  | zero =>
      intro s h
      obtain ⟨α, hα⟩ := h
      exact ⟨α, [], hα⟩
  | succ n ih =>
      intro s h
      rw [liveWithin_succ] at h
      rcases h with hacc | ⟨e, he, ⟨α, hα⟩, hlw⟩
      · obtain ⟨α, hα⟩ := hacc
        exact ⟨α, [], hα⟩
      · obtain ⟨β, w, hrun⟩ := ih e.2.2 hlw
        refine ⟨α, (e.2.1, β) :: w, e.2.2, ?_, hrun⟩
        show firstMatch (genW T) α (aut.trans s) = some (e.2.1, e.2.2)
        exact effList_fires (genW T) α (aut.trans s) .zero rfl e he hα

#print axioms effList_fires
#print axioms liveWithin_live

/-! ## The chain correspondence

    Bounded liveness is a step chain: a nonempty list of states linked by
    satisfiable effective arms, ending in acceptance.  Runs of any length
    give chains; chains of length `k+1` give `liveWithin k`.  The next
    phase dedups chains against a closed pool to cap the bound. -/

theorem liveWithin_of_acc (aut : GAut S A T) (s : S)
    (h : ∃ α : T → Bool, bval (genW T) (aut.hlt s) α = true) :
    ∀ n : Nat, liveWithin aut n s
  | 0 => h
  | _ + 1 => Or.inl h

theorem liveWithin_mono (aut : GAut S A T) :
    ∀ (n m : Nat), n ≤ m → ∀ s, liveWithin aut n s → liveWithin aut m s := by
  intro n
  induction n with
  | zero =>
      intro m _ s h
      exact liveWithin_of_acc aut s h m
  | succ n ih =>
      intro m hm s h
      rw [liveWithin_succ] at h
      rcases h with hacc | ⟨e, he, hsat, hlw⟩
      · exact liveWithin_of_acc aut s hacc m
      · cases m with
        | zero => exact absurd hm (by omega)
        | succ m =>
            rw [liveWithin_succ]
            exact Or.inr ⟨e, he, hsat, ih m (by omega) e.2.2 hlw⟩

/-- Converse of `effList_fires`: a first match is a firing effective
    arm. -/
theorem effList_of_firstMatch {Atom : Type} (V : T → Atom → Bool)
    (x : Atom) :
    ∀ (L : List (BExp T × A × S)) (D : BExp T),
      bval V D x = false →
      ∀ {o : A × S}, firstMatch V x L = some o →
        ∃ e ∈ effList L D, bval V e.1 x = true
          ∧ e.2.1 = o.1 ∧ e.2.2 = o.2 := by
  intro L
  induction L with
  | nil => intro D _ o h; exact nomatch h
  | cons hd rest ih =>
      intro D hD o h
      obtain ⟨g, a, t⟩ := hd
      rw [effList_cons]
      by_cases hg : bval V g x = true
      · rw [show firstMatch V x ((g, a, t) :: rest)
            = if bval V g x = true then some (a, t)
              else firstMatch V x rest from rfl, if_pos hg] at h
        have hinj := Option.some.inj h
        refine ⟨(.and g (.not D), a, t), List.mem_cons_self .., ?_, ?_, ?_⟩
        · show (bval V g x && !(bval V D x)) = true
          rw [hg, hD]
          rfl
        · show a = o.1
          rw [← hinj]
        · show t = o.2
          rw [← hinj]
      · rw [show firstMatch V x ((g, a, t) :: rest)
            = if bval V g x = true then some (a, t)
              else firstMatch V x rest from rfl, if_neg hg] at h
        have hg' : bval V g x = false := by
          cases hgv : bval V g x with
          | false => rfl
          | true => exact absurd hgv hg
        have hDg : (bval V D x || bval V g x) = false := by
          rw [hD, hg']
          rfl
        obtain ⟨e, he, h1, h2, h3⟩ := ih (.or D g) hDg h
        exact ⟨e, List.mem_cons_of_mem _ he, h1, h2, h3⟩

/-- A step chain: states linked by satisfiable effective arms, ending in
    acceptance. -/
def StepChain (aut : GAut S A T) : List S → Prop
  | [] => False
  | [s] => ∃ α : T → Bool, bval (genW T) (aut.hlt s) α = true
  | s :: t :: rest =>
      (∃ e ∈ effList (aut.trans s) .zero,
        (∃ α : T → Bool, bval (genW T) e.1 α = true) ∧ e.2.2 = t)
      ∧ StepChain aut (t :: rest)

private theorem stepChain_one (aut : GAut S A T) (s : S) :
    StepChain aut [s]
      = ∃ α : T → Bool, bval (genW T) (aut.hlt s) α = true := rfl

private theorem stepChain_cons (aut : GAut S A T) (s t : S)
    (rest : List S) :
    StepChain aut (s :: t :: rest)
      = ((∃ e ∈ effList (aut.trans s) .zero,
          (∃ α : T → Bool, bval (genW T) e.1 α = true) ∧ e.2.2 = t)
        ∧ StepChain aut (t :: rest)) := rfl

/-- Bounded liveness yields a short chain. -/
theorem liveWithin_chain (aut : GAut S A T) :
    ∀ (n : Nat) (s : S), liveWithin aut n s →
      ∃ ch : List S, StepChain aut ch ∧ ch.head? = some s
        ∧ ch.length ≤ n + 1 := by
  intro n
  induction n with
  | zero =>
      intro s h
      exact ⟨[s], h, rfl, by simp⟩
  | succ n ih =>
      intro s h
      rw [liveWithin_succ] at h
      rcases h with hacc | ⟨e, he, hsat, hlw⟩
      · exact ⟨[s], hacc, rfl, by simp⟩
      · obtain ⟨ch, hch, hhead, hlen⟩ := ih e.2.2 hlw
        cases ch with
        | nil => exact nomatch hhead
        | cons t ch' =>
            have ht : t = e.2.2 := Option.some.inj hhead
            subst ht
            refine ⟨s :: e.2.2 :: ch', ?_, rfl, ?_⟩
            · rw [stepChain_cons]
              exact ⟨⟨e, he, hsat, rfl⟩, hch⟩
            · simp only [List.length_cons] at hlen ⊢
              omega

/-- A chain of `k+1` states is liveness within `k` steps. -/
theorem chain_liveWithin (aut : GAut S A T) :
    ∀ (ch : List S) (s : S), StepChain aut ch → ch.head? = some s →
      liveWithin aut (ch.length - 1) s := by
  intro ch
  induction ch with
  | nil => intro s _ hh; exact nomatch hh
  | cons x ch' ih =>
      intro s hch hh
      have hx : x = s := Option.some.inj hh
      subst hx
      cases ch' with
      | nil => exact hch
      | cons y rest =>
          rw [stepChain_cons] at hch
          obtain ⟨⟨e, he, hsat, het⟩, hrest⟩ := hch
          show liveWithin aut (rest.length + 1) x
          rw [liveWithin_succ]
          refine Or.inr ⟨e, he, hsat, ?_⟩
          rw [het]
          have := ih y hrest rfl
          simp only [List.length_cons, Nat.add_sub_cancel] at this
          exact this

/-- Any run gives bounded liveness at its own length. -/
theorem run_liveWithin_len (aut : GAut S A T) :
    ∀ (w : List (A × (T → Bool))) (s : S) (α : T → Bool),
      autRun (genW T) aut s α w → liveWithin aut w.length s := by
  intro w
  induction w with
  | nil =>
      intro s α h
      exact ⟨α, h⟩
  | cons qa w' ih =>
      intro s α h
      obtain ⟨q, β⟩ := qa
      obtain ⟨s', hstep, hrun⟩ := h
      show liveWithin aut (w'.length + 1) s
      rw [liveWithin_succ]
      refine Or.inr ?_
      obtain ⟨e, he, hb, -, he2⟩ := effList_of_firstMatch (genW T) α
        (aut.trans s) .zero rfl hstep
      refine ⟨e, he, ⟨α, hb⟩, ?_⟩
      rw [he2]
      exact ih s' β hrun

#print axioms liveWithin_chain
#print axioms chain_liveWithin
#print axioms run_liveWithin_len

end GkatGuardDecide
