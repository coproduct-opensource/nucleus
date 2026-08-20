import GkatTrimProofs
import GkatListPigeonProofs

/-! # Decidable guard satisfiability — the de-choice keystone

    `bval` at the generic valuation depends only on the primitive tests
    occurring in the guard.  Over a decidable test alphabet, that makes
    guard satisfiability and refutability at generic atoms DECIDABLE by
    finite Boolean enumeration — computably, with no choice.  Every
    classical case split on guard degeneracy in the completeness ladder
    can then run on this instance instead of `Classical.em`. -/

namespace GkatGuardDecide

open GkatSyntax GkatGS GkatPlanExistence GkatListPigeon GkatTrim

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

/-! ## Constructive dedup: `Live ↔ liveWithin |pool|`

    A chain longer than a closed pool repeats a state (constructive
    pigeonhole via decidable equality); splicing at the repetition
    shortens it, preserving the head.  Shortest chains fit in the pool,
    so liveness is bounded liveness at `|pool|` — decidably. -/

/-- Effective arms carry original targets. -/
theorem effList_target_mem :
    ∀ (L : List (BExp T × A × S)) (D : BExp T),
      ∀ e ∈ effList L D, ∃ g₀, (g₀, e.2.1, e.2.2) ∈ L := by
  intro L
  induction L with
  | nil => intro D e he; exact nomatch he
  | cons hd rest ih =>
      intro D e he
      obtain ⟨g, a, t⟩ := hd
      rw [effList_cons] at he
      rcases List.mem_cons.mp he with heq | hmem
      · subst heq
        exact ⟨g, List.mem_cons_self ..⟩
      · obtain ⟨g₀, hg₀⟩ := ih (.or D g) e hmem
        exact ⟨g₀, List.mem_cons_of_mem _ hg₀⟩

/-- Chains from a pool state stay in a closed pool. -/
theorem stepChain_mem_pool (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool) :
    ∀ (ch : List S) (s : S), StepChain aut ch → ch.head? = some s →
      s ∈ pool → ∀ x ∈ ch, x ∈ pool := by
  intro ch
  induction ch with
  | nil => intro s _ hh; exact nomatch hh
  | cons y ch' ih =>
      intro s hch hh hs x hx
      have hy : y = s := Option.some.inj hh
      subst hy
      cases ch' with
      | nil =>
          rcases List.mem_cons.mp hx with heq | hm
          · exact heq ▸ hs
          · exact nomatch hm
      | cons z rest =>
          rw [stepChain_cons] at hch
          obtain ⟨⟨e, he, -, het⟩, hrest⟩ := hch
          have hz : z ∈ pool := by
            obtain ⟨g₀, hg₀⟩ := effList_target_mem (aut.trans y) .zero e he
            have := hclosed y hs (g₀, e.2.1, e.2.2) hg₀
            rw [het] at this
            exact this
          rcases List.mem_cons.mp hx with heq | hm
          · exact heq ▸ hs
          · exact ih z hrest rfl hz x hm

/-- A cons-suffix of a chain is a chain. -/
theorem stepChain_drop (aut : GAut S A T) :
    ∀ (l₁ l₂ : List S), StepChain aut (l₁ ++ l₂) → l₂ ≠ [] →
      StepChain aut l₂ := by
  intro l₁
  induction l₁ with
  | nil => intro l₂ h _; exact h
  | cons x l₁' ih =>
      intro l₂ h hne
      cases hll : l₁' ++ l₂ with
      | nil =>
          rcases List.append_eq_nil_iff.mp hll with ⟨-, h2⟩
          exact absurd h2 hne
      | cons z rest =>
          have h' : StepChain aut (x :: z :: rest) := by
            rw [← hll]
            exact h
          rw [stepChain_cons] at h'
          refine ih l₂ ?_ hne
          rw [hll]
          exact h'.2

/-- **SPLICE**: a chain with a repeated state shortens across the
    repetition, keeping its head. -/
theorem stepChain_splice (aut : GAut S A T) :
    ∀ (pre : List S) (a : S) (mid post : List S),
      StepChain aut (pre ++ a :: mid ++ a :: post) →
      StepChain aut (pre ++ a :: post) := by
  intro pre
  induction pre with
  | nil =>
      intro a mid post h
      exact stepChain_drop aut (a :: mid) (a :: post) h (by simp)
  | cons x pre' ih =>
      intro a mid post h
      cases pre' with
      | nil =>
          have h' : StepChain aut (x :: a :: (mid ++ a :: post)) := h
          rw [stepChain_cons] at h'
          show StepChain aut (x :: a :: post)
          rw [stepChain_cons]
          exact ⟨h'.1, ih a mid post h'.2⟩
      | cons y pre'' =>
          have h' : StepChain aut
              (x :: y :: (pre'' ++ a :: mid ++ a :: post)) := h
          rw [stepChain_cons] at h'
          show StepChain aut (x :: y :: (pre'' ++ a :: post))
          rw [stepChain_cons]
          exact ⟨h'.1, ih a mid post h'.2⟩

/-- Splicing keeps the head. -/
private theorem splice_head {γ : Type} (pre : List γ) (a : γ)
    (mid post : List γ) :
    (pre ++ a :: post).head? = (pre ++ a :: mid ++ a :: post).head? := by
  cases pre with
  | nil => rfl
  | cons x pre' => rfl

/-- **CHAIN SHORTENING**: every chain from a pool state shortens to fit
    the pool. -/
theorem chain_shorten [DecidableEq S] (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool) :
    ∀ (n : Nat) (ch : List S) (s : S), ch.length ≤ n →
      StepChain aut ch → ch.head? = some s → s ∈ pool →
      ∃ ch' : List S, StepChain aut ch' ∧ ch'.head? = some s
        ∧ ch'.length ≤ pool.length := by
  intro n
  induction n with
  | zero =>
      intro ch s hlen hch hh hs
      cases ch with
      | nil => exact nomatch hh
      | cons x ch' => exact absurd hlen (by simp)
  | succ n ih =>
      intro ch s hlen hch hh hs
      rcases Nat.lt_or_ge pool.length ch.length with hlong | hshort
      · have hin := stepChain_mem_pool aut pool hclosed ch s hch hh hs
        obtain ⟨a, pre, mid, post, hsplit⟩ :=
          long_in_pool_has_dup ch pool hin hlong
        subst hsplit
        have hch' := stepChain_splice aut pre a mid post hch
        have hh' : (pre ++ a :: post).head? = some s := by
          rw [splice_head pre a mid post]
          exact hh
        refine ih (pre ++ a :: post) s ?_ hch' hh' hs
        have h1 : (pre ++ a :: mid ++ a :: post).length ≤ n + 1 := hlen
        simp only [List.length_append, List.length_cons] at h1 ⊢
        omega
      · exact ⟨ch, hch, hh, hshort⟩

/-- **LIVENESS IS BOUNDED LIVENESS** — over a closed pool, decidably. -/
theorem live_iff_liveWithin [DecidableEq S] (aut : GAut S A T)
    (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool)
    (s : S) (hs : s ∈ pool) :
    Live aut s ↔ liveWithin aut pool.length s := by
  constructor
  · rintro ⟨α, w, hrun⟩
    have h1 := run_liveWithin_len aut w s α hrun
    obtain ⟨ch, hch, hh, -⟩ := liveWithin_chain aut w.length s h1
    obtain ⟨ch', hch', hh', hlen'⟩ := chain_shorten aut pool hclosed
      ch.length ch s (Nat.le_refl _) hch hh hs
    have h2 := chain_liveWithin aut ch' s hch' hh'
    have hpos : 0 < ch'.length := by
      cases ch' with
      | nil => exact nomatch hh'
      | cons x t => simp
    exact liveWithin_mono aut (ch'.length - 1) pool.length
      (by omega) s h2
  · exact liveWithin_live aut pool.length s

#print axioms live_iff_liveWithin

/-! ## The computable trim

    With decidable bounded liveness, the trim becomes computable: swap
    the classical `if Live` for `if liveWithin |pool|`.  Over a closed
    pool covering all arm targets, the computable trim IS the trim. -/

instance liveWithinInst [DecidableEq T] (aut : GAut S A T) (n : Nat)
    (s : S) : Decidable (liveWithin aut n s) :=
  liveWithinDec aut n s

/-- Computable trim of an arm list. -/
def trimListD [DecidableEq T] (aut : GAut S A T) (n : Nat) :
    List (BExp T × A × S) → BExp T → List (BExp T × A × S)
  | [], _ => []
  | (g, a, t) :: rest, D =>
      if liveWithin aut n t then
        (.and g (.not D), a, t) :: trimListD aut n rest D
      else trimListD aut n rest (.or D g)

private theorem trimListD_cons [DecidableEq T] (aut : GAut S A T)
    (n : Nat) (g : BExp T) (a : A) (t : S)
    (rest : List (BExp T × A × S)) (D : BExp T) :
    trimListD aut n ((g, a, t) :: rest) D
      = if liveWithin aut n t then
          (.and g (.not D), a, t) :: trimListD aut n rest D
        else trimListD aut n rest (.or D g) := rfl

open Classical in
private theorem trimList_cons₅ (aut : GAut S A T) (g : BExp T) (a : A)
    (t : S) (rest : List (BExp T × A × S)) (D : BExp T) :
    trimList aut ((g, a, t) :: rest) D
      = if Live aut t then (.and g (.not D), a, t) :: trimList aut rest D
        else trimList aut rest (.or D g) := rfl

/-- **THE COMPUTABLE TRIM IS THE TRIM** over a closed pool covering the
    targets. -/
theorem trimListD_eq_trimList [DecidableEq T] [DecidableEq S]
    (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool) :
    ∀ (L : List (BExp T × A × S)) (D : BExp T),
      (∀ e ∈ L, e.2.2 ∈ pool) →
      trimListD aut pool.length L D = trimList aut L D := by
  intro L
  induction L with
  | nil => intro D _; rfl
  | cons hd rest ih =>
      intro D hin
      obtain ⟨g, a, t⟩ := hd
      have ht : t ∈ pool := hin (g, a, t) (List.mem_cons_self ..)
      have hrest : ∀ e ∈ rest, e.2.2 ∈ pool :=
        fun e he => hin e (List.mem_cons_of_mem _ he)
      rw [trimListD_cons, trimList_cons₅]
      by_cases hl : Live aut t
      · rw [if_pos ((live_iff_liveWithin aut pool hclosed t ht).mp hl),
            if_pos hl, ih D hrest]
      · rw [if_neg (fun hlw =>
            hl ((live_iff_liveWithin aut pool hclosed t ht).mpr hlw)),
            if_neg hl, ih (.or D g) hrest]

/-- Computable trimmed automaton. -/
def trimAutD [DecidableEq T] (aut : GAut S A T) (n : Nat) :
    GAut S A T where
  states := aut.states
  hlt := aut.hlt
  trans := fun s => trimListD aut n (aut.trans s) .zero
  start := aut.start

/-- **THE COMPUTABLE TRIMMED AUTOMATON IS `trimAut`** when a pool covers
    every state's arm targets. -/
theorem trimAutD_eq_trimAut [DecidableEq T] [DecidableEq S]
    (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool)
    (htargets : ∀ s : S, ∀ e ∈ aut.trans s, e.2.2 ∈ pool) :
    trimAutD aut pool.length = trimAut aut := by
  have hfun : (fun s => trimListD aut pool.length (aut.trans s) .zero)
      = fun s => trimList aut (aut.trans s) .zero := by
    funext s
    exact trimListD_eq_trimList aut pool hclosed (aut.trans s) .zero
      (htargets s)
  show GAut.mk aut.states aut.hlt
      (fun s => trimListD aut pool.length (aut.trans s) .zero)
      aut.start
    = GAut.mk aut.states aut.hlt
      (fun s => trimList aut (aut.trans s) .zero) aut.start
  rw [hfun]

#print axioms trimListD_eq_trimList
#print axioms trimAutD_eq_trimAut

/-! ## The step-equivalence ladder

    Generic bisimilarity is the intersection of finite step-equivalence
    levels — with an EXPLICIT bisimulation witness, so both directions
    are choice-free.  Stabilization then makes one level decide all. -/

/-- Lift a relation through one deterministic step. -/
def optStepRel (P : S → S → Prop) :
    Option (A × S) → Option (A × S) → Prop
  | none, none => True
  | some o₁, some o₂ => o₁.1 = o₂.1 ∧ P o₁.2 o₂.2
  | some _, none => False
  | none, some _ => False

/-- `n`-step equivalence at the generic valuation. -/
def stepEquivWithin (aut : GAut S A T) : Nat → S → S → Prop
  | 0, _, _ => True
  | n + 1, s, t =>
      (∀ α : T → Bool,
        bval (genW T) (aut.hlt s) α = bval (genW T) (aut.hlt t) α)
      ∧ ∀ α : T → Bool,
          optStepRel (stepEquivWithin aut n)
            (autStep (genW T) aut s α) (autStep (genW T) aut t α)

private theorem stepEquivWithin_succ (aut : GAut S A T) (n : Nat)
    (s t : S) :
    stepEquivWithin aut (n + 1) s t
      = ((∀ α : T → Bool,
          bval (genW T) (aut.hlt s) α = bval (genW T) (aut.hlt t) α)
        ∧ ∀ α : T → Bool,
            optStepRel (stepEquivWithin aut n)
              (autStep (genW T) aut s α)
              (autStep (genW T) aut t α)) := rfl

/-- **DOWNWARD**: bisimilar states are step-equivalent at every level. -/
theorem genBisimilar_stepEquiv (aut : GAut S A T) {s t : S}
    (h : GenBisimilar aut s t) :
    ∀ n : Nat, stepEquivWithin aut n s t := by
  obtain ⟨R, hR, hRst⟩ := h
  intro n
  induction n generalizing s t with
  | zero => exact trivial
  | succ n ih =>
      rw [stepEquivWithin_succ]
      obtain ⟨hhlt, hfwd, hbwd⟩ := hR s t hRst
      refine ⟨hhlt, ?_⟩
      intro α
      cases hs : autStep (genW T) aut s α with
      | none =>
          cases ht : autStep (genW T) aut t α with
          | none => exact trivial
          | some o =>
              obtain ⟨s', hs', -⟩ := hbwd α o.1 o.2 (by
                rw [ht])
              rw [hs] at hs'
              exact nomatch hs'
      | some o =>
          obtain ⟨t', ht', hR'⟩ := hfwd α o.1 o.2 (by rw [hs])
          rw [ht']
          exact ⟨rfl, ih hR'⟩

/-- **UPWARD**: all-level step equivalence is bisimilarity, witnessed by
    the all-level relation itself — no choice. -/
theorem stepEquiv_all_bisim (aut : GAut S A T) {s t : S}
    (h : ∀ n : Nat, stepEquivWithin aut n s t) :
    GenBisimilar aut s t := by
  refine ⟨fun x y => ∀ n : Nat, stepEquivWithin aut n x y, ?_, h⟩
  intro x y hxy
  refine ⟨(hxy 1).1, ?_, ?_⟩
  · intro α q x' hx
    cases hy : autStep (genW T) aut y α with
    | none =>
        have h1 := (hxy 1).2 α
        rw [hx, hy] at h1
        exact absurd h1 (by intro hc; exact hc)
    | some o =>
        have h1 := (hxy 1).2 α
        rw [hx, hy] at h1
        obtain ⟨hq, -⟩ := h1
        refine ⟨o.2, ?_, ?_⟩
        · have hq' : q = o.1 := hq
          rw [hq']
        · intro n
          have hn := (hxy (n + 1)).2 α
          rw [hx, hy] at hn
          exact hn.2
  · intro α q y' hy
    cases hx : autStep (genW T) aut x α with
    | none =>
        have h1 := (hxy 1).2 α
        rw [hx, hy] at h1
        exact absurd h1 (by intro hc; exact hc)
    | some o =>
        have h1 := (hxy 1).2 α
        rw [hx, hy] at h1
        obtain ⟨hq, -⟩ := h1
        refine ⟨o.2, ?_, ?_⟩
        · have hq' : o.1 = q := hq
          rw [← hq']
        · intro n
          have hn := (hxy (n + 1)).2 α
          rw [hx, hy] at hn
          exact hn.2

/-- **THE LADDER CHARACTERIZATION** — choice-free in both directions. -/
theorem genBisimilar_iff_stepEquiv (aut : GAut S A T) (s t : S) :
    GenBisimilar aut s t ↔ ∀ n : Nat, stepEquivWithin aut n s t :=
  ⟨genBisimilar_stepEquiv aut, stepEquiv_all_bisim aut⟩

/-- Levels are antitone. -/
theorem stepEquivWithin_antitone (aut : GAut S A T) :
    ∀ (n : Nat) (s t : S), stepEquivWithin aut (n + 1) s t →
      stepEquivWithin aut n s t := by
  intro n
  induction n with
  | zero => intro s t _; exact trivial
  | succ n ih =>
      intro s t h
      rw [stepEquivWithin_succ] at h ⊢
      refine ⟨h.1, ?_⟩
      intro α
      have h2 := h.2 α
      cases hs : autStep (genW T) aut s α with
      | none =>
          cases ht : autStep (genW T) aut t α with
          | none => exact trivial
          | some o =>
              rw [hs, ht] at h2
              exact h2.elim
      | some o =>
          cases ht : autStep (genW T) aut t α with
          | none =>
              rw [hs, ht] at h2
              exact h2.elim
          | some o' =>
              rw [hs, ht] at h2
              exact ⟨h2.1, ih o.2 o'.2 h2.2⟩

#print axioms genBisimilar_iff_stepEquiv
#print axioms stepEquivWithin_antitone

end GkatGuardDecide
