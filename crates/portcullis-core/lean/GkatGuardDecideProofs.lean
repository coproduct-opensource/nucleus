import GkatAtomicLoopProofs
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
open GkatLoopFree GkatAtomicLoop

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

/-! ## Deciding each level

    A level's `∀ α` factors through finitely many guards: halting
    agreement is decidable guard equality, and the step condition is a
    finite conjunction over effective-arm pairs — co-satisfiable arms
    must agree in letter and drop a level, and no arm may fire where the
    other side has nothing. -/

/-- Hand-rolled decidable bounded universal over a list. -/
def decideAllMem {γ : Type} {P : γ → Prop}
    (dec : ∀ e : γ, Decidable (P e)) :
    (L : List γ) → Decidable (∀ e ∈ L, P e)
  | [] => isTrue (by intro e he; exact nomatch he)
  | x :: xs =>
      match dec x with
      | isFalse hx =>
          isFalse (fun h => hx (h x (List.mem_cons_self ..)))
      | isTrue hx =>
          match decideAllMem dec xs with
          | isTrue hxs =>
              isTrue (by
                intro e he
                rcases List.mem_cons.mp he with heq | hm
                · exact heq ▸ hx
                · exact hxs e hm)
          | isFalse hxs =>
              isFalse (fun h => hxs
                (fun e he => h e (List.mem_cons_of_mem _ he)))

/-- Decidable guard equality at generic atoms. -/
def guardEqDecidable [DecidableEq T] (g₁ g₂ : BExp T) :
    Decidable (∀ α : T → Bool,
      bval (genW T) g₁ α = bval (genW T) g₂ α) :=
  decidable_of_iff
    (∀ β ∈ enumAtoms (testsOf g₁ ++ testsOf g₂),
      bval (genW T) g₁ β = bval (genW T) g₂ β)
    (by
      constructor
      · intro h α
        obtain ⟨β, hmem, hagree⟩ :=
          enumAtoms_complete (testsOf g₁ ++ testsOf g₂) α
        calc bval (genW T) g₁ α
            = bval (genW T) g₁ β := (bval_testsOf (fun t ht =>
              hagree t (List.mem_append.mpr (Or.inl ht)))).symm
          _ = bval (genW T) g₂ β := h β hmem
          _ = bval (genW T) g₂ α := bval_testsOf (fun t ht =>
              hagree t (List.mem_append.mpr (Or.inr ht)))
      · intro h β _
        exact h β)

/-- The disjunction of a list's guards. -/
def armsOr : List (BExp T × A × S) → BExp T
  | [] => .zero
  | e :: rest => .or e.1 (armsOr rest)

private theorem fm_cons₆ {Atom : Type} (V : T → Atom → Bool) (x : Atom)
    (g : BExp T) (a : A) (t : S) (rest : List (BExp T × A × S)) :
    firstMatch V x ((g, a, t) :: rest)
      = if bval V g x = true then some (a, t)
        else firstMatch V x rest := rfl

/-- `firstMatch` fails exactly where no guard fires. -/
theorem firstMatch_none_iff {Atom : Type} (V : T → Atom → Bool)
    (x : Atom) :
    ∀ L : List (BExp T × A × S),
      firstMatch V x L = none ↔ bval V (armsOr L) x = false := by
  intro L
  induction L with
  | nil => exact ⟨fun _ => rfl, fun _ => rfl⟩
  | cons hd rest ih =>
      obtain ⟨g, a, t⟩ := hd
      rw [fm_cons₆]
      constructor
      · intro h
        by_cases hg : bval V g x = true
        · rw [if_pos hg] at h
          exact nomatch h
        · rw [if_neg hg] at h
          have hg' : bval V g x = false := by
            cases hgv : bval V g x with
            | false => rfl
            | true => exact absurd hgv hg
          show (bval V g x || bval V (armsOr rest) x) = false
          rw [hg', ih.mp h]
          rfl
      · intro h
        have h' : (bval V g x || bval V (armsOr rest) x) = false := h
        cases hgv : bval V g x with
        | true =>
            rw [hgv] at h'
            exact nomatch h'
        | false =>
            rw [if_neg (by exact Bool.false_ne_true)]
            refine ih.mpr ?_
            rw [hgv] at h'
            exact h'

/-- **THE STEP CONDITION IS FINITE**: the `∀ α` step clause is a finite
    conjunction over effective-arm pairs. -/
theorem forall_optStepRel_iff (aut : GAut S A T) (P : S → S → Prop)
    (s t : S) :
    (∀ α : T → Bool, optStepRel P
        (autStep (genW T) aut s α) (autStep (genW T) aut t α))
    ↔ ((∀ e ∈ effList (aut.trans s) .zero,
          ∀ e' ∈ effList (aut.trans t) .zero,
          (∃ α : T → Bool, bval (genW T) (.and e.1 e'.1) α = true) →
            e.2.1 = e'.2.1 ∧ P e.2.2 e'.2.2)
      ∧ (∀ e ∈ effList (aut.trans s) .zero,
          ¬ ∃ α : T → Bool, bval (genW T)
            (.and e.1 (.not (armsOr (aut.trans t)))) α = true)
      ∧ (∀ e' ∈ effList (aut.trans t) .zero,
          ¬ ∃ α : T → Bool, bval (genW T)
            (.and (.not (armsOr (aut.trans s))) e'.1) α = true)) := by
  constructor
  · intro h
    refine ⟨?_, ?_, ?_⟩
    · intro e he e' he' ⟨α, hα⟩
      have hα' : (bval (genW T) e.1 α && bval (genW T) e'.1 α)
          = true := hα
      rw [Bool.and_eq_true] at hα'
      have hs := effList_fires (genW T) α (aut.trans s) .zero rfl
        e he hα'.1
      have ht := effList_fires (genW T) α (aut.trans t) .zero rfl
        e' he' hα'.2
      have h2 := h α
      show e.2.1 = e'.2.1 ∧ P e.2.2 e'.2.2
      rw [show autStep (genW T) aut s α
          = some (e.2.1, e.2.2) from hs,
        show autStep (genW T) aut t α
          = some (e'.2.1, e'.2.2) from ht] at h2
      exact h2
    · rintro e he ⟨α, hα⟩
      have hα' : (bval (genW T) e.1 α
          && !(bval (genW T) (armsOr (aut.trans t)) α)) = true := hα
      rw [Bool.and_eq_true] at hα'
      have hs := effList_fires (genW T) α (aut.trans s) .zero rfl
        e he hα'.1
      have htnone : firstMatch (genW T) α (aut.trans t) = none := by
        refine (firstMatch_none_iff (genW T) α (aut.trans t)).mpr ?_
        cases hb : bval (genW T) (armsOr (aut.trans t)) α with
        | false => rfl
        | true =>
            rw [hb] at hα'
            exact nomatch hα'.2
      have h2 := h α
      rw [show autStep (genW T) aut s α
          = some (e.2.1, e.2.2) from hs,
        show autStep (genW T) aut t α = none from htnone] at h2
      exact h2
    · rintro e' he' ⟨α, hα⟩
      have hα' : (!(bval (genW T) (armsOr (aut.trans s)) α)
          && bval (genW T) e'.1 α) = true := hα
      rw [Bool.and_eq_true] at hα'
      have ht := effList_fires (genW T) α (aut.trans t) .zero rfl
        e' he' hα'.2
      have hsnone : firstMatch (genW T) α (aut.trans s) = none := by
        refine (firstMatch_none_iff (genW T) α (aut.trans s)).mpr ?_
        cases hb : bval (genW T) (armsOr (aut.trans s)) α with
        | false => rfl
        | true =>
            rw [hb] at hα'
            exact nomatch hα'.1
      have h2 := h α
      rw [show autStep (genW T) aut s α = none from hsnone,
        show autStep (genW T) aut t α
          = some (e'.2.1, e'.2.2) from ht] at h2
      exact h2
  · rintro ⟨hpair, hsnone, htnone⟩ α
    cases hs : autStep (genW T) aut s α with
    | none =>
        cases ht : autStep (genW T) aut t α with
        | none => exact trivial
        | some o =>
            obtain ⟨e', he', hb', -, -⟩ :=
              effList_of_firstMatch (genW T) α (aut.trans t) .zero
                rfl ht
            exfalso
            refine htnone e' he' ⟨α, ?_⟩
            show (!(bval (genW T) (armsOr (aut.trans s)) α)
              && bval (genW T) e'.1 α) = true
            rw [(firstMatch_none_iff (genW T) α (aut.trans s)).mp hs,
              hb']
            rfl
    | some o =>
        obtain ⟨e, he, hb, he1, he2⟩ :=
          effList_of_firstMatch (genW T) α (aut.trans s) .zero rfl hs
        cases ht : autStep (genW T) aut t α with
        | none =>
            exfalso
            refine hsnone e he ⟨α, ?_⟩
            show (bval (genW T) e.1 α
              && !(bval (genW T) (armsOr (aut.trans t)) α)) = true
            rw [(firstMatch_none_iff (genW T) α (aut.trans t)).mp ht,
              hb]
            rfl
        | some o' =>
            obtain ⟨e', he', hb', he1', he2'⟩ :=
              effList_of_firstMatch (genW T) α (aut.trans t) .zero
                rfl ht
            have := hpair e he e' he' ⟨α, by
              show (bval (genW T) e.1 α && bval (genW T) e'.1 α)
                = true
              rw [hb, hb']
              rfl⟩
            show o.1 = o'.1 ∧ P o.2 o'.2
            rw [← he1, ← he2, ← he1', ← he2']
            exact this

/-- Decidable implication from decidable parts. -/
def decImp {p q : Prop} (dp : Decidable p) (dq : Decidable q) :
    Decidable (p → q) :=
  match dp with
  | isFalse hp => isTrue (fun h => absurd h hp)
  | isTrue hp =>
      match dq with
      | isTrue hq => isTrue (fun _ => hq)
      | isFalse hq => isFalse (fun h => hq (h hp))

/-- Decidable conjunction from decidable parts. -/
def decAnd {p q : Prop} (dp : Decidable p) (dq : Decidable q) :
    Decidable (p ∧ q) :=
  match dp with
  | isFalse hp => isFalse (fun h => hp h.1)
  | isTrue hp =>
      match dq with
      | isTrue hq => isTrue ⟨hp, hq⟩
      | isFalse hq => isFalse (fun h => hq h.2)

/-- Decidable negation. -/
def decNot {p : Prop} (dp : Decidable p) : Decidable (¬ p) :=
  match dp with
  | isTrue hp => isFalse (fun h => h hp)
  | isFalse hp => isTrue hp

/-- **DECIDABLE LEVELS** — computable, choice-free. -/
def stepEquivWithinDec [DecidableEq T] [DecidableEq A]
    (aut : GAut S A T) :
    (n : Nat) → (s t : S) → Decidable (stepEquivWithin aut n s t)
  | 0, _, _ => isTrue trivial
  | n + 1, s, t =>
      decAnd (guardEqDecidable (aut.hlt s) (aut.hlt t))
        (@decidable_of_iff _ _
          (forall_optStepRel_iff aut (stepEquivWithin aut n) s t).symm
          (decAnd
            (decideAllMem (fun e =>
              decideAllMem (fun e' =>
                decImp (guardSatDecidable _)
                  (decAnd (decEq e.2.1 e'.2.1)
                    (stepEquivWithinDec aut n e.2.2 e'.2.2)))
                (effList (aut.trans t) .zero))
              (effList (aut.trans s) .zero))
            (decAnd
              (decideAllMem (fun e =>
                decNot (guardSatDecidable _))
                (effList (aut.trans s) .zero))
              (decideAllMem (fun e' =>
                decNot (guardSatDecidable _))
                (effList (aut.trans t) .zero)))))

#print axioms guardEqDecidable
#print axioms forall_optStepRel_iff
#print axioms stepEquivWithinDec

/-! ## Stabilization: bisimilarity decides at the pair bound

    The count of level-equivalent pairs over a closed pool is antitone;
    a descending Nat function has a fixpoint within its initial value;
    at a fixpoint level the refinement stops and propagates upward.  So
    generic bisimilarity on pool states IS step equivalence at
    `|pool|²` — and that level decides. -/

instance stepEquivInst [DecidableEq T] [DecidableEq A]
    (aut : GAut S A T) (n : Nat) (s t : S) :
    Decidable (stepEquivWithin aut n s t) :=
  stepEquivWithinDec aut n s t

/-- Generalized antitonicity. -/
theorem stepEquiv_le (aut : GAut S A T) :
    ∀ {m n : Nat}, m ≤ n → ∀ {s t : S},
      stepEquivWithin aut n s t → stepEquivWithin aut m s t := by
  intro m n hmn
  induction n with
  | zero =>
      intro s t h
      have hm : m = 0 := by omega
      subst hm
      exact h
  | succ n ih =>
      intro s t h
      rcases Nat.lt_or_ge m (n + 1) with hlt | hge
      · exact ih (by omega) (stepEquivWithin_antitone aut n s t h)
      · have hm : m = n + 1 := by omega
        subst hm
        exact h

/-- Steps stay in a closed pool. -/
theorem autStep_target_pool (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool)
    {s : S} (hs : s ∈ pool) {α : T → Bool} {q : A} {s' : S}
    (h : autStep (genW T) aut s α = some (q, s')) : s' ∈ pool := by
  obtain ⟨e, he, -, -, he2⟩ :=
    effList_of_firstMatch (genW T) α (aut.trans s) .zero rfl h
  obtain ⟨g₀, hg₀⟩ := effList_target_mem (aut.trans s) .zero e he
  have := hclosed s hs (g₀, e.2.1, e.2.2) hg₀
  rw [he2] at this
  exact this

/-- A stable level propagates upward on a closed pool. -/
theorem stepEquiv_stable_succ (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool) (N : Nat)
    (hstab : ∀ x ∈ pool, ∀ y ∈ pool, stepEquivWithin aut N x y →
      stepEquivWithin aut (N + 1) x y) :
    ∀ (k : Nat), ∀ x ∈ pool, ∀ y ∈ pool, stepEquivWithin aut N x y →
      stepEquivWithin aut (N + k) x y := by
  intro k
  induction k with
  | zero => intro x _ y _ h; exact h
  | succ k ih =>
      intro x hx y hy h
      have h1 := hstab x hx y hy h
      rw [stepEquivWithin_succ] at h1
      show stepEquivWithin aut (N + k + 1) x y
      rw [stepEquivWithin_succ]
      refine ⟨h1.1, ?_⟩
      intro α
      have h2 := h1.2 α
      cases hs : autStep (genW T) aut x α with
      | none =>
          cases ht : autStep (genW T) aut y α with
          | none => exact trivial
          | some o =>
              rw [hs, ht] at h2
              exact h2.elim
      | some o =>
          cases ht : autStep (genW T) aut y α with
          | none =>
              rw [hs, ht] at h2
              exact h2.elim
          | some o' =>
              rw [hs, ht] at h2
              refine ⟨h2.1, ?_⟩
              exact ih o.2 (autStep_target_pool aut pool hclosed hx hs)
                o'.2 (autStep_target_pool aut pool hclosed hy ht) h2.2

/-- All ordered pairs over a pool. -/
def pairList {γ : Type} (pool : List γ) : List (γ × γ) :=
  pool.flatMap (fun x => pool.map (fun y => (x, y)))

theorem pairList_mem {γ : Type} (pool : List γ) (x y : γ)
    (hx : x ∈ pool) (hy : y ∈ pool) : (x, y) ∈ pairList pool :=
  List.mem_flatMap.mpr ⟨x, hx, List.mem_map.mpr ⟨y, hy, rfl⟩⟩

/-- Filter length is monotone under pointwise implication. -/
theorem filter_length_mono {γ : Type} (f g : γ → Bool) :
    ∀ L : List γ, (∀ e ∈ L, f e = true → g e = true) →
      (L.filter f).length ≤ (L.filter g).length := by
  intro L
  induction L with
  | nil => intro _; exact Nat.le_refl _
  | cons x xs ih =>
      intro h
      have hxs := ih (fun e he => h e (List.mem_cons_of_mem _ he))
      cases hf : f x with
      | true =>
          rw [List.filter_cons_of_pos hf,
              List.filter_cons_of_pos (h x (List.mem_cons_self ..) hf)]
          simp only [List.length_cons]
          omega
      | false =>
          rw [List.filter_cons_of_neg (p := f)
            (by rw [hf]; exact Bool.false_ne_true)]
          cases hg : g x with
          | true =>
              rw [List.filter_cons_of_pos (p := g) hg]
              simp only [List.length_cons]
              omega
          | false =>
              rw [List.filter_cons_of_neg (p := g)
                (by rw [hg]; exact Bool.false_ne_true)]
              exact hxs

/-- Equal filter lengths under pointwise implication force pointwise
    equivalence on members. -/
theorem filter_eq_of_length_eq {γ : Type} (f g : γ → Bool) :
    ∀ L : List γ, (∀ e ∈ L, f e = true → g e = true) →
      (L.filter g).length = (L.filter f).length →
      ∀ e ∈ L, g e = true → f e = true := by
  intro L
  induction L with
  | nil => intro _ _ e he; exact nomatch he
  | cons x xs ih =>
      intro himp hlen e he hge
      have himp' := fun e he => himp e (List.mem_cons_of_mem _ he)
      cases hf : f x with
      | true =>
          rw [List.filter_cons_of_pos
              (himp x (List.mem_cons_self ..) hf),
            List.filter_cons_of_pos hf] at hlen
          simp only [List.length_cons] at hlen
          rcases List.mem_cons.mp he with heq | hm
          · exact heq ▸ hf
          · exact ih himp' (by omega) e hm hge
      | false =>
          rw [List.filter_cons_of_neg (p := f)
            (by rw [hf]; exact Bool.false_ne_true)] at hlen
          cases hgx : g x with
          | true =>
              exfalso
              rw [List.filter_cons_of_pos (p := g) hgx] at hlen
              simp only [List.length_cons] at hlen
              have := filter_length_mono f g xs himp'
              omega
          | false =>
              rw [List.filter_cons_of_neg (p := g)
                (by rw [hgx]; exact Bool.false_ne_true)] at hlen
              rcases List.mem_cons.mp he with heq | hm
              · rw [heq] at hge
                rw [hgx] at hge
                exact nomatch hge
              · exact ih himp' hlen e hm hge

/-- A descending Nat function has a fixpoint within its initial value. -/
theorem desc_fix (f : Nat → Nat) (hdesc : ∀ n, f (n + 1) ≤ f n) :
    ∃ N, N ≤ f 0 ∧ f (N + 1) = f N := by
  have key : ∀ k : Nat, f k + k ≤ f 0 ∨ ∃ N < k, f (N + 1) = f N := by
    intro k
    induction k with
    | zero => exact Or.inl (by omega)
    | succ k ih =>
        rcases ih with hle | ⟨N, hN, hfix⟩
        · rcases Nat.lt_or_ge (f (k + 1)) (f k) with hlt | hge
          · refine Or.inl ?_
            omega
          · have : f (k + 1) = f k :=
              Nat.le_antisymm (hdesc k) hge
            exact Or.inr ⟨k, by omega, this⟩
        · exact Or.inr ⟨N, by omega, hfix⟩
  rcases key (f 0 + 1) with hle | ⟨N, hN, hfix⟩
  · exact absurd hle (by omega)
  · exact ⟨N, by omega, hfix⟩

/-- The count of level-equivalent pairs. -/
private def eqCnt [DecidableEq T] [DecidableEq A] (aut : GAut S A T)
    (pool : List S) (N : Nat) : Nat :=
  ((pairList pool).filter
    (fun p => decide (stepEquivWithin aut N p.1 p.2))).length

/-- **STABILIZATION**: on a closed pool, bisimilarity is step equivalence
    at the pair bound. -/
theorem genBisimilar_iff_pairBound [DecidableEq T] [DecidableEq A]
    (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool)
    {x y : S} (hx : x ∈ pool) (hy : y ∈ pool) :
    GenBisimilar aut x y
      ↔ stepEquivWithin aut (pairList pool).length x y := by
  constructor
  · intro h
    exact genBisimilar_stepEquiv aut h _
  · intro h
    have hdesc : ∀ N, eqCnt aut pool (N + 1) ≤ eqCnt aut pool N := by
      intro N
      refine filter_length_mono _ _ (pairList pool) ?_
      intro e _ hf
      exact decide_eq_true (stepEquivWithin_antitone aut N e.1 e.2
        (of_decide_eq_true hf))
    obtain ⟨N, hNle, hNfix⟩ := desc_fix (eqCnt aut pool) hdesc
    have hcnt0 : eqCnt aut pool 0 ≤ (pairList pool).length := by
      show (List.filter _ (pairList pool)).length ≤ _
      exact List.length_filter_le _ _
    have hstab : ∀ a ∈ pool, ∀ b ∈ pool, stepEquivWithin aut N a b →
        stepEquivWithin aut (N + 1) a b := by
      intro a ha b hb hab
      have hmem := pairList_mem pool a b ha hb
      have hNfix' : ((pairList pool).filter
          (fun p => decide (stepEquivWithin aut N p.1 p.2))).length
          = ((pairList pool).filter
            (fun p => decide (stepEquivWithin aut (N + 1) p.1
              p.2))).length := hNfix.symm
      have := filter_eq_of_length_eq
        (fun p => decide (stepEquivWithin aut (N + 1) p.1 p.2))
        (fun p => decide (stepEquivWithin aut N p.1 p.2))
        (pairList pool)
        (fun e _ hf => decide_eq_true
          (stepEquivWithin_antitone aut N e.1 e.2
            (of_decide_eq_true hf)))
        hNfix'
        (a, b) hmem (decide_eq_true hab)
      exact of_decide_eq_true this
    refine stepEquiv_all_bisim aut ?_
    intro n
    have hxyN : stepEquivWithin aut N x y :=
      stepEquiv_le aut (by omega) h
    rcases Nat.lt_or_ge n N with hlt | hge
    · exact stepEquiv_le aut (by omega) hxyN
    · have := stepEquiv_stable_succ aut pool hclosed N hstab
        (n - N) x hx y hy hxyN
      rw [show N + (n - N) = n from by omega] at this
      exact this

/-- **DECIDABLE BISIMILARITY** on closed pools — computable, no
    choice. -/
def genBisimilarDec [DecidableEq T] [DecidableEq A]
    (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool)
    {x y : S} (hx : x ∈ pool) (hy : y ∈ pool) :
    Decidable (GenBisimilar aut x y) :=
  decidable_of_iff _
    (genBisimilar_iff_pairBound aut pool hclosed hx hy).symm

#print axioms genBisimilar_iff_pairBound
#print axioms genBisimilarDec

/-! ## The canonical representative

    `Classical.choose` gave each class an arbitrary representative; with
    decidable bisimilarity the FIRST equivalent state in the pool is a
    canonical one — computable, coherent, idempotent. -/

def findBisim [DecidableEq T] [DecidableEq A] [DecidableEq S]
    (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool)
    {s : S} (hs : s ∈ pool) :
    (cands : List S) → (∀ x ∈ cands, x ∈ pool) → S
  | [], _ => s
  | c :: cs, hc =>
      letI : Decidable (GenBisimilar aut s c) :=
        genBisimilarDec aut pool hclosed hs
          (hc c (List.mem_cons_self ..))
      if GenBisimilar aut s c then c
      else findBisim aut pool hclosed hs cs
        (fun x hx => hc x (List.mem_cons_of_mem _ hx))

private theorem findBisim_cons [DecidableEq T] [DecidableEq A]
    [DecidableEq S] (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool)
    {s : S} (hs : s ∈ pool) (c : S) (cs : List S)
    (hc : ∀ x ∈ c :: cs, x ∈ pool) :
    findBisim aut pool hclosed hs (c :: cs) hc
      = (letI : Decidable (GenBisimilar aut s c) :=
          genBisimilarDec aut pool hclosed hs
            (hc c (List.mem_cons_self ..))
        if GenBisimilar aut s c then c
        else findBisim aut pool hclosed hs cs
          (fun x hx => hc x (List.mem_cons_of_mem _ hx))) := rfl

theorem findBisim_bisim [DecidableEq T] [DecidableEq A] [DecidableEq S]
    (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool)
    {s : S} (hs : s ∈ pool) :
    ∀ (cands : List S) (hc : ∀ x ∈ cands, x ∈ pool),
      (∃ x ∈ cands, GenBisimilar aut s x) →
      GenBisimilar aut s (findBisim aut pool hclosed hs cands hc) := by
  intro cands
  induction cands with
  | nil =>
      intro hc hex
      obtain ⟨x, hx, -⟩ := hex
      exact nomatch hx
  | cons c cs ih =>
      intro hc hex
      rw [findBisim_cons]
      cases hdec : genBisimilarDec aut pool hclosed hs
          (hc c (List.mem_cons_self ..)) with
      | isTrue h => exact h
      | isFalse h =>
          refine ih _ ?_
          obtain ⟨x, hx, hbx⟩ := hex
          rcases List.mem_cons.mp hx with heq | hm
          · exact absurd (heq ▸ hbx) h
          · exact ⟨x, hm, hbx⟩

theorem findBisim_mem [DecidableEq T] [DecidableEq A] [DecidableEq S]
    (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool)
    {s : S} (hs : s ∈ pool) :
    ∀ (cands : List S) (hc : ∀ x ∈ cands, x ∈ pool),
      findBisim aut pool hclosed hs cands hc ∈ pool := by
  intro cands
  induction cands with
  | nil => intro hc; exact hs
  | cons c cs ih =>
      intro hc
      rw [findBisim_cons]
      cases hdec : genBisimilarDec aut pool hclosed hs
          (hc c (List.mem_cons_self ..)) with
      | isTrue h => exact hc c (List.mem_cons_self ..)
      | isFalse h => exact ih _

theorem findBisim_coherent [DecidableEq T] [DecidableEq A]
    [DecidableEq S] (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool)
    {s t : S} (hs : s ∈ pool) (ht : t ∈ pool)
    (hst : GenBisimilar aut s t) :
    ∀ (cands : List S) (hc : ∀ x ∈ cands, x ∈ pool),
      (∃ x ∈ cands, GenBisimilar aut s x) →
      findBisim aut pool hclosed hs cands hc
        = findBisim aut pool hclosed ht cands hc := by
  intro cands
  induction cands with
  | nil =>
      intro hc hex
      obtain ⟨x, hx, -⟩ := hex
      exact nomatch hx
  | cons c cs ih =>
      intro hc hex
      rw [findBisim_cons, findBisim_cons]
      cases hdec₁ : genBisimilarDec aut pool hclosed hs
          (hc c (List.mem_cons_self ..)) with
      | isTrue h₁ =>
          cases hdec₂ : genBisimilarDec aut pool hclosed ht
              (hc c (List.mem_cons_self ..)) with
          | isTrue h₂ => rfl
          | isFalse h₂ => exact absurd (hst.symm.trans h₁) h₂
      | isFalse h₁ =>
          cases hdec₂ : genBisimilarDec aut pool hclosed ht
              (hc c (List.mem_cons_self ..)) with
          | isTrue h₂ => exact absurd (hst.trans h₂) h₁
          | isFalse h₂ =>
              refine ih _ ?_
              obtain ⟨x, hx, hbx⟩ := hex
              rcases List.mem_cons.mp hx with heq | hm
              · exact absurd (heq ▸ hbx) h₁
              · exact ⟨x, hm, hbx⟩

/-- **THE CANONICAL COMPUTABLE REPRESENTATIVE**: first equivalent state
    in the pool. -/
def bisimRepDT [DecidableEq T] [DecidableEq A] [DecidableEq S]
    (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool)
    (s : S) : S :=
  if hs : s ∈ pool then
    findBisim aut pool hclosed hs pool (fun _ hx => hx)
  else s

theorem bisimRepDT_bisim [DecidableEq T] [DecidableEq A] [DecidableEq S]
    (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool)
    {s : S} (hs : s ∈ pool) :
    GenBisimilar aut s (bisimRepDT aut pool hclosed s) := by
  unfold bisimRepDT
  rw [dif_pos hs]
  exact findBisim_bisim aut pool hclosed hs pool (fun _ hx => hx)
    ⟨s, hs, GenBisimilar.refl aut s⟩

theorem bisimRepDT_mem [DecidableEq T] [DecidableEq A] [DecidableEq S]
    (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool)
    {s : S} (hs : s ∈ pool) :
    bisimRepDT aut pool hclosed s ∈ pool := by
  unfold bisimRepDT
  rw [dif_pos hs]
  exact findBisim_mem aut pool hclosed hs pool (fun _ hx => hx)

theorem bisimRepDT_coherent [DecidableEq T] [DecidableEq A]
    [DecidableEq S] (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool)
    {s t : S} (hs : s ∈ pool) (ht : t ∈ pool)
    (hst : GenBisimilar aut s t) :
    bisimRepDT aut pool hclosed s = bisimRepDT aut pool hclosed t := by
  unfold bisimRepDT
  rw [dif_pos hs, dif_pos ht]
  exact findBisim_coherent aut pool hclosed hs ht hst pool
    (fun _ hx => hx) ⟨s, hs, GenBisimilar.refl aut s⟩

theorem bisimRepDT_idem [DecidableEq T] [DecidableEq A] [DecidableEq S]
    (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool)
    {s : S} (hs : s ∈ pool) :
    bisimRepDT aut pool hclosed (bisimRepDT aut pool hclosed s)
      = bisimRepDT aut pool hclosed s :=
  (bisimRepDT_coherent aut pool hclosed
    (bisimRepDT_mem aut pool hclosed hs) hs
    (bisimRepDT_bisim aut pool hclosed hs).symm).trans rfl

#print axioms bisimRepDT_bisim
#print axioms bisimRepDT_coherent
#print axioms bisimRepDT_idem

/-! ## The computable quotient

    The canonical quotient rebuilt over the computable representative:
    same construction, same step correspondence, and the representative
    graph (restricted to the pool) is a bisimulation — so quotient
    classes carry their states' languages, computably. -/

def bisimQuotAutD [DecidableEq T] [DecidableEq A] [DecidableEq S]
    (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool) :
    GAut S A T where
  states := aut.states.map (bisimRepDT aut pool hclosed)
  hlt := aut.hlt
  trans := fun s => (aut.trans s).map
    (fun e => (e.1, e.2.1, bisimRepDT aut pool hclosed e.2.2))
  start := bisimRepDT aut pool hclosed aut.start

theorem bisimQuotAutD_step {Atom : Type} [DecidableEq T] [DecidableEq A]
    [DecidableEq S] (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool)
    (V : T → Atom → Bool) (r : S) (a : Atom) :
    autStep V (bisimQuotAutD aut pool hclosed) r a
      = (autStep V aut r a).map
          (fun y => (y.1, bisimRepDT aut pool hclosed y.2)) :=
  firstMatch_retarget V a (bisimRepDT aut pool hclosed) (aut.trans r)

/-- The computable representative graph is a bisimulation on the
    pool. -/
theorem bisimQuotD_bisim_gen [DecidableEq T] [DecidableEq A]
    [DecidableEq S] (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool) :
    GAutBisim (genW T) aut (bisimQuotAutD aut pool hclosed)
      (fun s q => s ∈ pool
        ∧ bisimRepDT aut pool hclosed s = q) := by
  intro s q hq
  obtain ⟨hs, hq⟩ := hq
  subst hq
  obtain ⟨h1, h2, h3⟩ := genBisimilar_bisim aut s
    (bisimRepDT aut pool hclosed s) (bisimRepDT_bisim aut pool hclosed hs)
  refine ⟨h1, ?_, ?_⟩
  · intro a q0 s' hstep
    obtain ⟨t', ht, hb⟩ := h2 a q0 s' hstep
    have hs' : s' ∈ pool := autStep_target_pool aut pool hclosed hs hstep
    have ht' : t' ∈ pool := autStep_target_pool aut pool hclosed
      (bisimRepDT_mem aut pool hclosed hs) ht
    refine ⟨bisimRepDT aut pool hclosed t', ?_,
      hs', bisimRepDT_coherent aut pool hclosed hs' ht' hb⟩
    rw [bisimQuotAutD_step, ht]
    rfl
  · intro a q0 u hu
    rw [bisimQuotAutD_step] at hu
    cases hstep : autStep (genW T) aut
        (bisimRepDT aut pool hclosed s) a with
    | none =>
        rw [hstep] at hu
        exact nomatch hu
    | some y =>
        obtain ⟨q1, t'⟩ := y
        rw [hstep] at hu
        have hp : (q1, bisimRepDT aut pool hclosed t') = (q0, u) :=
          Option.some.inj hu
        obtain ⟨s', hstep', hb⟩ := h3 a q1 t' hstep
        have hq1 : q1 = q0 := congrArg Prod.fst hp
        have hu' : bisimRepDT aut pool hclosed t' = u :=
          congrArg Prod.snd hp
        subst hq1
        subst hu'
        have hs' : s' ∈ pool :=
          autStep_target_pool aut pool hclosed hs hstep'
        have ht' : t' ∈ pool := autStep_target_pool aut pool hclosed
          (bisimRepDT_mem aut pool hclosed hs) hstep
        exact ⟨s', hstep',
          hs', bisimRepDT_coherent aut pool hclosed hs' ht' hb⟩

/-- **QUOTIENT CLASSES CARRY THEIR LANGUAGES** — computably. -/
theorem quotD_lang_eq [DecidableEq T] [DecidableEq A] [DecidableEq S]
    (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool)
    {s : S} (hs : s ∈ pool) :
    autLang (genW T) (bisimQuotAutD aut pool hclosed)
        (bisimRepDT aut pool hclosed s)
      = autLang (genW T) aut s :=
  (autLang_eq_of_gautBisim
    (bisimQuotD_bisim_gen aut pool hclosed) ⟨hs, rfl⟩).symm

#print axioms bisimQuotAutD_step
#print axioms bisimQuotD_bisim_gen
#print axioms quotD_lang_eq

/-! ## Phase 4: the computable minimal rank

    Bounded minimization of a monotone decidable predicate, applied to
    "some pool state of rank ≤ n is bisimilar to c".  Under trimmedness
    (language equality = bisimilarity) and pool exhaustiveness, this IS
    the classical `minRank` — by spec antisymmetry, no unfolding. -/

/-- Bounded minimization: least `n ≤ b` satisfying monotone `p`, else
    `b`. -/
def leastB (p : Nat → Bool) : Nat → Nat
  | 0 => 0
  | b + 1 => if p (leastB p b) = true then leastB p b else b + 1

private theorem leastB_succ (p : Nat → Bool) (b : Nat) :
    leastB p (b + 1)
      = if p (leastB p b) = true then leastB p b else b + 1 := rfl

theorem leastB_le (p : Nat → Bool) : ∀ b, leastB p b ≤ b := by
  intro b
  induction b with
  | zero => exact Nat.le_refl _
  | succ b ih =>
      rw [leastB_succ]
      by_cases h : p (leastB p b) = true
      · rw [if_pos h]
        omega
      · rw [if_neg h]
        omega

/-- Combined correctness: hit or all-below-fails, plus minimality. -/
theorem leastB_correct (p : Nat → Bool)
    (hmono : ∀ i j, i ≤ j → p i = true → p j = true) :
    ∀ b, (p (leastB p b) = true ∨ ∀ m, m ≤ b → p m = false)
      ∧ (∀ n, n ≤ b → p n = true → leastB p b ≤ n) := by
  intro b
  induction b with
  | zero =>
      constructor
      · by_cases h : p 0 = true
        · exact Or.inl h
        · refine Or.inr ?_
          intro m hm
          have hm0 : m = 0 := by omega
          subst hm0
          cases hp : p 0 with
          | false => rfl
          | true => exact absurd hp h
      · intro n _ _
        exact Nat.zero_le n
  | succ b ih =>
      obtain ⟨ih1, ih2⟩ := ih
      rw [leastB_succ]
      by_cases h : p (leastB p b) = true
      · rw [if_pos h]
        refine ⟨Or.inl h, ?_⟩
        intro n hn hpn
        rcases Nat.lt_or_ge n (b + 1) with hlt | hge
        · exact ih2 n (by omega) hpn
        · have := leastB_le p b
          omega
      · rw [if_neg h]
        have hallb : ∀ m, m ≤ b → p m = false := by
          rcases ih1 with hhit | hfail
          · exact absurd hhit h
          · exact hfail
        constructor
        · by_cases hb1 : p (b + 1) = true
          · exact Or.inl hb1
          · refine Or.inr ?_
            intro m hm
            rcases Nat.lt_or_ge m (b + 1) with hlt | hge
            · exact hallb m (by omega)
            · have hm1 : m = b + 1 := by omega
              rw [hm1]
              cases hp : p (b + 1) with
              | false => rfl
              | true => exact absurd hp hb1
        · intro n hn hpn
          rcases Nat.lt_or_ge n (b + 1) with hlt | hge
          · rw [hallb n (by omega)] at hpn
            exact nomatch hpn
          · omega

/-- Decidable pool-realizer search. -/
def existsRealizer [DecidableEq T] [DecidableEq A] [DecidableEq S]
    (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool)
    (rank : S → Nat) {c : S} (hc : c ∈ pool) (n : Nat) :
    (cands : List S) → (∀ x ∈ cands, x ∈ pool) → Bool
  | [], _ => false
  | u :: us, hu =>
      (decide (rank u ≤ n)
        && @decide (GenBisimilar aut u c)
          (genBisimilarDec aut pool hclosed
            (hu u (List.mem_cons_self ..)) hc))
      || existsRealizer aut pool hclosed rank hc n us
        (fun x hx => hu x (List.mem_cons_of_mem _ hx))

private theorem existsRealizer_cons [DecidableEq T] [DecidableEq A]
    [DecidableEq S] (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool)
    (rank : S → Nat) {c : S} (hc : c ∈ pool) (n : Nat)
    (u : S) (us : List S) (hu : ∀ x ∈ u :: us, x ∈ pool) :
    existsRealizer aut pool hclosed rank hc n (u :: us) hu
      = ((decide (rank u ≤ n)
          && @decide (GenBisimilar aut u c)
            (genBisimilarDec aut pool hclosed
              (hu u (List.mem_cons_self ..)) hc))
        || existsRealizer aut pool hclosed rank hc n us
          (fun x hx => hu x (List.mem_cons_of_mem _ hx))) := rfl

theorem existsRealizer_iff [DecidableEq T] [DecidableEq A]
    [DecidableEq S] (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool)
    (rank : S → Nat) {c : S} (hc : c ∈ pool) (n : Nat) :
    ∀ (cands : List S) (hcands : ∀ x ∈ cands, x ∈ pool),
      existsRealizer aut pool hclosed rank hc n cands hcands = true
        ↔ ∃ u ∈ cands, rank u ≤ n ∧ GenBisimilar aut u c := by
  intro cands
  induction cands with
  | nil =>
      intro hcands
      constructor
      · intro h; exact nomatch h
      · rintro ⟨u, hu, -⟩; exact nomatch hu
  | cons u us ih =>
      intro hcands
      rw [existsRealizer_cons, Bool.or_eq_true, Bool.and_eq_true]
      constructor
      · rintro (⟨h1, h2⟩ | h)
        · exact ⟨u, List.mem_cons_self ..,
            of_decide_eq_true h1,
            @of_decide_eq_true _
              (genBisimilarDec aut pool hclosed
                (hcands u (List.mem_cons_self ..)) hc) h2⟩
        · obtain ⟨v, hv, hr, hb⟩ := (ih _).mp h
          exact ⟨v, List.mem_cons_of_mem _ hv, hr, hb⟩
      · rintro ⟨v, hv, hr, hb⟩
        rcases List.mem_cons.mp hv with heq | hm
        · subst heq
          exact Or.inl ⟨decide_eq_true hr,
            @decide_eq_true _
              (genBisimilarDec aut pool hclosed
                (hcands v (List.mem_cons_self ..)) hc) hb⟩
        · exact Or.inr ((ih _).mpr ⟨v, hm, hr, hb⟩)

/-- **THE COMPUTABLE MINIMAL RANK** over a pool. -/
def minRankD [DecidableEq T] [DecidableEq A] [DecidableEq S]
    (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool)
    (rank : S → Nat) {c : S} (hc : c ∈ pool) : Nat :=
  leastB (fun n => existsRealizer aut pool hclosed rank hc n pool
    (fun _ hx => hx)) (rank c)

private theorem existsRealizer_mono [DecidableEq T] [DecidableEq A]
    [DecidableEq S] (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool)
    (rank : S → Nat) {c : S} (hc : c ∈ pool) :
    ∀ i j, i ≤ j →
      existsRealizer aut pool hclosed rank hc i pool
        (fun _ hx => hx) = true →
      existsRealizer aut pool hclosed rank hc j pool
        (fun _ hx => hx) = true := by
  intro i j hij h
  obtain ⟨u, hu, hr, hb⟩ :=
    (existsRealizer_iff aut pool hclosed rank hc i pool _).mp h
  exact (existsRealizer_iff aut pool hclosed rank hc j pool _).mpr
    ⟨u, hu, by omega, hb⟩

theorem minRankD_spec [DecidableEq T] [DecidableEq A] [DecidableEq S]
    (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool)
    (rank : S → Nat) {c : S} (hc : c ∈ pool) :
    ∃ u ∈ pool, rank u ≤ minRankD aut pool hclosed rank hc
      ∧ GenBisimilar aut u c := by
  have hcself : existsRealizer aut pool hclosed rank hc (rank c) pool
      (fun _ hx => hx) = true :=
    (existsRealizer_iff aut pool hclosed rank hc (rank c) pool _).mpr
      ⟨c, hc, Nat.le_refl _, GenBisimilar.refl aut c⟩
  obtain ⟨hcor, -⟩ := leastB_correct _
    (existsRealizer_mono aut pool hclosed rank hc) (rank c)
  rcases hcor with hhit | hfail
  · exact (existsRealizer_iff aut pool hclosed rank hc _ pool _).mp hhit
  · exact absurd hcself
      (by rw [hfail (rank c) (Nat.le_refl _)]; exact Bool.false_ne_true)

theorem minRankD_le [DecidableEq T] [DecidableEq A] [DecidableEq S]
    (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool, ∀ e ∈ aut.trans s, e.2.2 ∈ pool)
    (rank : S → Nat) {c u : S} (hc : c ∈ pool) (hu : u ∈ pool)
    (hb : GenBisimilar aut u c) :
    minRankD aut pool hclosed rank hc ≤ rank u := by
  obtain ⟨-, hmin⟩ := leastB_correct _
    (existsRealizer_mono aut pool hclosed rank hc) (rank c)
  rcases Nat.lt_or_ge (rank c) (rank u) with hlt | hge
  · exact Nat.le_trans (leastB_le _ _) (by omega)
  · exact hmin (rank u) hge
      ((existsRealizer_iff aut pool hclosed rank hc _ pool _).mpr
        ⟨u, hu, Nat.le_refl _, hb⟩)

/-- **THE BRIDGE**: on a trimmed automaton with an exhaustive pool, the
    computable minimal rank IS the classical one. -/
theorem minRankD_eq_minRank [DecidableEq T] [DecidableEq A]
    [DecidableEq S] (aut : GAut S A T) (pool : List S)
    (hclosed : ∀ s ∈ pool,
      ∀ e ∈ (trimAut aut).trans s, e.2.2 ∈ pool)
    (hexh : ∀ x : S, x ∈ pool)
    (rank : S → Nat) {c : S} (hc : c ∈ pool) :
    minRankD (trimAut aut) pool hclosed rank hc
      = minRank (trimAut aut) rank c := by
  refine Nat.le_antisymm ?_ ?_
  · obtain ⟨u, hule, huL⟩ := minRank_spec (trimAut aut) rank c
    have hb : GenBisimilar (trimAut aut) u c :=
      genBisimilar_of_uniformStateEquiv (liveSteps_trimAut aut)
        (uniformStateEquiv_of_gen huL)
    exact Nat.le_trans
      (minRankD_le (trimAut aut) pool hclosed rank hc (hexh u) hb)
      hule
  · obtain ⟨u, hu, hule, hb⟩ :=
      minRankD_spec (trimAut aut) pool hclosed rank hc
    have huL : autLang (genW T) (trimAut aut) u
        = autLang (genW T) (trimAut aut) c :=
      autLang_eq_of_gautBisim (genBisimilar_bisim (trimAut aut)) hb
    exact Nat.le_trans (minRank_le (trimAut aut) rank huL) hule

#print axioms minRankD_spec
#print axioms minRankD_le
#print axioms minRankD_eq_minRank

end GkatGuardDecide
