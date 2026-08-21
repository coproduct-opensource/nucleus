import GkatThreeLoopProofs

/-! # General state elimination: expression-labeled automata

    The vehicle for the FiniteAxiomsCompleteBA generalization.  `GAut`
    arms carry single actions; Gaussian elimination substitutes CLOSED
    EXPRESSIONS through same-rank cycles, so the intermediate objects
    are automata whose arms carry arbitrary productive expressions.
    The terminal form is `WNAutE` (self-loop + descending exits), whose
    solution `wnSolE` is already certified; this file grounds the
    intermediate form and its roles interface. -/

namespace GkatElim

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatSumQuotient
open GkatDecomp GkatPlanExistence GkatGuardedAlgebra GkatTrim GkatRingPlan
open GkatLoopFree GkatDecide
open GkatThreeLoop

variable {A T : Type}

/-- An expression-labeled automaton: `GAut` with expression arm
    bodies.  The carrier of Gaussian elimination. -/
structure ELabAut (S A T : Type) where
  states : List S
  hlt : S → BExp T
  trans : S → List (BExp T × Exp A T × S)

/-- The dispatch fold with expression bodies. -/
def foldTLE {S : Type} (sol : S → Exp A T) (h : BExp T)
    (L : List (BExp T × Exp A T × S)) : Exp A T :=
  L.foldr (fun t acc => Exp.ite t.1 (.seq t.2.1 (sol t.2.2)) acc)
    (.test h)

/-- The equation of a state. -/
def eqRHSEL {S : Type} (aut : ELabAut S A T) (sol : S → Exp A T)
    (s : S) : Exp A T :=
  foldTLE sol (aut.hlt s) (aut.trans s)

/-- Roles for expression-labeled automata, mirroring `StateRole`. -/
inductive ERole {S : Type} (aut : ELabAut S A T) (sol : S → Exp A T)
    (s : S) : Prop where
  | fold (h : sol s = eqRHSEL aut sol s)
  | equivFold (h : EquivBA (sol s) (eqRHSEL aut sol s))
  | salomaaE (G : BExp T) (BODY rest : Exp A T)
      (hsol : sol s = .seq (.wh G BODY) rest)
      (hrhs : EquivBA (eqRHSEL aut sol s)
        (.ite G (.seq BODY (sol s)) rest))

/-- The embedding of a flat automaton. -/
def embedG {S : Type} (aut : GAut S A T) : ELabAut S A T where
  states := aut.states
  hlt := aut.hlt
  trans := fun s => (aut.trans s).map (fun e => (e.1, .act e.2.1, e.2.2))

/-- The embedded dispatch is the flat dispatch. -/
theorem foldTLE_embed {S : Type} (sol : S → Exp A T) (h : BExp T)
    (L : List (BExp T × A × S)) :
    foldTLE sol h (L.map (fun e => (e.1, .act e.2.1, e.2.2)))
      = foldTL sol h L := by
  induction L with
  | nil => rfl
  | cons hd rest ih =>
      show Exp.ite hd.1 (.seq (.act hd.2.1) (sol hd.2.2))
          (foldTLE sol h (rest.map (fun e => (e.1, .act e.2.1, e.2.2))))
        = Exp.ite hd.1 (.seq (.act hd.2.1) (sol hd.2.2))
          (foldTL sol h rest)
      rw [ih]

/-- Embedded equations are flat equations. -/
theorem eqRHSEL_embed {S : Type} (aut : GAut S A T)
    (sol : S → Exp A T) (s : S) :
    eqRHSEL (embedG aut) sol s = eqRHS aut sol s := by
  show foldTLE sol (aut.hlt s)
      ((aut.trans s).map (fun e => (e.1, .act e.2.1, e.2.2)))
    = eqRHS aut sol s
  rw [foldTLE_embed, eqRHS_foldTL]

/-- **ROLES TRANSFER**: roles of the embedded automaton are flat
    roles — the general elimination concludes at `GAut` level. -/
theorem stateRole_of_eRole {S : Type} (aut : GAut S A T)
    (sol : S → Exp A T) (s : S)
    (h : ERole (embedG aut) sol s) : StateRole aut sol s := by
  cases h with
  | fold h =>
      refine StateRole.fold ?_
      rw [h, eqRHSEL_embed]
  | equivFold h =>
      refine StateRole.equivFold ?_
      rw [eqRHSEL_embed] at h
      exact h
  | salomaaE G BODY rest hsol hrhs =>
      refine StateRole.salomaaE G BODY rest hsol ?_
      rw [eqRHSEL_embed] at hrhs
      exact hrhs

#print axioms foldTLE_embed
#print axioms eqRHSEL_embed
#print axioms stateRole_of_eRole

/-! ## The substitution homomorphism

    Gaussian elimination substitutes closed forms for call markers.
    Provable equivalence is closed under action substitution, provided
    every substituted image is strictly productive (semantically) — the
    `w3`/`w3_ba` side conditions transport through `baTest` and a
    `bval`-level computation of `E` under substitution. -/

/-- Action substitution: replace each action by an expression; guards
    untouched. -/
def substA {A' : Type} (σ : A → Exp A' T) : Exp A T → Exp A' T
  | .act a => σ a
  | .test b => .test b
  | .seq e f => .seq (substA σ e) (substA σ f)
  | .ite b e f => .ite b (substA σ e) (substA σ f)
  | .wh b e => .wh b (substA σ e)

/-- `E` under substitution: with productive images, the empty-word
    guard is semantically unchanged. -/
theorem bval_E_substA {A' : Type} {σ : A → Exp A' T}
    (hσ : ∀ (a : A) (X : Type) (W : T → X → Bool) (x : X),
      bval W (E (σ a)) x = false) :
    ∀ (e : Exp A T) (X : Type) (W : T → X → Bool) (x : X),
      bval W (E (substA σ e)) x = bval W (E e) x := by
  intro e
  induction e with
  | act a =>
      intro X W x
      show bval W (E (σ a)) x = false
      exact hσ a X W x
  | test b => intro X W x; rfl
  | seq e f ihe ihf =>
      intro X W x
      show (bval W (E (substA σ e)) x && bval W (E (substA σ f)) x)
        = (bval W (E e) x && bval W (E f) x)
      rw [ihe X W x, ihf X W x]
  | ite b e f ihe ihf =>
      intro X W x
      show ((bval W b x && bval W (E (substA σ e)) x)
          || (!(bval W b x) && bval W (E (substA σ f)) x))
        = ((bval W b x && bval W (E e) x)
          || (!(bval W b x) && bval W (E f) x))
      rw [ihe X W x, ihf X W x]
  | wh b e ih => intro X W x; rfl

/-- Base provable equivalence maps into `EquivBA` under productive
    substitution (the `w3` side condition re-derives via `baTest`). -/
theorem equiv_substA {A' : Type} {σ : A → Exp A' T}
    (hσ : ∀ (a : A) (X : Type) (W : T → X → Bool) (x : X),
      bval W (E (σ a)) x = false)
    {e f : Exp A T} (h : Equiv e f) :
    EquivBA (substA σ e) (substA σ f) := by
  induction h with
  | refl e => exact EquivBA.base (Equiv.refl _)
  | symm _ ih => exact EquivBA.symm ih
  | trans _ _ ih₁ ih₂ => exact EquivBA.trans ih₁ ih₂
  | seq_c _ _ ih₁ ih₂ => exact EquivBA.seq_c ih₁ ih₂
  | ite_c _ _ ih₁ ih₂ => exact EquivBA.ite_c ih₁ ih₂
  | wh_c _ ih => exact EquivBA.wh_c ih
  | u1 b e => exact EquivBA.base (Equiv.u1 b _)
  | u2 b e f => exact EquivBA.base (Equiv.u2 b _ _)
  | u3 b c e f g => exact EquivBA.base (Equiv.u3 b c _ _ _)
  | u4 b e f => exact EquivBA.base (Equiv.u4 b _ _)
  | u5 b e f g => exact EquivBA.base (Equiv.u5 b _ _ _)
  | s1 e f g => exact EquivBA.base (Equiv.s1 _ _ _)
  | s2 e => exact EquivBA.base (Equiv.s2 _)
  | s3 e => exact EquivBA.base (Equiv.s3 _)
  | s4 e => exact EquivBA.base (Equiv.s4 _)
  | s5 e => exact EquivBA.base (Equiv.s5 _)
  | w1 b e => exact EquivBA.base (Equiv.w1 b _)
  | w2 b c e => exact EquivBA.base (Equiv.w2 b c _)
  | w3 hE hg ihE ihg =>
      refine EquivBA.w3_ba ?_ ihg
      refine EquivBA.trans
        (EquivBA.baTest (fun X W x => bval_E_substA hσ _ X W x)) ?_
      exact ihE

/-- **THE SUBSTITUTION HOMOMORPHISM**: `EquivBA` is closed under
    productive action substitution. -/
theorem equivBA_substA {A' : Type} {σ : A → Exp A' T}
    (hσ : ∀ (a : A) (X : Type) (W : T → X → Bool) (x : X),
      bval W (E (σ a)) x = false)
    {e f : Exp A T} (h : EquivBA e f) :
    EquivBA (substA σ e) (substA σ f) := by
  induction h with
  | base h => exact equiv_substA hσ h
  | symm _ ih => exact EquivBA.symm ih
  | trans _ _ ih₁ ih₂ => exact EquivBA.trans ih₁ ih₂
  | seq_c _ _ ih₁ ih₂ => exact EquivBA.seq_c ih₁ ih₂
  | ite_c _ _ ih₁ ih₂ => exact EquivBA.ite_c ih₁ ih₂
  | wh_c _ ih => exact EquivBA.wh_c ih
  | baTest h => exact EquivBA.baTest h
  | ite_guard h => exact EquivBA.ite_guard h
  | wh_guard h => exact EquivBA.wh_guard h
  | s6 b c => exact EquivBA.s6 b c
  | w3_ba hE hg ihE ihg =>
      refine EquivBA.w3_ba ?_ ihg
      refine EquivBA.trans
        (EquivBA.baTest (fun X W x => bval_E_substA hσ _ X W x)) ?_
      exact ihE

#print axioms bval_E_substA
#print axioms equiv_substA
#print axioms equivBA_substA

/-! ## Call markers and the transport layer

    Elimination derivations live over the extended alphabet `A ⊕ S` —
    calls are trailing actions.  Right-linearity keeps every `w3` body
    call-free, but the FINAL per-state facts have call-free endpoints
    outright, so ONE transport with the trivially productive
    substitution (calls ↦ `test zero`, which is strictly productive:
    `E(test 0) = 0`) brings them to `Exp A T`.  No reasoning about the
    productivity of closed forms is ever needed. -/

/-- Embed a flat expression into the call alphabet. -/
def embedC {S : Type} : Exp A T → Exp (Sum A S) T :=
  substA (fun a => .act (Sum.inl a))

/-- Substitution composes syntactically. -/
theorem substA_comp {A' A'' : Type} (σ : A → Exp A' T)
    (τ : A' → Exp A'' T) :
    ∀ e : Exp A T, substA τ (substA σ e) = substA (fun a => substA τ (σ a)) e := by
  intro e
  induction e with
  | act a => rfl
  | test b => rfl
  | seq e f ihe ihf =>
      show Exp.seq (substA τ (substA σ e)) (substA τ (substA σ f)) = _
      rw [ihe, ihf]
      rfl
  | ite b e f ihe ihf =>
      show Exp.ite b (substA τ (substA σ e)) (substA τ (substA σ f)) = _
      rw [ihe, ihf]
      rfl
  | wh b e ih =>
      show Exp.wh b (substA τ (substA σ e)) = _
      rw [ih]
      rfl

/-- The identity substitution. -/
theorem substA_id : ∀ e : Exp A T, substA (fun a => .act a) e = e := by
  intro e
  induction e with
  | act a => rfl
  | test b => rfl
  | seq e f ihe ihf =>
      show Exp.seq (substA _ e) (substA _ f) = _
      rw [ihe, ihf]
  | ite b e f ihe ihf =>
      show Exp.ite b (substA _ e) (substA _ f) = _
      rw [ihe, ihf]
  | wh b e ih =>
      show Exp.wh b (substA _ e) = _
      rw [ih]

/-- The collapse substitution: real actions restored, stray calls
    killed (they never occur in the transported endpoints). -/
def collapseC {S : Type} : Sum A S → Exp A T :=
  fun a => match a with
    | Sum.inl a => .act a
    | Sum.inr _ => .test .zero

/-- Collapsing an embedding is the identity. -/
theorem collapse_embed {S : Type} :
    ∀ e : Exp A T, substA (collapseC (S := S)) (embedC (S := S) e) = e := by
  intro e
  show substA collapseC (substA (fun a => .act (Sum.inl a)) e) = e
  rw [substA_comp]
  exact substA_id e

/-- **THE TRANSPORT**: call-level equivalence of embedded expressions
    is flat equivalence. -/
theorem equivBA_of_embed {S : Type} {e f : Exp A T}
    (h : EquivBA (embedC (S := S) e) (embedC (S := S) f)) :
    EquivBA e f := by
  have h2 := equivBA_substA (σ := collapseC (S := S)) ?_ h
  · rw [collapse_embed, collapse_embed] at h2
    exact h2
  · intro a X W x
    cases a with
    | inl a => rfl
    | inr s => rfl

#print axioms substA_comp
#print axioms substA_id
#print axioms collapse_embed
#print axioms equivBA_of_embed

/-! ## Right-linear trees

    The elimination's equation carrier: guarded branching over
    call-free prefixes, with calls at the leaves.  Substituting a
    state's closed tree for its calls is SYNTACTIC (resolution
    commutes, `resolve_substT`); collecting a single-target subtree
    into `prefix ; call` form is the `u5`-factoring
    (`factor_spec` — the abstract `hPfactor`). -/

/-- A right-linear equation tree: halts, prefixed calls, guarded
    branches, and prefixes. -/
inductive RTree (S A T : Type) where
  | halt (h : BExp T)
  | call (e : Exp A T) (s : S)
  | br (g : BExp T) (l r : RTree S A T)
  | pre (e : Exp A T) (t : RTree S A T)

/-- Resolve a tree against a solution assignment. -/
def resolveT {S : Type} (sol : S → Exp A T) : RTree S A T → Exp A T
  | .halt h => .test h
  | .call e s => .seq e (sol s)
  | .br g l r => .ite g (resolveT sol l) (resolveT sol r)
  | .pre e t => .seq e (resolveT sol t)

/-- Every leaf calls `u` (no halts): the single-target condition. -/
def AllCalls {S : Type} (u : S) : RTree S A T → Prop
  | .halt _ => False
  | .call _ s => s = u
  | .br _ l r => AllCalls u l ∧ AllCalls u r
  | .pre _ t => AllCalls u t

/-- The factored prefix of a single-target tree. -/
def factorE {S : Type} : RTree S A T → Exp A T
  | .halt _ => .test .zero
  | .call e _ => e
  | .br g l r => .ite g (factorE l) (factorE r)
  | .pre e t => .seq e (factorE t)

/-- **THE FACTORING LEMMA**: a single-target tree resolves to its
    factored prefix followed by the target — the generalized
    `hPfactor`, by `u5`-distribution and association. -/
theorem factor_spec {S : Type} (sol : S → Exp A T) (u : S) :
    ∀ (t : RTree S A T), AllCalls u t →
      EquivBA (resolveT sol t) (.seq (factorE t) (sol u)) := by
  intro t
  induction t with
  | halt h => intro hc; exact absurd hc (fun h => h)
  | call e s =>
      intro hc
      have hs : s = u := hc
      rw [hs]
      exact EquivBA.base (Equiv.refl _)
  | br g l r ihl ihr =>
      intro hc
      refine EquivBA.trans (EquivBA.ite_c (ihl hc.1) (ihr hc.2)) ?_
      exact EquivBA.base (Equiv.u5 g (factorE l) (factorE r) (sol u))
  | pre e t ih =>
      intro hc
      refine EquivBA.trans
        (EquivBA.seq_c (EquivBA.base (Equiv.refl e)) (ih hc)) ?_
      exact EquivBA.symm (EquivBA.base (Equiv.s1 e (factorE t) (sol u)))

/-- Substitute a closed tree for every call to `u`. -/
def substT {S : Type} [DecidableEq S] (u : S) (C : RTree S A T) :
    RTree S A T → RTree S A T
  | .halt h => .halt h
  | .call e s => if s = u then .pre e C else .call e s
  | .br g l r => .br g (substT u C l) (substT u C r)
  | .pre e t => .pre e (substT u C t)

/-- **SUBSTITUTION IS SYNTACTICALLY SOUND**: if the assignment
    already solves `u` as its closed tree, substituting the tree
    changes nothing under resolution — pure equality, no derivation. -/
theorem resolve_substT {S : Type} [DecidableEq S] (sol : S → Exp A T)
    (u : S) (C : RTree S A T) (hu : sol u = resolveT sol C) :
    ∀ t : RTree S A T, resolveT sol (substT u C t) = resolveT sol t := by
  intro t
  induction t with
  | halt h => rfl
  | call e s =>
      by_cases hs : s = u
      · show resolveT sol (if s = u then .pre e C else .call e s) = _
        rw [if_pos hs, hs]
        show Exp.seq e (resolveT sol C) = Exp.seq e (sol u)
        rw [hu]
      · show resolveT sol (if s = u then .pre e C else .call e s) = _
        rw [if_neg hs]
  | br g l r ihl ihr =>
      show Exp.ite g (resolveT sol (substT u C l))
          (resolveT sol (substT u C r)) = _
      rw [ihl, ihr]
      rfl
  | pre e t ih =>
      show Exp.seq e (resolveT sol (substT u C t)) = _
      rw [ih]
      rfl

#print axioms factor_spec
#print axioms resolve_substT

/-- **THE CLOSING STEP**: if a state's equation splits at the top into
    a single-target self part under guard `G` and a rest, then the
    Salomaa closed form — the factored lap wrapped in `wh`, followed by
    the rest — solves the equation.  One `w3`-power step (via
    `salomaa_solution_exists`), the factoring lemma, and congruence. -/
theorem elim_close {S : Type} (sol : S → Exp A T) (u : S) (G : BExp T)
    (tl rest : RTree S A T) (hall : AllCalls u tl)
    (hsol : sol u = .seq (.wh G (factorE tl)) (resolveT sol rest)) :
    EquivBA (sol u) (resolveT sol (.br G tl rest)) := by
  show EquivBA (sol u)
    (.ite G (resolveT sol tl) (resolveT sol rest))
  refine EquivBA.trans ?_ (EquivBA.ite_c
    (EquivBA.symm (factor_spec sol u tl hall))
    (EquivBA.base (Equiv.refl _)))
  have h1 : EquivBA (sol u)
      (.seq (.wh G (factorE tl)) (resolveT sol rest)) := by
    rw [hsol]
    exact EquivBA.base (Equiv.refl _)
  refine EquivBA.trans h1 ?_
  refine EquivBA.trans (EquivBA.base
    (salomaa_solution_exists G (factorE tl) (resolveT sol rest))) ?_
  refine EquivBA.ite_c ?_ (EquivBA.base (Equiv.refl _))
  refine EquivBA.seq_c (EquivBA.base (Equiv.refl _)) ?_
  rw [← hsol]
  exact EquivBA.base (Equiv.refl _)

#print axioms elim_close

/-! ## The schedule: back-substitution and call support

    A schedule closes states in order; each closed tree calls only
    LATER states and externals (the forward-parametric invariant), so
    the solution assigns values by structural recursion from the last
    step backwards.  Resolution respects call support, which is what
    lets the soundness induction replace tails. -/

/-- Calls restricted to a support. -/
def CallOnly {S : Type} (P : S → Prop) : RTree S A T → Prop
  | .halt _ => True
  | .call _ s => P s
  | .br _ l r => CallOnly P l ∧ CallOnly P r
  | .pre _ t => CallOnly P t

/-- Resolution only reads the solution on the call support. -/
theorem resolveT_congr {S : Type} {sol₁ sol₂ : S → Exp A T}
    {P : S → Prop} (h : ∀ s, P s → sol₁ s = sol₂ s) :
    ∀ t : RTree S A T, CallOnly P t →
      resolveT sol₁ t = resolveT sol₂ t := by
  intro t
  induction t with
  | halt hb => intro _; rfl
  | call e s =>
      intro hc
      show Exp.seq e (sol₁ s) = Exp.seq e (sol₂ s)
      rw [h s hc]
  | br g l r ihl ihr =>
      intro hc
      show Exp.ite g (resolveT sol₁ l) (resolveT sol₁ r) = _
      rw [ihl hc.1, ihr hc.2]
      rfl
  | pre e t ih =>
      intro hc
      show Exp.seq e (resolveT sol₁ t) = _
      rw [ih hc]
      rfl

/-- Monotonicity of call support. -/
theorem callOnly_mono {S : Type} {P Q : S → Prop}
    (h : ∀ s, P s → Q s) :
    ∀ t : RTree S A T, CallOnly P t → CallOnly Q t := by
  intro t
  induction t with
  | halt hb => intro _; exact True.intro
  | call e s => intro hc; exact h s hc
  | br g l r ihl ihr => intro hc; exact ⟨ihl hc.1, ihr hc.2⟩
  | pre e t ih => intro hc; exact ih hc

/-- Substitution's support: calls of the substituted tree lie in the
    original support minus `u`, plus the closed tree's support. -/
theorem callOnly_substT {S : Type} [DecidableEq S] {P Q : S → Prop}
    (u : S) (C : RTree S A T) (hC : CallOnly Q C)
    (hPQ : ∀ s, P s → s ≠ u → Q s) :
    ∀ t : RTree S A T, CallOnly P t →
      CallOnly Q (substT u C t) := by
  intro t
  induction t with
  | halt hb => intro _; exact True.intro
  | call e s =>
      intro hc
      show CallOnly Q (if s = u then .pre e C else .call e s)
      by_cases hs : s = u
      · rw [if_pos hs]; exact hC
      · rw [if_neg hs]; exact hPQ s hc hs
  | br g l r ihl ihr => intro hc; exact ⟨ihl hc.1, ihr hc.2⟩
  | pre e t ih => intro hc; exact ih hc

/-- The back-substitution solution: the head step's value resolves its
    closed tree against the tail's solution. -/
def backSol {S : Type} [DecidableEq S] (ext : S → Exp A T) :
    List (S × RTree S A T) → S → Exp A T
  | [] => ext
  | (u, C) :: rest => fun s =>
      if s = u then resolveT (backSol ext rest) C
      else backSol ext rest s

theorem backSol_head {S : Type} [DecidableEq S] (ext : S → Exp A T)
    (u : S) (C : RTree S A T) (rest : List (S × RTree S A T)) :
    backSol ext ((u, C) :: rest) u
      = resolveT (backSol ext rest) C := by
  show (if u = u then _ else _) = _
  rw [if_pos rfl]

theorem backSol_ne {S : Type} [DecidableEq S] (ext : S → Exp A T)
    (u : S) (C : RTree S A T) (rest : List (S × RTree S A T))
    (s : S) (h : s ≠ u) :
    backSol ext ((u, C) :: rest) s = backSol ext rest s := by
  show (if s = u then _ else _) = _
  rw [if_neg h]

/-- Off-schedule states keep their external values. -/
theorem backSol_ext {S : Type} [DecidableEq S] (ext : S → Exp A T) :
    ∀ (steps : List (S × RTree S A T)) (s : S),
      (∀ p ∈ steps, s ≠ p.1) → backSol ext steps s = ext s := by
  intro steps
  induction steps with
  | nil => intro s _; rfl
  | cons hd rest ih =>
      intro s hs
      obtain ⟨u, C⟩ := hd
      rw [backSol_ne ext u C rest s (hs (u, C) (List.mem_cons_self ..))]
      exact ih s (fun p hp => hs p (List.mem_cons_of_mem _ hp))

/-- The left-to-right cascade substitution of a closed prefix. -/
def stepSubst {S : Type} [DecidableEq S]
    (closed : List (S × RTree S A T)) (t : RTree S A T) : RTree S A T :=
  closed.foldl (fun acc p => substT p.1 p.2 acc) t

theorem stepSubst_nil {S : Type} [DecidableEq S] (t : RTree S A T) :
    stepSubst ([] : List (S × RTree S A T)) t = t := rfl

theorem stepSubst_cons {S : Type} [DecidableEq S]
    (u : S) (C : RTree S A T) (closed : List (S × RTree S A T))
    (t : RTree S A T) :
    stepSubst ((u, C) :: closed) t = stepSubst closed (substT u C t) := rfl

/-- Cascade substitution is resolution-sound: if the assignment solves
    every closed state as its closed tree, the cascade is invisible. -/
theorem resolve_stepSubst {S : Type} [DecidableEq S]
    (sol : S → Exp A T) :
    ∀ (closed : List (S × RTree S A T)),
      (∀ p ∈ closed, sol p.1 = resolveT sol p.2) →
      ∀ t : RTree S A T,
        resolveT sol (stepSubst closed t) = resolveT sol t := by
  intro closed
  induction closed with
  | nil => intro _ t; rfl
  | cons hd rest ih =>
      intro hall t
      obtain ⟨u, C⟩ := hd
      rw [stepSubst_cons]
      rw [ih (fun p hp => hall p (List.mem_cons_of_mem _ hp))
        (substT u C t)]
      exact resolve_substT sol u C
        (hall (u, C) (List.mem_cons_self ..)) t

#print axioms resolveT_congr
#print axioms callOnly_substT
#print axioms backSol_ext
#print axioms resolve_stepSubst

/-! ## Schedule soundness

    The forward-parametric certificate `Supp`: each closed tree calls
    only strictly-later scheduled states or externals; states distinct
    and off the external support.  Under it `backSol` solves every
    scheduled state AS its closed tree; adding the per-step closing
    certificate `SchedOk`, it solves every ORIGINAL equation. -/

/-- The support certificate. -/
inductive Supp {S : Type} (P : S → Prop) :
    List (S × RTree S A T) → Prop where
  | nil : Supp P []
  | cons (u : S) (C : RTree S A T) (rest : List (S × RTree S A T))
      (hC : CallOnly (fun s => (∃ q ∈ rest, s = q.1) ∨ P s) C)
      (hne : ∀ q ∈ rest, u ≠ q.1)
      (hP : ¬ P u)
      (hrest : Supp P rest) : Supp P ((u, C) :: rest)

/-- Every member's closed tree calls only schedule states or
    externals. -/
theorem supp_member {S : Type} (P : S → Prop) :
    ∀ steps : List (S × RTree S A T), Supp P steps →
      ∀ p ∈ steps,
        CallOnly (fun s => (∃ q ∈ steps, s = q.1) ∨ P s) p.2 := by
  intro steps
  induction steps with
  | nil => intro _ p hp; exact nomatch hp
  | cons hd rest ih =>
      intro hs p hp
      cases hs with
      | cons u C _ hC hne hP hrest =>
          rcases List.mem_cons.mp hp with hph | hpr
          · subst hph
            refine callOnly_mono ?_ _ hC
            intro s hs
            rcases hs with ⟨q, hq, hsq⟩ | hPs
            · exact Or.inl ⟨q, List.mem_cons_of_mem _ hq, hsq⟩
            · exact Or.inr hPs
          · refine callOnly_mono ?_ _ (ih hrest p hpr)
            intro s hs
            rcases hs with ⟨q, hq, hsq⟩ | hPs
            · exact Or.inl ⟨q, List.mem_cons_of_mem _ hq, hsq⟩
            · exact Or.inr hPs

/-- **SOLVED AS CLOSED**: the solution value of every scheduled state
    is its closed tree resolved against the full solution. -/
theorem backSol_solves_closed {S : Type} [DecidableEq S]
    (P : S → Prop) (ext : S → Exp A T) :
    ∀ steps : List (S × RTree S A T), Supp P steps →
      ∀ p ∈ steps,
        backSol ext steps p.1 = resolveT (backSol ext steps) p.2 := by
  intro steps
  induction steps with
  | nil => intro _ p hp; exact nomatch hp
  | cons hd rest ih =>
      intro hsupp p hp
      obtain ⟨u, C⟩ := hd
      cases hsupp with
      | cons _ _ _ hC hne hP hrest =>
          have hagree : ∀ s, ((∃ q ∈ rest, s = q.1) ∨ P s) →
              backSol ext rest s = backSol ext ((u, C) :: rest) s := by
            intro s hs
            have hsu : s ≠ u := by
              rcases hs with ⟨q, hq, hsq⟩ | hPs
              · exact fun h => hne q hq (h.symm.trans hsq)
              · exact fun h => hP (h ▸ hPs)
            exact (backSol_ne ext u C rest s hsu).symm
          rcases List.mem_cons.mp hp with hph | hpr
          · subst hph
            show backSol ext ((u, C) :: rest) u
              = resolveT (backSol ext ((u, C) :: rest)) C
            rw [backSol_head]
            exact resolveT_congr hagree C hC
          · have hp1 : p.1 ≠ u := fun h => hne p hpr h.symm
            rw [backSol_ne ext u C rest p.1 hp1, ih hrest p hpr]
            exact resolveT_congr hagree p.2
              (supp_member P rest hrest p hpr)

/-- The per-step closing certificate, threaded with the closed
    prefix: each closed tree is the Salomaa closing of a top split of
    the cascade-substituted equation, or (fold states) the substituted
    equation itself. -/
def SchedOk {S : Type} [DecidableEq S] (sys : S → RTree S A T) :
    List (S × RTree S A T) → List (S × RTree S A T) → Prop
  | _, [] => True
  | closedPre, (u, C) :: rest =>
      ((∃ G tl tr,
          (∀ sol : S → Exp A T,
            EquivBA (resolveT sol (stepSubst closedPre (sys u)))
              (resolveT sol (.br G tl tr)))
          ∧ AllCalls u tl
          ∧ C = .pre (.wh G (factorE tl)) tr)
        ∨ (∀ sol : S → Exp A T,
            EquivBA (resolveT sol (stepSubst closedPre (sys u)))
              (resolveT sol C))
        ∨ (∀ sol : S → Exp A T, sol u = resolveT sol C →
            EquivBA (resolveT sol C)
              (resolveT sol (stepSubst closedPre (sys u)))))
      ∧ SchedOk sys (closedPre ++ [(u, C)]) rest

/-- **SCHEDULE SOUNDNESS** (positioned form). -/
theorem sched_solves_from {S : Type} [DecidableEq S]
    (sys : S → RTree S A T) (P : S → Prop) (ext : S → Exp A T)
    (full : List (S × RTree S A T)) (hsupp : Supp P full) :
    ∀ (steps pre : List (S × RTree S A T)),
      full = pre ++ steps → SchedOk sys pre steps →
      ∀ p ∈ steps,
        EquivBA (backSol ext full p.1)
          (resolveT (backSol ext full) (sys p.1)) := by
  intro steps
  induction steps with
  | nil => intro pre _ _ p hp; exact nomatch hp
  | cons hd rest ih =>
      intro pre hfull hok p hp
      obtain ⟨u, C⟩ := hd
      obtain ⟨hclose, hrestok⟩ := hok
      rcases List.mem_cons.mp hp with hph | hpr
      · subst hph
        have hmemu : ((u, C) : S × RTree S A T) ∈ full := by
          rw [hfull]
          exact List.mem_append.mpr (Or.inr (List.mem_cons_self ..))
        have hsolu : backSol ext full u
            = resolveT (backSol ext full) C :=
          backSol_solves_closed P ext full hsupp (u, C) hmemu
        have hpresolved : ∀ q ∈ pre,
            backSol ext full q.1 = resolveT (backSol ext full) q.2 := by
          intro q hq
          refine backSol_solves_closed P ext full hsupp q ?_
          rw [hfull]
          exact List.mem_append.mpr (Or.inl hq)
        have hstep := resolve_stepSubst (backSol ext full) pre
          hpresolved (sys u)
        rcases hclose with ⟨G, tl, tr, hsplit, hall, hCform⟩ | hCfold
          | hCself
        · have hsol : backSol ext full u
              = .seq (.wh G (factorE tl))
                (resolveT (backSol ext full) tr) := by
            rw [hsolu, hCform]
            rfl
          have hclose' := elim_close (backSol ext full) u G tl tr
            hall hsol
          have hchain := EquivBA.trans hclose'
            (EquivBA.symm (hsplit (backSol ext full)))
          rw [hstep] at hchain
          exact hchain
        · have hchain : EquivBA (backSol ext full u)
              (resolveT (backSol ext full) (stepSubst pre (sys u))) := by
            rw [hsolu]
            exact EquivBA.symm (hCfold (backSol ext full))
          rw [hstep] at hchain
          exact hchain
        · have hchain : EquivBA (backSol ext full u)
              (resolveT (backSol ext full) (stepSubst pre (sys u))) := by
            rw [hsolu]
            exact hCself (backSol ext full) hsolu
          rw [hstep] at hchain
          exact hchain
      · refine ih (pre ++ [(u, C)]) ?_ hrestok p hpr
        rw [hfull]
        rw [List.append_assoc]
        rfl

/-- **SCHEDULE SOUNDNESS**: a certified schedule's back-substitution
    solution provably solves every scheduled state's original
    equation. -/
theorem sched_solves {S : Type} [DecidableEq S]
    (sys : S → RTree S A T) (P : S → Prop) (ext : S → Exp A T)
    (steps : List (S × RTree S A T)) (hsupp : Supp P steps)
    (hok : SchedOk sys [] steps) :
    ∀ p ∈ steps,
      EquivBA (backSol ext steps p.1)
        (resolveT (backSol ext steps) (sys p.1)) :=
  sched_solves_from sys P ext steps hsupp steps [] rfl hok

#print axioms supp_member
#print axioms backSol_solves_closed
#print axioms sched_solves

/-! ## The flat bridge and the generalized assembly

    A flat automaton's equations are trees; a family of certified
    schedules, one per rank class, assembles into full `StateRole`
    coverage — the walked and chord assemblies as instances. -/

/-- The equation tree of a flat automaton state. -/
def treeOf {S : Type} (aut : GAut S A T) (s : S) : RTree S A T :=
  (aut.trans s).foldr
    (fun e acc => .br e.1 (.call (.act e.2.1) e.2.2) acc)
    (.halt (aut.hlt s))

private theorem resolve_treeOf_aux {S : Type} (sol : S → Exp A T)
    (h : BExp T) :
    ∀ L : List (BExp T × A × S),
      resolveT sol (L.foldr
        (fun e acc => .br e.1 (.call (.act e.2.1) e.2.2) acc)
        (.halt h))
      = foldTL sol h L := by
  intro L
  induction L with
  | nil => rfl
  | cons hd rest ih =>
      show Exp.ite hd.1 (.seq (.act hd.2.1) (sol hd.2.2)) _ = _
      rw [ih]
      rfl

/-- Trees resolve to the flat equations. -/
theorem resolve_treeOf {S : Type} (aut : GAut S A T)
    (sol : S → Exp A T) (s : S) :
    resolveT sol (treeOf aut s) = eqRHS aut sol s := by
  rw [eqRHS_foldTL]
  exact resolve_treeOf_aux sol (aut.hlt s) (aut.trans s)

private theorem callOnly_treeOf_aux {S : Type} (P : S → Prop)
    (h : BExp T) :
    ∀ L : List (BExp T × A × S), (∀ e ∈ L, P e.2.2) →
      CallOnly P (L.foldr
        (fun e acc => .br e.1 (.call (.act e.2.1) e.2.2) acc)
        (.halt h)) := by
  intro L
  induction L with
  | nil => intro _; exact True.intro
  | cons hd rest ih =>
      intro hall
      exact ⟨hall hd (List.mem_cons_self ..),
        ih (fun e he => hall e (List.mem_cons_of_mem _ he))⟩

/-- Arm-descent bounds the tree's call support. -/
theorem callOnly_treeOf {S : Type} (aut : GAut S A T)
    (P : S → Prop) (s : S)
    (h : ∀ e ∈ aut.trans s, P e.2.2) :
    CallOnly P (treeOf aut s) :=
  callOnly_treeOf_aux P (aut.hlt s) (aut.trans s) h

/-- The rank-stratified solution: each level closes its schedule over
    the levels below. -/
noncomputable def rankSol {S : Type} [DecidableEq S]
    (sched : Nat → List (S × RTree S A T)) : Nat → S → Exp A T
  | 0 => fun _ => .test .zero
  | r + 1 => backSol (rankSol sched r) (sched r)

/-- Levels above a state's rank never move its value. -/
theorem rankSol_stable {S : Type} [DecidableEq S]
    (sched : Nat → List (S × RTree S A T)) (rank : S → Nat)
    (hrank : ∀ r, ∀ p ∈ sched r, rank p.1 = r) :
    ∀ (r' : Nat) (s : S), rank s < r' →
      rankSol sched r' s = rankSol sched (rank s + 1) s := by
  intro r'
  induction r' with
  | zero => intro s hs; exact nomatch hs
  | succ r' ih =>
      intro s hs
      by_cases hr : rank s = r'
      · rw [hr]
      · have hlt : rank s < r' := by omega
        show backSol (rankSol sched r') (sched r') s = _
        rw [backSol_ext (rankSol sched r') (sched r') s
          (fun p hp => by
            intro hcontra
            exact hr (by rw [hcontra]; exact hrank r' p hp))]
        exact ih s hlt

/-- **THE GENERALIZED SCHEDULE ASSEMBLY**: a flat automaton with
    rank-bounded arms and a certified schedule per rank class is fully
    role-covered. -/
theorem sched_assembly_roles {S : Type} [DecidableEq S]
    (aut : GAut S A T) (rank : S → Nat)
    (sched : Nat → List (S × RTree S A T))
    (hdesc : ∀ s ∈ aut.states, ∀ e ∈ aut.trans s,
      rank e.2.2 ≤ rank s)
    (hsupp : ∀ r, Supp (fun s => rank s < r) (sched r))
    (hok : ∀ r, SchedOk (treeOf aut) [] (sched r))
    (hrank : ∀ r, ∀ p ∈ sched r, rank p.1 = r)
    (hcover : ∀ s ∈ aut.states, ∃ C, (s, C) ∈ sched (rank s)) :
    ∃ sol : S → Exp A T, ∀ s ∈ aut.states, StateRole aut sol s := by
  refine ⟨fun s => rankSol sched (rank s + 1) s, fun s hs => ?_⟩
  obtain ⟨C, hmem⟩ := hcover s hs
  have hsolve := sched_solves (treeOf aut) (fun t => rank t < rank s)
    (rankSol sched (rank s)) (sched (rank s)) (hsupp (rank s))
    (hok (rank s)) (s, C) hmem
  have hagree : ∀ t, rank t ≤ rank s →
      backSol (rankSol sched (rank s)) (sched (rank s)) t
        = rankSol sched (rank t + 1) t := by
    intro t ht
    show rankSol sched (rank s + 1) t = _
    exact rankSol_stable sched rank hrank (rank s + 1) t (by omega)
  have hcall : CallOnly (fun t => rank t ≤ rank s) (treeOf aut s) :=
    callOnly_treeOf aut _ s (fun e he => hdesc s hs e he)
  refine StateRole.equivFold ?_
  have h1 : backSol (rankSol sched (rank s)) (sched (rank s)) s
      = rankSol sched (rank s + 1) s := rfl
  rw [h1] at hsolve
  have h2 : resolveT (backSol (rankSol sched (rank s))
        (sched (rank s))) (treeOf aut s)
      = resolveT (fun t => rankSol sched (rank t + 1) t)
        (treeOf aut s) :=
    resolveT_congr hagree (treeOf aut s) hcall
  rw [h2, resolve_treeOf] at hsolve
  exact hsolve

#print axioms resolve_treeOf
#print axioms rankSol_stable
#print axioms sched_assembly_roles

/-! ## Instance support -/

/-- Substitution is a no-op on trees that never call the state. -/
theorem substT_noop {S : Type} [DecidableEq S] (u : S)
    (C : RTree S A T) :
    ∀ t : RTree S A T, CallOnly (fun s => s ≠ u) t →
      substT u C t = t := by
  intro t
  induction t with
  | halt h => intro _; rfl
  | call e s =>
      intro hc
      show (if s = u then _ else _) = _
      rw [if_neg hc]
  | br g l r ihl ihr =>
      intro hc
      show RTree.br g (substT u C l) (substT u C r) = _
      rw [ihl hc.1, ihr hc.2]
  | pre e t ih =>
      intro hc
      show RTree.pre e (substT u C t) = _
      rw [ih hc]

/-- A cascade over a call-free tree is a no-op. -/
theorem stepSubst_noop {S : Type} [DecidableEq S]
    (closed : List (S × RTree S A T)) (t : RTree S A T)
    (h : CallOnly (fun s => ∀ p ∈ closed, s ≠ p.1) t) :
    stepSubst closed t = t := by
  induction closed generalizing t with
  | nil => rfl
  | cons hd rest ih =>
      rw [stepSubst_cons]
      rw [substT_noop hd.1 hd.2 t
        (callOnly_mono (fun s hs => hs hd (List.mem_cons_self ..)) t h)]
      exact ih t (callOnly_mono
        (fun s hs p hp => hs p (List.mem_cons_of_mem _ hp)) t h)

/-- The arm-chain tree of a flat arm list. -/
def armChain {S : Type} (L : List (BExp T × A × S)) (h : BExp T) :
    RTree S A T :=
  L.foldr (fun e acc => .br e.1 (.call (.act e.2.1) e.2.2) acc)
    (.halt h)

/-- Arm chains resolve to the flat dispatch. -/
theorem resolve_armChain {S : Type} (sol : S → Exp A T)
    (L : List (BExp T × A × S)) (h : BExp T) :
    resolveT sol (armChain L h) = foldTL sol h L :=
  resolve_treeOf_aux sol h L

/-- `treeOf` is the arm chain of the automaton's arms. -/
theorem treeOf_armChain {S : Type} (aut : GAut S A T) (s : S) :
    treeOf aut s = armChain (aut.trans s) (aut.hlt s) := rfl

/-- Arm chains call only arm targets. -/
theorem callOnly_armChain {S : Type} (P : S → Prop)
    (L : List (BExp T × A × S)) (h : BExp T)
    (hall : ∀ e ∈ L, P e.2.2) :
    CallOnly P (armChain L h) :=
  callOnly_treeOf_aux P h L hall

#print axioms substT_noop
#print axioms stepSubst_noop
#print axioms resolve_armChain

/-! ## Validation instance: the singleton-SCC stratum as a schedule

    Every state's arms are self or strictly descending: each state is
    its own one-step elimination (`multi_gather` rearranges, the
    cascade is a no-op).  Re-derives the S2 stratum through the
    generalized assembly — the certificate ergonomics check. -/

open Classical in
/-- The Salomaa closed tree of a singleton-SCC state. -/
noncomputable def ssTree {S : Type} (aut : GAut S A T) (s : S) :
    RTree S A T :=
  .pre (.wh (gGuard s (aut.trans s)) (gBody s (aut.trans s)))
    (armChain (gOthers s (aut.trans s)) (aut.hlt s))

open Classical in
/-- **SINGLETON-SCC VIA SCHEDULES**: the S2 stratum re-derived through
    the generalized assembly. -/
theorem singleton_scc_sched {S : Type} [DecidableEq S]
    (aut : GAut S A T) (rank : S → Nat) (enum : Nat → List S)
    (henum_rank : ∀ r, ∀ s ∈ enum r, rank s = r)
    (henum_pair : ∀ r, (enum r).Pairwise (· ≠ ·))
    (hcover : ∀ s ∈ aut.states, s ∈ enum (rank s))
    (hshape : ∀ s : S, ∀ e ∈ aut.trans s,
      e.2.2 = s ∨ rank e.2.2 < rank s) :
    ∃ sol : S → Exp A T, ∀ s ∈ aut.states, StateRole aut sol s := by
  have hcallLow : ∀ (s : S),
      CallOnly (fun t => rank t < rank s) (ssTree aut s) := by
    intro s
    show CallOnly _ (armChain (gOthers s (aut.trans s)) (aut.hlt s))
    refine callOnly_armChain _ _ _ ?_
    intro e he
    obtain ⟨heL, hne⟩ := gOthers_sub s (aut.trans s) e he
    rcases hshape s e heL with h1 | h2
    · exact absurd h1 hne
    · exact h2
  have hcallTree : ∀ (s : S),
      CallOnly (fun t => t = s ∨ rank t < rank s) (treeOf aut s) := by
    intro s
    refine callOnly_treeOf aut _ s ?_
    intro e he
    rcases hshape s e he with h1 | h2
    · exact Or.inl h1
    · exact Or.inr h2
  refine sched_assembly_roles aut rank
    (fun r => (enum r).map (fun s => (s, ssTree aut s)))
    ?_ ?_ ?_ ?_ ?_
  · -- hdesc
    intro s _ e he
    rcases hshape s e he with h1 | h2
    · rw [h1]
      exact Nat.le_refl _
    · omega
  · -- hsupp
    intro r
    have haux : ∀ L : List S, (∀ s ∈ L, rank s = r) →
        L.Pairwise (· ≠ ·) →
        Supp (fun t => rank t < r)
          (L.map (fun s => (s, ssTree aut s))) := by
      intro L
      induction L with
      | nil => intro _ _; exact Supp.nil
      | cons s L' ih =>
          intro hranks hpair
          cases hpair with
          | cons hhead htail =>
              refine Supp.cons s (ssTree aut s) _ ?_ ?_ ?_
                (ih (fun t ht => hranks t (List.mem_cons_of_mem _ ht))
                  htail)
              · refine callOnly_mono ?_ _ (hcallLow s)
                intro t ht
                exact Or.inr (by
                  rw [← hranks s (List.mem_cons_self ..)]
                  exact ht)
              · intro q hq
                obtain ⟨t, htL, hqe⟩ := List.mem_map.mp hq
                rw [← hqe]
                exact hhead t htL
              · rw [hranks s (List.mem_cons_self ..)]
                omega
    exact haux (enum r) (henum_rank r) (henum_pair r)
  · -- hok
    intro r
    have haux : ∀ (L : List S) (closedPre : List (S × RTree S A T)),
        (∀ s ∈ L, rank s = r) → L.Pairwise (· ≠ ·) →
        (∀ p ∈ closedPre, rank p.1 = r) →
        (∀ p ∈ closedPre, ∀ s ∈ L, p.1 ≠ s) →
        SchedOk (treeOf aut) closedPre
          (L.map (fun s => (s, ssTree aut s))) := by
      intro L
      induction L with
      | nil => intro _ _ _ _ _; exact True.intro
      | cons s L' ih =>
          intro closedPre hranks hpair hpreR hpreNe
          have hrs : rank s = r := hranks s (List.mem_cons_self ..)
          cases hpair with
          | cons hhead htail =>
              constructor
              · refine Or.inl ⟨gGuard s (aut.trans s),
                  .call (gBody s (aut.trans s)) s,
                  armChain (gOthers s (aut.trans s)) (aut.hlt s),
                  ?_, rfl, rfl⟩
                intro sol
                have hnoop : stepSubst closedPre (treeOf aut s)
                    = treeOf aut s := by
                  refine stepSubst_noop closedPre (treeOf aut s) ?_
                  refine callOnly_mono ?_ _ (hcallTree s)
                  intro t ht p hp
                  rcases ht with h1 | h2
                  · rw [h1]
                    exact (hpreNe p hp s (List.mem_cons_self ..)).symm
                  · intro hc
                    rw [hc, hpreR p hp] at h2
                    rw [hrs] at h2
                    omega
                rw [hnoop, resolve_treeOf, eqRHS_foldTL]
                show EquivBA _ (Exp.ite (gGuard s (aut.trans s))
                  (.seq (gBody s (aut.trans s)) (sol s))
                  (resolveT sol (armChain (gOthers s (aut.trans s))
                    (aut.hlt s))))
                rw [resolve_armChain]
                exact multi_gather sol (aut.hlt s) s (aut.trans s)
              · refine ih (closedPre ++ [(s, ssTree aut s)])
                  (fun t ht => hranks t (List.mem_cons_of_mem _ ht))
                  htail ?_ ?_
                · intro p hp
                  rcases List.mem_append.mp hp with h1 | h2
                  · exact hpreR p h1
                  · rcases List.mem_cons.mp h2 with h3 | h4
                    · rw [h3]
                      exact hrs
                    · exact nomatch h4
                · intro p hp t ht
                  rcases List.mem_append.mp hp with h1 | h2
                  · exact hpreNe p h1 t (List.mem_cons_of_mem _ ht)
                  · rcases List.mem_cons.mp h2 with h3 | h4
                    · rw [h3]
                      exact hhead t ht
                    · exact nomatch h4
    exact haux (enum r) [] (henum_rank r) (henum_pair r)
      (fun p hp => nomatch hp) (fun p hp => nomatch hp)
  · -- hrank
    intro r p hp
    obtain ⟨t, htL, hpe⟩ := List.mem_map.mp hp
    rw [← hpe]
    exact henum_rank r t htL
  · -- hcover
    intro s hs
    exact ⟨ssTree aut s, List.mem_map.mpr
      ⟨s, hcover s hs, rfl⟩⟩

#print axioms singleton_scc_sched

/-! ## The pruning toolkit

    Cascaded trees carry dead halt leaves (interior halts are
    semantically empty) and trivially-true guards; the rearrangement
    clauses prune them.  `halt_prune` turns a dead-halt branch into a
    test prefix — the branch guard rides into the factored lap body,
    exactly the `wh_exit`-style normal form. -/

/-- A dead halt collapses to the branch guard as a test prefix. -/
theorem halt_prune {h g : BExp T} (hemp : GuardEmpty h)
    (X : Exp A T) :
    EquivBA (.ite g X (.test h)) (.seq (.test g) X) := by
  refine EquivBA.trans (EquivBA.ite_c (EquivBA.base (Equiv.refl X))
    (EquivBA.baTest (b := h) (c := .zero)
      (fun Z W v => hemp Z W v))) ?_
  exact GkatGuardedAlgebra.ite_zero_else g X

/-- A semantically-true guard selects its branch. -/
theorem ite_true_collapse {g : BExp T}
    (htop : ∀ (Z : Type) (W : T → Z → Bool) (v : Z),
      bval W g v = true)
    (X Y : Exp A T) :
    EquivBA (.ite g X Y) X := by
  refine EquivBA.trans
    (GkatGuardedAlgebra.ite_restrict_else g X Y) ?_
  refine EquivBA.trans (EquivBA.ite_c (EquivBA.base (Equiv.refl X))
    (EquivBA.seq_c (EquivBA.baTest (b := .not g) (c := .zero)
      (fun Z W v => by
        show (!(bval W g v)) = false
        rw [htop Z W v]
        rfl))
      (EquivBA.base (Equiv.refl Y)))) ?_
  refine EquivBA.trans (EquivBA.ite_c (EquivBA.base (Equiv.refl X))
    (EquivBA.base (Equiv.s2 Y))) ?_
  refine EquivBA.trans (GkatGuardedAlgebra.ite_zero_else g X) ?_
  refine EquivBA.trans (EquivBA.seq_c
    (EquivBA.baTest (b := g) (c := .one)
      (fun Z W v => htop Z W v))
    (EquivBA.base (Equiv.refl X))) ?_
  exact EquivBA.base (Equiv.s4 X)

/-- Tree-level dead-halt pruning: a branch over a dead halt is the
    guard-prefixed branch. -/
theorem resolve_halt_prune {S : Type} {h g : BExp T}
    (hemp : GuardEmpty h) (sol : S → Exp A T) (t : RTree S A T) :
    EquivBA (resolveT sol (.br g t (.halt h)))
      (resolveT sol (.pre (.test g) t)) :=
  halt_prune hemp (resolveT sol t)

/-- Tree-level true-guard pruning. -/
theorem resolve_true_collapse {S : Type} {g : BExp T}
    (htop : ∀ (Z : Type) (W : T → Z → Bool) (v : Z),
      bval W g v = true)
    (sol : S → Exp A T) (l r : RTree S A T) :
    EquivBA (resolveT sol (.br g l r)) (resolveT sol l) :=
  ite_true_collapse htop (resolveT sol l) (resolveT sol r)

#print axioms halt_prune
#print axioms ite_true_collapse
#print axioms resolve_halt_prune

/-! ## Validation instance: the walked 2-cycle as a schedule

    Interior with a hoisted self-loop and exit, port feeding back —
    the first multi-state cascade: the interior closes by Salomaa, the
    port's substituted lap prunes its dead interior halt and factors
    into the `wh_exit`-style closed form. -/

open Classical in
/-- **THE WALKED 2-CYCLE VIA SCHEDULES**. -/
theorem walked_two_cycle_sched {S : Type} [DecidableEq S]
    (aut : GAut S A T) (i o : S) (hio : i ≠ o)
    (c nc b : BExp T) (qa ra pa : A)
    (hti : aut.trans i = [(c, qa, i), (nc, ra, o)])
    (hto : aut.trans o = [(b, pa, i)])
    (hhi : GuardEmpty (aut.hlt i))
    (hstates : ∀ s ∈ aut.states, s = i ∨ s = o) :
    ∃ sol : S → Exp A T, ∀ s ∈ aut.states, StateRole aut sol s := by
  have htreei : treeOf aut i
      = .br c (.call (.act qa) i)
        (.br nc (.call (.act ra) o) (.halt (aut.hlt i))) := by
    rw [treeOf_armChain, hti]
    rfl
  have htreeo : treeOf aut o
      = .br b (.call (.act pa) i) (.halt (aut.hlt o)) := by
    rw [treeOf_armChain, hto]
    rfl
  -- the closed trees
  let Ci : RTree S A T :=
    .pre (.wh c (.act qa))
      (.br nc (.call (.act ra) o) (.halt (aut.hlt i)))
  let tl' : RTree S A T :=
    .pre (.act pa) (.pre (.wh c (.act qa))
      (.pre (.test nc) (.call (.act ra) o)))
  let Co : RTree S A T :=
    .pre (.wh b (.seq (.act pa) (.seq (.wh c (.act qa))
      (.seq (.test nc) (.act ra))))) (.halt (aut.hlt o))
  refine sched_assembly_roles aut (fun _ => 0)
    (fun r => match r with
      | 0 => [(i, Ci), (o, Co)]
      | _ + 1 => []) ?_ ?_ ?_ ?_ ?_
  · -- hdesc
    intro s _ e _
    exact Nat.le_refl 0
  · -- hsupp
    intro r
    match r with
    | 0 =>
        refine Supp.cons i Ci _ ?_ ?_ ?_ ?_
        · exact ⟨Or.inl ⟨(o, Co), List.mem_cons_self .., rfl⟩,
            True.intro⟩
        · intro q hq
          rcases List.mem_cons.mp hq with h1 | h2
          · rw [h1]
            exact hio
          · exact nomatch h2
        · omega
        · refine Supp.cons o Co _ ?_ ?_ ?_ Supp.nil
          · exact True.intro
          · intro q hq
            exact nomatch hq
          · omega
    | r + 1 => exact Supp.nil
  · -- hok
    intro r
    match r with
    | 0 =>
        refine ⟨?_, ?_, True.intro⟩
        · -- interior step: hoisted Salomaa split
          refine Or.inl ⟨c, .call (.act qa) i,
            .br nc (.call (.act ra) o) (.halt (aut.hlt i)),
            ?_, rfl, rfl⟩
          intro sol
          show EquivBA (resolveT sol (treeOf aut i)) _
          rw [htreei]
          exact EquivBA.base (Equiv.refl _)
        · -- port step: cascade, prune, factor
          refine Or.inl ⟨b, tl', .halt (aut.hlt o), ?_, rfl, rfl⟩
          intro sol
          show EquivBA (resolveT sol
            (stepSubst [(i, Ci)] (treeOf aut o)))
            (resolveT sol (.br b tl' (.halt (aut.hlt o))))
          have hsub : stepSubst [(i, Ci)] (treeOf aut o)
              = .br b (.pre (.act pa) Ci) (.halt (aut.hlt o)) := by
            show substT i Ci (treeOf aut o) = _
            rw [htreeo]
            show RTree.br b (if i = i then .pre (.act pa) Ci
              else .call (.act pa) i) (.halt (aut.hlt o)) = _
            rw [if_pos rfl]
          rw [hsub]
          show EquivBA
            (.ite b (.seq (.act pa) (.seq (.wh c (.act qa))
              (.ite nc (.seq (.act ra) (sol o))
                (.test (aut.hlt i)))))
              (.test (aut.hlt o)))
            (.ite b (.seq (.act pa) (.seq (.wh c (.act qa))
              (.seq (.test nc) (.seq (.act ra) (sol o)))))
              (.test (aut.hlt o)))
          refine EquivBA.ite_c ?_ (EquivBA.base (Equiv.refl _))
          refine EquivBA.seq_c (EquivBA.base (Equiv.refl _)) ?_
          refine EquivBA.seq_c (EquivBA.base (Equiv.refl _)) ?_
          exact halt_prune hhi (.seq (.act ra) (sol o))
    | r + 1 => exact True.intro
  · -- hrank
    intro r p hp
    match r, hp with
    | 0, hp => rfl
    | r + 1, hp => exact nomatch hp
  · -- hcover
    intro s hs
    rcases hstates s hs with h1 | h2
    · rw [h1]
      exact ⟨Ci, List.mem_cons_self ..⟩
    · rw [h2]
      exact ⟨Co, List.mem_cons_of_mem _ (List.mem_cons_self ..)⟩

#print axioms walked_two_cycle_sched

/-! ## Validation instance: the chord 3-cycle as a schedule

    Mid and branch states are FOLD steps (no self-calls — their closed
    trees are the cascaded equations); the port prunes BOTH dead
    interior halts and factors the branching lap.  The chord closed
    form re-derived by general machinery. -/

open Classical in
/-- **THE CHORD 3-CYCLE VIA SCHEDULES**. -/
theorem chord_three_sched {S : Type} [DecidableEq S]
    (aut : GAut S A T) (x p o : S)
    (hxp : x ≠ p) (hxo : x ≠ o) (hpo : p ≠ o)
    (gx cg ncg bg : BExp T) (ya xa ya' pa : A)
    (htx : aut.trans x = [(gx, ya, o)])
    (htp : aut.trans p = [(cg, xa, x), (ncg, ya', o)])
    (hto : aut.trans o = [(bg, pa, p)])
    (hhx : GuardEmpty (aut.hlt x))
    (hhp : GuardEmpty (aut.hlt p))
    (hstates : ∀ s ∈ aut.states, s = x ∨ s = p ∨ s = o) :
    ∃ sol : S → Exp A T, ∀ s ∈ aut.states, StateRole aut sol s := by
  have htreex : treeOf aut x
      = .br gx (.call (.act ya) o) (.halt (aut.hlt x)) := by
    rw [treeOf_armChain, htx]
    rfl
  have htreep : treeOf aut p
      = .br cg (.call (.act xa) x)
        (.br ncg (.call (.act ya') o) (.halt (aut.hlt p))) := by
    rw [treeOf_armChain, htp]
    rfl
  have htreeo : treeOf aut o
      = .br bg (.call (.act pa) p) (.halt (aut.hlt o)) := by
    rw [treeOf_armChain, hto]
    rfl
  let Cx : RTree S A T :=
    .br gx (.call (.act ya) o) (.halt (aut.hlt x))
  let Cp : RTree S A T :=
    .br cg (.pre (.act xa) Cx)
      (.br ncg (.call (.act ya') o) (.halt (aut.hlt p)))
  let tl' : RTree S A T :=
    .pre (.act pa) (.br cg
      (.pre (.act xa) (.pre (.test gx) (.call (.act ya) o)))
      (.pre (.test ncg) (.call (.act ya') o)))
  let Co : RTree S A T :=
    .pre (.wh bg (.seq (.act pa) (.ite cg
      (.seq (.act xa) (.seq (.test gx) (.act ya)))
      (.seq (.test ncg) (.act ya'))))) (.halt (aut.hlt o))
  refine sched_assembly_roles aut (fun _ => 0)
    (fun r => match r with
      | 0 => [(x, Cx), (p, Cp), (o, Co)]
      | _ + 1 => []) ?_ ?_ ?_ ?_ ?_
  · intro s _ e _
    exact Nat.le_refl 0
  · intro r
    match r with
    | 0 =>
        refine Supp.cons x Cx _ ?_ ?_ ?_ ?_
        · exact ⟨Or.inl ⟨(o, Co),
            List.mem_cons_of_mem _ (List.mem_cons_self ..), rfl⟩,
            True.intro⟩
        · intro q hq
          rcases List.mem_cons.mp hq with h1 | h2
          · rw [h1]; exact hxp
          · rcases List.mem_cons.mp h2 with h3 | h4
            · rw [h3]; exact hxo
            · exact nomatch h4
        · omega
        · refine Supp.cons p Cp _ ?_ ?_ ?_ ?_
          · exact ⟨⟨Or.inl ⟨(o, Co), List.mem_cons_self .., rfl⟩,
              True.intro⟩,
              Or.inl ⟨(o, Co), List.mem_cons_self .., rfl⟩,
              True.intro⟩
          · intro q hq
            rcases List.mem_cons.mp hq with h1 | h2
            · rw [h1]; exact hpo
            · exact nomatch h2
          · omega
          · refine Supp.cons o Co _ ?_ ?_ ?_ Supp.nil
            · exact True.intro
            · intro q hq
              exact nomatch hq
            · omega
    | r + 1 => exact Supp.nil
  · intro r
    match r with
    | 0 =>
        refine ⟨?_, ?_, ?_, True.intro⟩
        · -- mid: fold
          refine Or.inr (Or.inl ?_)
          intro sol
          show EquivBA (resolveT sol (treeOf aut x)) (resolveT sol Cx)
          rw [htreex]
          exact EquivBA.base (Equiv.refl _)
        · -- branch: fold over the cascade
          refine Or.inr (Or.inl ?_)
          intro sol
          show EquivBA (resolveT sol
            (stepSubst [(x, Cx)] (treeOf aut p))) (resolveT sol Cp)
          have hsub : stepSubst [(x, Cx)] (treeOf aut p) = Cp := by
            show substT x Cx (treeOf aut p) = Cp
            rw [htreep]
            show RTree.br cg
              (if x = x then .pre (.act xa) Cx else .call (.act xa) x)
              (.br ncg
                (if o = x then .pre (.act ya') Cx
                  else .call (.act ya') o)
                (.halt (aut.hlt p))) = Cp
            rw [if_pos rfl, if_neg (fun h => hxo h.symm)]
          rw [hsub]
          exact EquivBA.base (Equiv.refl _)
        · -- port: cascade, double prune, factor
          refine Or.inl ⟨bg, tl', .halt (aut.hlt o), ?_, ⟨rfl, rfl⟩,
            rfl⟩
          intro sol
          show EquivBA (resolveT sol
            (stepSubst [(x, Cx), (p, Cp)] (treeOf aut o)))
            (resolveT sol (.br bg tl' (.halt (aut.hlt o))))
          have hsub : stepSubst [(x, Cx), (p, Cp)] (treeOf aut o)
              = .br bg (.pre (.act pa) Cp) (.halt (aut.hlt o)) := by
            show substT p Cp (substT x Cx (treeOf aut o)) = _
            rw [htreeo]
            show substT p Cp (RTree.br bg
              (if p = x then .pre (.act pa) Cx else .call (.act pa) p)
              (.halt (aut.hlt o))) = _
            rw [if_neg (fun h => hxp h.symm)]
            show RTree.br bg
              (if p = p then .pre (.act pa) Cp else .call (.act pa) p)
              (.halt (aut.hlt o)) = _
            rw [if_pos rfl]
          rw [hsub]
          show EquivBA
            (.ite bg (.seq (.act pa) (.ite cg
              (.seq (.act xa) (.ite gx (.seq (.act ya) (sol o))
                (.test (aut.hlt x))))
              (.ite ncg (.seq (.act ya') (sol o))
                (.test (aut.hlt p)))))
              (.test (aut.hlt o)))
            (.ite bg (.seq (.act pa) (.ite cg
              (.seq (.act xa) (.seq (.test gx)
                (.seq (.act ya) (sol o))))
              (.seq (.test ncg) (.seq (.act ya') (sol o)))))
              (.test (aut.hlt o)))
          refine EquivBA.ite_c ?_ (EquivBA.base (Equiv.refl _))
          refine EquivBA.seq_c (EquivBA.base (Equiv.refl _)) ?_
          refine EquivBA.ite_c ?_ ?_
          · refine EquivBA.seq_c (EquivBA.base (Equiv.refl _)) ?_
            exact halt_prune hhx (.seq (.act ya) (sol o))
          · exact halt_prune hhp (.seq (.act ya') (sol o))
    | r + 1 => exact True.intro
  · intro r q hq
    match r, hq with
    | 0, hq => rfl
    | r + 1, hq => exact nomatch hq
  · intro s hs
    rcases hstates s hs with h1 | h2 | h3
    · rw [h1]
      exact ⟨Cx, List.mem_cons_self ..⟩
    · rw [h2]
      exact ⟨Cp, List.mem_cons_of_mem _ (List.mem_cons_self ..)⟩
    · rw [h3]
      exact ⟨Co, List.mem_cons_of_mem _
        (List.mem_cons_of_mem _ (List.mem_cons_self ..))⟩

#print axioms chord_three_sched

/-! ## The sixth theorem through the general pipeline

    The census facts instantiate `chord_three_sched` at the cleaned
    chord quotient — the bespoke chord assembly is no longer on the
    mainline. -/

open Classical in
/-- **CHORD COMPLETENESS VIA SCHEDULES**: `chordloops_complete`
    re-derived through the generalized elimination. -/
theorem chordloops_complete_sched (b c : BExp T) (p x y : A)
    (b' c' : BExp T) (p' x' y' : A)
    (hentB : ∃ α : T → Bool, bval (genW T) b α = true
      ∧ bval (genW T) b' α = true)
    (hentC : ∃ α : T → Bool, bval (genW T) c α = true
      ∧ bval (genW T) c' α = true)
    (hexitC : ∃ α : T → Bool, bval (genW T) c α = false)
    (hexitB : ∃ α : T → Bool, bval (genW T) b α = false)
    (hexitC' : ∃ α : T → Bool, bval (genW T) c' α = false)
    (hexitB' : ∃ α : T → Bool, bval (genW T) b' α = false)
    (heq : UniformLanguageEquivalent (chordLoop b c p x y)
      (chordLoop b' c' p' x' y')) :
    EquivBA (chordLoop b c p x y) (chordLoop b' c' p' x' y') := by
  have hstart : autLang (genW T)
      (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inl none)
    = autLang (genW T)
        (trimAut (chordSum b c p x y b' c' p' x' y')) (Sum.inr none) := by
    rw [autLang_trimAut, autLang_trimAut]
    show autLang (genW T) (sumGAut
        (certifiedThompson A T (chordLoop b c p x y)).aut.toGAut
        (certifiedThompson A T (chordLoop b' c' p' x' y')).aut.toGAut)
        (Sum.inl none)
      = autLang (genW T) (sumGAut
        (certifiedThompson A T (chordLoop b c p x y)).aut.toGAut
        (certifiedThompson A T (chordLoop b' c' p' x' y')).aut.toGAut)
        (Sum.inr none)
    rw [autLang_sum_inl, autLang_sum_inr,
      certifiedThompson_start_language (chordLoop b c p x y),
      certifiedThompson_start_language (chordLoop b' c' p' x' y')]
    funext gs
    exact propext (heq (T → Bool) (genW T) gs)
  have hdist := chord_reps_distinct b c p x y b' c' p' x' y'
    (⟨Classical.choose hentC, (Classical.choose_spec hentC).1⟩)
    hexitC hexitB
  obtain ⟨gX, aX, harmX, -⟩ := chord_midarms b c p x y b' c' p' x' y' hentB hentC hexitC hexitB hexitC' hexitB' hstart
  obtain ⟨g₁, g₂, a₁, a₂, harmP, -⟩ := chord_brancharms b c p x y b' c' p' x' y' hentB hentC hexitC hexitB hexitC' hexitB' hstart
  obtain ⟨gR, aR, harmR⟩ := chord_portarms b c p x y b' c' p' x' y' hentB hentC hexitC hexitB hexitC' hexitB' hstart
  obtain ⟨hhP, hhX⟩ := chord_hlts_empty b c p x y b' c' p' x' y' hentB hentC hexitC hexitB hexitC' hexitB' hstart
  have hstates : ∀ s ∈ (cleanAut (bisimQuotAut (trimAut
      (chordSum b c p x y b' c' p' x' y')))).states,
      s = chordRepX b c p x y b' c' p' x' y'
        ∨ s = chordRepP b c p x y b' c' p' x' y'
        ∨ s = chordRepR b c p x y b' c' p' x' y' := by
    intro s hs
    obtain ⟨t, ht, hrep⟩ := List.mem_map.mp hs
    rcases chord_census b c p x y b' c' p' x' y' hentB hentC hexitC hexitB hexitC' hexitB' hstart t with h1 | h2 | h3
    · exact Or.inr (Or.inr (hrep ▸ h1.symm ▸ rfl))
    · exact Or.inr (Or.inl (hrep ▸ h2.symm ▸ rfl))
    · exact Or.inl (hrep ▸ h3.symm ▸ rfl)
  obtain ⟨qsol, hroles⟩ := chord_three_sched
    (cleanAut (bisimQuotAut (trimAut (chordSum b c p x y b' c' p' x' y'))))
    (chordRepX b c p x y b' c' p' x' y') (chordRepP b c p x y b' c' p' x' y') (chordRepR b c p x y b' c' p' x' y')
    (fun h => hdist.2.2 h.symm) (fun h => hdist.2.1 h.symm)
    (fun h => hdist.1 h.symm)
    gX g₁ g₂ gR aX a₁ a₂ aR harmX harmP harmR hhX hhP hstates
  exact equivBA_of_quot_solvesBA (chordLoop b c p x y)
    (chordLoop b' c' p' x' y') heq
    (solvesBA_unclean _ (decomp_solves _ _ hroles))

#print axioms chordloops_complete_sched

/-! ## Census constructor: self-loops over a DAG

    A rank class whose same-rank calls are SELF or STRICTLY LATER in
    the enumeration schedules with no cascades at all: every state
    closes by `multi_gather` on its own arm list.  Subsumes the
    singleton-SCC stratum and handles acyclic SCC interiors — the
    workhorse leaf constructor for the census. -/

/-- Pairwise relations split across an append. -/
theorem pairwise_append_parts {α : Type} {R : α → α → Prop} :
    ∀ (L₁ L₂ : List α), (L₁ ++ L₂).Pairwise R →
      (∀ a ∈ L₁, ∀ b ∈ L₂, R a b) ∧ L₂.Pairwise R := by
  intro L₁
  induction L₁ with
  | nil => intro L₂ h; exact ⟨fun a ha => (nomatch ha), h⟩
  | cons x L₁' ih =>
      intro L₂ h
      cases h with
      | cons hx hrest =>
          obtain ⟨hcross, hp⟩ := ih L₂ hrest
          refine ⟨?_, hp⟩
          intro a ha b hb
          rcases List.mem_cons.mp ha with h1 | h2
          · rw [h1]
            exact hx b (List.mem_append.mpr (Or.inr hb))
          · exact hcross a h2 b hb

open Classical in
/-- **THE FOREST CONSTRUCTOR**: same-rank calls self-or-later ⟹ the
    class schedules with cascade-free `multi_gather` closings. -/
theorem forest_class_sched {S : Type} [DecidableEq S]
    (aut : GAut S A T) (rank : S → Nat) (enum : Nat → List S)
    (henum_rank : ∀ r, ∀ s ∈ enum r, rank s = r)
    (henum_pair : ∀ r, (enum r).Pairwise (· ≠ ·))
    (hcover : ∀ s ∈ aut.states, s ∈ enum (rank s))
    (hshape : ∀ (r : Nat) (L₁ : List S) (s : S) (L₂ : List S),
      enum r = L₁ ++ s :: L₂ → ∀ e ∈ aut.trans s,
        e.2.2 = s ∨ rank e.2.2 < r ∨ e.2.2 ∈ L₂) :
    ∃ sol : S → Exp A T, ∀ s ∈ aut.states, StateRole aut sol s := by
  refine sched_assembly_roles aut rank
    (fun r => (enum r).map (fun s => (s, ssTree aut s)))
    ?_ ?_ ?_ ?_ ?_
  · -- hdesc
    intro s hs e he
    obtain ⟨L₁, L₂, hsplit⟩ := List.append_of_mem (hcover s hs)
    rcases hshape (rank s) L₁ s L₂ hsplit e he with h1 | h2 | h3
    · rw [h1]
      exact Nat.le_refl _
    · omega
    · rw [henum_rank (rank s) e.2.2
        (hsplit ▸ List.mem_append.mpr
          (Or.inr (List.mem_cons_of_mem _ h3)))]
      exact Nat.le_refl _
  · -- hsupp
    intro r
    have haux : ∀ (L₂ L₁ : List S), enum r = L₁ ++ L₂ →
        Supp (fun t => rank t < r)
          (L₂.map (fun s => (s, ssTree aut s))) := by
      intro L₂
      induction L₂ with
      | nil => intro _ _; exact Supp.nil
      | cons s L₂' ih =>
          intro L₁ hL
          have hpair := pairwise_append_parts L₁ (s :: L₂')
            (hL ▸ henum_pair r)
          cases hpair.2 with
          | cons hhead htail =>
              refine Supp.cons s (ssTree aut s) _ ?_ ?_ ?_
                (ih (L₁ ++ [s]) (by rw [hL, List.append_assoc]; rfl))
              · show CallOnly _
                  (armChain (gOthers s (aut.trans s)) (aut.hlt s))
                refine callOnly_armChain _ _ _ ?_
                intro e he
                obtain ⟨heL, hne⟩ := gOthers_sub s (aut.trans s) e he
                rcases hshape r L₁ s L₂' hL e heL with h1 | h2 | h3
                · exact absurd h1 hne
                · exact Or.inr h2
                · exact Or.inl ⟨(e.2.2, ssTree aut e.2.2),
                    List.mem_map.mpr ⟨e.2.2, h3, rfl⟩, rfl⟩
              · intro q hq
                obtain ⟨t, htL, hqe⟩ := List.mem_map.mp hq
                rw [← hqe]
                exact hhead t htL
              · rw [henum_rank r s
                  (hL ▸ List.mem_append.mpr
                    (Or.inr (List.mem_cons_self ..)))]
                omega
    exact haux (enum r) [] rfl
  · -- hok
    intro r
    have haux : ∀ (L₂ L₁ : List S), enum r = L₁ ++ L₂ →
        SchedOk (treeOf aut) (L₁.map (fun s => (s, ssTree aut s)))
          (L₂.map (fun s => (s, ssTree aut s))) := by
      intro L₂
      induction L₂ with
      | nil => intro _ _; exact True.intro
      | cons s L₂' ih =>
          intro L₁ hL
          have hparts := pairwise_append_parts L₁ (s :: L₂')
            (hL ▸ henum_pair r)
          have hnoop : stepSubst (L₁.map (fun t => (t, ssTree aut t)))
              (treeOf aut s) = treeOf aut s := by
            refine stepSubst_noop _ _ ?_
            refine callOnly_treeOf aut _ s ?_
            intro e he q hq
            obtain ⟨t, htL, hqe⟩ := List.mem_map.mp hq
            rcases hshape r L₁ s L₂' hL e he with h1 | h2 | h3
            · rw [h1, ← hqe]
              exact fun hc => (hparts.1 t htL s
                (List.mem_cons_self ..)) hc.symm
            · rw [← hqe]
              intro hc
              rw [hc, henum_rank r t
                (hL ▸ List.mem_append.mpr (Or.inl htL))] at h2
              omega
            · rw [← hqe]
              intro hc
              exact (hparts.1 t htL e.2.2
                (List.mem_cons_of_mem _ h3)) hc.symm
          constructor
          · refine Or.inl ⟨gGuard s (aut.trans s),
              .call (gBody s (aut.trans s)) s,
              armChain (gOthers s (aut.trans s)) (aut.hlt s),
              ?_, rfl, rfl⟩
            intro sol
            rw [hnoop, resolve_treeOf, eqRHS_foldTL]
            show EquivBA _ (Exp.ite (gGuard s (aut.trans s))
              (.seq (gBody s (aut.trans s)) (sol s))
              (resolveT sol (armChain (gOthers s (aut.trans s))
                (aut.hlt s))))
            rw [resolve_armChain]
            exact multi_gather sol (aut.hlt s) s (aut.trans s)
          · have hres := ih (L₁ ++ [s])
              (by rw [hL, List.append_assoc]; rfl)
            show SchedOk (treeOf aut)
              ((L₁.map (fun t => (t, ssTree aut t)))
                ++ [(s, ssTree aut s)]) _
            have hmap : (L₁.map (fun t => (t, ssTree aut t)))
                ++ [(s, ssTree aut s)]
              = (L₁ ++ [s]).map (fun t => (t, ssTree aut t)) := by
              rw [List.map_append]
              rfl
            rw [hmap]
            exact hres
    exact haux (enum r) [] rfl
  · -- hrank
    intro r q hq
    obtain ⟨t, htL, hqe⟩ := List.mem_map.mp hq
    rw [← hqe]
    exact henum_rank r t htL
  · -- hcover
    intro s hs
    exact ⟨ssTree aut s, List.mem_map.mpr ⟨s, hcover s hs, rfl⟩⟩

#print axioms forest_class_sched

/-! ## The pruning machine

    Cascaded port trees carry dead interior halts at arbitrary depth.
    `pruneT` removes them wholesale: dead subtrees collapse, their
    sibling guards ride in as test prefixes.  A pruned dead-halt tree
    whose calls all target the port is `AllCalls` — ready for
    factoring. -/

/-- Every halt leaf is semantically dead. -/
def DeadHalts {S : Type} : RTree S A T → Prop
  | .halt h => GuardEmpty h
  | .call _ _ => True
  | .br _ l r => DeadHalts l ∧ DeadHalts r
  | .pre _ t => DeadHalts t

/-- Prune dead halts; `none` when the whole tree is dead. -/
def pruneT {S : Type} : RTree S A T → Option (RTree S A T)
  | .halt _ => none
  | .call e s => some (.call e s)
  | .br g l r =>
      match pruneT l, pruneT r with
      | some l', some r' => some (.br g l' r')
      | some l', none => some (.pre (.test g) l')
      | none, some r' => some (.pre (.test (.not g)) r')
      | none, none => none
  | .pre e t => (pruneT t).map (.pre e)

/-- A fully dead tree resolves to failure. -/
theorem dead_resolve {S : Type} (sol : S → Exp A T) :
    ∀ t : RTree S A T, DeadHalts t → pruneT t = none →
      EquivBA (resolveT sol t) (.test .zero) := by
  intro t
  induction t with
  | halt h =>
      intro hd _
      exact EquivBA.baTest (fun Z W v => hd Z W v)
  | call e s => intro _ hp; exact nomatch hp
  | br g l r ihl ihr =>
      intro hd hp
      show EquivBA (.ite g (resolveT sol l) (resolveT sol r)) _
      cases hl : pruneT l with
      | some l' =>
          exfalso
          cases hr : pruneT r with
          | some r' =>
              rw [show pruneT (.br g l r)
                = some (.br g l' r') from by
                  show (match pruneT l, pruneT r with
                    | some l', some r' => some (RTree.br g l' r')
                    | some l', none => some (.pre (.test g) l')
                    | none, some r' => some (.pre (.test (.not g)) r')
                    | none, none => none) = _
                  rw [hl, hr]] at hp
              exact nomatch hp
          | none =>
              rw [show pruneT (.br g l r)
                = some (.pre (.test g) l') from by
                  show (match pruneT l, pruneT r with
                    | some l', some r' => some (RTree.br g l' r')
                    | some l', none => some (.pre (.test g) l')
                    | none, some r' => some (.pre (.test (.not g)) r')
                    | none, none => none) = _
                  rw [hl, hr]] at hp
              exact nomatch hp
      | none =>
          cases hr : pruneT r with
          | some r' =>
              exfalso
              rw [show pruneT (.br g l r)
                = some (.pre (.test (.not g)) r') from by
                  show (match pruneT l, pruneT r with
                    | some l', some r' => some (RTree.br g l' r')
                    | some l', none => some (.pre (.test g) l')
                    | none, some r' => some (.pre (.test (.not g)) r')
                    | none, none => none) = _
                  rw [hl, hr]] at hp
              exact nomatch hp
          | none =>
              refine EquivBA.trans (EquivBA.ite_c
                (ihl hd.1 hl) (ihr hd.2 hr)) ?_
              exact EquivBA.base (Equiv.u1 g (.test .zero))
  | pre e t ih =>
      intro hd hp
      show EquivBA (.seq e (resolveT sol t)) _
      cases ht : pruneT t with
      | some t' =>
          exfalso
          rw [show pruneT (.pre e t) = some (.pre e t') from by
            show (pruneT t).map _ = _
            rw [ht]
            rfl] at hp
          exact nomatch hp
      | none =>
          refine EquivBA.trans (EquivBA.seq_c
            (EquivBA.base (Equiv.refl e)) (ih hd ht)) ?_
          exact EquivBA.base (Equiv.s3 e)

/-- **PRUNE SPEC**: pruning preserves resolution. -/
theorem prune_resolve {S : Type} (sol : S → Exp A T) :
    ∀ (t t' : RTree S A T), DeadHalts t → pruneT t = some t' →
      EquivBA (resolveT sol t) (resolveT sol t') := by
  intro t
  induction t with
  | halt h => intro t' _ hp; exact nomatch hp
  | call e s =>
      intro t' _ hp
      have := Option.some.inj hp
      rw [← this]
      exact EquivBA.base (Equiv.refl _)
  | br g l r ihl ihr =>
      intro t' hd hp
      have hpeq : (match pruneT l, pruneT r with
          | some l', some r' => some (RTree.br g l' r')
          | some l', none => some (.pre (.test g) l')
          | none, some r' => some (.pre (.test (.not g)) r')
          | none, none => none) = some t' := hp
      cases hl : pruneT l with
      | some l' =>
          cases hr : pruneT r with
          | some r' =>
              rw [hl, hr] at hpeq
              have := Option.some.inj hpeq
              rw [← this]
              exact EquivBA.ite_c (ihl l' hd.1 hl) (ihr r' hd.2 hr)
          | none =>
              rw [hl, hr] at hpeq
              have := Option.some.inj hpeq
              rw [← this]
              show EquivBA (.ite g (resolveT sol l) (resolveT sol r))
                (.seq (.test g) (resolveT sol l'))
              refine EquivBA.trans (EquivBA.ite_c (ihl l' hd.1 hl)
                (dead_resolve sol r hd.2 hr)) ?_
              exact GkatGuardedAlgebra.ite_zero_else g
                (resolveT sol l')
      | none =>
          cases hr : pruneT r with
          | some r' =>
              rw [hl, hr] at hpeq
              have := Option.some.inj hpeq
              rw [← this]
              show EquivBA (.ite g (resolveT sol l) (resolveT sol r))
                (.seq (.test (.not g)) (resolveT sol r'))
              refine EquivBA.trans (EquivBA.ite_c
                (dead_resolve sol l hd.1 hl) (ihr r' hd.2 hr)) ?_
              exact GkatGuardedAlgebra.ite_zero_then g
                (resolveT sol r')
          | none =>
              rw [hl, hr] at hpeq
              exact nomatch hpeq
  | pre e t ih =>
      intro t' hd hp
      have hpeq : (pruneT t).map (RTree.pre e) = some t' := hp
      cases ht : pruneT t with
      | some t₀ =>
          rw [ht] at hpeq
          have := Option.some.inj hpeq
          rw [← this]
          exact EquivBA.seq_c (EquivBA.base (Equiv.refl e))
            (ih t₀ hd ht)
      | none =>
          rw [ht] at hpeq
          exact nomatch hpeq

/-- **PRUNED TREES FACTOR**: pruning a port-targeted tree yields
    `AllCalls`. -/
theorem prune_allCalls {S : Type} (o : S) :
    ∀ (t t' : RTree S A T), CallOnly (fun s => s = o) t →
      pruneT t = some t' → AllCalls o t' := by
  intro t
  induction t with
  | halt h => intro t' _ hp; exact nomatch hp
  | call e s =>
      intro t' hc hp
      have := Option.some.inj hp
      rw [← this]
      exact hc
  | br g l r ihl ihr =>
      intro t' hc hp
      have hpeq : (match pruneT l, pruneT r with
          | some l', some r' => some (RTree.br g l' r')
          | some l', none => some (.pre (.test g) l')
          | none, some r' => some (.pre (.test (.not g)) r')
          | none, none => none) = some t' := hp
      cases hl : pruneT l with
      | some l' =>
          cases hr : pruneT r with
          | some r' =>
              rw [hl, hr] at hpeq
              have := Option.some.inj hpeq
              rw [← this]
              exact ⟨ihl l' hc.1 hl, ihr r' hc.2 hr⟩
          | none =>
              rw [hl, hr] at hpeq
              have := Option.some.inj hpeq
              rw [← this]
              exact ihl l' hc.1 hl
      | none =>
          cases hr : pruneT r with
          | some r' =>
              rw [hl, hr] at hpeq
              have := Option.some.inj hpeq
              rw [← this]
              exact ihr r' hc.2 hr
          | none =>
              rw [hl, hr] at hpeq
              exact nomatch hpeq
  | pre e t ih =>
      intro t' hc hp
      have hpeq : (pruneT t).map (RTree.pre e) = some t' := hp
      cases ht : pruneT t with
      | some t₀ =>
          rw [ht] at hpeq
          have := Option.some.inj hpeq
          rw [← this]
          exact ih t₀ hc ht
      | none =>
          rw [ht] at hpeq
          exact nomatch hpeq

#print axioms dead_resolve
#print axioms prune_resolve
#print axioms prune_allCalls

/-! ## The chain gather

    Tree-level `multi_gather`: a top-level branch chain partitions by a
    selector into port-reaching branches — factored and merged into one
    Salomaa arm — and the rest.  `arms_merge`/`arm_commute` do the
    shuffling once `factor_spec` has factored the selected subtrees. -/

/-- A top-level branch chain. -/
def chainT {S : Type} (h : BExp T) :
    List (BExp T × RTree S A T) → RTree S A T
  | [] => .halt h
  | (g, t) :: rest => .br g t (chainT h rest)

/-- The gathered guard of the selected branches. -/
def selGuard {S : Type} (sel : BExp T × RTree S A T → Bool) :
    List (BExp T × RTree S A T) → BExp T
  | [] => .zero
  | b :: rest =>
      if sel b then .or b.1 (selGuard sel rest)
      else .and (selGuard sel rest) (.not b.1)

/-- The merged, factored body of the selected branches. -/
def selBody {S : Type} (sel : BExp T × RTree S A T → Bool) :
    List (BExp T × RTree S A T) → Exp A T
  | [] => .test .zero
  | b :: rest =>
      if sel b then .ite b.1 (factorE b.2) (selBody sel rest)
      else selBody sel rest

/-- The unselected remainder. -/
def selOthers {S : Type} (sel : BExp T × RTree S A T → Bool) :
    List (BExp T × RTree S A T) → List (BExp T × RTree S A T)
  | [] => []
  | b :: rest =>
      if sel b then selOthers sel rest
      else b :: selOthers sel rest

/-- **THE CHAIN GATHER**: selected port-reaching branches collect into
    one factored Salomaa arm over the remainder chain. -/
theorem port_gather {S : Type} (sol : S → Exp A T) (o : S)
    (sel : BExp T × RTree S A T → Bool) (h : BExp T) :
    ∀ L : List (BExp T × RTree S A T),
      (∀ b ∈ L, sel b = true → AllCalls o b.2) →
      EquivBA (resolveT sol (chainT h L))
        (.ite (selGuard sel L) (.seq (selBody sel L) (sol o))
          (resolveT sol (chainT h (selOthers sel L)))) := by
  intro L
  induction L with
  | nil =>
      intro _
      exact EquivBA.symm (GkatDeadExitElim.ite_zero_guard _ _
        (fun Z W v => rfl))
  | cons b rest ih =>
      intro hall
      have ihr := ih (fun q hq hs => hall q (List.mem_cons_of_mem _ hq) hs)
      cases hsel : sel b with
      | true =>
          have hgu : selGuard sel (b :: rest)
              = .or b.1 (selGuard sel rest) := by
            show (if sel b then _ else _) = _
            rw [hsel]
            rfl
          have hbo : selBody sel (b :: rest)
              = .ite b.1 (factorE b.2) (selBody sel rest) := by
            show (if sel b then _ else _) = _
            rw [hsel]
            rfl
          have hot : selOthers sel (b :: rest)
              = selOthers sel rest := by
            show (if sel b then _ else _) = _
            rw [hsel]
            rfl
          rw [hgu, hbo, hot]
          show EquivBA (.ite b.1 (resolveT sol b.2)
            (resolveT sol (chainT h rest))) _
          refine EquivBA.trans (EquivBA.ite_c
            (factor_spec sol o b.2
              (hall b (List.mem_cons_self ..) hsel)) ihr) ?_
          exact arms_merge b.1 (selGuard sel rest) (factorE b.2)
            (selBody sel rest) (sol o)
            (resolveT sol (chainT h (selOthers sel rest)))
      | false =>
          have hgu : selGuard sel (b :: rest)
              = .and (selGuard sel rest) (.not b.1) := by
            show (if sel b then _ else _) = _
            rw [hsel]
            rfl
          have hbo : selBody sel (b :: rest) = selBody sel rest := by
            show (if sel b then _ else _) = _
            rw [hsel]
            rfl
          have hot : selOthers sel (b :: rest)
              = b :: selOthers sel rest := by
            show (if sel b then _ else _) = _
            rw [hsel]
            rfl
          rw [hgu, hbo, hot]
          show EquivBA (.ite b.1 (resolveT sol b.2)
            (resolveT sol (chainT h rest))) _
          refine EquivBA.trans (EquivBA.ite_c
            (EquivBA.base (Equiv.refl _)) ihr) ?_
          show EquivBA _ (.ite (.and (selGuard sel rest) (.not b.1))
            (.seq (selBody sel rest) (sol o))
            (.ite b.1 (resolveT sol b.2)
              (resolveT sol (chainT h (selOthers sel rest)))))
          exact arm_commute b.1 (selGuard sel rest)
            (resolveT sol b.2)
            (.seq (selBody sel rest) (sol o))
            (resolveT sol (chainT h (selOthers sel rest)))

#print axioms port_gather

/-! ## Chain bridges

    The port's cascaded equation is a branch chain: substitution
    distributes over chains, flat equations are chains of prefixed
    calls, pruning lifts branchwise, and dead halts survive
    substitution.  The four bridges between the schedule world and the
    gather world. -/

/-- Substitution distributes over chains. -/
theorem substT_chainT {S : Type} [DecidableEq S] (u : S)
    (C : RTree S A T) (h : BExp T) :
    ∀ L : List (BExp T × RTree S A T),
      substT u C (chainT h L)
        = chainT h (L.map (fun b => (b.1, substT u C b.2))) := by
  intro L
  induction L with
  | nil => rfl
  | cons b rest ih =>
      show RTree.br b.1 (substT u C b.2) (substT u C (chainT h rest)) = _
      rw [ih]
      rfl

/-- Cascades distribute over chains. -/
theorem stepSubst_chainT {S : Type} [DecidableEq S]
    (h : BExp T) :
    ∀ (closed : List (S × RTree S A T)) (L : List (BExp T × RTree S A T)),
      stepSubst closed (chainT h L)
        = chainT h (L.map (fun b =>
            (b.1, stepSubst closed b.2))) := by
  intro closed
  induction closed with
  | nil =>
      intro L
      show chainT h L = _
      have : L.map (fun b => (b.1, stepSubst [] b.2)) = L := by
        induction L with
        | nil => rfl
        | cons b rest ihL =>
            show (b.1, b.2) :: _ = _
            rw [ihL]
      rw [this]
  | cons p rest ih =>
      intro L
      rw [stepSubst_cons, substT_chainT, ih]
      have : (L.map (fun b => (b.1, substT p.1 p.2 b.2))).map
            (fun b => (b.1, stepSubst rest b.2))
          = L.map (fun b => (b.1, stepSubst rest (substT p.1 p.2 b.2))) := by
        induction L with
        | nil => rfl
        | cons b rest' ihL =>
            show (b.1, _) :: _ = (b.1, _) :: _
            rw [ihL]
      rw [this]
      rfl

/-- Flat equations are chains of prefixed calls. -/
theorem treeOf_chainT {S : Type} (aut : GAut S A T) (s : S) :
    treeOf aut s
      = chainT (aut.hlt s) ((aut.trans s).map
          (fun e => (e.1, .call (.act e.2.1) e.2.2))) := by
  show armChain (aut.trans s) (aut.hlt s) = _
  induction aut.trans s with
  | nil => rfl
  | cons e rest ih =>
      show RTree.br e.1 (.call (.act e.2.1) e.2.2)
        (armChain rest (aut.hlt s)) = _
      rw [ih]
      rfl

/-- Prune a branch, keeping dead branches in place. -/
def pruneBranch {S : Type} (b : BExp T × RTree S A T) :
    BExp T × RTree S A T :=
  match pruneT b.2 with
  | some t' => (b.1, t')
  | none => b

/-- Branchwise pruning preserves chain resolution. -/
theorem chain_prune_congr {S : Type} (sol : S → Exp A T) (h : BExp T) :
    ∀ L : List (BExp T × RTree S A T),
      (∀ b ∈ L, DeadHalts b.2) →
      EquivBA (resolveT sol (chainT h L))
        (resolveT sol (chainT h (L.map pruneBranch))) := by
  intro L
  induction L with
  | nil => intro _; exact EquivBA.base (Equiv.refl _)
  | cons b rest ih =>
      intro hall
      show EquivBA (.ite b.1 (resolveT sol b.2)
        (resolveT sol (chainT h rest))) _
      have hd := hall b (List.mem_cons_self ..)
      cases hp : pruneT b.2 with
      | some t' =>
          have hbr : pruneBranch b = (b.1, t') := by
            show (match pruneT b.2 with
              | some t' => (b.1, t') | none => b) = _
            rw [hp]
          show EquivBA _ (resolveT sol
            (chainT h (pruneBranch b :: rest.map pruneBranch)))
          rw [hbr]
          exact EquivBA.ite_c (prune_resolve sol b.2 t' hd hp)
            (ih (fun q hq => hall q (List.mem_cons_of_mem _ hq)))
      | none =>
          have hbr : pruneBranch b = b := by
            show (match pruneT b.2 with
              | some t' => (b.1, t') | none => b) = _
            rw [hp]
          show EquivBA _ (resolveT sol
            (chainT h (pruneBranch b :: rest.map pruneBranch)))
          rw [hbr]
          exact EquivBA.ite_c (EquivBA.base (Equiv.refl _))
            (ih (fun q hq => hall q (List.mem_cons_of_mem _ hq)))

/-- Dead halts survive substitution. -/
theorem substT_deadHalts {S : Type} [DecidableEq S] (u : S)
    (C : RTree S A T) (hC : DeadHalts C) :
    ∀ t : RTree S A T, DeadHalts t → DeadHalts (substT u C t) := by
  intro t
  induction t with
  | halt hb => intro hd; exact hd
  | call e s =>
      intro _
      show DeadHalts (if s = u then .pre e C else .call e s)
      by_cases hs : s = u
      · rw [if_pos hs]; exact hC
      · rw [if_neg hs]; exact True.intro
  | br g l r ihl ihr => intro hd; exact ⟨ihl hd.1, ihr hd.2⟩
  | pre e t ih => intro hd; exact ih hd

#print axioms substT_chainT
#print axioms stepSubst_chainT
#print axioms treeOf_chainT
#print axioms chain_prune_congr
#print axioms substT_deadHalts

/-! ## Cascade invariants and the selector -/

open Classical in
/-- The Salomaa closed tree of a forest state has dead halts when its
    own halt is empty. -/
theorem ssTree_deadHalts {S : Type} (aut : GAut S A T) (s : S)
    (h : GuardEmpty (aut.hlt s)) :
    DeadHalts (ssTree aut s) := by
  show DeadHalts (armChain (gOthers s (aut.trans s)) (aut.hlt s))
  induction gOthers s (aut.trans s) with
  | nil => exact h
  | cons e rest ih => exact ⟨True.intro, ih⟩

/-- Cascading dead-halt closed trees preserves dead halts. -/
theorem stepSubst_deadHalts {S : Type} [DecidableEq S] :
    ∀ (closed : List (S × RTree S A T)),
      (∀ p ∈ closed, DeadHalts p.2) →
      ∀ t : RTree S A T, DeadHalts t →
        DeadHalts (stepSubst closed t) := by
  intro closed
  induction closed with
  | nil => intro _ t ht; exact ht
  | cons p rest ih =>
      intro hall t ht
      rw [stepSubst_cons]
      exact ih (fun q hq => hall q (List.mem_cons_of_mem _ hq))
        (substT p.1 p.2 t)
        (substT_deadHalts p.1 p.2
          (hall p (List.mem_cons_self ..)) t ht)

/-- **CASCADE SUPPORT**: cascading a schedule prefix over a tree whose
    calls lie in the prefix-or-`P` leaves calls only in `P` — the
    `Supp`-driven collapse of the call support. -/
theorem stepSubst_callOnly {S : Type} [DecidableEq S] {P : S → Prop} :
    ∀ steps : List (S × RTree S A T), Supp P steps →
      ∀ t : RTree S A T,
        CallOnly (fun s => (∃ q ∈ steps, s = q.1) ∨ P s) t →
        CallOnly P (stepSubst steps t) := by
  intro steps
  induction steps with
  | nil =>
      intro _ t ht
      refine callOnly_mono ?_ t ht
      intro s hs
      rcases hs with ⟨q, hq, _⟩ | hP
      · exact nomatch hq
      · exact hP
  | cons hd rest ih =>
      intro hsupp t ht
      obtain ⟨u, C⟩ := hd
      cases hsupp with
      | cons _ _ _ hC hne hP hrest =>
          rw [stepSubst_cons]
          refine ih hrest (substT u C t) ?_
          refine callOnly_substT u C ?_ ?_ t ht
          · exact hC
          · intro s hs hsu
            rcases hs with ⟨q, hq, hsq⟩ | hPs
            · rcases List.mem_cons.mp hq with h1 | h2
              · refine absurd ?_ hsu
                rw [h1] at hsq
                exact hsq
              · exact Or.inl ⟨q, h2, hsq⟩
            · exact Or.inr hPs

/-- Boolean check: all calls target `o`. -/
def callsB {S : Type} [DecidableEq S] (o : S) : RTree S A T → Bool
  | .halt _ => true
  | .call _ s => s = o
  | .br _ l r => callsB o l && callsB o r
  | .pre _ t => callsB o t

/-- Boolean check: no halt leaves. -/
def haltFreeB {S : Type} : RTree S A T → Bool
  | .halt _ => false
  | .call _ _ => true
  | .br _ l r => haltFreeB l && haltFreeB r
  | .pre _ t => haltFreeB t

/-- Halt-free trees whose calls all target `o` are `AllCalls`. -/
theorem allCalls_of_bools {S : Type} [DecidableEq S] (o : S) :
    ∀ t : RTree S A T, callsB o t = true → haltFreeB t = true →
      AllCalls o t := by
  intro t
  induction t with
  | halt h => intro _ hf; exact nomatch hf
  | call e s =>
      intro hc _
      show s = o
      exact of_decide_eq_true hc
  | br g l r ihl ihr =>
      intro hc hf
      have hc' := Bool.and_eq_true_iff.mp hc
      have hf' := Bool.and_eq_true_iff.mp hf
      exact ⟨ihl hc'.1 hf'.1, ihr hc'.2 hf'.2⟩
  | pre e t ih => intro hc hf; exact ih hc hf

/-- Trees whose calls all target `o` (Boolean form) call only `o`. -/
theorem callOnly_of_callsB {S : Type} [DecidableEq S] (o : S) :
    ∀ t : RTree S A T, callsB o t = true →
      CallOnly (fun s => s = o) t := by
  intro t
  induction t with
  | halt h => intro _; exact True.intro
  | call e s =>
      intro hc
      show s = o
      exact of_decide_eq_true hc
  | br g l r ihl ihr =>
      intro hc
      have hc' := Bool.and_eq_true_iff.mp hc
      exact ⟨ihl hc'.1, ihr hc'.2⟩
  | pre e t ih => intro hc; exact ih hc

#print axioms ssTree_deadHalts
#print axioms stepSubst_deadHalts
#print axioms stepSubst_callOnly
#print axioms allCalls_of_bools

/-! ## Prune/selector interplay -/

/-- Pairwise restricts to the left part of an append. -/
theorem pairwise_append_left {α : Type} {R : α → α → Prop} :
    ∀ (L₁ L₂ : List α), (L₁ ++ L₂).Pairwise R → L₁.Pairwise R := by
  intro L₁
  induction L₁ with
  | nil => intro _ _; exact List.Pairwise.nil
  | cons x L₁' ih =>
      intro L₂ h
      cases h with
      | cons hx hrest =>
          exact List.Pairwise.cons
            (fun b hb => hx b (List.mem_append.mpr (Or.inl hb)))
            (ih L₂ hrest)

/-- Pruning preserves the call support. -/
theorem callOnly_pruneT {S : Type} {P : S → Prop} :
    ∀ (t t' : RTree S A T), CallOnly P t → pruneT t = some t' →
      CallOnly P t' := by
  intro t
  induction t with
  | halt h => intro t' _ hp; exact nomatch hp
  | call e s =>
      intro t' hc hp
      have := Option.some.inj hp
      rw [← this]
      exact hc
  | br g l r ihl ihr =>
      intro t' hc hp
      have hpeq : (match pruneT l, pruneT r with
          | some l', some r' => some (RTree.br g l' r')
          | some l', none => some (.pre (.test g) l')
          | none, some r' => some (.pre (.test (.not g)) r')
          | none, none => none) = some t' := hp
      cases hl : pruneT l with
      | some l' =>
          cases hr : pruneT r with
          | some r' =>
              rw [hl, hr] at hpeq
              rw [← Option.some.inj hpeq]
              exact ⟨ihl l' hc.1 hl, ihr r' hc.2 hr⟩
          | none =>
              rw [hl, hr] at hpeq
              rw [← Option.some.inj hpeq]
              exact ihl l' hc.1 hl
      | none =>
          cases hr : pruneT r with
          | some r' =>
              rw [hl, hr] at hpeq
              rw [← Option.some.inj hpeq]
              exact ihr r' hc.2 hr
          | none =>
              rw [hl, hr] at hpeq
              exact nomatch hpeq
  | pre e t ih =>
      intro t' hc hp
      have hpeq : (pruneT t).map (RTree.pre e) = some t' := hp
      cases ht : pruneT t with
      | some t₀ =>
          rw [ht] at hpeq
          rw [← Option.some.inj hpeq]
          exact ih t₀ hc ht
      | none =>
          rw [ht] at hpeq
          exact nomatch hpeq

/-- Pruned trees are halt-free. -/
theorem pruneT_haltFree {S : Type} :
    ∀ (t t' : RTree S A T), pruneT t = some t' →
      haltFreeB t' = true := by
  intro t
  induction t with
  | halt h => intro t' hp; exact nomatch hp
  | call e s =>
      intro t' hp
      rw [← Option.some.inj hp]
      rfl
  | br g l r ihl ihr =>
      intro t' hp
      have hpeq : (match pruneT l, pruneT r with
          | some l', some r' => some (RTree.br g l' r')
          | some l', none => some (.pre (.test g) l')
          | none, some r' => some (.pre (.test (.not g)) r')
          | none, none => none) = some t' := hp
      cases hl : pruneT l with
      | some l' =>
          cases hr : pruneT r with
          | some r' =>
              rw [hl, hr] at hpeq
              rw [← Option.some.inj hpeq]
              show (haltFreeB l' && haltFreeB r') = true
              rw [ihl l' hl, ihr r' hr]
              rfl
          | none =>
              rw [hl, hr] at hpeq
              rw [← Option.some.inj hpeq]
              exact ihl l' hl
      | none =>
          cases hr : pruneT r with
          | some r' =>
              rw [hl, hr] at hpeq
              rw [← Option.some.inj hpeq]
              exact ihr r' hr
          | none =>
              rw [hl, hr] at hpeq
              exact nomatch hpeq
  | pre e t ih =>
      intro t' hp
      have hpeq : (pruneT t).map (RTree.pre e) = some t' := hp
      cases ht : pruneT t with
      | some t₀ =>
          rw [ht] at hpeq
          rw [← Option.some.inj hpeq]
          exact ih t₀ ht
      | none =>
          rw [ht] at hpeq
          exact nomatch hpeq

/-- Fully dead trees are call-free. -/
theorem pruneT_none_noCalls {S : Type} (P : S → Prop) :
    ∀ t : RTree S A T, pruneT t = none → CallOnly P t := by
  intro t
  induction t with
  | halt h => intro _; exact True.intro
  | call e s => intro hp; exact nomatch hp
  | br g l r ihl ihr =>
      intro hp
      have hpeq : (match pruneT l, pruneT r with
          | some l', some r' => some (RTree.br g l' r')
          | some l', none => some (.pre (.test g) l')
          | none, some r' => some (.pre (.test (.not g)) r')
          | none, none => none) = none := hp
      cases hl : pruneT l with
      | some l' =>
          cases hr : pruneT r with
          | some r' => rw [hl, hr] at hpeq; exact nomatch hpeq
          | none => rw [hl, hr] at hpeq; exact nomatch hpeq
      | none =>
          cases hr : pruneT r with
          | some r' => rw [hl, hr] at hpeq; exact nomatch hpeq
          | none => exact ⟨ihl hl, ihr hr⟩
  | pre e t ih =>
      intro hp
      have hpeq : (pruneT t).map (RTree.pre e) = none := hp
      cases ht : pruneT t with
      | some t₀ => rw [ht] at hpeq; exact nomatch hpeq
      | none => exact ih ht

/-- The Boolean call check is complete. -/
theorem callsB_of_callOnly {S : Type} [DecidableEq S] (o : S) :
    ∀ t : RTree S A T, CallOnly (fun s => s = o) t →
      callsB o t = true := by
  intro t
  induction t with
  | halt h => intro _; rfl
  | call e s =>
      intro hc
      show decide (s = o) = true
      exact decide_eq_true hc
  | br g l r ihl ihr =>
      intro hc
      show (callsB o l && callsB o r) = true
      rw [ihl hc.1, ihr hc.2]
      rfl
  | pre e t ih => intro hc; exact ih hc

/-- Unselected branches come from the list, unselected. -/
theorem selOthers_sub {S : Type} (sel : BExp T × RTree S A T → Bool) :
    ∀ L : List (BExp T × RTree S A T),
      ∀ b ∈ selOthers sel L, b ∈ L ∧ sel b = false := by
  intro L
  induction L with
  | nil => intro b hb; exact nomatch hb
  | cons q rest ih =>
      intro b hb
      by_cases hq : sel q = true
      · have : selOthers sel (q :: rest) = selOthers sel rest := by
          show (if sel q then _ else _) = _
          rw [hq]
          rfl
        rw [this] at hb
        obtain ⟨h1, h2⟩ := ih b hb
        exact ⟨List.mem_cons_of_mem _ h1, h2⟩
      · have hqf : sel q = false := by
          cases hs : sel q
          · rfl
          · exact absurd hs hq
        have : selOthers sel (q :: rest) = q :: selOthers sel rest := by
          show (if sel q then _ else _) = _
          rw [hqf]
          rfl
        rw [this] at hb
        rcases List.mem_cons.mp hb with h1 | h2
        · rw [h1]
          exact ⟨List.mem_cons_self .., hqf⟩
        · obtain ⟨h3, h4⟩ := ih b h2
          exact ⟨List.mem_cons_of_mem _ h3, h4⟩

#print axioms pairwise_append_left
#print axioms callOnly_pruneT
#print axioms pruneT_haltFree
#print axioms pruneT_none_noCalls
#print axioms callsB_of_callOnly
#print axioms selOthers_sub

/-- Trees with no surviving calls have a halt leaf. -/
theorem pruneT_none_hasHalt {S : Type} :
    ∀ t : RTree S A T, pruneT t = none → haltFreeB t = false := by
  intro t
  induction t with
  | halt h => intro _; rfl
  | call e s => intro hp; exact nomatch hp
  | br g l r ihl ihr =>
      intro hp
      have hpeq : (match pruneT l, pruneT r with
          | some l', some r' => some (RTree.br g l' r')
          | some l', none => some (.pre (.test g) l')
          | none, some r' => some (.pre (.test (.not g)) r')
          | none, none => none) = none := hp
      cases hl : pruneT l with
      | some l' =>
          cases hr : pruneT r with
          | some r' => rw [hl, hr] at hpeq; exact nomatch hpeq
          | none => rw [hl, hr] at hpeq; exact nomatch hpeq
      | none =>
          show (haltFreeB l && haltFreeB r) = false
          rw [ihl hl]
          rfl
  | pre e t ih =>
      intro hp
      have hpeq : (pruneT t).map (RTree.pre e) = none := hp
      cases ht : pruneT t with
      | some t₀ => rw [ht] at hpeq; exact nomatch hpeq
      | none => exact ih ht

/-! ## THE SCC CONSTRUCTOR

    One rank class = a DAG-with-self-loops of interiors plus a single
    exit port.  Interiors close forest-style; the port closes through
    the full pipeline: cascade → prune → gather → factor → Salomaa. -/

open Classical in
/-- The interior schedule of an SCC. -/
noncomputable def sccIntSteps {S : Type} (aut : GAut S A T)
    (ints : List S) : List (S × RTree S A T) :=
  ints.map (fun s => (s, ssTree aut s))

open Classical in
/-- The port's cascaded branches. -/
noncomputable def sccCasc {S : Type} [DecidableEq S] (aut : GAut S A T)
    (ints : List S) (o : S) : List (BExp T × RTree S A T) :=
  (aut.trans o).map (fun e =>
    (e.1, stepSubst (sccIntSteps aut ints) (.call (.act e.2.1) e.2.2)))

/-- The selection: port-reaching, halt-free branches. -/
def sccSel {S : Type} [DecidableEq S] (o : S) :
    BExp T × RTree S A T → Bool :=
  fun b => callsB o b.2 && haltFreeB b.2

open Classical in
/-- The port's closed tree. -/
noncomputable def sccPortTree {S : Type} [DecidableEq S]
    (aut : GAut S A T) (ints : List S) (o : S) : RTree S A T :=
  .pre (.wh (selGuard (sccSel o) ((sccCasc aut ints o).map pruneBranch))
      (selBody (sccSel o) ((sccCasc aut ints o).map pruneBranch)))
    (chainT (aut.hlt o)
      (selOthers (sccSel o) ((sccCasc aut ints o).map pruneBranch)))

open Classical in
/-- **THE SCC CONSTRUCTOR**: interiors (self ∨ later ∨ port, empty
    halts) plus a single port (interiors ∨ self ∨ descent) yield a
    certified rank-class schedule. -/
theorem scc_rank_sched {S : Type} [DecidableEq S]
    (aut : GAut S A T) (rank : S → Nat) (r : Nat)
    (ints : List S) (o : S)
    (hpair : (ints ++ [o]).Pairwise (· ≠ ·))
    (hrankAll : ∀ s ∈ ints ++ [o], rank s = r)
    (hint : ∀ (L₁ : List S) (s : S) (L₂ : List S),
      ints = L₁ ++ s :: L₂ → ∀ e ∈ aut.trans s,
        e.2.2 = s ∨ e.2.2 ∈ L₂ ∨ e.2.2 = o)
    (hhlt : ∀ s ∈ ints, GuardEmpty (aut.hlt s))
    (hport : ∀ e ∈ aut.trans o,
      e.2.2 ∈ ints ∨ e.2.2 = o ∨ rank e.2.2 < r) :
    Supp (fun t => rank t < r)
        (sccIntSteps aut ints ++ [(o, sccPortTree aut ints o)])
      ∧ SchedOk (treeOf aut) []
          (sccIntSteps aut ints ++ [(o, sccPortTree aut ints o)])
      ∧ (∀ p ∈ sccIntSteps aut ints ++ [(o, sccPortTree aut ints o)],
          rank p.1 = r)
      ∧ (∀ s ∈ ints ++ [o], ∃ C,
          (s, C) ∈ sccIntSteps aut ints
            ++ [(o, sccPortTree aut ints o)]) := by
  have hcross : ∀ a ∈ ints, a ≠ o := fun a ha =>
    (pairwise_append_parts ints [o] hpair).1 a ha o
      (List.mem_cons_self ..)
  have hpairInts : ints.Pairwise (· ≠ ·) :=
    pairwise_append_left ints [o] hpair
  have hrankInts : ∀ s ∈ ints, rank s = r := fun s hs =>
    hrankAll s (List.mem_append.mpr (Or.inl hs))
  have hranko : rank o = r :=
    hrankAll o (List.mem_append.mpr (Or.inr (List.mem_cons_self ..)))
  -- interior closed trees: dead halts, support toward {o}
  have hintDead : ∀ p ∈ sccIntSteps aut ints, DeadHalts p.2 := by
    intro p hp
    obtain ⟨s, hsL, hpe⟩ := List.mem_map.mp hp
    rw [← hpe]
    exact ssTree_deadHalts aut s (hhlt s hsL)
  have hsuppO : ∀ (L₂ L₁ : List S), ints = L₁ ++ L₂ →
      Supp (fun t => t = o)
        (L₂.map (fun s => (s, ssTree aut s))) := by
    intro L₂
    induction L₂ with
    | nil => intro _ _; exact Supp.nil
    | cons s L₂' ih =>
        intro L₁ hL
        have hparts := pairwise_append_parts L₁ (s :: L₂')
          (hL ▸ hpairInts)
        cases hparts.2 with
        | cons hhead htail =>
            refine Supp.cons s (ssTree aut s) _ ?_ ?_ ?_
              (ih (L₁ ++ [s]) (by rw [hL, List.append_assoc]; rfl))
            · show CallOnly _
                (armChain (gOthers s (aut.trans s)) (aut.hlt s))
              refine callOnly_armChain _ _ _ ?_
              intro e he
              obtain ⟨heL, hne⟩ := gOthers_sub s (aut.trans s) e he
              rcases hint L₁ s L₂' hL e heL with h1 | h2 | h3
              · exact absurd h1 hne
              · exact Or.inl ⟨(e.2.2, ssTree aut e.2.2),
                  List.mem_map.mpr ⟨e.2.2, h2, rfl⟩, rfl⟩
              · exact Or.inr h3
            · intro q hq
              obtain ⟨t, htL, hqe⟩ := List.mem_map.mp hq
              rw [← hqe]
              exact hhead t htL
            · exact hcross s (hL ▸ List.mem_append.mpr
                (Or.inr (List.mem_cons_self ..)))
  have hsuppOInts := hsuppO ints [] rfl
  -- branch classification
  have hbranchCO : ∀ e ∈ aut.trans o,
      (e.2.2 ∈ ints ∨ e.2.2 = o) →
      CallOnly (fun t => t = o)
        (stepSubst (sccIntSteps aut ints)
          (.call (.act e.2.1) e.2.2)) := by
    intro e _ hcase
    refine stepSubst_callOnly (sccIntSteps aut ints) hsuppOInts _ ?_
    show (∃ q ∈ sccIntSteps aut ints, e.2.2 = q.1) ∨ e.2.2 = o
    rcases hcase with h1 | h2
    · exact Or.inl ⟨(e.2.2, ssTree aut e.2.2),
        List.mem_map.mpr ⟨e.2.2, h1, rfl⟩, rfl⟩
    · exact Or.inr h2
  have hbranchLow : ∀ e ∈ aut.trans o, rank e.2.2 < r →
      stepSubst (sccIntSteps aut ints)
          (.call (.act e.2.1) e.2.2)
        = .call (.act e.2.1) e.2.2 := by
    intro e _ hlow
    refine stepSubst_noop _ _ ?_
    show CallOnly _ (RTree.call (.act e.2.1) e.2.2)
    intro p hp
    obtain ⟨s, hsL, hpe⟩ := List.mem_map.mp hp
    rw [← hpe]
    intro hc
    rw [hc] at hlow
    rw [hrankInts s hsL] at hlow
    omega
  have hcascDead : ∀ b ∈ sccCasc aut ints o, DeadHalts b.2 := by
    intro b hb
    obtain ⟨e, heL, hbe⟩ := List.mem_map.mp hb
    rw [← hbe]
    exact stepSubst_deadHalts (sccIntSteps aut ints) hintDead _
      True.intro
  have hselAll : ∀ b ∈ (sccCasc aut ints o).map pruneBranch,
      sccSel o b = true → AllCalls o b.2 := by
    intro b _ hs
    have hs' := Bool.and_eq_true_iff.mp hs
    exact allCalls_of_bools o b.2 hs'.1 hs'.2
  have hothersCO : ∀ b ∈ selOthers (sccSel o)
      ((sccCasc aut ints o).map pruneBranch),
      CallOnly (fun t => rank t < r) b.2 := by
    intro b hb
    obtain ⟨hbin, hbsel⟩ := selOthers_sub (sccSel o) _ b hb
    obtain ⟨b₀, hb₀, hbe⟩ := List.mem_map.mp hbin
    obtain ⟨e, heL, hb₀e⟩ := List.mem_map.mp hb₀
    rcases hport e heL with h1 | h2 | h3
    · -- interior branch: selected or dead
      have hco : CallOnly (fun t => t = o) b₀.2 := by
        rw [← hb₀e]
        exact hbranchCO e heL (Or.inl h1)
      cases hpr : pruneT b₀.2 with
      | some t' =>
          exfalso
          have hbr : pruneBranch b₀ = (b₀.1, t') := by
            show (match pruneT b₀.2 with
              | some t' => (b₀.1, t') | none => b₀) = _
            rw [hpr]
          rw [hbr] at hbe
          have hsel : sccSel o b = true := by
            rw [← hbe]
            show (callsB o t' && haltFreeB t') = true
            rw [callsB_of_callOnly o t'
              (callOnly_pruneT b₀.2 t' hco hpr),
              pruneT_haltFree b₀.2 t' hpr]
            rfl
          rw [hsel] at hbsel
          exact nomatch hbsel
      | none =>
          have hbr : pruneBranch b₀ = b₀ := by
            show (match pruneT b₀.2 with
              | some t' => (b₀.1, t') | none => b₀) = _
            rw [hpr]
          rw [hbr] at hbe
          rw [← hbe]
          exact pruneT_none_noCalls _ b₀.2 hpr
    · -- self branch: always selected (contradiction)
      exfalso
      have hnoop : b₀.2 = .call (.act e.2.1) o := by
        rw [← hb₀e]
        show stepSubst (sccIntSteps aut ints)
          (.call (.act e.2.1) e.2.2) = _
        rw [h2]
        refine stepSubst_noop _ _ ?_
        show CallOnly _ (RTree.call (.act e.2.1) o)
        intro p hp
        obtain ⟨s, hsL, hpe⟩ := List.mem_map.mp hp
        rw [← hpe]
        exact fun hc => (hcross s hsL) hc.symm
      have hbr : pruneBranch b₀ = b₀ := by
        show (match pruneT b₀.2 with
          | some t' => (b₀.1, t') | none => b₀) = _
        rw [hnoop]
        show (b₀.1, RTree.call (.act e.2.1) o) = b₀
        rw [← hnoop]
      rw [hbr] at hbe
      have hsel : sccSel o b = true := by
        rw [← hbe]
        show (callsB o b₀.2 && haltFreeB b₀.2) = true
        rw [hnoop]
        show (decide (o = o) && true) = true
        rw [decide_eq_true rfl]
        rfl
      rw [hsel] at hbsel
      exact nomatch hbsel
    · -- descent branch
      have hnoop : b₀.2 = .call (.act e.2.1) e.2.2 := by
        rw [← hb₀e]
        exact hbranchLow e heL h3
      have hbr : pruneBranch b₀ = b₀ := by
        show (match pruneT b₀.2 with
          | some t' => (b₀.1, t') | none => b₀) = _
        rw [hnoop]
        show (b₀.1, RTree.call (.act e.2.1) e.2.2) = b₀
        rw [← hnoop]
      rw [hbr] at hbe
      rw [← hbe, hnoop]
      exact h3
  refine ⟨?_, ?_, ?_, ?_⟩
  · -- Supp
    have haux : ∀ (L₂ L₁ : List S), ints = L₁ ++ L₂ →
        Supp (fun t => rank t < r)
          ((L₂.map (fun s => (s, ssTree aut s)))
            ++ [(o, sccPortTree aut ints o)]) := by
      intro L₂
      induction L₂ with
      | nil =>
          intro _ _
          refine Supp.cons o (sccPortTree aut ints o) [] ?_ ?_ ?_
            Supp.nil
          · show CallOnly _ (chainT (aut.hlt o)
              (selOthers (sccSel o)
                ((sccCasc aut ints o).map pruneBranch)))
            have hchain : ∀ (L : List (BExp T × RTree S A T)),
                (∀ b ∈ L, CallOnly (fun t => rank t < r) b.2) →
                CallOnly (fun t => (∃ q ∈ ([] :
                    List (S × RTree S A T)), t = q.1)
                  ∨ rank t < r) (chainT (aut.hlt o) L) := by
              intro L
              induction L with
              | nil => intro _; exact True.intro
              | cons b rest ihc =>
                  intro hall
                  exact ⟨callOnly_mono (fun t ht => Or.inr ht) _
                    (hall b (List.mem_cons_self ..)),
                    ihc (fun q hq => hall q
                      (List.mem_cons_of_mem _ hq))⟩
            exact hchain _ hothersCO
          · intro q hq
            exact nomatch hq
          · rw [hranko]
            omega
      | cons s L₂' ih =>
          intro L₁ hL
          have hparts := pairwise_append_parts L₁ (s :: L₂')
            (hL ▸ hpairInts)
          cases hparts.2 with
          | cons hhead htail =>
              refine Supp.cons s (ssTree aut s) _ ?_ ?_ ?_
                (ih (L₁ ++ [s]) (by rw [hL, List.append_assoc]; rfl))
              · show CallOnly _
                  (armChain (gOthers s (aut.trans s)) (aut.hlt s))
                refine callOnly_armChain _ _ _ ?_
                intro e he
                obtain ⟨heL, hne⟩ := gOthers_sub s (aut.trans s) e he
                rcases hint L₁ s L₂' hL e heL with h1 | h2 | h3
                · exact absurd h1 hne
                · exact Or.inl ⟨(e.2.2, ssTree aut e.2.2),
                    List.mem_append.mpr (Or.inl
                      (List.mem_map.mpr ⟨e.2.2, h2, rfl⟩)), rfl⟩
                · exact Or.inl ⟨(o, sccPortTree aut ints o),
                    List.mem_append.mpr (Or.inr
                      (List.mem_cons_self ..)), h3⟩
              · intro q hq
                rcases List.mem_append.mp hq with h1 | h2
                · obtain ⟨t, htL, hqe⟩ := List.mem_map.mp h1
                  rw [← hqe]
                  exact hhead t htL
                · rcases List.mem_cons.mp h2 with h3 | h4
                  · rw [h3]
                    exact hcross s (hL ▸ List.mem_append.mpr
                      (Or.inr (List.mem_cons_self ..)))
                  · exact nomatch h4
              · rw [hrankInts s (hL ▸ List.mem_append.mpr
                  (Or.inr (List.mem_cons_self ..)))]
                omega
    exact haux ints [] rfl
  · -- SchedOk
    have haux : ∀ (L₂ L₁ : List S), ints = L₁ ++ L₂ →
        SchedOk (treeOf aut)
          (L₁.map (fun s => (s, ssTree aut s)))
          ((L₂.map (fun s => (s, ssTree aut s)))
            ++ [(o, sccPortTree aut ints o)]) := by
      intro L₂
      induction L₂ with
      | nil =>
          intro L₁ hL
          have hL₁ : L₁ = ints := by rw [hL, List.append_nil]
          rw [hL₁]
          refine ⟨?_, True.intro⟩
          refine Or.inl ⟨selGuard (sccSel o)
              ((sccCasc aut ints o).map pruneBranch),
            .call (selBody (sccSel o)
              ((sccCasc aut ints o).map pruneBranch)) o,
            chainT (aut.hlt o) (selOthers (sccSel o)
              ((sccCasc aut ints o).map pruneBranch)),
            ?_, rfl, rfl⟩
          intro sol
          show EquivBA (resolveT sol (stepSubst
            (sccIntSteps aut ints) (treeOf aut o))) _
          rw [treeOf_chainT, stepSubst_chainT, List.map_map]
          have hcomp : ((aut.trans o).map
              ((fun b => (b.1, stepSubst (sccIntSteps aut ints) b.2))
                ∘ (fun e => (e.1, RTree.call (.act e.2.1) e.2.2))))
              = sccCasc aut ints o := rfl
          rw [hcomp]
          refine EquivBA.trans (chain_prune_congr sol (aut.hlt o)
            (sccCasc aut ints o) hcascDead) ?_
          exact port_gather sol o (sccSel o) (aut.hlt o)
            ((sccCasc aut ints o).map pruneBranch) hselAll
      | cons s L₂' ih =>
          intro L₁ hL
          have hparts := pairwise_append_parts L₁ (s :: L₂')
            (hL ▸ hpairInts)
          have hnoop : stepSubst
              (L₁.map (fun t => (t, ssTree aut t)))
              (treeOf aut s) = treeOf aut s := by
            refine stepSubst_noop _ _ ?_
            refine callOnly_treeOf aut _ s ?_
            intro e he q hq
            obtain ⟨t, htL, hqe⟩ := List.mem_map.mp hq
            rcases hint L₁ s L₂' hL e he with h1 | h2 | h3
            · rw [h1, ← hqe]
              exact fun hc => (hparts.1 t htL s
                (List.mem_cons_self ..)) hc.symm
            · rw [← hqe]
              exact fun hc => (hparts.1 t htL e.2.2
                (List.mem_cons_of_mem _ h2)) hc.symm
            · rw [h3, ← hqe]
              exact fun hc => (hcross t (hL ▸ List.mem_append.mpr
                (Or.inl htL))) hc.symm
          constructor
          · refine Or.inl ⟨gGuard s (aut.trans s),
              .call (gBody s (aut.trans s)) s,
              armChain (gOthers s (aut.trans s)) (aut.hlt s),
              ?_, rfl, rfl⟩
            intro sol
            rw [hnoop, resolve_treeOf, eqRHS_foldTL]
            show EquivBA _ (Exp.ite (gGuard s (aut.trans s))
              (.seq (gBody s (aut.trans s)) (sol s))
              (resolveT sol (armChain (gOthers s (aut.trans s))
                (aut.hlt s))))
            rw [resolve_armChain]
            exact multi_gather sol (aut.hlt s) s (aut.trans s)
          · have hres := ih (L₁ ++ [s])
              (by rw [hL, List.append_assoc]; rfl)
            show SchedOk (treeOf aut)
              ((L₁.map (fun t => (t, ssTree aut t)))
                ++ [(s, ssTree aut s)]) _
            have hmap : (L₁.map (fun t => (t, ssTree aut t)))
                ++ [(s, ssTree aut s)]
              = (L₁ ++ [s]).map (fun t => (t, ssTree aut t)) := by
              rw [List.map_append]
              rfl
            rw [hmap]
            exact hres
    exact haux ints [] rfl
  · -- hrank
    intro p hp
    rcases List.mem_append.mp hp with h1 | h2
    · obtain ⟨t, htL, hpe⟩ := List.mem_map.mp h1
      rw [← hpe]
      exact hrankInts t htL
    · rcases List.mem_cons.mp h2 with h3 | h4
      · rw [h3]
        exact hranko
      · exact nomatch h4
  · -- coverage
    intro s hs
    rcases List.mem_append.mp hs with h1 | h2
    · exact ⟨ssTree aut s, List.mem_append.mpr (Or.inl
        (List.mem_map.mpr ⟨s, h1, rfl⟩))⟩
    · rcases List.mem_cons.mp h2 with h3 | h4
      · rw [h3]
        exact ⟨sccPortTree aut ints o, List.mem_append.mpr
          (Or.inr (List.mem_cons_self ..))⟩
      · exact nomatch h4

#print axioms pruneT_none_hasHalt
#print axioms scc_rank_sched

/-! ## Composition and the general port step

    Nested sub-SCCs are handled compositionally: schedules concatenate
    (`Supp_append`, `SchedOk_append`), and a port can close over ANY
    certified prefix — not just forest interiors — via
    `port_step_sched`.  Hierarchy = inner schedules composed under
    outer ports. -/

/-- Schedule elements are off the external support. -/
theorem supp_not_P {S : Type} {P : S → Prop} :
    ∀ steps : List (S × RTree S A T), Supp P steps →
      ∀ p ∈ steps, ¬ P p.1 := by
  intro steps
  induction steps with
  | nil => intro _ p hp; exact nomatch hp
  | cons hd rest ih =>
      intro hs p hp
      cases hs with
      | cons u C _ hC hne hP hrest =>
          rcases List.mem_cons.mp hp with h1 | h2
          · rw [h1]
            exact hP
          · exact ih hrest p h2

/-- Support certificates compose across concatenation. -/
theorem Supp_append {S : Type} {P : S → Prop} :
    ∀ steps₁ steps₂ : List (S × RTree S A T),
      Supp (fun t => (∃ q ∈ steps₂, t = q.1) ∨ P t) steps₁ →
      Supp P steps₂ →
      Supp P (steps₁ ++ steps₂) := by
  intro steps₁
  induction steps₁ with
  | nil => intro steps₂ _ h₂; exact h₂
  | cons hd rest ih =>
      intro steps₂ h₁ h₂
      cases h₁ with
      | cons u C _ hC hne hP hrest =>
          refine Supp.cons u C _ ?_ ?_ ?_ (ih steps₂ hrest h₂)
          · refine callOnly_mono ?_ _ hC
            intro s hs
            rcases hs with ⟨q, hq, hsq⟩ | h2
            · exact Or.inl ⟨q, List.mem_append.mpr (Or.inl hq), hsq⟩
            · rcases h2 with ⟨q, hq, hsq⟩ | hPs
              · exact Or.inl ⟨q,
                  List.mem_append.mpr (Or.inr hq), hsq⟩
              · exact Or.inr hPs
          · intro q hq
            rcases List.mem_append.mp hq with h1 | h2
            · exact hne q h1
            · intro hc
              exact hP (Or.inl ⟨q, h2, hc⟩)
          · intro hPu
            exact hP (Or.inr hPu)

/-- Closing certificates compose across concatenation. -/
theorem SchedOk_append {S : Type} [DecidableEq S]
    (sys : S → RTree S A T) :
    ∀ (steps₁ steps₂ pre : List (S × RTree S A T)),
      SchedOk sys pre steps₁ →
      SchedOk sys (pre ++ steps₁) steps₂ →
      SchedOk sys pre (steps₁ ++ steps₂) := by
  intro steps₁
  induction steps₁ with
  | nil =>
      intro steps₂ pre _ h₂
      rw [List.append_nil] at h₂
      exact h₂
  | cons hd rest ih =>
      intro steps₂ pre h₁ h₂
      obtain ⟨hclause, hrest⟩ := h₁
      refine ⟨hclause, ?_⟩
      refine ih steps₂ (pre ++ [hd]) hrest ?_
      show SchedOk sys ((pre ++ [hd]) ++ rest) steps₂
      rw [List.append_assoc]
      exact h₂

open Classical in
/-- The port's cascaded branches over an arbitrary prefix. -/
noncomputable def genCasc {S : Type} [DecidableEq S] (aut : GAut S A T)
    (steps : List (S × RTree S A T)) (o : S) :
    List (BExp T × RTree S A T) :=
  (aut.trans o).map (fun e =>
    (e.1, stepSubst steps (.call (.act e.2.1) e.2.2)))

open Classical in
/-- The port's closed tree over an arbitrary prefix. -/
noncomputable def genPortTree {S : Type} [DecidableEq S]
    (aut : GAut S A T) (steps : List (S × RTree S A T)) (o : S) :
    RTree S A T :=
  .pre (.wh (selGuard (sccSel o) ((genCasc aut steps o).map pruneBranch))
      (selBody (sccSel o) ((genCasc aut steps o).map pruneBranch)))
    (chainT (aut.hlt o)
      (selOthers (sccSel o) ((genCasc aut steps o).map pruneBranch)))

open Classical in
/-- **THE GENERAL PORT STEP**: a port closes over ANY certified,
    dead-halted, port-supported prefix. -/
theorem port_step_sched {S : Type} [DecidableEq S]
    (aut : GAut S A T) (rank : S → Nat) (r : Nat)
    (steps : List (S × RTree S A T)) (o : S)
    (hsuppO : Supp (fun t => t = o) steps)
    (hdead : ∀ p ∈ steps, DeadHalts p.2)
    (hpre_rank : ∀ p ∈ steps, rank p.1 = r)
    (hranko : rank o = r)
    (hport : ∀ e ∈ aut.trans o,
      (∃ q ∈ steps, e.2.2 = q.1) ∨ e.2.2 = o ∨ rank e.2.2 < r) :
    Supp (fun t => rank t < r) [(o, genPortTree aut steps o)]
      ∧ SchedOk (treeOf aut) steps [(o, genPortTree aut steps o)] := by
  have hnoto : ∀ p ∈ steps, p.1 ≠ o := supp_not_P steps hsuppO
  have hbranchCO : ∀ e ∈ aut.trans o,
      ((∃ q ∈ steps, e.2.2 = q.1) ∨ e.2.2 = o) →
      CallOnly (fun t => t = o)
        (stepSubst steps (.call (.act e.2.1) e.2.2)) := by
    intro e _ hcase
    refine stepSubst_callOnly steps hsuppO _ ?_
    show (∃ q ∈ steps, e.2.2 = q.1) ∨ e.2.2 = o
    exact hcase
  have hbranchLow : ∀ e ∈ aut.trans o, rank e.2.2 < r →
      stepSubst steps (.call (.act e.2.1) e.2.2)
        = .call (.act e.2.1) e.2.2 := by
    intro e _ hlow
    refine stepSubst_noop _ _ ?_
    show CallOnly _ (RTree.call (.act e.2.1) e.2.2)
    intro p hp hc
    rw [hc, hpre_rank p hp] at hlow
    omega
  have hcascDead : ∀ b ∈ genCasc aut steps o, DeadHalts b.2 := by
    intro b hb
    obtain ⟨e, heL, hbe⟩ := List.mem_map.mp hb
    rw [← hbe]
    exact stepSubst_deadHalts steps hdead _ True.intro
  have hselAll : ∀ b ∈ (genCasc aut steps o).map pruneBranch,
      sccSel o b = true → AllCalls o b.2 := by
    intro b _ hs
    have hs' := Bool.and_eq_true_iff.mp hs
    exact allCalls_of_bools o b.2 hs'.1 hs'.2
  have hothersCO : ∀ b ∈ selOthers (sccSel o)
      ((genCasc aut steps o).map pruneBranch),
      CallOnly (fun t => rank t < r) b.2 := by
    intro b hb
    obtain ⟨hbin, hbsel⟩ := selOthers_sub (sccSel o) _ b hb
    obtain ⟨b₀, hb₀, hbe⟩ := List.mem_map.mp hbin
    obtain ⟨e, heL, hb₀e⟩ := List.mem_map.mp hb₀
    rcases hport e heL with h1 | h2 | h3
    · have hco : CallOnly (fun t => t = o) b₀.2 := by
        rw [← hb₀e]
        exact hbranchCO e heL (Or.inl h1)
      cases hpr : pruneT b₀.2 with
      | some t' =>
          exfalso
          have hbr : pruneBranch b₀ = (b₀.1, t') := by
            show (match pruneT b₀.2 with
              | some t' => (b₀.1, t') | none => b₀) = _
            rw [hpr]
          rw [hbr] at hbe
          have hsel : sccSel o b = true := by
            rw [← hbe]
            show (callsB o t' && haltFreeB t') = true
            rw [callsB_of_callOnly o t'
              (callOnly_pruneT b₀.2 t' hco hpr),
              pruneT_haltFree b₀.2 t' hpr]
            rfl
          rw [hsel] at hbsel
          exact nomatch hbsel
      | none =>
          have hbr : pruneBranch b₀ = b₀ := by
            show (match pruneT b₀.2 with
              | some t' => (b₀.1, t') | none => b₀) = _
            rw [hpr]
          rw [hbr] at hbe
          rw [← hbe]
          exact pruneT_none_noCalls _ b₀.2 hpr
    · exfalso
      have hnoop : b₀.2 = .call (.act e.2.1) o := by
        rw [← hb₀e]
        show stepSubst steps (.call (.act e.2.1) e.2.2) = _
        rw [h2]
        refine stepSubst_noop _ _ ?_
        show CallOnly _ (RTree.call (.act e.2.1) o)
        intro p hp hc
        exact (hnoto p hp) hc.symm
      have hbr : pruneBranch b₀ = b₀ := by
        show (match pruneT b₀.2 with
          | some t' => (b₀.1, t') | none => b₀) = _
        rw [hnoop]
        show (b₀.1, RTree.call (.act e.2.1) o) = b₀
        rw [← hnoop]
      rw [hbr] at hbe
      have hsel : sccSel o b = true := by
        rw [← hbe]
        show (callsB o b₀.2 && haltFreeB b₀.2) = true
        rw [hnoop]
        show (decide (o = o) && true) = true
        rw [decide_eq_true rfl]
        rfl
      rw [hsel] at hbsel
      exact nomatch hbsel
    · have hnoop : b₀.2 = .call (.act e.2.1) e.2.2 := by
        rw [← hb₀e]
        exact hbranchLow e heL h3
      have hbr : pruneBranch b₀ = b₀ := by
        show (match pruneT b₀.2 with
          | some t' => (b₀.1, t') | none => b₀) = _
        rw [hnoop]
        show (b₀.1, RTree.call (.act e.2.1) e.2.2) = b₀
        rw [← hnoop]
      rw [hbr] at hbe
      rw [← hbe, hnoop]
      exact h3
  constructor
  · refine Supp.cons o (genPortTree aut steps o) [] ?_ ?_ ?_ Supp.nil
    · show CallOnly _ (chainT (aut.hlt o)
        (selOthers (sccSel o) ((genCasc aut steps o).map pruneBranch)))
      have hchain : ∀ (L : List (BExp T × RTree S A T)),
          (∀ b ∈ L, CallOnly (fun t => rank t < r) b.2) →
          CallOnly (fun t => (∃ q ∈ ([] :
              List (S × RTree S A T)), t = q.1)
            ∨ rank t < r) (chainT (aut.hlt o) L) := by
        intro L
        induction L with
        | nil => intro _; exact True.intro
        | cons b rest ihc =>
            intro hall
            exact ⟨callOnly_mono (fun t ht => Or.inr ht) _
              (hall b (List.mem_cons_self ..)),
              ihc (fun q hq => hall q (List.mem_cons_of_mem _ hq))⟩
      exact hchain _ hothersCO
    · intro q hq
      exact nomatch hq
    · rw [hranko]
      omega
  · refine ⟨?_, True.intro⟩
    refine Or.inl ⟨selGuard (sccSel o)
        ((genCasc aut steps o).map pruneBranch),
      .call (selBody (sccSel o)
        ((genCasc aut steps o).map pruneBranch)) o,
      chainT (aut.hlt o) (selOthers (sccSel o)
        ((genCasc aut steps o).map pruneBranch)),
      ?_, rfl, rfl⟩
    intro sol
    show EquivBA (resolveT sol (stepSubst steps (treeOf aut o))) _
    rw [treeOf_chainT, stepSubst_chainT, List.map_map]
    have hcomp : ((aut.trans o).map
        ((fun b => (b.1, stepSubst steps b.2))
          ∘ (fun e => (e.1, RTree.call (.act e.2.1) e.2.2))))
        = genCasc aut steps o := rfl
    rw [hcomp]
    refine EquivBA.trans (chain_prune_congr sol (aut.hlt o)
      (genCasc aut steps o) hcascDead) ?_
    exact port_gather sol o (sccSel o) (aut.hlt o)
      ((genCasc aut steps o).map pruneBranch) hselAll

#print axioms supp_not_P
#print axioms Supp_append
#print axioms SchedOk_append
#print axioms port_step_sched

open Classical in
/-- **THE GENERAL PORT STEP, ABSTRACT SUPPORT**: as `port_step_sched`
    with an arbitrary external support `P` in place of lower ranks —
    the form that lets same-rank SCC blocks compose. -/
theorem port_step_schedP {S : Type} [DecidableEq S]
    (aut : GAut S A T) (P : S → Prop)
    (steps : List (S × RTree S A T)) (o : S)
    (hsuppO : Supp (fun t => t = o) steps)
    (hdead : ∀ p ∈ steps, DeadHalts p.2)
    (hPdisj : ∀ p ∈ steps, ¬ P p.1)
    (hPo : ¬ P o)
    (hport : ∀ e ∈ aut.trans o,
      (∃ q ∈ steps, e.2.2 = q.1) ∨ e.2.2 = o ∨ P e.2.2) :
    Supp P [(o, genPortTree aut steps o)]
      ∧ SchedOk (treeOf aut) steps [(o, genPortTree aut steps o)] := by
  have hnoto : ∀ p ∈ steps, p.1 ≠ o := supp_not_P steps hsuppO
  have hbranchCO : ∀ e ∈ aut.trans o,
      ((∃ q ∈ steps, e.2.2 = q.1) ∨ e.2.2 = o) →
      CallOnly (fun t => t = o)
        (stepSubst steps (.call (.act e.2.1) e.2.2)) := by
    intro e _ hcase
    refine stepSubst_callOnly steps hsuppO _ ?_
    show (∃ q ∈ steps, e.2.2 = q.1) ∨ e.2.2 = o
    exact hcase
  have hbranchLow : ∀ e ∈ aut.trans o, P e.2.2 →
      stepSubst steps (.call (.act e.2.1) e.2.2)
        = .call (.act e.2.1) e.2.2 := by
    intro e _ hlow
    refine stepSubst_noop _ _ ?_
    show CallOnly _ (RTree.call (.act e.2.1) e.2.2)
    intro p hp hc
    rw [hc] at hlow
    exact hPdisj p hp hlow
  have hcascDead : ∀ b ∈ genCasc aut steps o, DeadHalts b.2 := by
    intro b hb
    obtain ⟨e, heL, hbe⟩ := List.mem_map.mp hb
    rw [← hbe]
    exact stepSubst_deadHalts steps hdead _ True.intro
  have hselAll : ∀ b ∈ (genCasc aut steps o).map pruneBranch,
      sccSel o b = true → AllCalls o b.2 := by
    intro b _ hs
    have hs' := Bool.and_eq_true_iff.mp hs
    exact allCalls_of_bools o b.2 hs'.1 hs'.2
  have hothersCO : ∀ b ∈ selOthers (sccSel o)
      ((genCasc aut steps o).map pruneBranch),
      CallOnly P b.2 := by
    intro b hb
    obtain ⟨hbin, hbsel⟩ := selOthers_sub (sccSel o) _ b hb
    obtain ⟨b₀, hb₀, hbe⟩ := List.mem_map.mp hbin
    obtain ⟨e, heL, hb₀e⟩ := List.mem_map.mp hb₀
    rcases hport e heL with h1 | h2 | h3
    · have hco : CallOnly (fun t => t = o) b₀.2 := by
        rw [← hb₀e]
        exact hbranchCO e heL (Or.inl h1)
      cases hpr : pruneT b₀.2 with
      | some t' =>
          exfalso
          have hbr : pruneBranch b₀ = (b₀.1, t') := by
            show (match pruneT b₀.2 with
              | some t' => (b₀.1, t') | none => b₀) = _
            rw [hpr]
          rw [hbr] at hbe
          have hsel : sccSel o b = true := by
            rw [← hbe]
            show (callsB o t' && haltFreeB t') = true
            rw [callsB_of_callOnly o t'
              (callOnly_pruneT b₀.2 t' hco hpr),
              pruneT_haltFree b₀.2 t' hpr]
            rfl
          rw [hsel] at hbsel
          exact nomatch hbsel
      | none =>
          have hbr : pruneBranch b₀ = b₀ := by
            show (match pruneT b₀.2 with
              | some t' => (b₀.1, t') | none => b₀) = _
            rw [hpr]
          rw [hbr] at hbe
          rw [← hbe]
          exact pruneT_none_noCalls _ b₀.2 hpr
    · exfalso
      have hnoop : b₀.2 = .call (.act e.2.1) o := by
        rw [← hb₀e]
        show stepSubst steps (.call (.act e.2.1) e.2.2) = _
        rw [h2]
        refine stepSubst_noop _ _ ?_
        show CallOnly _ (RTree.call (.act e.2.1) o)
        intro p hp hc
        exact (hnoto p hp) hc.symm
      have hbr : pruneBranch b₀ = b₀ := by
        show (match pruneT b₀.2 with
          | some t' => (b₀.1, t') | none => b₀) = _
        rw [hnoop]
        show (b₀.1, RTree.call (.act e.2.1) o) = b₀
        rw [← hnoop]
      rw [hbr] at hbe
      have hsel : sccSel o b = true := by
        rw [← hbe]
        show (callsB o b₀.2 && haltFreeB b₀.2) = true
        rw [hnoop]
        show (decide (o = o) && true) = true
        rw [decide_eq_true rfl]
        rfl
      rw [hsel] at hbsel
      exact nomatch hbsel
    · have hnoop : b₀.2 = .call (.act e.2.1) e.2.2 := by
        rw [← hb₀e]
        exact hbranchLow e heL h3
      have hbr : pruneBranch b₀ = b₀ := by
        show (match pruneT b₀.2 with
          | some t' => (b₀.1, t') | none => b₀) = _
        rw [hnoop]
        show (b₀.1, RTree.call (.act e.2.1) e.2.2) = b₀
        rw [← hnoop]
      rw [hbr] at hbe
      rw [← hbe, hnoop]
      exact h3
  constructor
  · refine Supp.cons o (genPortTree aut steps o) [] ?_ ?_ ?_ Supp.nil
    · show CallOnly _ (chainT (aut.hlt o)
        (selOthers (sccSel o) ((genCasc aut steps o).map pruneBranch)))
      have hchain : ∀ (L : List (BExp T × RTree S A T)),
          (∀ b ∈ L, CallOnly P b.2) →
          CallOnly (fun t => (∃ q ∈ ([] :
              List (S × RTree S A T)), t = q.1)
            ∨ P t) (chainT (aut.hlt o) L) := by
        intro L
        induction L with
        | nil => intro _; exact True.intro
        | cons b rest ihc =>
            intro hall
            exact ⟨callOnly_mono (fun t ht => Or.inr ht) _
              (hall b (List.mem_cons_self ..)),
              ihc (fun q hq => hall q (List.mem_cons_of_mem _ hq))⟩
      exact hchain _ hothersCO
    · intro q hq
      exact nomatch hq
    · exact hPo
  · refine ⟨?_, True.intro⟩
    refine Or.inl ⟨selGuard (sccSel o)
        ((genCasc aut steps o).map pruneBranch),
      .call (selBody (sccSel o)
        ((genCasc aut steps o).map pruneBranch)) o,
      chainT (aut.hlt o) (selOthers (sccSel o)
        ((genCasc aut steps o).map pruneBranch)),
      ?_, rfl, rfl⟩
    intro sol
    show EquivBA (resolveT sol (stepSubst steps (treeOf aut o))) _
    rw [treeOf_chainT, stepSubst_chainT, List.map_map]
    have hcomp : ((aut.trans o).map
        ((fun b => (b.1, stepSubst steps b.2))
          ∘ (fun e => (e.1, RTree.call (.act e.2.1) e.2.2))))
        = genCasc aut steps o := rfl
    rw [hcomp]
    refine EquivBA.trans (chain_prune_congr sol (aut.hlt o)
      (genCasc aut steps o) hcascDead) ?_
    exact port_gather sol o (sccSel o) (aut.hlt o)
      ((genCasc aut steps o).map pruneBranch) hselAll

#print axioms port_step_schedP

/-- Support targets strengthen under implication, given the schedule
    stays off the new support. -/
theorem Supp_target {S : Type} {P Q : S → Prop} :
    ∀ steps : List (S × RTree S A T), Supp P steps →
      (∀ s, P s → Q s) → (∀ p ∈ steps, ¬ Q p.1) →
      Supp Q steps := by
  intro steps
  induction steps with
  | nil => intro _ _ _; exact Supp.nil
  | cons hd rest ih =>
      intro hs hPQ hQdisj
      cases hs with
      | cons u C _ hC hne hP hrest =>
          refine Supp.cons u C _ ?_ hne
            (hQdisj (u, C) (List.mem_cons_self ..))
            (ih hrest hPQ
              (fun p hp => hQdisj p (List.mem_cons_of_mem _ hp)))
          refine callOnly_mono ?_ _ hC
          intro s hs
          rcases hs with ⟨q, hq, hsq⟩ | hPs
          · exact Or.inl ⟨q, hq, hsq⟩
          · exact Or.inr (hPQ s hPs)

open Classical in
/-- The interior prefix supports toward its exit. -/
theorem forest_prefix_supp {S : Type} [DecidableEq S]
    (aut : GAut S A T) (ints : List S) (o : S)
    (hpairInts : ints.Pairwise (· ≠ ·))
    (hcross : ∀ a ∈ ints, a ≠ o)
    (hint : ∀ (L₁ : List S) (s : S) (L₂ : List S),
      ints = L₁ ++ s :: L₂ → ∀ e ∈ aut.trans s,
        e.2.2 = s ∨ e.2.2 ∈ L₂ ∨ e.2.2 = o) :
    Supp (fun t => t = o) (sccIntSteps aut ints) := by
  have haux : ∀ (L₂ L₁ : List S), ints = L₁ ++ L₂ →
      Supp (fun t => t = o)
        (L₂.map (fun s => (s, ssTree aut s))) := by
    intro L₂
    induction L₂ with
    | nil => intro _ _; exact Supp.nil
    | cons s L₂' ih =>
        intro L₁ hL
        have hparts := pairwise_append_parts L₁ (s :: L₂')
          (hL ▸ hpairInts)
        cases hparts.2 with
        | cons hhead htail =>
            refine Supp.cons s (ssTree aut s) _ ?_ ?_ ?_
              (ih (L₁ ++ [s]) (by rw [hL, List.append_assoc]; rfl))
            · show CallOnly _
                (armChain (gOthers s (aut.trans s)) (aut.hlt s))
              refine callOnly_armChain _ _ _ ?_
              intro e he
              obtain ⟨heL, hne⟩ := gOthers_sub s (aut.trans s) e he
              rcases hint L₁ s L₂' hL e heL with h1 | h2 | h3
              · exact absurd h1 hne
              · exact Or.inl ⟨(e.2.2, ssTree aut e.2.2),
                  List.mem_map.mpr ⟨e.2.2, h2, rfl⟩, rfl⟩
              · exact Or.inr h3
            · intro q hq
              obtain ⟨t, htL, hqe⟩ := List.mem_map.mp hq
              rw [← hqe]
              exact hhead t htL
            · exact hcross s (hL ▸ List.mem_append.mpr
                (Or.inr (List.mem_cons_self ..)))
  exact haux ints [] rfl

open Classical in
/-- The interior prefix closes forest-style. -/
theorem forest_prefix_ok {S : Type} [DecidableEq S]
    (aut : GAut S A T) (ints : List S) (o : S)
    (hpairInts : ints.Pairwise (· ≠ ·))
    (hcross : ∀ a ∈ ints, a ≠ o)
    (hint : ∀ (L₁ : List S) (s : S) (L₂ : List S),
      ints = L₁ ++ s :: L₂ → ∀ e ∈ aut.trans s,
        e.2.2 = s ∨ e.2.2 ∈ L₂ ∨ e.2.2 = o) :
    SchedOk (treeOf aut) [] (sccIntSteps aut ints) := by
  have haux : ∀ (L₂ L₁ : List S), ints = L₁ ++ L₂ →
      SchedOk (treeOf aut)
        (L₁.map (fun s => (s, ssTree aut s)))
        (L₂.map (fun s => (s, ssTree aut s))) := by
    intro L₂
    induction L₂ with
    | nil => intro _ _; exact True.intro
    | cons s L₂' ih =>
        intro L₁ hL
        have hparts := pairwise_append_parts L₁ (s :: L₂')
          (hL ▸ hpairInts)
        have hnoop : stepSubst
            (L₁.map (fun t => (t, ssTree aut t)))
            (treeOf aut s) = treeOf aut s := by
          refine stepSubst_noop _ _ ?_
          refine callOnly_treeOf aut _ s ?_
          intro e he q hq
          obtain ⟨t, htL, hqe⟩ := List.mem_map.mp hq
          rcases hint L₁ s L₂' hL e he with h1 | h2 | h3
          · rw [h1, ← hqe]
            exact fun hc => (hparts.1 t htL s
              (List.mem_cons_self ..)) hc.symm
          · rw [← hqe]
            exact fun hc => (hparts.1 t htL e.2.2
              (List.mem_cons_of_mem _ h2)) hc.symm
          · rw [h3, ← hqe]
            exact fun hc => (hcross t (hL ▸ List.mem_append.mpr
              (Or.inl htL))) hc.symm
        constructor
        · refine Or.inl ⟨gGuard s (aut.trans s),
            .call (gBody s (aut.trans s)) s,
            armChain (gOthers s (aut.trans s)) (aut.hlt s),
            ?_, rfl, rfl⟩
          intro sol
          rw [hnoop, resolve_treeOf, eqRHS_foldTL]
          show EquivBA _ (Exp.ite (gGuard s (aut.trans s))
            (.seq (gBody s (aut.trans s)) (sol s))
            (resolveT sol (armChain (gOthers s (aut.trans s))
              (aut.hlt s))))
          rw [resolve_armChain]
          exact multi_gather sol (aut.hlt s) s (aut.trans s)
        · have hres := ih (L₁ ++ [s])
            (by rw [hL, List.append_assoc]; rfl)
          show SchedOk (treeOf aut)
            ((L₁.map (fun t => (t, ssTree aut t)))
              ++ [(s, ssTree aut s)]) _
          have hmap : (L₁.map (fun t => (t, ssTree aut t)))
              ++ [(s, ssTree aut s)]
            = (L₁ ++ [s]).map (fun t => (t, ssTree aut t)) := by
            rw [List.map_append]
            rfl
          rw [hmap]
          exact hres
  exact haux ints [] rfl

open Classical in
/-- **THE BLOCK CONSTRUCTOR**: a single-exit SCC block certified
    against an arbitrary external support — the composable unit for
    multi-SCC rank classes and nesting. -/
theorem scc_block_schedP {S : Type} [DecidableEq S]
    (aut : GAut S A T) (P : S → Prop) (ints : List S) (o : S)
    (hpair : (ints ++ [o]).Pairwise (· ≠ ·))
    (hint : ∀ (L₁ : List S) (s : S) (L₂ : List S),
      ints = L₁ ++ s :: L₂ → ∀ e ∈ aut.trans s,
        e.2.2 = s ∨ e.2.2 ∈ L₂ ∨ e.2.2 = o)
    (hhlt : ∀ s ∈ ints, GuardEmpty (aut.hlt s))
    (hPints : ∀ s ∈ ints, ¬ P s) (hPo : ¬ P o)
    (hport : ∀ e ∈ aut.trans o,
      e.2.2 ∈ ints ∨ e.2.2 = o ∨ P e.2.2) :
    Supp P (sccIntSteps aut ints
        ++ [(o, genPortTree aut (sccIntSteps aut ints) o)])
      ∧ SchedOk (treeOf aut) []
          (sccIntSteps aut ints
            ++ [(o, genPortTree aut (sccIntSteps aut ints) o)]) := by
  have hcross : ∀ a ∈ ints, a ≠ o := fun a ha =>
    (pairwise_append_parts ints [o] hpair).1 a ha o
      (List.mem_cons_self ..)
  have hpairInts : ints.Pairwise (· ≠ ·) :=
    pairwise_append_left ints [o] hpair
  have hsuppO := forest_prefix_supp aut ints o hpairInts hcross hint
  have hintDead : ∀ p ∈ sccIntSteps aut ints, DeadHalts p.2 := by
    intro p hp
    obtain ⟨s, hsL, hpe⟩ := List.mem_map.mp hp
    rw [← hpe]
    exact ssTree_deadHalts aut s (hhlt s hsL)
  have hPdisj : ∀ p ∈ sccIntSteps aut ints, ¬ P p.1 := by
    intro p hp
    obtain ⟨s, hsL, hpe⟩ := List.mem_map.mp hp
    rw [← hpe]
    exact hPints s hsL
  have hport' : ∀ e ∈ aut.trans o,
      (∃ q ∈ sccIntSteps aut ints, e.2.2 = q.1) ∨ e.2.2 = o
        ∨ P e.2.2 := by
    intro e he
    rcases hport e he with h1 | h2 | h3
    · exact Or.inl ⟨(e.2.2, ssTree aut e.2.2),
        List.mem_map.mpr ⟨e.2.2, h1, rfl⟩, rfl⟩
    · exact Or.inr (Or.inl h2)
    · exact Or.inr (Or.inr h3)
  obtain ⟨hportSupp, hportOk⟩ := port_step_schedP aut P
    (sccIntSteps aut ints) o hsuppO hintDead hPdisj hPo hport'
  constructor
  · refine Supp_append _ _ ?_ hportSupp
    refine Supp_target _ hsuppO ?_ ?_
    · intro s hs
      exact Or.inl ⟨(o, genPortTree aut (sccIntSteps aut ints) o),
        List.mem_cons_self .., hs⟩
    · intro p hp
      intro hc
      rcases hc with ⟨q, hq, hsq⟩ | hPs
      · rcases List.mem_cons.mp hq with h1 | h2
        · obtain ⟨s, hsL, hpe⟩ := List.mem_map.mp hp
          rw [← hpe] at hsq
          rw [h1] at hsq
          exact hcross s hsL hsq
        · exact nomatch h2
      · exact hPdisj p hp hPs
  · refine SchedOk_append (treeOf aut) _ _ []
      (forest_prefix_ok aut ints o hpairInts hcross hint) ?_
    exact hportOk

#print axioms Supp_target
#print axioms forest_prefix_supp
#print axioms forest_prefix_ok
#print axioms scc_block_schedP

/-! ## Prefix irrelevance

    A block certified with an empty prefix stays certified behind any
    prefix its equations never call — the tool that lets standalone
    block certificates concatenate into rank-class schedules. -/

/-- Cascades split across appended prefixes. -/
theorem stepSubst_append {S : Type} [DecidableEq S]
    (l₁ l₂ : List (S × RTree S A T)) (t : RTree S A T) :
    stepSubst (l₁ ++ l₂) t = stepSubst l₂ (stepSubst l₁ t) := by
  show List.foldl _ t (l₁ ++ l₂) = _
  rw [List.foldl_append]
  rfl

/-- **PREFIX IRRELEVANCE**: closing certificates survive un-called
    prefixes. -/
theorem SchedOk_disjoint_prefix {S : Type} [DecidableEq S]
    (sys : S → RTree S A T) (pre : List (S × RTree S A T)) :
    ∀ (steps done : List (S × RTree S A T)),
      (∀ p ∈ steps, CallOnly
        (fun t => ∀ q ∈ pre, t ≠ q.1) (sys p.1)) →
      SchedOk sys done steps →
      SchedOk sys (pre ++ done) steps := by
  intro steps
  induction steps with
  | nil => intro _ _ _; exact True.intro
  | cons hd rest ih =>
      intro done hdisj hok
      obtain ⟨u, C⟩ := hd
      obtain ⟨hclause, hrest⟩ := hok
      have hnoop : stepSubst (pre ++ done) (sys u)
          = stepSubst done (sys u) := by
        rw [stepSubst_append]
        rw [stepSubst_noop pre (sys u)
          (hdisj (u, C) (List.mem_cons_self ..))]
      refine ⟨?_, ?_⟩
      · rcases hclause with ⟨G, tl, tr, hre, hall, hCf⟩ | hfold | hself
        · refine Or.inl ⟨G, tl, tr, ?_, hall, hCf⟩
          intro sol
          rw [hnoop]
          exact hre sol
        · refine Or.inr (Or.inl ?_)
          intro sol
          rw [hnoop]
          exact hfold sol
        · refine Or.inr (Or.inr ?_)
          intro sol hu
          rw [hnoop]
          exact hself sol hu
      · have hres := ih (done ++ [(u, C)])
          (fun p hp => hdisj p (List.mem_cons_of_mem _ hp)) hrest
        show SchedOk sys ((pre ++ done) ++ [(u, C)]) rest
        rw [List.append_assoc]
        exact hres

#print axioms stepSubst_append
#print axioms SchedOk_disjoint_prefix

end GkatElim
