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
              (resolveT sol C)))
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
    (hdesc : ∀ s, ∀ e ∈ aut.trans s, rank e.2.2 ≤ rank s)
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
    callOnly_treeOf aut _ s (fun e he => hdesc s e he)
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
    intro s e he
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

end GkatElim
