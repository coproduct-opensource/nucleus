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
open GkatDecomp GkatPlanExistence GkatGuardedAlgebra GkatTrim
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

end GkatElim
