import GkatKleeneProofs

/-!
# Finite-axiom uniqueness for occurrence-based Thompson automata

Pham's 2026 uniqueness theorem concerns the original Thompson construction with an
initial pseudostate.  It does **not** directly concern `GkatKleene.derivAut`, whose states
are Brzozowski residual expressions.  This file formalizes the correct interface before
transporting the theorem into the completeness reduction.

The key strengthening is parameterized solvability: a transition that would accept may
instead continue with an arbitrary ending expression.  The induction target says that
every such solution is the standard Thompson solution followed by that ending.  Setting
the ending to `1` gives ordinary uniqueness.
-/

namespace GkatThompson

open GkatSyntax GkatGS GkatKleene GkatFaithful

variable {S S₁ S₂ A T : Type}

/-- A finite symbolic equation system without a distinguished internal start state.
    Thompson tests genuinely have no internal states, so reusing `GAut` (which requires
    `start : S`) would incorrectly rule out the base case. -/
structure GSystem (S A T : Type) where
  states : List S
  hlt : S → BExp T
  trans : S → List (BExp T × A × S)

/-- A Thompson system plus its initial pseudostate, represented in the same symbolic
    guarded-transition format. -/
structure InitializedGAut (S A T : Type) where
  core : GSystem S A T
  initHlt : BExp T
  initTrans : List (BExp T × A × S)

/-- Parameterized acceptance: successful termination continues with `finish`. -/
def paramFallback (halt : BExp T) (finish : Exp A T) : Exp A T :=
  .seq (.test halt) finish

/-- The equation RHS of an internal state with a parameterized ending expression. -/
def eqRHSParam (aut : GSystem S A T) (sol : S → Exp A T)
    (finish : Exp A T) (state : S) : Exp A T :=
  guardedFold (transitionBranches (aut.trans state) sol)
    (paramFallback (aut.hlt state) finish)

/-- A parameterized solution satisfies every listed internal-state equation. -/
def ParamSolvesBA (aut : GSystem S A T) (sol : S → Exp A T)
    (finish : Exp A T) : Prop :=
  ∀ state ∈ aut.states, EquivBA (sol state) (eqRHSParam aut sol finish state)

/-- Evaluation of the initial pseudostate under a parameterized solution. -/
def initRHSParam (aut : InitializedGAut S A T) (sol : S → Exp A T)
    (finish : Exp A T) : Exp A T :=
  guardedFold (transitionBranches aut.initTrans sol)
    (paramFallback aut.initHlt finish)

/-- Pham's strengthened induction invariant: every parameterized solution is the
    standard state expression followed by the supplied ending expression. -/
def ParametricCanonicalBA (aut : GSystem S A T) (standard : S → Exp A T) : Prop :=
  ∀ (finish : Exp A T) (sol : S → Exp A T), ParamSolvesBA aut sol finish →
    ∀ state ∈ aut.states, EquivBA (sol state) (.seq (standard state) finish)

/-- The corresponding initial-pseudostate invariant: evaluating the initial dynamics of
    the generated automaton yields the source program followed by the ending expression. -/
def ParametricInitialBA (aut : InitializedGAut S A T)
    (program : Exp A T) : Prop :=
  ∀ (finish : Exp A T) (sol : S → Exp A T),
    ParamSolvesBA aut.core sol finish →
      EquivBA (initRHSParam aut sol finish) (.seq program finish)

/-- The complete strengthened induction package for one generated Thompson automaton. -/
structure ParametricThompsonBA (aut : InitializedGAut S A T)
    (standard : S → Exp A T) (program : Exp A T) : Prop where
  states : ParametricCanonicalBA aut.core standard
  initial : ParametricInitialBA aut program

/-- The two additional facts supplied by an actual Thompson construction: its standard
    labelling is a solution, and initial transition guards are disjoint from initial halt. -/
def StandardSolvesBA (aut : InitializedGAut S A T)
    (standard : S → Exp A T) : Prop :=
  ParamSolvesBA aut.core standard (.test .one)

def InitHaltDisjointBA (aut : InitializedGAut S A T)
    (standard : S → Exp A T) : Prop :=
  ∀ branch ∈ transitionBranches aut.initTrans standard,
    ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and branch.1 aut.initHlt) x = false

/-- Every target reachable from the initial pseudostate is an actual listed internal
    state. This well-formedness condition is essential when state canonicality is used
    to rewrite the initial derivative. -/
def InitTargetsListed (aut : InitializedGAut S A T) : Prop :=
  ∀ transition ∈ aut.initTrans, transition.2.2 ∈ aut.core.states

def CoreTargetsListed (aut : InitializedGAut S A T) : Prop :=
  ∀ state ∈ aut.core.states, ∀ transition ∈ aut.core.trans state,
    transition.2.2 ∈ aut.core.states

def CoreHaltDisjoint (aut : InitializedGAut S A T) : Prop :=
  ∀ state ∈ aut.core.states, ∀ transition ∈ aut.core.trans state,
    ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and transition.1 (aut.core.hlt state)) x = false

structure CoreStructural (aut : InitializedGAut S A T) : Prop where
  targets : CoreTargetsListed aut
  disjoint : CoreHaltDisjoint aut

/-- All induction invariants required by nested Thompson constructors. Keeping these
    facts bundled prevents a later loop proof from silently assuming automaton
    well-formedness or existence of the canonical solution. -/
structure ThompsonCertificateBA (aut : InitializedGAut S A T)
    (standard : S → Exp A T) (program : Exp A T) : Prop where
  parametric : ParametricThompsonBA aut standard program
  standardSolves : StandardSolvesBA aut standard
  initDisjoint : InitHaltDisjointBA aut standard
  initTargets : InitTargetsListed aut

/-- Pointwise replacement of branch labels under fixed guards. -/
theorem guardedFold_branch_congr
    (branches : List (BExp T × Exp A T))
    (labels : BExp T × Exp A T → Exp A T) (fallback : Exp A T)
    (hlabels : ∀ branch ∈ branches, EquivBA branch.2 (labels branch)) :
    EquivBA (guardedFold branches fallback)
      (guardedFold (branches.map (fun branch => (branch.1, labels branch))) fallback) := by
  induction branches with
  | nil => exact EquivBA.base (Equiv.refl _)
  | cons branch branches ih =>
      exact EquivBA.ite_c
        (hlabels branch (List.Mem.head _))
        (ih (fun item hmem => hlabels item (List.Mem.tail _ hmem)))

/-- Replacing a parameterized solution by its canonical state labelling factors the
    common ending out of the action-only initial derivative. -/
theorem initialDerivative_factor
    (aut : InitializedGAut S A T) (standard sol : S → Exp A T)
    (finish : Exp A T)
    (hcanonical : ParametricCanonicalBA aut.core standard)
    (hsol : ParamSolvesBA aut.core sol finish)
    (htargets : InitTargetsListed aut) :
    let solDerivative := guardedFold
      (transitionBranches aut.initTrans sol) (.test .zero)
    let standardDerivative := guardedFold
      (transitionBranches aut.initTrans standard) (.test .zero)
    EquivBA solDerivative (.seq standardDerivative finish) := by
  dsimp
  let solBranches := transitionBranches aut.initTrans sol
  let standardBranches := transitionBranches aut.initTrans standard
  have hreplace : EquivBA (guardedFold solBranches (.test .zero))
      (guardedFold (standardBranches.map (fun branch =>
        (branch.1, Exp.seq branch.2 finish))) (.test .zero)) := by
    dsimp only [solBranches, standardBranches, transitionBranches]
    have go : ∀ transitions : List (BExp T × A × S),
        (∀ item ∈ transitions, item.2.2 ∈ aut.core.states) →
        EquivBA
          (guardedFold (transitions.map (fun transition =>
            (transition.1, Exp.seq (.act transition.2.1) (sol transition.2.2))))
            (.test .zero))
          (guardedFold
            ((transitions.map (fun transition =>
              (transition.1, Exp.seq (.act transition.2.1)
                (standard transition.2.2)))).map (fun branch =>
                (branch.1, Exp.seq branch.2 finish)))
            (.test .zero)) := by
      intro transitions hlisted
      induction transitions with
    | nil => exact EquivBA.base (Equiv.refl _)
    | cons transition transitions ih =>
        obtain ⟨guard, action, target⟩ := transition
        have htarget : target ∈ aut.core.states :=
          hlisted (guard, action, target) (List.Mem.head _)
        have htail : ∀ item ∈ transitions, item.2.2 ∈ aut.core.states := by
          intro item hmem
          exact hlisted item (List.Mem.tail _ hmem)
        have hhead : EquivBA (.seq (.act action) (sol target))
            (.seq (.seq (.act action) (standard target)) finish) :=
          EquivBA.trans
            (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
              (hcanonical finish sol hsol target htarget))
            (EquivBA.symm
              (EquivBA.base (Equiv.s1 (.act action) (standard target) finish)))
        exact EquivBA.ite_c hhead (ih htail)
    exact go aut.initTrans htargets
  have hseq := guardedFold_seq_right standardBranches (.test .zero) finish
  have hfallback := guardedFold_fallback_congr
    (standardBranches.map (fun branch =>
      (branch.1, Exp.seq branch.2 finish)))
    (EquivBA.symm (EquivBA.base (Equiv.s2 finish)))
  exact EquivBA.trans hreplace
    (EquivBA.trans hfallback (EquivBA.symm hseq))

/-- Right-continuation substitution for a standard solution. This is the existence-side
    counterpart of parameterized canonicality and uses only S1, S5, and U5. -/
theorem StandardSolvesBA.withContinuation
    (aut : InitializedGAut S A T) (standard : S → Exp A T)
    (hstandard : StandardSolvesBA aut standard) (finish : Exp A T) :
    ParamSolvesBA aut.core (fun state => .seq (standard state) finish) finish := by
  intro state hstate
  have hbase := hstandard state hstate
  have hprefix : EquivBA (.seq (standard state) finish)
      (.seq (eqRHSParam aut.core standard (.test .one) state) finish) :=
    EquivBA.seq_c hbase (EquivBA.base (Equiv.refl finish))
  let transitions := aut.core.trans state
  let oldBranches := transitionBranches transitions standard
  have hdistribute := guardedFold_seq_right oldBranches
    (paramFallback (aut.core.hlt state) (.test .one)) finish
  have hrewrite : EquivBA
      (guardedFold (oldBranches.map (fun branch =>
        (branch.1, Exp.seq branch.2 finish)))
        (.seq (paramFallback (aut.core.hlt state) (.test .one)) finish))
      (eqRHSParam aut.core (fun item => .seq (standard item) finish)
        finish state) := by
    dsimp only [eqRHSParam, transitions, oldBranches, transitionBranches,
      paramFallback]
    induction aut.core.trans state with
    | nil =>
        exact EquivBA.seq_c
          (EquivBA.base (Equiv.s5 (.test (aut.core.hlt state) : Exp A T)))
          (EquivBA.base (Equiv.refl finish))
    | cons transition rest ih =>
        obtain ⟨guard, action, target⟩ := transition
        exact EquivBA.ite_c
          (EquivBA.base (Equiv.s1 (.act action) (standard target) finish)) ih
  exact EquivBA.trans hprefix
    (EquivBA.trans hdistribute hrewrite)

/-- Fundamental decomposition of the initial pseudostate into its halt test and its
    action-only derivative fold. This is the exact premise used by the productive-loop
    step in the Thompson iteration proof. -/
theorem initial_program_decomposition
    (aut : InitializedGAut S A T) (standard : S → Exp A T)
    (program : Exp A T)
    (hparam : ParametricThompsonBA aut standard program)
    (hsol : StandardSolvesBA aut standard)
    (hdis : InitHaltDisjointBA aut standard) :
    EquivBA program
      (.ite aut.initHlt (.test .one)
        (guardedFold (transitionBranches aut.initTrans standard) (.test .zero))) := by
  let branches := transitionBranches aut.initTrans standard
  have hinitial := hparam.initial (.test .one) standard hsol
  have htoInitial : EquivBA program (initRHSParam aut standard (.test .one)) :=
    EquivBA.trans
      (EquivBA.symm (EquivBA.base (Equiv.s5 program)))
      (EquivBA.symm hinitial)
  have hhalt : EquivBA
      (paramFallback aut.initHlt (.test .one : Exp A T))
      (.test aut.initHlt : Exp A T) :=
    EquivBA.base (Equiv.s5 (.test aut.initHlt : Exp A T))
  have hnormalize := guardedFold_fallback_congr branches hhalt
  have hpartition := guardedFold_test_partition aut.initHlt branches hdis
  exact EquivBA.trans htoInitial
    (EquivBA.trans hnormalize hpartition)

/-- A fold whose every branch begins with an action cannot accept the empty guarded
    string. This is a direct Boolean computation over the finite transition list. -/
theorem transitionActionFold_productive
    (transitions : List (BExp T × A × S)) (sol : S → Exp A T) :
    ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W
        (E (guardedFold (transitionBranches transitions sol) (.test .zero))) x = false := by
  induction transitions with
  | nil =>
      intro X W x
      rfl
  | cons transition transitions ih =>
      obtain ⟨guard, action, target⟩ := transition
      intro X W x
      change bval W
        (E (.ite guard (.seq (.act action) (sol target))
          (guardedFold (transitionBranches transitions sol) (.test .zero)))) x = false
      simp only [E, bval]
      have htail := ih X W x
      rw [htail]
      cases bval W guard x <;> rfl

/-- The action-only initial derivative fold is productive in the full Boolean-aware
    equational theory. -/
theorem transitionActionFold_productiveBA
    (transitions : List (BExp T × A × S)) (sol : S → Exp A T) :
    EquivBA
      (.test (E (guardedFold (transitionBranches transitions sol) (.test .zero))) :
        Exp A T)
      (.test .zero) :=
  EquivBA.baTest (transitionActionFold_productive transitions sol)

/-- Productive-loop normalization for an initialized Thompson system. The original
    program may terminate immediately; W2 removes those silent iterations, leaving the
    action-only initial derivative fold. -/
theorem initialized_productiveLoop
    (guard : BExp T) (aut : InitializedGAut S A T)
    (standard : S → Exp A T) (program : Exp A T)
    (hparam : ParametricThompsonBA aut standard program)
    (hsol : StandardSolvesBA aut standard)
    (hdis : InitHaltDisjointBA aut standard) :
    let derivative := guardedFold
      (transitionBranches aut.initTrans standard) (.test .zero)
    EquivBA (.wh guard program) (.wh guard derivative) := by
  let branches := transitionBranches aut.initTrans standard
  let derivative := guardedFold branches (.test .zero)
  have hdecomp : EquivBA program
      (.ite aut.initHlt (.test .one) derivative) :=
    initial_program_decomposition aut standard program hparam hsol hdis
  have himp : ∀ branch ∈ branches, GuardImplies branch.1 (.not aut.initHlt) := by
    intro branch hmem X W x hguard
    have hd := hdis branch hmem X W x
    change (bval W branch.1 x && bval W aut.initHlt x) = false at hd
    change (!bval W aut.initHlt x) = true
    rw [hguard] at hd
    cases hhalt : bval W aut.initHlt x
    · rfl
    · rw [hhalt] at hd
      exact Bool.noConfusion hd
  have hprefix : EquivBA
      (.seq (.test (.not aut.initHlt)) derivative : Exp A T) derivative :=
    test_seq_guardedFold_of_implies (.not aut.initHlt) branches himp
  exact EquivBA.trans (EquivBA.wh_c hdecomp)
    (EquivBA.trans
      (EquivBA.wh_c
        (EquivBA.base (Equiv.u2 aut.initHlt (.test .one) derivative)))
      (EquivBA.trans
        (EquivBA.base (Equiv.w2 guard (.not aut.initHlt) derivative))
        (EquivBA.wh_c hprefix)))

/-! ## Iteration construction -/

/-- Occurrence-based Thompson feedback construction. On loop entry, `¬guard` accepts,
    `guard` follows a productive body transition, and an immediate body halt under `guard`
    is discarded as a silent/nonproductive iteration. -/
def loopInitialized (guard : BExp T) (body : InitializedGAut S A T) :
    InitializedGAut S A T where
  core := {
    states := body.core.states
    hlt := fun state => .and (body.core.hlt state) (.not guard)
    trans := fun state =>
      body.core.trans state ++
      body.initTrans.map (fun transition =>
        (BExp.and (body.core.hlt state) (BExp.and guard transition.1),
          transition.2))
  }
  initHlt := .not guard
  initTrans := body.initTrans.map (fun transition =>
    (BExp.and guard transition.1, transition.2))

theorem loopInitialized_coreStructural
    (guard : BExp T) (body : InitializedGAut S A T)
    (hbody : CoreStructural body)
    (hinitTargets : InitTargetsListed body) :
    CoreStructural (loopInitialized guard body) := by
  constructor
  · intro state hstate transition htransition
    simp only [loopInitialized, List.mem_append, List.mem_map] at htransition
    rcases htransition with htransition | htransition
    · exact hbody.targets state hstate transition htransition
    · obtain ⟨original, horiginal, rfl⟩ := htransition
      exact hinitTargets original horiginal
  · intro state hstate transition htransition X W x
    simp only [loopInitialized, List.mem_append, List.mem_map] at htransition
    rcases htransition with htransition | htransition
    · have hd := hbody.disjoint state hstate transition htransition X W x
      change (bval W transition.1 x &&
        (bval W (body.core.hlt state) x && !bval W guard x)) = false
      change (bval W transition.1 x && bval W (body.core.hlt state) x) = false at hd
      rw [← Bool.and_assoc, hd]
      rfl
    · obtain ⟨original, horiginal, rfl⟩ := htransition
      change ((bval W (body.core.hlt state) x &&
        (bval W guard x && bval W original.1 x)) &&
        (bval W (body.core.hlt state) x && !bval W guard x)) = false
      cases hg : bval W guard x <;> simp [hg]

/-- Ordinary internal solutions, represented as parameterized solutions ending in `1`. -/
def ThompsonSolvesBA (aut : GSystem S A T) (sol : S → Exp A T) : Prop :=
  ParamSolvesBA aut sol (.test .one)

/-- The strengthened parameterized invariant immediately yields uniqueness at ending `1`. -/
theorem ParametricCanonicalBA.unique {aut : GSystem S A T}
    {standard sol₁ sol₂ : S → Exp A T}
    (hcanonical : ParametricCanonicalBA aut standard)
    (h₁ : ThompsonSolvesBA aut sol₁) (h₂ : ThompsonSolvesBA aut sol₂) :
    ∀ state ∈ aut.states, EquivBA (sol₁ state) (sol₂ state) := by
  intro state hstate
  exact EquivBA.trans
    (hcanonical (.test .one) sol₁ h₁ state hstate)
    (EquivBA.symm (hcanonical (.test .one) sol₂ h₂ state hstate))

/-- Thompson automaton for an embedded test has no internal states. -/
def thompsonTest (test : BExp T) : InitializedGAut Empty A T where
  core := {
    states := []
    hlt := fun state => nomatch state
    trans := fun state => nomatch state
  }
  initHlt := test
  initTrans := []

/-- Thompson automaton for one action: its sole internal state accepts immediately. -/
def thompsonAction (action : A) : InitializedGAut Unit A T where
  core := {
    states := [()]
    hlt := fun _ => .one
    trans := fun _ => []
  }
  initHlt := .zero
  initTrans := [(.one, action, ())]

/-- The empty standard solution is parametrically canonical. -/
theorem thompsonTest_parametricCanonical (test : BExp T) :
    ParametricCanonicalBA (thompsonTest (A := A) test).core
      (fun state : Empty => nomatch state) := by
  intro finish sol hsol state hstate
  exact nomatch hstate

/-- The action state is exactly the successful test, so its parameterized equation is
    already `1 · finish`. -/
theorem thompsonAction_parametricCanonical (action : A) :
    ParametricCanonicalBA (thompsonAction (T := T) action).core
      (fun _ : Unit => (Exp.test .one : Exp A T)) := by
  intro finish sol hsol state hstate
  have heq := hsol state hstate
  cases state
  simpa only [eqRHSParam, thompsonAction, transitionBranches, guardedFold,
    paramFallback] using heq

/-- The test initial pseudostate denotes the test followed by the ending expression. -/
theorem thompsonTest_parametricInitial (test : BExp T) :
    ParametricInitialBA (thompsonTest (A := A) test) (.test test) := by
  intro finish sol hsol
  exact EquivBA.base (Equiv.refl _)

/-- The action initial pseudostate performs the action, while its sole internal state
    contributes only successful termination before the ending expression. -/
theorem thompsonAction_parametricInitial (action : A) :
    ParametricInitialBA (thompsonAction (T := T) action) (.act action) := by
  intro finish sol hsol
  have hstate : () ∈ (thompsonAction (T := T) action).core.states :=
    List.Mem.head []
  have hcanonical := thompsonAction_parametricCanonical (T := T) action
    finish sol hsol () hstate
  dsimp only [initRHSParam, thompsonAction, transitionBranches, guardedFold,
    paramFallback]
  exact EquivBA.trans (ite_one _ _)
    (EquivBA.trans
      (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hcanonical)
      (EquivBA.trans
        (EquivBA.symm
          (EquivBA.base (Equiv.s1 (.act action) (.test .one) finish)))
        (EquivBA.seq_c (EquivBA.base (Equiv.s5 (.act action)))
          (EquivBA.base (Equiv.refl finish)))))

def thompsonTest_parametric (test : BExp T) :
    ParametricThompsonBA (thompsonTest (A := A) test)
      (fun state : Empty => nomatch state) (.test test) :=
  ⟨thompsonTest_parametricCanonical test, thompsonTest_parametricInitial test⟩

def thompsonAction_parametric (action : A) :
    ParametricThompsonBA (thompsonAction (T := T) action)
      (fun _ : Unit => (Exp.test .one : Exp A T)) (.act action) :=
  ⟨thompsonAction_parametricCanonical action,
    thompsonAction_parametricInitial action⟩

theorem thompsonTest_standardSolves (test : BExp T) :
    StandardSolvesBA (thompsonTest (A := A) test)
      (fun state : Empty => nomatch state) := by
  intro state hstate
  exact nomatch hstate

theorem thompsonAction_standardSolves (action : A) :
    StandardSolvesBA (thompsonAction (T := T) action)
      (fun _ : Unit => (Exp.test .one : Exp A T)) := by
  intro state hstate
  cases state
  exact EquivBA.symm (EquivBA.base (Equiv.s5 (.test .one : Exp A T)))

theorem thompsonTest_initDisjoint (test : BExp T) :
    InitHaltDisjointBA (thompsonTest (A := A) test)
      (fun state : Empty => nomatch state) := by
  intro branch hbranch
  exact nomatch hbranch

theorem thompsonAction_initDisjoint (action : A) :
    InitHaltDisjointBA (thompsonAction (T := T) action)
      (fun _ : Unit => (Exp.test .one : Exp A T)) := by
  intro branch hbranch X W x
  simp only [thompsonAction, transitionBranches, List.map_cons, List.map_nil, List.mem_cons,
    List.not_mem_nil, or_false] at hbranch
  rcases hbranch with rfl
  rfl

theorem thompsonTest_initTargets (test : BExp T) :
    InitTargetsListed (thompsonTest (A := A) test) := by
  intro transition htransition
  exact nomatch htransition

theorem thompsonAction_initTargets (action : A) :
    InitTargetsListed (thompsonAction (T := T) action) := by
  intro transition htransition
  simp only [thompsonAction, List.mem_cons, List.not_mem_nil, or_false] at htransition
  rcases htransition with rfl
  exact List.Mem.head []

theorem thompsonTest_coreStructural (test : BExp T) :
    CoreStructural (thompsonTest (A := A) test) := by
  constructor
  · intro state hstate
    exact nomatch hstate
  · intro state hstate
    exact nomatch hstate

theorem thompsonAction_coreStructural (action : A) :
    CoreStructural (thompsonAction (T := T) action) := by
  constructor
  · intro state hstate transition htransition
    exact nomatch htransition
  · intro state hstate transition htransition
    exact nomatch htransition

def thompsonTest_certificate (test : BExp T) :
    ThompsonCertificateBA (thompsonTest (A := A) test)
      (fun state : Empty => nomatch state) (.test test) :=
  ⟨thompsonTest_parametric test, thompsonTest_standardSolves test,
    thompsonTest_initDisjoint test, thompsonTest_initTargets test⟩

def thompsonAction_certificate (action : A) :
    ThompsonCertificateBA (thompsonAction (T := T) action)
      (fun _ : Unit => (Exp.test .one : Exp A T)) (.act action) :=
  ⟨thompsonAction_parametric action, thompsonAction_standardSolves action,
    thompsonAction_initDisjoint action, thompsonAction_initTargets action⟩

/-- Disjoint union of internal Thompson systems. Conditional construction changes only
    the initial pseudostate, so this is its entire internal-state operation. -/
def sumGSystem (left : GSystem S₁ A T) (right : GSystem S₂ A T) :
    GSystem (Sum S₁ S₂) A T where
  states := left.states.map Sum.inl ++ right.states.map Sum.inr
  hlt
    | .inl state => left.hlt state
    | .inr state => right.hlt state
  trans
    | .inl state => (left.trans state).map (fun transition =>
        (transition.1, transition.2.1, Sum.inl transition.2.2))
    | .inr state => (right.trans state).map (fun transition =>
        (transition.1, transition.2.1, Sum.inr transition.2.2))

private theorem mem_map_direct {X Y : Type} (map : X → Y) {item : X} {items : List X}
    (hmem : item ∈ items) : map item ∈ items.map map := by
  induction items with
  | nil => exact nomatch hmem
  | cons head tail ih =>
      cases hmem with
      | head => exact List.Mem.head _
      | tail _ htail => exact List.Mem.tail _ (ih htail)

private theorem mem_append_left_direct {X : Type} {item : X} {left right : List X}
    (hmem : item ∈ left) : item ∈ left ++ right := by
  induction left with
  | nil => exact nomatch hmem
  | cons head tail ih =>
      cases hmem with
      | head => exact List.Mem.head _
      | tail _ htail => exact List.Mem.tail _ (ih htail)

private theorem mem_append_right_direct {X : Type} (left : List X)
    {item : X} {right : List X} (hmem : item ∈ right) : item ∈ left ++ right := by
  induction left generalizing item with
  | nil => exact hmem
  | cons head tail ih => exact List.Mem.tail _ (ih hmem)

/-- Parameterized canonicity is closed under disjoint union, hence under the internal
    state part of Thompson conditionals. -/
theorem ParametricCanonicalBA.sum
    {left : GSystem S₁ A T} {right : GSystem S₂ A T}
    {leftStandard : S₁ → Exp A T} {rightStandard : S₂ → Exp A T}
    (hleft : ParametricCanonicalBA left leftStandard)
    (hright : ParametricCanonicalBA right rightStandard) :
    ParametricCanonicalBA (sumGSystem left right)
      (fun state => match state with
        | .inl item => leftStandard item
        | .inr item => rightStandard item) := by
  intro finish sol hsol state hstate
  have hsolLeft : ParamSolvesBA left (fun item => sol (.inl item)) finish := by
    intro item hitem
    have hsum : Sum.inl item ∈ (sumGSystem left right).states :=
      mem_append_left_direct (mem_map_direct Sum.inl hitem)
    simpa only [eqRHSParam, sumGSystem, transitionBranches, List.map_map,
      Function.comp_apply] using
      hsol (.inl item) hsum
  have hsolRight : ParamSolvesBA right (fun item => sol (.inr item)) finish := by
    intro item hitem
    have hsum : Sum.inr item ∈ (sumGSystem left right).states :=
      mem_append_right_direct _ (mem_map_direct Sum.inr hitem)
    simpa only [eqRHSParam, sumGSystem, transitionBranches, List.map_map,
      Function.comp_apply] using
      hsol (.inr item) hsum
  cases state with
  | inl item =>
      have hitem : item ∈ left.states := by
        change Sum.inl item ∈ left.states.map Sum.inl ++ right.states.map Sum.inr at hstate
        simpa using hstate
      exact hleft finish _ hsolLeft item hitem
  | inr item =>
      have hitem : item ∈ right.states := by
        change Sum.inr item ∈ left.states.map Sum.inl ++ right.states.map Sum.inr at hstate
        simpa using hstate
      exact hright finish _ hsolRight item hitem

theorem StandardSolvesBA.sumSystems
    {left : InitializedGAut S₁ A T} {right : InitializedGAut S₂ A T}
    {leftStandard : S₁ → Exp A T} {rightStandard : S₂ → Exp A T}
    (hleft : StandardSolvesBA left leftStandard)
    (hright : StandardSolvesBA right rightStandard) :
    ParamSolvesBA (sumGSystem left.core right.core)
      (fun state => match state with
        | .inl item => leftStandard item
        | .inr item => rightStandard item)
      (.test .one) := by
  intro state hstate
  cases state with
  | inl item =>
      have hitem : item ∈ left.core.states := by
        change Sum.inl item ∈ left.core.states.map Sum.inl ++
          right.core.states.map Sum.inr at hstate
        simpa using hstate
      simpa only [eqRHSParam, sumGSystem, transitionBranches,
        List.map_map, Function.comp_apply] using hleft item hitem
  | inr item =>
      have hitem : item ∈ right.core.states := by
        change Sum.inr item ∈ left.core.states.map Sum.inl ++
          right.core.states.map Sum.inr at hstate
        simpa using hstate
      simpa only [eqRHSParam, sumGSystem, transitionBranches,
        List.map_map, Function.comp_apply] using hright item hitem

/-! ## Conditional construction -/

/-- Initialized Thompson conditional: internal systems are disjoint; only the initial
    pseudostate is partitioned by the conditional guard. -/
def iteInitialized (guard : BExp T) (left : InitializedGAut S₁ A T)
    (right : InitializedGAut S₂ A T) : InitializedGAut (Sum S₁ S₂) A T where
  core := sumGSystem left.core right.core
  initHlt := .or (.and guard left.initHlt) (.and (.not guard) right.initHlt)
  initTrans :=
    left.initTrans.map (fun transition =>
      (BExp.and guard transition.1,
        transition.2.1, Sum.inl transition.2.2)) ++
    right.initTrans.map (fun transition =>
      (BExp.and (BExp.not guard) transition.1,
        transition.2.1, Sum.inr transition.2.2))

theorem iteInitialized_coreStructural
    (guard : BExp T) (left : InitializedGAut S₁ A T)
    (right : InitializedGAut S₂ A T)
    (hleft : CoreStructural left) (hright : CoreStructural right) :
    CoreStructural (iteInitialized guard left right) := by
  constructor
  · intro state hstate transition htransition
    cases state with
    | inl item =>
        have hitem : item ∈ left.core.states := by
          change Sum.inl item ∈ left.core.states.map Sum.inl ++
            right.core.states.map Sum.inr at hstate
          simpa using hstate
        simp only [iteInitialized, sumGSystem, List.mem_map] at htransition
        obtain ⟨original, horiginal, rfl⟩ := htransition
        exact mem_append_left_direct
          (mem_map_direct Sum.inl (hleft.targets item hitem original horiginal))
    | inr item =>
        have hitem : item ∈ right.core.states := by
          change Sum.inr item ∈ left.core.states.map Sum.inl ++
            right.core.states.map Sum.inr at hstate
          simpa using hstate
        simp only [iteInitialized, sumGSystem, List.mem_map] at htransition
        obtain ⟨original, horiginal, rfl⟩ := htransition
        exact mem_append_right_direct _
          (mem_map_direct Sum.inr (hright.targets item hitem original horiginal))
  · intro state hstate transition htransition X W x
    cases state with
    | inl item =>
        have hitem : item ∈ left.core.states := by
          change Sum.inl item ∈ left.core.states.map Sum.inl ++
            right.core.states.map Sum.inr at hstate
          simpa using hstate
        simp only [iteInitialized, sumGSystem, List.mem_map] at htransition
        obtain ⟨original, horiginal, rfl⟩ := htransition
        exact hleft.disjoint item hitem original horiginal X W x
    | inr item =>
        have hitem : item ∈ right.core.states := by
          change Sum.inr item ∈ left.core.states.map Sum.inl ++
            right.core.states.map Sum.inr at hstate
          simpa using hstate
        simp only [iteInitialized, sumGSystem, List.mem_map] at htransition
        obtain ⟨original, horiginal, rfl⟩ := htransition
        exact hright.disjoint item hitem original horiginal X W x


/-- Factoring a common parameterized ending from a conditional also combines its two
    halt tests into the standard Boolean terminal guard. -/
theorem ite_paramFallback (guard leftHalt rightHalt : BExp T)
    (finish : Exp A T) :
    EquivBA
      (.ite guard (paramFallback leftHalt finish)
        (paramFallback rightHalt finish))
      (paramFallback
        (.or (.and guard leftHalt) (.and (.not guard) rightHalt)) finish) := by
  exact EquivBA.trans
    (EquivBA.base
      (Equiv.u5 guard (.test leftHalt) (.test rightHalt) finish))
    (EquivBA.seq_c
      (ite_tests_ba guard leftHalt rightHalt)
      (EquivBA.base (Equiv.refl finish)))

/-- Full conditional constructor for the strengthened Thompson induction package. -/
theorem ParametricThompsonBA.ite
    {left : InitializedGAut S₁ A T} {right : InitializedGAut S₂ A T}
    {leftStandard : S₁ → Exp A T} {rightStandard : S₂ → Exp A T}
    {leftProgram rightProgram : Exp A T}
    (guard : BExp T)
    (hleft : ParametricThompsonBA left leftStandard leftProgram)
    (hright : ParametricThompsonBA right rightStandard rightProgram) :
    ParametricThompsonBA (iteInitialized guard left right)
      (fun state => match state with
        | .inl item => leftStandard item
        | .inr item => rightStandard item)
      (.ite guard leftProgram rightProgram) := by
  constructor
  · exact hleft.states.sum hright.states
  · intro finish sol hsol
    have hsolLeft : ParamSolvesBA left.core
        (fun item => sol (.inl item)) finish := by
      intro item hitem
      have hsum : Sum.inl item ∈ (iteInitialized guard left right).core.states :=
        mem_append_left_direct (mem_map_direct Sum.inl hitem)
      have heq := hsol (.inl item) hsum
      simpa only [iteInitialized, eqRHSParam, sumGSystem, transitionBranches,
        List.map_map, Function.comp_apply] using heq
    have hsolRight : ParamSolvesBA right.core
        (fun item => sol (.inr item)) finish := by
      intro item hitem
      have hsum : Sum.inr item ∈ (iteInitialized guard left right).core.states :=
        mem_append_right_direct _ (mem_map_direct Sum.inr hitem)
      have heq := hsol (.inr item) hsum
      simpa only [iteInitialized, eqRHSParam, sumGSystem, transitionBranches,
        List.map_map, Function.comp_apply] using heq
    have hleftInitial := hleft.initial finish
      (fun item => sol (.inl item)) hsolLeft
    have hrightInitial := hright.initial finish
      (fun item => sol (.inr item)) hsolRight
    let leftBranches := transitionBranches left.initTrans
      (fun item => sol (.inl item))
    let rightBranches := transitionBranches right.initTrans
      (fun item => sol (.inr item))
    have hpartition := ite_guardedFold_partition guard leftBranches rightBranches
      (paramFallback left.initHlt finish) (paramFallback right.initHlt finish)
    have hterminal := ite_paramFallback guard left.initHlt right.initHlt finish
    have hlift := guardedFold_fallback_congr
      (leftBranches.map (fun branch =>
          (BExp.and guard branch.1, branch.2)) ++
        rightBranches.map (fun branch =>
          (BExp.and (BExp.not guard) branch.1, branch.2))) hterminal
    have hshape : transitionBranches (iteInitialized guard left right).initTrans sol =
        leftBranches.map (fun branch =>
          (BExp.and guard branch.1, branch.2)) ++
        rightBranches.map (fun branch =>
          (BExp.and (BExp.not guard) branch.1, branch.2)) := by
      dsimp only [iteInitialized, leftBranches, rightBranches, transitionBranches]
      simp only [List.map_append, List.map_map, Function.comp_apply]
      congr 1
    have hflattened : EquivBA
        (.ite guard
          (initRHSParam left (fun item => sol (.inl item)) finish)
          (initRHSParam right (fun item => sol (.inr item)) finish))
        (initRHSParam (iteInitialized guard left right) sol finish) := by
      exact EquivBA.trans
        (by
          dsimp only [initRHSParam]
          exact hpartition)
        (EquivBA.trans hlift
          (by
            dsimp only [initRHSParam]
            rw [hshape]
            exact EquivBA.base (Equiv.refl _)))
    exact EquivBA.trans (EquivBA.symm hflattened)
      (EquivBA.trans
        (EquivBA.ite_c hleftInitial hrightInitial)
        (EquivBA.base
          (Equiv.u5 guard leftProgram rightProgram finish)))

theorem iteInitialized_standardSolves
    {left : InitializedGAut S₁ A T} {right : InitializedGAut S₂ A T}
    {leftStandard : S₁ → Exp A T} {rightStandard : S₂ → Exp A T}
    (guard : BExp T)
    (hleft : StandardSolvesBA left leftStandard)
    (hright : StandardSolvesBA right rightStandard) :
    StandardSolvesBA (iteInitialized guard left right)
      (fun state => match state with
        | .inl item => leftStandard item
        | .inr item => rightStandard item) :=
  hleft.sumSystems hright

theorem iteInitialized_initTargets
    (guard : BExp T) (left : InitializedGAut S₁ A T)
    (right : InitializedGAut S₂ A T)
    (hleft : InitTargetsListed left) (hright : InitTargetsListed right) :
    InitTargetsListed (iteInitialized guard left right) := by
  intro transition htransition
  simp only [iteInitialized, List.mem_append, List.mem_map] at htransition
  rcases htransition with htransition | htransition
  · obtain ⟨original, horiginal, rfl⟩ := htransition
    exact mem_append_left_direct (mem_map_direct Sum.inl (hleft original horiginal))
  · obtain ⟨original, horiginal, rfl⟩ := htransition
    exact mem_append_right_direct _
      (mem_map_direct Sum.inr (hright original horiginal))

theorem iteInitialized_initDisjoint
    (guard : BExp T) (left : InitializedGAut S₁ A T)
    (right : InitializedGAut S₂ A T)
    (leftStandard : S₁ → Exp A T) (rightStandard : S₂ → Exp A T)
    (hleft : InitHaltDisjointBA left leftStandard)
    (hright : InitHaltDisjointBA right rightStandard) :
    InitHaltDisjointBA (iteInitialized guard left right)
      (fun state => match state with
        | .inl item => leftStandard item
        | .inr item => rightStandard item) := by
  intro branch hbranch X W x
  simp only [iteInitialized, transitionBranches, List.mem_map] at hbranch
  obtain ⟨transition, htransition, rfl⟩ := hbranch
  simp only [List.mem_append, List.mem_map] at htransition
  rcases htransition with htransition | htransition
  · obtain ⟨original, horiginal, rfl⟩ := htransition
    have hmember :
        (original.1, Exp.seq (.act original.2.1)
          (leftStandard original.2.2)) ∈
          transitionBranches left.initTrans leftStandard :=
      List.mem_map.mpr ⟨original, horiginal, rfl⟩
    have hd := hleft _ hmember X W x
    change ((bval W guard x && bval W original.1 x) &&
      ((bval W guard x && bval W left.initHlt x) ||
        (!bval W guard x && bval W right.initHlt x))) = false
    cases hg : bval W guard x
    · simp [hg]
    · simp only [hg, Bool.true_and, Bool.not_true, Bool.false_and, Bool.or_false]
      exact hd
  · obtain ⟨original, horiginal, rfl⟩ := htransition
    have hmember :
        (original.1, Exp.seq (.act original.2.1)
          (rightStandard original.2.2)) ∈
          transitionBranches right.initTrans rightStandard :=
      List.mem_map.mpr ⟨original, horiginal, rfl⟩
    have hd := hright _ hmember X W x
    change (((!bval W guard x) && bval W original.1 x) &&
      ((bval W guard x && bval W left.initHlt x) ||
        (!bval W guard x && bval W right.initHlt x))) = false
    cases hg : bval W guard x
    · simp only [hg, Bool.not_false, Bool.true_and, Bool.false_and, Bool.or_false]
      exact hd
    · simp [hg]

theorem ThompsonCertificateBA.ite
    {left : InitializedGAut S₁ A T} {right : InitializedGAut S₂ A T}
    {leftStandard : S₁ → Exp A T} {rightStandard : S₂ → Exp A T}
    {leftProgram rightProgram : Exp A T}
    (guard : BExp T)
    (hleft : ThompsonCertificateBA left leftStandard leftProgram)
    (hright : ThompsonCertificateBA right rightStandard rightProgram) :
    ThompsonCertificateBA (iteInitialized guard left right)
      (fun state => match state with
        | .inl item => leftStandard item
        | .inr item => rightStandard item)
      (.ite guard leftProgram rightProgram) := by
  constructor
  · exact hleft.parametric.ite guard hright.parametric
  · exact iteInitialized_standardSolves guard
      hleft.standardSolves hright.standardSolves
  · exact iteInitialized_initDisjoint guard left right leftStandard rightStandard
      hleft.initDisjoint hright.initDisjoint
  · exact iteInitialized_initTargets guard left right
      hleft.initTargets hright.initTargets

/-! ## Sequencing: flattening a successful exit into the next initial dynamics -/

/-- Connecting a left dynamics to a right dynamics is algebraically the same as using
    `test region · right` as the left fallback. This is the symbolic, finite-list form of
    the continuation substitution in Pham's sequencing case. -/
theorem guardedFold_connect (region : BExp T)
    (left right : List (BExp T × Exp A T)) (fallback : Exp A T) :
    EquivBA
      (guardedFold left
        (.seq (.test region) (guardedFold right fallback)))
      (guardedFold
        (left ++ right.map (fun branch =>
          (BExp.and region branch.1, branch.2)))
        (.ite region fallback (.test .zero))) := by
  have hgate := test_seq_guardedFold_gate region right fallback
  have hlift := guardedFold_fallback_congr left hgate
  have happend := guardedFold_append left
    (right.map (fun branch => (BExp.and region branch.1, branch.2)))
    (.ite region fallback (.test .zero))
  exact EquivBA.trans hlift
    (by
      rw [happend]
      exact EquivBA.base (Equiv.refl _))

/-- The connected terminal branch is precisely conjunction of the two halt guards. -/
theorem ite_paramFallback_zero (region halt : BExp T) (finish : Exp A T) :
    EquivBA (.ite region (paramFallback halt finish) (.test .zero))
      (paramFallback (.and region halt) finish) := by
  have hassert : EquivBA
      (.seq (.test (.and region halt)) finish : Exp A T)
      (.seq (.test region) (.seq (.test halt) finish)) := by
    exact EquivBA.trans
      (EquivBA.seq_c (EquivBA.symm (EquivBA.s6 region halt))
        (EquivBA.base (Equiv.refl finish)))
      (EquivBA.base (Equiv.s1 (.test region) (.test halt) finish))
  exact EquivBA.trans
    (EquivBA.symm
      (test_seq_as_ite region (.seq (.test halt) finish)))
    (EquivBA.symm hassert)

/-- A loop-state equation is the original body-state equation whose successful exit has
    been parameterized by the feedback initial dynamics. -/
theorem eqRHSParam_loopInitialized
    (guard : BExp T) (body : InitializedGAut S A T)
    (sol : S → Exp A T) (finish : Exp A T) (state : S) :
    EquivBA
      (eqRHSParam body.core sol
        (initRHSParam (loopInitialized guard body) sol finish) state)
      (eqRHSParam (loopInitialized guard body).core sol finish state) := by
  let leftBranches := transitionBranches (body.core.trans state) sol
  let feedbackBranches := transitionBranches
    (loopInitialized guard body).initTrans sol
  have hconnect := guardedFold_connect (body.core.hlt state)
    leftBranches feedbackBranches
    (paramFallback (.not guard) finish)
  have hterminal := ite_paramFallback_zero
    (body.core.hlt state) (.not guard) finish
  have hlift := guardedFold_fallback_congr
    (leftBranches ++ feedbackBranches.map (fun branch =>
      (BExp.and (body.core.hlt state) branch.1, branch.2))) hterminal
  have hshape : transitionBranches
      ((loopInitialized guard body).core.trans state) sol =
      leftBranches ++ feedbackBranches.map (fun branch =>
        (BExp.and (body.core.hlt state) branch.1, branch.2)) := by
    dsimp only [loopInitialized, leftBranches, feedbackBranches, transitionBranches]
    simp only [List.map_append, List.map_map, Function.comp_apply]
    congr 1
  exact EquivBA.trans
    (by
      dsimp only [eqRHSParam, initRHSParam]
      exact hconnect)
    (EquivBA.trans hlift
      (by
        dsimp only [eqRHSParam]
        rw [hshape]
        exact EquivBA.base (Equiv.refl _)))

/-- The loop pseudostate is exactly a guarded feedback equation over the body's
    action-only initial derivative. Immediate body termination is intentionally absent. -/
theorem loopInitial_feedback
    (guard : BExp T) (body : InitializedGAut S A T)
    (sol : S → Exp A T) (finish : Exp A T) :
    let derivative := guardedFold
      (transitionBranches body.initTrans sol) (.test .zero)
    EquivBA (initRHSParam (loopInitialized guard body) sol finish)
      (.ite guard derivative finish) := by
  dsimp
  let branches := transitionBranches body.initTrans sol
  have hpartition := ite_guardedFold_partition guard branches []
    (.test .zero) finish
  have hterminal : EquivBA
      (.ite guard (.test .zero) finish : Exp A T)
      (paramFallback (.not guard) finish) := by
    exact EquivBA.trans
      (EquivBA.base (Equiv.u2 guard (.test .zero) finish))
      (EquivBA.symm (test_seq_as_ite (.not guard) finish))
  have hlift := guardedFold_fallback_congr
    (branches.map (fun branch =>
      (BExp.and guard branch.1, branch.2))) hterminal
  have hpartition' : EquivBA
      (.ite guard (guardedFold branches (.test .zero)) finish)
      (guardedFold (branches.map (fun branch =>
        (BExp.and guard branch.1, branch.2)))
        (.ite guard (.test .zero) finish)) := by
    simpa only [guardedFold, List.map_nil, List.append_nil] using hpartition
  have hshape : transitionBranches
      (loopInitialized guard body).initTrans sol =
      branches.map (fun branch =>
        (BExp.and guard branch.1, branch.2)) := by
    dsimp only [loopInitialized, branches, transitionBranches]
    induction body.initTrans with
    | nil => rfl
    | cons transition transitions ih =>
        obtain ⟨transitionGuard, action, target⟩ := transition
        simp only [List.map_cons, ih]
  dsimp only [initRHSParam]
  rw [hshape]
  exact EquivBA.symm (EquivBA.trans hpartition' hlift)

theorem eqRHSParam_finish_congr
    (aut : GSystem S A T) (sol : S → Exp A T) (state : S)
    {left right : Exp A T} (hfinish : EquivBA left right) :
    EquivBA (eqRHSParam aut sol left state)
      (eqRHSParam aut sol right state) := by
  exact guardedFold_fallback_congr _
    (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hfinish)

/-- The canonical loop labelling has the expected feedback value by W1 unfolding.
    This proves existence; W3 is reserved for proving that every other solution agrees. -/
theorem loopStandard_feedback
    (guard : BExp T) (body : InitializedGAut S A T)
    (standard : S → Exp A T) (program : Exp A T)
    (hparam : ParametricThompsonBA body standard program)
    (hstandard : StandardSolvesBA body standard)
    (hdisjoint : InitHaltDisjointBA body standard)
    (htargets : InitTargetsListed body) :
    let loopProgram := Exp.wh guard program
    let loopStandard := fun state => Exp.seq (standard state) loopProgram
    EquivBA (initRHSParam (loopInitialized guard body) loopStandard (.test .one))
      loopProgram := by
  dsimp
  let loopProgram := Exp.wh guard program
  let loopStandard := fun state => Exp.seq (standard state) loopProgram
  let standardDerivative := guardedFold
    (transitionBranches body.initTrans standard) (.test .zero)
  have hbodyContinuation := hstandard.withContinuation body standard loopProgram
  have hfactor := initialDerivative_factor body standard loopStandard loopProgram
    hparam.states hbodyContinuation htargets
  have hfeedback := loopInitial_feedback guard body loopStandard (.test .one)
  have hnormalize : EquivBA loopProgram (.wh guard standardDerivative) :=
    initialized_productiveLoop guard body standard program
      hparam hstandard hdisjoint
  exact EquivBA.trans hfeedback
    (EquivBA.trans
      (EquivBA.ite_c hfactor (EquivBA.base (Equiv.refl _)))
      (EquivBA.trans
        (EquivBA.ite_c
          (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hnormalize)
          (EquivBA.base (Equiv.refl _)))
        (EquivBA.trans
          (EquivBA.symm (EquivBA.base (Equiv.w1 guard standardDerivative)))
          (EquivBA.symm hnormalize))))

theorem loopInitialized_standardSolves
    (guard : BExp T) (body : InitializedGAut S A T)
    (standard : S → Exp A T) (program : Exp A T)
    (hparam : ParametricThompsonBA body standard program)
    (hstandard : StandardSolvesBA body standard)
    (hdisjoint : InitHaltDisjointBA body standard)
    (htargets : InitTargetsListed body) :
    StandardSolvesBA (loopInitialized guard body)
      (fun state => .seq (standard state) (.wh guard program)) := by
  let loopProgram := Exp.wh guard program
  let loopStandard := fun state => Exp.seq (standard state) loopProgram
  have hbodyContinuation := hstandard.withContinuation body standard loopProgram
  have hfeedback : EquivBA
      (initRHSParam (loopInitialized guard body) loopStandard (.test .one))
      loopProgram :=
    loopStandard_feedback guard body standard program
      hparam hstandard hdisjoint htargets
  intro state hstate
  exact EquivBA.trans (hbodyContinuation state hstate)
    (EquivBA.trans
      (eqRHSParam_finish_congr body.core loopStandard state
        (EquivBA.symm hfeedback))
      (eqRHSParam_loopInitialized guard body loopStandard (.test .one) state))

/-- The single feedback value of a Thompson loop is forced by the original finite W3
    rule. No simultaneous-system uniqueness principle is used. -/
theorem loopFeedback_canonical
    (guard : BExp T) (body : InitializedGAut S A T)
    (standard sol : S → Exp A T) (program finish : Exp A T)
    (hparam : ParametricThompsonBA body standard program)
    (hstandard : StandardSolvesBA body standard)
    (hdisjoint : InitHaltDisjointBA body standard)
    (htargets : InitTargetsListed body)
    (hloopSol : ParamSolvesBA (loopInitialized guard body).core sol finish) :
    EquivBA (initRHSParam (loopInitialized guard body) sol finish)
      (.seq (.wh guard program) finish) := by
  let feedback := initRHSParam (loopInitialized guard body) sol finish
  let solDerivative := guardedFold
    (transitionBranches body.initTrans sol) (.test .zero)
  let standardDerivative := guardedFold
    (transitionBranches body.initTrans standard) (.test .zero)
  have hbodySol : ParamSolvesBA body.core sol feedback := by
    intro state hstate
    have hloopEq := hloopSol state hstate
    exact EquivBA.trans hloopEq
      (EquivBA.symm
        (eqRHSParam_loopInitialized guard body sol finish state))
  have hfeedback : EquivBA feedback
      (.ite guard solDerivative finish) :=
    loopInitial_feedback guard body sol finish
  have hfactor : EquivBA solDerivative
      (.seq standardDerivative feedback) :=
    initialDerivative_factor body standard sol feedback
      hparam.states hbodySol htargets
  have hequation : EquivBA feedback
      (.ite guard (.seq standardDerivative feedback) finish) :=
    EquivBA.trans hfeedback
      (EquivBA.ite_c hfactor (EquivBA.base (Equiv.refl _)))
  have hproductive : EquivBA
      (.test (E standardDerivative) : Exp A T) (.test .zero) :=
    transitionActionFold_productiveBA body.initTrans standard
  have hw3 : EquivBA feedback
      (.seq (.wh guard standardDerivative) finish) :=
    EquivBA.w3_ba hproductive hequation
  have hnormalize : EquivBA (.wh guard program)
      (.wh guard standardDerivative) :=
    initialized_productiveLoop guard body standard program
      hparam hstandard hdisjoint
  exact EquivBA.trans hw3
    (EquivBA.seq_c (EquivBA.symm hnormalize)
      (EquivBA.base (Equiv.refl finish)))

/-- Iteration preserves the strengthened Thompson uniqueness invariant. The standard
    expression at a body state is its body continuation followed by the whole loop. -/
theorem ParametricThompsonBA.loop
    (guard : BExp T) (body : InitializedGAut S A T)
    (standard : S → Exp A T) (program : Exp A T)
    (hparam : ParametricThompsonBA body standard program)
    (hstandard : StandardSolvesBA body standard)
    (hdisjoint : InitHaltDisjointBA body standard)
    (htargets : InitTargetsListed body) :
    ParametricThompsonBA (loopInitialized guard body)
      (fun state => .seq (standard state) (.wh guard program))
      (.wh guard program) := by
  constructor
  · intro finish sol hloopSol state hstate
    let feedback := initRHSParam (loopInitialized guard body) sol finish
    have hbodySol : ParamSolvesBA body.core sol feedback := by
      intro item hitem
      have hloopEq := hloopSol item hitem
      exact EquivBA.trans hloopEq
        (EquivBA.symm
          (eqRHSParam_loopInitialized guard body sol finish item))
    have hstateCanonical := hparam.states feedback sol hbodySol state hstate
    have hfeedback := loopFeedback_canonical guard body standard sol program finish
      hparam hstandard hdisjoint htargets hloopSol
    exact EquivBA.trans hstateCanonical
      (EquivBA.trans
        (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hfeedback)
        (EquivBA.symm
          (EquivBA.base
            (Equiv.s1 (standard state) (.wh guard program) finish))))
  · intro finish sol hloopSol
    exact loopFeedback_canonical guard body standard sol program finish
      hparam hstandard hdisjoint htargets hloopSol

theorem loopInitialized_initTargets
    (guard : BExp T) (body : InitializedGAut S A T)
    (htargets : InitTargetsListed body) :
    InitTargetsListed (loopInitialized guard body) := by
  intro transition htransition
  simp only [loopInitialized, List.mem_map] at htransition
  obtain ⟨original, horiginal, rfl⟩ := htransition
  exact htargets original horiginal

theorem loopInitialized_initDisjoint
    (guard : BExp T) (body : InitializedGAut S A T)
    (standard : S → Exp A T) (program : Exp A T) :
    InitHaltDisjointBA (loopInitialized guard body)
      (fun state => .seq (standard state) (.wh guard program)) := by
  intro branch hbranch X W x
  simp only [loopInitialized, transitionBranches, List.mem_map] at hbranch
  obtain ⟨transition, htransition, rfl⟩ := hbranch
  obtain ⟨original, horiginal, rfl⟩ := htransition
  change ((bval W guard x && bval W original.1 x) && !bval W guard x) = false
  cases bval W guard x <;> simp

/-- The complete recursive certificate is closed under iteration. -/
theorem ThompsonCertificateBA.loop
    (guard : BExp T) (body : InitializedGAut S A T)
    (standard : S → Exp A T) (program : Exp A T)
    (hbody : ThompsonCertificateBA body standard program) :
    ThompsonCertificateBA (loopInitialized guard body)
      (fun state => .seq (standard state) (.wh guard program))
      (.wh guard program) := by
  constructor
  · exact hbody.parametric.loop guard body standard program
      hbody.standardSolves hbody.initDisjoint hbody.initTargets
  · exact loopInitialized_standardSolves guard body standard program
      hbody.parametric hbody.standardSolves hbody.initDisjoint hbody.initTargets
  · exact loopInitialized_initDisjoint guard body standard program
  · exact loopInitialized_initTargets guard body hbody.initTargets

/-- Internal system of Thompson sequencing. Successful exits from a left state enter the
    right initial dynamics; right states are inherited unchanged. -/
def seqGSystem (left : GSystem S₁ A T)
    (right : InitializedGAut S₂ A T) : GSystem (Sum S₁ S₂) A T where
  states := left.states.map Sum.inl ++ right.core.states.map Sum.inr
  hlt
    | .inl state => .and (left.hlt state) right.initHlt
    | .inr state => right.core.hlt state
  trans
    | .inl state =>
        (left.trans state).map (fun transition =>
          (transition.1, transition.2.1, Sum.inl transition.2.2)) ++
        right.initTrans.map (fun transition =>
          (BExp.and (left.hlt state) transition.1,
            transition.2.1, Sum.inr transition.2.2))
    | .inr state => (right.core.trans state).map (fun transition =>
        (transition.1, transition.2.1, Sum.inr transition.2.2))

/-- Full initialized Thompson construction for sequential composition. -/
def seqInitialized (left : InitializedGAut S₁ A T)
    (right : InitializedGAut S₂ A T) : InitializedGAut (Sum S₁ S₂) A T where
  core := seqGSystem left.core right
  initHlt := .and left.initHlt right.initHlt
  initTrans :=
    left.initTrans.map (fun transition =>
      (transition.1, transition.2.1, Sum.inl transition.2.2)) ++
    right.initTrans.map (fun transition =>
      (BExp.and left.initHlt transition.1,
        transition.2.1, Sum.inr transition.2.2))

theorem seqInitialized_coreStructural
    (left : InitializedGAut S₁ A T) (right : InitializedGAut S₂ A T)
    (rightStandard : S₂ → Exp A T)
    (hleft : CoreStructural left) (hright : CoreStructural right)
    (hrightTargets : InitTargetsListed right)
    (hrightDisjoint : InitHaltDisjointBA right rightStandard) :
    CoreStructural (seqInitialized left right) := by
  constructor
  · intro state hstate transition htransition
    cases state with
    | inl item =>
        have hitem : item ∈ left.core.states := by
          change Sum.inl item ∈ left.core.states.map Sum.inl ++
            right.core.states.map Sum.inr at hstate
          simpa using hstate
        simp only [seqInitialized, seqGSystem, List.mem_append,
          List.mem_map] at htransition
        rcases htransition with htransition | htransition
        · obtain ⟨original, horiginal, rfl⟩ := htransition
          exact mem_append_left_direct (mem_map_direct Sum.inl
            (hleft.targets item hitem original horiginal))
        · obtain ⟨original, horiginal, rfl⟩ := htransition
          exact mem_append_right_direct _ (mem_map_direct Sum.inr
            (hrightTargets original horiginal))
    | inr item =>
        have hitem : item ∈ right.core.states := by
          change Sum.inr item ∈ left.core.states.map Sum.inl ++
            right.core.states.map Sum.inr at hstate
          simpa using hstate
        simp only [seqInitialized, seqGSystem, List.mem_map] at htransition
        obtain ⟨original, horiginal, rfl⟩ := htransition
        exact mem_append_right_direct _ (mem_map_direct Sum.inr
          (hright.targets item hitem original horiginal))
  · intro state hstate transition htransition X W x
    cases state with
    | inl item =>
        have hitem : item ∈ left.core.states := by
          change Sum.inl item ∈ left.core.states.map Sum.inl ++
            right.core.states.map Sum.inr at hstate
          simpa using hstate
        simp only [seqInitialized, seqGSystem, List.mem_append,
          List.mem_map] at htransition
        rcases htransition with htransition | htransition
        · obtain ⟨original, horiginal, rfl⟩ := htransition
          have hd := hleft.disjoint item hitem original horiginal X W x
          change (bval W original.1 x &&
            (bval W (left.core.hlt item) x && bval W right.initHlt x)) = false
          change (bval W original.1 x && bval W (left.core.hlt item) x) = false at hd
          rw [← Bool.and_assoc, hd]
          rfl
        · obtain ⟨original, horiginal, rfl⟩ := htransition
          have hbranch :
              (original.1, Exp.seq (.act original.2.1)
                (rightStandard original.2.2)) ∈
                transitionBranches right.initTrans rightStandard :=
            List.mem_map.mpr ⟨original, horiginal, rfl⟩
          have hd := hrightDisjoint _ hbranch X W x
          change ((bval W (left.core.hlt item) x && bval W original.1 x) &&
            (bval W (left.core.hlt item) x && bval W right.initHlt x)) = false
          cases hl : bval W (left.core.hlt item) x
          · simp [hl]
          · simpa only [hl, Bool.true_and] using hd
    | inr item =>
        have hitem : item ∈ right.core.states := by
          change Sum.inr item ∈ left.core.states.map Sum.inl ++
            right.core.states.map Sum.inr at hstate
          simpa using hstate
        simp only [seqInitialized, seqGSystem, List.mem_map] at htransition
        obtain ⟨original, horiginal, rfl⟩ := htransition
        exact hright.disjoint item hitem original horiginal X W x

/-- Exact equation bridge for a left state of a sequentially connected Thompson system.
    The flattened combined dynamics is the original left equation parameterized by the
    evaluated right initial pseudostate. -/
theorem eqRHSParam_seqGSystem_inl
    (left : GSystem S₁ A T) (right : InitializedGAut S₂ A T)
    (sol : Sum S₁ S₂ → Exp A T) (finish : Exp A T) (state : S₁) :
    EquivBA
      (eqRHSParam left (fun item => sol (.inl item))
        (initRHSParam right (fun item => sol (.inr item)) finish) state)
      (eqRHSParam (seqGSystem left right) sol finish (.inl state)) := by
  let leftBranches := transitionBranches (left.trans state)
    (fun item => sol (.inl item))
  let rightBranches := transitionBranches right.initTrans
    (fun item => sol (.inr item))
  have hconnect := guardedFold_connect (left.hlt state)
    leftBranches rightBranches (paramFallback right.initHlt finish)
  have hterminal := ite_paramFallback_zero
    (left.hlt state) right.initHlt finish
  have hlift := guardedFold_fallback_congr
    (leftBranches ++ rightBranches.map (fun branch =>
      (BExp.and (left.hlt state) branch.1, branch.2))) hterminal
  have hshape :
      transitionBranches ((seqGSystem left right).trans (.inl state)) sol =
        leftBranches ++ rightBranches.map (fun branch =>
          (BExp.and (left.hlt state) branch.1, branch.2)) := by
    dsimp only [seqGSystem, leftBranches, rightBranches, transitionBranches]
    simp only [List.map_append, List.map_map, Function.comp_apply]
    congr 1
  exact EquivBA.trans
    (by
      dsimp only [eqRHSParam, initRHSParam]
      exact hconnect)
    (EquivBA.trans hlift
      (by
        dsimp only [eqRHSParam]
        rw [hshape]
        exact EquivBA.base (Equiv.refl _)))

/-- **Sequencing case of Pham's parameterized uniqueness induction.** The right system
    is solved first with `finish`; its initial evaluation becomes the temporary ending
    for the left system. -/
theorem ParametricCanonicalBA.seq
    {left : GSystem S₁ A T} {right : InitializedGAut S₂ A T}
    {leftStandard : S₁ → Exp A T} {rightStandard : S₂ → Exp A T}
    {rightProgram : Exp A T}
    (hleft : ParametricCanonicalBA left leftStandard)
    (hright : ParametricCanonicalBA right.core rightStandard)
    (hrightInit : ParametricInitialBA right rightProgram) :
    ParametricCanonicalBA (seqGSystem left right)
      (fun state => match state with
        | .inl item => .seq (leftStandard item) rightProgram
        | .inr item => rightStandard item) := by
  intro finish sol hsol state hstate
  have hsolRight : ParamSolvesBA right.core
      (fun item => sol (.inr item)) finish := by
    intro item hitem
    have hsum : Sum.inr item ∈ (seqGSystem left right).states :=
      mem_append_right_direct _ (mem_map_direct Sum.inr hitem)
    have heq := hsol (.inr item) hsum
    simpa only [eqRHSParam, seqGSystem, transitionBranches, List.map_map,
      Function.comp_apply] using heq
  let ending := initRHSParam right (fun item => sol (.inr item)) finish
  have hending : EquivBA ending (.seq rightProgram finish) :=
    hrightInit finish (fun item => sol (.inr item)) hsolRight
  have hsolLeft : ParamSolvesBA left
      (fun item => sol (.inl item)) ending := by
    intro item hitem
    have hsum : Sum.inl item ∈ (seqGSystem left right).states :=
      mem_append_left_direct (mem_map_direct Sum.inl hitem)
    exact EquivBA.trans (hsol (.inl item) hsum)
      (EquivBA.symm
        (eqRHSParam_seqGSystem_inl left right sol finish item))
  cases state with
  | inl item =>
      have hitem : item ∈ left.states := by
        change Sum.inl item ∈
          left.states.map Sum.inl ++ right.core.states.map Sum.inr at hstate
        simpa using hstate
      exact EquivBA.trans
        (hleft ending (fun source => sol (.inl source)) hsolLeft item hitem)
        (EquivBA.trans
          (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hending)
          (EquivBA.symm
            (EquivBA.base (Equiv.s1 (leftStandard item) rightProgram finish))))
  | inr item =>
      have hitem : item ∈ right.core.states := by
        change Sum.inr item ∈
          left.states.map Sum.inl ++ right.core.states.map Sum.inr at hstate
        simpa using hstate
      exact hright finish (fun source => sol (.inr source)) hsolRight item hitem

/-- Full sequencing constructor for the strengthened Thompson induction package. -/
theorem ParametricThompsonBA.seq
    {left : InitializedGAut S₁ A T} {right : InitializedGAut S₂ A T}
    {leftStandard : S₁ → Exp A T} {rightStandard : S₂ → Exp A T}
    {leftProgram rightProgram : Exp A T}
    (hleft : ParametricThompsonBA left leftStandard leftProgram)
    (hright : ParametricThompsonBA right rightStandard rightProgram) :
    ParametricThompsonBA (seqInitialized left right)
      (fun state => match state with
        | .inl item => .seq (leftStandard item) rightProgram
        | .inr item => rightStandard item)
      (.seq leftProgram rightProgram) := by
  constructor
  · exact hleft.states.seq hright.states hright.initial
  · intro finish sol hsol
    have hsolRight : ParamSolvesBA right.core
        (fun item => sol (.inr item)) finish := by
      intro item hitem
      have hsum : Sum.inr item ∈ (seqInitialized left right).core.states :=
        mem_append_right_direct _ (mem_map_direct Sum.inr hitem)
      have heq := hsol (.inr item) hsum
      simpa only [seqInitialized, eqRHSParam, seqGSystem, transitionBranches,
        List.map_map, Function.comp_apply] using heq
    let ending := initRHSParam right (fun item => sol (.inr item)) finish
    have hending : EquivBA ending (.seq rightProgram finish) :=
      hright.initial finish (fun item => sol (.inr item)) hsolRight
    have hsolLeft : ParamSolvesBA left.core
        (fun item => sol (.inl item)) ending := by
      intro item hitem
      have hsum : Sum.inl item ∈ (seqInitialized left right).core.states :=
        mem_append_left_direct (mem_map_direct Sum.inl hitem)
      exact EquivBA.trans (hsol (.inl item) hsum)
        (EquivBA.symm
          (eqRHSParam_seqGSystem_inl left.core right sol finish item))
    have hleftInitial := hleft.initial ending
      (fun item => sol (.inl item)) hsolLeft
    let leftBranches := transitionBranches left.initTrans
      (fun item => sol (.inl item))
    let rightBranches := transitionBranches right.initTrans
      (fun item => sol (.inr item))
    have hconnect := guardedFold_connect left.initHlt leftBranches rightBranches
      (paramFallback right.initHlt finish)
    have hterminal := ite_paramFallback_zero left.initHlt right.initHlt finish
    have hlift := guardedFold_fallback_congr
      (leftBranches ++ rightBranches.map (fun branch =>
        (BExp.and left.initHlt branch.1, branch.2))) hterminal
    have hshape : transitionBranches (seqInitialized left right).initTrans sol =
        leftBranches ++ rightBranches.map (fun branch =>
          (BExp.and left.initHlt branch.1, branch.2)) := by
      dsimp only [seqInitialized, leftBranches, rightBranches, transitionBranches]
      simp only [List.map_append, List.map_map, Function.comp_apply]
      congr 1
    have hflat : EquivBA (initRHSParam (seqInitialized left right) sol finish)
        (initRHSParam left (fun item => sol (.inl item)) ending) := by
      exact EquivBA.trans
        (by
          dsimp only [initRHSParam]
          rw [hshape]
          exact EquivBA.symm hlift)
        (by
          dsimp only [initRHSParam, ending]
          exact EquivBA.symm hconnect)
    exact EquivBA.trans hflat
      (EquivBA.trans hleftInitial
        (EquivBA.trans
          (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hending)
          (EquivBA.symm
            (EquivBA.base (Equiv.s1 leftProgram rightProgram finish)))))

theorem seqInitialized_standardSolves
    {left : InitializedGAut S₁ A T} {right : InitializedGAut S₂ A T}
    {leftStandard : S₁ → Exp A T} {rightStandard : S₂ → Exp A T}
    {rightProgram : Exp A T}
    (hleft : StandardSolvesBA left leftStandard)
    (hright : StandardSolvesBA right rightStandard)
    (hrightInitial : ParametricInitialBA right rightProgram) :
    StandardSolvesBA (seqInitialized left right)
      (fun state => match state with
        | .inl item => .seq (leftStandard item) rightProgram
        | .inr item => rightStandard item) := by
  let combinedStandard : Sum S₁ S₂ → Exp A T := fun state => match state with
    | .inl item => .seq (leftStandard item) rightProgram
    | .inr item => rightStandard item
  have hrightEnding : EquivBA
      (initRHSParam right rightStandard (.test .one)) rightProgram :=
    EquivBA.trans (hrightInitial (.test .one) rightStandard hright)
      (EquivBA.base (Equiv.s5 rightProgram))
  have hleftContinuation := hleft.withContinuation left leftStandard rightProgram
  intro state hstate
  cases state with
  | inl item =>
      have hitem : item ∈ left.core.states := by
        change Sum.inl item ∈ left.core.states.map Sum.inl ++
          right.core.states.map Sum.inr at hstate
        simpa using hstate
      exact EquivBA.trans (hleftContinuation item hitem)
        (EquivBA.trans
          (eqRHSParam_finish_congr left.core
            (fun source => combinedStandard (.inl source)) item
            (EquivBA.symm hrightEnding))
          (eqRHSParam_seqGSystem_inl left.core right combinedStandard
            (.test .one) item))
  | inr item =>
      have hitem : item ∈ right.core.states := by
        change Sum.inr item ∈ left.core.states.map Sum.inl ++
          right.core.states.map Sum.inr at hstate
        simpa using hstate
      simpa only [seqInitialized, eqRHSParam, seqGSystem, transitionBranches,
        List.map_map, Function.comp_apply] using hright item hitem

theorem seqInitialized_initTargets
    (left : InitializedGAut S₁ A T) (right : InitializedGAut S₂ A T)
    (hleft : InitTargetsListed left) (hright : InitTargetsListed right) :
    InitTargetsListed (seqInitialized left right) := by
  intro transition htransition
  simp only [seqInitialized, List.mem_append, List.mem_map] at htransition
  rcases htransition with htransition | htransition
  · obtain ⟨original, horiginal, rfl⟩ := htransition
    exact mem_append_left_direct (mem_map_direct Sum.inl (hleft original horiginal))
  · obtain ⟨original, horiginal, rfl⟩ := htransition
    exact mem_append_right_direct _
      (mem_map_direct Sum.inr (hright original horiginal))

theorem seqInitialized_initDisjoint
    (left : InitializedGAut S₁ A T) (right : InitializedGAut S₂ A T)
    (leftStandard : S₁ → Exp A T) (rightStandard : S₂ → Exp A T)
    (rightProgram : Exp A T)
    (hleft : InitHaltDisjointBA left leftStandard)
    (hright : InitHaltDisjointBA right rightStandard) :
    InitHaltDisjointBA (seqInitialized left right)
      (fun state => match state with
        | .inl item => .seq (leftStandard item) rightProgram
        | .inr item => rightStandard item) := by
  intro branch hbranch X W x
  simp only [seqInitialized, transitionBranches, List.mem_map] at hbranch
  obtain ⟨transition, htransition, rfl⟩ := hbranch
  simp only [List.mem_append, List.mem_map] at htransition
  rcases htransition with htransition | htransition
  · obtain ⟨original, horiginal, rfl⟩ := htransition
    have hmember :
        (original.1, Exp.seq (.act original.2.1)
          (leftStandard original.2.2)) ∈
          transitionBranches left.initTrans leftStandard :=
      List.mem_map.mpr ⟨original, horiginal, rfl⟩
    have hd := hleft _ hmember X W x
    change (bval W original.1 x &&
      (bval W left.initHlt x && bval W right.initHlt x)) = false
    change (bval W original.1 x && bval W left.initHlt x) = false at hd
    rw [← Bool.and_assoc, hd]
    rfl
  · obtain ⟨original, horiginal, rfl⟩ := htransition
    have hmember :
        (original.1, Exp.seq (.act original.2.1)
          (rightStandard original.2.2)) ∈
          transitionBranches right.initTrans rightStandard :=
      List.mem_map.mpr ⟨original, horiginal, rfl⟩
    have hd := hright _ hmember X W x
    change ((bval W left.initHlt x && bval W original.1 x) &&
      (bval W left.initHlt x && bval W right.initHlt x)) = false
    cases hl : bval W left.initHlt x
    · simp [hl]
    · simpa only [hl, Bool.true_and] using hd

theorem ThompsonCertificateBA.seq
    {left : InitializedGAut S₁ A T} {right : InitializedGAut S₂ A T}
    {leftStandard : S₁ → Exp A T} {rightStandard : S₂ → Exp A T}
    {leftProgram rightProgram : Exp A T}
    (hleft : ThompsonCertificateBA left leftStandard leftProgram)
    (hright : ThompsonCertificateBA right rightStandard rightProgram) :
    ThompsonCertificateBA (seqInitialized left right)
      (fun state => match state with
        | .inl item => .seq (leftStandard item) rightProgram
        | .inr item => rightStandard item)
      (.seq leftProgram rightProgram) := by
  constructor
  · exact hleft.parametric.seq hright.parametric
  · exact seqInitialized_standardSolves hleft.standardSolves
      hright.standardSolves hright.parametric.initial
  · exact seqInitialized_initDisjoint left right leftStandard rightStandard
      rightProgram hleft.initDisjoint hright.initDisjoint
  · exact seqInitialized_initTargets left right hleft.initTargets hright.initTargets

/-! ## Certified Thompson translation for every GKAT expression -/

/-- A Thompson automaton carries its expression-indexed standard labelling and the full
    finite-axiom certificate. The state type is allowed to vary with syntax. -/
structure CertifiedThompson (A T : Type) (program : Exp A T) where
  State : Type
  aut : InitializedGAut State A T
  standard : State → Exp A T
  certificate : ThompsonCertificateBA aut standard program
  structural : CoreStructural aut

/-- Package a certificate while letting Lean infer the standard labelling exactly once.
    This avoids dependent eta-conversion issues when rebuilding the same labelling. -/
def CertifiedThompson.ofCertificate {S A T : Type} {program : Exp A T}
    {aut : InitializedGAut S A T} {standard : S → Exp A T}
    (certificate : ThompsonCertificateBA aut standard program)
    (structural : CoreStructural aut) :
    CertifiedThompson A T program where
  State := S
  aut := aut
  standard := standard
  certificate := certificate
  structural := structural

def CertifiedThompson.ite (guard : BExp T)
    {leftProgram rightProgram : Exp A T}
    (left : CertifiedThompson A T leftProgram)
    (right : CertifiedThompson A T rightProgram) :
    CertifiedThompson A T (.ite guard leftProgram rightProgram) :=
  CertifiedThompson.ofCertificate
    (left.certificate.ite guard right.certificate)
    (iteInitialized_coreStructural guard left.aut right.aut
      left.structural right.structural)

def CertifiedThompson.seq
    {leftProgram rightProgram : Exp A T}
    (left : CertifiedThompson A T leftProgram)
    (right : CertifiedThompson A T rightProgram) :
    CertifiedThompson A T (.seq leftProgram rightProgram) :=
  CertifiedThompson.ofCertificate (left.certificate.seq right.certificate)
    (seqInitialized_coreStructural left.aut right.aut right.standard
      left.structural right.structural right.certificate.initTargets
      right.certificate.initDisjoint)

def CertifiedThompson.loop (guard : BExp T) {bodyProgram : Exp A T}
    (body : CertifiedThompson A T bodyProgram) :
    CertifiedThompson A T (.wh guard bodyProgram) :=
  CertifiedThompson.ofCertificate
    (body.certificate.loop guard body.aut body.standard bodyProgram)
    (loopInitialized_coreStructural guard body.aut body.structural
      body.certificate.initTargets)

/-- Structural occurrence-based Thompson construction, certified constructor by
    constructor. This is the machine-checked version of Pham's syntax induction. -/
def certifiedThompson (A T : Type) :
    (program : Exp A T) → CertifiedThompson A T program
  | .test test => {
      State := Empty
      aut := thompsonTest test
      standard := fun state => nomatch state
      certificate := thompsonTest_certificate test
      structural := thompsonTest_coreStructural test
    }
  | .act action => {
      State := Unit
      aut := thompsonAction action
      standard := fun _ => .test .one
      certificate := thompsonAction_certificate action
      structural := thompsonAction_coreStructural action
    }
  | .ite guard leftProgram rightProgram =>
      CertifiedThompson.ite guard
        (certifiedThompson A T leftProgram)
        (certifiedThompson A T rightProgram)
  | .seq leftProgram rightProgram =>
      CertifiedThompson.seq
        (certifiedThompson A T leftProgram)
        (certifiedThompson A T rightProgram)
  | .wh guard bodyProgram =>
      CertifiedThompson.loop guard (certifiedThompson A T bodyProgram)

/-- Every GKAT expression therefore has a Thompson equation system whose solutions are
    provably unique using the finite axioms alone. -/
theorem certifiedThompson_solution_unique (program : Exp A T)
    (left right : (certifiedThompson A T program).State → Exp A T)
    (hleft : ThompsonSolvesBA (certifiedThompson A T program).aut.core left)
    (hright : ThompsonSolvesBA (certifiedThompson A T program).aut.core right) :
    ∀ state ∈ (certifiedThompson A T program).aut.core.states,
      EquivBA (left state) (right state) :=
  (certifiedThompson A T program).certificate.parametric.states.unique hleft hright

theorem certifiedThompson_initial_canonical (program finish : Exp A T)
    (sol : (certifiedThompson A T program).State → Exp A T)
    (hsol : ParamSolvesBA (certifiedThompson A T program).aut.core sol finish) :
    EquivBA (initRHSParam (certifiedThompson A T program).aut sol finish)
      (.seq program finish) :=
  (certifiedThompson A T program).certificate.parametric.initial finish sol hsol

theorem certifiedThompson_initial_recovers_program (program : Exp A T) :
    EquivBA
      (initRHSParam (certifiedThompson A T program).aut
        (certifiedThompson A T program).standard (.test .one))
      program := by
  exact EquivBA.trans
    (certifiedThompson_initial_canonical program (.test .one)
      (certifiedThompson A T program).standard
      (certifiedThompson A T program).certificate.standardSolves)
    (EquivBA.base (Equiv.s5 program))

/-! ## Bridge to ordinary pointed `GAut`s and the quotient infrastructure -/

/-- Materialize the initial pseudostate as `none`; internal Thompson states become
    `some state`. This makes the occurrence-based construction compatible with the
    repository's existing homomorphism and behavioral-quotient machinery. -/
def InitializedGAut.toGAut (aut : InitializedGAut S A T) :
    GAut (Option S) A T where
  states := none :: aut.core.states.map some
  hlt
    | none => aut.initHlt
    | some state => aut.core.hlt state
  trans
    | none => aut.initTrans.map (fun transition =>
        (transition.1, transition.2.1, some transition.2.2))
    | some state => aut.core.trans state |>.map (fun transition =>
        (transition.1, transition.2.1, some transition.2.2))
  start := none

theorem firstMatch_none_of_halt_disjoint
    {X : Type}
    (W : T → X → Bool) (x : X) (halt : BExp T)
    (transitions : List (BExp T × A × S))
    (hdisjoint : ∀ transition ∈ transitions,
      bval W (.and transition.1 halt) x = false)
    (hhalt : bval W halt x = true) :
    firstMatch W x transitions = none := by
  cases hmatch : firstMatch W x transitions with
  | none => rfl
  | some output =>
      obtain ⟨action, target⟩ := output
      obtain ⟨guard, hmember, hguard⟩ :=
        firstMatch_some_mem W x transitions hmatch
      have hd := hdisjoint (guard, action, target) hmember
      change (bval W guard x && bval W halt x) = false at hd
      rw [hguard, hhalt] at hd
      exact Bool.noConfusion hd

theorem firstMatch_target_listed
    {X : Type}
    (W : T → X → Bool) (x : X)
    (transitions : List (BExp T × A × S)) (states : List S)
    (htargets : ∀ transition ∈ transitions, transition.2.2 ∈ states)
    {action : A} {target : S}
    (hmatch : firstMatch W x transitions = some (action, target)) :
    target ∈ states := by
  obtain ⟨guard, hmember, hguard⟩ :=
    firstMatch_some_mem W x transitions hmatch
  exact htargets (guard, action, target) hmember

theorem InitializedGAut.toGAut_uniformWF
    (aut : InitializedGAut S A T) (standard : S → Exp A T)
    (hcoreTargets : CoreTargetsListed aut)
    (hcoreDisjoint : CoreHaltDisjoint aut)
    (hinitTargets : InitTargetsListed aut)
    (hinitDisjoint : InitHaltDisjointBA aut standard) :
    UniformWF aut.toGAut := by
  intro X W
  constructor
  · intro state hstate x hhalt
    cases state with
    | none =>
        change firstMatch W x
          (aut.initTrans.map (fun transition =>
            (transition.1, transition.2.1, some transition.2.2))) = none
        apply firstMatch_none_of_halt_disjoint W x aut.initHlt
        · intro transition htransition
          simp only [List.mem_map] at htransition
          obtain ⟨original, horiginal, rfl⟩ := htransition
          have hbranch :
              (original.1, Exp.seq (.act original.2.1)
                (standard original.2.2)) ∈
                transitionBranches aut.initTrans standard :=
            List.mem_map.mpr ⟨original, horiginal, rfl⟩
          exact hinitDisjoint _ hbranch X W x
        · exact hhalt
    | some item =>
        have hitem : item ∈ aut.core.states := by
          change some item ∈ none :: aut.core.states.map some at hstate
          simpa using hstate
        change firstMatch W x
          ((aut.core.trans item).map (fun transition =>
            (transition.1, transition.2.1, some transition.2.2))) = none
        apply firstMatch_none_of_halt_disjoint W x (aut.core.hlt item)
        · intro transition htransition
          simp only [List.mem_map] at htransition
          obtain ⟨original, horiginal, rfl⟩ := htransition
          exact hcoreDisjoint item hitem original horiginal X W x
        · exact hhalt
  · intro state hstate x action target hstep
    cases state with
    | none =>
        change firstMatch W x
          (aut.initTrans.map (fun transition =>
            (transition.1, transition.2.1, some transition.2.2))) =
          some (action, target) at hstep
        have htarget : target ∈ aut.core.states.map some :=
          firstMatch_target_listed W x _ _ (by
            intro transition htransition
            obtain ⟨original, horiginal, rfl⟩ := List.mem_map.mp htransition
            exact mem_map_direct some (hinitTargets original horiginal)) hstep
        exact List.Mem.tail none htarget
    | some item =>
        have hitem : item ∈ aut.core.states := by
          change some item ∈ none :: aut.core.states.map some at hstate
          simpa using hstate
        change firstMatch W x
          ((aut.core.trans item).map (fun transition =>
            (transition.1, transition.2.1, some transition.2.2))) =
          some (action, target) at hstep
        have htarget : target ∈ aut.core.states.map some :=
          firstMatch_target_listed W x _ _ (by
            intro transition htransition
            obtain ⟨original, horiginal, rfl⟩ := List.mem_map.mp htransition
            exact mem_map_direct some
              (hcoreTargets item hitem original horiginal)) hstep
        exact List.Mem.tail none htarget

def initializedStandard (program : Exp A T) (standard : S → Exp A T) :
    Option S → Exp A T
  | none => program
  | some state => standard state

theorem transitionBranches_option_map
    (transitions : List (BExp T × A × S))
    (sol : Option S → Exp A T) :
    transitionBranches
      (transitions.map (fun transition =>
        (transition.1, transition.2.1, some transition.2.2)))
      sol =
    transitionBranches transitions (fun state => sol (some state)) := by
  induction transitions with
  | nil => rfl
  | cons transition transitions ih =>
      obtain ⟨guard, action, target⟩ := transition
      change
        (guard, Exp.seq (.act action) (sol (some target))) ::
            transitionBranches
              (transitions.map (fun item =>
                (item.1, item.2.1, some item.2.2)))
              sol =
          (guard, Exp.seq (.act action) (sol (some target))) ::
            transitionBranches transitions (fun state => sol (some state))
      exact congrArg (List.cons
        (guard, Exp.seq (.act action) (sol (some target)))) ih

/-- A full Thompson certificate induces a provable solution of the materialized pointed
    automaton. Thus existence is available in exactly the `SolvesBA` interface used by
    the common-quotient reduction. -/
theorem ThompsonCertificateBA.toGAut_solves
    (aut : InitializedGAut S A T) (standard : S → Exp A T)
    (program : Exp A T)
    (hcert : ThompsonCertificateBA aut standard program) :
    SolvesBA aut.toGAut (initializedStandard program standard) := by
  intro state hstate
  cases state with
  | none =>
      have hinitial : EquivBA
          (initRHSParam aut standard (.test .one)) program :=
        EquivBA.trans
          (hcert.parametric.initial (.test .one) standard hcert.standardSolves)
          (EquivBA.base (Equiv.s5 program))
      exact EquivBA.trans (EquivBA.symm hinitial)
        (by
          have hfallback := guardedFold_fallback_congr
            (transitionBranches aut.initTrans standard)
            (EquivBA.base (Equiv.s5 (.test aut.initHlt : Exp A T)))
          rw [eqRHS_eq_guardedFold]
          dsimp only [InitializedGAut.toGAut, initializedStandard,
            initRHSParam]
          rw [transitionBranches_option_map]
          exact hfallback)

  | some item =>
      have hitem : item ∈ aut.core.states := by
        change some item ∈ none :: aut.core.states.map some at hstate
        simpa using hstate
      have hsolve := hcert.standardSolves item hitem
      have hfallback := guardedFold_fallback_congr
        (transitionBranches (aut.core.trans item) standard)
        (EquivBA.base (Equiv.s5 (.test (aut.core.hlt item) : Exp A T)))
      exact EquivBA.trans hsolve
        (by
          rw [eqRHS_eq_guardedFold]
          dsimp only [InitializedGAut.toGAut, initializedStandard,
            eqRHSParam, paramFallback]
          rw [transitionBranches_option_map]
          exact hfallback)

/-- Under the two remaining structural invariants, the materialized Thompson automaton
    accepts exactly the guarded language of its source program at the pseudostart. -/
theorem ThompsonCertificateBA.toGAut_start_language
    (aut : InitializedGAut S A T) (standard : S → Exp A T)
    (program : Exp A T)
    (hcert : ThompsonCertificateBA aut standard program)
    (hcoreTargets : CoreTargetsListed aut)
    (hcoreDisjoint : CoreHaltDisjoint aut)
    (X : Type) (W : T → X → Bool) :
    autLang W aut.toGAut none = den W program := by
  have hwf := aut.toGAut_uniformWF standard hcoreTargets hcoreDisjoint
    hcert.initTargets hcert.initDisjoint X W
  have hsol := hcert.toGAut_solves aut standard program
  exact sem_solves_autLang hwf (solvesBA_semSolves hsol)
    none (List.Mem.head _)

theorem certifiedThompson_toGAut_solves (program : Exp A T) :
    SolvesBA (certifiedThompson A T program).aut.toGAut
      (initializedStandard program (certifiedThompson A T program).standard) :=
  (certifiedThompson A T program).certificate.toGAut_solves
    (certifiedThompson A T program).aut
    (certifiedThompson A T program).standard program

theorem certifiedThompson_uniformWF (program : Exp A T) :
    UniformWF (certifiedThompson A T program).aut.toGAut :=
  (certifiedThompson A T program).aut.toGAut_uniformWF
    (certifiedThompson A T program).standard
    (certifiedThompson A T program).structural.targets
    (certifiedThompson A T program).structural.disjoint
    (certifiedThompson A T program).certificate.initTargets
    (certifiedThompson A T program).certificate.initDisjoint

theorem certifiedThompson_start_language
    (program : Exp A T) (X : Type) (W : T → X → Bool) :
    autLang W (certifiedThompson A T program).aut.toGAut none = den W program :=
  (certifiedThompson A T program).certificate.toGAut_start_language
    (certifiedThompson A T program).aut
    (certifiedThompson A T program).standard program
    (certifiedThompson A T program).structural.targets
    (certifiedThompson A T program).structural.disjoint X W

/-- The semantic correctness theorem is not special to the pseudostart: every listed
    Thompson state denotes the guarded language of its canonical expression label. -/
theorem certifiedThompson_state_language
    (program : Exp A T)
    (state : Option (certifiedThompson A T program).State)
    (hstate : state ∈ (certifiedThompson A T program).aut.toGAut.states)
    (X : Type) (W : T → X → Bool) :
    autLang W (certifiedThompson A T program).aut.toGAut state =
      den W (initializedStandard program
        (certifiedThompson A T program).standard state) := by
  exact sem_solves_autLang (certifiedThompson_uniformWF program X W)
    (solvesBA_semSolves (certifiedThompson_toGAut_solves program)) state hstate

/-- Uniform emptiness of an automaton state. Quantifying over all carriers and test
    interpretations is essential: emptiness for one valuation cannot justify a
    finite-axiom rewrite. -/
def UniformAutLempty (aut : GAut S A T) (state : S) : Prop :=
  ∀ (X : Type) (W : T → X → Bool) (gs : GS A X), ¬ autLang W aut state gs

/-- Uniform emptiness of a GKAT expression. -/
def UniformExpLempty (expression : Exp A T) : Prop :=
  ∀ (X : Type) (W : T → X → Bool) (gs : GS A X), ¬ den W expression gs

/-- A loop whose guard is false immediately terminates. This is the easy constant-guard
    half of Boolean-cell normalization. -/
theorem while_false_eq_one (body : Exp A T) :
    EquivBA (.wh .zero body) (.test .one) := by
  exact EquivBA.trans (EquivBA.base (Equiv.w1 .zero body))
    (EquivBA.base (GkatFaithful.ite_zero
      (.seq body (.wh .zero body)) (.test .one)))

/-- A productive loop whose guard is true has no finite exit and is provably `0` using
    only W3. This is the nontrivial constant-guard case needed by the proposed finite
    Boolean-cell null-language normalization. -/
theorem productive_while_true_eq_zero (body : Exp A T)
    (hproductive : EquivBA (.test (E body) : Exp A T) (.test .zero)) :
    EquivBA (.wh .one body) (.test .zero) := by
  have hstep : EquivBA (.test .zero : Exp A T)
      (.ite .one (.seq body (.test .zero)) (.test .one)) := by
    exact EquivBA.trans (EquivBA.symm (EquivBA.base (Equiv.s3 body)))
      (EquivBA.symm (GkatFaithful.ite_one
        (.seq body (.test .zero)) (.test .one)))
  have hfixed : EquivBA (.test .zero : Exp A T)
      (.seq (.wh .one body) (.test .one)) :=
    EquivBA.w3_ba hproductive hstep
  exact EquivBA.trans
    (EquivBA.symm (EquivBA.base (Equiv.s5 (.wh .one body))))
    (EquivBA.symm hfixed)

/-- Every always-guarded GKAT loop has empty guarded language, and the original finite
    axioms prove it equal to `0`. Thompson decomposition removes nullable iterations,
    reducing the arbitrary body to its action-headed (hence productive) derivative; W3
    then closes the resulting constant-true loop. -/
theorem while_true_eq_zero (body : Exp A T) :
    EquivBA (.wh .one body) (.test .zero) := by
  let cert := certifiedThompson A T body
  let derivative := guardedFold
    (transitionBranches cert.aut.initTrans cert.standard) (.test .zero)
  have hnormalize : EquivBA (.wh .one body) (.wh .one derivative) := by
    exact initialized_productiveLoop .one cert.aut cert.standard body
      cert.certificate.parametric cert.certificate.standardSolves
      cert.certificate.initDisjoint
  exact EquivBA.trans hnormalize
    (productive_while_true_eq_zero derivative
      (transitionActionFold_productiveBA cert.aut.initTrans cert.standard))

/-- A listed Thompson state is uniformly dead exactly when its canonical expression
    label is uniformly empty. This pins down the dead-transition obligation without
    assuming the desired completeness theorem. -/
theorem certifiedThompson_state_empty_iff
    (program : Exp A T)
    (state : Option (certifiedThompson A T program).State)
    (hstate : state ∈ (certifiedThompson A T program).aut.toGAut.states) :
    UniformAutLempty (certifiedThompson A T program).aut.toGAut state ↔
      UniformExpLempty (initializedStandard program
        (certifiedThompson A T program).standard state) := by
  constructor <;> intro hempty X W gs
  · rw [← certifiedThompson_state_language program state hstate X W]
    exact hempty X W gs
  · rw [certifiedThompson_state_language program state hstate X W]
    exact hempty X W gs

/-- Uniform semantic emptiness is precisely uniform language equivalence with `0`. -/
theorem uniformExpLempty_iff_zero (expression : Exp A T) :
    UniformExpLempty expression ↔
      UniformLanguageEquivalent expression (.test .zero) := by
  constructor
  · intro hempty X W gs
    have hzero : ¬ den W (.test .zero : Exp A T) gs := by
      simp [den_test, bval]
    constructor
    · intro h; exact False.elim (hempty X W gs h)
    · intro h; exact False.elim (hzero h)
  · intro heq X W gs h
    have hzero : ¬ den W (.test .zero : Exp A T) gs := by
      simp [den_test, bval]
    exact hzero ((heq X W gs).mp h)

/-- Steelman checkpoint: deleting a uniformly dead Thompson transition by rewriting
    its target label to `0` follows from full finite-axiom completeness, but invoking
    that fact here would be circular. Any successful pruning proof must establish this
    special null-language case directly for Thompson labels. -/
theorem dead_thompson_label_eq_zero_of_complete
    (hcomplete : FiniteAxiomsCompleteBA A T)
    (program : Exp A T)
    (state : Option (certifiedThompson A T program).State)
    (hstate : state ∈ (certifiedThompson A T program).aut.toGAut.states)
    (hdead : UniformAutLempty
      (certifiedThompson A T program).aut.toGAut state) :
    EquivBA (initializedStandard program
      (certifiedThompson A T program).standard state) (.test .zero) := by
  apply hcomplete
  exact (uniformExpLempty_iff_zero _).mp
    ((certifiedThompson_state_empty_iff program state hstate).mp hdead)

/-! ## Direct zero solutions for dead equation-system components -/

/-- Conjoin a region to every guard in a branch list. -/
def restrictBranches (region : BExp T) :
    List (BExp T × Exp A T) → List (BExp T × Exp A T) :=
  List.map (fun branch => (.and region branch.1, branch.2))

/-- Inside the else arm of `guard`, every later branch may be restricted by `¬guard`.
    This is the list-level first-match normalization generated by `ite_else_restrict`. -/
theorem guardedFold_else_restrict (guard : BExp T) (label fallback : Exp A T)
    (branches : List (BExp T × Exp A T)) :
    EquivBA
      (.ite guard label (guardedFold branches fallback))
      (.ite guard label
        (guardedFold (restrictBranches (.not guard) branches) fallback)) := by
  let restricted := restrictBranches (.not guard) branches
  have hgate := GkatFaithful.ite_guardedFold_gate_right
    (.not guard) branches fallback label
  have hcomm := GkatFaithful.guardedFold_gate_comm
    (.not guard) branches (.ite (.not guard) fallback label)
  have hfallback := guardedFold_fallback_congr restricted
    (EquivBA.symm (EquivBA.base (Equiv.u2 guard label fallback)))
  have hdis : ∀ branch ∈ restricted,
      ∀ (X : Type) (W : T → X → Bool) (x : X),
        bval W (.and guard branch.1) x = false := by
    intro branch hbranch X W x
    simp only [restricted, restrictBranches, List.mem_map] at hbranch
    obtain ⟨original, _, rfl⟩ := hbranch
    simp only [bval]
    cases bval W guard x <;> rfl
  have hrotate := GkatFaithful.guardedFold_rotate_of_disjoint
    label fallback restricted hdis
  exact EquivBA.trans (EquivBA.base (Equiv.u2 guard label _))
    (EquivBA.trans hgate
      (EquivBA.trans hcomm
        (EquivBA.trans hfallback
          (by
            rw [guardedFold_append] at hrotate
            exact EquivBA.symm hrotate))))

/-- Replace every ordered guard by its effective first-match region. The head is
    unchanged; all later guards are recursively restricted by its negation. -/
def effectiveBranches : List (BExp T × Exp A T) → List (BExp T × Exp A T)
  | [] => []
  | (guard, label) :: tail =>
      (guard, label) :: effectiveBranches (restrictBranches (.not guard) tail)
termination_by branches => branches.length
decreasing_by simp [restrictBranches]

/-- Effective-guard normalization preserves the guarded expression using only the
    finite guarded-choice axioms and Boolean guard congruence. -/
theorem guardedFold_effective (branches : List (BExp T × Exp A T))
    (fallback : Exp A T) :
    EquivBA (guardedFold branches fallback)
      (guardedFold (effectiveBranches branches) fallback) := by
  induction branches using effectiveBranches.induct with
  | case1 =>
      rw [effectiveBranches]
      exact EquivBA.base (Equiv.refl _)
  | case2 guard label tail ih =>
      rw [effectiveBranches]
      exact EquivBA.trans
        (guardedFold_else_restrict guard label fallback tail)
        (EquivBA.ite_c (EquivBA.base (Equiv.refl _)) ih)

def BranchesUnder (region : BExp T)
    (branches : List (BExp T × Exp A T)) : Prop :=
  ∀ branch ∈ branches, GuardImplies branch.1 region

theorem restrictBranches_under (region : BExp T)
    (branches : List (BExp T × Exp A T)) :
    BranchesUnder region (restrictBranches region branches) := by
  intro branch hbranch X W x hguard
  simp only [restrictBranches, List.mem_map] at hbranch
  obtain ⟨original, _, rfl⟩ := hbranch
  change (bval W region x && bval W original.1 x) = true at hguard
  cases hr : bval W region x <;>
    cases ho : bval W original.1 x <;> simp_all

/-- Effective normalization preserves any region already implied by all input guards. -/
theorem effectiveBranches_preserves_under (region : BExp T)
    (branches : List (BExp T × Exp A T))
    (hunder : BranchesUnder region branches) :
    BranchesUnder region (effectiveBranches branches) := by
  induction branches using effectiveBranches.induct with
  | case1 =>
      rw [effectiveBranches]
      intro branch hbranch
      cases hbranch
  | case2 guard label tail ih =>
      rw [effectiveBranches]
      intro branch hbranch
      rcases List.mem_cons.mp hbranch with rfl | htail
      · exact hunder (guard, label) (List.Mem.head _)
      · apply ih
        · intro restricted hrestricted
          intro X W x hvalue
          simp only [restrictBranches, List.mem_map] at hrestricted
          obtain ⟨original, horiginal, rfl⟩ := hrestricted
          apply hunder original (List.Mem.tail _ horiginal) X W x
          change ((! bval W guard x) && bval W original.1 x) = true at hvalue
          cases hg : bval W guard x <;>
            cases ho : bval W original.1 x <;> simp_all
        · exact htail

def BranchGuardsDisjoint (left right : BExp T × Exp A T) : Prop :=
  ∀ (X : Type) (W : T → X → Bool) (x : X),
    bval W (.and left.1 right.1) x = false

/-- Effective first-match guards are pairwise disjoint. This turns ordered absence into
    ordinary Boolean regions suitable for a dead-sink completion. -/
theorem effectiveBranches_pairwise_disjoint
    (branches : List (BExp T × Exp A T)) :
    (effectiveBranches branches).Pairwise BranchGuardsDisjoint := by
  induction branches using effectiveBranches.induct with
  | case1 =>
      rw [effectiveBranches]
      exact List.Pairwise.nil
  | case2 guard label tail ih =>
      rw [effectiveBranches]
      apply List.Pairwise.cons
      · intro branch hbranch X W x
        have hunder := effectiveBranches_preserves_under (.not guard)
          (restrictBranches (.not guard) tail)
          (restrictBranches_under (.not guard) tail) branch hbranch X W x
        simp only [bval]
        cases hguard : bval W guard x
        · rfl
        · have hnot : bval W (.not guard) x = false := by
            change (! bval W guard x) = false
            rw [hguard]
            rfl
          cases hbranchValue : bval W branch.1 x
          · rfl
          · exact False.elim (Bool.noConfusion (hnot ▸ hunder hbranchValue))
      · exact ih

/-- A zero-valued branch disjoint from a terminal halt test is redundant. -/
theorem ite_zero_before_disjoint_test (guard halt : BExp T)
    (hdisjoint : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and guard halt) x = false) :
    EquivBA (.ite guard (.test .zero) (.test halt) : Exp A T) (.test halt) := by
  have htest := test_eq_ite_one_zero (A := A) halt
  have hswap := GkatFaithful.ite_swap_of_disjoint
    (.test .zero : Exp A T) (.test .one) (.test .zero) hdisjoint
  exact EquivBA.trans (EquivBA.ite_c (EquivBA.base (Equiv.refl _)) htest)
    (EquivBA.trans hswap
      (EquivBA.trans
        (EquivBA.ite_c (EquivBA.base (Equiv.refl _))
          (EquivBA.base (Equiv.u1 guard (.test .zero))))
        (EquivBA.symm htest)))

/-- Any finite list of zero-labelled branches, each disjoint from halt, leaves the
    terminal halt test unchanged. -/
theorem guardedFold_dead_before_test
    (branches : List (BExp T × Exp A T)) (halt : BExp T)
    (hzero : ∀ branch ∈ branches, EquivBA branch.2 (.test .zero))
    (hdisjoint : ∀ branch ∈ branches,
      ∀ (X : Type) (W : T → X → Bool) (x : X),
        bval W (.and branch.1 halt) x = false) :
    EquivBA (guardedFold branches (.test halt)) (.test halt) := by
  induction branches with
  | nil => exact EquivBA.base (Equiv.refl _)
  | cons branch tail ih =>
      have htailZero : ∀ item ∈ tail,
          EquivBA item.2 (.test .zero) := by
        intro item hitem
        exact hzero item (List.Mem.tail _ hitem)
      have htailDisjoint : ∀ item ∈ tail,
          ∀ (X : Type) (W : T → X → Bool) (x : X),
            bval W (.and item.1 halt) x = false := by
        intro item hitem
        exact hdisjoint item (List.Mem.tail _ hitem)
      exact EquivBA.trans
        (EquivBA.ite_c
          (hzero branch (List.Mem.head _))
          (ih htailZero htailDisjoint))
        (ite_zero_before_disjoint_test branch.1 halt
          (hdisjoint branch (List.Mem.head _)))

/-- Appending halt-disjoint dead transitions to an existing first-match equation does
    not change it. List position supplies the implicit "no earlier transition" guard. -/
theorem guardedFold_append_dead_preserves
    (original completion : List (BExp T × Exp A T)) (halt : BExp T)
    (hzero : ∀ branch ∈ completion, EquivBA branch.2 (.test .zero))
    (hdisjoint : ∀ branch ∈ completion,
      ∀ (X : Type) (W : T → X → Bool) (x : X),
        bval W (.and branch.1 halt) x = false) :
    EquivBA
      (guardedFold (original ++ completion) (.test halt))
      (guardedFold original (.test halt)) := by
  rw [guardedFold_append]
  exact guardedFold_fallback_congr original
    (guardedFold_dead_before_test completion halt hzero hdisjoint)

/-- Append state-local completion transitions while preserving the carrier, halt tests,
    state list, and distinguished start. -/
def appendGAutTransitions (aut : GAut S A T)
    (completion : S → List (BExp T × A × S)) : GAut S A T where
  states := aut.states
  hlt := aut.hlt
  trans := fun state => aut.trans state ++ completion state
  start := aut.start

/-- Automaton-level preservation: appended transitions whose targets are labelled zero
    and whose guards are disjoint from the source halt test do not alter its equation. -/
theorem eqRHS_append_dead_transitions_preserves
    (aut : GAut S A T) (completion : S → List (BExp T × A × S))
    (sol : S → Exp A T) (state : S)
    (htargetZero : ∀ transition ∈ completion state,
      EquivBA (sol transition.2.2) (.test .zero))
    (hdisjoint : ∀ transition ∈ completion state,
      ∀ (X : Type) (W : T → X → Bool) (x : X),
        bval W (.and transition.1 (aut.hlt state)) x = false) :
    EquivBA (eqRHS (appendGAutTransitions aut completion) sol state)
      (eqRHS aut sol state) := by
  rw [eqRHS_eq_guardedFold, eqRHS_eq_guardedFold]
  dsimp only [appendGAutTransitions]
  rw [transitionBranches_append]
  apply guardedFold_append_dead_preserves
  · intro branch hbranch
    simp only [transitionBranches, List.mem_map] at hbranch
    obtain ⟨transition, htransition, rfl⟩ := hbranch
    exact EquivBA.trans
      (EquivBA.seq_c (EquivBA.base (Equiv.refl _))
        (htargetZero transition htransition))
      (EquivBA.base (Equiv.s3 (.act transition.2.1)))
  · intro branch hbranch
    simp only [transitionBranches, List.mem_map] at hbranch
    obtain ⟨transition, htransition, rfl⟩ := hbranch
    exact hdisjoint transition htransition

/-- A solution survives any such dead-transition completion. -/
theorem solvesBA_append_dead_transitions
    (aut : GAut S A T) (completion : S → List (BExp T × A × S))
    (sol : S → Exp A T) (hsol : SolvesBA aut sol)
    (htargetZero : ∀ state ∈ aut.states, ∀ transition ∈ completion state,
      EquivBA (sol transition.2.2) (.test .zero))
    (hdisjoint : ∀ state ∈ aut.states, ∀ transition ∈ completion state,
      ∀ (X : Type) (W : T → X → Bool) (x : X),
        bval W (.and transition.1 (aut.hlt state)) x = false) :
    SolvesBA (appendGAutTransitions aut completion) sol := by
  intro state hstate
  exact EquivBA.trans (hsol state hstate)
    (EquivBA.symm (eqRHS_append_dead_transitions_preserves
      aut completion sol state
      (htargetZero state hstate) (hdisjoint state hstate)))

/-- Add a fresh dead state without adding any incoming completion transitions yet. -/
def deadSinkBase (aut : GAut S A T) : GAut (Option S) A T where
  states := none :: aut.states.map some
  hlt
    | none => .zero
    | some state => aut.hlt state
  trans
    | none => []
    | some state => (aut.trans state).map (fun transition =>
        (transition.1, transition.2.1, some transition.2.2))
  start := some aut.start

def deadSinkSolution (sol : S → Exp A T) : Option S → Exp A T
  | none => .test .zero
  | some state => sol state

/-- A solution lifts through addition of an isolated zero state. -/
theorem deadSinkBase_solvesBA (aut : GAut S A T) (sol : S → Exp A T)
    (hsol : SolvesBA aut sol) :
    SolvesBA (deadSinkBase aut) (deadSinkSolution sol) := by
  intro state hstate
  cases state with
  | none =>
      rw [eqRHS_eq_guardedFold]
      exact EquivBA.base (Equiv.refl _)
  | some state =>
      have hsource : state ∈ aut.states := by
        change some state ∈ none :: aut.states.map some at hstate
        simpa using hstate
      have hs := hsol state hsource
      rw [eqRHS_eq_guardedFold] at hs ⊢
      dsimp only [deadSinkBase, deadSinkSolution]
      rw [transitionBranches_option_map]
      exact hs

/-- Convert requested `(guard, action)` completions into transitions to the fresh sink. -/
def deadSinkTransitions (completion : S → List (BExp T × A)) :
    Option S → List (BExp T × A × Option S)
  | none => []
  | some state => (completion state).map (fun item => (item.1, item.2, none))

def completeWithDeadSink (aut : GAut S A T)
    (completion : S → List (BExp T × A)) : GAut (Option S) A T :=
  appendGAutTransitions (deadSinkBase aut) (deadSinkTransitions completion)

/-- The packaged dead-sink completion theorem. Any finite completion regions disjoint
    from the corresponding source halt guard may be assigned arbitrary actions and
    routed to the fresh all-zero state while preserving the original solution. -/
theorem completeWithDeadSink_solvesBA
    (aut : GAut S A T) (completion : S → List (BExp T × A))
    (sol : S → Exp A T) (hsol : SolvesBA aut sol)
    (hdisjoint : ∀ state ∈ aut.states, ∀ item ∈ completion state,
      ∀ (X : Type) (W : T → X → Bool) (x : X),
        bval W (.and item.1 (aut.hlt state)) x = false) :
    SolvesBA (completeWithDeadSink aut completion) (deadSinkSolution sol) := by
  apply solvesBA_append_dead_transitions
    (deadSinkBase aut) (deadSinkTransitions completion)
    (deadSinkSolution sol) (deadSinkBase_solvesBA aut sol hsol)
  · intro state hstate transition htransition
    cases state with
    | none => cases htransition
    | some state =>
        simp only [deadSinkTransitions, List.mem_map] at htransition
        obtain ⟨item, _, rfl⟩ := htransition
        exact EquivBA.base (Equiv.refl _)
  · intro state hstate transition htransition X W x
    cases state with
    | none => cases htransition
    | some state =>
        have hsource : state ∈ aut.states := by
          change some state ∈ none :: aut.states.map some at hstate
          simpa using hstate
        simp only [deadSinkTransitions, List.mem_map] at htransition
        obtain ⟨item, hitem, rfl⟩ := htransition
        exact hdisjoint state hsource item hitem X W x

/-- A guarded decision list whose branches and fallback are all provably zero is itself
    provably zero. Unlike semantic null-language completeness, this is a direct finite
    U-axiom calculation. -/
theorem guardedFold_all_zero
    (branches : List (BExp T × Exp A T))
    (hzero : ∀ branch ∈ branches, EquivBA branch.2 (.test .zero)) :
    EquivBA (guardedFold branches (.test .zero)) (.test .zero) := by
  induction branches with
  | nil => exact EquivBA.base (Equiv.refl _)
  | cons branch tail ih =>
      have htail : ∀ item ∈ tail, EquivBA item.2 (.test .zero) := by
        intro item hitem
        exact hzero item (List.Mem.tail _ hitem)
      exact EquivBA.trans
        (EquivBA.ite_c
          (hzero branch (List.Mem.head _)) (ih htail))
        (EquivBA.base (Equiv.u1 branch.1 (.test .zero)))

/-- If every listed state's halt test is Boolean-false, the all-zero labelling solves
    the entire guarded equation system. No uniqueness or language-completeness premise
    is used: S3 kills every action-to-zero branch and U1 joins the zero alternatives. -/
theorem allZero_solvesBA_of_halt_false
    (aut : GAut S A T)
    (hhalt : ∀ state ∈ aut.states,
      EquivBA (.test (aut.hlt state) : Exp A T) (.test .zero)) :
    SolvesBA aut (fun _ => (.test .zero : Exp A T)) := by
  intro state hstate
  rw [eqRHS_eq_guardedFold]
  apply EquivBA.symm
  apply EquivBA.trans
    (guardedFold_fallback_congr _ (hhalt state hstate))
  apply guardedFold_all_zero
  intro branch hbranch
  simp only [transitionBranches, List.mem_map] at hbranch
  obtain ⟨transition, _, rfl⟩ := hbranch
  exact EquivBA.base (Equiv.s3 (.act transition.2.1))

/-- Every listed state of an automaton has empty language, uniformly over test
    interpretations. -/
def AllStatesUniformlyDead (aut : GAut S A T) : Prop :=
  ∀ state ∈ aut.states, UniformAutLempty aut state

/-- Uniform semantic deadness supplies exactly the Boolean halt premise needed by the
    direct all-zero construction. This uses semantics only to prove a Boolean identity;
    the program-equation proof remains entirely within the finite axioms. -/
theorem allZero_solvesBA_of_uniform_dead
    (aut : GAut S A T) (hdead : AllStatesUniformlyDead aut) :
    SolvesBA aut (fun _ => (.test .zero : Exp A T)) := by
  apply allZero_solvesBA_of_halt_false aut
  intro state hstate
  apply EquivBA.baTest
  intro X W x
  have hnot : ¬ autLang W aut state (x, []) := hdead state hstate X W (x, [])
  simp only [autLang, autRun] at hnot
  cases hvalue : bval W (aut.hlt state) x with
  | false => rfl
  | true => exact False.elim (hnot hvalue)

/-- Every solution of the materialized pointed Thompson automaton labels its start by
    the source program. This is the pointed form of finite-axiom Thompson uniqueness. -/
theorem ThompsonCertificateBA.toGAut_start_canonical
    (aut : InitializedGAut S A T) (standard : S → Exp A T)
    (program : Exp A T)
    (hcert : ThompsonCertificateBA aut standard program)
    (sol : Option S → Exp A T) (hsol : SolvesBA aut.toGAut sol) :
    EquivBA (sol aut.toGAut.start) program := by
  let inner : S → Exp A T := fun state => sol (some state)
  have hinner : ParamSolvesBA aut.core inner (.test .one) := by
    intro state hstate
    have hlisted : some state ∈ aut.toGAut.states :=
      List.Mem.tail none (mem_map_direct some hstate)
    have hordinary := hsol (some state) hlisted
    have hfallback := guardedFold_fallback_congr
      (transitionBranches (aut.core.trans state) inner)
      (EquivBA.base (Equiv.s5 (.test (aut.core.hlt state) : Exp A T)))
    have hbridge : EquivBA
        (eqRHSParam aut.core inner (.test .one) state)
        (eqRHS aut.toGAut sol (some state)) := by
      rw [eqRHS_eq_guardedFold]
      dsimp only [InitializedGAut.toGAut, eqRHSParam, paramFallback]
      rw [transitionBranches_option_map (aut.core.trans state) sol]
      exact hfallback
    exact EquivBA.trans hordinary (EquivBA.symm hbridge)
  have hnone : none ∈ aut.toGAut.states := List.Mem.head _
  have hstartEquation := hsol none hnone
  have hfallback := guardedFold_fallback_congr
    (transitionBranches aut.initTrans inner)
    (EquivBA.base (Equiv.s5 (.test aut.initHlt : Exp A T)))
  have hbridge : EquivBA
      (initRHSParam aut inner (.test .one))
      (eqRHS aut.toGAut sol none) := by
    rw [eqRHS_eq_guardedFold]
    dsimp only [InitializedGAut.toGAut, initRHSParam, paramFallback]
    rw [transitionBranches_option_map aut.initTrans sol]
    exact hfallback
  exact EquivBA.trans hstartEquation
    (EquivBA.trans (EquivBA.symm hbridge)
      (EquivBA.trans
        (hcert.parametric.initial (.test .one) inner hinner)
        (EquivBA.base (Equiv.s5 program))))

/-- Pointwise form of Thompson uniqueness for every listed materialized state, not only
    the pseudostart. -/
theorem ThompsonCertificateBA.toGAut_state_canonical
    (aut : InitializedGAut S A T) (standard : S → Exp A T)
    (program : Exp A T)
    (hcert : ThompsonCertificateBA aut standard program)
    (sol : Option S → Exp A T) (hsol : SolvesBA aut.toGAut sol)
    (state : Option S) (hstate : state ∈ aut.toGAut.states) :
    EquivBA (sol state) (initializedStandard program standard state) := by
  cases state with
  | none => exact hcert.toGAut_start_canonical aut standard program sol hsol
  | some item =>
      have hitem : item ∈ aut.core.states := by
        change some item ∈ none :: aut.core.states.map some at hstate
        simpa using hstate
      let inner : S → Exp A T := fun source => sol (some source)
      have hinner : ParamSolvesBA aut.core inner (.test .one) := by
        intro source hsource
        have hlisted : some source ∈ aut.toGAut.states :=
          List.Mem.tail none (mem_map_direct some hsource)
        have hordinary := hsol (some source) hlisted
        have hfallback := guardedFold_fallback_congr
          (transitionBranches (aut.core.trans source) inner)
          (EquivBA.base (Equiv.s5 (.test (aut.core.hlt source) : Exp A T)))
        have hbridge : EquivBA
            (eqRHSParam aut.core inner (.test .one) source)
            (eqRHS aut.toGAut sol (some source)) := by
          rw [eqRHS_eq_guardedFold]
          dsimp only [InitializedGAut.toGAut, eqRHSParam, paramFallback]
          rw [transitionBranches_option_map (aut.core.trans source) sol]
          exact hfallback
        exact EquivBA.trans hordinary (EquivBA.symm hbridge)
      exact EquivBA.trans
        (hcert.parametric.states (.test .one) inner hinner item hitem)
        (EquivBA.base (Equiv.s5 (standard item)))

/-- A solved common quotient of the two materialized Thompson automata suffices for
    program equality. Unlike the derivative reduction, no separate fundamental or UA
    premise remains: both are supplied by the syntax-generated certificates. -/
theorem certifiedThompson_common_solved_quotient
    {Q A T : Type} {leftProgram rightProgram : Exp A T}
    {quot : GAut Q A T}
    (leftHom : GAutHom (certifiedThompson A T leftProgram).aut.toGAut quot)
    (rightHom : GAutHom (certifiedThompson A T rightProgram).aut.toGAut quot)
    (qsol : Q → Exp A T) (hqsol : SolvesBA quot qsol)
    (hstart : leftHom.mapState none = rightHom.mapState none) :
    EquivBA leftProgram rightProgram := by
  have hleftSol := leftHom.lift_solvesBA hqsol
  have hrightSol := rightHom.lift_solvesBA hqsol
  have hleft :=
    (certifiedThompson A T leftProgram).certificate.toGAut_start_canonical
      (certifiedThompson A T leftProgram).aut
      (certifiedThompson A T leftProgram).standard leftProgram
      (fun state => qsol (leftHom.mapState state)) hleftSol
  have hright :=
    (certifiedThompson A T rightProgram).certificate.toGAut_start_canonical
      (certifiedThompson A T rightProgram).aut
      (certifiedThompson A T rightProgram).standard rightProgram
      (fun state => qsol (rightHom.mapState state)) hrightSol
  change EquivBA (qsol (leftHom.mapState none)) leftProgram at hleft
  change EquivBA (qsol (rightHom.mapState none)) rightProgram at hright
  rw [hstart] at hleft
  exact EquivBA.trans (EquivBA.symm hleft) hright

/-- Behavioral-quotient version of the Thompson endgame. Guard partitions may differ
    syntactically: the existing uniform normalization theorem supplies the lifted source
    solutions, and Thompson start canonicity finishes the proof. -/
theorem certifiedThompson_uniform_solved_quotient
    {Q A T : Type} {leftProgram rightProgram : Exp A T}
    {quot : GAut Q A T}
    (π : UniformBehavioralGAutQuotient
      (sumGAut
        (certifiedThompson A T leftProgram).aut.toGAut
        (certifiedThompson A T rightProgram).aut.toGAut)
      quot)
    (qsol : Q → Exp A T) (hqsol : SolvesBA quot qsol)
    (hstart : π.mapState (.inl none) = π.mapState (.inr none)) :
    EquivBA leftProgram rightProgram := by
  let leftAut := (certifiedThompson A T leftProgram).aut.toGAut
  let rightAut := (certifiedThompson A T rightProgram).aut.toGAut
  let sumSol : Sum (Option (certifiedThompson A T leftProgram).State)
      (Option (certifiedThompson A T rightProgram).State) → Exp A T :=
    fun state => qsol (π.mapState state)
  have hsum : SolvesBA (sumGAut leftAut rightAut) sumSol :=
    π.lift_solvesBA hqsol
  have hleftSol : SolvesBA leftAut
      (fun state => qsol (π.mapState (.inl state))) :=
    (GAutHom.inl leftAut rightAut).lift_solvesBA hsum
  have hrightSol : SolvesBA rightAut
      (fun state => qsol (π.mapState (.inr state))) :=
    (GAutHom.inr leftAut rightAut).lift_solvesBA hsum
  have hleft :=
    (certifiedThompson A T leftProgram).certificate.toGAut_start_canonical
      (certifiedThompson A T leftProgram).aut
      (certifiedThompson A T leftProgram).standard leftProgram
      (fun state => qsol (π.mapState (.inl state))) hleftSol
  have hright :=
    (certifiedThompson A T rightProgram).certificate.toGAut_start_canonical
      (certifiedThompson A T rightProgram).aut
      (certifiedThompson A T rightProgram).standard rightProgram
      (fun state => qsol (π.mapState (.inr state))) hrightSol
  change EquivBA (qsol (π.mapState (.inl none))) leftProgram at hleft
  change EquivBA (qsol (π.mapState (.inr none))) rightProgram at hright
  rw [hstart] at hleft
  exact EquivBA.trans (EquivBA.symm hleft) hright

/-! ## Exact descent criterion for quotient solvability -/

def GAutTargetsListed (aut : GAut S A T) : Prop :=
  ∀ state ∈ aut.states, ∀ transition ∈ aut.trans state,
    transition.2.2 ∈ aut.states

theorem eqRHS_solution_congr
    (aut : GAut S A T) (left right : S → Exp A T) (state : S)
    (hlabels : ∀ transition ∈ aut.trans state,
      EquivBA (left transition.2.2) (right transition.2.2)) :
    EquivBA (eqRHS aut left state) (eqRHS aut right state) := by
  rw [eqRHS_eq_guardedFold, eqRHS_eq_guardedFold]
  let transitions := aut.trans state
  have hlabels' : ∀ transition ∈ transitions,
      EquivBA (left transition.2.2) (right transition.2.2) := by
    intro transition htransition
    exact hlabels transition htransition
  have go : ∀ items : List (BExp T × A × S),
      (∀ transition ∈ items,
        EquivBA (left transition.2.2) (right transition.2.2)) →
      EquivBA
        (guardedFold (transitionBranches items left) (.test (aut.hlt state)))
        (guardedFold (transitionBranches items right) (.test (aut.hlt state))) := by
    intro items hitems
    induction items with
    | nil => exact EquivBA.base (Equiv.refl _)
    | cons transition tail ih =>
        obtain ⟨guard, action, target⟩ := transition
        have hhead := hitems (guard, action, target) (List.Mem.head _)
        have htail : ∀ item ∈ tail,
            EquivBA (left item.2.2) (right item.2.2) := by
          intro item hitem
          exact hitems item (List.Mem.tail _ hitem)
        exact EquivBA.ite_c
          (EquivBA.seq_c (EquivBA.base (Equiv.refl _)) hhead)
          (ih htail)
  exact go transitions hlabels'

/-- Representative choice yields a quotient solution precisely once the chosen quotient
    labels provably agree with the source solution on every fiber. This theorem isolates
    the non-semantic descent obligation left by Thompson uniqueness. -/
theorem UniformBehavioralGAutQuotient.solves_of_descends
    {S Q A T : Type} {aut : GAut S A T} {quot : GAut Q A T}
    (π : UniformBehavioralGAutQuotient aut quot)
    (htargets : GAutTargetsListed aut)
    (sourceSol : S → Exp A T) (hsource : SolvesBA aut sourceSol)
    (quotSol : Q → Exp A T)
    (hdescends : ∀ state ∈ aut.states,
      EquivBA (quotSol (π.mapState state)) (sourceSol state)) :
    SolvesBA quot quotSol := by
  intro q hq
  obtain ⟨state, hstate, rfl⟩ := π.onto_states q hq
  have hrewrite : EquivBA (eqRHS aut sourceSol state)
      (eqRHS aut (fun item => quotSol (π.mapState item)) state) := by
    apply eqRHS_solution_congr
    intro transition htransition
    exact EquivBA.symm
      (hdescends transition.2.2
        (htargets state hstate transition htransition))
  exact EquivBA.trans (hdescends state hstate)
    (EquivBA.trans (hsource state hstate)
      (EquivBA.trans hrewrite (π.eqRHS_ba quotSol state)))

/-! ## Language equivalence is bisimulation only up to dead residuals -/

/-- Map the atom carrier of a guarded string, preserving actions. -/
def mapGSAtoms {X Y : Type} (f : X → Y) (gs : GS A X) : GS A Y :=
  (f gs.1, gs.2.map (fun item => (item.1, f item.2)))

theorem bval_map_atoms {X Y : Type} (V : T → X → Bool) (V' : T → Y → Bool)
    (f : X → Y) (hV : ∀ test x, V' test (f x) = V test x)
    (guard : BExp T) (x : X) :
    bval V' guard (f x) = bval V guard x := by
  induction guard with
  | zero => rfl
  | one => rfl
  | prim test => exact hV test x
  | and left right ihLeft ihRight => simp only [bval, ihLeft, ihRight]
  | or left right ihLeft ihRight => simp only [bval, ihLeft, ihRight]
  | not body ih => simp only [bval, ih]

theorem firstMatch_map_atoms {X Y : Type}
    (V : T → X → Bool) (V' : T → Y → Bool) (f : X → Y)
    (hV : ∀ test x, V' test (f x) = V test x)
    (x : X) (transitions : List (BExp T × A × S)) :
    firstMatch V' (f x) transitions = firstMatch V x transitions := by
  induction transitions with
  | nil => rfl
  | cons transition tail ih =>
      obtain ⟨guard, action, target⟩ := transition
      simp only [firstMatch, bval_map_atoms V V' f hV guard x, ih]

/-- Automaton runs are invariant under an atom renaming on which primitive-test
    interpretations agree. -/
theorem autRun_map_atoms {X Y : Type}
    (V : T → X → Bool) (V' : T → Y → Bool) (f : X → Y)
    (hV : ∀ test x, V' test (f x) = V test x)
    (aut : GAut S A T) (state : S) (x : X) (tail : List (A × X)) :
    autRun V' aut state (f x)
        (tail.map (fun item => (item.1, f item.2))) ↔
      autRun V aut state x tail := by
  induction tail generalizing state x with
  | nil =>
      simp only [List.map_nil, autRun]
      rw [bval_map_atoms V V' f hV]
  | cons item tail ih =>
      obtain ⟨action, nextAtom⟩ := item
      simp only [List.map_cons, autRun,
        autStep, firstMatch_map_atoms V V' f hV]
      constructor
      · rintro ⟨target, hstep, hrun⟩
        exact ⟨target, hstep, (ih target nextAtom).mp hrun⟩
      · rintro ⟨target, hstep, hrun⟩
        exact ⟨target, hstep, (ih target nextAtom).mpr hrun⟩

theorem autLang_map_atoms {X Y : Type}
    (V : T → X → Bool) (V' : T → Y → Bool) (f : X → Y)
    (hV : ∀ test x, V' test (f x) = V test x)
    (aut : GAut S A T) (state : S) (gs : GS A X) :
    autLang V' aut state (mapGSAtoms f gs) ↔ autLang V aut state gs := by
  obtain ⟨x, tail⟩ := gs
  exact autRun_map_atoms V V' f hV aut state x tail

def UniformAutLangEq (left : GAut S₁ A T) (right : GAut S₂ A T)
    (s₁ : S₁) (s₂ : S₂) : Prop :=
  ∀ (X : Type) (W : T → X → Bool) (gs : GS A X),
    autLang W left s₁ gs ↔ autLang W right s₂ gs

/-- **Fresh-atom uniformization.** If uniformly language-equivalent states disagree on
    an enabled action at even one source valuation, the unmatched residual is not merely
    empty for that valuation: it is uniformly empty. An arbitrary target valuation is
    installed on the right summand of a fresh sum carrier, independently of the source
    atom on the left summand. -/
theorem unmatched_step_target_uniformly_dead
    (left : GAut S₁ A T) (right : GAut S₂ A T)
    {s₁ : S₁} {s₂ : S₂} (heq : UniformAutLangEq left right s₁ s₂)
    {X : Type} (Wsource : T → X → Bool) (x : X)
    {action : A} {target₁ : S₁}
    (hstep₁ : autStep Wsource left s₁ x = some (action, target₁))
    (hnomatch : ¬ ∃ target₂,
      autStep Wsource right s₂ x = some (action, target₂)) :
    UniformAutLempty left target₁ := by
  intro Y Wtarget gs htarget
  let Wsum : T → Sum X Y → Bool := fun test atom =>
    match atom with
    | .inl source => Wsource test source
    | .inr target => Wtarget test target
  have hsourceV : ∀ test source,
      Wsum test (Sum.inl source) = Wsource test source := by
    intro test source
    rfl
  have htargetV : ∀ test target,
      Wsum test (Sum.inr target) = Wtarget test target := by
    intro test target
    rfl
  have hstepSum : autStep Wsum left s₁ (Sum.inl x) =
      some (action, target₁) := by
    simpa only [autStep, firstMatch_map_atoms Wsource Wsum Sum.inl hsourceV]
      using hstep₁
  have htargetSum :
      autLang Wsum left target₁ (mapGSAtoms Sum.inr gs) :=
    (autLang_map_atoms Wtarget Wsum Sum.inr htargetV left target₁ gs).mpr htarget
  have hleft : autLang Wsum left s₁
      (Sum.inl x, (action, (mapGSAtoms Sum.inr gs).1) ::
        (mapGSAtoms Sum.inr gs).2) := by
    simp only [autLang, autRun]
    exact ⟨target₁, hstepSum, htargetSum⟩
  have hright := (heq (Sum X Y) Wsum
    (Sum.inl x, (action, (mapGSAtoms Sum.inr gs).1) ::
      (mapGSAtoms Sum.inr gs).2)).mp hleft
  simp only [autLang, autRun] at hright
  obtain ⟨target₂, hstep₂, _⟩ := hright
  apply hnomatch
  refine ⟨target₂, ?_⟩
  simpa only [autStep, firstMatch_map_atoms Wsource Wsum Sum.inl hsourceV]
    using hstep₂

/-- The matched companion to `unmatched_step_target_uniformly_dead`: one witnessed pair
    of equally-labelled steps from uniformly equivalent states has uniformly equivalent
    residuals. The target valuation remains arbitrary and independent of the witnessing
    source valuation. -/
theorem matched_step_targets_uniform_langEq
    (left : GAut S₁ A T) (right : GAut S₂ A T)
    {s₁ : S₁} {s₂ : S₂} (heq : UniformAutLangEq left right s₁ s₂)
    {X : Type} (Wsource : T → X → Bool) (x : X)
    {action : A} {target₁ : S₁} {target₂ : S₂}
    (hstep₁ : autStep Wsource left s₁ x = some (action, target₁))
    (hstep₂ : autStep Wsource right s₂ x = some (action, target₂)) :
    UniformAutLangEq left right target₁ target₂ := by
  intro Y Wtarget gs
  let Wsum : T → Sum X Y → Bool := fun test atom =>
    match atom with
    | .inl source => Wsource test source
    | .inr target => Wtarget test target
  have hsourceV : ∀ test source,
      Wsum test (Sum.inl source) = Wsource test source := by
    intro test source
    rfl
  have htargetV : ∀ test target,
      Wsum test (Sum.inr target) = Wtarget test target := by
    intro test target
    rfl
  have hstepSum₁ : autStep Wsum left s₁ (Sum.inl x) =
      some (action, target₁) := by
    simpa only [autStep, firstMatch_map_atoms Wsource Wsum Sum.inl hsourceV]
      using hstep₁
  have hstepSum₂ : autStep Wsum right s₂ (Sum.inl x) =
      some (action, target₂) := by
    simpa only [autStep, firstMatch_map_atoms Wsource Wsum Sum.inl hsourceV]
      using hstep₂
  constructor
  · intro htarget
    have htargetSum : autLang Wsum left target₁ (mapGSAtoms Sum.inr gs) :=
      (autLang_map_atoms Wtarget Wsum Sum.inr htargetV left target₁ gs).mpr htarget
    have hsourceLeft : autLang Wsum left s₁
        (Sum.inl x, (action, (mapGSAtoms Sum.inr gs).1) ::
          (mapGSAtoms Sum.inr gs).2) := by
      simp only [autLang, autRun]
      exact ⟨target₁, hstepSum₁, htargetSum⟩
    have hsourceRight := (heq (Sum X Y) Wsum _).mp hsourceLeft
    have htargetRight : autLang Wsum right target₂ (mapGSAtoms Sum.inr gs) := by
      simp only [autLang, autRun] at hsourceRight
      obtain ⟨found, hfound, hrun⟩ := hsourceRight
      rw [hstepSum₂, Option.some.injEq, Prod.mk.injEq] at hfound
      obtain ⟨_, rfl⟩ := hfound
      exact hrun
    exact (autLang_map_atoms Wtarget Wsum Sum.inr htargetV
      right target₂ gs).mp htargetRight
  · intro htarget
    have htargetSum : autLang Wsum right target₂ (mapGSAtoms Sum.inr gs) :=
      (autLang_map_atoms Wtarget Wsum Sum.inr htargetV right target₂ gs).mpr htarget
    have hsourceRight : autLang Wsum right s₂
        (Sum.inl x, (action, (mapGSAtoms Sum.inr gs).1) ::
          (mapGSAtoms Sum.inr gs).2) := by
      simp only [autLang, autRun]
      exact ⟨target₂, hstepSum₂, htargetSum⟩
    have hsourceLeft := (heq (Sum X Y) Wsum _).mpr hsourceRight
    have htargetLeft : autLang Wsum left target₁ (mapGSAtoms Sum.inr gs) := by
      simp only [autLang, autRun] at hsourceLeft
      obtain ⟨found, hfound, hrun⟩ := hsourceLeft
      rw [hstepSum₁, Option.some.injEq, Prod.mk.injEq] at hfound
      obtain ⟨_, rfl⟩ := hfound
      exact hrun
    exact (autLang_map_atoms Wtarget Wsum Sum.inr htargetV
      left target₁ gs).mp htargetLeft

def pairedTransitionGuards (left : GAut S₁ A T) (right : GAut S₂ A T)
    (s₁ : S₁) (s₂ : S₂) : List (BExp T) :=
  (left.trans s₁).map (fun transition => transition.1) ++
    (right.trans s₂).map (fun transition => transition.1)

def leftCellChoice (left : GAut S₁ A T) (s₁ : S₁)
    (decisions : List (BExp T × Bool)) : Option (A × S₁) :=
  decidedFirst decisions (left.trans s₁)

def rightCellChoice (left : GAut S₁ A T) (right : GAut S₂ A T)
    (s₁ : S₁) (s₂ : S₂) (decisions : List (BExp T × Bool)) : Option (A × S₂) :=
  decidedFirst
    (GkatFaithful.dropGuardDecisions
      ((left.trans s₁).map (fun transition => transition.1)) decisions)
    (right.trans s₂)

/-- Complete semantic classification of a satisfiable joint transition cell. -/
inductive UniformCellClass (left : GAut S₁ A T) (right : GAut S₂ A T) :
    Option (A × S₁) → Option (A × S₂) → Prop where
  | absent : UniformCellClass left right none none
  | matched (action : A) (target₁ : S₁) (target₂ : S₂)
      (related : UniformAutLangEq left right target₁ target₂) :
      UniformCellClass left right (some (action, target₁)) (some (action, target₂))
  | leftOnly (action : A) (target₁ : S₁)
      (dead : UniformAutLempty left target₁) :
      UniformCellClass left right (some (action, target₁)) none
  | rightOnly (action : A) (target₂ : S₂)
      (dead : UniformAutLempty right target₂) :
      UniformCellClass left right none (some (action, target₂))
  | mismatch (leftAction rightAction : A) (target₁ : S₁) (target₂ : S₂)
      (different : leftAction ≠ rightAction)
      (leftDead : UniformAutLempty left target₁)
      (rightDead : UniformAutLempty right target₂) :
      UniformCellClass left right
        (some (leftAction, target₁)) (some (rightAction, target₂))

/-- Every finite joint Boolean cell is either unsatisfiable or has exactly the semantic
    status needed by dead completion: absent, matched with uniformly equivalent targets,
    one-sided with a uniformly dead target, or action-mismatched with both targets dead. -/
theorem uniform_cell_classification
    (left : GAut S₁ A T) (right : GAut S₂ A T)
    {s₁ : S₁} {s₂ : S₂} (heq : UniformAutLangEq left right s₁ s₂)
    (decisions : List (BExp T × Bool))
    (hassignment : GkatFaithful.IsGuardAssignment
      (pairedTransitionGuards left right s₁ s₂) decisions) :
    (∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (GkatFaithful.guardCell decisions) x = false) ∨
    UniformCellClass left right
      (leftCellChoice left s₁ decisions)
      (rightCellChoice left right s₁ s₂ decisions) := by
  classical
  by_cases hsatisfiable : ∃ (X : Type) (W : T → X → Bool) (x : X),
      bval W (GkatFaithful.guardCell decisions) x = true
  · right
    obtain ⟨X, W, x, hcell⟩ := hsatisfiable
    obtain ⟨leftDecisions, rightDecisions, rfl, hleftAssign, hrightAssign⟩ :=
      hassignment.split_append
    obtain ⟨hleftCell, hrightCell⟩ :=
      GkatFaithful.guardCell_append_implies W x leftDecisions rightDecisions hcell
    have hleftStep := firstMatch_eq_decidedFirst W x (left.trans s₁)
      leftDecisions hleftAssign hleftCell
    have hrightStep := firstMatch_eq_decidedFirst W x (right.trans s₂)
      rightDecisions hrightAssign hrightCell
    rw [leftCellChoice, decidedFirst_append_of_assignment
      (left.trans s₁) leftDecisions rightDecisions hleftAssign]
    rw [rightCellChoice,
      GkatFaithful.dropGuardDecisions_append rightDecisions hleftAssign]
    cases hleftChoice : decidedFirst leftDecisions (left.trans s₁) with
    | none =>
        cases hrightChoice : decidedFirst rightDecisions (right.trans s₂) with
        | none => exact .absent
        | some rightOutput =>
            obtain ⟨rightAction, target₂⟩ := rightOutput
            apply UniformCellClass.rightOnly
            apply unmatched_step_target_uniformly_dead right left
              (fun Y V gs => (heq Y V gs).symm) W x (action := rightAction)
            · unfold autStep
              rw [hrightStep]
              exact hrightChoice
            · intro hmatch
              obtain ⟨target₁, hmatch⟩ := hmatch
              unfold autStep at hmatch
              rw [hleftStep, hleftChoice] at hmatch
              contradiction
    | some leftOutput =>
        obtain ⟨leftAction, target₁⟩ := leftOutput
        cases hrightChoice : decidedFirst rightDecisions (right.trans s₂) with
        | none =>
            apply UniformCellClass.leftOnly
            apply unmatched_step_target_uniformly_dead left right heq W x
              (action := leftAction)
            · unfold autStep
              rw [hleftStep]
              exact hleftChoice
            · intro hmatch
              obtain ⟨target₂, hmatch⟩ := hmatch
              unfold autStep at hmatch
              rw [hrightStep, hrightChoice] at hmatch
              contradiction
        | some rightOutput =>
            obtain ⟨rightAction, target₂⟩ := rightOutput
            by_cases haction : leftAction = rightAction
            · subst rightAction
              apply UniformCellClass.matched
              apply matched_step_targets_uniform_langEq left right heq W x
                (action := leftAction)
              · unfold autStep
                rw [hleftStep]
                exact hleftChoice
              · unfold autStep
                rw [hrightStep]
                exact hrightChoice
            · apply UniformCellClass.mismatch leftAction rightAction target₁ target₂ haction
              · apply unmatched_step_target_uniformly_dead left right heq W x
                  (action := leftAction)
                · unfold autStep
                  rw [hleftStep]
                  exact hleftChoice
                · intro hmatch
                  obtain ⟨found, hmatch⟩ := hmatch
                  unfold autStep at hmatch
                  rw [hrightStep, hrightChoice, Option.some.injEq,
                    Prod.mk.injEq] at hmatch
                  exact haction hmatch.1.symm
              · apply unmatched_step_target_uniformly_dead right left
                  (fun Y V gs => (heq Y V gs).symm) W x (action := rightAction)
                · unfold autStep
                  rw [hrightStep]
                  exact hrightChoice
                · intro hmatch
                  obtain ⟨found, hmatch⟩ := hmatch
                  unfold autStep at hmatch
                  rw [hleftStep, hleftChoice, Option.some.injEq,
                    Prod.mk.injEq] at hmatch
                  exact haction hmatch.1
  · left
    intro X W x
    cases hvalue : bval W (GkatFaithful.guardCell decisions) x with
    | false => rfl
    | true => exact False.elim (hsatisfiable ⟨X, W, x, hvalue⟩)

/-- The one-state automaton with no accepting behavior. -/
def zeroGAut (A T : Type) : GAut Unit A T where
  states := [()]
  hlt := fun _ => .zero
  trans := fun _ => []
  start := ()

theorem zeroGAut_language_empty
    (X : Type) (W : T → X → Bool) (gs : GS A X) :
    ¬ autLang W (zeroGAut A T) () gs := by
  obtain ⟨x, tail⟩ := gs
  cases tail with
  | nil => simp [autLang, autRun, zeroGAut, bval]
  | cons item tail => simp [autLang, autRun, autStep, firstMatch, zeroGAut]

/-- A uniformly dead state is uniformly language-equivalent to the explicit zero
    automaton. -/
theorem uniformDead_eq_zeroGAut (aut : GAut S A T) (state : S)
    (hdead : UniformAutLempty aut state) :
    UniformAutLangEq aut (zeroGAut A T) state () := by
  intro X W gs
  constructor
  · intro h
    exact False.elim (hdead X W gs h)
  · intro h
    exact False.elim (zeroGAut_language_empty X W gs h)

/-- Uniform deadness is forward closed along every transition that can actually fire.
    The target is uniformly dead even though the witnessing step uses only one valuation. -/
theorem uniformDead_step_target
    (aut : GAut S A T) {state target : S}
    (hdead : UniformAutLempty aut state)
    {X : Type} (W : T → X → Bool) (x : X)
    {action : A} (hstep : autStep W aut state x = some (action, target)) :
    UniformAutLempty aut target := by
  apply unmatched_step_target_uniformly_dead aut (zeroGAut A T)
    (uniformDead_eq_zeroGAut aut state hdead) W x hstep
  intro hmatch
  obtain ⟨sink, hmatch⟩ := hmatch
  simp [autStep, firstMatch, zeroGAut] at hmatch

/-- Cell-level form of forward closure. A satisfiable assignment selecting a transition
    out of a uniformly dead state selects a uniformly dead target. -/
theorem uniformDead_decided_target
    (aut : GAut S A T) {state : S}
    (hdead : UniformAutLempty aut state)
    (decisions : List (BExp T × Bool))
    (hassignment : GkatFaithful.IsGuardAssignment
      ((aut.trans state).map (fun transition => transition.1)) decisions)
    {action : A} {target : S}
    (hchoice : decidedFirst decisions (aut.trans state) = some (action, target))
    {X : Type} (W : T → X → Bool) (x : X)
    (hcell : bval W (GkatFaithful.guardCell decisions) x = true) :
    UniformAutLempty aut target := by
  apply uniformDead_step_target aut hdead W x
  unfold autStep
  rw [firstMatch_eq_decidedFirst W x (aut.trans state) decisions
    hassignment hcell]
  exact hchoice

/-- A symbolic edge is effective when some complete assignment cell selects it and that
    cell is satisfiable in the free Boolean algebra. -/
def UniformEffectiveStep (aut : GAut S A T) (source target : S) : Prop :=
  ∃ (action : A) (decisions : List (BExp T × Bool)),
    GkatFaithful.IsGuardAssignment
      ((aut.trans source).map (fun transition => transition.1)) decisions ∧
    (∃ (X : Type) (W : T → X → Bool) (x : X),
      bval W (GkatFaithful.guardCell decisions) x = true) ∧
    decidedFirst decisions (aut.trans source) = some (action, target)

theorem decidedFirst_map_target
    (decisions : List (BExp T × Bool))
    (transitions : List (BExp T × A × S₁)) (f : S₁ → S₂) :
    decidedFirst decisions
      (transitions.map (fun transition =>
        (transition.1, transition.2.1, f transition.2.2))) =
      (decidedFirst decisions transitions).map
        (fun output => (output.1, f output.2)) := by
  induction decisions generalizing transitions with
  | nil => rfl
  | cons decision decisions ih =>
      cases transitions with
      | nil => rfl
      | cons transition transitions =>
          obtain ⟨guard, action, target⟩ := transition
          obtain ⟨test, bit⟩ := decision
          simp only [List.map_cons, decidedFirst]
          cases bit <;> simp [ih]

theorem uniformEffectiveStep_sum_inl_iff
    (left : GAut S₁ A T) (right : GAut S₂ A T)
    (source target : S₁) :
    UniformEffectiveStep (sumGAut left right) (.inl source) (.inl target) ↔
      UniformEffectiveStep left source target := by
  constructor
  · rintro ⟨action, decisions, hassignment, hsatisfiable, hchoice⟩
    refine ⟨action, decisions, ?_, hsatisfiable, ?_⟩
    · simpa only [sumGAut, List.map_map, Function.comp_apply] using hassignment
    · dsimp only [sumGAut] at hchoice
      rw [decidedFirst_map_target] at hchoice
      cases hbase : decidedFirst decisions (left.trans source) with
      | none => simp [hbase] at hchoice
      | some output =>
          obtain ⟨foundAction, foundTarget⟩ := output
          simp only [hbase, Option.map_some, Option.some.injEq,
            Prod.mk.injEq, Sum.inl.injEq] at hchoice
          obtain ⟨rfl, rfl⟩ := hchoice
          rfl
  · rintro ⟨action, decisions, hassignment, hsatisfiable, hchoice⟩
    refine ⟨action, decisions, ?_, hsatisfiable, ?_⟩
    · simpa only [sumGAut, List.map_map, Function.comp_apply] using hassignment
    · dsimp only [sumGAut]
      rw [decidedFirst_map_target, hchoice]
      rfl

theorem uniformEffectiveStep_sum_inr_iff
    (left : GAut S₁ A T) (right : GAut S₂ A T)
    (source target : S₂) :
    UniformEffectiveStep (sumGAut left right) (.inr source) (.inr target) ↔
      UniformEffectiveStep right source target := by
  constructor
  · rintro ⟨action, decisions, hassignment, hsatisfiable, hchoice⟩
    refine ⟨action, decisions, ?_, hsatisfiable, ?_⟩
    · simpa only [sumGAut, List.map_map, Function.comp_apply] using hassignment
    · dsimp only [sumGAut] at hchoice
      rw [decidedFirst_map_target] at hchoice
      cases hbase : decidedFirst decisions (right.trans source) with
      | none => simp [hbase] at hchoice
      | some output =>
          obtain ⟨foundAction, foundTarget⟩ := output
          simp only [hbase, Option.map_some, Option.some.injEq,
            Prod.mk.injEq, Sum.inr.injEq] at hchoice
          obtain ⟨rfl, rfl⟩ := hchoice
          rfl
  · rintro ⟨action, decisions, hassignment, hsatisfiable, hchoice⟩
    refine ⟨action, decisions, ?_, hsatisfiable, ?_⟩
    · simpa only [sumGAut, List.map_map, Function.comp_apply] using hassignment
    · dsimp only [sumGAut]
      rw [decidedFirst_map_target, hchoice]
      rfl

theorem uniformEffectiveStep_sum_inl_target
    (left : GAut S₁ A T) (right : GAut S₂ A T)
    (source : S₁) (target : Sum S₁ S₂)
    (hstep : UniformEffectiveStep (sumGAut left right) (.inl source) target) :
    ∃ target₁, target = .inl target₁ ∧ UniformEffectiveStep left source target₁ := by
  obtain ⟨action, decisions, hassignment, hsatisfiable, hchoice⟩ := hstep
  dsimp only [sumGAut] at hchoice
  rw [decidedFirst_map_target] at hchoice
  cases hbase : decidedFirst decisions (left.trans source) with
  | none => simp [hbase] at hchoice
  | some output =>
      obtain ⟨foundAction, foundTarget⟩ := output
      simp only [hbase, Option.map_some, Option.some.injEq,
        Prod.mk.injEq] at hchoice
      obtain ⟨rfl, rfl⟩ := hchoice
      refine ⟨foundTarget, rfl, ?_⟩
      exact (uniformEffectiveStep_sum_inl_iff left right source foundTarget).mp
        ⟨foundAction, decisions, hassignment, hsatisfiable, by
          dsimp only [sumGAut]
          rw [decidedFirst_map_target, hbase]
          rfl⟩

theorem uniformEffectiveStep_sum_inr_target
    (left : GAut S₁ A T) (right : GAut S₂ A T)
    (source : S₂) (target : Sum S₁ S₂)
    (hstep : UniformEffectiveStep (sumGAut left right) (.inr source) target) :
    ∃ target₂, target = .inr target₂ ∧ UniformEffectiveStep right source target₂ := by
  obtain ⟨action, decisions, hassignment, hsatisfiable, hchoice⟩ := hstep
  dsimp only [sumGAut] at hchoice
  rw [decidedFirst_map_target] at hchoice
  cases hbase : decidedFirst decisions (right.trans source) with
  | none => simp [hbase] at hchoice
  | some output =>
      obtain ⟨foundAction, foundTarget⟩ := output
      simp only [hbase, Option.map_some, Option.some.injEq,
        Prod.mk.injEq] at hchoice
      obtain ⟨rfl, rfl⟩ := hchoice
      refine ⟨foundTarget, rfl, ?_⟩
      exact (uniformEffectiveStep_sum_inr_iff left right source foundTarget).mp
        ⟨foundAction, decisions, hassignment, hsatisfiable, by
          dsimp only [sumGAut]
          rw [decidedFirst_map_target, hbase]
          rfl⟩

inductive UniformEffectiveReaches (aut : GAut S A T) (source : S) : S → Prop where
  | refl : UniformEffectiveReaches aut source source
  | tail {middle target : S} :
      UniformEffectiveReaches aut source middle →
      UniformEffectiveStep aut middle target →
      UniformEffectiveReaches aut source target

theorem uniformEffectiveReaches_sum_inl
    (left : GAut S₁ A T) (right : GAut S₂ A T)
    (source : S₁) {target : Sum S₁ S₂}
    (hreach : UniformEffectiveReaches (sumGAut left right) (.inl source) target) :
    ∃ target₁, target = .inl target₁ ∧
      UniformEffectiveReaches left source target₁ := by
  induction hreach with
  | refl => exact ⟨source, rfl, UniformEffectiveReaches.refl⟩
  | @tail middle target hprefix hstep ih =>
      obtain ⟨middle₁, rfl, hleftPrefix⟩ := ih
      obtain ⟨target₁, rfl, hleftStep⟩ :=
        uniformEffectiveStep_sum_inl_target left right middle₁ target hstep
      exact ⟨target₁, rfl, UniformEffectiveReaches.tail hleftPrefix hleftStep⟩

theorem uniformEffectiveReaches_sum_inr
    (left : GAut S₁ A T) (right : GAut S₂ A T)
    (source : S₂) {target : Sum S₁ S₂}
    (hreach : UniformEffectiveReaches (sumGAut left right) (.inr source) target) :
    ∃ target₂, target = .inr target₂ ∧
      UniformEffectiveReaches right source target₂ := by
  induction hreach with
  | refl => exact ⟨source, rfl, UniformEffectiveReaches.refl⟩
  | @tail middle target hprefix hstep ih =>
      obtain ⟨middle₂, rfl, hrightPrefix⟩ := ih
      obtain ⟨target₂, rfl, hrightStep⟩ :=
        uniformEffectiveStep_sum_inr_target left right middle₂ target hstep
      exact ⟨target₂, rfl, UniformEffectiveReaches.tail hrightPrefix hrightStep⟩

theorem uniformEffectiveReaches_sum_inl_iff
    (left : GAut S₁ A T) (right : GAut S₂ A T) (source target : S₁) :
    UniformEffectiveReaches (sumGAut left right) (.inl source) (.inl target) ↔
      UniformEffectiveReaches left source target := by
  constructor
  · intro h
    obtain ⟨found, heq, hreach⟩ := uniformEffectiveReaches_sum_inl left right source h
    exact Sum.inl.inj heq ▸ hreach
  · intro h
    induction h with
    | refl => exact UniformEffectiveReaches.refl
    | tail hprefix hstep ih =>
        exact UniformEffectiveReaches.tail ih
          ((uniformEffectiveStep_sum_inl_iff left right _ _).mpr hstep)

theorem uniformEffectiveReaches_sum_inr_iff
    (left : GAut S₁ A T) (right : GAut S₂ A T) (source target : S₂) :
    UniformEffectiveReaches (sumGAut left right) (.inr source) (.inr target) ↔
      UniformEffectiveReaches right source target := by
  constructor
  · intro h
    obtain ⟨found, heq, hreach⟩ := uniformEffectiveReaches_sum_inr left right source h
    exact Sum.inr.inj heq ▸ hreach
  · intro h
    induction h with
    | refl => exact UniformEffectiveReaches.refl
    | tail hprefix hstep ih =>
        exact UniformEffectiveReaches.tail ih
          ((uniformEffectiveStep_sum_inr_iff left right _ _).mpr hstep)

/-- Every state effectively reachable from a uniformly dead state is uniformly dead.
    Listed transitions hidden behind contradictory or shadowed guards are deliberately
    excluded; they are the unreachable live states that invalidated the naive all-state
    zero construction. -/
theorem uniformDead_effective_reaches
    (aut : GAut S A T) {source target : S}
    (hdead : UniformAutLempty aut source)
    (hreach : UniformEffectiveReaches aut source target) :
    UniformAutLempty aut target := by
  induction hreach with
  | refl => exact hdead
  | @tail middle target _ hstep ih =>
      obtain ⟨action, decisions, hassignment,
        ⟨X, W, x, hcell⟩, hchoice⟩ := hstep
      exact uniformDead_decided_target aut ih decisions hassignment
        hchoice W x hcell

/-- Keep precisely the listed states effectively reachable from a chosen source. The
    transition equations themselves are unchanged; only the set of equations required by
    `SolvesBA` is restricted. -/
noncomputable def effectiveReachableSubaut
    (aut : GAut S A T) (source : S) : GAut S A T where
  states := aut.states.filter (fun state =>
    @decide (UniformEffectiveReaches aut source state)
      (Classical.propDecidable _))
  hlt := aut.hlt
  trans := aut.trans
  start := source

theorem effectiveReachableSubaut_mem_reaches
    (aut : GAut S A T) (source state : S)
    (hstate : state ∈ (effectiveReachableSubaut aut source).states) :
    UniformEffectiveReaches aut source state := by
  simp only [effectiveReachableSubaut, List.mem_filter, decide_eq_true_eq] at hstate
  exact hstate.2

/-- The effective reachable subsystem of a uniformly dead state has a direct all-zero
    solution. This is the rigorous partial-solution result needed for dead-fiber pruning;
    no claim is made yet that it extends to equations of semantically unreachable states. -/
theorem effectiveDeadSubaut_allZero_solvesBA
    (aut : GAut S A T) (source : S)
    (hdead : UniformAutLempty aut source) :
    SolvesBA (effectiveReachableSubaut aut source)
      (fun _ => (.test .zero : Exp A T)) := by
  apply allZero_solvesBA_of_halt_false
  intro state hstate
  have hstateDead : UniformAutLempty aut state :=
    uniformDead_effective_reaches aut hdead
      (effectiveReachableSubaut_mem_reaches aut source state hstate)
  apply EquivBA.baTest
  intro X W x
  change bval W (aut.hlt state) x = false
  have hnot : ¬ autLang W aut state (x, []) := hstateDead X W (x, [])
  simp only [autLang, autRun] at hnot
  cases hvalue : bval W (aut.hlt state) x with
  | false => rfl
  | true => exact False.elim (hnot hvalue)

def UniformEffectiveReachesFrom (aut : GAut S A T)
    (roots : List S) (state : S) : Prop :=
  ∃ root ∈ roots, UniformEffectiveReaches aut root state

def leftRoots : List (Sum S₁ S₂) → List S₁
  | [] => []
  | .inl state :: roots => state :: leftRoots roots
  | .inr _ :: roots => leftRoots roots

def rightRoots : List (Sum S₁ S₂) → List S₂
  | [] => []
  | .inl _ :: roots => rightRoots roots
  | .inr state :: roots => state :: rightRoots roots

theorem mem_leftRoots_iff (roots : List (Sum S₁ S₂)) (state : S₁) :
    state ∈ leftRoots roots ↔ Sum.inl state ∈ roots := by
  induction roots with
  | nil => simp [leftRoots]
  | cons root roots ih =>
      cases root <;> simp [leftRoots, ih]

theorem mem_rightRoots_iff (roots : List (Sum S₁ S₂)) (state : S₂) :
    state ∈ rightRoots roots ↔ Sum.inr state ∈ roots := by
  induction roots with
  | nil => simp [rightRoots]
  | cons root roots ih =>
      cases root <;> simp [rightRoots, ih]

theorem uniformEffectiveReachesFrom_sum_inl_iff
    (left : GAut S₁ A T) (right : GAut S₂ A T)
    (roots : List (Sum S₁ S₂)) (target : S₁) :
    UniformEffectiveReachesFrom (sumGAut left right) roots (.inl target) ↔
      UniformEffectiveReachesFrom left (leftRoots roots) target := by
  constructor
  · rintro ⟨root, hroot, hreach⟩
    cases root with
    | inl source =>
        exact ⟨source, (mem_leftRoots_iff roots source).mpr hroot,
          (uniformEffectiveReaches_sum_inl_iff left right source target).mp hreach⟩
    | inr source =>
        obtain ⟨found, heq, _⟩ :=
          uniformEffectiveReaches_sum_inr left right source hreach
        cases heq
  · rintro ⟨source, hsource, hreach⟩
    exact ⟨.inl source, (mem_leftRoots_iff roots source).mp hsource,
      (uniformEffectiveReaches_sum_inl_iff left right source target).mpr hreach⟩

theorem uniformEffectiveReachesFrom_sum_inr_iff
    (left : GAut S₁ A T) (right : GAut S₂ A T)
    (roots : List (Sum S₁ S₂)) (target : S₂) :
    UniformEffectiveReachesFrom (sumGAut left right) roots (.inr target) ↔
      UniformEffectiveReachesFrom right (rightRoots roots) target := by
  constructor
  · rintro ⟨root, hroot, hreach⟩
    cases root with
    | inl source =>
        obtain ⟨found, heq, _⟩ :=
          uniformEffectiveReaches_sum_inl left right source hreach
        cases heq
    | inr source =>
        exact ⟨source, (mem_rightRoots_iff roots source).mpr hroot,
          (uniformEffectiveReaches_sum_inr_iff left right source target).mp hreach⟩
  · rintro ⟨source, hsource, hreach⟩
    exact ⟨.inr source, (mem_rightRoots_iff roots source).mp hsource,
      (uniformEffectiveReaches_sum_inr_iff left right source target).mpr hreach⟩

theorem autRun_sumGAut_inl_iff
    {X : Type} (W : T → X → Bool)
    (left : GAut S₁ A T) (right : GAut S₂ A T)
    (state : S₁) (x : X) (tail : List (A × X)) :
    autRun W (sumGAut left right) (.inl state) x tail ↔
      autRun W left state x tail := by
  induction tail generalizing state x with
  | nil => rfl
  | cons item tail ih =>
      obtain ⟨action, nextAtom⟩ := item
      simp only [autRun, autStep_sumGAut_inl]
      constructor
      · rintro ⟨target, hstep, hrun⟩
        cases hbase : autStep W left state x with
        | none => simp [hbase] at hstep
        | some output =>
            obtain ⟨foundAction, foundTarget⟩ := output
            simp only [hbase, Option.map_some, Option.some.injEq,
              Prod.mk.injEq] at hstep
            obtain ⟨rfl, rfl⟩ := hstep
            exact ⟨foundTarget, rfl, (ih foundTarget nextAtom).mp hrun⟩
      · rintro ⟨target, hstep, hrun⟩
        exact ⟨.inl target, by rw [hstep]; rfl,
          (ih target nextAtom).mpr hrun⟩

theorem autRun_sumGAut_inr_iff
    {X : Type} (W : T → X → Bool)
    (left : GAut S₁ A T) (right : GAut S₂ A T)
    (state : S₂) (x : X) (tail : List (A × X)) :
    autRun W (sumGAut left right) (.inr state) x tail ↔
      autRun W right state x tail := by
  induction tail generalizing state x with
  | nil => rfl
  | cons item tail ih =>
      obtain ⟨action, nextAtom⟩ := item
      simp only [autRun, autStep_sumGAut_inr]
      constructor
      · rintro ⟨target, hstep, hrun⟩
        cases hbase : autStep W right state x with
        | none => simp [hbase] at hstep
        | some output =>
            obtain ⟨foundAction, foundTarget⟩ := output
            simp only [hbase, Option.map_some, Option.some.injEq,
              Prod.mk.injEq] at hstep
            obtain ⟨rfl, rfl⟩ := hstep
            exact ⟨foundTarget, rfl, (ih foundTarget nextAtom).mp hrun⟩
      · rintro ⟨target, hstep, hrun⟩
        exact ⟨.inr target, by rw [hstep]; rfl,
          (ih target nextAtom).mpr hrun⟩

theorem uniformDead_sumGAut_inl_iff
    (left : GAut S₁ A T) (right : GAut S₂ A T) (state : S₁) :
    UniformAutLempty (sumGAut left right) (.inl state) ↔
      UniformAutLempty left state := by
  constructor <;> intro hdead X W gs hrun
  · exact hdead X W gs
      ((autRun_sumGAut_inl_iff W left right state gs.1 gs.2).mpr hrun)
  · exact hdead X W gs
      ((autRun_sumGAut_inl_iff W left right state gs.1 gs.2).mp hrun)

theorem uniformDead_sumGAut_inr_iff
    (left : GAut S₁ A T) (right : GAut S₂ A T) (state : S₂) :
    UniformAutLempty (sumGAut left right) (.inr state) ↔
      UniformAutLempty right state := by
  constructor <;> intro hdead X W gs hrun
  · exact hdead X W gs
      ((autRun_sumGAut_inr_iff W left right state gs.1 gs.2).mpr hrun)
  · exact hdead X W gs
      ((autRun_sumGAut_inr_iff W left right state gs.1 gs.2).mp hrun)

noncomputable def effectiveReachableFromSubaut
    (aut : GAut S A T) (roots : List S) : GAut S A T where
  states := aut.states.filter (fun state =>
    @decide (UniformEffectiveReachesFrom aut roots state)
      (Classical.propDecidable _))
  hlt := aut.hlt
  trans := aut.trans
  start := aut.start

theorem effectiveReachableFromSubaut_mem_reaches
    (aut : GAut S A T) (roots : List S) (state : S)
    (hstate : state ∈ (effectiveReachableFromSubaut aut roots).states) :
    UniformEffectiveReachesFrom aut roots state := by
  simp only [effectiveReachableFromSubaut, List.mem_filter,
    decide_eq_true_eq] at hstate
  exact hstate.2

/-- A finite union of effective reachable components rooted at uniformly dead states is
    uniformly dead and therefore has the direct all-zero solution. -/
theorem effectiveDeadRootsSubaut_allZero_solvesBA
    (aut : GAut S A T) (roots : List S)
    (hroots : ∀ root ∈ roots, UniformAutLempty aut root) :
    SolvesBA (effectiveReachableFromSubaut aut roots)
      (fun _ => (.test .zero : Exp A T)) := by
  apply allZero_solvesBA_of_halt_false
  intro state hstate
  obtain ⟨root, hroot, hreach⟩ :=
    effectiveReachableFromSubaut_mem_reaches aut roots state hstate
  have hstateDead : UniformAutLempty aut state :=
    uniformDead_effective_reaches aut (hroots root hroot) hreach
  apply EquivBA.baTest
  intro X W x
  change bval W (aut.hlt state) x = false
  have hnot : ¬ autLang W aut state (x, []) := hstateDead X W (x, [])
  simp only [autLang, autRun] at hnot
  cases hvalue : bval W (aut.hlt state) x with
  | false => rfl
  | true => exact False.elim (hnot hvalue)

/-- Finite-root extension is the compositional form required by Thompson constructors. -/
def EffectiveSolutionsExtendFromBA (aut : GAut S A T) (roots : List S) : Prop :=
  ∀ (subSol : S → Exp A T),
    SolvesBA (effectiveReachableFromSubaut aut roots) subSol →
    ∃ full : S → Exp A T,
      SolvesBA aut full ∧
      ∀ state ∈ (effectiveReachableFromSubaut aut roots).states,
        EquivBA (full state) (subSol state)

def DeadEffectiveFiniteExtensionsBA (aut : GAut S A T) : Prop :=
  ∀ roots : List S,
    (∀ root ∈ roots, UniformAutLempty aut root) →
    EffectiveSolutionsExtendFromBA aut roots

theorem effectiveReachableFrom_singleton_iff
    (aut : GAut S A T) (source state : S) :
    UniformEffectiveReachesFrom aut [source] state ↔
      UniformEffectiveReaches aut source state := by
  constructor
  · rintro ⟨root, hroot, hreach⟩
    simp only [List.mem_singleton] at hroot
    subst root
    exact hreach
  · intro hreach
    exact ⟨source, by simp, hreach⟩

/-- Source-local extension property for the effective reachable subsystem. -/
def EffectiveSolutionExtendsAtBA (aut : GAut S A T) (source : S) : Prop :=
  ∀ (subSol : S → Exp A T),
    SolvesBA (effectiveReachableSubaut aut source) subSol →
    ∃ full : S → Exp A T,
      SolvesBA aut full ∧
      ∀ state ∈ (effectiveReachableSubaut aut source).states,
        EquivBA (full state) (subSol state)

/-- Uniform version, retained as the eventual constructor-induction target. -/
def EffectiveSolutionsExtendBA (aut : GAut S A T) : Prop :=
  ∀ source, EffectiveSolutionExtendsAtBA aut source

/-- The exact Thompson induction target only asks for extension at uniformly dead
    sources; demanding it at live internal states is unnecessary. -/
def DeadEffectiveSolutionsExtendBA (aut : GAut S A T) : Prop :=
  ∀ source, UniformAutLempty aut source →
    EffectiveSolutionExtendsAtBA aut source

/-- The finite-root property subsumes the source-local interface. -/
theorem deadFiniteExtensions_implies_deadSourceExtension
    (aut : GAut S A T) (hall : DeadEffectiveFiniteExtensionsBA aut) :
    DeadEffectiveSolutionsExtendBA aut := by
  intro source hdead subSol hsub
  have hfrom : SolvesBA (effectiveReachableFromSubaut aut [source]) subSol := by
    intro state hstate
    apply hsub state
    simp only [effectiveReachableFromSubaut, effectiveReachableSubaut,
      List.mem_filter, decide_eq_true_eq] at hstate ⊢
    exact ⟨hstate.1,
      (effectiveReachableFrom_singleton_iff aut source state).mp hstate.2⟩
  obtain ⟨full, hfull, hext⟩ := hall [source]
    (by
      intro root hroot
      have heq : root = source := by simpa using hroot
      subst root
      exact hdead) subSol hfrom
  refine ⟨full, hfull, ?_⟩
  intro state hstate
  apply hext state
  simp only [effectiveReachableFromSubaut, effectiveReachableSubaut,
    List.mem_filter, decide_eq_true_eq] at hstate ⊢
  exact ⟨hstate.1,
    (effectiveReachableFrom_singleton_iff aut source state).mpr hstate.2⟩

/-- If every listed state is effectively reachable from the source, the restricted
    equation set already contains every equation and extension is immediate. -/
theorem effectiveSolutionExtendsAt_of_all_reachable
    (aut : GAut S A T) (source : S)
    (hall : ∀ state ∈ aut.states,
      UniformEffectiveReaches aut source state) :
    EffectiveSolutionExtendsAtBA aut source := by
  intro subSol hsub
  refine ⟨subSol, ?_, ?_⟩
  · intro state hstate
    apply hsub state
    simp only [effectiveReachableSubaut, List.mem_filter, decide_eq_true_eq]
    exact ⟨hstate, hall state hstate⟩
  · intro state hstate
    exact EquivBA.base (Equiv.refl _)

/-- Base constructor: a materialized test has only its pseudostart, so every listed
    equation is reachable from it. -/
theorem thompsonTest_dead_effective_extension (test : BExp T) :
    DeadEffectiveSolutionsExtendBA (thompsonTest (A := A) test).toGAut := by
  intro source hdead
  cases source with
  | none =>
      apply effectiveSolutionExtendsAt_of_all_reachable
      intro state hstate
      cases state with
      | none => exact UniformEffectiveReaches.refl
      | some impossible => exact nomatch impossible
  | some impossible => exact nomatch impossible

/-- Base constructor: neither state of the one-action Thompson automaton is uniformly
    dead. The pseudostart accepts one action and the internal state accepts immediately. -/
theorem thompsonAction_dead_effective_extension (action : A) :
    DeadEffectiveSolutionsExtendBA (thompsonAction (T := T) action).toGAut := by
  intro source hdead
  exfalso
  cases source with
  | none =>
      let W : T → Unit → Bool := fun _ _ => false
      apply hdead Unit W ((), [(action, ())])
      simp [autLang, autRun, autStep, firstMatch,
        InitializedGAut.toGAut, thompsonAction, W, bval]
  | some state =>
      cases state
      let W : T → Unit → Bool := fun _ _ => false
      apply hdead Unit W ((), [])
      simp [autLang, autRun, InitializedGAut.toGAut,
        thompsonAction, W, bval]

/-- The extension property would discharge the dead-label obligation without assuming
    language completeness: extend the verified all-zero reachable solution, then apply
    finite-axiom Thompson uniqueness pointwise. -/
theorem dead_thompson_label_eq_zero_of_effective_extension
    (program : Exp A T)
    (state : Option (certifiedThompson A T program).State)
    (hextend : EffectiveSolutionExtendsAtBA
      (certifiedThompson A T program).aut.toGAut state)
    (hstate : state ∈ (certifiedThompson A T program).aut.toGAut.states)
    (hdead : UniformAutLempty
      (certifiedThompson A T program).aut.toGAut state) :
    EquivBA (initializedStandard program
      (certifiedThompson A T program).standard state) (.test .zero) := by
  let aut := (certifiedThompson A T program).aut.toGAut
  let zero : Option (certifiedThompson A T program).State → Exp A T :=
    fun _ => .test .zero
  have hsubSol : SolvesBA (effectiveReachableSubaut aut state) zero :=
    effectiveDeadSubaut_allZero_solvesBA aut state hdead
  obtain ⟨full, hfull, hext⟩ := hextend zero hsubSol
  have hsubstate : state ∈ (effectiveReachableSubaut aut state).states := by
    simp only [effectiveReachableSubaut, List.mem_filter, decide_eq_true_eq]
    exact ⟨hstate, UniformEffectiveReaches.refl⟩
  have hcanonical :=
    (certifiedThompson A T program).certificate.toGAut_state_canonical
      (certifiedThompson A T program).aut
      (certifiedThompson A T program).standard program full hfull state hstate
  exact EquivBA.trans (EquivBA.symm hcanonical) (hext state hsubstate)

def AutLangEq {X : Type} (W : T → X → Bool) (left : GAut S₁ A T)
    (right : GAut S₂ A T) (s₁ : S₁) (s₂ : S₂) : Prop :=
  ∀ gs : GS A X, autLang W left s₁ gs ↔ autLang W right s₂ gs

def AutLempty {X : Type} (W : T → X → Bool) (aut : GAut S A T) (state : S) : Prop :=
  ∀ gs : GS A X, ¬ autLang W aut state gs

def GAutBisimUpToEmpty {X : Type} (W : T → X → Bool)
    (left : GAut S₁ A T) (right : GAut S₂ A T)
    (R : S₁ → S₂ → Prop) : Prop :=
  ∀ s₁ s₂, R s₁ s₂ →
    (∀ x, bval W (left.hlt s₁) x = bval W (right.hlt s₂) x) ∧
    (∀ x action target₁, autStep W left s₁ x = some (action, target₁) →
      AutLempty W left target₁ ∨
        ∃ target₂, autStep W right s₂ x = some (action, target₂) ∧ R target₁ target₂) ∧
    (∀ x action target₂, autStep W right s₂ x = some (action, target₂) →
      AutLempty W right target₂ ∨
        ∃ target₁, autStep W left s₁ x = some (action, target₁) ∧ R target₁ target₂)

theorem autLang_cons_step
    {X : Type} (W : T → X → Bool) (aut : GAut S A T)
    {state target : S} {x x' : X} {action : A} {tail : List (A × X)}
    (hstep : autStep W aut state x = some (action, target)) :
    autLang W aut state (x, (action, x') :: tail) ↔
      autLang W aut target (x', tail) := by
  simp only [autLang, autRun]
  constructor
  · rintro ⟨target', hstep', hrun⟩
    rw [hstep, Option.some.injEq, Prod.mk.injEq] at hstep'
    obtain ⟨_, htarget⟩ := hstep'
    rw [← htarget] at hrun
    exact hrun
  · intro hrun
    exact ⟨target, hstep, hrun⟩

/-- For arbitrary deterministic guarded automata, equality of state languages is a
    bisimulation up to empty residuals. Ordinary `GAutBisim` would be false here. -/
theorem autLangEq_is_bisim_up_to_empty
    {X : Type} (W : T → X → Bool) (left : GAut S₁ A T) (right : GAut S₂ A T) :
    GAutBisimUpToEmpty W left right (AutLangEq W left right) := by
  intro s₁ s₂ heq
  refine ⟨?_, ?_, ?_⟩
  · intro x
    have hempty := heq (x, [])
    simp only [autLang, autRun] at hempty
    cases hleft : bval W (left.hlt s₁) x <;>
      cases hright : bval W (right.hlt s₂) x <;> simp_all
  · intro x action target₁ hstep₁
    by_cases hmatch : ∃ target₂,
        autStep W right s₂ x = some (action, target₂)
    · obtain ⟨target₂, hstep₂⟩ := hmatch
      exact Or.inr ⟨target₂, hstep₂, fun gs => by
        obtain ⟨x', tail⟩ := gs
        exact (autLang_cons_step W left hstep₁).symm.trans
          ((heq (x, (action, x') :: tail)).trans
            (autLang_cons_step W right hstep₂))⟩
    · exact Or.inl (fun gs hrun => by
        obtain ⟨x', tail⟩ := gs
        have hrightRun := (heq (x, (action, x') :: tail)).mp
          ((autLang_cons_step W left hstep₁).mpr hrun)
        simp only [autLang, autRun] at hrightRun
        obtain ⟨target₂, hstep₂, _⟩ := hrightRun
        exact hmatch ⟨target₂, hstep₂⟩)
  · intro x action target₂ hstep₂
    by_cases hmatch : ∃ target₁,
        autStep W left s₁ x = some (action, target₁)
    · obtain ⟨target₁, hstep₁⟩ := hmatch
      exact Or.inr ⟨target₁, hstep₁, fun gs => by
        obtain ⟨x', tail⟩ := gs
        exact (autLang_cons_step W left hstep₁).symm.trans
          ((heq (x, (action, x') :: tail)).trans
            (autLang_cons_step W right hstep₂))⟩
    · exact Or.inl (fun gs hrun => by
        obtain ⟨x', tail⟩ := gs
        have hleftRun := (heq (x, (action, x') :: tail)).mpr
          ((autLang_cons_step W right hstep₂).mpr hrun)
        simp only [autLang, autRun] at hleftRun
        obtain ⟨target₁, hstep₁, _⟩ := hleftRun
        exact hmatch ⟨target₁, hstep₁⟩)

theorem gaut_bisim_up_to_empty_sound
    {X : Type} (W : T → X → Bool)
    (left : GAut S₁ A T) (right : GAut S₂ A T)
    {R : S₁ → S₂ → Prop} (hR : GAutBisimUpToEmpty W left right R) :
    ∀ {s₁ s₂}, R s₁ s₂ → AutLangEq W left right s₁ s₂ := by
  have key : ∀ (tail : List (A × X)) (s₁ : S₁) (s₂ : S₂) (x : X),
      R s₁ s₂ → (autRun W left s₁ x tail ↔ autRun W right s₂ x tail) := by
    intro tail
    induction tail with
    | nil =>
        intro s₁ s₂ x hrel
        simp only [autRun]
        rw [(hR s₁ s₂ hrel).1 x]
    | cons head tail ih =>
        obtain ⟨action, x'⟩ := head
        intro s₁ s₂ x hrel
        obtain ⟨_, hfwd, hbwd⟩ := hR s₁ s₂ hrel
        simp only [autRun]
        constructor
        · rintro ⟨target₁, hstep₁, hrun₁⟩
          rcases hfwd x action target₁ hstep₁ with hempty | ⟨target₂, hstep₂, hnext⟩
          · exact absurd hrun₁ (hempty (x', tail))
          · exact ⟨target₂, hstep₂, (ih target₁ target₂ x' hnext).mp hrun₁⟩
        · rintro ⟨target₂, hstep₂, hrun₂⟩
          rcases hbwd x action target₂ hstep₂ with hempty | ⟨target₁, hstep₁, hnext⟩
          · exact absurd hrun₂ (hempty (x', tail))
          · exact ⟨target₁, hstep₁, (ih target₁ target₂ x' hnext).mpr hrun₂⟩
  intro s₁ s₂ hrel gs
  exact key gs.2 s₁ s₂ gs.1 hrel

theorem autLangEq_iff_bisim_up_to_empty
    {X : Type} (W : T → X → Bool)
    (left : GAut S₁ A T) (right : GAut S₂ A T) (s₁ : S₁) (s₂ : S₂) :
    AutLangEq W left right s₁ s₂ ↔
      ∃ R, GAutBisimUpToEmpty W left right R ∧ R s₁ s₂ :=
  ⟨fun h => ⟨AutLangEq W left right,
      autLangEq_is_bisim_up_to_empty W left right, h⟩,
    fun ⟨R, hR, hrel⟩ => gaut_bisim_up_to_empty_sound W left right hR hrel⟩

/-- Uniform guarded-language equivalence of programs therefore relates the starts of
    their certified Thompson automata by a bisimulation up to dead residuals, for every
    interpretation. This is the correct replacement for the false ordinary-bisimulation
    quotient premise. -/
theorem certifiedThompson_starts_bisim_up_to_empty
    {A T : Type} {leftProgram rightProgram : Exp A T}
    (heq : UniformLanguageEquivalent leftProgram rightProgram)
    (X : Type) (W : T → X → Bool) :
    ∃ R, GAutBisimUpToEmpty W
      (certifiedThompson A T leftProgram).aut.toGAut
      (certifiedThompson A T rightProgram).aut.toGAut R ∧ R none none := by
  apply (autLangEq_iff_bisim_up_to_empty W
    (certifiedThompson A T leftProgram).aut.toGAut
    (certifiedThompson A T rightProgram).aut.toGAut none none).mp
  intro gs
  rw [certifiedThompson_start_language leftProgram X W,
    certifiedThompson_start_language rightProgram X W]
  exact heq X W gs

/-- The same start-state fact with the quantifiers retained uniformly. This stronger
    relation is what permits `unmatched_step_target_uniformly_dead` to combine an
    enabling source valuation with an arbitrary residual valuation. -/
theorem certifiedThompson_starts_uniform_langEq
    {A T : Type} {leftProgram rightProgram : Exp A T}
    (heq : UniformLanguageEquivalent leftProgram rightProgram) :
    UniformAutLangEq
      (certifiedThompson A T leftProgram).aut.toGAut
      (certifiedThompson A T rightProgram).aut.toGAut none none := by
  intro X W gs
  rw [certifiedThompson_start_language leftProgram X W,
    certifiedThompson_start_language rightProgram X W]
  exact heq X W gs

#print axioms thompsonTest_parametricCanonical
#print axioms initial_program_decomposition
#print axioms thompsonAction_parametricCanonical
#print axioms thompsonTest_parametricInitial
#print axioms thompsonAction_parametricInitial
#print axioms ParametricCanonicalBA.unique
#print axioms ParametricCanonicalBA.sum
#print axioms StandardSolvesBA.sumSystems
#print axioms ite_paramFallback
#print axioms ParametricThompsonBA.ite
#print axioms ThompsonCertificateBA.ite
#print axioms guardedFold_connect
#print axioms ite_paramFallback_zero
#print axioms guardedFold_branch_congr
#print axioms initialDerivative_factor
#print axioms StandardSolvesBA.withContinuation
#print axioms loopInitial_feedback
#print axioms loopStandard_feedback
#print axioms loopInitialized_standardSolves
#print axioms loopFeedback_canonical
#print axioms ParametricThompsonBA.loop
#print axioms loopInitialized_initTargets
#print axioms loopInitialized_initDisjoint
#print axioms ThompsonCertificateBA.loop
#print axioms eqRHSParam_seqGSystem_inl
#print axioms ParametricCanonicalBA.seq
#print axioms ParametricThompsonBA.seq
#print axioms ThompsonCertificateBA.seq
#print axioms iteInitialized_coreStructural
#print axioms seqInitialized_coreStructural
#print axioms loopInitialized_coreStructural
#print axioms certifiedThompson
#print axioms certifiedThompson_solution_unique
#print axioms certifiedThompson_initial_canonical
#print axioms certifiedThompson_initial_recovers_program
#print axioms transitionBranches_option_map
#print axioms InitializedGAut.toGAut_uniformWF
#print axioms ThompsonCertificateBA.toGAut_solves
#print axioms ThompsonCertificateBA.toGAut_start_language
#print axioms certifiedThompson_toGAut_solves
#print axioms certifiedThompson_uniformWF
#print axioms certifiedThompson_start_language
#print axioms certifiedThompson_state_language
#print axioms while_false_eq_one
#print axioms productive_while_true_eq_zero
#print axioms while_true_eq_zero
#print axioms certifiedThompson_state_empty_iff
#print axioms uniformExpLempty_iff_zero
#print axioms dead_thompson_label_eq_zero_of_complete
#print axioms guardedFold_else_restrict
#print axioms guardedFold_effective
#print axioms effectiveBranches_pairwise_disjoint
#print axioms ite_zero_before_disjoint_test
#print axioms guardedFold_dead_before_test
#print axioms guardedFold_append_dead_preserves
#print axioms eqRHS_append_dead_transitions_preserves
#print axioms solvesBA_append_dead_transitions
#print axioms deadSinkBase_solvesBA
#print axioms completeWithDeadSink_solvesBA
#print axioms guardedFold_all_zero
#print axioms allZero_solvesBA_of_halt_false
#print axioms allZero_solvesBA_of_uniform_dead
#print axioms ThompsonCertificateBA.toGAut_start_canonical
#print axioms certifiedThompson_common_solved_quotient
#print axioms certifiedThompson_uniform_solved_quotient
#print axioms eqRHS_solution_congr
#print axioms UniformBehavioralGAutQuotient.solves_of_descends
#print axioms autLangEq_is_bisim_up_to_empty
#print axioms bval_map_atoms
#print axioms autRun_map_atoms
#print axioms autLang_map_atoms
#print axioms unmatched_step_target_uniformly_dead
#print axioms matched_step_targets_uniform_langEq
#print axioms uniform_cell_classification
#print axioms zeroGAut_language_empty
#print axioms uniformDead_step_target
#print axioms uniformDead_effective_reaches
#print axioms effectiveDeadSubaut_allZero_solvesBA
#print axioms effectiveDeadRootsSubaut_allZero_solvesBA
#print axioms decidedFirst_map_target
#print axioms uniformEffectiveStep_sum_inl_iff
#print axioms uniformEffectiveStep_sum_inr_iff
#print axioms uniformEffectiveReachesFrom_sum_inl_iff
#print axioms uniformEffectiveReachesFrom_sum_inr_iff
#print axioms uniformDead_sumGAut_inl_iff
#print axioms uniformDead_sumGAut_inr_iff
#print axioms ThompsonCertificateBA.toGAut_state_canonical
#print axioms effectiveSolutionExtendsAt_of_all_reachable
#print axioms deadFiniteExtensions_implies_deadSourceExtension
#print axioms thompsonTest_dead_effective_extension
#print axioms thompsonAction_dead_effective_extension
#print axioms dead_thompson_label_eq_zero_of_effective_extension
#print axioms gaut_bisim_up_to_empty_sound
#print axioms autLangEq_iff_bisim_up_to_empty
#print axioms certifiedThompson_starts_bisim_up_to_empty
#print axioms certifiedThompson_starts_uniform_langEq

end GkatThompson
