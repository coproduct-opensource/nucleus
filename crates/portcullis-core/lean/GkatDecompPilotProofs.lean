import GkatRingDecompProofs

/-! # Composition pilot: a mixed quotient solved by the compositional API alone

    The k=6 residue's pair #2 quotient is the smallest mixed shape: a straight-line
    start (s0), a 2-ring {s1, s2} with header s2, an exit from s1 to a fold state
    (s3), and s3 itself.  GkatK6R02 certified it with bespoke recipes; this file
    solves the same automaton using ONLY the compositional lemmas — extHeaderSol,
    extSol, refl folds — demonstrating the DAG-assembly story on real data:

      s3  (fold, test ¬t)   ←  s1 exits here
      ring: header s2 (exit ¬t), walk [s1]; s1 steps to s2 on t
      s0  (fold) → s1, s3

    Everything a general Decomp datatype must produce, produced by hand once. -/

namespace GkatDecompPilot

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatRingSupport GkatGuardedAlgebra
open GkatResidue GkatRingPlan GkatRingPlan2 GkatRingDecomp

abbrev Tst := Unit
abbrev Act := Unit
def bT : BExp Tst := .prim ()
def pA : Exp Act Tst := .act ()

/-- s3: the terminal fold. -/
def sol3 : Exp Act Tst := .test (.not bT)

/-- The ring: header s2 (no self-loop, steps to the walk on `t`, exits on `¬t`);
    walk = [s1], where s1 exits to s3 on `¬t` and steps home on `t`. -/
def N1 : ExtNode Act Tst where
  loopG := .zero
  loopA := ()
  loopW := []
  exits := [((.not bT), (), sol3)]
  stepG := bT
  stepA := ()
  hltG := .zero

def RING : ExtRing Act Tst where
  hLoopG := .zero
  hLoopA := ()
  hLoopW := []
  hStepG := bT
  hStepA := ()
  exitG := .not bT
  nodes := [N1]

def sol2 : Exp Act Tst := extHeaderSol RING
def sol1 : Exp Act Tst := extSol N1 sol2

/-- s0: the straight-line start — its solution IS its equation. -/
def sol0 : Exp Act Tst :=
  .ite (.not bT) (.seq pA sol3) (.ite bT (.seq pA sol1) (.test BExp.zero))

/-- The assembled automaton (dead arms included, keeping every state in the uniform
    dispatch shape the compositional lemmas produce). -/
def QAut : GAut Nat Act Tst where
  states := [0, 1, 2, 3]
  hlt
    | 2 => .not bT
    | 3 => .not bT
    | _ => BExp.zero
  trans
    | 0 => [((.not bT), (), 3), (bT, (), 1)]
    | 1 => [(BExp.zero, (), 1), ((.not bT), (), 3), (bT, (), 2)]
    | 2 => [(bT, (), 1), (BExp.zero, (), 2)]
    | _ => []
  start := 0

def qsol : Nat → Exp Act Tst
  | 0 => sol0
  | 1 => sol1
  | 2 => sol2
  | _ => sol3

/-! ## The absorption facts the composition needs -/

/-- s3's solution absorbs the ring's header solution: subset absorption at `¬t ⊆ ¬t`. -/
private theorem habs3 : EquivBA (.seq sol3 sol2) sol3 :=
  test_header_absorb_sub (.not bT) (.not bT) (.or bT BExp.zero) (extBody RING)
    (fun X W x h => by
      show (!(bval W bT x || false)) = true
      revert h
      show bval W (.not bT) x = true → _
      cases hb : W () x <;> simp [bval, bT, hb])
    (fun X W x => by cases hb : W () x <;> simp [bval, bT, hb])

/-- Walk-node halts are dead. -/
private theorem hdead1 : GuardEmpty (BExp.zero : BExp Tst) := fun _ _ _ => rfl

/-! ## The four state equations, from the compositional API alone -/

theorem E2 : EquivBA sol2 (eqRHS QAut qsol 2) := by
  have h := extHeaderSol_solves RING
    (fun X W x => by
      show (bval W bT x && bval W BExp.zero x) = false
      cases hb : W () x <;> simp [bval, bT, hb])
    N1 [] rfl
    (fun n hn => by
      have : n = N1 := by simpa [RING] using hn
      subst this
      exact test_empty_absorb (fun _ _ _ => rfl) _)
    (fun n hn x hx => by
      have hn' : n = N1 := by simpa [RING] using hn
      subst hn'
      have hx' : x = ((.not bT), (), sol3) := by simpa [N1] using hx
      subst hx'
      exact habs3)
    (fun g hg => by simp [RING] at hg)
  exact h

theorem E1 : EquivBA sol1 (eqRHS QAut qsol 1) := by
  have h := extSol_solves N1 sol2 (fun g hg => by simp [N1] at hg)
  exact h

theorem E0 : EquivBA sol0 (eqRHS QAut qsol 0) :=
  EquivBA.base (Equiv.refl _)

theorem E3 : EquivBA sol3 (eqRHS QAut qsol 3) :=
  EquivBA.base (Equiv.refl _)

/-- **The composite automaton is solved** — folds by refl, the ring by its two
    compositional lemmas, glued by nothing but the solution assignment. -/
theorem composite_solves : SolvesBA QAut qsol := by
  intro s hs
  match s, hs with
  | 0, _ => exact E0
  | 1, _ => exact E1
  | 2, _ => exact E2
  | 3, _ => exact E3

#print axioms composite_solves

end GkatDecompPilot
