import GkatSynthesisProofs

/-!
# The positive fork, discharged on the hard pair

`completeness_of_solvable_intermediate` reduces finite-axiom completeness to one existence
statement: every uniformly equivalent pair admits a **common intermediate that is solvable
by the syntax**.  This file discharges that statement for the pair that refutes the cospan,

    e = p ; while b do p        f = (if b then 1 else p) ; while b do p

so the replacement target is not merely unrefuted there — it is *met*, through the same
machinery, end to end.

The intermediate is `h = if b then e else f`, and it is solvable for a trivial reason once
the framing is right: it is a Thompson automaton, so it covers itself.  What has to be
proved is that it covers *both sides* as an `InitCover` — the pseudostate-preserving cover
the synthesis engine consumes — which is strictly more than the behavioural quotient
`GkatSpanWitnessProofs` already builds, because `InitCover` separates the initial dynamics
from the core dynamics.

That separation is the whole point.  The cospan died because the collapse had to *be*
syntax-generated; the intermediate here only has to be *covered by* syntax, and the covers
compose.

Axioms: `[propext, Quot.sound]`, `sorryAx`-free.
-/

namespace GkatPositiveFork

open GkatSyntax GkatGS GkatKleene GkatFaithful GkatThompson GkatCrystallization
open GkatCollapseRefutation GkatSpanWitness GkatSynthesis

/-! ## The three automata, at the initialized level

    `InitCover` speaks about `initTrans` and `core.trans` directly, not about the `toGAut`
    bridge, so the transition lists are re-pinned here without the `some`. -/

private abbrev hA := (certifiedThompson Act Tst hProg).aut
private abbrev eA := (certifiedThompson Act Tst eProg).aut
private abbrev fA := (certifiedThompson Act Tst fProg).aut

/-- Every action state on every side has this one transition: fire on `b`. -/
private theorem fm_single {S X : Type} (W : Tst → X → Bool) (x : X) (t : S) :
    firstMatch W x [(BExp.and BExp.one (BExp.and bT BExp.one), ((), t))]
      = if W () x then some ((), t) else none := by
  cases hb : W () x <;> simp [firstMatch, bval, bT, hb] <;> rfl

/-! ## Step computations, initialized level -/

private theorem h_init {X : Type} (W : Tst → X → Bool) (x : X) :
    firstMatch W x hA.initTrans
      = if W () x then some ((), Sum.inl (Sum.inl ()))
        else some ((), Sum.inr (Sum.inl (Sum.inr ()))) := by
  rw [show hA.initTrans =
    [ (BExp.and bT BExp.one, ((), Sum.inl (Sum.inl ())))
    , (BExp.and bT (BExp.and BExp.zero (BExp.and bT BExp.one)), ((), Sum.inl (Sum.inr ())))
    , (BExp.and (BExp.not bT) (BExp.and (BExp.not bT) BExp.one), ((),
        Sum.inr (Sum.inl (Sum.inr ()))))
    , (BExp.and (BExp.not bT)
        (BExp.and (BExp.or (BExp.and bT BExp.one) (BExp.and (BExp.not bT) BExp.zero))
          (BExp.and bT BExp.one)), ((), Sum.inr (Sum.inr ()))) ] from rfl]
  cases hb : W () x <;> simp [firstMatch, bval, bT, hb] <;> rfl

private theorem e_init {X : Type} (W : Tst → X → Bool) (x : X) :
    firstMatch W x eA.initTrans = some ((), Sum.inl ()) := by
  rw [show eA.initTrans =
    [ (BExp.one, ((), Sum.inl ()))
    , (BExp.and BExp.zero (BExp.and bT BExp.one), ((), Sum.inr ())) ] from rfl]
  simp [firstMatch, bval] <;> rfl

private theorem f_init {X : Type} (W : Tst → X → Bool) (x : X) :
    firstMatch W x fA.initTrans
      = if W () x then some ((), Sum.inr ()) else some ((), Sum.inl (Sum.inr ())) := by
  rw [show fA.initTrans =
    [ (BExp.and (BExp.not bT) BExp.one, ((), Sum.inl (Sum.inr ())))
    , (BExp.and (BExp.or (BExp.and bT BExp.one) (BExp.and (BExp.not bT) BExp.zero))
        (BExp.and bT BExp.one), ((), Sum.inr ())) ] from rfl]
  cases hb : W () x <;> simp [firstMatch, bval, bT, hb] <;> rfl

private theorem h_core_ll {X : Type} (W : Tst → X → Bool) (x : X) :
    firstMatch W x (hA.core.trans (Sum.inl (Sum.inl ())))
      = if W () x then some ((), Sum.inl (Sum.inr ())) else none := by
  rw [show hA.core.trans (Sum.inl (Sum.inl ())) =
    [(BExp.and BExp.one (BExp.and bT BExp.one), ((), Sum.inl (Sum.inr ())))] from rfl]
  exact fm_single W x _

private theorem h_core_lr {X : Type} (W : Tst → X → Bool) (x : X) :
    firstMatch W x (hA.core.trans (Sum.inl (Sum.inr ())))
      = if W () x then some ((), Sum.inl (Sum.inr ())) else none := by
  rw [show hA.core.trans (Sum.inl (Sum.inr ())) =
    [(BExp.and BExp.one (BExp.and bT BExp.one), ((), Sum.inl (Sum.inr ())))] from rfl]
  exact fm_single W x _

private theorem h_core_rl {X : Type} (W : Tst → X → Bool) (x : X) :
    firstMatch W x (hA.core.trans (Sum.inr (Sum.inl (Sum.inr ()))))
      = if W () x then some ((), Sum.inr (Sum.inr ())) else none := by
  rw [show hA.core.trans (Sum.inr (Sum.inl (Sum.inr ()))) =
    [(BExp.and BExp.one (BExp.and bT BExp.one), ((), Sum.inr (Sum.inr ())))] from rfl]
  exact fm_single W x _

private theorem h_core_rr {X : Type} (W : Tst → X → Bool) (x : X) :
    firstMatch W x (hA.core.trans (Sum.inr (Sum.inr ())))
      = if W () x then some ((), Sum.inr (Sum.inr ())) else none := by
  rw [show hA.core.trans (Sum.inr (Sum.inr ())) =
    [(BExp.and BExp.one (BExp.and bT BExp.one), ((), Sum.inr (Sum.inr ())))] from rfl]
  exact fm_single W x _

private theorem e_core_l {X : Type} (W : Tst → X → Bool) (x : X) :
    firstMatch W x (eA.core.trans (Sum.inl ()))
      = if W () x then some ((), Sum.inr ()) else none := by
  rw [show eA.core.trans (Sum.inl ()) =
    [(BExp.and BExp.one (BExp.and bT BExp.one), ((), Sum.inr ()))] from rfl]
  exact fm_single W x _

private theorem e_core_r {X : Type} (W : Tst → X → Bool) (x : X) :
    firstMatch W x (eA.core.trans (Sum.inr ()))
      = if W () x then some ((), Sum.inr ()) else none := by
  rw [show eA.core.trans (Sum.inr ()) =
    [(BExp.and BExp.one (BExp.and bT BExp.one), ((), Sum.inr ()))] from rfl]
  exact fm_single W x _

private theorem f_core_l {X : Type} (W : Tst → X → Bool) (x : X) :
    firstMatch W x (fA.core.trans (Sum.inl (Sum.inr ())))
      = if W () x then some ((), Sum.inr ()) else none := by
  rw [show fA.core.trans (Sum.inl (Sum.inr ())) =
    [(BExp.and BExp.one (BExp.and bT BExp.one), ((), Sum.inr ()))] from rfl]
  exact fm_single W x _

private theorem f_core_r {X : Type} (W : Tst → X → Bool) (x : X) :
    firstMatch W x (fA.core.trans (Sum.inr ()))
      = if W () x then some ((), Sum.inr ()) else none := by
  rw [show fA.core.trans (Sum.inr ()) =
    [(BExp.and BExp.one (BExp.and bT BExp.one), ((), Sum.inr ()))] from rfl]
  exact fm_single W x _

/-! ## The two legs, as `InitCover`s -/

/-- `h`'s core states: `e`'s two action occurrences, then `f`'s two. -/
private def phiCore : (certifiedThompson Act Tst hProg).State →
    (certifiedThompson Act Tst eProg).State
  | Sum.inl u => u
  | Sum.inr (Sum.inl (Sum.inl z)) => nomatch z
  | Sum.inr (Sum.inl (Sum.inr _)) => Sum.inl ()
  | Sum.inr (Sum.inr _) => Sum.inr ()

private def psiCore : (certifiedThompson Act Tst hProg).State →
    (certifiedThompson Act Tst fProg).State
  | Sum.inl _ => Sum.inr ()
  | Sum.inr (Sum.inl (Sum.inl z)) => nomatch z
  | Sum.inr (Sum.inl (Sum.inr _)) => Sum.inl (Sum.inr ())
  | Sum.inr (Sum.inr _) => Sum.inr ()

/-- The `e` leg. -/
def phiCover : InitCover hA eA where
  map := phiCore
  initHlt_eq := fun _ W x => by
    show bval W (BExp.or (BExp.and bT (BExp.and BExp.zero (BExp.not bT)))
      (BExp.and (BExp.not bT)
        (BExp.and (BExp.or (BExp.and bT BExp.one) (BExp.and (BExp.not bT) BExp.zero))
          (BExp.not bT)))) x
      = bval W (BExp.and BExp.zero (BExp.not bT)) x
    cases hb : W () x <;> simp [bval, bT, hb]
  coreHlt_eq := fun s _ _ _ => by
    cases s with
    | inl u => cases u with | inl _ => rfl | inr _ => rfl
    | inr w =>
        cases w with
        | inl y => cases y with | inl z => exact nomatch z | inr _ => rfl
        | inr _ => rfl
  initStep_eq := fun _ W x => by
    rw [h_init, e_init]
    cases hb : W () x <;> simp [hb] <;> rfl
  coreStep_eq := fun s _ W x => by
    cases s with
    | inl u =>
        cases u with
        | inl _ =>
            show (firstMatch W x (hA.core.trans (Sum.inl (Sum.inl ())))).map
                (fun o => (o.1, phiCore o.2)) = firstMatch W x (eA.core.trans (Sum.inl ()))
            rw [h_core_ll, e_core_l]; cases hb : W () x <;> simp [hb] <;> rfl
        | inr _ =>
            show (firstMatch W x (hA.core.trans (Sum.inl (Sum.inr ())))).map
                (fun o => (o.1, phiCore o.2)) = firstMatch W x (eA.core.trans (Sum.inr ()))
            rw [h_core_lr, e_core_r]; cases hb : W () x <;> simp [hb] <;> rfl
    | inr w =>
        cases w with
        | inl y =>
            cases y with
            | inl z => exact nomatch z
            | inr _ =>
                show (firstMatch W x (hA.core.trans (Sum.inr (Sum.inl (Sum.inr ()))))).map
                    (fun o => (o.1, phiCore o.2))
                  = firstMatch W x (eA.core.trans (Sum.inl ()))
                rw [h_core_rl, e_core_l]; cases hb : W () x <;> simp [hb] <;> rfl
        | inr _ =>
            show (firstMatch W x (hA.core.trans (Sum.inr (Sum.inr ())))).map
                (fun o => (o.1, phiCore o.2)) = firstMatch W x (eA.core.trans (Sum.inr ()))
            rw [h_core_rr, e_core_r]; cases hb : W () x <;> simp [hb] <;> rfl
  maps := by
    intro s _
    cases s with
    | inl u =>
        cases u with
        | inl _ => exact List.Mem.head _
        | inr _ => exact List.Mem.tail _ (List.Mem.head _)
    | inr w =>
        cases w with
        | inl y =>
            cases y with
            | inl z => exact nomatch z
            | inr _ => exact List.Mem.head _
        | inr _ => exact List.Mem.tail _ (List.Mem.head _)
  onto := by
    intro q _
    cases q with
    | inl _ => exact ⟨Sum.inl (Sum.inl ()), List.Mem.head _, rfl⟩
    | inr _ => exact ⟨Sum.inl (Sum.inr ()), List.Mem.tail _ (List.Mem.head _), rfl⟩

/-- The `f` leg. -/
def psiCover : InitCover hA fA where
  map := psiCore
  initHlt_eq := fun _ W x => by
    show bval W (BExp.or (BExp.and bT (BExp.and BExp.zero (BExp.not bT)))
      (BExp.and (BExp.not bT)
        (BExp.and (BExp.or (BExp.and bT BExp.one) (BExp.and (BExp.not bT) BExp.zero))
          (BExp.not bT)))) x
      = bval W (BExp.and (BExp.or (BExp.and bT BExp.one) (BExp.and (BExp.not bT) BExp.zero))
          (BExp.not bT)) x
    cases hb : W () x <;> simp [bval, bT, hb]
  coreHlt_eq := fun s _ _ _ => by
    cases s with
    | inl u => cases u with | inl _ => rfl | inr _ => rfl
    | inr w =>
        cases w with
        | inl y => cases y with | inl z => exact nomatch z | inr _ => rfl
        | inr _ => rfl
  initStep_eq := fun _ W x => by
    rw [h_init, f_init]
    cases hb : W () x <;> simp [hb] <;> rfl
  coreStep_eq := fun s _ W x => by
    cases s with
    | inl u =>
        cases u with
        | inl _ =>
            show (firstMatch W x (hA.core.trans (Sum.inl (Sum.inl ())))).map
                (fun o => (o.1, psiCore o.2)) = firstMatch W x (fA.core.trans (Sum.inr ()))
            rw [h_core_ll, f_core_r]; cases hb : W () x <;> simp [hb] <;> rfl
        | inr _ =>
            show (firstMatch W x (hA.core.trans (Sum.inl (Sum.inr ())))).map
                (fun o => (o.1, psiCore o.2)) = firstMatch W x (fA.core.trans (Sum.inr ()))
            rw [h_core_lr, f_core_r]; cases hb : W () x <;> simp [hb] <;> rfl
    | inr w =>
        cases w with
        | inl y =>
            cases y with
            | inl z => exact nomatch z
            | inr _ =>
                show (firstMatch W x (hA.core.trans (Sum.inr (Sum.inl (Sum.inr ()))))).map
                    (fun o => (o.1, psiCore o.2))
                  = firstMatch W x (fA.core.trans (Sum.inl (Sum.inr ())))
                rw [h_core_rl, f_core_l]; cases hb : W () x <;> simp [hb] <;> rfl
        | inr _ =>
            show (firstMatch W x (hA.core.trans (Sum.inr (Sum.inr ())))).map
                (fun o => (o.1, psiCore o.2)) = firstMatch W x (fA.core.trans (Sum.inr ()))
            rw [h_core_rr, f_core_r]; cases hb : W () x <;> simp [hb] <;> rfl
  maps := by
    intro s _
    cases s with
    | inl _ => exact List.Mem.tail _ (List.Mem.head _)
    | inr w =>
        cases w with
        | inl y =>
            cases y with
            | inl z => exact nomatch z
            | inr _ => exact List.Mem.head _
        | inr _ => exact List.Mem.tail _ (List.Mem.head _)
  onto := by
    intro q _
    cases q with
    | inl y =>
        cases y with
        | inl z => exact nomatch z
        | inr _ =>
            exact ⟨Sum.inr (Sum.inl (Sum.inr ())),
              List.Mem.tail _ (List.Mem.tail _ (List.Mem.head _)), rfl⟩
    | inr _ => exact ⟨Sum.inl (Sum.inl ()), List.Mem.head _, rfl⟩

/-! ## The fork, discharged -/

/-- **The positive fork holds on the refuting pair.**  `h = if b then e else f` is a common
    intermediate covering both sides, and it is solvable by the syntax — trivially, since it
    is itself a Thompson automaton.

    This is the exact hypothesis of `completeness_of_solvable_intermediate`, instantiated at
    the pair for which the cospan is provably impossible. -/
theorem solvable_intermediate_for_the_refuting_pair :
    ∃ (S : Type) (mid : InitializedGAut S Act Tst),
      Nonempty (InitCover mid (certifiedThompson Act Tst eProg).aut) ∧
      Nonempty (InitCover mid (certifiedThompson Act Tst fProg).aut) ∧
      HasThompsonCover mid :=
  ⟨(certifiedThompson Act Tst hProg).State, hA,
    ⟨phiCover⟩, ⟨psiCover⟩, ⟨hProg, ⟨InitCover.id _⟩⟩⟩

/-- Non-vacuity: running the discharged fork through the reduction re-derives the pair's
    provable equality, independently of both earlier derivations. -/
theorem equivBA_via_the_fork : EquivBA eProg fProg :=
  equivBA_of_common_refinement (InitCover.id hA) phiCover psiCover

#print axioms phiCover
#print axioms psiCover
#print axioms solvable_intermediate_for_the_refuting_pair
#print axioms equivBA_via_the_fork

end GkatPositiveFork
