/-
  Nucleus / WitnessOlog  (Phase 2 — proof-of-work that accumulates)

  **STATUS: PROVED (0 `sorry`).** Mathlib-free: pure Lean 4 core, discharged by
  `rfl`, structural case analysis, and `omega`. Mirrors the proof style of
  `Nucleus.Auctions.SettlementDecision`.

  This file discharges the two theorems that the Rust crate `nucleus-witness-olog`
  previously carried as MODELED (stated, not proven):

  1. **Functoriality** of the witness→olog map `Gov` — `Gov(g ∘ f) = Gov(g) ∘
     Gov(f)` and `Gov(id) = id`. Modelled here over the *assurance algebra*: a
     derivation step carries a weakest-link assurance, composition is `min` with a
     neutral "no-op" step, and `Gov` carries assurance through UNCHANGED (the
     no-upgrade invariant). `Gov` is constructed as a `Func` whose `map_id` /
     `map_comp` fields are discharged — i.e. *Gov is a functor* is the theorem.
     The Rust counterpart: `nucleus_witness_olog::functor` (`NoUpgradeGov`).

  2. **Fork-cost incentive** — the skin-in-the-game / cost-of-corruption
     inequality the Rust `staying_is_rational` + `FORK_COST_THEOREM_MODELED`
     modelled: when the forfeitable bonded standing is at least the maximum
     defection gain, staying on the canonical ledger is (weakly, and strictly)
     the dominant strategy. Plus a tightness theorem: below that threshold,
     forking pays strictly more — so the condition is exactly right, not
     conservative.

  # Honest scope boundary (read this)

  The functoriality theorem is over the **assurance composition** (objects
  abstracted to a one-object category whose morphisms are weakest-link assurance
  steps). It proves the compositional core — `Gov` respects identity and the
  `min`/weakest-link composition, and never upgrades assurance — which is exactly
  the "proven work composes without inflating trust" claim. It does NOT model the
  full content of an olog instance (the real lineage DAG + instance digests);
  that richer functoriality remains future work (tracked alongside the olog Lean
  `sorry` budget). The fork-cost theorem is a closed, non-vacuous game-theoretic
  inequality with no scope caveat.
-/

namespace Nucleus.WitnessOlog

-- ───────────────────────────────────────────────────────────────────────
-- The assurance algebra: weakest-link composition of derivation steps.
-- ───────────────────────────────────────────────────────────────────────

/-- An assurance rung (0 = self-reported … 4 = zk upper-envelope). -/
abbrev Rung : Type := Nat

/-- A derivation step's contribution to a pipeline's assurance. `none` is the
    neutral "no-op" step (an identity — degrades nothing, the top element);
    `some r` is a step whose assurance is rung `r`. -/
abbrev Step : Type := Option Rung

/-- Compose two steps: the assurance of the composite is the **weakest link**
    (`min`). The no-op step `none` is neutral. -/
def stepComp : Step → Step → Step
  | none,   y      => y
  | x,      none   => x
  | some a, some b => some (Nat.min a b)

/-- The identity (no-op) step. -/
def stepId : Step := none

theorem stepId_comp (x : Step) : stepComp stepId x = x := rfl

theorem stepComp_id (x : Step) : stepComp x stepId = x := by
  cases x <;> rfl

theorem stepComp_assoc (x y z : Step) :
    stepComp (stepComp x y) z = stepComp x (stepComp y z) := by
  cases x with
  | none => rfl
  | some a =>
    cases y with
    | none => rfl
    | some b =>
      cases z with
      | none => rfl
      | some c =>
        exact congrArg some (Nat.min_assoc a b c)

/-- **Weakest-link (explicit).** The composite of two concrete steps is the
    `min` of their rungs — a pipeline is only as assured as its weakest step. -/
theorem weakest_link (a b : Rung) :
    stepComp (some a) (some b) = some (Nat.min a b) := rfl

theorem pipeline_le_left (a b : Rung) : Nat.min a b ≤ a := Nat.min_le_left a b
theorem pipeline_le_right (a b : Rung) : Nat.min a b ≤ b := Nat.min_le_right a b

-- ───────────────────────────────────────────────────────────────────────
-- A minimal (Mathlib-free) category + functor.
-- ───────────────────────────────────────────────────────────────────────

/-- A category: objects, hom-types, identities, composition, and the unit +
    associativity laws as proof fields. -/
structure Cat where
  Obj : Type
  Hom : Obj → Obj → Type
  idm : (X : Obj) → Hom X X
  compm : {X Y Z : Obj} → Hom X Y → Hom Y Z → Hom X Z
  id_comp : ∀ {X Y : Obj} (f : Hom X Y), compm (idm X) f = f
  comp_id : ∀ {X Y : Obj} (f : Hom X Y), compm f (idm Y) = f
  assoc : ∀ {W X Y Z : Obj} (f : Hom W X) (g : Hom X Y) (h : Hom Y Z),
            compm (compm f g) h = compm f (compm g h)

/-- A functor: an object map + a morphism map that preserve identity and
    composition. Constructing one (with `map_id` / `map_comp` discharged) IS the
    proof that the map is functorial. -/
structure Func (C D : Cat) where
  obj : C.Obj → D.Obj
  map : {X Y : C.Obj} → C.Hom X Y → D.Hom (obj X) (obj Y)
  map_id : ∀ (X : C.Obj), map (C.idm X) = D.idm (obj X)
  map_comp : ∀ {X Y Z : C.Obj} (f : C.Hom X Y) (g : C.Hom Y Z),
               map (C.compm f g) = D.compm (map f) (map g)

/-- The assurance category: one object; morphisms are weakest-link assurance
    steps. The unit + associativity laws are exactly the `Step` monoid laws. -/
def AssuranceCat : Cat where
  Obj := Unit
  Hom := fun _ _ => Step
  idm := fun _ => stepId
  compm := fun f g => stepComp f g
  id_comp := fun f => stepId_comp f
  comp_id := fun f => stepComp_id f
  assoc := fun f g h => stepComp_assoc f g h

/-- **The witness→olog functor `Gov`.** Objects map across; assurance is carried
    through UNCHANGED (`map := id` on steps — the no-upgrade invariant). The
    `map_id` / `map_comp` fields below being discharged is the *functoriality
    theorem*: `Gov` respects identity and weakest-link composition. -/
def Gov : Func AssuranceCat AssuranceCat where
  obj := fun _ => ()
  map := fun f => f
  map_id := fun _ => rfl
  map_comp := fun _ _ => rfl

/-- **Functoriality (PROVED).** The two functor laws for `Gov`, packaged as one
    theorem: `Gov` preserves identities and weakest-link composition. This is the
    discharge of `nucleus-witness-olog`'s previously-MODELED functoriality claim —
    "proven work composes (and `Gov` never inflates assurance)". -/
theorem gov_is_functor :
    (∀ X : AssuranceCat.Obj,
        Gov.map (AssuranceCat.idm X) = AssuranceCat.idm (Gov.obj X))
  ∧ (∀ {X Y Z : AssuranceCat.Obj}
        (f : AssuranceCat.Hom X Y) (g : AssuranceCat.Hom Y Z),
        Gov.map (AssuranceCat.compm f g) = AssuranceCat.compm (Gov.map f) (Gov.map g)) :=
  ⟨Gov.map_id, fun f g => Gov.map_comp f g⟩

/-- **No-upgrade (explicit).** `Gov` carries a step's assurance through exactly —
    it never inflates trust. -/
theorem gov_no_upgrade (s : Step) :
    @Func.map AssuranceCat AssuranceCat Gov () () s = s := rfl

-- ───────────────────────────────────────────────────────────────────────
-- Fork-cost incentive (skin-in-the-game / cost of corruption).
-- ───────────────────────────────────────────────────────────────────────

namespace ForkCost

/-- Payoff of STAYING on the canonical ledger, as the baseline (the honest flow
    is identical whether or not you defect, so it cancels out of the decision and
    is normalised to 0). -/
def stayPayoff : Int := 0

/-- Net payoff of FORKING / defecting: capture the defection gain `g`, but FORFEIT
    the bonded standing `b` (non-portable — pinned to the canonical
    transparency-log root). The honest flow cancels, so the decision is exactly
    `gain − forfeited bond`. -/
def forkPayoff (g b : Int) : Int := g - b

/-- **Fork-cost incentive (PROVED).** When the forfeitable bonded standing is at
    least the maximum defection gain (`g ≤ b`), forking is not profitable —
    staying is weakly dominant. This is the cost-of-corruption inequality the Rust
    `staying_is_rational` (`forfeiture ≥ gain`) + `FORK_COST_THEOREM_MODELED`
    modelled; here discharged sorry-free, with no sign assumptions. -/
theorem staying_dominates (g b : Int) (hbg : g ≤ b) :
    forkPayoff g b ≤ stayPayoff := by
  unfold forkPayoff stayPayoff
  omega

/-- Strict version: a stake strictly larger than any defection gain makes staying
    the *strictly* dominant strategy. -/
theorem staying_strictly_dominates (g b : Int) (hbg : g < b) :
    forkPayoff g b < stayPayoff := by
  unfold forkPayoff stayPayoff
  omega

/-- **Tightness.** Below the threshold (`b < g`) forking pays strictly more — so
    `g ≤ b` is exactly the right deterrence condition, not a conservative one. The
    mechanism deters defection precisely when the forfeit covers the gain. -/
theorem forking_pays_when_understaked (g b : Int) (hgb : b < g) :
    stayPayoff < forkPayoff g b := by
  unfold forkPayoff stayPayoff
  omega

end ForkCost

end Nucleus.WitnessOlog
