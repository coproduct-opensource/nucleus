import GkatGuardedStringProofs

/-!
# Faithfulness bridges: earning "not a GKAT theorem" and non-vacuity

Two honesty repairs to the guarded-string frontier results, closing gaps surfaced by
an adversarial audit.

## (a) The test Boolean algebra — `left_distrib` is not a theorem of GKAT *with tests*
`GkatSyntax.Equiv` axiomatizes GKAT's guarded-union/sequencing/loop axioms but NOT
the Boolean algebra on tests. So `left_distrib_not_gkat_theorem` literally says "not
derivable from U/S/W"; real GKAT could in principle use BA reasoning on tests. It
cannot — because the guarded-string model **validates the test Boolean algebra**:
`bval` is a BA homomorphism, so BA-equal tests denote equal languages (`den_test_ba`).
Extending the axioms with the full test BA (`EquivBA`) keeps the model sound
(`sound_BA`), and left-distributivity STILL fails — `left_distrib_not_ba_theorem`.
This upgrades the claim from "not derivable from a subset" to "not a theorem of GKAT
with its test Boolean algebra."

## (b) `two_state_semantic_uniqueness` is non-vacuous
"Any two solutions are equal" is vacuous if no productive system has a solution.
`two_state_uniqueness_nonvacuous` exhibits a concrete productive 2-state system with a
**non-empty** solution `g₀ = g₁ = (p)^(b)`, so the uniqueness theorem has real content.

Axioms `[propext, Quot.sound]`, `sorryAx`-free.
-/

namespace GkatFaithful

open GkatSyntax GkatGS

variable {A T Atom : Type} (V : T → Atom → Bool)

-- ── (a) The test Boolean algebra is validated by the model ───────────────────

/-- BA-equal tests (equal under every Boolean valuation) denote equal languages.
    This is the semantic content of "the model validates the test Boolean algebra":
    `bval` factors through the free Boolean algebra on `T`. -/
theorem den_test_ba {b c : BExp T}
    (h : ∀ (X : Type) (W : T → X → Bool) (x : X), bval W b x = bval W c x) :
    ∀ gs : GS A Atom, den V (.test b : Exp A T) gs ↔ den V (.test c) gs := by
  intro gs; simp only [den_test, h Atom V gs.1]

/-- GKAT's axioms **plus the full test Boolean algebra**: `Equiv` extended with the
    rule that BA-equal tests are equivalent (and congruence to propagate it). -/
inductive EquivBA : Exp A T → Exp A T → Prop where
  | base {e f} : Equiv e f → EquivBA e f
  | symm {e f} : EquivBA e f → EquivBA f e
  | trans {e f g} : EquivBA e f → EquivBA f g → EquivBA e g
  | seq_c {e e' f f'} : EquivBA e e' → EquivBA f f' → EquivBA (.seq e f) (.seq e' f')
  | ite_c {b e e' f f'} : EquivBA e e' → EquivBA f f' → EquivBA (.ite b e f) (.ite b e' f')
  | wh_c {b e e'} : EquivBA e e' → EquivBA (.wh b e) (.wh b e')
  | baTest {b c : BExp T} :
      (∀ (X : Type) (W : T → X → Bool) (x : X), bval W b x = bval W c x) →
      EquivBA (.test b : Exp A T) (.test c)

/-- **Soundness for GKAT + test BA.** The guarded-string model validates every
    equivalence provable from the GKAT axioms together with the test Boolean algebra.
    Base cases reuse `sound`; the `baTest` case is `den_test_ba`. -/
theorem sound_BA {e f : Exp A T} (h : EquivBA e f) :
    ∀ gs : GS A Atom, den V e gs ↔ den V f gs := by
  induction h with
  | base h => exact sound V h
  | symm _ ih => intro gs; exact (ih gs).symm
  | trans _ _ ih1 ih2 => intro gs; exact (ih1 gs).trans (ih2 gs)
  | seq_c _ _ ih1 ih2 =>
      intro gs; simp only [den_seq]
      constructor
      · rintro ⟨l1, l2, hl, he, hf⟩; exact ⟨l1, l2, hl, (ih1 _).mp he, (ih2 _).mp hf⟩
      · rintro ⟨l1, l2, hl, he, hf⟩; exact ⟨l1, l2, hl, (ih1 _).mpr he, (ih2 _).mpr hf⟩
  | ite_c _ _ ih1 ih2 =>
      intro gs; simp only [den_ite]
      constructor
      · rintro (⟨hb, h⟩ | ⟨hb, h⟩)
        · exact Or.inl ⟨hb, (ih1 _).mp h⟩
        · exact Or.inr ⟨hb, (ih2 _).mp h⟩
      · rintro (⟨hb, h⟩ | ⟨hb, h⟩)
        · exact Or.inl ⟨hb, (ih1 _).mpr h⟩
        · exact Or.inr ⟨hb, (ih2 _).mpr h⟩
  | wh_c _ ih => intro gs; exact ⟨InLoop_congr V ih, InLoop_congr V (fun gs => (ih gs).symm)⟩
  | baTest hbc => exact den_test_ba V hbc

/-- **`left_distrib` is not a theorem of GKAT with its test Boolean algebra.** Even
    with the full BA on tests available, `p·(1 +_c 0) ≡ (p·1) +_c (p·0)` is not
    derivable — a sound model (`sound_BA`) refutes it (`left_distrib_fails`). -/
theorem left_distrib_not_ba_theorem :
    ¬ EquivBA (.seq (.act ()) (.ite (.prim ()) (.test .one) (.test .zero)) : Exp Unit Unit)
              (.ite (.prim ()) (.seq (.act ()) (.test .one))
                               (.seq (.act ()) (.test .zero))) :=
  fun h => left_distrib_fails (sound_BA V0 h)

-- ── (b) `two_state_semantic_uniqueness` is non-vacuous ───────────────────────

/-- The `while` unrolling (W1) as a denotational identity: `⟦e^(b)⟧` accepts `gs` iff
    `⟦if b then e·e^(b) else 1⟧` does. -/
theorem den_wh_unfold (b : BExp T) (e : Exp A T) (gs : GS A Atom) :
    den V (.wh b e) gs ↔ den V (.ite b (.seq e (.wh b e)) (.test .one)) gs := by
  simp only [den_wh, den_ite, den_seq, den_test]
  constructor
  · intro h
    cases h with
    | exit a hb => exact Or.inr ⟨hb, rfl, rfl⟩
    | step a l1 rest hb hbody hrec => exact Or.inl ⟨hb, l1, rest, rfl, hbody, hrec⟩
  · rintro (⟨hb, l1, l2, hl, hbody, hloop⟩ | ⟨hb, _, hnil⟩)
    · rw [show gs = (gs.1, l1 ++ l2) from by rw [← hl]]
      exact InLoop.step gs.1 l1 l2 hb hbody hloop
    · rw [show gs = (gs.1, []) from by rw [← hnil]]
      exact InLoop.exit gs.1 hb

/-- **Non-vacuity.** The concrete productive symmetric 2-state system `b = p?`,
    `e = p`, `f = 1` has the **non-empty** solution `g₀ = g₁ = (p)^(b)`: productivity
    holds, both loop equations hold (W1), and the solution accepts `(false, [])`. So
    `GkatUniqFrontier.two_state_semantic_uniqueness` applies to a system that really
    has solutions — it is not vacuously true. -/
theorem two_state_uniqueness_nonvacuous :
    (∀ a : Bool, ¬ den V0 (.act () : Exp Unit Unit) (a, [])) ∧
    (∀ gs : GS Unit Bool, den V0 (.wh (.prim ()) (.act ())) gs ↔
        den V0 (.ite (.prim ()) (.seq (.act ()) (.wh (.prim ()) (.act ()))) (.test .one)) gs) ∧
    den V0 (.wh (.prim ()) (.act ()) : Exp Unit Unit) (false, []) := by
  refine ⟨?_, den_wh_unfold V0 (.prim ()) (.act ()), ?_⟩
  · rintro a ⟨x, y, h⟩; exact absurd (congrArg Prod.snd h) (by simp)
  · exact InLoop.exit false rfl

#print axioms left_distrib_not_ba_theorem
#print axioms two_state_uniqueness_nonvacuous

end GkatFaithful
