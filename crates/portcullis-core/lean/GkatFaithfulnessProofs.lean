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

/-- GKAT's U/S/W axioms together with the two-sorted Boolean-test theory.

    **Provenance of every clause beyond `Equiv`.**  POPL'20 defines `≡` as the
    smallest congruence *with respect to all operators* on `Exp` that satisfies
    Figure 1 and subsumes Boolean equivalence, "in the sense that `b ≡_BA c`
    implies `b ≡ c`".  Against that definition:

    * `symm`, `trans`, `seq_c`, `ite_c`, `wh_c` — the congruence clause at
      OPERAND positions.
    * `baTest` — the `≡_BA`-subsumption clause verbatim.  It is stated
      semantically (agreement under every carrier and valuation) because the
      paper establishes that `Bexp/≡_BA` is the FREE Boolean algebra on `T` and
      that `≡_BA` is complete for the truth-assignment semantics; so agreement
      under all valuations IS `≡_BA`, not something stronger.
    * `ite_guard`, `wh_guard` — **ADMISSIBLE, hence harmless.**  These
      transport Boolean equality through GUARD positions, and it is a fair
      question whether they exceed the paper's congruence clause.  They do
      not: guard transport is DERIVABLE from Figure 1 together with the
      test-level `≡_BA` subsumption and `s6`, with congruence needed at
      OPERAND positions only.  The derivation is
      `U2×2 → U6 → U8 → U8' → U4' → canon → transport`, where U8 comes from
      the AXIOM U3 instantiated at `e := 0`, `b := 1`, `c := b̄` (the
      published route to U8 via U5' and U3' is circular for this purpose,
      since U3' is itself derived using a guard-transport step).  For loops,
      `W1 + ite_guard + W3` gives it for productive bodies, and
      `GkatNormalization.productive_loop` reduces the general case — and that
      lemma's own proof uses `ite_guard` at most, never `wh_guard`, so there
      is no circularity.
      An earlier version of this docstring asserted the opposite — that
      guard transport is NOT derivable, on the grounds that U2 applied twice
      yields `e +_{¬¬b} f` and cannot be undone.  That was wrong twice over:
      U2 applied twice IS the undoing (`e +_b f ≡ f +_{b̄} e ≡ e +_{¬¬b} f`
      is a derivation, not an obstacle), and the general transport follows.
      So including these as constructors does not strengthen `EquivBA`
      beyond the paper's `≡`; the relation is the same either way.
    * `s6` — a REPRESENTATION bridge rather than a theory addition.  The paper
      has `Bexp ⊆ Exp` with Boolean `·` literally being sequencing, so `b·c`
      and `b ∧ c` are the same term there and no axiom is needed.  This
      development keeps `BExp` and `Exp` as separate types, and `s6` is what
      that separation costs.
    * `w3_ba` — W3, relative to `EquivBA`.

    Every clause is sound for the guarded-string model: see `sound_BA`. -/
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
  | ite_guard {b c : BExp T} {e f : Exp A T} :
      (∀ (X : Type) (W : T → X → Bool) (x : X), bval W b x = bval W c x) →
      EquivBA (.ite b e f) (.ite c e f)
  | wh_guard {b c : BExp T} {e : Exp A T} :
      (∀ (X : Type) (W : T → X → Bool) (x : X), bval W b x = bval W c x) →
      EquivBA (.wh b e) (.wh c e)
  | s6 (b c : BExp T) :
      EquivBA (.seq (.test b) (.test c) : Exp A T) (.test (.and b c))
  | w3_ba {b : BExp T} {e f g : Exp A T} :
      EquivBA (.test (E e)) (.test .zero) →
      EquivBA g (.ite b (.seq e g) f) →
      EquivBA g (.seq (.wh b e) f)

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
  | @ite_guard b c e f hbc =>
      intro gs
      simp only [den_ite, hbc Atom V gs.1]
  | @wh_guard b c e hbc =>
      intro gs
      constructor
      · intro h
        induction h with
        | exit a hb => exact InLoop.exit a (by rw [← hbc Atom V a]; exact hb)
        | step a l₁ rest hb he _ ih =>
            exact InLoop.step a l₁ rest (by rw [← hbc Atom V a]; exact hb) he ih
      · intro h
        induction h with
        | exit a hb => exact InLoop.exit a (by rw [hbc Atom V a]; exact hb)
        | step a l₁ rest hb he _ ih =>
            exact InLoop.step a l₁ rest (by rw [hbc Atom V a]; exact hb) he ih
  | s6 b c =>
      rintro ⟨a, w⟩
      simp only [den_seq, den_test]
      constructor
      · rintro ⟨l₁, l₂, hs, ⟨hb, rfl⟩, ⟨hc, rfl⟩⟩
        have hc' : bval V c a = true := by simpa [lastAtom] using hc
        exact ⟨by simp [bval, hb, hc'], by simpa using hs⟩
      · rintro ⟨hbc, rfl⟩
        simp only [bval, Bool.and_eq_true] at hbc
        exact ⟨[], [], rfl, ⟨hbc.1, rfl⟩, ⟨hbc.2, rfl⟩⟩
  | @w3_ba b e f g hguard hsol ihg ihs =>
      have hprod : ∀ a : Atom, ¬ den V e (a, []) := by
        intro a hden
        have he : bval V (E e) a = true := (den_empty_E V e a).mp hden
        have hfalse := (ihg (a, [])).mp ⟨he, rfl⟩
        simp [den, bval] at hfalse
      suffices H : ∀ (n : Nat) (w : List (A × Atom)) (a : Atom), w.length ≤ n →
          (den V g (a, w) ↔ den V (.seq (.wh b e) f) (a, w)) by
        intro gs
        have := H gs.2.length gs.2 gs.1 (Nat.le_refl _)
        simpa using this
      intro n
      induction n with
      | zero =>
          intro w a hlen
          obtain rfl : w = [] := by simpa using Nat.le_zero.mp hlen
          rw [ihs (a, [])]
          simp only [den_ite, den_seq, den_test, den_wh]
          constructor
          · rintro (⟨hb, l1, l2, hl, hde, _⟩ | ⟨hb, hf⟩)
            · obtain ⟨rfl, rfl⟩ : l1 = [] ∧ l2 = [] := by simpa using hl.symm
              exact absurd hde (hprod a)
            · exact ⟨[], [], rfl, InLoop.exit a hb, hf⟩
          · rintro ⟨m1, m2, hl, hloop, hf⟩
            obtain ⟨rfl, rfl⟩ : m1 = [] ∧ m2 = [] := by simpa using hl.symm
            exact Or.inr ⟨InLoop_nil V hloop rfl, hf⟩
      | succ n ih =>
          intro w a hlen
          rw [ihs (a, w)]
          simp only [den_ite, den_seq, den_test, den_wh]
          constructor
          · rintro (⟨hb, l1, l2, hl, hde, hg⟩ | ⟨hb, hf⟩)
            · have hne : l1 ≠ [] := by rintro rfl; exact hprod a hde
              have hlt : l2.length ≤ n := by
                have hlp : l1.length + l2.length = w.length := by rw [hl, List.length_append]
                have hpos : 0 < l1.length := by
                  cases l1 with | nil => exact absurd rfl hne | cons _ _ => exact Nat.succ_pos _
                omega
              obtain ⟨m1, m2, hm, hloop, hf⟩ := ((ih l2 (lastAtom a l1) hlt).mp hg)
              refine ⟨l1 ++ m1, m2, ?_, ?_, ?_⟩
              · show w = l1 ++ m1 ++ m2
                have hm2 : l2 = m1 ++ m2 := hm
                rw [hl, hm2]; exact (List.append_assoc l1 m1 m2).symm
              · exact InLoop.step a l1 m1 hb hde hloop
              · simpa [lastAtom_append] using hf
            · exact ⟨[], w, rfl, InLoop.exit a hb, hf⟩
          · rintro ⟨m1, m2, hl, hloop, hf⟩
            cases hloop with
            | exit a hb =>
                rw [List.nil_append] at hl; subst hl
                exact Or.inr ⟨hb, hf⟩
            | step a l1 rest hb hde hrec =>
                have hne : l1 ≠ [] := by rintro rfl; exact hprod a hde
                have hlt : (rest ++ m2).length ≤ n := by
                  have h1 : l1.length + (rest ++ m2).length = w.length := by
                    rw [hl]; simp only [List.length_append]; omega
                  have hpos : 0 < l1.length := by
                    cases l1 with | nil => exact absurd rfl hne | cons _ _ => exact Nat.succ_pos _
                  omega
                refine Or.inl ⟨hb, l1, rest ++ m2, ?_, hde, ?_⟩
                · show w = l1 ++ (rest ++ m2)
                  rw [hl, List.append_assoc]
                refine (ih (rest ++ m2) (lastAtom a l1) hlt).mpr ⟨rest, m2, rfl, hrec, ?_⟩
                simpa [lastAtom_append] using hf

/-- A branch guarded by false selects its else arm. This already follows from U1, U4,
    and S2; no Boolean-algebra transport is needed. -/
theorem ite_zero (e f : Exp A T) : Equiv (.ite .zero e f) f := by
  let z : Exp A T := .test .zero
  have lhs : Equiv (.ite .zero e f) (.ite .zero z f) :=
    Equiv.trans (Equiv.u4 .zero e f)
      (Equiv.ite_c (Equiv.s2 e) (Equiv.refl f))
  have rhs : Equiv f (.ite .zero z f) :=
    Equiv.trans (Equiv.symm (Equiv.u1 .zero f))
      (Equiv.trans (Equiv.u4 .zero f f)
        (Equiv.ite_c (Equiv.s2 f) (Equiv.refl f)))
  exact Equiv.trans lhs (Equiv.symm rhs)

/-- A branch guarded by true selects its then arm in the full two-sorted GKAT theory.
    U2 swaps the branches; Boolean congruence identifies `not 1` with `0`; `ite_zero`
    finishes the derivation. This is the normalization needed by pure Thompson states. -/
theorem ite_one (e f : Exp A T) : EquivBA (.ite .one e f) e := by
  have hguard : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.not .one) x = bval W .zero x := by
    intro X W x
    rfl
  exact EquivBA.trans (EquivBA.base (Equiv.u2 .one e f))
    (EquivBA.trans (EquivBA.ite_guard (e := f) (f := e) hguard)
      (EquivBA.base (ite_zero f e)))

/-- An embedded Boolean test is the corresponding guarded choice between success and
    failure. This connects the test subalgebra to conditional control flow. -/
theorem test_eq_ite_one_zero (b : BExp T) :
    EquivBA (Exp.test b : Exp A T) (.ite b (.test .one) (.test .zero)) := by
  have hdis : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and (.not b) b) x = bval W (.zero : BExp T) x := by
    intro X W x
    change ((! bval W b x) && bval W b x) = false
    cases bval W b x <;> rfl
  have hnotnot : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.not (.not b)) x = bval W b x := by
    intro X W x
    change (! (! bval W b x)) = bval W b x
    cases bval W b x <;> rfl
  exact EquivBA.trans
    (EquivBA.symm (EquivBA.base (Equiv.u1 b (.test b))))
    (EquivBA.trans
      (EquivBA.base (Equiv.u2 b (.test b) (.test b)))
      (EquivBA.trans
        (EquivBA.base (Equiv.u4 (.not b) (.test b) (.test b)))
        (EquivBA.trans
          (EquivBA.ite_c
            (EquivBA.trans (EquivBA.s6 (.not b) b) (EquivBA.baTest hdis))
            (EquivBA.base (Equiv.refl _)))
          (EquivBA.trans
            (EquivBA.base (Equiv.u2 (.not b) (.test .zero) (.test b)))
            (EquivBA.trans
              (EquivBA.ite_guard (e := .test b) (f := .test .zero) hnotnot)
              (EquivBA.trans
                (EquivBA.ite_c
                  (EquivBA.symm (EquivBA.base (Equiv.s5 (.test b))))
                  (EquivBA.base (Equiv.refl _)))
                (EquivBA.symm
                  (EquivBA.base (Equiv.u4 b (.test .one) (.test .zero))))))))))

/-- Shannon absorption for guarded choice: two branches returning the same expression
    combine by Boolean disjunction. -/
theorem ite_same_then_or (a b : BExp T) (x y : Exp A T) :
    EquivBA (.ite a x (.ite b x y)) (.ite (.or a b) x y) := by
  have hcomm : ∀ (X : Type) (W : T → X → Bool) (z : X),
      bval W (.and (.not b) (.not a)) z =
        bval W (.and (.not a) (.not b)) z := by
    intro X W z
    change ((! bval W b z) && (! bval W a z)) =
      ((! bval W a z) && (! bval W b z))
    cases bval W a z <;> cases bval W b z <;> rfl
  have hdemorgan : ∀ (X : Type) (W : T → X → Bool) (z : X),
      bval W (.and (.not a) (.not b)) z = bval W (.not (.or a b)) z := by
    intro X W z
    change ((! bval W a z) && (! bval W b z)) =
      (! (bval W a z || bval W b z))
    cases bval W a z <;> cases bval W b z <;> rfl
  exact EquivBA.trans
    (EquivBA.base (Equiv.u2 a x (.ite b x y)))
    (EquivBA.trans
      (EquivBA.ite_c (EquivBA.base (Equiv.u2 b x y))
        (EquivBA.base (Equiv.refl x)))
      (EquivBA.trans
        (EquivBA.base (Equiv.u3 (.not b) (.not a) y x x))
        (EquivBA.trans
          (EquivBA.ite_c (EquivBA.base (Equiv.refl y))
            (EquivBA.base (Equiv.u1 (.not a) x)))
          (EquivBA.trans
            (EquivBA.ite_guard (e := y) (f := x) hcomm)
            (EquivBA.trans
              (EquivBA.ite_guard (e := y) (f := x) hdemorgan)
              (EquivBA.symm (EquivBA.base (Equiv.u2 (.or a b) x y))))))))

/-- **Adjacent disjoint guarded branches commute.**  This is the local permutation lemma
    behind the paper's generalized guarded union: if `b ∧ c = 0` in the free Boolean
    algebra, testing `b` before `c` is provably the same as testing `c` before `b`.
    Only U2, U3, congruence, and Boolean guard congruence are used. -/
theorem ite_swap_of_disjoint {b c : BExp T} (e f g : Exp A T)
    (hdis : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and b c) x = false) :
    EquivBA (.ite b e (.ite c f g)) (.ite c f (.ite b e g)) := by
  have hnotnot : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.not (.not b)) x = bval W b x := by
    intro X W x
    simp only [bval]
    cases bval W b x <;> rfl
  have hcnb : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and c (.not b)) x = bval W c x := by
    intro X W x
    have hd := hdis X W x
    simp only [bval] at hd ⊢
    cases hb : bval W b x with
    | false => cases bval W c x <;> rfl
    | true =>
        cases hc : bval W c x with
        | false => rfl
        | true =>
            simp only [hb, hc] at hd
            exact Bool.noConfusion hd
  exact EquivBA.trans (EquivBA.base (Equiv.u2 b e (.ite c f g)))
    (EquivBA.trans (EquivBA.base (Equiv.u3 c (.not b) f g e))
      (EquivBA.trans
        (EquivBA.ite_c (EquivBA.base (Equiv.refl f))
          (EquivBA.base (Equiv.u2 (.not b) g e)))
        (EquivBA.trans
          (EquivBA.ite_c (EquivBA.base (Equiv.refl f))
            (EquivBA.ite_guard (e := e) (f := g) hnotnot))
          (EquivBA.ite_guard (e := f) (f := .ite b e g) hcnb))))

/-- **First-match refinement.** Inside the else arm of a `b`-test, a later guard `c`
    may be replaced by `¬b ∧ c`.  This is the algebraic step that turns an ordered
    first-match list into mutually disjoint effective guards. -/
theorem ite_else_restrict (b c : BExp T) (e f g : Exp A T) :
    EquivBA (.ite b e (.ite c f g))
      (.ite b e (.ite (.and (.not b) c) f g)) := by
  have hnotnot : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.not (.not b)) x = bval W b x := by
    intro X W x
    simp only [bval]
    cases bval W b x <;> rfl
  have hcomm : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and c (.not b)) x = bval W (.and (.not b) c) x := by
    intro X W x
    simp only [bval]
    cases bval W b x <;> cases bval W c x <;> rfl
  have hdis : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and (.and (.not b) c) b) x = false := by
    intro X W x
    simp only [bval]
    cases bval W b x <;> cases bval W c x <;> rfl
  exact EquivBA.trans (EquivBA.base (Equiv.u2 b e (.ite c f g)))
    (EquivBA.trans (EquivBA.base (Equiv.u3 c (.not b) f g e))
      (EquivBA.trans
        (EquivBA.ite_c (EquivBA.base (Equiv.refl f))
          (EquivBA.base (Equiv.u2 (.not b) g e)))
        (EquivBA.trans
          (EquivBA.ite_c (EquivBA.base (Equiv.refl f))
            (EquivBA.ite_guard (e := e) (f := g) hnotnot))
          (EquivBA.trans
            (EquivBA.ite_guard (e := f) (f := .ite b e g) hcomm)
            (ite_swap_of_disjoint f e g hdis)))))

/-- Semantic implication between guards, quantified over the free Boolean algebra. -/
def GuardImplies (b c : BExp T) : Prop :=
  ∀ (X : Type) (W : T → X → Bool) (x : X), bval W b x = true → bval W c x = true

/-- Repeating the same test in the else arm is redundant. -/
theorem ite_else_absorb (b : BExp T) (e f g : Exp A T) :
    EquivBA (.ite b e (.ite b f g)) (.ite b e g) := by
  have hzero : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and (.not b) b) x = false := by
    intro X W x
    simp only [bval]
    cases bval W b x <;> rfl
  have hinner : EquivBA (.ite (.and (.not b) b) f g) g :=
    EquivBA.trans
      (EquivBA.ite_guard (b := .and (.not b) b) (c := .zero)
        (e := f) (f := g) (fun X W x => hzero X W x))
      (EquivBA.base (ite_zero f g))
  exact EquivBA.trans (ite_else_restrict b b e f g)
    (EquivBA.ite_c (EquivBA.base (Equiv.refl e)) hinner)

/-- Under a region implying `b`, an inner `b`-conditional reduces to its true branch. -/
theorem ite_under_implies_true {region b : BExp T} (e f rest : Exp A T)
    (himp : GuardImplies region b) :
    EquivBA (.ite region (.ite b e f) rest) (.ite region e rest) := by
  have hguard : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and b region) x = bval W region x := by
    intro X W x
    simp only [bval]
    cases hr : bval W region x with
    | false => cases bval W b x <;> rfl
    | true =>
        have hb := himp X W x hr
        rw [hb]
        rfl
  exact EquivBA.trans (EquivBA.base (Equiv.u3 b region e f rest))
    (EquivBA.trans
      (EquivBA.ite_guard (e := e) (f := .ite region f rest) hguard)
      (ite_else_absorb region e f rest))

/-- Under a region implying `¬b`, an inner `b`-conditional reduces to its false branch. -/
theorem ite_under_implies_false {region b : BExp T} (e f rest : Exp A T)
    (himp : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W region x = true → bval W b x = false) :
    EquivBA (.ite region (.ite b e f) rest) (.ite region f rest) := by
  have hzero : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and b region) x = false := by
    intro X W x
    simp only [bval]
    cases hr : bval W region x with
    | false => cases bval W b x <;> rfl
    | true =>
        have hb := himp X W x hr
        rw [hb]
        rfl
  exact EquivBA.trans (EquivBA.base (Equiv.u3 b region e f rest))
    (EquivBA.trans
      (EquivBA.ite_guard (e := e) (f := .ite region f rest)
        (b := .and b region) (c := .zero) (fun X W x => hzero X W x))
      (EquivBA.base (ite_zero e (.ite region f rest))))

/-- An unsatisfiable guard can be deleted from a decision list. -/
theorem ite_of_unsat {b : BExp T} (e f : Exp A T)
    (hfalse : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W b x = false) : EquivBA (.ite b e f) f := by
  have hb0 : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W b x = bval W (.zero : BExp T) x := by
    intro X W x
    exact hfalse X W x
  exact EquivBA.trans (EquivBA.ite_guard (e := e) (f := f) hb0)
    (EquivBA.base (ite_zero e f))

/-- The expression encoded by a finite guarded decision list. -/
def guardedFold (branches : List (BExp T × Exp A T)) (fallback : Exp A T) : Exp A T :=
  branches.foldr (fun branch rest => .ite branch.1 branch.2 rest) fallback

/-- Folding an append is folding the left list over the folded right list. -/
theorem guardedFold_append (left right : List (BExp T × Exp A T)) (fallback : Exp A T) :
    guardedFold (left ++ right) fallback = guardedFold left (guardedFold right fallback) := by
  induction left with
  | nil => rfl
  | cons branch left ih =>
      unfold guardedFold at ⊢
      simp only [List.cons_append, List.foldr_cons]
      exact congrArg (fun rest => Exp.ite branch.1 branch.2 rest) ih

/-- Push an enclosing guard through a finite decision list. This is repeated U3; guards
    are accumulated on the right to match U3's `inner ∧ outer` shape. -/
theorem ite_guardedFold_gate_right (region : BExp T)
    (branches : List (BExp T × Exp A T)) (fallback rest : Exp A T) :
    EquivBA (.ite region (guardedFold branches fallback) rest)
      (guardedFold (branches.map (fun branch =>
        (.and branch.1 region, branch.2))) (.ite region fallback rest)) := by
  induction branches with
  | nil => exact EquivBA.base (Equiv.refl _)
  | cons branch branches ih =>
      obtain ⟨guard, branchExp⟩ := branch
      exact EquivBA.trans
        (EquivBA.base (Equiv.u3 guard region branchExp
          (guardedFold branches fallback) rest))
        (EquivBA.ite_c (EquivBA.base (Equiv.refl branchExp)) ih)

/-- The order of the region conjunction in a gated branch list is immaterial in the free
    Boolean algebra. -/
theorem guardedFold_gate_comm (region : BExp T)
    (branches : List (BExp T × Exp A T)) (fallback : Exp A T) :
    EquivBA
      (guardedFold (branches.map (fun branch =>
        (.and branch.1 region, branch.2))) fallback)
      (guardedFold (branches.map (fun branch =>
        (.and region branch.1, branch.2))) fallback) := by
  induction branches with
  | nil => exact EquivBA.base (Equiv.refl _)
  | cons branch branches ih =>
      obtain ⟨guard, branchExp⟩ := branch
      change EquivBA
        (.ite (.and guard region) branchExp
          (guardedFold (branches.map (fun item =>
            (.and item.1 region, item.2))) fallback))
        (.ite (.and region guard) branchExp
          (guardedFold (branches.map (fun item =>
            (.and region item.1, item.2))) fallback))
      exact EquivBA.trans
        (EquivBA.ite_guard (e := branchExp)
          (f := guardedFold (branches.map
            (fun item => (.and item.1 region, item.2))) fallback)
          (b := .and guard region) (c := .and region guard) (by
            intro X W x
            change (bval W guard x && bval W region x) =
              (bval W region x && bval W guard x)
            cases bval W guard x <;> cases bval W region x <;> rfl))
        (EquivBA.ite_c (EquivBA.base (Equiv.refl branchExp)) ih)

/-- A guarded fold is congruent in its terminal fallback. -/
theorem guardedFold_fallback_congr (branches : List (BExp T × Exp A T))
    {firstFallback secondFallback : Exp A T}
    (h : EquivBA firstFallback secondFallback) :
    EquivBA (guardedFold branches firstFallback)
      (guardedFold branches secondFallback) := by
  induction branches with
  | nil => exact h
  | cons branch branches ih =>
      exact EquivBA.ite_c (EquivBA.base (Equiv.refl branch.2)) ih

/-- Pull a terminal test in front of a guarded decision list when every action branch
    is disjoint from it. This is the finite-list form of the fundamental decomposition
    `1 +_c D`, proved only with guarded-choice laws and Boolean guard congruence. -/
theorem guardedFold_test_partition (c : BExp T)
    (branches : List (BExp T × Exp A T))
    (hdis : ∀ branch ∈ branches,
      ∀ (X : Type) (W : T → X → Bool) (x : X),
        bval W (.and branch.1 c) x = false) :
    EquivBA (guardedFold branches (.test c))
      (.ite c (.test .one) (guardedFold branches (.test .zero))) := by
  induction branches with
  | nil => exact test_eq_ite_one_zero c
  | cons branch branches ih =>
      obtain ⟨guard, branchExp⟩ := branch
      have hhead := hdis (guard, branchExp) (by simp only [List.mem_cons, true_or])
      have htail : ∀ item ∈ branches,
          ∀ (X : Type) (W : T → X → Bool) (x : X),
            bval W (.and item.1 c) x = false := by
        intro item hmem
        exact hdis item (by simp only [List.mem_cons, hmem, or_true])
      exact EquivBA.trans
        (EquivBA.ite_c (EquivBA.base (Equiv.refl branchExp)) (ih htail))
        (ite_swap_of_disjoint branchExp (.test .one)
          (guardedFold branches (.test .zero)) hhead)

/-- Right sequencing distributes through a guarded decision list by U5. -/
theorem guardedFold_seq_right (branches : List (BExp T × Exp A T))
    (fallback suffix : Exp A T) :
    EquivBA (.seq (guardedFold branches fallback) suffix)
      (guardedFold (branches.map (fun branch =>
        (branch.1, .seq branch.2 suffix))) (.seq fallback suffix)) := by
  induction branches with
  | nil => exact EquivBA.base (Equiv.refl _)
  | cons branch branches ih =>
      obtain ⟨guard, branchExp⟩ := branch
      exact EquivBA.trans
        (EquivBA.symm (EquivBA.base
          (Equiv.u5 guard branchExp (guardedFold branches fallback) suffix)))
        (EquivBA.ite_c (EquivBA.base (Equiv.refl _)) ih)

/-- Sequential assertion is guarded choice between continuing and failure. -/
theorem test_seq_as_ite (b : BExp T) (e : Exp A T) :
    EquivBA (.seq (.test b) e : Exp A T) (.ite b e (.test .zero)) := by
  exact EquivBA.trans
    (EquivBA.seq_c (test_eq_ite_one_zero b) (EquivBA.base (Equiv.refl e)))
    (EquivBA.trans
      (EquivBA.symm (EquivBA.base
        (Equiv.u5 b (.test .one) (.test .zero) e)))
      (EquivBA.ite_c (EquivBA.base (Equiv.s4 e))
        (EquivBA.base (Equiv.s2 e))))

/-- Push a sequential assertion through a decision list. This is the valid test-prefix
    specialization of left distribution; arbitrary program prefixes do not satisfy it. -/
theorem test_seq_guardedFold_gate (b : BExp T)
    (branches : List (BExp T × Exp A T)) (fallback : Exp A T) :
    EquivBA (.seq (.test b) (guardedFold branches fallback) : Exp A T)
      (guardedFold (branches.map (fun branch =>
        (.and b branch.1, branch.2))) (.ite b fallback (.test .zero))) := by
  exact EquivBA.trans (test_seq_as_ite b (guardedFold branches fallback))
    (EquivBA.trans
      (ite_guardedFold_gate_right b branches fallback (.test .zero))
      (guardedFold_gate_comm b branches (.ite b fallback (.test .zero))))

/-- If every branch guard implies `b`, prefixing the zero-fallback decision list by
    the assertion `b` is redundant. -/
theorem test_seq_guardedFold_of_implies (b : BExp T)
    (branches : List (BExp T × Exp A T))
    (himp : ∀ branch ∈ branches, GuardImplies branch.1 b) :
    EquivBA (.seq (.test b) (guardedFold branches (.test .zero)) : Exp A T)
      (guardedFold branches (.test .zero)) := by
  have hgated : EquivBA
      (guardedFold (branches.map (fun branch =>
        (.and b branch.1, branch.2))) (.test .zero))
      (guardedFold branches (.test .zero)) := by
    induction branches with
    | nil => exact EquivBA.base (Equiv.refl _)
    | cons branch branches ih =>
        obtain ⟨guard, branchExp⟩ := branch
        have hhead := himp (guard, branchExp) (by simp only [List.mem_cons, true_or])
        have hguard : ∀ (X : Type) (W : T → X → Bool) (x : X),
            bval W (.and b guard) x = bval W guard x := by
          intro X W x
          change (bval W b x && bval W guard x) = bval W guard x
          cases hg : bval W guard x with
          | false => cases bval W b x <;> rfl
          | true =>
              have hb := hhead X W x hg
              rw [hb]
              rfl
        have htail : ∀ item ∈ branches, GuardImplies item.1 b := by
          intro item hmem
          exact himp item (by simp only [List.mem_cons, hmem, or_true])
        exact EquivBA.ite_c
          (EquivBA.base (Equiv.refl branchExp)) (ih htail) |>.trans
          (EquivBA.ite_guard (e := branchExp)
            (f := guardedFold branches (.test .zero)) hguard)
  have hterminal : EquivBA
      (.ite b (.test .zero) (.test .zero) : Exp A T) (.test .zero) :=
    EquivBA.base (Equiv.u1 b (.test .zero))
  exact EquivBA.trans
    (test_seq_guardedFold_gate b branches (.test .zero))
    (EquivBA.trans (guardedFold_fallback_congr _ hterminal) hgated)

/-- Partition two decision lists under a top-level conditional. This is the algebraic
    constructor law needed by the derivative fundamental theorem for `ite`. -/
theorem ite_guardedFold_partition (region : BExp T)
    (left right : List (BExp T × Exp A T))
    (leftFallback rightFallback : Exp A T) :
    EquivBA
      (.ite region (guardedFold left leftFallback)
        (guardedFold right rightFallback))
      (guardedFold
        (left.map (fun branch => (.and region branch.1, branch.2)) ++
          right.map (fun branch => (.and (.not region) branch.1, branch.2)))
        (.ite region leftFallback rightFallback)) := by
  let leftRight : List (BExp T × Exp A T) :=
    left.map (fun branch => (BExp.and branch.1 region, branch.2))
  let rightRight : List (BExp T × Exp A T) :=
    right.map (fun branch => (BExp.and branch.1 (BExp.not region), branch.2))
  have hrightTerminal : EquivBA
      (.ite region leftFallback (guardedFold right rightFallback))
      (guardedFold rightRight (.ite region leftFallback rightFallback)) := by
    exact EquivBA.trans
      (EquivBA.base (Equiv.u2 region leftFallback (guardedFold right rightFallback)))
      (EquivBA.trans
        (ite_guardedFold_gate_right (.not region) right rightFallback leftFallback)
        (guardedFold_fallback_congr rightRight
          (EquivBA.trans
            (EquivBA.base (Equiv.u2 (.not region) rightFallback leftFallback))
            (EquivBA.ite_guard (e := leftFallback) (f := rightFallback)
              (b := .not (.not region)) (c := region) (by
                intro X W x
                change (! (! bval W region x)) = bval W region x
                cases bval W region x <;> rfl)))))
  have hpartitionRight : EquivBA
      (.ite region (guardedFold left leftFallback)
        (guardedFold right rightFallback))
      (guardedFold (leftRight ++ rightRight)
        (.ite region leftFallback rightFallback)) := by
    exact EquivBA.trans
      (ite_guardedFold_gate_right region left leftFallback
        (guardedFold right rightFallback))
      (EquivBA.trans
        (guardedFold_fallback_congr leftRight hrightTerminal)
        (EquivBA.base (by
          rw [guardedFold_append]
          exact Equiv.refl _)))
  let terminal := Exp.ite region leftFallback rightFallback
  have hopen : EquivBA
      (guardedFold (leftRight ++ rightRight) terminal)
      (guardedFold leftRight (guardedFold rightRight terminal)) := by
    exact EquivBA.base (by
      rw [guardedFold_append]
      exact Equiv.refl _)
  have hrightComm : EquivBA
      (guardedFold leftRight (guardedFold rightRight terminal))
      (guardedFold leftRight
        (guardedFold (right.map (fun branch =>
          (.and (.not region) branch.1, branch.2))) terminal)) :=
    guardedFold_fallback_congr leftRight
      (guardedFold_gate_comm (.not region) right terminal)
  have hleftComm : EquivBA
      (guardedFold leftRight
        (guardedFold (right.map (fun branch =>
          (.and (.not region) branch.1, branch.2))) terminal))
      (guardedFold (left.map (fun branch =>
          (.and region branch.1, branch.2)))
        (guardedFold (right.map (fun branch =>
          (.and (.not region) branch.1, branch.2))) terminal)) :=
    guardedFold_gate_comm region left _
  have hclose : EquivBA
      (guardedFold (left.map (fun branch =>
          (.and region branch.1, branch.2)))
        (guardedFold (right.map (fun branch =>
          (.and (.not region) branch.1, branch.2))) terminal))
      (guardedFold
        (left.map (fun branch => (.and region branch.1, branch.2)) ++
          right.map (fun branch => (.and (.not region) branch.1, branch.2))) terminal) := by
    exact EquivBA.base (by
      rw [guardedFold_append]
      exact Equiv.refl _)
  exact EquivBA.trans hpartitionRight
    (EquivBA.trans hopen (EquivBA.trans hrightComm (EquivBA.trans hleftComm hclose)))

/-- A conditional whose branches are tests is itself the Boolean if-then-else test. -/
theorem ite_tests_ba (b c d : BExp T) :
    EquivBA (.ite b (.test c) (.test d) : Exp A T)
      (.test (.or (.and b c) (.and (.not b) d))) := by
  let one : Exp A T := .test .one
  let zero : Exp A T := .test .zero
  let left : List (BExp T × Exp A T) := [(c, one)]
  let right : List (BExp T × Exp A T) := [(d, one)]
  have hbranches : EquivBA (.ite b (.test c) (.test d) : Exp A T)
      (.ite b (guardedFold left zero) (guardedFold right zero)) := by
    exact EquivBA.ite_c (test_eq_ite_one_zero c) (test_eq_ite_one_zero d)
  have hpartition := ite_guardedFold_partition b left right zero zero
  have hterminal : EquivBA (.ite b zero zero) zero :=
    EquivBA.base (Equiv.u1 b zero)
  have hzero : EquivBA
      (guardedFold
        (left.map (fun branch => (.and b branch.1, branch.2)) ++
          right.map (fun branch => (.and (.not b) branch.1, branch.2)))
        (.ite b zero zero))
      (guardedFold
        (left.map (fun branch => (.and b branch.1, branch.2)) ++
          right.map (fun branch => (.and (.not b) branch.1, branch.2))) zero) :=
    guardedFold_fallback_congr _ hterminal
  have hor : EquivBA
      (guardedFold
        (left.map (fun branch => (.and b branch.1, branch.2)) ++
          right.map (fun branch => (.and (.not b) branch.1, branch.2))) zero)
      (.ite (.or (.and b c) (.and (.not b) d)) one zero) := by
    dsimp only [left, right, guardedFold]
    exact ite_same_then_or (.and b c) (.and (.not b) d) one zero
  exact EquivBA.trans hbranches
    (EquivBA.trans hpartition
      (EquivBA.trans hzero
        (EquivBA.trans hor
          (EquivBA.symm
            (test_eq_ite_one_zero (.or (.and b c) (.and (.not b) d)))))))

/-- Boolean disjunction of a finite list of guards. -/
def guardsOr : List (BExp T) → BExp T
  | [] => .zero
  | guard :: guards => .or guard (guardsOr guards)

/-- Split a conditional under `region` into its true and false subregions. -/
theorem ite_region_split (region b : BExp T) (e f rest : Exp A T) :
    EquivBA (.ite region (.ite b e f) rest)
      (.ite (.and b region) e
        (.ite (.and (.not (.and b region)) region) f rest)) := by
  exact EquivBA.trans (EquivBA.base (Equiv.u3 b region e f rest))
    (ite_else_restrict (.and b region) region e f rest)

/-- If `guard` occurs in a list, its truth makes the finite disjunction true. -/
theorem bval_guardsOr_of_mem {guard : BExp T} {guards : List (BExp T)}
    (hmem : guard ∈ guards) :
    ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W guard x = true → bval W (guardsOr guards) x = true := by
  induction guards with
  | nil => exact nomatch hmem
  | cons head guards ih =>
      cases hmem with
      | head =>
          intro X W x hguard
          change (bval W guard x || bval W (guardsOr guards) x) = true
          rw [hguard]
          rfl
      | tail _ htail =>
          intro X W x hguard
          have hrest := ih htail X W x hguard
          change (bval W head x || bval W (guardsOr guards) x) = true
          rw [hrest]
          cases bval W head x <;> rfl

private theorem bool_and_true_parts {a b : Bool} (h : (a && b) = true) :
    a = true ∧ b = true := by
  cases a <;> cases b
  · exact Bool.noConfusion h
  · exact Bool.noConfusion h
  · exact Bool.noConfusion h
  · exact ⟨rfl, rfl⟩

/-- **Coverage cancellation.** When the listed guards cover `region`, the terminal
    fallback of their guarded fold is irrelevant under that region.  This is a finite
    U3/Boolean derivation, not a uniqueness or fixed-point principle. -/
theorem guardedFold_fallback_under_cover {region : BExp T}
    (branches : List (BExp T × Exp A T)) (firstFallback secondFallback rest : Exp A T)
    (hcover : GuardImplies region (guardsOr (branches.map (fun branch => branch.1)))) :
    EquivBA (.ite region (guardedFold branches firstFallback) rest)
      (.ite region (guardedFold branches secondFallback) rest) := by
  induction branches generalizing region with
  | nil =>
      have hfalse : ∀ (X : Type) (W : T → X → Bool) (x : X),
          bval W region x = false := by
        intro X W x
        cases hr : bval W region x with
        | false => rfl
        | true =>
            have hz := hcover X W x hr
            exact Bool.noConfusion hz
      exact EquivBA.trans (ite_of_unsat firstFallback rest hfalse)
        (EquivBA.symm (ite_of_unsat secondFallback rest hfalse))
  | cons branch branches ih =>
      obtain ⟨guard, branchExp⟩ := branch
      let nextRegion : BExp T := .and (.not (.and guard region)) region
      have htailCover : GuardImplies nextRegion
          (guardsOr (branches.map (fun branch => branch.1))) := by
        intro X W x hnext
        have hcov := hcover X W x
        change ((! (bval W guard x && bval W region x)) && bval W region x) = true at hnext
        have hparts := bool_and_true_parts hnext
        have hr : bval W region x = true := hparts.2
        have hg : bval W guard x = false := by
          cases hguard : bval W guard x with
          | false => rfl
          | true =>
              have hn1 : (!(true && bval W region x)) = true := hguard ▸ hparts.1
              have hn2 : (!(true && true)) = true := hr ▸ hn1
              exact Bool.noConfusion hn2
        have hall := hcov hr
        change (bval W guard x ||
          bval W (guardsOr (branches.map (fun branch => branch.1))) x) = true at hall
        have hall' : (false ||
            bval W (guardsOr (branches.map (fun branch => branch.1))) x) = true :=
          hg ▸ hall
        exact hall'
      exact EquivBA.trans
        (ite_region_split region guard branchExp
          (guardedFold branches firstFallback) rest)
        (EquivBA.trans
          (EquivBA.ite_c (EquivBA.base (Equiv.refl branchExp))
            (ih htailCover))
          (EquivBA.symm
            (ite_region_split region guard branchExp
              (guardedFold branches secondFallback) rest)))

/-- Global form of coverage cancellation (`region = 1`). -/
theorem guardedFold_fallback_of_cover
    (branches : List (BExp T × Exp A T)) (firstFallback secondFallback : Exp A T)
    (hcover : GuardImplies (.one : BExp T)
      (guardsOr (branches.map (fun branch => branch.1)))) :
    EquivBA (guardedFold branches firstFallback) (guardedFold branches secondFallback) := by
  let rest : Exp A T := firstFallback
  exact EquivBA.trans
    (EquivBA.symm (ite_one (guardedFold branches firstFallback) rest))
    (EquivBA.trans
      (guardedFold_fallback_under_cover branches firstFallback secondFallback rest hcover)
      (ite_one (guardedFold branches secondFallback) rest))

/-- Adjacent disjoint entries of a guarded decision list may be swapped.  Repeated use
    yields the order-independence step of generalized guarded-union normalization. -/
theorem guardedFold_swap_of_disjoint {b c : BExp T} (e f fallback : Exp A T)
    (rest : List (BExp T × Exp A T))
    (hdis : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and b c) x = false) :
    EquivBA
      (guardedFold ((b, e) :: (c, f) :: rest) fallback)
      (guardedFold ((c, f) :: (b, e) :: rest) fallback) := by
  exact ite_swap_of_disjoint e f (guardedFold rest fallback) hdis

/-- A branch can be rotated from the front to the end of a decision list when its guard
    is disjoint from every intervening guard.  This packages repeated adjacent swaps and
    is the induction step needed to prove arbitrary order-independence of canonical cells. -/
theorem guardedFold_rotate_of_disjoint {b : BExp T} (e fallback : Exp A T)
    (rest : List (BExp T × Exp A T))
    (hdis : ∀ branch ∈ rest, ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and b branch.1) x = false) :
    EquivBA (guardedFold ((b, e) :: rest) fallback)
      (guardedFold (rest ++ [(b, e)]) fallback) := by
  induction rest with
  | nil => exact EquivBA.base (Equiv.refl _)
  | cons branch rest ih =>
      obtain ⟨c, f⟩ := branch
      have hbc : ∀ (X : Type) (W : T → X → Bool) (x : X),
          bval W (.and b c) x = false := hdis (c, f) (List.Mem.head _)
      have htail : ∀ branch ∈ rest, ∀ (X : Type) (W : T → X → Bool) (x : X),
          bval W (.and b branch.1) x = false := by
        intro branch hmem
        exact hdis branch (List.Mem.tail _ hmem)
      exact EquivBA.trans
        (guardedFold_swap_of_disjoint e f fallback rest hbc)
        (EquivBA.ite_c (EquivBA.base (Equiv.refl f)) (ih htail))

/-- A cell may be pulled from an arbitrary position to the front when it is disjoint from
    the prefix it crosses.  Together with finite-list induction, this is the usual
    permutation-invariance proof for generalized guarded unions. -/
theorem guardedFold_move_to_front_of_disjoint {b : BExp T} (e fallback : Exp A T)
    (pre suffix : List (BExp T × Exp A T))
    (hdis : ∀ branch ∈ pre, ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and b branch.1) x = false) :
    EquivBA (guardedFold (pre ++ (b, e) :: suffix) fallback)
      (guardedFold ((b, e) :: pre ++ suffix) fallback) := by
  have hrotate := guardedFold_rotate_of_disjoint e (guardedFold suffix fallback) pre hdis
  have hleft := guardedFold_append pre ((b, e) :: suffix) fallback
  have hpre := guardedFold_append pre [(b, e)] (guardedFold suffix fallback)
  rw [hleft, guardedFold_append ((b, e) :: pre) suffix fallback]
  change EquivBA
    (guardedFold pre (guardedFold [(b, e)] (guardedFold suffix fallback)))
    (guardedFold ((b, e) :: pre) (guardedFold suffix fallback))
  rw [← hpre]
  exact EquivBA.symm hrotate

-- ── Finite Boolean cells generated by the guards actually occurring in a system ──

/-- The positive or negative literal selected by one Boolean decision. -/
def guardLiteral (decision : BExp T × Bool) : BExp T :=
  if decision.2 then decision.1 else .not decision.1

/-- The conjunction describing one cell of a finite guard partition.  This construction
    uses only the finitely many guards occurring in the compared transition lists; the
    primitive-test type `T` itself need not be finite. -/
def guardCell (decisions : List (BExp T × Bool)) : BExp T :=
  decisions.foldr (fun decision cell => .and (guardLiteral decision) cell) .one

/-- Evaluation of a finite guard cell is the conjunction of its selected literals. -/
theorem bval_guardCell {X : Type} (W : T → X → Bool) (x : X)
    (decisions : List (BExp T × Bool)) :
    bval W (guardCell decisions) x =
      decisions.foldr
        (fun decision value =>
          (if decision.2 then bval W decision.1 x else !bval W decision.1 x) && value)
        true := by
  induction decisions with
  | nil => rfl
  | cons decision decisions ih =>
      obtain ⟨guard, bit⟩ := decision
      change (bval W (guardLiteral (guard, bit)) x && bval W (guardCell decisions) x) = _
      rw [ih]
      unfold guardLiteral
      cases bit <;> rfl

/-- Prepending a positive literal forces its guard to evaluate to true throughout the cell. -/
theorem guardCell_positive_implies {X : Type} (W : T → X → Bool) (x : X)
    (b : BExp T) (decisions : List (BExp T × Bool))
    (hcell : bval W (guardCell ((b, true) :: decisions)) x = true) :
    bval W b x = true := by
  change (bval W b x && bval W (guardCell decisions) x) = true at hcell
  cases hb : bval W b x with
  | false =>
      have hc : (false && bval W (guardCell decisions) x) = true := hb ▸ hcell
      exact Bool.noConfusion hc
  | true => rfl

/-- Prepending a negative literal forces its guard to evaluate to false throughout the cell. -/
theorem guardCell_negative_implies {X : Type} (W : T → X → Bool) (x : X)
    (b : BExp T) (decisions : List (BExp T × Bool))
    (hcell : bval W (guardCell ((b, false) :: decisions)) x = true) :
    bval W b x = false := by
  change (!bval W b x && bval W (guardCell decisions) x) = true at hcell
  cases hb : bval W b x with
  | false => rfl
  | true =>
      have hc : (!true && bval W (guardCell decisions) x) = true := hb ▸ hcell
      exact Bool.noConfusion hc

/-- If a nonempty cell holds, its tail cell also holds. -/
theorem guardCell_tail_implies {X : Type} (W : T → X → Bool) (x : X)
    (decision : BExp T × Bool) (decisions : List (BExp T × Bool))
    (hcell : bval W (guardCell (decision :: decisions)) x = true) :
    bval W (guardCell decisions) x = true := by
  change (bval W (guardLiteral decision) x && bval W (guardCell decisions) x) = true at hcell
  cases hl : bval W (guardLiteral decision) x with
  | false =>
      have hc : (false && bval W (guardCell decisions) x) = true := hl ▸ hcell
      exact Bool.noConfusion hc
  | true =>
      have hc : (true && bval W (guardCell decisions) x) = true := hl ▸ hcell
      exact hc

/-- Cells choosing opposite values for the same leading guard are disjoint. -/
theorem guardCell_opposite_disjoint (b : BExp T)
    (positiveTail negativeTail : List (BExp T × Bool)) :
    ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W
        (.and (guardCell ((b, true) :: positiveTail))
          (guardCell ((b, false) :: negativeTail))) x = false := by
  intro X W x
  change ((bval W b x && bval W (guardCell positiveTail) x) &&
    (!bval W b x && bval W (guardCell negativeTail) x)) = false
  cases bval W b x <;> cases bval W (guardCell positiveTail) x <;>
    cases bval W (guardCell negativeTail) x <;> rfl

/-- Conjoining the same literal onto two already-disjoint cells preserves disjointness. -/
theorem guardCell_cons_disjoint {first second : List (BExp T × Bool)}
    (decision : BExp T × Bool)
    (hdis : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and (guardCell first) (guardCell second)) x = false) :
    ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W
        (.and (guardCell (decision :: first)) (guardCell (decision :: second))) x = false := by
  intro X W x
  obtain ⟨guard, bit⟩ := decision
  have hd := hdis X W x
  change ((bval W (guardLiteral (guard, bit)) x && bval W (guardCell first) x) &&
    (bval W (guardLiteral (guard, bit)) x && bval W (guardCell second) x)) = false
  change (bval W (guardCell first) x && bval W (guardCell second) x) = false at hd
  cases hl : bval W (guardLiteral (guard, bit)) x with
  | false => rfl
  | true =>
      cases hf : bval W (guardCell first) x with
      | false => rfl
      | true =>
          cases hs : bval W (guardCell second) x with
          | false => rfl
          | true =>
              simp only [hf, hs] at hd
              exact Bool.noConfusion hd

/-- All Boolean decision vectors over a finite list of guards. -/
def guardAssignments : List (BExp T) → List (List (BExp T × Bool))
  | [] => [[]]
  | b :: guards =>
      (guardAssignments guards).map (fun decisions => (b, true) :: decisions) ++
      (guardAssignments guards).map (fun decisions => (b, false) :: decisions)

/-- An assignment chooses exactly one Boolean value for every guard in the given list. -/
inductive IsGuardAssignment : List (BExp T) → List (BExp T × Bool) → Prop where
  | nil : IsGuardAssignment [] []
  | cons {guards decisions} (b : BExp T) (bit : Bool) :
      IsGuardAssignment guards decisions →
      IsGuardAssignment (b :: guards) ((b, bit) :: decisions)

/-- Disjointness of Boolean guards is symmetric. -/
theorem guard_disjoint_symm {b c : BExp T}
    (hdis : ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and b c) x = false) :
    ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and c b) x = false := by
  intro X W x
  have hd := hdis X W x
  simp only [bval] at hd ⊢
  cases hb : bval W b x with
  | false => cases bval W c x <;> rfl
  | true =>
      cases hc : bval W c x with
      | false => rfl
      | true =>
          simp only [hb, hc] at hd
          exact Bool.noConfusion hd

/-- Every interpretation selects a cell of the finite partition generated by `guards`. -/
theorem guardAssignment_exists {X : Type} (W : T → X → Bool) (x : X)
    (guards : List (BExp T)) :
    ∃ decisions, IsGuardAssignment guards decisions ∧
      bval W (guardCell decisions) x = true := by
  induction guards with
  | nil => exact ⟨[], IsGuardAssignment.nil, rfl⟩
  | cons b guards ih =>
      obtain ⟨decisions, hassignment, hcell⟩ := ih
      cases hb : bval W b x with
      | false =>
          refine ⟨(b, false) :: decisions, IsGuardAssignment.cons b false hassignment, ?_⟩
          change (!bval W b x && bval W (guardCell decisions) x) = true
          rw [hb, hcell]
          rfl
      | true =>
          refine ⟨(b, true) :: decisions, IsGuardAssignment.cons b true hassignment, ?_⟩
          change (bval W b x && bval W (guardCell decisions) x) = true
          rw [hb, hcell]
          rfl

/-- Distinct assignments over the same finite guard list determine disjoint cells. -/
theorem IsGuardAssignment.cells_disjoint {guards : List (BExp T)}
    {first second : List (BExp T × Bool)}
    (hfirst : IsGuardAssignment guards first)
    (hsecond : IsGuardAssignment guards second) (hne : first ≠ second) :
    ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and (guardCell first) (guardCell second)) x = false := by
  induction hfirst generalizing second with
  | nil =>
      cases hsecond
      exact absurd rfl hne
  | @cons guards firstTail b firstBit htail ih =>
      cases hsecond with
      | @cons _ secondTail _ secondBit hsecondTail =>
          cases firstBit with
          | false =>
              cases secondBit with
              | false =>
                  apply guardCell_cons_disjoint (b, false)
                  apply ih hsecondTail
                  intro htails
                  exact hne (congrArg (fun tail => (b, false) :: tail) htails)
              | true =>
                  exact guard_disjoint_symm
                    (guardCell_opposite_disjoint b secondTail firstTail)
          | true =>
              cases secondBit with
              | false => exact guardCell_opposite_disjoint b firstTail secondTail
              | true =>
                  apply guardCell_cons_disjoint (b, true)
                  apply ih hsecondTail
                  intro htails
                  exact hne (congrArg (fun tail => (b, true) :: tail) htails)

private theorem mem_map_direct_cell {U V : Type} (f : U → V) {u : U} {items : List U}
    (hmem : u ∈ items) : f u ∈ items.map f := by
  induction items with
  | nil => exact nomatch hmem
  | cons item items ih =>
      cases hmem with
      | head => exact List.Mem.head _
      | tail _ htail => exact List.Mem.tail _ (ih htail)

private theorem mem_append_left_cell {U : Type} {u : U} {left right : List U}
    (hmem : u ∈ left) : u ∈ left ++ right := by
  induction left with
  | nil => exact nomatch hmem
  | cons item left ih =>
      cases hmem with
      | head => exact List.Mem.head _
      | tail _ htail => exact List.Mem.tail _ (ih htail)

private theorem mem_append_right_cell {U : Type} (left : List U) {u : U} {right : List U}
    (hmem : u ∈ right) : u ∈ left ++ right := by
  induction left generalizing u with
  | nil => exact hmem
  | cons item left ih => exact List.Mem.tail _ (ih hmem)

private theorem mem_append_cases_cell {U : Type} {u : U} {left right : List U}
    (hmem : u ∈ left ++ right) : u ∈ left ∨ u ∈ right := by
  induction left with
  | nil => exact Or.inr hmem
  | cons item left ih =>
      cases hmem with
      | head => exact Or.inl (List.Mem.head _)
      | tail _ htail =>
          cases ih htail with
          | inl hleft => exact Or.inl (List.Mem.tail _ hleft)
          | inr hright => exact Or.inr hright

private theorem mem_map_cases_cell {U V : Type} (f : U → V) {v : V} {items : List U}
    (hmem : v ∈ items.map f) : ∃ u, u ∈ items ∧ f u = v := by
  induction items with
  | nil => exact nomatch hmem
  | cons item items ih =>
      cases hmem with
      | head => exact ⟨item, List.Mem.head _, rfl⟩
      | tail _ htail =>
          obtain ⟨u, hu, hfu⟩ := ih htail
          exact ⟨u, List.Mem.tail _ hu, hfu⟩

/-- The explicit enumeration contains every well-shaped assignment. -/
theorem guardAssignments_complete {guards : List (BExp T)} {decisions : List (BExp T × Bool)}
    (hassignment : IsGuardAssignment guards decisions) :
    decisions ∈ guardAssignments guards := by
  induction hassignment with
  | nil => exact List.Mem.head _
  | @cons guards decisions b bit _ ih =>
      cases bit with
      | false =>
          exact mem_append_right_cell _
            (mem_map_direct_cell (fun tail => (b, false) :: tail) ih)
      | true =>
          exact mem_append_left_cell
            (mem_map_direct_cell (fun tail => (b, true) :: tail) ih)

/-- Every entry emitted by the explicit enumeration is a well-shaped assignment. -/
theorem guardAssignments_sound {guards : List (BExp T)} {decisions : List (BExp T × Bool)}
    (hmem : decisions ∈ guardAssignments guards) :
    IsGuardAssignment guards decisions := by
  induction guards generalizing decisions with
  | nil =>
      cases hmem with
      | head => exact IsGuardAssignment.nil
      | tail _ htail => exact nomatch htail
  | cons b guards ih =>
      unfold guardAssignments at hmem
      cases mem_append_cases_cell hmem with
      | inl hpositive =>
          obtain ⟨tail, htail, heq⟩ :=
            mem_map_cases_cell (fun tail => (b, true) :: tail) hpositive
          subst decisions
          exact IsGuardAssignment.cons b true (ih htail)
      | inr hnegative =>
          obtain ⟨tail, htail, heq⟩ :=
            mem_map_cases_cell (fun tail => (b, false) :: tail) hnegative
          subst decisions
          exact IsGuardAssignment.cons b false (ih htail)

/-- The generated finite cells are pairwise disjoint. -/
theorem guardAssignments_pairwise_disjoint {guards : List (BExp T)}
    {first second : List (BExp T × Bool)}
    (hfirst : first ∈ guardAssignments guards)
    (hsecond : second ∈ guardAssignments guards) (hne : first ≠ second) :
    ∀ (X : Type) (W : T → X → Bool) (x : X),
      bval W (.and (guardCell first) (guardCell second)) x = false :=
  (guardAssignments_sound hfirst).cells_disjoint (guardAssignments_sound hsecond) hne

/-- Every interpretation satisfies at least one explicitly generated cell. -/
theorem guardAssignments_exhaustive {X : Type} (W : T → X → Bool) (x : X)
    (guards : List (BExp T)) :
    ∃ decisions, decisions ∈ guardAssignments guards ∧
      bval W (guardCell decisions) x = true := by
  obtain ⟨decisions, hassignment, hcell⟩ := guardAssignment_exists W x guards
  exact ⟨decisions, guardAssignments_complete hassignment, hcell⟩

/-- Guard cells respect concatenation of decision vectors. -/
theorem bval_guardCell_append {X : Type} (W : T → X → Bool) (x : X)
    (first second : List (BExp T × Bool)) :
    bval W (guardCell (first ++ second)) x =
      (bval W (guardCell first) x && bval W (guardCell second) x) := by
  induction first with
  | nil => rfl
  | cons decision first ih =>
      change (bval W (guardLiteral decision) x &&
          bval W (guardCell (first ++ second)) x) =
        ((bval W (guardLiteral decision) x && bval W (guardCell first) x) &&
          bval W (guardCell second) x)
      rw [ih]
      cases bval W (guardLiteral decision) x <;>
        cases bval W (guardCell first) x <;> cases bval W (guardCell second) x <;> rfl

/-- If a concatenated cell holds, both component cells hold. -/
theorem guardCell_append_implies {X : Type} (W : T → X → Bool) (x : X)
    (first second : List (BExp T × Bool))
    (hcell : bval W (guardCell (first ++ second)) x = true) :
    bval W (guardCell first) x = true ∧ bval W (guardCell second) x = true := by
  rw [bval_guardCell_append W x first second] at hcell
  cases hf : bval W (guardCell first) x with
  | false =>
      have hc : (false && bval W (guardCell second) x) = true := hf ▸ hcell
      exact Bool.noConfusion hc
  | true =>
      cases hs : bval W (guardCell second) x with
      | false =>
          have hc1 : (true && bval W (guardCell second) x) = true := hf ▸ hcell
          have hc2 : (true && false) = true := hs ▸ hc1
          exact Bool.noConfusion hc2
      | true => exact ⟨rfl, rfl⟩

/-- Assignments over an appended guard list split at the same boundary. -/
theorem IsGuardAssignment.split_append {firstGuards secondGuards : List (BExp T)}
    {decisions : List (BExp T × Bool)}
    (hassignment : IsGuardAssignment (firstGuards ++ secondGuards) decisions) :
    ∃ first second, decisions = first ++ second ∧
      IsGuardAssignment firstGuards first ∧ IsGuardAssignment secondGuards second := by
  induction firstGuards generalizing decisions with
  | nil => exact ⟨[], decisions, rfl, IsGuardAssignment.nil, hassignment⟩
  | cons guard firstGuards ih =>
      cases hassignment with
      | @cons _ tail _ bit htail =>
          obtain ⟨first, second, heq, hfirst, hsecond⟩ := ih htail
          exact ⟨(guard, bit) :: first, second,
            congrArg (List.cons (guard, bit)) heq,
            IsGuardAssignment.cons guard bit hfirst, hsecond⟩

/-- Drop the decision prefix aligned with a specified guard prefix. -/
def dropGuardDecisions : List (BExp T) → List (BExp T × Bool) → List (BExp T × Bool)
  | [], decisions => decisions
  | _ :: guards, [] => dropGuardDecisions guards []
  | _ :: guards, _ :: decisions => dropGuardDecisions guards decisions

/-- Dropping the first guard block of an aligned appended assignment leaves an assignment
    aligned with the second block. -/
theorem IsGuardAssignment.drop_append {firstGuards secondGuards : List (BExp T)}
    {decisions : List (BExp T × Bool)}
    (hassignment : IsGuardAssignment (firstGuards ++ secondGuards) decisions) :
    IsGuardAssignment secondGuards (dropGuardDecisions firstGuards decisions) := by
  induction firstGuards generalizing decisions with
  | nil => exact hassignment
  | cons guard firstGuards ih =>
      cases hassignment with
      | @cons _ tail _ bit htail => exact ih htail

/-- Dropping an aligned decision prefix from an explicit concatenation returns the suffix. -/
theorem dropGuardDecisions_append {firstGuards : List (BExp T)}
    {firstDecisions : List (BExp T × Bool)}
    (secondDecisions : List (BExp T × Bool))
    (haligned : IsGuardAssignment firstGuards firstDecisions) :
    dropGuardDecisions firstGuards (firstDecisions ++ secondDecisions) =
      secondDecisions := by
  induction haligned with
  | nil => rfl
  | @cons guards decisions guard bit _ ih => exact ih

/-- Truth of a combined cell implies truth of the suffix cell obtained after dropping an
    aligned guard prefix. -/
theorem guardCell_drop_implies {X : Type} (W : T → X → Bool) (x : X)
    {firstGuards secondGuards : List (BExp T)} {decisions : List (BExp T × Bool)}
    (hassignment : IsGuardAssignment (firstGuards ++ secondGuards) decisions)
    (hcell : bval W (guardCell decisions) x = true) :
    bval W (guardCell (dropGuardDecisions firstGuards decisions)) x = true := by
  induction firstGuards generalizing decisions with
  | nil => exact hcell
  | cons guard firstGuards ih =>
      cases hassignment with
      | @cons _ tail _ bit htail =>
          exact ih htail (guardCell_tail_implies W x (guard, bit) tail hcell)

/-- The leaf selected from a guarded decision list by an aligned Boolean assignment. -/
def decidedGuardedFold : List (BExp T × Bool) →
    List (BExp T × Exp A T) → Exp A T → Exp A T
  | [], _, fallback => fallback
  | _, [], fallback => fallback
  | (_, bit) :: decisions, (_, branch) :: branches, fallback =>
      match bit with
      | true => branch
      | false => decidedGuardedFold decisions branches fallback

/-- **A decision list reduces under a cell.** If `region` implies an aligned assignment
    cell, the entire guarded fold is provably equal under `region` to the single leaf selected
    by that assignment.  This is derived solely from U3 and Boolean guard congruence. -/
theorem guardedFold_decide_under {region : BExp T}
    (branches : List (BExp T × Exp A T)) (fallback rest : Exp A T)
    (decisions : List (BExp T × Bool))
    (hassignment : IsGuardAssignment (branches.map (fun branch => branch.1)) decisions)
    (hregion : GuardImplies region (guardCell decisions)) :
    EquivBA (.ite region (guardedFold branches fallback) rest)
      (.ite region (decidedGuardedFold decisions branches fallback) rest) := by
  induction branches generalizing decisions with
  | nil =>
      cases hassignment
      exact EquivBA.base (Equiv.refl _)
  | cons branch branches ih =>
      obtain ⟨guard, branchExp⟩ := branch
      cases hassignment with
      | @cons _ tail _ bit htail =>
          have htailRegion : GuardImplies region (guardCell tail) := by
            intro X W x hr
            exact guardCell_tail_implies W x (guard, bit) tail (hregion X W x hr)
          cases bit with
          | false =>
              have hguard : ∀ (X : Type) (W : T → X → Bool) (x : X),
                  bval W region x = true → bval W guard x = false := by
                intro X W x hr
                exact guardCell_negative_implies W x guard tail (hregion X W x hr)
              exact EquivBA.trans
                (ite_under_implies_false branchExp (guardedFold branches fallback) rest hguard)
                (ih tail htail htailRegion)
          | true =>
              have hguard : GuardImplies region guard := by
                intro X W x hr
                exact guardCell_positive_implies W x guard tail (hregion X W x hr)
              exact ite_under_implies_true branchExp (guardedFold branches fallback) rest hguard

/-- A decision list also reduces under a cell whose assignment continues with unrelated
    trailing guards.  `decidedGuardedFold` consumes only the prefix aligned with `branches`;
    this is the form needed for a common source/target guard partition. -/
theorem guardedFold_decide_under_prefix {region : BExp T}
    (branches : List (BExp T × Exp A T)) (extraGuards : List (BExp T))
    (fallback rest : Exp A T) (decisions : List (BExp T × Bool))
    (hassignment : IsGuardAssignment
      (branches.map (fun branch => branch.1) ++ extraGuards) decisions)
    (hregion : GuardImplies region (guardCell decisions)) :
    EquivBA (.ite region (guardedFold branches fallback) rest)
      (.ite region (decidedGuardedFold decisions branches fallback) rest) := by
  induction branches generalizing decisions with
  | nil =>
      cases decisions <;> exact EquivBA.base (Equiv.refl _)
  | cons branch branches ih =>
      obtain ⟨guard, branchExp⟩ := branch
      cases hassignment with
      | @cons _ tail _ bit htail =>
          have htailRegion : GuardImplies region (guardCell tail) := by
            intro X W x hr
            exact guardCell_tail_implies W x (guard, bit) tail (hregion X W x hr)
          cases bit with
          | false =>
              have hguard : ∀ (X : Type) (W : T → X → Bool) (x : X),
                  bval W region x = true → bval W guard x = false := by
                intro X W x hr
                exact guardCell_negative_implies W x guard tail (hregion X W x hr)
              exact EquivBA.trans
                (ite_under_implies_false branchExp
                  (guardedFold branches fallback) rest hguard)
                (ih tail htail htailRegion)
          | true =>
              have hguard : GuardImplies region guard := by
                intro X W x hr
                exact guardCell_positive_implies W x guard tail (hregion X W x hr)
              exact ite_under_implies_true branchExp
                (guardedFold branches fallback) rest hguard

/-- Common-cell branches labelled by the leaf selected from an original decision list. -/
def cellNormalBranches (assignments : List (List (BExp T × Bool)))
    (branches : List (BExp T × Exp A T)) (fallback : Exp A T) :
    List (BExp T × Exp A T) :=
  assignments.map (fun decisions =>
    (guardCell decisions, decidedGuardedFold decisions branches fallback))

/-- A guarded fold whose every branch and fallback is the same expression collapses by U1. -/
theorem guardedFold_cells_same (assignments : List (List (BExp T × Bool)))
    (e : Exp A T) :
    EquivBA
      (guardedFold (assignments.map (fun decisions => (guardCell decisions, e))) e) e := by
  induction assignments with
  | nil => exact EquivBA.base (Equiv.refl e)
  | cons decisions assignments ih =>
      exact EquivBA.trans
        (EquivBA.ite_c (EquivBA.base (Equiv.refl e)) ih)
        (EquivBA.base (Equiv.u1 (guardCell decisions) e))

/-- Replace the repeated original expression in every cell by the leaf that cell selects. -/
theorem guardedFold_cells_replace
    (branches : List (BExp T × Exp A T)) (fallback : Exp A T)
    (assignments : List (List (BExp T × Bool)))
    (hall : ∀ decisions ∈ assignments,
      IsGuardAssignment (branches.map (fun branch => branch.1)) decisions) :
    let original := guardedFold branches fallback
    EquivBA
      (guardedFold (assignments.map (fun decisions => (guardCell decisions, original))) original)
      (guardedFold (cellNormalBranches assignments branches fallback) original) := by
  dsimp only
  induction assignments with
  | nil => exact EquivBA.base (Equiv.refl _)
  | cons decisions assignments ih =>
      let original := guardedFold branches fallback
      have hassignment := hall decisions (List.Mem.head _)
      have htail : ∀ decisions ∈ assignments,
          IsGuardAssignment (branches.map (fun branch => branch.1)) decisions := by
        intro tail hmem
        exact hall tail (List.Mem.tail _ hmem)
      have hregion : GuardImplies (guardCell decisions) (guardCell decisions) := by
        intro X W x h
        exact h
      exact EquivBA.trans
        (guardedFold_decide_under branches fallback
          (guardedFold (assignments.map
            (fun tail => (guardCell tail, original))) original)
          decisions hassignment hregion)
        (EquivBA.ite_c (EquivBA.base (Equiv.refl _)) (ih htail))

/-- **Finite common-cell normal form for a guarded decision list.** Every decision list is
    provably equal to the fold of its cell-selected leaves, with the original expression as
    the (semantically unreachable once the cells are exhaustive) fallback. -/
theorem guardedFold_cell_normal_form
    (branches : List (BExp T × Exp A T)) (fallback : Exp A T)
    (assignments : List (List (BExp T × Bool)))
    (hall : ∀ decisions ∈ assignments,
      IsGuardAssignment (branches.map (fun branch => branch.1)) decisions) :
    EquivBA (guardedFold branches fallback)
      (guardedFold (cellNormalBranches assignments branches fallback)
        (guardedFold branches fallback)) := by
  let original := guardedFold branches fallback
  exact EquivBA.trans
    (EquivBA.symm (guardedFold_cells_same assignments original))
    (guardedFold_cells_replace branches fallback assignments hall)

/-- The canonical cells generated from a finite decision list cover the whole Boolean
    space.  No finiteness assumption on the ambient primitive-test type is needed: only
    the finitely many guards occurring in `branches` are enumerated. -/
theorem cellNormalBranches_cover
    (branches : List (BExp T × Exp A T)) (fallback : Exp A T) :
    GuardImplies (.one : BExp T)
      (guardsOr ((cellNormalBranches
        (guardAssignments (branches.map (fun branch => branch.1))) branches fallback).map
          (fun branch => branch.1))) := by
  intro X W x _
  obtain ⟨decisions, hmem, hcell⟩ :=
    guardAssignments_exhaustive W x (branches.map (fun branch => branch.1))
  apply bval_guardsOr_of_mem
    (guard := guardCell decisions)
    (guards := (cellNormalBranches
      (guardAssignments (branches.map (fun branch => branch.1))) branches fallback).map
        (fun branch => branch.1))
  · exact mem_map_direct_cell (fun branch => branch.1)
      (mem_map_direct_cell
        (fun ds => (guardCell ds, decidedGuardedFold ds branches fallback)) hmem)
  · exact hcell

/-- **Canonical finite-cell normal form with a freely chosen fallback.** Exhaustiveness
    of the generated cells makes the terminal fallback observationally unreachable, and
    the finite GKAT/Boolean axioms suffice to replace it. -/
theorem guardedFold_canonical_cell_normal_form
    (branches : List (BExp T × Exp A T)) (fallback newFallback : Exp A T) :
    EquivBA (guardedFold branches fallback)
      (guardedFold (cellNormalBranches
        (guardAssignments (branches.map (fun branch => branch.1))) branches fallback)
        newFallback) := by
  let assignments := guardAssignments (branches.map (fun branch => branch.1))
  have hall : ∀ decisions ∈ assignments,
      IsGuardAssignment (branches.map (fun branch => branch.1)) decisions := by
    intro decisions hmem
    exact guardAssignments_sound hmem
  exact EquivBA.trans
    (guardedFold_cell_normal_form branches fallback assignments hall)
    (guardedFold_fallback_of_cover
      (cellNormalBranches assignments branches fallback)
      (guardedFold branches fallback) newFallback
      (cellNormalBranches_cover branches fallback))

/-- Replace each repeated copy of `original` by an arbitrary cell-local label.  The
    caller supplies exactly the local conditional equality needed at each cell; the
    induction transports it through the remaining decision list. -/
theorem guardedFold_cells_replace_by
    (assignments : List (List (BExp T × Bool))) (original : Exp A T)
    (label : List (BExp T × Bool) → Exp A T)
    (hlocal : ∀ decisions ∈ assignments, ∀ rest,
      EquivBA (.ite (guardCell decisions) original rest)
        (.ite (guardCell decisions) (label decisions) rest)) :
    EquivBA
      (guardedFold (assignments.map (fun decisions => (guardCell decisions, original)))
        original)
      (guardedFold (assignments.map (fun decisions =>
        (guardCell decisions, label decisions))) original) := by
  induction assignments with
  | nil => exact EquivBA.base (Equiv.refl _)
  | cons decisions assignments ih =>
      have htail : ∀ tail ∈ assignments, ∀ rest,
          EquivBA (.ite (guardCell tail) original rest)
            (.ite (guardCell tail) (label tail) rest) := by
        intro tail hmem
        exact hlocal tail (List.Mem.tail _ hmem)
      exact EquivBA.trans
        (hlocal decisions (List.Mem.head _)
          (guardedFold (assignments.map
            (fun tail => (guardCell tail, original))) original))
        (EquivBA.ite_c (EquivBA.base (Equiv.refl _)) (ih htail))

/-- Replace one arbitrary labelling of a fixed cell list by another when each replacement
    is valid under its own cell. -/
theorem guardedFold_labels_replace
    (assignments : List (List (BExp T × Bool)))
    (firstLabel secondLabel : List (BExp T × Bool) → Exp A T)
    (fallback : Exp A T)
    (hlocal : ∀ decisions ∈ assignments, ∀ rest,
      EquivBA (.ite (guardCell decisions) (firstLabel decisions) rest)
        (.ite (guardCell decisions) (secondLabel decisions) rest)) :
    EquivBA
      (guardedFold (assignments.map (fun decisions =>
        (guardCell decisions, firstLabel decisions))) fallback)
      (guardedFold (assignments.map (fun decisions =>
        (guardCell decisions, secondLabel decisions))) fallback) := by
  induction assignments with
  | nil => exact EquivBA.base (Equiv.refl _)
  | cons decisions assignments ih =>
      have htail : ∀ tail ∈ assignments, ∀ rest,
          EquivBA (.ite (guardCell tail) (firstLabel tail) rest)
            (.ite (guardCell tail) (secondLabel tail) rest) := by
        intro tail hmem
        exact hlocal tail (List.Mem.tail _ hmem)
      exact EquivBA.trans
        (hlocal decisions (List.Mem.head _)
          (guardedFold (assignments.map
            (fun tail => (guardCell tail, firstLabel tail))) fallback))
        (EquivBA.ite_c (EquivBA.base (Equiv.refl _)) (ih htail))

/-- Any labelling of every generated assignment cell covers the whole Boolean space. -/
theorem guardAssignments_label_cover (guards : List (BExp T))
    (label : List (BExp T × Bool) → Exp A T) :
    GuardImplies (.one : BExp T)
      (guardsOr (((guardAssignments guards).map
        (fun decisions => (guardCell decisions, label decisions))).map
          (fun branch => branch.1))) := by
  intro X W x _
  obtain ⟨decisions, hmem, hcell⟩ := guardAssignments_exhaustive W x guards
  apply bval_guardsOr_of_mem (guard := guardCell decisions)
  · exact mem_map_direct_cell (fun branch => branch.1)
      (mem_map_direct_cell
        (fun ds => (guardCell ds, label ds)) hmem)
  · exact hcell

/-- **Generic exhaustive-cell normalizer.** If `original` reduces under every generated
    cell to the supplied label, the finite axioms rewrite it to the corresponding common
    cell fold, with any terminal fallback. -/
theorem guardAssignments_label_normal_form
    (guards : List (BExp T)) (original newFallback : Exp A T)
    (label : List (BExp T × Bool) → Exp A T)
    (hlocal : ∀ decisions ∈ guardAssignments guards, ∀ rest,
      EquivBA (.ite (guardCell decisions) original rest)
        (.ite (guardCell decisions) (label decisions) rest)) :
    EquivBA original
      (guardedFold ((guardAssignments guards).map
        (fun decisions => (guardCell decisions, label decisions))) newFallback) := by
  let assignments := guardAssignments guards
  exact EquivBA.trans
    (EquivBA.symm (guardedFold_cells_same assignments original))
    (EquivBA.trans
      (guardedFold_cells_replace_by assignments original label hlocal)
      (guardedFold_fallback_of_cover
        (assignments.map (fun decisions => (guardCell decisions, label decisions)))
        original newFallback (guardAssignments_label_cover guards label)))

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

-- ── (c) The loop matches the official `L^(B) = ⋃ₙ (B ◇ L)ⁿ ◇ B̄` ─────────────

/-- `n` iterations of "enter at a `b`-atom, run the body" followed by an exit at a
    `¬b`-atom — the `n`-th summand of the official guarded-iteration language
    `L^(B) = ⋃_{n≥0} (B ◇ L)ⁿ ◇ B̄` (Smolka et al. POPL'20). -/
def iterate (b : BExp T) (dene : GS A Atom → Prop) : Nat → GS A Atom → Prop
  | 0,   gs => bval V b gs.1 = false ∧ gs.2 = []
  | n+1, gs => bval V b gs.1 = true ∧
      ∃ l1 l2, gs.2 = l1 ++ l2 ∧ dene (gs.1, l1) ∧ iterate b dene n (lastAtom gs.1 l1, l2)

/-- **The loop is the union of finite iterations.** Our inductive least-fixpoint loop
    `InLoop` equals the official denotational loop `L^(B) = ⋃_{n≥0} (B ◇ L)ⁿ ◇ B̄`: a
    guarded string is in `⟦e^(b)⟧` iff it is `n` body-iterations (each entered at a
    `b`-atom) followed by an exit at a `¬b`-atom, for some `n`. This bridges our
    `den (e^(b))` to the literature's denotational loop semantics. -/
theorem loop_is_union_of_iterations (b : BExp T) (dene : GS A Atom → Prop)
    (gs : GS A Atom) : InLoop V b dene gs ↔ ∃ n, iterate V b dene n gs := by
  constructor
  · intro h
    induction h with
    | exit a hb => exact ⟨0, hb, rfl⟩
    | step a l1 rest hb hbody _ ih => obtain ⟨n, hn⟩ := ih; exact ⟨n + 1, hb, l1, rest, rfl, hbody, hn⟩
  · rintro ⟨n, hn⟩
    suffices H : ∀ m (gs : GS A Atom), iterate V b dene m gs → InLoop V b dene gs from H n gs hn
    intro m
    induction m with
    | zero =>
        intro gs hg; obtain ⟨hb, hnil⟩ := hg
        rw [show gs = (gs.1, []) from by rw [← hnil]]; exact InLoop.exit gs.1 hb
    | succ n ih =>
        intro gs hg; obtain ⟨hb, l1, l2, hl, hbody, hrec⟩ := hg
        rw [show gs = (gs.1, l1 ++ l2) from by rw [← hl]]
        exact InLoop.step gs.1 l1 l2 hb hbody (ih _ hrec)

#print axioms left_distrib_not_ba_theorem
#print axioms ite_zero
#print axioms ite_one
#print axioms test_eq_ite_one_zero
#print axioms ite_same_then_or
#print axioms ite_tests_ba
#print axioms ite_swap_of_disjoint
#print axioms ite_else_restrict
#print axioms ite_else_absorb
#print axioms ite_under_implies_true
#print axioms ite_under_implies_false
#print axioms ite_of_unsat
#print axioms guardedFold_swap_of_disjoint
#print axioms guardedFold_rotate_of_disjoint
#print axioms guardedFold_append
#print axioms guardedFold_seq_right
#print axioms test_seq_as_ite
#print axioms test_seq_guardedFold_gate
#print axioms test_seq_guardedFold_of_implies
#print axioms ite_guardedFold_gate_right
#print axioms guardedFold_gate_comm
#print axioms guardedFold_fallback_congr
#print axioms guardedFold_test_partition
#print axioms ite_guardedFold_partition
#print axioms ite_region_split
#print axioms bval_guardsOr_of_mem
#print axioms guardedFold_fallback_under_cover
#print axioms guardedFold_fallback_of_cover
#print axioms guardedFold_move_to_front_of_disjoint
#print axioms bval_guardCell
#print axioms guardCell_positive_implies
#print axioms guardCell_negative_implies
#print axioms guardCell_tail_implies
#print axioms guardCell_opposite_disjoint
#print axioms guardCell_cons_disjoint
#print axioms guard_disjoint_symm
#print axioms guardAssignment_exists
#print axioms IsGuardAssignment.cells_disjoint
#print axioms guardAssignments_complete
#print axioms guardAssignments_sound
#print axioms guardAssignments_pairwise_disjoint
#print axioms guardAssignments_exhaustive
#print axioms bval_guardCell_append
#print axioms guardCell_append_implies
#print axioms IsGuardAssignment.split_append
#print axioms IsGuardAssignment.drop_append
#print axioms dropGuardDecisions_append
#print axioms guardCell_drop_implies
#print axioms guardedFold_decide_under
#print axioms guardedFold_decide_under_prefix
#print axioms guardedFold_cells_same
#print axioms guardedFold_cells_replace
#print axioms guardedFold_cell_normal_form
#print axioms cellNormalBranches_cover
#print axioms guardedFold_canonical_cell_normal_form
#print axioms guardedFold_cells_replace_by
#print axioms guardedFold_labels_replace
#print axioms guardAssignments_label_cover
#print axioms guardAssignments_label_normal_form
#print axioms sound_BA
#print axioms EquivBA.w3_ba
#print axioms two_state_uniqueness_nonvacuous
#print axioms loop_is_union_of_iterations

end GkatFaithful
