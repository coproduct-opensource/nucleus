import GkatSyntaxProofs

/-!
# The guarded-string model — and left-distributivity is genuinely unsound

The single-atom model (`GkatLanguageProofs`) is sound and separates `0` from `1`,
but it is too coarse to witness the *frontier* obstruction: with one atom, tests
are constant, so left-distributivity `p·(a +_c b) ≡ p·a +_c p·b` holds there.

This file builds the canonical **guarded-string** model over ≥2 atoms, where an
action can change the atom a later test reads. A guarded string is
`α₀ p₁ α₁ … pₙ αₙ` — represented as `(α₀, [(p₁,α₁), …, (pₙ,αₙ)])` — and a language
is a set of guarded strings. The loop is the least fixpoint of "run `e` while the
current atom satisfies `b`", captured by an **inductive predicate** `InLoop`.

The headline (this file): `left_distrib_fails` — a concrete 2-atom (`Bool`)
countermodel where `p·(1 +_c 0)` and `(p·1) +_c (p·0)` denote *different* languages,
because `p` moves from a `¬c`-atom to a `c`-atom (the guard is read at the START
atom on one side, the END atom on the other). This is machine-checked here.

The `den` above is the **standard guarded-string semantics** of GKAT (actions =
single steps, `+_b` = guarded union, `·` = fusion product, `e^(b)` = the `InLoop`
least fixpoint). Its **soundness for the full GKAT axiom system (U1–U5, S1–S5,
W1–W3, congruence)** is `sound` below — the classical Smolka et al. (2019) result,
**machine-checked here, not cited**. The loop cases are the substantive part: W1 is
the `InLoop` unrolling, W2 is a structural induction on the loop proof (the
`skip`-on-`¬c` branch can never terminate), and W3 is the guarded-Kleene-star
**uniqueness** — a well-founded induction on string length in which the
productivity side condition `E(e) ≡ 0` forces each iteration to consume ≥1 step.

Combining `sound` with `left_distrib_fails` gives `left_distrib_not_gkat_theorem`:
**`LeftDistrib` is not a GKAT theorem** — fully self-contained, no citation. So the
completeness-frontier obstruction (`GkatFrontierProofs.two_cycle_solvable_of_left_distrib`,
reducing n=2 existence to exactly this law) rests on a law GKAT genuinely cannot
have, not one merely left unused.

Everything here is machine-checked: the model, its full soundness, the refutation,
and their combination. Axioms: `[propext, Quot.sound]`.
-/

namespace GkatGS

open GkatSyntax

variable {A T Atom : Type} (V : T → Atom → Bool)

/-- Test valuation at an atom. -/
def bval : BExp T → Atom → Bool
  | .zero,    _ => false
  | .one,     _ => true
  | .prim t,  a => V t a
  | .and b c, a => bval b a && bval c a
  | .or b c,  a => bval b a || bval c a
  | .not b,   a => ! bval b a

/-- A guarded string: a start atom and a list of (action, next-atom) steps. -/
abbrev GS (A Atom : Type) := Atom × List (A × Atom)

/-- The final atom of a guarded string. -/
def lastAtom : Atom → List (A × Atom) → Atom
  | a, [] => a
  | _, (_, b) :: rest => lastAtom b rest

/-- The loop language as a least fixpoint: run `dene` while the current atom
    satisfies `b`, exit (empty string) when it does not. -/
inductive InLoop (b : BExp T) (dene : GS A Atom → Prop) : GS A Atom → Prop where
  | exit (a : Atom) : bval V b a = false → InLoop b dene (a, [])
  | step (a : Atom) (l1 : List (A × Atom)) (rest : List (A × Atom)) :
      bval V b a = true → dene (a, l1) →
      InLoop b dene (lastAtom a l1, rest) →
      InLoop b dene (a, l1 ++ rest)

/-- The guarded-string denotation. -/
def den : Exp A T → GS A Atom → Prop
  | .act p    => fun gs => ∃ a b, gs = (a, [(p, b)])
  | .test t   => fun gs => bval V t gs.1 = true ∧ gs.2 = []
  | .seq e f  => fun gs => ∃ l1 l2, gs.2 = l1 ++ l2 ∧ den e (gs.1, l1) ∧
                    den f (lastAtom gs.1 l1, l2)
  | .ite b e f => fun gs =>
      (bval V b gs.1 = true ∧ den e gs) ∨ (bval V b gs.1 = false ∧ den f gs)
  | .wh b e   => InLoop V b (den e)

@[simp] theorem den_act (p : A) (gs : GS A Atom) :
    den V (.act p) gs ↔ ∃ a b, gs = (a, [(p, b)]) := Iff.rfl
@[simp] theorem den_test (t : BExp T) (gs : GS A Atom) :
    den V (Exp.test t : Exp A T) gs ↔ (bval V t gs.1 = true ∧ gs.2 = []) := Iff.rfl
@[simp] theorem den_seq (e f : Exp A T) (gs : GS A Atom) :
    den V (.seq e f) gs ↔
      ∃ l1 l2, gs.2 = l1 ++ l2 ∧ den V e (gs.1, l1) ∧ den V f (lastAtom gs.1 l1, l2) :=
  Iff.rfl
@[simp] theorem den_ite (b : BExp T) (e f : Exp A T) (gs : GS A Atom) :
    den V (.ite b e f) gs ↔
      ((bval V b gs.1 = true ∧ den V e gs) ∨ (bval V b gs.1 = false ∧ den V f gs)) :=
  Iff.rfl

-- ── Loop-free soundness (U1–U5, S1–S5) over the guarded-string model ─────────

/-- The loop-free fragment of GKAT's provable equivalence (U/S axioms). -/
inductive LEquiv : Exp A T → Exp A T → Prop where
  | refl (e) : LEquiv e e
  | symm {e f} : LEquiv e f → LEquiv f e
  | trans {e f g} : LEquiv e f → LEquiv f g → LEquiv e g
  | seq_c {e e' f f'} : LEquiv e e' → LEquiv f f' → LEquiv (.seq e f) (.seq e' f')
  | ite_c {b e e' f f'} : LEquiv e e' → LEquiv f f' → LEquiv (.ite b e f) (.ite b e' f')
  | u1 (b) (e : Exp A T) : LEquiv (.ite b e e) e
  | u2 (b) (e f : Exp A T) : LEquiv (.ite b e f) (.ite (.not b) f e)
  | u4 (b) (e f : Exp A T) : LEquiv (.ite b e f) (.ite b (.seq (.test b) e) f)
  | u5 (b) (e f g : Exp A T) :
      LEquiv (.ite b (.seq e g) (.seq f g)) (.seq (.ite b e f) g)
  | s1 (e f g : Exp A T) : LEquiv (.seq (.seq e f) g) (.seq e (.seq f g))
  | s2 (e : Exp A T) : LEquiv (.seq (.test .zero) e) (.test .zero)
  | s3 (e : Exp A T) : LEquiv (.seq e (.test .zero)) (.test .zero)
  | s4 (e : Exp A T) : LEquiv (.seq (.test .one) e) e
  | s5 (e : Exp A T) : LEquiv (.seq e (.test .one)) e

theorem lastAtom_append (a : Atom) (l1 l2 : List (A × Atom)) :
    lastAtom a (l1 ++ l2) = lastAtom (lastAtom a l1) l2 := by
  induction l1 generalizing a with
  | nil => rfl
  | cons hd tl ih => cases hd; simp only [List.cons_append, lastAtom]; exact ih _

/-- **Loop-free soundness.** `LEquiv e f → ⟦e⟧ = ⟦f⟧` in the guarded-string model.
    `seq` threads the fusion atom via `lastAtom_append`; guards are resolved by
    `by_cases` on `bval V b gs.1`, never by collapsing the disjunction. -/
theorem lf_sound {e f : Exp A T} (h : LEquiv e f) :
    ∀ gs : GS A Atom, den V e gs ↔ den V f gs := by
  induction h with
  | refl e => intro gs; rfl
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
  | u1 b e =>
      intro gs; simp only [den_ite]
      constructor
      · rintro (⟨_, h⟩ | ⟨_, h⟩) <;> exact h
      · intro h
        by_cases hb : bval V b gs.1 = true
        · exact Or.inl ⟨hb, h⟩
        · exact Or.inr ⟨Bool.not_eq_true _ ▸ hb, h⟩
  | u2 b e f =>
      intro gs; simp only [den_ite]
      constructor
      · rintro (⟨hb, h⟩ | ⟨hb, h⟩)
        · exact Or.inr ⟨by simp [bval, hb], h⟩
        · exact Or.inl ⟨by simp [bval] at hb ⊢; exact hb, h⟩
      · rintro (⟨hb, h⟩ | ⟨hb, h⟩)
        · exact Or.inr ⟨by simp [bval] at hb ⊢; exact hb, h⟩
        · exact Or.inl ⟨by simp [bval] at hb ⊢; exact hb, h⟩
  | u4 b e f =>
      intro gs; simp only [den_ite, den_seq, den_test]
      constructor
      · rintro (⟨hb, he⟩ | ⟨hb, hf⟩)
        · exact Or.inl ⟨hb, [], gs.2, rfl, ⟨hb, rfl⟩, he⟩
        · exact Or.inr ⟨hb, hf⟩
      · rintro (⟨hb, l1, l2, hl, ⟨_, rfl⟩, hy⟩ | ⟨hb, hf⟩)
        · rw [List.nil_append] at hl; subst hl
          exact Or.inl ⟨hb, hy⟩
        · exact Or.inr ⟨hb, hf⟩
  | u5 b e f g =>
      intro gs; simp only [den_ite, den_seq]
      constructor
      · rintro (⟨hb, l1, l2, hl, he, hg⟩ | ⟨hb, l1, l2, hl, hf, hg⟩)
        · exact ⟨l1, l2, hl, Or.inl ⟨hb, he⟩, hg⟩
        · exact ⟨l1, l2, hl, Or.inr ⟨hb, hf⟩, hg⟩
      · rintro ⟨l1, l2, hl, (⟨hb, he⟩ | ⟨hb, hf⟩), hg⟩
        · exact Or.inl ⟨hb, l1, l2, hl, he, hg⟩
        · exact Or.inr ⟨hb, l1, l2, hl, hf, hg⟩
  | s1 e f g =>
      intro gs; simp only [den_seq]
      constructor
      · rintro ⟨l1, l2, hl, ⟨m1, m2, hm, he, hf⟩, hg⟩
        subst hm
        refine ⟨m1, m2 ++ l2, by rw [hl, List.append_assoc], he, m2, l2, rfl, hf, ?_⟩
        rw [lastAtom_append] at hg; exact hg
      · rintro ⟨l1, l2, hl, he, ⟨m1, m2, hm, hf, hg⟩⟩
        subst hm
        refine ⟨l1 ++ m1, m2, by rw [hl, List.append_assoc], ⟨l1, m1, rfl, he, hf⟩, ?_⟩
        rw [lastAtom_append]; exact hg
  | s2 e =>
      intro gs; simp only [den_seq, den_test, bval]
      constructor
      · rintro ⟨_, _, _, ⟨hbf, _⟩, _⟩; exact absurd hbf (by decide)
      · rintro ⟨hbf, _⟩; exact absurd hbf (by decide)
  | s3 e =>
      intro gs; simp only [den_seq, den_test, bval]
      constructor
      · rintro ⟨_, _, _, _, hbf, _⟩; exact absurd hbf (by decide)
      · rintro ⟨hbf, _⟩; exact absurd hbf (by decide)
  | s4 e =>
      intro gs; simp only [den_seq, den_test]
      constructor
      · rintro ⟨l1, l2, hl, ⟨_, rfl⟩, hy⟩
        rw [List.nil_append] at hl; subst hl; exact hy
      · intro h; exact ⟨[], gs.2, rfl, ⟨rfl, rfl⟩, h⟩
  | s5 e =>
      intro gs; simp only [den_seq, den_test]
      constructor
      · rintro ⟨l1, l2, hl, hx, ⟨_, rfl⟩⟩
        rw [List.append_nil] at hl; subst hl; exact hx
      · intro h; exact ⟨gs.2, [], (List.append_nil _).symm, h, ⟨rfl, rfl⟩⟩

-- ── Full soundness including the loop axioms (W1–W3) ─────────────────────────

@[simp] theorem den_wh (b : BExp T) (e : Exp A T) (gs : GS A Atom) :
    den V (.wh b e) gs ↔ InLoop V b (den V e) gs := Iff.rfl

/-- A loop can accept the empty string only by exiting immediately: if the guarded
    string has no steps, the guard must already be false. Structural induction on
    the loop proof (indexing everything by `s` so the recursive premise carries). -/
theorem InLoop_nil {b : BExp T} {P : GS A Atom → Prop} {s : GS A Atom}
    (h : InLoop V b P s) : s.2 = [] → bval V b s.1 = false := by
  induction h with
  | exit a hb => intro _; exact hb
  | step a l1 rest hb hbody hrec ih =>
      intro hnil
      obtain ⟨rfl, rfl⟩ : l1 = [] ∧ rest = [] := by simpa using hnil
      exact ih rfl

/-- **`E`-correspondence.** `e` accepts the empty string at atom `a` iff `E(e)`
    holds there. (For `wh`, an accepting empty loop can only be the immediate
    exit — `InLoop_nil` — so `E(e^(b)) = ¬b`.) -/
theorem den_empty_E (e : Exp A T) (a : Atom) :
    den V e (a, []) ↔ bval V (E e) a = true := by
  induction e generalizing a with
  | act p => simp only [den, E, bval]; constructor
             · rintro ⟨x, y, h⟩; exact absurd (congrArg Prod.snd h) (by simp)
             · intro h; exact absurd h (by simp)
  | test t => simp [den, E]
  | seq e f ihe ihf =>
      simp only [den, E, bval]
      constructor
      · rintro ⟨l1, l2, hl, he, hf⟩
        obtain ⟨rfl, rfl⟩ : l1 = [] ∧ l2 = [] := by simpa using hl.symm
        exact Bool.and_eq_true _ _ ▸ ⟨(ihe a).mp he, (ihf a).mp hf⟩
      · intro h
        obtain ⟨he, hf⟩ := Bool.and_eq_true _ _ |>.mp h
        exact ⟨[], [], rfl, (ihe a).mpr he, (ihf a).mpr hf⟩
  | ite c e f ihe ihf =>
      simp only [den, E, bval]
      by_cases hc : bval V c a = true
      · simp [hc, ihe a]
      · simp only [Bool.not_eq_true] at hc; simp [hc, ihf a]
  | wh b e _ =>
      simp only [den_wh, E, bval]
      constructor
      · intro h; simpa using InLoop_nil V h rfl
      · intro h; exact InLoop.exit a (by simpa using h)

/-- Congruence of the loop under pointwise-equal bodies. -/
theorem InLoop_congr {b : BExp T} {P Q : GS A Atom → Prop}
    (h : ∀ gs, P gs ↔ Q gs) {gs : GS A Atom} (hin : InLoop V b P gs) :
    InLoop V b Q gs := by
  induction hin with
  | exit a hb => exact InLoop.exit a hb
  | step a l1 rest hb hbody _ ihrest => exact InLoop.step a l1 rest hb ((h _).mp hbody) ihrest

/-- **Full soundness.** `⊢ e ≡ f → ⟦e⟧ = ⟦f⟧` in the guarded-string model, for the
    COMPLETE GKAT axiom system (U1–U5, S1–S5, W1–W3, congruence). This is the
    Smolka et al. (2019) soundness theorem, machine-checked here. The loop cases:
    W1 is the `InLoop` unrolling, W2 is a structural induction on the loop proof
    (the `skip`-on-`¬c` branch can never terminate), and W3 is the guarded-Kleene-
    star **uniqueness** — a well-founded induction on string length, where the
    productivity side condition `E(e) ≡ 0` guarantees each loop iteration consumes
    at least one step, so the recursion is on a strictly shorter string. -/
theorem sound {e f : Exp A T} (h : Equiv e f) :
    ∀ gs : GS A Atom, den V e gs ↔ den V f gs := by
  induction h with
  | refl e => intro gs; rfl
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
  | wh_c _ ih =>
      intro gs
      exact ⟨InLoop_congr V ih, InLoop_congr V (fun gs => (ih gs).symm)⟩
  | u1 b e =>
      intro gs; simp only [den_ite]
      constructor
      · rintro (⟨_, h⟩ | ⟨_, h⟩) <;> exact h
      · intro h
        by_cases hb : bval V b gs.1 = true
        · exact Or.inl ⟨hb, h⟩
        · exact Or.inr ⟨Bool.not_eq_true _ ▸ hb, h⟩
  | u2 b e f =>
      intro gs; simp only [den_ite]
      constructor
      · rintro (⟨hb, h⟩ | ⟨hb, h⟩)
        · exact Or.inr ⟨by simp [bval, hb], h⟩
        · exact Or.inl ⟨by simp [bval] at hb ⊢; exact hb, h⟩
      · rintro (⟨hb, h⟩ | ⟨hb, h⟩)
        · exact Or.inr ⟨by simp [bval] at hb ⊢; exact hb, h⟩
        · exact Or.inl ⟨by simp [bval] at hb ⊢; exact hb, h⟩
  | u3 b c e f g =>
      intro gs; simp only [den_ite, bval]
      rcases Bool.eq_false_or_eq_true (bval V b gs.1) with hb | hb <;>
        rcases Bool.eq_false_or_eq_true (bval V c gs.1) with hc | hc <;>
        simp [hb, hc]
  | u4 b e f =>
      intro gs; simp only [den_ite, den_seq, den_test]
      constructor
      · rintro (⟨hb, he⟩ | ⟨hb, hf⟩)
        · exact Or.inl ⟨hb, [], gs.2, rfl, ⟨hb, rfl⟩, he⟩
        · exact Or.inr ⟨hb, hf⟩
      · rintro (⟨hb, l1, l2, hl, ⟨_, rfl⟩, hy⟩ | ⟨hb, hf⟩)
        · rw [List.nil_append] at hl; subst hl
          exact Or.inl ⟨hb, hy⟩
        · exact Or.inr ⟨hb, hf⟩
  | u5 b e f g =>
      intro gs; simp only [den_ite, den_seq]
      constructor
      · rintro (⟨hb, l1, l2, hl, he, hg⟩ | ⟨hb, l1, l2, hl, hf, hg⟩)
        · exact ⟨l1, l2, hl, Or.inl ⟨hb, he⟩, hg⟩
        · exact ⟨l1, l2, hl, Or.inr ⟨hb, hf⟩, hg⟩
      · rintro ⟨l1, l2, hl, (⟨hb, he⟩ | ⟨hb, hf⟩), hg⟩
        · exact Or.inl ⟨hb, l1, l2, hl, he, hg⟩
        · exact Or.inr ⟨hb, l1, l2, hl, hf, hg⟩
  | s1 e f g =>
      intro gs; simp only [den_seq]
      constructor
      · rintro ⟨l1, l2, hl, ⟨m1, m2, hm, he, hf⟩, hg⟩
        subst hm
        refine ⟨m1, m2 ++ l2, by rw [hl, List.append_assoc], he, m2, l2, rfl, hf, ?_⟩
        rw [lastAtom_append] at hg; exact hg
      · rintro ⟨l1, l2, hl, he, ⟨m1, m2, hm, hf, hg⟩⟩
        subst hm
        refine ⟨l1 ++ m1, m2, by rw [hl, List.append_assoc], ⟨l1, m1, rfl, he, hf⟩, ?_⟩
        rw [lastAtom_append]; exact hg
  | s2 e =>
      intro gs; simp only [den_seq, den_test, bval]
      constructor
      · rintro ⟨_, _, _, ⟨hbf, _⟩, _⟩; exact absurd hbf (by decide)
      · rintro ⟨hbf, _⟩; exact absurd hbf (by decide)
  | s3 e =>
      intro gs; simp only [den_seq, den_test, bval]
      constructor
      · rintro ⟨_, _, _, _, hbf, _⟩; exact absurd hbf (by decide)
      · rintro ⟨hbf, _⟩; exact absurd hbf (by decide)
  | s4 e =>
      intro gs; simp only [den_seq, den_test]
      constructor
      · rintro ⟨l1, l2, hl, ⟨_, rfl⟩, hy⟩
        rw [List.nil_append] at hl; subst hl; exact hy
      · intro h; exact ⟨[], gs.2, rfl, ⟨rfl, rfl⟩, h⟩
  | s5 e =>
      intro gs; simp only [den_seq, den_test]
      constructor
      · rintro ⟨l1, l2, hl, hx, ⟨_, rfl⟩⟩
        rw [List.append_nil] at hl; subst hl; exact hx
      · intro h; exact ⟨gs.2, [], (List.append_nil _).symm, h, ⟨rfl, rfl⟩⟩
  | w1 b e =>
      intro gs; simp only [den_wh, den_ite, den_seq, den_test]
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
  | w2 b c e =>
      intro gs; simp only [den_wh]
      constructor
      · intro h
        induction h with
        | exit a hb => exact InLoop.exit a hb
        | step a l1 rest hb hbody hrec ih =>
            simp only [den_ite, den_test] at hbody
            rcases hbody with ⟨hc, hde⟩ | ⟨hc, _, hl1⟩
            · exact InLoop.step a l1 rest hb ⟨[], l1, rfl, ⟨hc, rfl⟩, hde⟩ ih
            · rw [hl1] at ih ⊢; simpa using ih
      · intro h
        induction h with
        | exit a hb => exact InLoop.exit a hb
        | step a l1 rest hb hbody hrec ih =>
            simp only [den_seq, den_test] at hbody
            obtain ⟨m1, m2, hm, ⟨hc, rfl⟩, hde⟩ := hbody
            rw [List.nil_append] at hm
            exact InLoop.step a l1 rest hb (Or.inl ⟨hc, hm.symm ▸ hde⟩) ih
  | @w3 b e f g hguard hsol ihg ihs =>
      -- productivity: E(e) ≡ 0 means e never accepts the empty string
      have hprod : ∀ a : Atom, ¬ den V e (a, []) := by
        intro a hden
        have : bval V (E e) a = true := (den_empty_E V e a).mp hden
        have hfalse := (ihg (a, [])).mp ⟨this, rfl⟩
        simp [den, bval] at hfalse
      -- well-founded on string length via fuel
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

-- ── Left-distributivity fails: a concrete 2-atom (Bool) countermodel ─────────

/-- Atoms = `Bool`; the primitive test reads the atom (`c` true iff the atom is
    `true`). Action `p` (any) can move `false ↦ true`. -/
def V0 : Unit → Bool → Bool := fun _ a => a

/-- **Left-distributivity is unsound** — a sound GKAT model refutes it, so it is
    not a GKAT theorem. Witness: the string `false --p--> true`. In
    `p·(1 +_c 0)` the guard `c` is read at the END atom (`true` ⇒ accept); in
    `(p·1) +_c (p·0)` it is read at the START atom (`false` ⇒ reject). So the two
    denote different languages. `c := prim ()`, valuation `V0`. -/
theorem left_distrib_fails :
    ¬ (∀ gs : GS Unit Bool,
        den V0 (.seq (.act ()) (.ite (.prim ()) (.test .one) (.test .zero))) gs ↔
        den V0 (.ite (.prim ()) (.seq (.act ()) (.test .one))
                                (.seq (.act ()) (.test .zero))) gs) := by
  intro h
  -- LHS holds at the witness `false --p--> true` (guard `c` read at end atom = true)
  have hlhs : den V0 (.seq (.act ()) (.ite (.prim ()) (.test .one) (.test .zero)))
      (false, [((), true)]) :=
    ⟨[((), true)], [], rfl, ⟨false, true, rfl⟩, Or.inl ⟨rfl, rfl, rfl⟩⟩
  -- RHS fails at the witness (guard `c` read at start atom = false)
  have hrhs : ¬ den V0 (.ite (.prim ()) (.seq (.act ()) (.test .one))
      (.seq (.act ()) (.test .zero))) (false, [((), true)]) := by
    rintro (⟨hc, _⟩ | ⟨_, l1, l2, _, _, hz, _⟩)
    · exact absurd hc (by decide)
    · simp [bval] at hz
  exact hrhs ((h _).mp hlhs)

/-- **`LeftDistrib` is not a GKAT theorem** — fully self-contained, no citation.
    If GKAT proved `p·(1 +_c 0) ≡ (p·1) +_c (p·0)`, then by machine-checked
    `sound`ness its two sides would denote equal languages in the guarded-string
    model — contradicting `left_distrib_fails`. Hence the completeness-frontier
    obstruction (`GkatFrontierProofs.two_cycle_solvable_of_left_distrib`, which
    reduces n=2 existence to exactly this law) rests on a law GKAT genuinely
    cannot have. Depends only on `[propext, Quot.sound]`. -/
theorem left_distrib_not_gkat_theorem :
    ¬ Equiv (.seq (.act ()) (.ite (.prim ()) (.test .one) (.test .zero)) : Exp Unit Unit)
            (.ite (.prim ()) (.seq (.act ()) (.test .one))
                             (.seq (.act ()) (.test .zero))) :=
  fun h => left_distrib_fails (sound V0 h)

#print axioms sound
#print axioms left_distrib_fails
#print axioms left_distrib_not_gkat_theorem

end GkatGS
