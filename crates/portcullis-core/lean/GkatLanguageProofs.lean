import GkatSyntaxProofs

/-!
# GKAT is consistent — a sound language model closing the loop (incl. W3)

`GkatDenotationalProofs.lean` proved consistency of the LOOP-FREE theory but showed
(`w3_unsound_in_this_model`) that the deterministic state model is unsound for the
W3 fixpoint axiom: syntactic productivity `E(e)≡0` does not entail the semantic
state-progress a deterministic model needs (a productive action can self-loop on
state), so it has no length measure to force the fixpoint.

This file closes that gap with a model that DOES have a length measure: the
**single-atom word-language model**. Taking the trivial test algebra (one atom)
collapses guarded strings to plain action words `List A`, and a language is a set
of words. It is a coarse but genuine GKAT model — coarse suffices, because
consistency only needs ONE sound model separating `0` from `1`, and here
productivity means "every word is non-empty", giving exactly the length induction
that forces the loop's fixpoint.

Result: `sound : Equiv e f → (∀ w, ⟦e⟧ w ↔ ⟦f⟧ w)` — soundness of ALL axioms
(U1–U5, S1–S5, W1–W3), the loop axioms included — and `gkat_consistent`: `0 ≢ 1`.
So GKAT's equational theory is **consistent, machine-checked**. W3 soundness
(`loop_is_empty`) is the length induction; everything else is word-concatenation
algebra.
-/

namespace GkatLang

open GkatSyntax

/-- A language over actions `A`: a set of finite action words. -/
abbrev Lang (A : Type) := List A → Prop

variable {A T : Type} (v : T → Bool)

/-- Test valuation at the single atom `v`. -/
def bval : BExp T → Bool
  | .zero    => false
  | .one     => true
  | .prim t  => v t
  | .and b c => bval b && bval c
  | .or b c  => bval b || bval c
  | .not b   => ! bval b

/-- The single-atom language denotation. `e^(b)` is degenerate here — with one
    atom the guard never changes, so `while b do e` either exits immediately
    (`¬b ⇒ {[]}`) or loops forever (`b ⇒ ∅`) — but it is sound, which is all a
    consistency model needs. -/
def den : Exp A T → Lang A
  | .act p     => fun w => w = [p]
  | .test b    => fun w => bval v b = true ∧ w = []
  | .seq e f   => fun w => ∃ x y, w = x ++ y ∧ den e x ∧ den f y
  | .ite b e f => fun w => (bval v b = true ∧ den e w) ∨ (bval v b = false ∧ den f w)
  | .wh b _    => fun w => bval v b = false ∧ w = []

/-- `l₁ ++ l₂ = []` splits both to `[]`. -/
theorem append_nil_iff {l1 l2 : List A} : l1 ++ l2 = [] ↔ l1 = [] ∧ l2 = [] := by
  cases l1 <;> simp

@[simp] theorem den_act (p : A) (w : List A) : den v (.act p) w ↔ w = [p] := Iff.rfl
@[simp] theorem den_test (b : BExp T) (w : List A) :
    den v (Exp.test b : Exp A T) w ↔ (bval v b = true ∧ w = []) := Iff.rfl
@[simp] theorem den_seq (e f : Exp A T) (w : List A) :
    den v (.seq e f) w ↔ ∃ x y, w = x ++ y ∧ den v e x ∧ den v f y := Iff.rfl
@[simp] theorem den_ite (b : BExp T) (e f : Exp A T) (w : List A) :
    den v (.ite b e f) w ↔
      ((bval v b = true ∧ den v e w) ∨ (bval v b = false ∧ den v f w)) := Iff.rfl
@[simp] theorem den_wh (b : BExp T) (e : Exp A T) (w : List A) :
    den v (.wh b e) w ↔ (bval v b = false ∧ w = []) := Iff.rfl

/-- `E(e)` is sound: `bval (E e) = true ↔ ⟦e⟧` accepts the empty word. -/
theorem empty_iff_E (e : Exp A T) : (den v e [] ) ↔ bval v (E e) = true := by
  induction e with
  | act p => simp [den, E, bval]
  | test b => simp [den, E]
  | seq e f ihe ihf =>
      constructor
      · rintro ⟨x, y, hxy, hx, hy⟩
        obtain ⟨rfl, rfl⟩ := append_nil_iff.mp hxy.symm
        simp only [E, bval, Bool.and_eq_true]
        exact ⟨ihe.mp hx, ihf.mp hy⟩
      · intro h
        simp only [E, bval, Bool.and_eq_true] at h
        exact ⟨[], [], rfl, ihe.mpr h.1, ihf.mpr h.2⟩
  | ite b e f ihe ihf =>
      by_cases hb : bval v b = true <;>
        simp_all [den, E, bval, Bool.not_eq_true]
  | wh b e _ =>
      simp [den_wh, E, bval]

-- ── The loop fixpoint under productivity: a length induction (W3's core) ─────

/-- **Productivity forces the loop's fixpoint to be empty.** If `e` accepts no
    empty word and `⟦g⟧` solves `⟦g⟧ = ⟦e⟧·⟦g⟧`, then `⟦g⟧ = ∅`. Proof: a shortest
    word in `⟦g⟧` would split as `x·y` with `x ∈ ⟦e⟧` non-empty, so `y` is a
    strictly shorter word in `⟦g⟧` — impossible. This is the length measure the
    deterministic model lacked. -/
theorem loop_is_empty {e g : Exp A T} (hef : ¬ den v e [])
    (hfix : ∀ w, den v g w ↔ (∃ x y, w = x ++ y ∧ den v e x ∧ den v g y)) :
    ∀ w, ¬ den v g w := by
  have key : ∀ n w, w.length ≤ n → ¬ den v g w := by
    intro n
    induction n with
    | zero =>
        intro w hw hg
        obtain rfl : w = [] := by cases w with
          | nil => rfl
          | cons _ _ => simp at hw
        obtain ⟨x, y, hxy, hx, _⟩ := (hfix []).mp hg
        obtain ⟨rfl, _⟩ := append_nil_iff.mp hxy.symm
        exact hef hx
    | succ n ih =>
        intro w hw hg
        obtain ⟨x, y, hxy, hx, hy⟩ := (hfix w).mp hg
        have hx1 : 1 ≤ x.length := by
          cases x with
          | nil => exact absurd hx hef
          | cons _ _ => exact Nat.succ_le_succ (Nat.zero_le _)
        have hlen : w.length = x.length + y.length := by rw [hxy, List.length_append]
        exact ih y (by omega) hy
  intro w; exact key w.length w (Nat.le_refl _)

-- ── Soundness of the full equational theory ─────────────────────────────────

/-- **Soundness.** `⊢ e ≡ f → ⟦e⟧ = ⟦f⟧` (pointwise), over ALL axioms — the loop
    axioms W1/W2/W3 included. -/
theorem sound {e f : Exp A T} (h : Equiv e f) : ∀ w, den v e w ↔ den v f w := by
  induction h with
  | refl e => intro w; rfl
  | symm _ ih => intro w; exact (ih w).symm
  | trans _ _ ih1 ih2 => intro w; exact (ih1 w).trans (ih2 w)
  | seq_c _ _ ih1 ih2 =>
      intro w; simp only [den_seq]
      constructor
      · rintro ⟨x, y, hxy, hx, hy⟩; exact ⟨x, y, hxy, (ih1 x).mp hx, (ih2 y).mp hy⟩
      · rintro ⟨x, y, hxy, hx, hy⟩; exact ⟨x, y, hxy, (ih1 x).mpr hx, (ih2 y).mpr hy⟩
  | ite_c _ _ ih1 ih2 =>
      intro w; simp only [den_ite]
      constructor
      · rintro (⟨hb, h⟩ | ⟨hb, h⟩)
        · exact Or.inl ⟨hb, (ih1 w).mp h⟩
        · exact Or.inr ⟨hb, (ih2 w).mp h⟩
      · rintro (⟨hb, h⟩ | ⟨hb, h⟩)
        · exact Or.inl ⟨hb, (ih1 w).mpr h⟩
        · exact Or.inr ⟨hb, (ih2 w).mpr h⟩
  | wh_c _ _ => intro w; rfl
  | u1 b e =>
      intro w; simp only [den_ite]
      by_cases hb : bval v b = true
      · constructor
        · rintro (⟨_, h⟩ | ⟨_, h⟩) <;> exact h
        · intro h; exact Or.inl ⟨hb, h⟩
      · rw [Bool.not_eq_true] at hb
        constructor
        · rintro (⟨_, h⟩ | ⟨_, h⟩) <;> exact h
        · intro h; exact Or.inr ⟨hb, h⟩
  | u2 b e f =>
      intro w; simp only [den_ite, bval]
      by_cases hb : bval v b = true <;> simp_all [Bool.not_eq_true]
  | u3 b c e f g =>
      intro w; simp only [den_ite, bval]
      by_cases hc : bval v c = true <;> by_cases hb : bval v b = true <;>
        simp_all [Bool.not_eq_true]
  | u4 b e f =>
      intro w; simp only [den_ite, den_seq, den_test]
      by_cases hb : bval v b = true
      · constructor
        · rintro (⟨_, he⟩ | ⟨hbf, _⟩)
          · exact Or.inl ⟨hb, [], w, rfl, ⟨hb, rfl⟩, he⟩
          · rw [hb] at hbf; exact absurd hbf (by decide)
        · rintro (⟨_, x, y, hxy, ⟨_, hx0⟩, hy⟩ | ⟨hbf, _⟩)
          · subst hx0; rw [List.nil_append] at hxy; exact Or.inl ⟨hb, hxy ▸ hy⟩
          · rw [hb] at hbf; exact absurd hbf (by decide)
      · rw [Bool.not_eq_true] at hb
        constructor
        · rintro (⟨hbt, _⟩ | ⟨_, hf⟩)
          · rw [hb] at hbt; exact absurd hbt (by decide)
          · exact Or.inr ⟨hb, hf⟩
        · rintro (⟨hbt, _⟩ | ⟨_, hf⟩)
          · rw [hb] at hbt; exact absurd hbt (by decide)
          · exact Or.inr ⟨hb, hf⟩
  | u5 b e f g =>
      intro w; simp only [den_ite, den_seq]
      by_cases hb : bval v b = true
      · constructor
        · rintro (⟨_, x, y, hxy, hx, hy⟩ | ⟨hbf, _⟩)
          · exact ⟨x, y, hxy, Or.inl ⟨hb, hx⟩, hy⟩
          · rw [hb] at hbf; exact absurd hbf (by decide)
        · rintro ⟨x, y, hxy, (⟨_, hx⟩ | ⟨hbf, _⟩), hy⟩
          · exact Or.inl ⟨hb, x, y, hxy, hx, hy⟩
          · rw [hb] at hbf; exact absurd hbf (by decide)
      · rw [Bool.not_eq_true] at hb
        constructor
        · rintro (⟨hbf, _⟩ | ⟨_, x, y, hxy, hx, hy⟩)
          · rw [hb] at hbf; exact absurd hbf (by decide)
          · exact ⟨x, y, hxy, Or.inr ⟨hb, hx⟩, hy⟩
        · rintro ⟨x, y, hxy, (⟨hbf, _⟩ | ⟨_, hx⟩), hy⟩
          · rw [hb] at hbf; exact absurd hbf (by decide)
          · exact Or.inr ⟨hb, x, y, hxy, hx, hy⟩
  | s1 e f g =>
      intro w; simp only [den_seq]
      constructor
      · rintro ⟨x, y, hxy, ⟨a, c, hac, ha, hc⟩, hy⟩
        exact ⟨a, c ++ y, by rw [hxy, hac, List.append_assoc], ha, c, y, rfl, hc, hy⟩
      · rintro ⟨x, y, hxy, hx, a, c, hac, ha, hc⟩
        exact ⟨x ++ a, c, by rw [hxy, hac, List.append_assoc], ⟨x, a, rfl, hx, ha⟩, hc⟩
  | s2 e =>
      intro w; simp only [den_seq, den_test]
      constructor
      · rintro ⟨x, y, _, ⟨hbf, _⟩, _⟩; simp [bval] at hbf
      · rintro ⟨hbf, _⟩; simp [bval] at hbf
  | s3 e =>
      intro w; simp only [den_seq, den_test]
      constructor
      · rintro ⟨x, y, _, _, hbf, _⟩; simp [bval] at hbf
      · rintro ⟨hbf, _⟩; simp [bval] at hbf
  | s4 e =>
      intro w; simp only [den_seq, den_test]
      constructor
      · rintro ⟨x, y, hxy, ⟨_, hx0⟩, hy⟩
        subst hx0; rw [List.nil_append] at hxy; exact hxy ▸ hy
      · intro h; exact ⟨[], w, rfl, ⟨rfl, rfl⟩, h⟩
  | s5 e =>
      intro w; simp only [den_seq, den_test]
      constructor
      · rintro ⟨x, y, hxy, hx, ⟨_, hy0⟩⟩
        subst hy0; rw [List.append_nil] at hxy; exact hxy ▸ hx
      · intro h; exact ⟨w, [], (List.append_nil w).symm, h, ⟨rfl, rfl⟩⟩
  | w1 b e =>
      intro w; simp only [den_wh, den_ite, den_seq, den_test]
      by_cases hb : bval v b = true
      · constructor
        · rintro ⟨hbf, _⟩; rw [hb] at hbf; exact absurd hbf (by decide)
        · rintro (⟨_, _, _, _, _, hbf, _⟩ | ⟨hbf, _⟩) <;>
            (rw [hb] at hbf; exact absurd hbf (by decide))
      · rw [Bool.not_eq_true] at hb
        constructor
        · rintro ⟨_, hw⟩; exact Or.inr ⟨hb, rfl, hw⟩
        · rintro (⟨hbt, _⟩ | ⟨_, _, hw0⟩)
          · rw [hb] at hbt; exact absurd hbt (by decide)
          · exact ⟨hb, hw0⟩
  | w2 b c e => intro w; simp only [den_wh]
  | w3 hguard hsol ihguard ihsol =>
      rename_i b e f g
      have hef : ¬ den v e [] := by
        intro he
        have hE : bval v (E e) = true := (empty_iff_E v e).mp he
        have h0 := (ihguard []).mp ⟨hE, rfl⟩
        simp only [den_test, bval] at h0
        exact absurd h0.1 (by decide)
      intro w
      by_cases hb : bval v b = true
      · have hfix : ∀ w, den v g w ↔ (∃ x y, w = x ++ y ∧ den v e x ∧ den v g y) := by
          intro w; rw [ihsol w]; simp only [den_ite, den_seq]
          constructor
          · rintro (⟨_, h⟩ | ⟨hbf, _⟩)
            · exact h
            · rw [hb] at hbf; exact absurd hbf (by decide)
          · intro h; exact Or.inl ⟨hb, h⟩
        have hg := loop_is_empty v hef hfix w
        simp only [den_seq, den_wh]
        constructor
        · intro h; exact absurd h hg
        · rintro ⟨x, y, _, ⟨hbf, _⟩, _⟩; rw [hb] at hbf; exact absurd hbf (by decide)
      · rw [ihsol w]; rw [Bool.not_eq_true] at hb
        constructor
        · intro h; rw [den_ite] at h
          rcases h with ⟨hbt, _⟩ | ⟨_, hf⟩
          · rw [hb] at hbt; exact absurd hbt (by decide)
          · exact ⟨[], w, rfl, ⟨hb, rfl⟩, hf⟩
        · intro h
          rcases h with ⟨x, y, hxy, ⟨_, hx0⟩, hy⟩
          subst hx0; rw [List.nil_append] at hxy; subst hxy
          rw [den_ite]; exact Or.inr ⟨hb, hy⟩

-- ── Consistency ─────────────────────────────────────────────────────────────

/-- **GKAT is consistent.** `⊢ 0 ≡ 1` is not derivable: the model separates them —
    `1` accepts the empty word, `0` accepts nothing. -/
theorem gkat_consistent : ¬ Equiv (Exp.test .zero : Exp Unit Unit) (.test .one) := by
  intro h
  have := (sound (fun _ => true) h) []
  simp [den, bval] at this

#print axioms sound
#print axioms gkat_consistent

end GkatLang
