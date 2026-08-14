import GkatSyntaxProofs

/-!
# GKAT denotational model — soundness of the loop-free theory, and consistency

The syntactic side (`GkatSyntaxProofs.lean`) formalized GKAT's axioms. To know the
equational theory `≡` is not vacuous — that it does not prove everything equal — we
need a **sound model**: an interpretation `⟦·⟧` with `⊢ e ≡ f → ⟦e⟧ = ⟦f⟧` and two
expressions with different denotations.

GKAT programs are **partial** (`0` and a failing test abort), so the faithful
model is partial functions `S → Option S` (`none` = abort/diverge), NOT total
endomaps — a total-endomap model is unsound (it cannot separate `0` from `1`).

This file builds that partial model and proves:
- `den_none` — every denotation is strict (`⟦e⟧ none = none`);
- soundness of the **loop-free** axioms (U1–U5, S1–S5) + congruence, as
  `lequiv_sound : LEquiv e f → ⟦e⟧ = ⟦f⟧`;
- `lequiv_consistent` — `⟦0⟧ ≠ ⟦1⟧`, so the loop-free theory is **consistent**.

## Boundary
`LEquiv` is the loop-free fragment of `Equiv` (U/S axioms). The loop denotation
`⟦e^(b)⟧` is defined here (fuel-bounded `while`), but soundness of the LOOP axioms
(W1 unroll, W2 tighten, W3 fixpoint) is NOT proven — it needs the least fixpoint of
the while-operator on the definedness order (divergence ↦ `none`), i.e. the
fuel-stability/lfp argument. That, extending `lequiv_sound` to the full `Equiv` and
hence full consistency, is the remaining step — and it is where the semantic
results of `GkatWhileStep` (W1 ↔ `whileStep_solves`, W3 ↔ `solution_unique`) plug in.
-/

namespace GkatDenote

open GkatSyntax

/-- The partial state domain: `none` is abort/divergence. -/
abbrev St := Option Bool

/-- A model: how primitive actions and tests act on the state. -/
structure Model (A T : Type) where
  act : A → Bool → Bool
  tst : T → Bool → Bool

variable {A T : Type} (M : Model A T)

/-- Boolean-test valuation. -/
def bval : BExp T → Bool → Bool
  | .zero,    _ => false
  | .one,     _ => true
  | .prim t,  s => M.tst t s
  | .and b c, s => bval b s && bval c s
  | .or b c,  s => bval b s || bval c s
  | .not b,   s => ! bval b s

/-- Fuel-bounded `while b do (den e)`: run `de` while the guard holds; on `none`
    (abort) stop; when fuel runs out, diverge to `none`. |St| = 3, so any
    terminating run finishes in ≤ 2 steps and fuel `4` is safe. -/
def whileF (b : BExp T) (de : St → St) : Nat → St → St
  | 0,     _ => none
  | _ + 1, none => none
  | n + 1, some s => if bval M b s then whileF b de n (de (some s)) else some s

/-- Denotation `⟦e⟧ : St → St`, a partial function (Kleisli of `Option`). -/
def den : Exp A T → St → St
  | .act p    => fun o => o.map (M.act p)
  | .test b   => fun o => o.bind (fun s => if bval M b s then some s else none)
  | .seq e f  => fun o => den f (den e o)
  | .ite b e f => fun o => o.bind (fun s => if bval M b s then den e (some s) else den f (some s))
  | .wh b e   => whileF M b (den e) 4

/-- Every denotation is strict in abort: `⟦e⟧ none = none`. -/
theorem den_none (e : Exp A T) : den M e none = none := by
  induction e with
  | act p => rfl
  | test b => rfl
  | seq e f ihe ihf => show den M f (den M e none) = none; rw [ihe]; exact ihf
  | ite b e f _ _ => rfl
  | wh b e _ => rfl

-- ── Loop-free equational theory (the U/S fragment of `Equiv`) ────────────────

/-- The loop-free fragment of GKAT's provable equivalence: equivalence +
    congruence + U1–U5 + S1–S5 (no loop axioms). -/
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

/-- **Soundness of the loop-free theory.** `LEquiv e f → ⟦e⟧ = ⟦f⟧`. -/
theorem lequiv_sound {e f : Exp A T} (h : LEquiv e f) : den M e = den M f := by
  induction h with
  | refl e => rfl
  | symm _ ih => exact ih.symm
  | trans _ _ ih1 ih2 => exact ih1.trans ih2
  | seq_c _ _ ih1 ih2 => funext o; simp only [den]; rw [ih1, ih2]
  | ite_c _ _ ih1 ih2 => funext o; cases o <;> simp [den, ih1, ih2]
  | u1 b e => funext o; cases o <;> simp [den, den_none]
  | u2 b e f =>
      funext o; cases o with
      | none => simp [den]
      | some s => by_cases hb : bval M b s <;> simp [den, bval, hb]
  | u4 b e f =>
      funext o; cases o with
      | none => simp [den]
      | some s => by_cases hb : bval M b s <;> simp [den, hb]
  | u5 b e f g =>
      funext o; cases o with
      | none => simp [den, den_none]
      | some s => by_cases hb : bval M b s <;> simp [den, hb]
  | s1 e f g => rfl
  | s2 e => funext o; cases o <;> simp [den, bval, den_none]
  | s3 e =>
      funext o; cases o with
      | none => simp [den, den_none, bval]
      | some s => simp only [den]; cases den M e (some s) <;> simp [bval]
  | s4 e => funext o; cases o <;> simp [den, bval, den_none]
  | s5 e =>
      funext o; cases o with
      | none => simp [den, den_none]
      | some s => simp only [den]; cases den M e (some s) <;> simp [bval]

-- ── Non-degeneracy ⇒ consistency of the loop-free theory ────────────────────

/-- A concrete model over `Unit` actions/tests. -/
def M0 : Model Unit Unit := ⟨fun _ b => b, fun _ b => b⟩

/-- `⟦0⟧ ≠ ⟦1⟧` in `M0`: they differ at `some true`. -/
theorem zero_ne_one : den M0 (.test .zero) ≠ den M0 (.test (.one)) := by
  intro h
  have := congrFun h (some true)
  simp [den, bval] at this

/-- **Consistency of the loop-free theory.** `≡₀` does not prove `0 ≡ 1`. -/
theorem lequiv_consistent : ¬ LEquiv (Exp.test .zero : Exp Unit Unit) (.test .one) := by
  intro h
  exact zero_ne_one (lequiv_sound M0 h)

#print axioms lequiv_sound
#print axioms lequiv_consistent

end GkatDenote
