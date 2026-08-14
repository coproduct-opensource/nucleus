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
- `lequiv_consistent` — `⟦0⟧ ≠ ⟦1⟧`, so the loop-free theory is **consistent**;
- `w3_unsound_in_this_model` — and the negative result below.

## Why this does NOT close the loop (a discovered obstruction, machine-checked)

I set out to extend `lequiv_sound` to the full `Equiv` (all loop axioms) and so
get full consistency, expecting the loop axioms to "plug in" via `GkatWhileStep`'s
`whileStep_solves` / `solution_unique`. That is FALSE, and `w3_unsound_in_this_model`
proves it: this deterministic state model is **unsound for the W3 fixpoint axiom**.

The reason (the real content): W3's side condition is *syntactic* productivity
`E(e) ≡ 0`, which does NOT entail the *semantic* state-progress a deterministic
model needs — a productive action can self-loop on state (identity). That is the
precise gap to `GkatWhileStep.Progress` (`b x → body x ≠ x`), the hypothesis that
actually makes `solution_unique` hold. So `E(e)≡0` is too weak here, and W3 fails.

**Closing the loop (full consistency incl. W1/W2/W3) therefore requires the finer
guarded-string LANGUAGE model** of Smolka et al., where productivity ⇒ each loop
turn appends an action ⇒ strictly longer strings ⇒ a unique/∅ fixpoint. That is a
larger, separate formalization; this file proves the loop-free consistency and
pins exactly why the state model cannot be pushed further.
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

-- ── Why the loop cannot be closed with THIS model (a checked obstruction) ────

/-- **The deterministic partial-function model is UNSOUND for the W3 fixpoint
    axiom** — so full consistency cannot be obtained by extending `lequiv_sound`
    to it. Concretely, with `b = 1`, `e = act ()` (interpreted by `M0` as the
    IDENTITY on state — productive, `E(e) = 0`), and `f = g = 1`:

      1. the W3 side condition `E(e) ≡ 0` is sound (`E(act) = 0`);
      2. `g` SOLVES the fixpoint equation `g ≡ e·g +_b f` in the model
         (`⟦1⟧ = ⟦ite 1 (act·1) 1⟧`, both the identity);
      3. yet `⟦g⟧ ≠ ⟦e^(b)·f⟧` — `⟦g⟧ = id` but `⟦e^(b)·f⟧ = const none` (the loop
         `while 1 do id` DIVERGES), so they differ at `some true`.

    W3 would take (1)+(2) to `g ≡ e^(b)·f`, i.e. `⟦g⟧ = ⟦e^(b)·f⟧` — false here.

    **The reason** (the real content): syntactic productivity `E(e) ≡ 0` does NOT
    entail the *semantic* state-progress a deterministic model needs — a
    productive action can self-loop on state (`id`). This is exactly the gap
    between `E(e)≡0` and `GkatWhileStep.Progress` (`b x → body x ≠ x`): the latter
    is what makes `solution_unique` hold, and `E(e)≡0` does not imply it here.

    The classical guarded-string LANGUAGE model reconciles them — productivity ⇒
    each loop turn appends an action ⇒ strictly longer strings ⇒ the fixpoint is
    unique (∅ for a bare productive loop). **Closing the loop (full consistency,
    incl. W3) requires that finer language/trace model, not this state model.** -/
theorem w3_unsound_in_this_model :
    (den M0 (.test (E (.act () : Exp Unit Unit))) = den M0 (.test .zero))
    ∧ (den M0 (.test .one : Exp Unit Unit)
        = den M0 (.ite .one (.seq (.act ()) (.test .one)) (.test .one)))
    ∧ (den M0 (.test .one : Exp Unit Unit)
        ≠ den M0 (.seq (.wh .one (.act ())) (.test .one))) := by
  refine ⟨rfl, ?_, ?_⟩
  · funext o; cases o with
    | none => rfl
    | some s => cases s <;> rfl
  · intro h
    have hc := congrFun h (some true)
    have e1 : den M0 (.test .one : Exp Unit Unit) (some true) = some true := rfl
    have e2 : den M0 (.seq (.wh .one (.act ())) (.test .one)) (some true) = none := rfl
    rw [e1, e2] at hc
    exact absurd hc (by decide)

#print axioms lequiv_sound
#print axioms lequiv_consistent
#print axioms w3_unsound_in_this_model

end GkatDenote
