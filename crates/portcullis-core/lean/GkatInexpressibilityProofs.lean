import GkatDerivativeFiniteProofs

/-!
# Toward inexpressibility: the loop derivatives all halt on ¬b (the D.2 `^(b)` crux)

Route B to the first GKAT inexpressibility (Fig. 3 of Schmid–Kappé–Kozen–Silva, ICALP
2021). Their **Lemma D.2**: every infinite branch of a GKAT behavior is *finitely
alternating* — it cannot have `E(∂_w t)=b` and `E(∂_w t)=b̄` both infinitely often.
Fig. 3's b/b̄-alternating 2-cycle violates this, so it is denoted by no expression.

**Finitization.** `⟦e⟧` has finitely many derivatives (`derivs`, Lemma F.1), so an
infinite branch must cycle; the ω-property reduces to a **cycle** property of the
finite derivative automaton `⟨E, next⟩`. No coinductive trees are needed.

D.2's proof inducts on `e`; the `^(b)` (loop) case is the crux, and it is exactly our
`InLoop_exits_on_not_b` generalized to *all* loop derivatives: **every derivative of
`e^(b)` accepts only on `¬b`-atoms** (`E(e^(b)) = ¬b`, and any derivative is
`e'·e^(b)` with `E = E(e')∧¬b ⊆ ¬b`). Hence no cycle inside a loop can ever reach an
`E=b` state — the loop's branches are finitely alternating (never `b` at all). This
file machine-checks that crux.

Axioms `[propext, Quot.sound]`, `sorryAx`-free.
-/

namespace GkatDeriv

open GkatSyntax GkatGS

variable {A T Atom : Type} (V : T → Atom → Bool)

/-- **The `^(b)` crux of Lemma D.2.** Every derivative of a loop `e^(b)` accepts only
    on `¬b`-atoms: if a derivative `e'` of `.wh b e` halts at atom `a` (`E(e')` holds),
    then `b` is false at `a`. So along any branch that stays inside the loop, the
    acceptance condition never equals `b` — the branch cannot alternate `b`/`b̄`. This
    generalizes `InLoop_exits_on_not_b` from the loop head to all its derivatives. -/
theorem loop_deriv_halts_on_not_b {b : BExp T} {e : Exp A T} {e' : Exp A T}
    (h : e' ∈ derivs (.wh b e)) {a : Atom} (hE : bval V (E e') a = true) :
    bval V b a = false := by
  simp only [derivs, List.mem_cons, List.mem_map] at h
  rcases h with rfl | ⟨e'', _, rfl⟩
  · -- e' = e^(b):  E(e^(b)) = ¬b
    simpa [E, bval] using hE
  · -- e' = e''·e^(b):  E = E(e'') ∧ ¬b
    simp only [E, bval, Bool.and_eq_true] at hE
    simpa using hE.2

/-- Corollary: a loop `e^(b)` never has a derivative that halts on a `b`-atom. So the
    set of atoms any loop-derivative accepts on is disjoint from `b` — the finite,
    `derivs`-level shadow of "no branch of `⟦e^(b)⟧` accepts `b` infinitely often". -/
theorem loop_deriv_no_halt_in_b {b : BExp T} {e : Exp A T} {e' : Exp A T}
    (h : e' ∈ derivs (.wh b e)) {a : Atom} (hb : bval V b a = true) :
    bval V (E e') a = false := by
  cases h' : bval V (E e') a with
  | false => rfl
  | true => rw [loop_deriv_halts_on_not_b V h h'] at hb; exact absurd hb (by simp)

/-- **The loop case of D.2, in strong form.** No two derivatives of a loop `e^(b)`
    (with `b` satisfiable) accept on *complementary* atom-sets. So a loop's cycle can
    never contain a state accepting exactly on `c` and one accepting exactly on `c̄` —
    the finite obstruction to the b/b̄-alternation of Figure 3. Both derivatives accept
    only on `¬b`-atoms (`loop_deriv_no_halt_in_b`); at a `b`-atom `a₀` both reject, but
    complementarity forces one to accept there. -/
theorem loop_no_complementary {b : BExp T} {e d1 d2 : Exp A T}
    (h1 : d1 ∈ derivs (.wh b e)) (h2 : d2 ∈ derivs (.wh b e))
    (hcomp : ∀ a, bval V (E d2) a = ! bval V (E d1) a)
    (a0 : Atom) (hb0 : bval V b a0 = true) : False := by
  have hd1 := loop_deriv_no_halt_in_b V h1 hb0
  have hd2 := loop_deriv_no_halt_in_b V h2 hb0
  rw [hcomp a0, hd1] at hd2; simp at hd2

-- ── The domination invariant: `AccBounded b' d` (d accepts only outside b') ──────

/-- `d` accepts only on `¬b'`-atoms — the acceptance set of `d` is disjoint from `b'`.
    The invariant that dominates all states inside a loop (guard `b'`) and, crucially,
    is preserved by right-composition `·f` (which only shrinks acceptance). -/
def AccBounded (b' : BExp T) (d : Exp A T) : Prop := ∀ a, bval V (E d) a = true → bval V b' a = false

/-- Every derivative of a loop `e^(b)` is `AccBounded` by `b` (= `loop_deriv_halts_on_not_b`). -/
theorem accBounded_loop {b : BExp T} {e d : Exp A T} (h : d ∈ derivs (.wh b e)) :
    AccBounded V b d := fun _ hE => loop_deriv_halts_on_not_b V h hE

/-- **`AccBounded` is preserved by right-composition.** `E(d'·f) = E(d')∧E(f) ⊆ E(d')`,
    so if `d'` avoids `b'` then so does `d'·f`. This is what carries the loop
    domination through the `seq`/`ite` derivatives in the induction. -/
theorem AccBounded.seq {b' : BExp T} {d' f : Exp A T} (hd : AccBounded V b' d') :
    AccBounded V b' (.seq d' f) := by
  intro a hE; simp only [E, bval, Bool.and_eq_true] at hE; exact hd a hE.1

/-- **Two `AccBounded`, complementary, on a satisfiable `b'` — contradiction.** If
    `d₁,d₂` both avoid `b'` and accept on complementary atom-sets, then at any `b'`-atom
    both reject, yet complementarity forces one to accept. This is the finite kernel of
    D.2: mutually-reachable states share a satisfiable loop guard `b'` that bounds both,
    so complementary acceptance is impossible. -/
theorem complementary_accBounded_false {b' : BExp T} {d1 d2 : Exp A T}
    (hb1 : AccBounded V b' d1) (hb2 : AccBounded V b' d2)
    (hcomp : ∀ a, bval V (E d2) a = ! bval V (E d1) a)
    (a0 : Atom) (ha0 : bval V b' a0 = true) : False := by
  have h1 : bval V (E d1) a0 = false := by
    cases h : bval V (E d1) a0 with
    | false => rfl
    | true => rw [hb1 a0 h] at ha0; exact absurd ha0 (by simp)
  have h2 : bval V (E d2) a0 = false := by
    cases h : bval V (E d2) a0 with
    | false => rfl
    | true => rw [hb2 a0 h] at ha0; exact absurd ha0 (by simp)
  rw [hcomp a0, h1] at h2; simp at h2

-- ── Reachability in the derivative automaton ────────────────────────────────

/-- One-step transition: `d` steps to `d'` on some atom via some action. -/
def Step (d d' : Exp A T) : Prop := ∃ (a : Atom) (q : A), next V d a = some (q, d')

/-- Reachability — reflexive-transitive closure of `Step`. -/
inductive Reaches (V : T → Atom → Bool) : Exp A T → Exp A T → Prop where
  | refl (d) : Reaches V d d
  | tail {d d' d''} : Reaches V d d' → Step V d' d'' → Reaches V d d''

theorem Reaches.trans {d d' d'' : Exp A T}
    (h1 : Reaches V d d') (h2 : Reaches V d' d'') : Reaches V d d'' := by
  induction h2 with
  | refl => exact h1
  | tail _ hstep ih => exact Reaches.tail ih hstep

/-- `Step` composed on the left gives reachability. -/
theorem Reaches.head {d d' d'' : Exp A T}
    (hstep : Step V d d') (h : Reaches V d' d'') : Reaches V d d'' :=
  Reaches.trans V (Reaches.tail (Reaches.refl d) hstep) h

#print axioms loop_deriv_halts_on_not_b
#print axioms loop_no_complementary
#print axioms complementary_accBounded_false
#print axioms Reaches.trans

end GkatDeriv
