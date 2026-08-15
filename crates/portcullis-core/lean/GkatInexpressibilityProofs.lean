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

/-- **Reachability stays inside `derivs e`** (from `derivs_closed`). Every state a run
    from a derivative of `e` can reach is itself a derivative of `e` — so all cycles
    live in the finite set `derivs e`, the confinement every remaining case rests on. -/
theorem reaches_mem_derivs {e d d' : Exp A T} (hd : d ∈ derivs e)
    (h : Reaches V d d') : d' ∈ derivs e := by
  induction h with
  | refl => exact hd
  | tail _ hstep ih => obtain ⟨a, q, hn⟩ := hstep; exact derivs_closed e ih hn

-- ── LoopActive: "inside a loop with guard b, under outer composition" ────────────

/-- `d` is a state inside a loop with guard `b`: either a derivative of some `e^(b)`,
    or such a state under outer right-composition `·f`. Captures exactly the states
    whose cycle lives in the loop `e^(b)` — `derivs (e^(b))` closed under `·f`. -/
inductive LoopActive (b : BExp T) : Exp A T → Prop where
  | core {e d0 : Exp A T} : d0 ∈ derivs (.wh b e) → LoopActive b d0
  | comp {d0 f : Exp A T} : LoopActive b d0 → LoopActive b (.seq d0 f)

/-- Every `LoopActive b` state is `AccBounded b` (accepts only on `¬b`). -/
theorem loopActive_accBounded {b : BExp T} {d : Exp A T} (h : LoopActive b d) :
    AccBounded V b d := by
  induction h with
  | core hd0 => exact accBounded_loop V hd0
  | comp _ ih => exact AccBounded.seq V ih

/-- **`LoopActive` is preserved by a step at a `b`-atom.** At a `b`-atom the loop
    cannot exit (exits happen at `¬b`, by `AccBounded`), so a step stays inside the
    loop. This is what keeps a cycle within one loop guard. -/
theorem loopActive_next {b : BExp T} {d : Exp A T} (h : LoopActive b d) :
    ∀ {a : Atom} {q : A} {d' : Exp A T},
      bval V b a = true → next V d a = some (q, d') → LoopActive b d' := by
  induction h with
  | @core e d0 hd0 => intro a q d' _ hn; exact LoopActive.core (derivs_closed (.wh b e) hd0 hn)
  | @comp d0 f h_inner ih =>
      intro a q d' hb hn
      simp only [next] at hn
      cases hne : next V d0 a with
      | some pe =>
          rw [hne] at hn; obtain ⟨q0, d0'⟩ := pe
          rw [Option.some.injEq, Prod.mk.injEq] at hn; rw [← hn.2]
          exact LoopActive.comp (ih hb hne)
      | none =>
          rw [hne] at hn
          by_cases hE : bval V (E d0) a = true
          · exact absurd (by rw [loopActive_accBounded V h_inner a hE] at hb; exact hb) (by simp)
          · rw [if_neg hE] at hn; simp at hn

/-- **`LoopActive` step dichotomy.** A step from a `LoopActive b` state either stays
    `LoopActive b`, or was taken at a `¬b`-atom (the only way to exit the loop). So
    along a path that only uses `b`-atoms — or that never leaves the loop — `LoopActive`
    is preserved. The clean engine for the cycle argument. -/
theorem loopActive_step {b : BExp T} {d : Exp A T} (h : LoopActive b d) :
    ∀ {a : Atom} {q : A} {d' : Exp A T},
      next V d a = some (q, d') → LoopActive b d' ∨ bval V b a = false := by
  induction h with
  | @core e d0 hd0 => intro a q d' hn; exact Or.inl (LoopActive.core (derivs_closed (.wh b e) hd0 hn))
  | @comp d0 f h_inner ih =>
      intro a q d' hn
      simp only [next] at hn
      cases hne : next V d0 a with
      | some pe =>
          rw [hne] at hn; obtain ⟨q0, d0'⟩ := pe
          rw [Option.some.injEq, Prod.mk.injEq] at hn; rw [← hn.2]
          rcases ih hne with h' | h'
          · exact Or.inl (LoopActive.comp h')
          · exact Or.inr h'
      | none =>
          rw [hne] at hn
          by_cases hE : bval V (E d0) a = true
          · exact Or.inr (loopActive_accBounded V h_inner a hE)
          · rw [if_neg hE] at hn; simp at hn

#print axioms loop_deriv_halts_on_not_b
#print axioms loop_no_complementary
#print axioms complementary_accBounded_false
#print axioms Reaches.trans
#print axioms loopActive_next
#print axioms loopActive_step

end GkatDeriv
