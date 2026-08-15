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

Axioms `[propext, Classical.choice, Quot.sound]` (the three standard Lean axioms;
`Classical.choice` enters via `by_cases` on the derivative-equality split), `sorryAx`-free.
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

-- ── Base-case acyclicity: `act`/`test` derivatives have no self-cycle ────────────

/-- `test t` performs no step. -/
theorem step_test {t : BExp T} {d' : Exp A T} : ¬ Step V (.test t) d' := by
  rintro ⟨a, q, h⟩; simp [next] at h

/-- Anything reachable from `test t` is `test t` (it is a sink). -/
theorem reaches_test {t : BExp T} {d' : Exp A T} (h : Reaches V (.test t) d') :
    d' = .test t := by
  induction h with
  | refl => rfl
  | tail _ hstep ih => subst ih; exact absurd hstep (step_test V)

/-- `act p` steps only to `test 1`. -/
theorem step_act {p : A} {d' : Exp A T} (h : Step V (.act p) d') : d' = .test .one := by
  obtain ⟨a, q, hn⟩ := h
  simp only [next, Option.some.injEq, Prod.mk.injEq] at hn; exact hn.2.symm

/-- ≥1-step reachability (a genuine cycle when `Reaches1 d d`). -/
def Reaches1 (d d' : Exp A T) : Prop := ∃ x, Step V d x ∧ Reaches V x d'

/-- `test t` derivatives have no self-cycle. -/
theorem no_selfcycle_test {t : BExp T} {d : Exp A T} (hd : d ∈ derivs (.test t)) :
    ¬ Reaches1 V d d := by
  simp only [derivs, List.mem_singleton] at hd; subst hd
  rintro ⟨x, hstep, _⟩; exact step_test V hstep

/-- `act p` derivatives have no self-cycle (`act p → test 1 → ⊥`). -/
theorem no_selfcycle_act {p : A} {d : Exp A T} (hd : d ∈ derivs (.act p)) :
    ¬ Reaches1 V d d := by
  simp only [derivs, List.mem_cons, List.mem_singleton, List.not_mem_nil, or_false] at hd
  rcases hd with rfl | rfl
  · rintro ⟨x, hstep, hr⟩
    rw [step_act V hstep] at hr
    exact absurd (reaches_test V hr) (by simp)
  · rintro ⟨x, hstep, _⟩; exact step_test V hstep

/-- **Reachability through a sequence splits.** A run from `d0·g` either stays in the
    `d0`-part (so its endpoint is `d0'·g` and `d0` reaches `d0'`), or it has exited
    into `g`'s derivatives. The engine for the `seq` case of `selfCyclic`: a cycle
    through `d0·g` either projects to a cycle of `d0`, or lands `d0·g ∈ derivs g`. -/
theorem reaches_seq_split {d0 g y : Exp A T} (h : Reaches V (.seq d0 g) y) :
    (∃ d0', y = .seq d0' g ∧ Reaches V d0 d0') ∨ y ∈ derivs g := by
  induction h with
  | refl => exact Or.inl ⟨d0, rfl, Reaches.refl d0⟩
  | tail hR hstep ih =>
      rcases ih with ⟨d0', rfl, hr⟩ | hg
      · obtain ⟨a, q, hn⟩ := hstep
        simp only [next] at hn
        cases hne : next V d0' a with
        | some pe =>
            rw [hne] at hn; obtain ⟨q', d⟩ := pe
            rw [Option.some.injEq, Prod.mk.injEq] at hn; rw [← hn.2]
            exact Or.inl ⟨d, rfl, Reaches.tail hr ⟨a, q', hne⟩⟩
        | none =>
            rw [hne] at hn
            by_cases hE : bval V (E d0') a = true
            · rw [if_pos hE] at hn; exact Or.inr (deriv_mem g hn)
            · rw [if_neg hE] at hn; simp at hn
      · obtain ⟨a, q, hn⟩ := hstep; exact Or.inr (derivs_closed g hg hn)

/-- **Reachability through a loop-tailed state splits.** A run from `e'·e^(b)` either
    stays via pure body-steps (endpoint `e''·e^(b)`, `e'` reaches `e''`), or it took a
    loop-back — which needs a `b`-atom, so `b` is satisfiable. The engine for the `wh`
    case: a cycle either projects to a body cycle (IH) or witnesses `b` satisfiable. -/
theorem reaches_loop_split {b : BExp T} {e e' y : Exp A T}
    (h : Reaches V (.seq e' (.wh b e)) y) :
    (∃ e'', y = .seq e'' (.wh b e) ∧ Reaches V e' e'') ∨ (∃ a, bval V b a = true) := by
  induction h with
  | refl => exact Or.inl ⟨e', rfl, Reaches.refl e'⟩
  | tail hR hstep ih =>
      rcases ih with ⟨e'', rfl, hr⟩ | hb
      · obtain ⟨a, q, hn⟩ := hstep
        simp only [next] at hn
        cases hne : next V e'' a with
        | some pe =>
            rw [hne] at hn; obtain ⟨q', d⟩ := pe
            rw [Option.some.injEq, Prod.mk.injEq] at hn; rw [← hn.2]
            exact Or.inl ⟨d, rfl, Reaches.tail hr ⟨a, q', hne⟩⟩
        | none =>
            rw [hne] at hn
            by_cases hE : bval V (E e'') a = true
            · rw [if_pos hE] at hn
              by_cases hb : bval V b a = true
              · exact Or.inr ⟨a, hb⟩
              · rw [if_neg hb] at hn; simp at hn
            · rw [if_neg hE] at hn; simp at hn
      · exact Or.inr hb

/-- **The `Dom` lemma.** A self-cyclic derivative of `e` is `LoopActive` by a
    *satisfiable* guard. By induction on `e`: base cases have no self-cycle; `seq`/`ite`
    project cycles to a part (IH) or land in `derivs f`/`derivs e`; `wh` either
    witnesses `b` satisfiable (loop-back) and is a loop core, or projects to a body
    cycle (IH). This is the "cycle ⟹ satisfiable enclosing loop" fact — with the
    would-be well-founded acyclicity absorbed into the structural induction. -/
theorem selfCyclic_loopActive {e : Exp A T} :
    ∀ {d : Exp A T}, d ∈ derivs e → Reaches1 V d d →
      ∃ b', (∃ a, bval V b' a = true) ∧ LoopActive b' d := by
  induction e with
  | act p => intro d hd hcyc; exact absurd hcyc (no_selfcycle_act V hd)
  | test t => intro d hd hcyc; exact absurd hcyc (no_selfcycle_test V hd)
  | seq e f ihe ihf =>
      intro d hd hcyc
      simp only [derivs, List.mem_append, List.mem_map] at hd
      rcases hd with ⟨d0, hd0, rfl⟩ | hdf
      · obtain ⟨x, ⟨a, q, hn⟩, hr⟩ := id hcyc
        simp only [next] at hn
        cases hne : next V d0 a with
        | some pe =>
            rw [hne] at hn; obtain ⟨q', d0'⟩ := pe
            rw [Option.some.injEq, Prod.mk.injEq] at hn; rw [← hn.2] at hr
            rcases reaches_seq_split V hr with ⟨d0'', heq, hrr⟩ | hin
            · rw [Exp.seq.injEq] at heq
              obtain ⟨b', hsat, hla⟩ := ihe hd0 ⟨d0', ⟨a, q', hne⟩, heq.1.symm ▸ hrr⟩
              exact ⟨b', hsat, LoopActive.comp hla⟩
            · exact ihf hin hcyc
        | none =>
            rw [hne] at hn
            by_cases hE : bval V (E d0) a = true
            · rw [if_pos hE] at hn
              exact ihf (reaches_mem_derivs V (deriv_mem f hn) hr) hcyc
            · rw [if_neg hE] at hn; simp at hn
      · exact ihf hdf hcyc
  | ite b e f ihe ihf =>
      intro d hd hcyc
      simp only [derivs, List.mem_cons, List.mem_append] at hd
      rcases hd with rfl | hde | hdf
      · obtain ⟨x, ⟨a, q, hn⟩, hr⟩ := id hcyc
        simp only [next] at hn
        by_cases hb : bval V b a = true
        · rw [if_pos hb] at hn
          exact ihe (reaches_mem_derivs V (deriv_mem e hn) hr) hcyc
        · rw [if_neg hb] at hn
          exact ihf (reaches_mem_derivs V (deriv_mem f hn) hr) hcyc
      · exact ihe hde hcyc
      · exact ihf hdf hcyc
  | wh b e ihe =>
      intro d hd hcyc
      have hmem : ∀ {e' : Exp A T}, e' ∈ derivs e → .seq e' (.wh b e) ∈ derivs (.wh b e) :=
        fun he' => by simp only [derivs, List.mem_cons, List.mem_map]; exact Or.inr ⟨_, he', rfl⟩
      simp only [derivs, List.mem_cons, List.mem_map] at hd
      rcases hd with rfl | ⟨e', he', rfl⟩
      · obtain ⟨x, ⟨a, q, hn⟩, _⟩ := hcyc
        simp only [next] at hn
        by_cases hb : bval V b a = true
        · exact ⟨b, ⟨a, hb⟩, LoopActive.core (mem_self (.wh b e))⟩
        · rw [if_neg hb] at hn; simp at hn
      · obtain ⟨x, ⟨a, q, hn⟩, hr⟩ := hcyc
        simp only [next] at hn
        cases hne : next V e' a with
        | some pe =>
            rw [hne] at hn; obtain ⟨q', e''⟩ := pe
            rw [Option.some.injEq, Prod.mk.injEq] at hn; rw [← hn.2] at hr
            rcases reaches_loop_split V hr with ⟨e''', heq, hrr⟩ | ⟨a0, hb0⟩
            · rw [Exp.seq.injEq] at heq
              obtain ⟨b', hsat, hla⟩ := ihe he' ⟨e'', ⟨a, q', hne⟩, heq.1.symm ▸ hrr⟩
              exact ⟨b', hsat, LoopActive.comp hla⟩
            · exact ⟨b, ⟨a0, hb0⟩, LoopActive.core (hmem he')⟩
        | none =>
            rw [hne] at hn
            by_cases hE : bval V (E e') a = true
            · rw [if_pos hE] at hn
              by_cases hb : bval V b a = true
              · exact ⟨b, ⟨a, hb⟩, LoopActive.core (hmem he')⟩
              · rw [if_neg hb] at hn; simp at hn
            · rw [if_neg hE] at hn; simp at hn

/-- A `Reaches1` (one-or-more steps) yields a plain `Reaches`. -/
theorem reaches1_reaches {d d' : Exp A T} (h : Reaches1 V d d') : Reaches V d d' := by
  obtain ⟨x, hs, hr⟩ := h; exact Reaches.head V hs hr

/-- A run is either trivial or a real (≥1-step) `Reaches1`. -/
theorem reaches_refl_or_step {d d' : Exp A T} (h : Reaches V d d') :
    d = d' ∨ Reaches1 V d d' := by
  induction h with
  | refl => exact Or.inl rfl
  | tail hR hstep ih =>
      rcases ih with rfl | ⟨x, hs, hr⟩
      · exact Or.inr ⟨_, hstep, Reaches.refl _⟩
      · exact Or.inr ⟨x, hs, Reaches.tail hr hstep⟩

/-- Reachability between *distinct* states is a real (≥1-step) `Reaches1`. -/
theorem reaches_ne_reaches1 {d d' : Exp A T} (h : Reaches V d d') (hne : d ≠ d') :
    Reaches1 V d d' := (reaches_refl_or_step V h).resolve_left hne

/-- **The pair `Dom` lemma.** Two mutually-reachable derivatives of `e` are
    `AccBounded` by a *common satisfiable* guard. Induction on `e` — the guard-switch
    across nesting is handled by descending into the right loop: in `seq`, an exit
    lands both states in `derivs f` (IH_f); in `wh`, a loop-back witnesses `b`
    satisfiable (both `AccBounded b`), else a body cycle recurses (IH_e + `AccBounded.seq`).
    The `d1 = d2` collapse is discharged uniformly by `selfCyclic_loopActive`. -/
theorem cycle_common_bound {e : Exp A T} :
    ∀ {d1 d2 : Exp A T}, d1 ∈ derivs e → Reaches1 V d1 d2 → Reaches1 V d2 d1 →
      ∃ b', (∃ a, bval V b' a = true) ∧ AccBounded V b' d1 ∧ AccBounded V b' d2 := by
  induction e with
  | act p =>
      intro d1 d2 hd1 h12 h21
      obtain ⟨x, hs, hr⟩ := id h12
      exact absurd ⟨x, hs, Reaches.trans V hr (reaches1_reaches V h21)⟩ (no_selfcycle_act V hd1)
  | test t =>
      intro d1 d2 hd1 h12 h21
      obtain ⟨x, hs, hr⟩ := id h12
      exact absurd ⟨x, hs, Reaches.trans V hr (reaches1_reaches V h21)⟩ (no_selfcycle_test V hd1)
  | seq e f ihe ihf =>
      intro d1 d2 hd1 h12 h21
      by_cases hd12 : d1 = d2
      · subst hd12
        obtain ⟨b', hsat, hla⟩ := selfCyclic_loopActive V hd1 h12
        exact ⟨b', hsat, loopActive_accBounded V hla, loopActive_accBounded V hla⟩
      · simp only [derivs, List.mem_append, List.mem_map] at hd1
        rcases hd1 with ⟨d01, hd01, rfl⟩ | hd1f
        · -- d1 = d01·f
          rcases reaches_seq_split V (reaches1_reaches V h12) with ⟨d0', rfl, hR12⟩ | hd2f
          · -- d2 = d0'·f, Reaches d01 d0'
            rcases reaches_seq_split V (reaches1_reaches V h21) with ⟨d0'', heq, hR21⟩ | hd1f2
            · rw [Exp.seq.injEq] at heq
              have hne01 : d01 ≠ d0' := fun h => hd12 (by rw [h])
              obtain ⟨b', hsat, ha1, ha2⟩ :=
                ihe hd01 (reaches_ne_reaches1 V hR12 hne01)
                  (reaches_ne_reaches1 V (heq.1 ▸ hR21) (fun h => hne01 h.symm))
              exact ⟨b', hsat, AccBounded.seq V ha1, AccBounded.seq V ha2⟩
            · exact ihf hd1f2 h12 h21  -- d1·f ∈ derivs f (overlap)
          · -- d2 ∈ derivs f ⟹ d1 ∈ derivs f (reaches back) ⟹ IH_f
            exact ihf (reaches_mem_derivs V hd2f (reaches1_reaches V h21)) h12 h21
        · exact ihf hd1f h12 h21
  | ite b e f ihe ihf =>
      intro d1 d2 hd1 h12 h21
      by_cases hd12 : d1 = d2
      · subst hd12
        obtain ⟨b', hsat, hla⟩ := selfCyclic_loopActive V hd1 h12
        exact ⟨b', hsat, loopActive_accBounded V hla, loopActive_accBounded V hla⟩
      · simp only [derivs, List.mem_cons, List.mem_append] at hd1
        rcases hd1 with rfl | hde | hdf
        · -- d1 = ite b e f (head): first step lands in derivs e / derivs f
          obtain ⟨x, ⟨a, q, hn⟩, hr⟩ := id h12
          simp only [next] at hn
          by_cases hb : bval V b a = true
          · rw [if_pos hb] at hn
            have hd2 : d2 ∈ derivs e := reaches_mem_derivs V (deriv_mem e hn) hr
            exact ihe (reaches_mem_derivs V hd2 (reaches1_reaches V h21)) h12 h21
          · rw [if_neg hb] at hn
            have hd2 : d2 ∈ derivs f := reaches_mem_derivs V (deriv_mem f hn) hr
            exact ihf (reaches_mem_derivs V hd2 (reaches1_reaches V h21)) h12 h21
        · exact ihe hde h12 h21
        · exact ihf hdf h12 h21
  | wh b e ihe =>
      intro d1 d2 hd1 h12 h21
      by_cases hd12 : d1 = d2
      · subst hd12
        obtain ⟨b', hsat, hla⟩ := selfCyclic_loopActive V hd1 h12
        exact ⟨b', hsat, loopActive_accBounded V hla, loopActive_accBounded V hla⟩
      · have hmem : ∀ {e' : Exp A T}, e' ∈ derivs e →
            Exp.seq e' (.wh b e) ∈ derivs (.wh b e) :=
          fun he' => by simp only [derivs, List.mem_cons, List.mem_map]; exact Or.inr ⟨_, he', rfl⟩
        simp only [derivs, List.mem_cons, List.mem_map] at hd1
        rcases hd1 with rfl | ⟨e1', he1', rfl⟩
        · -- d1 = e^(b) (loop head): the first step needs a b-atom ⟹ b satisfiable
          obtain ⟨x, ⟨a, q, hn⟩, _⟩ := id h12
          simp only [next] at hn
          by_cases hb : bval V b a = true
          · have hd2 : d2 ∈ derivs (.wh b e) :=
              reaches_mem_derivs V (mem_self (.wh b e)) (reaches1_reaches V h12)
            exact ⟨b, ⟨a, hb⟩, accBounded_loop V (mem_self (.wh b e)), accBounded_loop V hd2⟩
          · rw [if_neg hb] at hn; simp at hn
        · -- d1 = e1'·e^(b): loop-back ⟹ b sat, else body cycle ⟹ IH_e
          have hd1m : Exp.seq e1' (.wh b e) ∈ derivs (.wh b e) := hmem he1'
          have hd2m : d2 ∈ derivs (.wh b e) :=
            reaches_mem_derivs V hd1m (reaches1_reaches V h12)
          rcases reaches_loop_split V (reaches1_reaches V h12) with ⟨e2', rfl, hR12⟩ | ⟨a0, hb0⟩
          · rcases reaches_loop_split V (reaches1_reaches V h21) with ⟨e1'', heq, hR21⟩ | ⟨a0, hb0⟩
            · rw [Exp.seq.injEq] at heq
              have hne1 : e1' ≠ e2' := fun h => hd12 (by rw [h])
              obtain ⟨b', hsat, ha1, ha2⟩ :=
                ihe he1' (reaches_ne_reaches1 V hR12 hne1)
                  (reaches_ne_reaches1 V (heq.1 ▸ hR21) (fun h => hne1 h.symm))
              exact ⟨b', hsat, AccBounded.seq V ha1, AccBounded.seq V ha2⟩
            · exact ⟨b, ⟨a0, hb0⟩, accBounded_loop V hd1m, accBounded_loop V hd2m⟩
          · exact ⟨b, ⟨a0, hb0⟩, accBounded_loop V hd1m, accBounded_loop V hd2m⟩

/-- **No mutually-reachable complementary pair.** Two derivatives of `e` that are
    mutually reachable and accept on complementary atom-sets cannot exist. They share a
    common satisfiable loop guard (`cycle_common_bound`) that bounds both acceptance
    sets away from it — but complementarity forces one to accept on a guard-atom
    (`complementary_accBounded_false`). This is the finite kernel of Lemma D.2's
    obstruction: a b/b̄-alternating 2-cycle is impossible in any GKAT behavior. -/
theorem no_mutreach_complementary {e d1 d2 : Exp A T} (hd1 : d1 ∈ derivs e)
    (h12 : Reaches1 V d1 d2) (h21 : Reaches1 V d2 d1)
    (hcomp : ∀ a, bval V (E d2) a = ! bval V (E d1) a) : False := by
  obtain ⟨b', ⟨a0, ha0⟩, ha1, ha2⟩ := cycle_common_bound V hd1 h12 h21
  exact complementary_accBounded_false V ha1 ha2 hcomp a0 ha0

#print axioms loop_deriv_halts_on_not_b
#print axioms loop_no_complementary
#print axioms complementary_accBounded_false
#print axioms Reaches.trans
#print axioms loopActive_next
#print axioms loopActive_step
#print axioms no_selfcycle_act
#print axioms reaches_seq_split
#print axioms reaches_loop_split
#print axioms selfCyclic_loopActive
#print axioms cycle_common_bound
#print axioms no_mutreach_complementary

end GkatDeriv
