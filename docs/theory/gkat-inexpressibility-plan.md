# Plan: the first machine-checked GKAT inexpressibility

**Goal.** Machine-check that some guarded-string language `L` is denoted by **no**
GKAT expression — the "no expression at all" inexpressibility, not the
single-loop/bounded-shape results we already have
(`GkatInexpressibleProofs`, `GkatExistenceFrontierProofs`). This has never been
mechanized; the underlying mathematics is Schmid–Kappé–Kozen–Silva, *Coequations,
Coinduction, and Completeness* (ICALP 2021, arXiv:2102.08286).

**Status:** research project, multi-session. Milestone 1 landed; 2–5 are open.

## The mathematics (what we must faithfully encode)

- Expression behaviors are **guarded-string languages** with a coalgebra structure
  `⟨output, derivative⟩` (our `GkatBehaviorProofs`: `Lhalt`, `langDeriv`).
- The **nesting coequation `W`** (Def. 12) is the *smallest* set of behaviors
  containing the discrete behaviors `D = {⟦b⟧ | b a test}` and closed under:
  1. sequential composition `t·s`,
  2. **derivative closure**: `(∀ a ∈ N(t), ∂ₐt ∈ W) ⟹ t ∈ W`  (the subtle rule),
  3. continuation `t ⊳ s`  (the loop / dual of Kleene star).
- **Prop. 13:** `W = {⟦e⟧ | e ∈ Exp}`. So `L ∉ W ⟺ L` is inexpressible.
- **Trap (confirmed from the paper):** the Fig. 4 automaton is *non-well-nested but
  expressible*. Well-nestedness is **not** the characterization — `W` is. Any
  inexpressibility must go through `W`, not a structural automaton property. There is
  also **no simpler necessary invariant** that separates the witness (determinism
  holds for `L` too); this is exactly why the problem is hard.

## The hard part

Rule 2 (derivative closure) makes `W` a **mixed inductive/coinductive** definition:
`W` is a least fixpoint, yet rule 2 concludes `t ∈ W` from a *universal over
derivatives* premise. Encoding this faithfully in Lean (so that both `⟦e⟧ ∈ W` and a
witness `L ∉ W` are provable) is the crux. Options to evaluate in Milestone 2:
- an inductive predicate with rule 2 as a constructor taking `∀ a, ∂ₐt ∈ W` (works if
  the recursion is well-founded on a size/rank measure — needs a termination story);
- a fuel-/rank-indexed family `Wₙ` with `W = ⋃ₙ Wₙ`, matching the least-fixpoint
  reading;
- Knaster–Tarski over the behavior lattice (we already have `RankedLattice`/lfp
  machinery in `ExposureLoopFixpointProofs`).

## Milestones

1. **[DONE] Behavior coalgebra.** `GkatBehaviorProofs`: `Lhalt`, `langDeriv`, and
   `den` is a coalgebra homomorphism (`Lhalt_den`, `langDeriv_den`,
   `langDeriv_den_step`). Foundation `W` is defined over.

2. **Encode `W`.** Define the nesting coequation as a predicate on behaviors, with a
   termination/rank story for rule 2. Define `t·s`, `∂ₐt`, `t ⊳ s`, `N(t)` on our
   language behaviors. *Risk: high — the fixpoint encoding is the crux.*

3. **Soundness of Prop. 13 (`⟦e⟧ ∈ W`).** By induction on `e`: `act`/`test` → base +
   rule 2; `seq` → rule 1; `ite` → rule 2 (guarded union via derivatives); `wh` →
   rule 3 (continuation). Uses Milestone 1's homomorphism. *Risk: medium.*

4. **Completeness of Prop. 13 (`W ⊆ {⟦e⟧}`) — OR bypass it.** The Kleene-theorem
   direction. For a *specific* inexpressible `L` we may not need full Prop. 13: it
   suffices to (a) exhibit `L`, (b) prove `L ∉ W` directly by showing every `W`-member
   satisfies a property `L` lacks, extracted from the `W` closure rules. *Risk: high;
   the direct `L ∉ W` route is likely more tractable than full Prop. 13.*

5. **The witness `L ∉ W`.** Construct a concrete deterministic language `L` (a
   non-well-nested 2-cycle-with-two-exits behavior) and prove `L ∉ W`, hence `∀ e,
   ⟦e⟧ ≠ L`. *Risk: high — depends on Milestones 2–4.*

## UNBLOCKED — precise definitions obtained (from the paper, §5–6, verbatim)

**The final coalgebra `Z`** (§4): trees `t : A⁺ ⇀ 2+Σ` (partial functions, `A ⊆ dom
t`), where `t(a)=0` reject, `t(a)=1` accept, `t(a)=p∈Σ` action. Output/derivative:
`t↓a` iff `t(a)=0`; `t⇓a` iff `t(a)=1`; `t —a|p→ ∂ₐt` iff `t(a)=p`, with `∂ₐt := λw.
t(aw)`. (Remark 4.1: trees ≅ deterministic guarded languages `L ⊆ (A·Σ)*·A ∪
(A·Σ)ω`.) This is exactly our behavior coalgebra `⟨Lhalt, langDeriv⟩` (M1), extended
to record *which* action and to infinite (`ω`) branches.

**Behavioral differential equations (§5), the operations `W` uses:**
- Tests `⟦b⟧(a) = 1` if `a∈b` else `0`.  Action `⟦p⟧(a)=p`, `∂ₐ⟦p⟧ = ⟦1⟧`.
- Sequential `·`:  `(s·t)(a) = t(a)` if `s(a)=1` else `s(a)`;  `∂ₐ(s·t) = ∂ₐt` if
  `s(a)=1` else `(∂ₐs)·t`.  (= the fusion product; our `langSeq`.)
- Guarded union `+_b`:  `(s+_b t)(a) = s(a)` if `a∈b` else `t(a)`;  `∂ₐ(s+_b t) = ∂ₐs`
  if `a∈b` else `∂ₐt`.
- Guarded exponential `t^(b)`:  `t^(b)(a) = 1` if `a∉b`; `t(a)` if `a∈b ∧ t(a)∈Σ`; `0`
  otherwise.  `∂ₐ(t^(b)) = ∂ₐt · t^(b)`.
- **Continuation `▷`** (NOT a GKAT op; the loop primitive, dual to Kleene star):
  `(s▷t)(a) = t(a)` if `s(a)=1` else `s(a)`;  `∂ₐ(s▷t) = (∂ₐt)▷t` if `s(a)=1` else
  `(∂ₐs)▷t`.  "attaches infinitely many copies of `t` to `s`."

**Definition 6.1 (the nesting coequation `W`), verbatim.** `W` is the smallest subset
of `Z` containing the discrete coequation `D := {⟦b⟧ | b ⊆ A}` and closed under:
```
  t,s ∈ W          (∀a∈A) t(a)∈Σ ⟹ ∂ₐt ∈ W          t,s ∈ W
  ─────────        ──────────────────────────         ─────────
  t·s ∈ W                   t ∈ W                     t▷s ∈ W
```
**Prop 6.2:** `W = {⟦e⟧ | e ∈ Exp}`. Soundness (`⟦e⟧ ∈ W`) uses: `∂ₐ⟦p⟧=1` so `p∈W`
by rule 2; `·` by rule 1; `+_b` since every derivative of `s+_b t` is a derivative of
`s` or of `t` (rule 2); and the **key identity** `t^(b) = 1 ▷ (t̃ +_b 1)` where `t̃ :=
Σ_{a|pₐ→tₐ} pₐ·tₐ`, giving loops via rule 3.

**The concrete inexpressible witness — Figure 3 (§6).** The two-state automaton:
`v₀ —b|p→ v₁`, `v₁ —b̄|q→ v₀`, i.e. state `v₀` acts `p` and moves to `v₁` on atoms
`a∈b`, and `v₁` acts `q` and moves back to `v₀` on atoms `a∈b̄`. Its single infinite
branch reads atoms alternating `b, b̄, b, b̄, …`. **It exhibits no behavior `⟦e⟧`**
when `b ≠ 0 ≠ b̄`, because (Appendix D, *not in the pages we have*) **no branch of a
GKAT behavior accepts both `b` and `b̄` infinitely often.** (Cf. our
`InLoop_exits_on_not_b`: a single loop continues only on `b`-atoms.)

## BREAKTHROUGH: the ω-property FINITIZES — route B is tractable with our corpus

**Appendix D (obtained).** `N(t) := {a | t(a)∈Σ}`. **Lemma D.2:** for `t ∈ W` and any
infinite branch `B ⊆ Node(t)`, `B` is *finitely alternating*: either
`|{w∈B | E(∂_w t)=b}| < ω` or `|{w∈B | E(∂_w t)=b̄}| < ω`. **Example D.1 / Fig. 3:**
`v₀ —b|p→ v₁`, `v₁ —b̄|q→ v₀` is not nested when `b,b̄ ≠ 0` — its single branch has
`E` alternating `b, b̄, …` infinitely, violating D.2. D.2's proof inducts on the
nesting construction (·, +, ▷); the ▷ case is a contradiction argument.

**Finitization (the key move).** `⟦e⟧` has finitely many derivatives (Lemma F.1 =
our `derivs`, `derivs_closed`). So an infinite branch must **cycle**, and "infinitely
often" collapses to a **cycle** property of the finite automaton `⟨E, next⟩`: no
cycle contains derivatives `e'` with `E(e')=b` and `e''` with `E(e'')=b̄`. **No
coinductive trees needed** — this lives entirely in our finite `derivs`/`next`/`E`
world. (This *revises* the earlier "needs coinductive Z" assessment below: that was
right about the raw tree, wrong about the *decidable* image `⟦e⟧`.)

**Crux `^(b)` case — DONE** (`GkatInexpressibilityProofs.loop_deriv_halts_on_not_b`):
every derivative of `e^(b)` accepts only on `¬b`-atoms (`E(e^(b))=¬b`; a derivative is
`e'·e^(b)` with `E = E(e')∧¬b ⊆ ¬b`). So a loop's cycle never reaches an `E=b` state —
its branches are finitely alternating (never `b`). This generalizes
`InLoop_exits_on_not_b` to all loop derivatives; `[propext, Quot.sound]`, sorryAx-free.

**Revised remaining route B (tractable):**
- (i) [DONE] loop case: `loop_deriv_halts_on_not_b`.
- (ii) `·` and `+_b` cases: derivatives of `seq e f` / `ite b e f` are derivatives of
  the parts (we have `derivs`/`deriv_mem` for this); a cycle in the composite lives in
  one part. Prove the finite criterion by induction on `e`.
- (iii) State the finite criterion (no cycle with both `E=b` and `E=b̄`) over
  `derivs`/`next`, and prove `∀ e, ⟦e⟧` satisfies it.
- (iv) Define Fig. 3's automaton (over `derivs`/`next` or as a small language) and
  show it has a cycle with `E=b` and `E=b̄` → violates (iii) → inexpressible.

The hard conceptual barriers are gone: no coinductive `Z`, no full `W` encoding —
just the finite derivative automaton we already built. (ii)–(iv) are structural-
induction + finite-graph work.

## SUPERSEDED: earlier "the obstruction is an ω-property" note (kept for the record)

The Fig. 3 automaton (b/b̄-alternating 2-cycle) has, if neither state accepts, **no
finite accepting strings** — so `den(Fig 3) = ∅ = ⟦0⟧`, which is *finitely
expressible*. Its inexpressibility lives entirely in the **infinite branch** (the
`ω`-word alternating `b, b̄, …`), which the "accept `b` and `b̄` infinitely often"
criterion is about. **Our `den` (finite guarded strings) is blind to this.** Trees in
`Z` are `L ⊆ (A·Σ)*·A ∪ (A·Σ)ω` — the `ω` part carries the obstruction (Remark 4.1).

**Consequence:** M1's finite-string behavior coalgebra is the *finite shadow* of `Z`
and is genuinely insufficient for M4/M5. Both routes below require modelling the
**infinite (coinductive) tree**, not just finite acceptance:

- **(A) via `W`:** build the tree coalgebra `Z` (coinductive `t : A⁺ ⇀ 2+Σ`), the ops
  `·, +_b, ^(b), ▷` by their BDEs, `W` (Def 6.1) as an inductive predicate on trees,
  prove `⟦e⟧ ∈ W` (Prop 6.2), and `Fig 3 ∉ W`.
- **(B) via the criterion:** model behaviors as trees / `ω`-branches, formalize "no
  branch accepts both `b` and `b̄` infinitely often", prove every `⟦e⟧` satisfies it
  (Appendix D — **not in the pages we have**), show Fig. 3 violates it.

Either way, **Milestone 2 is now: construct the coinductive tree coalgebra `Z`** (with
`Σ`-labelled transitions and `ω`-branches) and re-establish `den`/`⟦·⟧` as its
finite-plus-infinite unfolding. Our existing `next`/`E`/`InLoop` corpus feeds the
transition structure, but the `ω`-completion is new, coinductive work.

## Honest assessment

Milestone 1 is solid but is the *finite shadow* of the real object. The project is
UNBLOCKED on definitions (`W` = Def 6.1 exact; witness = Fig. 3; criterion known), and
the true M2 is now precisely identified: the **coinductive tree coalgebra `Z`** — a
different and larger formalization than the finite-string work so far. Route B also
needs Appendix D (still to obtain). This is a genuine research-mechanisation project;
the honest near-term deliverable is `Z` + the BDE operations + `W`'s definition, then
`⟦e⟧ ∈ W`. That is the resumable next step, now fully specified.
