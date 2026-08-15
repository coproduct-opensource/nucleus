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

## Honest assessment

Milestones 2–5 are each a substantial formalization; the fixpoint encoding (M2) and
the `L ∉ W` argument (M4/M5) are genuine research. This plan exists so the effort is
scoped and resumable rather than open-ended. The realistic near-term value is
M1 (done) + M2 + M3 — a machine-checked nesting coequation with the soundness of the
GKAT-behaviors characterization; M4/M5 (the actual inexpressibility) follow only once
the encoding in M2 is settled.
