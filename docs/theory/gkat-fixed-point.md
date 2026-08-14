# GKAT's fixed point: the research task, and our reconciliation

This note records two things: (1) where the GKAT completeness question stands and
what the concrete open task is, and (2) how GKAT's guarded loop relates to the
least-fixed-point ratchet we prove in
`crates/portcullis-core/lean/ExposureLoopFixpointProofs.lean`, made machine-checked
in `GkatGuardedLoopBridge.lean`.

## Why GKAT, for us

GKAT (Guarded Kleene Algebra with Tests, Smolka et al. 2019) is the **decidable,
guarded** fragment of KAT: its programs are exactly `if b then p else q` and
`while b do p` over actions and Boolean tests, and equivalence is decidable in
nearly linear time. It is the natural user-facing surface for a **cascade** DSL
with branches and guards — the parked follow-up to the straight-line cascade in
`crates/nucleus-ifc-kernel/src/cascade.rs`. Full action logic (residuation + star)
is Σ⁰₁-undecidable (Kuznetsov 2019), so GKAT — not KAT-with-residuation — is the
right surface if we ever add `if`/`while` to user cascades.

## The fixed point is the whole difficulty

Dropping KAT's unrestricted `+` removes the natural order, so GKAT's `while`
**cannot** be axiomatized as a *least* fixed point the way Kleene star is. Instead
it is axiomatized as a **unique** fixed point (Salomaa style), and uniqueness is
made to hold by a **guardedness** side condition (the loop body must make
progress). Concretely, `while b do p` satisfies the unrolling
`while b do p ≡ if b then (p ; while b do p) else skip`, and the fixed-point rule
says: any guarded `x` satisfying that same equation is provably equal to
`while b do p`.

### State of the art (sources)

- **Completeness is open** since GKAT was introduced (Smolka et al. 2019/2020).
  [GKAT: Verification of Uninterpreted Programs in Nearly Linear Time,
  arXiv:1907.05920](https://arxiv.org/abs/1907.05920)
- The coalgebraic/coinductive completeness route is **conditional on a uniqueness
  axiom (UA)** that seems necessary in every known proof, and it is open whether
  UA can be eliminated. [Coequations, Coinduction, and Completeness, ICALP 2021,
  arXiv:2102.08286](https://arxiv.org/abs/2102.08286)
- The **skip-free** fragment IS fully solved: a complete algebraic axiomatization
  that eliminates *both* the uniqueness axiom *and* the guardedness side
  condition. [A Complete Inference System for Skip-free GKAT, FoSSaCS 2023,
  arXiv:2301.11301](https://arxiv.org/abs/2301.11301)
- A **cyclic proof system** for GKAT (2024).
  [arXiv:2405.07505](https://arxiv.org/abs/2405.07505)
- Freshest, and the clearest "next task" signal: **Toward a Completeness Theorem
  for GKAT** (Hung Pham, 2026) proves a **uniqueness theorem** — any two solutions
  of the equation system of a Thompson-generated automaton are provably equal —
  and reduces the remaining work to showing a **solution exists** for that
  automaton. [Bucknell honors thesis
  754](https://digitalcommons.bucknell.edu/honors_theses/754/)

### The concrete open task (reading 1)

> **Existence.** For a Thompson-generated G-automaton `A` (the automaton of a GKAT
> expression), its states induce a system of guarded equations. Show that the
> system has a solution that is *provable in the GKAT axioms* — i.e. that `A` is
> provably solvable back into a GKAT term.

With Pham's uniqueness in hand, existence completes the argument: two expressions
with bisimilar automata both solve the (quotient) automaton's system, so by
uniqueness they are provably equal — completeness. The adjacent open question is
whether the **uniqueness axiom can be eliminated** outside the skip-free fragment.

This is a genuine open problem; it is not something to "close" in passing. The
tractable stepping stone, if pursued, is to **formalize the uniqueness→existence
reduction in Lean** over a small G-automaton, which would (a) pin the existence
obligation precisely and (b) reuse the same finite-lattice machinery below.

## Our reconciliation (reading 2) — proven

GKAT's loop is a *unique* fixed point; our ratchet uses the *least* fixed point.
`GkatGuardedLoopBridge.lean` shows they **coincide on the exposure lattice** for
the operational loop:

- `guardedStep b f = fun x => if b x then f x else x` is GKAT's `b · f`.
- With the guard "the body still changes the state" (`f x ≠ x`), the guarded step
  IS the body (`guardedStep_notFixed_eq`), so iterating the guarded loop from ⊥
  reaches exactly `lfp f` (`guarded_loop_is_lfp`), and the loop halts precisely at
  that fixed point (`guarded_loop_halts_at_lfp`, which is where monotonicity is
  used). Hence a guarded loop over a monotone body **inherits the anti-laundering
  ratchet** (`guarded_loop_ratchets`) — the same one-theorem story the
  straight-line cascade has.
- The reconciliation needs a well-behaved guard: with an **arbitrary** GKAT test
  the guarded step need not be a monotone endomap
  (`arbitrary_guard_breaks_monotonicity` — a concrete `L3` counterexample), so it
  does not automatically inherit the ratchet.

That last point is exactly the boundary: extending user cascades to full `if`/
`while` (arbitrary guards) needs the **guardedness/termination** side condition —
the same object that makes GKAT's fixed point unique, and the same object the
research task above is about. So (1) and (2) are two ends of one thread: the
guardedness condition that our cascade surface would need is the guardedness
condition whose axiom GKAT completeness is trying to pin down.

## Next task, decided

- **For the cascade surface:** the proven bridge is enough to add a *not-fixed*
  (converge-to-fixpoint) guarded loop today; a full `while b` step is gated on a
  guardedness predicate over the guard `b` — that is the next brick, and it is
  small (state the termination condition, prove the run is a monotone endomap
  under it, reuse `loop_admissible`).
- **For the research frontier:** attempt the uniqueness→existence reduction as a
  Lean formalization over a small G-automaton, which is the honest way to make
  progress on the open existence obligation rather than asserting it.
