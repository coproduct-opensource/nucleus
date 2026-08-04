# Effect sequencing and authority — why not a monad tower, and why not F\*

Status: **decided**, 2026-07-26. Supersedes nothing; records a fork that was
evaluated and closed so it is not re-opened from scratch.

## The question

Nested permissions and context — the discharge bundle, the IFC floating label,
the delegation ceiling, the budget — look like a monad transformer stack. The
appeal is concrete and worth taking seriously: **concise sequencing**. Threading
four kinds of context by hand through every effect is the ergonomic cost we
actually pay.

Two candidate answers were examined: build the tower in Rust, or adopt F\* for
its indexed effects.

## What is already true

`portcullis-wasi::ifc::BoundaryMonitor` **is** LIO with the monad removed: `pc`
starts at `⊥`, `stamp` joins (monotone, only raises), `check` tests `flows_to` at
the sink, and declassify is the sole lowering step. That is exactly the
floating-label discipline of Stefan et al.'s `LIO` monad, implemented as a
`&mut struct`. The shape fits; the question is only what an explicit encoding
buys.

And the enforcement path already **is** a monadic encoding — the least safe one.
`proof: &DischargedBundle` at every effect boundary is `ReaderT Capability`:
authority that is ambient and readable at every bind. `require_scope` rejects a
bundle earned for a *different* action, which is real and was worth building. It
does not stop a *matching* bundle from being replayed arbitrarily often. The
one-shot property the Lean side proves has no counterpart in the Rust types.

## Decision 1 — no monad transformer tower

A tower is a good *description* of the sequencing and a poor *enforcement*
mechanism, because it flattens the two properties the design rests on:

* **Authority is graded, not ambient.** A monad has one fixed effect signature;
  `ReaderT` makes the capability duplicable at every `>>=`. What the design needs
  is a *graded* monad indexed by the permission lattice — "consumes authority
  `a`, yields `b`" — so composition is the lattice operation. The algebra is
  already present, unnamed: `delegation_is_functor` (`c' ≤ c → c'.scope ⊆
  c.scope`) is a monotone map of preorders.
* **One-shot tokens are affine, and monads duplicate.** Nothing in the monad laws
  forbids `tok >>= \t -> f t >> g t`. Rust's move semantics already gives
  at-most-once for free; a monadic re-encoding would trade that away.

Transformer order is also a security property here rather than a style choice:
`StateT s (Except e)` discards state on failure, `ExceptT e (State s)` keeps it.
For a taint label and an audit trail, "what survives a denial" is exactly the
kind of thing that should be stated and tested. It currently is not.

## Decision 2 — no F\*

F\* is the most mature system with genuine indexed effects, and Pulse/Steel are
real (StarMalloc, HACL\*). It is still the wrong move here, for three reasons in
ascending order of weight.

1. **It moves off the recommended Aeneas backend.** Aeneas supports F\*, but its
   most mature backends are Lean and HOL4; Lean is the recommended one and the
   only one with partial functions, extrinsic termination proofs, and tactics for
   monadic programs. `OlogCoreGen` is already the broken link in the Rust→Lean
   chain — a less mature backend makes that worse.
2. **It is a third kernel substrate.** olog's `check-language-sprawl.sh`
   (Pa.Defense.A.1) states the rule: every active language is either the verified
   kernel substrate (Rust/Lean) or a thin known-shape mount. This programme has
   already made this call once — the Coq beachhead in capability-primitive was
   retired as **debt, not an asset**: an option that is paid for and not
   exercised.
3. **Z3 enters the trusted base.** F\* is SMT-backed. For a programme whose thesis
   is an enumerable trusted base — measured at 44 entries and, in the same week,
   demonstrated irreducible by two independent mechanisms — adding an SMT solver
   is a qualitative change from Lean's small kernel. It is also *priced*:
   `report-trusted-base.py --gate` ratchets `proved edges / trusted entries`, and
   F\* adds observations (build, verify, extract) with no new proved edges. **The
   assurance ratio falls and the gate fires.** The metric registers this decision
   as a regression before any human argues about it.

The clearest way to see the mismatch: the ergonomic cost is at **Rust call
sites**. F\* would not improve them. It relocates where the proof lives, which is
an answer to an adjacent question.

**What would re-open this:** if the Iris-in-Lean liveness work turns out to be
permanently blocked rather than staged, Pulse/Steel is a genuine alternative for
the concurrency track specifically. That is the one place F\* competes with
something already invested in and resisted, so it is where to look — not a reason
to switch wholesale.

## Decision 3 — what to do instead

**Rust: a consuming chain is linear do-notation.** `self` by value is a bind that
consumes; `?` is the `ExceptT` layer with syntax support already; a phantom
parameter carries the grade:

```rust
session.read(input)?.exec(cmd)?.egress(sink)?
```

Replay becomes a move-after-move compile error rather than a policy. No HKT, no
new dependency, nothing added to the trusted base. This is the same move `dlc-d`
already made — *compilation is the proof*.

Note the precise property Rust gives: **affine** (use at most once), not linear
(use exactly once). At-most-once is what one-shot declassification needs, so the
weaker guarantee is the right one. A widely-circulated claim that Rust 1.95
shipped linear types via a `std::marker::MustMove` trait is **false** — checked
against 1.96.1, which is newer; the trait does not exist.

**Lean: the graded structure already exists.** `delegation_calc`'s `Deriv` is an
indexed family. If the syntax is wanted, a `do`-macro over an indexed bind is
bounded work, not a language migration.

## Cost, stated

A linear spine is awkward for branching and parallel composition — one authority
threading through one chain. If an action genuinely fans out, the chain is the
wrong shape and the honest answer is to mint separate authorities. Grades also
explode combinatorially if the lattice is fine-grained, so keep them coarse:
`Operation` × `SinkClass`, which is what `require_scope` already checks.

## References

* Stefan et al., [Flexible Dynamic Information Flow Control in Haskell](https://www.scs.stanford.edu/~dm/home/papers/stefan:lio.pdf) — LIO
* [Unifying graded and parameterised monads](https://arxiv.org/pdf/2001.10274)
* [Granule](https://www.cs.kent.ac.uk/people/staff/dao7/publ/granule-icfp19.pdf) — graded modal types over a linear calculus
* [Handlers in Action](https://homepages.inf.ed.ac.uk/slindley/papers/handlers.pdf) — why handlers beat transformer stacks ergonomically
* [Programming and Proving with Indexed Effects](https://fstar-lang.org/papers/indexedeffects/indexedeffects.pdf) — F\*
* [Aeneas](https://github.com/AeneasVerif/aeneas) — backend maturity
