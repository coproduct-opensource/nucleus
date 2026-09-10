# ADR 0005 — Four collapses: the security surface is compositions of four objects, not sixty-five

- Status: **proposed** (2026-09-10). Nothing in this ADR is implemented.
- Tracks: the 2026-09-09 architectural audit; `SECURITY_TODO.md` items 17–30; PR #2778 (Tiers 1–2)
- Applies to: `portcullis`, `portcullis-core`, `portcullis-effects`, `nucleus-ifc-kernel`, `nucleus`, `nucleus-node`, `nucleus-tool-proxy` — the ~217k LOC dependency closure of `nucleus-node`

## Context

An audit asked whether several of nucleus's operational concepts are instances of
shared algebraic objects. They mostly are. But the finding that mattered was not
the algebra:

> **Most of those unifications are already built, several are machine-proved, and
> they are not wired to the enforcement path.**

`ProductLattice` — the categorical product in **Lat** — had zero uses, while
`PermissionLattice` is a hand-rolled six-factor product spelling `meet`/`join`/`leq`
out by hand. Lean-proved `MeetCap` had zero production call sites, and
`Kernel::attenuate` is that trait transcribed by hand, complete with a defensive
`leq` re-check of the law the trait would have guaranteed. `PathLattice::with_work_dir`
— the filesystem sandbox root — has eleven callers, every one a test, three of them
the adversarial suites that prove path-traversal containment. They prove it of a
configuration production never builds.

The repo already knew this class in two narrow places: `docs/north-star.md` demoted
clause C9 because "the attested-cert producer is dead-code with its result
discarded", and `scripts/check-extracted-callsites.sh` (C8) gates it for the Aeneas
predicates — *"a predicate proven about a function nobody calls is a proof about
dead code."* PR #2778 generalised that into a standing gate. This ADR is about the
other half: **why there were so many places for a mechanism to go unwired.**

### The measurement

Counted over the tree, not estimated:

| surface | count | of which unified |
|---|---|---|
| decision points ("may this happen") | ~65 | 1 real kernel; the rest adapters, mirrors, or duplicates |
| effect handlers owning independent gate logic | 26 | — |
| child-clamping implementations | ~24 | 1 abstract trait, **0** production call sites |
| authority-bearing dimensions | ~31 | 10 inside the product order, ~21 outside |
| expiry implementations | ~29 | in **6** numeric universes; ~10% handle clock skew |
| risk-combination rules | ~49 | across 2 unrelated families |
| canonicalization functions | ~40 | in **7** incompatible encoding families |
| identity representations | ~43 | **0** `From` impls; 13 divergent URI parsers |
| one-shot permit types | 21 | **1** satisfies unforgeable + non-`Clone` + request-bound + time-bound + consume-once |
| linear resource quantities | 20 | **1** machine-proved (`LedgerCore`) |

And the shape of the test suite explains why none of it was caught: **342 of 7,033
tests are law-shaped (~5%)**. The rest are instance tests, which verify a mechanism
and cannot see whether it is reached.

### The failure mode these numbers produce

Every defect in items 17–30 is the same sentence with different nouns: *a correct,
tested, sometimes machine-proved pure function, called with the wrong argument or
not called at all.* `require_isolation` is right and got the wrong backend.
`attest_containment` is right and lives in the wrong crate. `record_tokens` was a
ceiling check named "record". `Kernel::with_isolation` has no production caller, so
two enforcement gates have never fired.

Instance tests cannot catch that class. Laws can, because a law is a statement about
*all* paths rather than one.

## Decision

Collapse the security surface onto four objects, each carrying one law and one gate.

$$\text{Principal} \xrightarrow{\ \text{Delegation}\ } \text{Authority} \xrightarrow{\ \text{Allocation}\ } \text{Permit⟨Effect⟩} \xrightarrow{\ \text{Execution}\ } \text{Receipt}$$

Each arrow **already has exactly one correct implementation, surrounded by
imitations** — which is why this is deletion and wiring, not design:

| arrow | the one correct implementation | surrounded by |
|---|---|---|
| attenuation | `chain_attenuates` (Lean-proved, parity-tested) | ~24 hand-rolled clamps |
| conservation | `LedgerCore` (Kani E1/E2, over the shipped type) | 19 hand-rolled counters + 12 misclassified as affine |
| linearity | `Authority::spend` (affine, by value) | 20 permits passed by reference |
| lineage | `LineageEdge` + `verify_chain` | 28 other chains, 9 never walked |

### C1 — `LedgerCore<Unit>`: conservation

`LedgerCore<const N>` is generic over slot count only; the unit is hardcoded
micro-USD down to `LedgerError::InsufficientBudget`'s field names. Make it generic
over `Unit` and requantify the two existing Kani harnesses once.

- **Law:** `Σ live child grants + consumed ≤ parent max`, per unit.
- **Gate:** E1/E2 at `Unit = u64`; by parametricity that covers every candidate,
  since all ~20 are `u64`/`usize` quantities.
- **Do not force in:** TTLs and token buckets (replenishment is a function of
  wall-clock, so `Remaining` is not conserved), VCG budgets (a knapsack; the
  interesting theorems are truthfulness and IR), the settlement split (refund is
  *defined* as the residual, so conservation is definitional and already Lean-proved).
  Jamming these in would weaken the one proof that currently works.

### C2 — `Effect`: the protected-boundary vocabulary

There is no `Effect` sum. There are two half-types: `Operation` (13 untargeted
verbs — `ReadFiles`, not `Read(path)`) and `SinkClass` (19 targets), joined by an
ad-hoc compatibility relation that leaves four sinks structurally unreachable.
Because `Operation` carries no payload, `subject: &str` is threaded everywhere and
re-parsed by each gate — **at least six independent parses of the same string per
`web_fetch`**.

- **Shape:** ~17 variants carrying their target, with `operation()` and
  `sink_class()` **derived**. That deletes `operation_allowed_for_sink` and the
  unreachable-sink class outright.
- **Law:** every protected boundary crossing is an `Effect` variant, and every
  handler takes `Authorized<Effect>`. The 26 independent gate sites become
  interpreters.
- **Precedent:** `Executor::run_args` takes an `Authority` **by value** (wrapping a
  sealed `DischargedBundle`) *so that an un-preflighted spawn is a compile error*,
  pinned by a `compile_fail` doctest. That trick works for one effect today; this
  generalises it to all of them. Note the same signature still carries a vestigial
  `&DecisionToken` checked only by `debug_assert` — the shape this collapse removes.

### C3 — `Permit` / `Ceiling`: linearity

21 types mean "this exceptional act may now happen"; **one** satisfies all five
properties (`DeclassificationToken`). The others are `Clone`, or passed by `&`, or
carry a `max_uses` field with zero consumers.

- **The answer is two types, not one.** `Ceiling<A>` is `Clone`, attenuable,
  time-bound — a reusable bound (`VerifiedGrant`, `PodGrant`, `AttenuationToken`).
  `Permit<A>` is affine, burn-bound, request-bound. **Conflating them is what
  produced 21 types**, and a single `Permit` would repeat the mistake.
- **Law:** a `Permit` is spent exactly once — `spend(self, …)` plus one burn ledger.
  Today there are four correct, non-interoperating burn ledgers.
- **`Action = Effect`**, which is why this follows C2.

### C4 — Authority as a product order: attenuation

`PermissionLattice` already implements `Lattice`, so `MeetCap<PermissionLattice>`
typechecks today; nothing constructs one. Ten dimensions are inside the order and
~21 are outside, enforced ad hoc.

The bug generator is visible in `create_sub_pod`: step 4 clamps `policy` through the
lattice, **4b** strips `workload` ("the delegation ceiling does not clamp it"),
**4c** clamps `credentialed_egress` ("a spec field the delegation ceiling does not
cover") — and there is no 4d. `resources`, `cgroup`, `image`, `network`,
`audit_sink`, `labels`, `work_dir` are forwarded unclamped. That enumeration *is*
the security boundary, maintained by hand, and the comment at 4b says the quiet part:
authority "must be made deliberately, not inherited from a field being added."

- **Law:** `delegate(p, r) ≼ p`, one `Attenuating` trait, one `meet`.
- **Warning from item 20:** adding a dimension to the *signed* lattice means
  certificate-hash coverage and a domain-tag bump. Budget for it; the alternative
  is an unsigned field a holder can reset, which is the hole `consumed_usd`'s
  comment already describes.

### Sequence

**C1 → C2 → C3 → C4.**

`LedgerCore<Unit>` first as the **proving run**: mechanical, self-contained, zero
live-path behaviour change, and it converts two Kani harnesses into coverage for ~20
quantities. It establishes the pattern — collapse, law, gate — on the item with the
least blast radius.

`Effect` second because it is the keystone: `Authorized<Effect>` is what makes the
reachability analysis below meaningful, and `Permit<Action>` wants `Action = Effect`.

`Authority` last, not because it matters least — it deletes the most bespoke code —
but because it has the largest surface and the most signature churn, and by then the
gates and the discipline exist.

### The capstone this unlocks

Once effect methods take `Authorized<Effect>` by value, that type **is** a dominance
proof, and a dylint pass over MIR can decide the real question:

> for every agent-reachable entry point and every protected effect, does the
> effect's gate dominate it on all paths?

failing with the concrete offending call path when an effect is reachable without
its gate, when two paths to one effect discharge different gate sets, or when a gate
is present but inert. That gate subsumes essentially every finding in items 17–30 —
and unlike the manifest in PR #2778, it is **derived**, so it cannot be incomplete
by omission. It is out of scope here and depends on C2.

## First consumer

`nucleus-tool-proxy`'s HTTP and MCP handlers. They are the pair that already
demonstrates the defect: the same effects, reached by two paths, discharging
different gate sets — the MCP path passes `None` for the request certificate where
HTTP passes `certified`, so per-request attenuation is enforced on one and silently
ignored on the other, while MCP adds a `guard.check` HTTP lacks. **Neither is a
superset of the other.** Under C2/C3 that divergence is not a bug to find; it is
un-writable.

## Consequences

**Honest scope.** This is months, across the live enforcement path. It should not
start while the merge queue is serial and contended, and each collapse should land
as its own stack with its law and gate, never as one change.

**What becomes derived.** Roughly **15–25%** of the security test surface — the
combination tests and the parity mirrors. Not more: most of the 7,033 tests encode
*content* (does this glob match, does this command pattern parse, does this
certificate verify), which is irreducible and stays.

That undersells the value. The laws catch a class the instance tests structurally
cannot, and it is the class every item in 17–30 belongs to: a correct, well-tested
pure function called with the wrong argument, or not called at all. No amount of
instance testing finds those. A totality law finds them at compile time.

**A fourth honesty tier.** `docs/PROOFS.md` separates PROVEN / TESTED / ATTESTED and
its §5 names the extraction gap ("the proven model could differ from the running
code"). The audit found a category it does not cover: **PROVEN but not on the path.**
A `wired?` column, mechanically checked, would have caught most of items 17–30.

**The `tighten` rule has a limit, learned the expensive way.** Item 24 merged two
disagreeing tables at the pointwise-strictest value and broke legitimate flows —
`flow_red_team` showed `Deterministic` and `HumanPromoted` data denied at a git sink,
which is what a verified sink exists to accept. Where two implementations disagree,
**the stricter value is not automatically the correct one**; one of them may simply
be wrong, and there it was the copy the discharge path never consulted. Merging to
one decider is right. Assuming the strict side wins is not.

## Rejected

**A monad transformer tower.** Already decided in
`docs/architecture/effect-sequencing-and-authority.md` (2026-07-26) and not reopened:
a tower flattens the two properties the design rests on — authority is *graded*, not
ambient, and one-shot tokens are *affine*, while monads duplicate. Rust's move
semantics already give at-most-once for free; a monadic re-encoding trades that away.

**Parity tests between duplicates instead of one decider.** A parity test between two
copies still leaves two copies, and makes the next drift a test failure rather than an
impossibility. Item 24 deleted the duplicate tables rather than pinning them together,
and that is the pattern.

**One `Permit` type covering all 21.** Standing ceilings and one-shot permits are
different objects; merging them is the confusion that produced the 21.

**Hand-maintained manifests as the primary mechanism.** PR #2778's law-mechanism
manifest is a stopgap: it catches what someone thought to list. It stays as a debt
ledger, not as the answer.

**Doing this instead of Tier 1.** The defects in items 17–30 are fixed on their own
merits and did not wait for any of this. A collapse is how you stop generating them;
it is not how you fix the ones already shipped.
