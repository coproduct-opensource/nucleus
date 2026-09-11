# ADR 0006 — Four collapses: the security surface is compositions of four objects, not sixty-five

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
| one-shot permit types | 21 | **0** satisfy unforgeable + non-`Clone` + request-bound + time-bound + consume-once — see C3, where that is the finding rather than a gap |
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

$$\text{Principal} \xrightarrow{\ \text{Delegation}\ } \text{Authority} \xrightarrow{\ \text{Allocation}\ } \text{Permit⟨Act⟩} \xrightarrow{\ \text{Execution}\ } \text{Receipt}$$

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
- **Gate:** E1/E2 at `Unit = u64` — but **not by parametricity**, which is what an
  earlier draft claimed. The candidates are not all `u64`/`usize`: they are `u64`,
  `usize`, `u32`, `Decimal`, `f64`, and one that stores money as a `String`. `usize`
  is not `u64` on every target, so a proof at `u64` does not transfer for free. It
  transfers via the **`Unit` trait's saturating-arithmetic laws**, which is a
  stronger claim and has to be stated and discharged rather than assumed. Writing
  those laws down is part of C1, not a follow-up.
- **Also part of C1:** `FORMAL_METHODS.md` claims budget conservation runs on every
  PR. It does not — E1/E2 sit in the nightly `kani-full` lane. They are tiny (4
  slots, `u8` symbolics, unwind 8); putting them on `kani-fast` makes the claim true
  and is the cheapest honesty fix in this ADR.
- **Do not force in:** TTLs and token buckets (replenishment is a function of
  wall-clock, so `Remaining` is not conserved), VCG budgets (a knapsack; the
  interesting theorems are truthfulness and IR), the settlement split (refund is
  *defined* as the residual, so conservation is definitional and already Lean-proved).
  Jamming these in would weaken the one proof that currently works.

### C2 — `Act`: the protected-boundary vocabulary

There is no targeted sum. There are two half-types: `Operation` (13 untargeted
verbs — `ReadFiles`, not `Read(path)`) and `SinkClass` (19 targets), joined by an
ad-hoc compatibility relation that leaves four sinks structurally unreachable.
Because `Operation` carries no payload, `subject: &str` is threaded through 47
signatures and re-parsed by each gate — **seven distinct parse implementations of
one URL per `web_fetch`**, using three different hand-rolled host extractors.

**Call it `Act`, not `Effect`.** Four things in the tree are already called some
form of effect, and one of them is at an adjacent layer of this same design:
`portcullis::EffectId` / `EffectCatalog` is ADR 0004's *open, data-driven,
human-sized* authority vocabulary that lowers to `Operation` + `SinkClass` + hosts.
This collapse introduces a *closed, typed, machine-sized* sum underneath it. They
are different objects and both are needed; reusing the name guarantees a reader
mistakes one for the other. (`nucleus-ifc-kernel::EffectKind`,
`nucleus-policy-kernel::Effect` — Permit/Forbid, a false friend — and
`portcullis_effects::EffectCall` are the other three.)

- **Shape:** ~17 variants carrying their target, with `operation()` and
  `sink_class()` **derived**. 13 × 19 gives 247 pairs of which exactly **27** are
  admissible — a number the tree already pins as `EARNABLE_PAIRS`. Deriving the
  projection replaces `operation_allowed_for_sink` and makes the unreachable-sink
  class a *derived* fact rather than a hand-written table.
- **`Act` wraps `Operation`/`SinkClass`; it does not replace them.** Both carry
  pinned `u8` discriminants with `const _` assertions "for Aeneas", are extracted
  across 12 generated Lean directories, and have 3,716 references in 147 Rust files
  including 32 exhaustive 13-arm matches. They stay as the fieldless, proof-facing
  core; `Act` is host-side and outside the extraction scope. This is the single
  decision that keeps C2 from breaking 27 Lean files.
- **Law:** every protected boundary crossing is an `Act`, and every handler takes
  the witness by value. The ~60 hardcoded `(Operation, SinkClass)` gate literals
  across six files become interpreters.
- **The witness already exists four times over, and none carries the target.**
  `CheckProof` (`guard.rs:179`) is the live MCP witness and holds only an
  `Operation`. `Authority` is affine but its scope is the untargeted pair.
  `GuardedAction<A>` is properly sealed and used nowhere outside its own module —
  `check_operation` returns `GuardedAction<Operation>` and `check_path` returns
  `GuardedAction<String>`, two proofs that are never combined. And
  `Authorized<A>` (`enforcement.rs:272`) is `Clone + Copy` with public fields and
  zero call sites, so it is both unsound as a witness and dead. C2 is largely the
  work of making one of these carry the `Act` and deleting the rest.
- **Precedent:** `Executor::run_args` takes an `Authority` **by value** (wrapping a
  sealed `DischargedBundle`) *so that an un-preflighted spawn is a compile error*,
  pinned by a `compile_fail` doctest. That trick works for one effect today; this
  generalises it to all of them. Note the same signature still carries a vestigial
  `&DecisionToken` checked only by `debug_assert` — the shape this collapse removes.

### C3 — `Ceiling` / `Permit` / `Voucher`: linearity

21 types mean "this exceptional act may now happen", and **none** satisfies all
five. An earlier draft of this ADR claimed `DeclassificationToken` did. It does
not: it derives `Clone` *and* `Serialize` (`portcullis-core/src/declassify.rs:160`),
and every apply path takes `&token`
(`kernel/declassify_authority.rs:61,89,105`; `flow_graph.rs:1442,1506`). It is
unforgeable, request-bound and time-bound, but consume-once comes from an
**external** burn ledger keyed on its signature — not from the type.

That correction is not a footnote; it is the design. The shape that token
demonstrates is *signed data plus an external ledger*, and **a permit that crosses
a process or wire boundary cannot be affine**, because Rust's move semantics do not
survive serialization. So the answer is **three** objects, not two:

| object | lives | mechanism | today |
|---|---|---|---|
| `Ceiling<A>` | anywhere | `Clone`, attenuable, time-bound — a reusable bound | `VerifiedGrant`, `PodGrant`, `AttenuationToken` |
| `Permit<A>` | one process | affine — `!Clone`, `spend(self, …)` | `Authority`, `CheckProof`, `DischargedBundle`, `ServeToken`/`VerifyToken` |
| `Voucher<A>` | across a wire | signed, externally burned; `Clone` by necessity | `DeclassificationToken`, `ApprovalToken`, `ApprovalBundleClaims` |

**Conflating any two of these is what produced 21 types**, and a single `Permit`
would repeat the mistake at a deeper level than the two-type split catches.

- **Law:** a `Permit` is spent exactly once by the type system; a `Voucher` is spent
  exactly once by one burn ledger. Today there are **five** correct,
  non-interoperating burn ledgers: the governed-release set in `FlowGraph`, two
  separate approval-nonce caches, `JtiCache`, and three one-shot `AtomicBool`s in
  the workload API.
- **`Action = Act`**, which is why this follows C2.

Two claims from the earlier draft are withdrawn. `max_uses` is **not** an unread
field — it is wired end to end (`approval_bundle.rs:136` → `main.rs:849` →
`ApprovalRegistry::{approve,consume}`, seven live call sites, and a test). The
genuinely unread fields beside it are `attestation_hash` and `drand_round`. And
`SessionCleanseToken`, despite a doc comment calling it sealed and unforgeable, is
taken by `&` at both call sites and never consumed.

### C4 — Authority as a product order: attenuation

`PermissionLattice` already implements `Lattice`, so `MeetCap<PermissionLattice>`
typechecks today; nothing constructs one. Ten dimensions are inside the order and
~21 are outside, enforced ad hoc.

The bug generator is visible in `create_sub_pod`: step 4 clamps `policy` through the
lattice, **4b** strips `workload` ("the delegation ceiling does not clamp it"),
**4c** clamps `credentialed_egress` ("a spec field the delegation ceiling does not
cover") — and there is no 4d. **Twelve** fields ride through unclamped into the
serialized child spec: `work_dir`, `timeout_seconds`, `budget_model`, `resources`,
`network`, `image`, `vsock`, `seccomp`, `cgroup`, `audit_sink`, `metadata.labels`
and `metadata.task_grant_id`. That enumeration *is* the security boundary,
maintained by hand, and the comment at 4b says the quiet part: authority "must be
made deliberately, not inherited from a field being added."

The two guards that watch it are `create_sub_pod_still_clamps_credentialed_egress`
and `create_sub_pod_always_narrows_and_reserves` — both of which **grep the
function's own source text** for the three calls. They can notice a call being
deleted. They structurally cannot notice a thirteenth field being added, which is
the only way this defect has ever actually occurred.

- **Law:** `delegate(p, r) ≼ p`, one `Attenuating` trait, one `meet`.
- **Mechanism, not vigilance:** `create_sub_pod` destructures `PodSpecInner`
  **exhaustively**, so adding a field to the spec is a compile error in the
  delegation path until someone decides what it means. That is the same move
  `EARNABLE_PAIRS` and the exact ratchets already make elsewhere: turn a thing
  somebody has to remember into a thing the compiler refuses.
- **Warning from item 20:** adding a dimension to the *signed* lattice means
  certificate-hash coverage and a domain-tag bump. Budget for it; the alternative
  is an unsigned field a holder can reset, which is the hole `consumed_usd`'s
  comment already describes.

### Sequence

**C0 → C1 → C2 → C3 → C4.**

C0 first, and it is not a collapse: the standing gates that stop the surface
growing while the rest lands. Without them, months of collapse work races new
unwired mechanisms into the tree faster than it removes them.

`LedgerCore<Unit>` next as the **proving run**: mechanical, self-contained, one
production consumer, zero live-path behaviour change. It extends two Kani harnesses
to cover every quantity that satisfies the `Unit` laws — which is the claim C1 has
to discharge rather than assume. It establishes the pattern — collapse, law, gate —
on the item with the least blast radius.

`Act` second because it is the keystone: an authorized `Act` is what makes the
reachability analysis below meaningful, and `Permit<Action>` wants `Action = Act`.

`Authority` last, not because it matters least — it deletes the most bespoke code —
but because it has the largest surface and the most signature churn, and by then the
gates and the discipline exist.

### The capstone this unlocks

Once effect methods take an authorized `Act` by value, that type **is** a dominance
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
different gate sets. `mcp.rs` never names `CertifiedPermissions` and never calls
`state.ceiling(...)`; `main.rs` does both, at six sites. The MCP guard is a
process-level `Arc<RwLock<Option<_>>>` on `AppState`, so it *structurally cannot*
carry per-request attenuation — this is not a forgotten argument but a shape that
has nowhere to put one. Meanwhile MCP adds a `guard.check` HTTP lacks.
**Neither path is a superset of the other.** Under C2/C3 that divergence is not a
bug to find; it is un-writable.

That gap is live today and does not wait for the collapse: it is the **first PR of
the C2 stack**, not its last.

## Consequences

**Honest scope.** This is months, across the live enforcement path, and each
collapse should land as its own stack with its law and gate, never as one change.

An earlier draft said it should not start while the merge queue is serial and
contended. That is the wrong constraint, and the measurement says so: the queue is
strictly serial (`max_entries_to_build: 1`) and still merged **100+ PRs in ten
days**. What actually gates throughput is per-PR size — median +150 lines on `main`,
p90 +747. So the rule is not *wait*; it is *decompose*. A collapse that arrives as
one refactor will not clear the queue no matter how quiet it is.

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

## Milestones

`C0` is not one of the four collapses. It is the standing gates that stop the
surface growing while they land — without it, months of collapse work races new
unwired mechanisms into the tree.

Each row is a stack of PRs sized to the p90 above, not a single change. Live
defects are folded into the collapse that owns the code, and sit at the **front**
of their stack rather than the end.

| # | Delivers | Folded-in defect | Status |
|---|---|---|---|
| C0.1 | `xtask` ratchet on inert authority: `_authority` / `_proof` / `_cert` bindings, seeded exact at the measured 43 of 226, with the genuine no-op impls allow-listed by path and reason | an authority accepted and dropped is a gate that is present but does nothing | proposed |
| C0.2 | Add `GuardedAction` and `Authorized<A>` to #2778's law-mechanism manifest | `Authorized<A>` is `Clone + Copy` with public fields and zero call sites — unsound *and* dead | proposed |
| C0.3 | This ADR, renumbered off #2753's 0005, with the three corrections above | the ADR's own claims about `DeclassificationToken`, `max_uses` and parametricity | **this PR** |
| C1.1 | `LedgerCore<Unit>`: `Unit` trait with stated saturating-arithmetic laws, `PhantomData`, `*_micro` → `*_units`. Drop `const fn new` (const trait methods are unstable at MSRV 1.93). Keep every `while i < N` loop and add no heap — `budget_ledger.rs` has zero `kani-divergence.toml` entries and must keep it | `LedgerError::UnrepresentableAmount` names `Decimal` but is produced only by `BudgetLedger` | proposed |
| C1.2 | E1/E2 onto the `kani-fast` lane | `FORMAL_METHODS.md` claims budget conservation runs every PR; it runs nightly | proposed |
| C1.3 | First two consumers: `BudgetGate` (already micro-USD `u64`) and `AtomicBudget` | `AtomicBudget::reserve` splits token limits by `/2` — *"Give half of remaining"* — which the ledger's law rejects | proposed |
| C2.0 | MCP path gets the per-request certificate attenuation HTTP has, or a written reason it must not | **the MCP/HTTP divergence** | proposed |
| C2.1 | The `Act` sum in `portcullis-core`, totality proved against the 27 admissible pairs | `default_sink_class` returns `SecretRead` for 3 of 13 operations — a pair `operation_allowed_for_sink` **rejects** | proposed |
| C2.2 | `CheckProof` carries the `Act`; `ToolCallGuard::check(Act)` | makes the six untargeted `guard.check(Operation::…)` MCP sites a compile error | proposed |
| C2.3 | `GuardedAction<Act>` replaces `GuardedAction<Operation>` / `<String>`; delete `Authorized<A>` | lowers `DEAD_COUNT` from C0.2 | proposed |
| C2.4 | `Authority::spend(act)`; `EffectCall` stops being `(&'static str, String)` | the `gate()` helper's `Ok(Authority::new(bundle))` re-wrap, which reopens the affine seam it just closed | proposed |
| C2.5 | Effect traits take the witness by value, one trait per PR | `run_args`'s `compile_fail` doctest fails on **arity**, so it pins nothing; `DecisionToken` is inert outside `debug_assert` (item 25) | proposed |
| C3.1 | The `Ceiling` / `Permit` / `Voucher` split; `Action = Act` | — | proposed |
| C3.2 | One burn ledger for the five that exist | `SessionCleanseToken` is taken by `&` and never consumed | proposed |
| C4.1 | `PermissionLattice` through `ProductLattice`; `Kernel::attenuate` through `MeetCap` | deletes the defensive `leq` re-check of a law the trait guarantees | proposed |
| C4.2 | `create_sub_pod` destructures `PodSpecInner` **exhaustively**, so a new field is a compile error until someone decides | **12 fields forwarded unclamped**; today's two guards grep the function's own text and structurally cannot see a field that was just added | proposed |

**The price of C4, stated in advance so it is budgeted rather than discovered.**
Adding one dimension to the *signed* lattice costs, measured from item 20's fix:
two `canonical_permissions_hash` insertions, a `meet`/`join`/`leq` triple with the
order **reversed** for consumed quantities, **two domain-tag bumps that invalidate
every outstanding certificate**, atomic cross-dimension consumption, and a rewrite
inside the required OWASP LLM Security Gauntlet context.
