# A command grammar for nucleus

Draft, 2026-09-15. What an operator may type, the authority it demands, and the
laws relating the two — written after measuring that the demand is currently
written nowhere, so the sections that matter most are the ones listing laws that
do **not** hold and where the grammar would be decoration.

The thesis in one line: **a command's required authority should be an index on
its grammar term, derivable by structural recursion, not attached by
convention.**

## What this is written against

Three facts, each re-derivable from the cited files rather than asserted.

**1. No operator command touches the permission vocabulary.**
`grep -rn "Act::\|preflight_action" crates/nucleus-cli/src/` returns **zero**
lines. `preflight_action` has call sites in `portcullis-effects/src/runtime.rs`,
`portcullis/src/kernel.rs` and `nucleus-tool-proxy/src/run_gate.rs`, and none in
the CLI. The CLI imports `PermissionLattice` in six files, but only to construct
policy *for the guest*. Every one of the CLI's 51 leaves has its own authority
decided by nothing.

**2. The two halves of `verify` sit at opposite ends of the authority order, at
the same nesting depth.** `crates/nucleus-cli/src/verify.rs` (1357 lines) boots a
Firecracker pod, downloads pinned artifacts, and re-invokes itself inside a Lima
VM. `manifest verify`, `identity verify`, `token verify`, `envelope-verify`,
`verify-attestation` and `lineage-verify-chain` read a file and compare bytes to
a key. Same word. One is the most authority-demanding command in the tree; six
are the least. Counted 2026-09-15: **7 verification entry points**, 4 of them
top-level.

**3. Exit status is not a contract.** `main()` (`nucleus-cli/src/main.rs`) returns
`anyhow::Result<()>`, so a missing file, a malformed JWT and a genuine policy
violation all leave the process with status 1. Beside it, `goal.rs:49` defines
`EXIT_NEEDS_CONFIRMATION = 2` — while `crates/ci-spec/src/lib.rs:26-32` already
documents the repository's contract, *"`0` clean, `1` a violation, `2` could not
look … Reporting 'we could not look' as a pass is the exact vacuity the
invariants exist to find"*, with `Report::exit_code` implementing it. **Two
meanings for 2 in one binary family**, and the CLI uses neither.

Fact 1 is the thesis. The grammar exists to make facts 2 and 3 derivable
consequences rather than matters of taste.

## Sorts

```
Act        := portcullis_core::Act            -- act.rs:330, 13 variants
Operation  := nucleus_ifc_kernel::Operation   -- ifc_ops.rs:23
SinkClass  := nucleus_ifc_kernel::SinkClass   -- ifc_ops.rs:220, 19 variants
Band       := Observe | Emit | Reach
Authority  := the PermissionLattice, ordered by ≼
Evidence   := DischargedBundle                -- nucleus-ifc-kernel/src/discharge.rs
Cmd        := atom(Act) | skip | Cmd ; Cmd | Cmd +_b Cmd
Refusal    := a named reason, never a silent fallback
```

Only `Cmd` and `Band` are new, and `Band` is a two-bit projection of predicates
that already exist. Everything else is already proven about; the grammar's job is
to reach it, not replace it.

**Which `SinkClass`.** There are two, and picking the wrong one silently defeats
the whole design. `portcullis_core::manifest::SinkClass` (`manifest.rs:41`) has
five variants and is a *tool-manifest self-declaration* — its own header says it
is "NOT yet wired into the MCP mediation layer or `Kernel::decide()`" and that "a
malicious tool can lie". `nucleus_ifc_kernel::SinkClass` (`ifc_ops.rs:220`) has
19 and is what `Act::sink_class()` returns and what the kernel gates on. **The
grammar indexes on the kernel's.** An earlier draft of this document used the
manifest's, which would have indexed authority on self-declarations — the exact
failure the seal discipline exists to prevent, one layer up.

## Operations

```
req  : Cmd → Authority        structural recursion, total
band : Cmd → Band             the coarse projection that names commands

req(skip)      = ⊥
req(atom(a))   = least lattice element admitting a
req(p ; q)     = req(p) ⊔ req(q)
req(p +_b q)   = req(p) ⊔ req(q)              join, not meet — see C2

band(c) = Reach   if some atom's Operation::is_exfiltration_vector()
        = Emit    else if some atom's Operation::is_mutation()
        = Observe otherwise
```

Both band predicates are existing sealed-trait methods (`ifc_ops.rs:96`, `:103`),
so `band` is a fold over things the kernel already computes.

`+_b` is GKAT's *predicate-guarded* choice rather than KAT's unrestricted union.
The one real instance in the tree is `verify.rs`'s `--here` flag, which guards on
"am I already inside the Lima VM" and either delegates into a VM or runs locally
— `p +_b q` written by hand.

**Guarded iteration is deliberately absent, and its absence is a decision rather
than a backlog.** Nothing in the surface loops over a permission test. The cheap
argument stops there — an operator with no inhabitants is decoration — but this
repository can make the stronger one, because it has mechanized both sides of the
line. `crates/portcullis-core/lean/` holds **23 `Gkat*.lean` files, ~5600
lines**, in the *proven* tier. That is a checked status, not a label: all 23 are
on the `lake build` list of `.github/workflows/portcullis-core-proven-lean.yml`,
and none appears between the `GATE-ALLOWLIST` markers in
`crates/portcullis-core/lean/CONJECTURES.md` — the research tier, the only place
a `sorry` is permitted. Read against that body, the line between the loop-free
fragment and the loop is not taste:

- **Loop-free sits inside the proved region.** `GkatKleeneProofs.lean:995`
  (`acyclic_expressible`) synthesizes an expression for every acyclic automaton
  via `buildSol` — in the file's own words, *"with no `wh`, no fixpoint, no
  UA"* — and `:1007` (`acyclic_flat_expressible`) discharges even the assumed
  rank, deriving strict descent across every live edge from acyclicity via the
  SCC rank `reachCount`.
- **The loop is where the open questions are.** `wh` is a *unique* fixed point
  only under a guardedness side condition, and completeness is open —
  `docs/theory/gkat-fixed-point.md`, with the inexpressibility frontier in
  `docs/theory/gkat-inexpressibility-plan.md`.

So the fragment proposed here is the fragment whose expressibility this
repository has already machine-checked, and the operator it omits is the one
carrying every caveat. That is a better reason than "nothing loops today", and
it is the reason worth recording.

## Laws that hold

**C1 — `req` is a monoid homomorphism.** `(Cmd, ;, skip) → (Authority, ⊔, ⊥)`.
This is what makes "authority is derivable, not declared" operational: a
composite's requirement is computed by a fold, never re-declared. It is the
command-surface image of the narrowing at
`cert_bridge::intersect_grant_with_certificate`, which is a meet — authority
narrows as it delegates downward and joins as commands compose upward, the same
fact from two ends.

**C2 — a guard demands the join, not the branch taken.** The operator must hold
authority for the branch *not* taken, because `b` is evaluated at run time
against host state the grantor could not see. A grant covering only the taken
branch would be issued against a fact nobody checked. This is the CLI analogue of
the kernel's own fail-closed rule: `WithinDelegationCeiling` denies when *either*
the ceiling or the requested level is absent, rather than assuming the favourable
case.

**C3 — an atom's demand is a total function of its `Act`, computed in one
place.** No flag, no config file, no environment variable may enter. `Act`
already carries its target structurally rather than as a re-parsed string, so
`req(atom(a))` has everything it needs from `a`.

**C4 — `band` factors through `(Operation, SinkClass)`** and does not see the
path, the argv or the pattern. Both projections are exhaustive matches over enums
deliberately not `#[non_exhaustive]`, so a new verb is a compile error
everywhere. Consequence: **the head word of a command is a function of its band**,
and that is mechanically checkable.

**C5 — authority composes; evidence does not.** `req(p;q) = req(p) ⊔ req(q)` does
**not** license one `DischargedBundle` for both atoms. A bundle binds the
operation, sink class *and subject* it was minted for, because without that
binding "a bundle earned for a workspace write was structurally usable to
authorise a shell spawn" — the confused deputy, in the tree's own words. ADR
0007's load-bearing example `f7f9719b` is exactly this failure.

## Laws that do NOT hold, with evidence

**¬A1 — `req` is not sound in the presence of `Act::Run`.** `Run { argv }`
projects to `SinkClass::BashExec`, and the kernel's own documentation says why
that is a lower bound rather than a classification: *"a single operation can map
to different sink classes depending on context"* (`ifc_ops.rs:206-212`). A shell
command reaches any sink. `verify.rs` is the worst case: it shells out **and
re-invokes itself inside a VM**, so the acts the term performs are an inner
process's, invisible to the outer term. Therefore: **a term containing `Run` with
non-literal argv has no derived band and is assigned `Reach` by fiat.**
`CommandLattice` (`portcullis/src/command.rs`) narrows this for literal argvs and
is the only path to deriving rather than asserting — but it decides a *grant*,
not a classification, and it does not follow a subprocess. This is the largest
hole and this document does not close it.

**¬A2 — `req` is not the meet on choice, and `+_b` is not a lattice operation on
terms.** Two tempting errors. "You only need authority for the branch you take"
is false whenever the guard reads state the grantor did not fix — `verify --here`
is the live counterexample, where a grant issued on macOS would silently cover
the Linux branch's pod boot. And there is no order on `Cmd` at all: `⊔` above is
the join on `Authority`, not on terms.

**¬A3 — term equality is not observational equality, and two in-house theorems
say a rewriter may not pretend otherwise.** GKAT's equational theory is over
*uninterpreted* actions. Atoms here are not pure: `Write{path}` twice leaves a
different world than once if anything appends or rotates. So `p ; p ≡ p` does not
hold and **the algebra may not justify de-duplication, caching, or skipping a
step.** This is where it differs from build-ops, whose L1 *does* license `admit`
answering one request with another's evidence.

Two proved results push this past an argument from prudence, and each refutes a
rewrite an optimizer reaches for first:

- **A prefix may not be pushed past a guard.**
  `GkatGuardedStringProofs.lean:509` (`left_distrib_not_gkat_theorem`) proves
  `p·(1 +_c 0) ≢ (p·1) +_c (p·0)`, from a two-atom countermodel at `:484`: on the
  left the guard `c` is read at the *end* atom, on the right at the *start*. A
  guard reads the state the prefix just changed. Here that is `verify --here`,
  which guards on "am I already inside the VM" — hoisting any step across that
  guard changes the world the guard sees. C2 is this fact stated forward; this is
  its proof.
- **A precondition is not a test.** `GkatObservationProofs.lean:113`
  (`wp_not_definable`) exhibits a weakest precondition that no GKAT test denotes,
  because it splits two observationally equivalent states. "Compute what this
  command would need and fold it into the guard" is therefore not expressible in
  general — and that is exactly the shape of a `req`-aware optimizer.

**¬A4 — the band does not bound the blast radius.** `Observe` contains both "read
a tool manifest" and "read a private key": `SinkClass::SecretRead` is a read,
hence `Observe`, and it is the most dangerous read in the enum. Separating those
is `PathLattice`'s job. The band does not do it and must not be described as
doing it.

**¬A5 — `requires` is not injective, and cannot generate the taxonomy.** Distinct
commands legitimately share a requirement: `manifest verify` and `token verify`
both need nothing. So `req` is a **refutation test** — it can show a grouping
conflates different requirements, and cannot produce the right grouping. The
consequences below use it only that way.

**¬A6 — the grammar does not detect a lying manifest.** `manifest.rs:56-59`
already concedes that a `ToolManifest` is self-declared and that catching a lie
needs runtime behavioural verification which does not exist. The grammar inherits
that hole; it neither widens nor closes it.

**¬A7 — exit codes do not form the lattice the verdicts do.** A process returns
one byte, so the verdict must project onto a chain and the projection is lossy.
The measured instance is next door: gatehouse's `assure all`
(`crates/xtask/src/main.rs:71`) computes `if codes.iter().any(|c| *c != SUCCESS)
{ 1 }`, so seven clean gates plus one that *could not look* reports **1
(violation)** — contradicting the contract documented four lines above it in the
same file. Found by writing this law down.

**¬A8 — a set of guarded strings is not a command denotation.** The tempting
shortcut is to model a command by the traces it admits and compare sets. Two
proved results say that map is not onto. `GkatCoequationProofs.lean:228`
(`W_not_subset_den`) exhibits a behavior in the nesting coequation `W` that no
expression denotes — it both halts and steps at one atom, which an expression
cannot do — so the characterization holds only over *deterministic* behaviors.
And `:338` (`halt_not_bexp_not_den`) shows expressibility forces the halt-set to
be `BExp`-definable, so a behavior halting on a non-definable set of atoms is
denoted by nothing at all. The consequence for this document is concrete:
**`req` is defined on terms, never on trace sets.** A trace set has no term to
recurse on, and may correspond to no term.

## What the grammar should refuse to express

- A command whose `req` is declared rather than derived. If it cannot be computed
  from the term, the term is wrong.
- One verb spanning two bands. See below.
- **A flag that changes a term's band.** A band is a property of the command; a
  flag that moves it means two commands share a name. Live instances: `xtask
  bound --measure`, `xtask scorecard --measure`, `xtask action-inputs --network`
  (`Observe` vs `Reach`), and `nucleus verify --print-pins` versus `verify
  --tier2` — one prints JSON and exits, the other boots a VM.
- A command configured entirely by environment, whose authority cannot be read
  off any term.

## Consequences for the command surface

An algebra with no consequence for the 51 leaves would be decoration.

**The seven verification entry points split by band, not by taste.** Criterion:
`req = ⊥` or not. The six document checkers — `manifest verify`, `identity
verify`, `token verify`, `envelope-verify`, `verify-attestation`,
`lineage-verify-chain` — read a file and compare bytes: same band, same exit
contract, same shape. They are **one verb with six objects**. The seventh,
`nucleus verify --tier2`, boots a pod: band `Reach`, and it is not `verify` at
all — it is a self-test, and should say so.

**`xtask`'s 31 flat commands take a namespace, but not one.** Most decide from
committed files alone (`assure`); some report a number and cannot fail on content
(`measure`); a few touch an endpoint — `ci-otel` POSTs OTLP, `schedule-liveness`
shells to `gh api` (`reach`). A single `assure` namespace would be wrong here even
though gatehouse's ten fit under one, because nucleus's set is band-heterogeneous
and gatehouse's is not.

**One exit contract, and it already exists.** Adopt `ci-spec`'s `0` clean, `1`
violation, `2` could not look verbatim rather than restating it — the repository
wrote this contract down and implemented it in `Report::exit_code`, and the CLI
simply does not use it. `goal.rs`'s `EXIT_NEEDS_CONFIRMATION = 2` means "deferred
to a human", which is a third thing and needs its own code.

**The command surface earns a `STABILITY.md` row** once the grammar is applied,
not before. `STABILITY.md` freezes four action vocabularies — the 12 `Operation`
variants, `ExposureLabel`, `CapabilityLevel`, and the MCP tools — and says
nothing about commands. Freezing 51 leaves the grammar is about to rename would
freeze the mess.

## Enforcement

Per ADR 0007 every rule names its tier, so "review" reads as a gap rather than as
coverage.

| rule | tier |
|---|---|
| every leaf declares a band; the declaration is total in both directions | **`cargo xtask command-grammar`** |
| no head word collides with a `SinkClass` wire name | **review** — see below |
| C1, C2, C3 | review |
| C4 head-word ↔ band | review until each leaf declares its `Act`s; then the same gate |
| C5 (evidence is affine, subject-bound) | already a type — `DischargedBundle` is `!Clone` behind a private `Seal` |
| ¬A1, ¬A2 | **review, permanently.** No mechanism can see that a guard reads unconstrained host state, or follow a subprocess |
| exit contract | review until a gate reads the arms |

**The mechanised row checks totality, not correctness.** A leaf declared
`observe` that boots a VM passes. Stating that is the difference between a gate
and a comment — `FINDINGS.md` F-52, where a pin nothing read was described for a
week as a control. The property it does establish is exactly: *the surface cannot
grow a command whose authority nobody wrote down.*

**A-19, measured 2026-09-15**, both directions on the real defect rather than a
synthetic one:

| perturbation | result |
|---|---|
| add a CLI leaf with no table entry | exit **1**, naming `nucleus exfiltrate` |
| add a table entry naming no command | exit **1**, naming the stale entry |
| remove the table | exit **2** — could not look, never a pass (unit test) |
| restore | exit **0**, 52 leaves |

**The sink-name rule is review-tier because a gate for it would be vacuous.**
`SinkClass` carries `#[serde(rename_all = "snake_case")]` and all 19 variants are
compound — `workspace_write`, `bash_exec`, `secret_read` — while every head word
is a single token. The check cannot fire today or plausibly ever, and a gate that
only ever passes proves nothing. Writing it would have bought a green light for
free, which is the failure mode this repository spends the most effort hunting.

**"xtask" is a fourth tier ADR 0007's table does not list**, though the
repository runs 32 of them and `CLAUDE.md` mandates them. If this design is
adopted, that table should gain the row rather than this document pretending the
gate is a dylint.

## Relation to gatehouse's build-ops algebra

Siblings, not overlapping. `gatehouse/docs/build-ops-algebra.md` factors *what is
being built* — `Spec × Tree × Scratch`, with `Prog` as identity. This factors
*who may ask* — `Act → Cmd → Authority`, with `req` as index.

They meet at one arrow: build-ops' `run : Build → Result + Refusal` is, here, a
single atom of band `Reach`, and its `Refusal` is the same object as a hard-gate
refusal. A build controller invoking nucleus is an operator.

One difference worth naming rather than smoothing: build-ops' L1 licenses
substituting one result's evidence for another's when keys match. ¬A3 and C5 both
forbid the analogous move. **Authority is not a cache.**

## What this does not claim

- **It does not claim the kernel enforces the CLI.** Measured: zero `Act::` and
  zero `preflight_action` call sites under `crates/nucleus-cli/`. This grammar
  makes authority *derivable and stated*; it does not make it *decided*. Wiring
  `preflight_action` into operator commands is a separate change with its own
  unanswered question — whose grant does an operator at a terminal hold.
- **It does not claim a decision procedure, or completeness.** These are the two
  things a reader would assume from the name, and neither is available. There is
  decidable **membership** — `GkatDecisionProofs.lean:44` (`den_run`) turns "does
  `⟦e⟧` accept `(a,w)`?" into following a deterministic derivative run — but
  **no assembled decision procedure for equivalence**: that file's own header
  calls bounding emptiness and equivalence by the finiteness of `derivs e` *"the
  remaining engineering"*, and no `Decidable (⟦e⟧ = ⟦f⟧)` instance is written.
  GKAT **equational** completeness is likewise neither proved here nor assumed
  here; what is proved is the coalgebraic bisimulation characterization, in both
  directions. `req` is a fold, not a solver, so nothing here needs either — but
  "we use GKAT" must not be read as "equivalence is decided for us".
- **It does not claim the Lean development is wired to anything.** Measured
  2026-09-15: `grep -rn "Gkat\|GKAT\|guarded_string" crates --include='*.rs'`
  returns **zero** lines. The proofs and the Rust tree do not touch. This
  document proposes a grammar *shaped by* the proved fragment; it proposes no
  extraction path from one to the other, and contains none.
- **No proof.** There is no Lean or Kani artifact behind C1–C5.
- **No migration.** This decides the shape; renaming 51 leaves is a breaking
  change to a public-but-unfrozen surface and needs its own compatibility call.
- **Nothing about the ~26 leaves in adjacent binaries** (`nucleus-audit`,
  `nucleus-perf`, `nucleus-trust-registry`, `nucleus-mcp-guard`), which overlap
  the CLI's nouns and need the same treatment.
- **It does not reduce risk; it reduces ambiguity.** No command becomes safer
  because it is renamed. What changes is that a reader can tell, from the head
  word, whether the thing is about to boot a microVM.

## Where this would be decoration

Stated plainly, because the alternative is shipping a type with no inhabitants.

Every one of the 51 leaves today is either a single atom or an opaque `Run`.
There are **no composite commands written in Rust** — the compositions live in
shell and in `verify.rs`'s self-re-invocation. So `;` and `+_b` would be
operators with nothing to operate on. They are written down here because the
sorts need them to be coherent; they should be *constructed* the day the first
composite command is written in Rust, and not before.

This is a statement about CLI leaves, not about nucleus. The node API and the
guest’s vsock protocol are used as sequences, and their laws are sequencing
laws — one-shot absorption, cancel absorption, personalisation before snapshot.
Those are the subject of [`command-walk.md`](command-walk.md), which checks them
by a random walk against a model.

What is load-bearing today, and is the whole of v1: each leaf declares its band;
one gate checks that declaration is total in both directions; the exit contract
is adopted from `ci-spec`; and the renames above follow. The head-word/sink-name
rule is *not* in that gate — it is review-tier, for the reason given under
Enforcement.
