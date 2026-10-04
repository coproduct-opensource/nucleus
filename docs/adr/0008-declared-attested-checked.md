# ADR 0008 — A fact is declared, attested, or checked, and a verdict is about a disk rather than a tree

- Status: **accepted** (2026-09-20) for the placement rule and the input-closure key; **not yet wired** — the keystone (binding a run's first disk) and the key change carry named targets below and a measured baseline.
- Extends: ADR 0007. 0007 makes a defect unwritable inside one process; this makes a *claim* unwritable across processes, by removing the tier a claim can be made in without evidence.
- Applies to: every fact a gate verdict rests on, in `coproduct-opensource/nucleus` and `coproduct-private/gatehouse`. gatehouse has no ADR series; its half lands as an A-n row plus `docs/declared-attested-checked.md`.

## Context

Eleven open `architecture-decision` issues look like eleven problems. They are one
problem at eleven layers: **a claim that outruns its wiring.** `theorem f_ok : True :=
trivial` passes a proof gate. The jailer/seccomp/netns boundary is enforced by tests
naming it. Bids self-report. Eval ranks on wall-clock nobody can re-derive. Three
"verified" constructors rest on Rust module privacy. And the box that gates every merge
had no declared provenance at all — `lima.yaml` has zero provision lines, which is how a
rebuild nearly became archaeology on 2026-09-19.

Fixing them one at a time means eleven designs. What they need is one rule about *where a
fact is allowed to live*.

### The rule already exists in miniature

`prelude/ci.writ` states it for one case. `Policy` is what an operator **decides** and
cannot be wrong. `Deployment` is what the executor **measured** and can be wrong. The
kernel checks one against the other. Eleven `Policy` fields were moved to `Deployment` on
exactly that test.

Generalised:

1. **Declared** — in writ, by an operator. The kernel can decide it. Wrong only if the
   operator is wrong, never because the machine changed.
2. **Attested** — by the component that measured it, signed. The kernel cannot derive it.
3. **Checked** — the kernel holds a declaration against an attestation. **This is the only
   tier that produces a verdict.**

> **Placement rule: if a fact can be wrong because the machine changed, it is attested,
> not declared.**

A fact asserted in a document, a test name, or a Rust constant is in **no** tier. That is
the defect this ADR names, and every one of the eleven issues is an instance of it.

## What the tiers cost when they are confused, measured

Measured 2026-09-20 on 400 first-parent commits to `nucleus` main (2026-08-31 → 09-20),
selecting each gate's declared scope with `gatehouse_scope`'s own matcher and hashing the
`(path, blob-oid)` list — the faithful analogue of `scope_hash`.

| gate | files in scope (of 2093) | wall | hit rate | runs today |
|---|---|---|---|---|
| `text-gates` | 1694 | ~120 s | 5.8% | 399 |
| `fmt` | 1537 | ~60 s | 25.6% | 399 |
| `clippy` | 1541 | ~900 s | 25.3% | 399 |
| `test-core` | **2093 — declares `**`** | ~1200 s | **0.3%** | 399 |
| `lean-build` | **0 — scope unparseable (F-160)** | ~420 s | **0%** | 399 |
| `ci-spec` | 1639 | ~90 s | 6.5% | 399 |

**Keying verdicts on scope instead of the tree is worth 9.3% on this plan, and that is the
whole point.** The cache is nearly worthless, and not because caching is the wrong idea:

* `test-core` declares `**`, costs the most, and therefore can never be skipped. Given the
  scope `clippy` already declares, the same gate hits **25.6%** instead of 0.3% — worth about
  11 points on its own, because it is the 1200-second gate.
* `lean-build` declares `crates/portcullis-core/lean/*.lean`, which the scope engine refuses
  to parse, so it has no scope hash and is uncacheable by construction (F-160).
* `ci-spec` and `text-gates` reach `crates/**`, so any crate edit fires them.

> The ceiling on this whole class of optimization is set by how honestly a gate says what it
> reads. `docs/efficiency-floor.md` said so on 2026-09-18 and the number now says it twice.

So the order is **narrow the scopes, then key on the closure** — not the reverse. Wall-clock
figures are lane estimates, not instrumented measurements; the hit rates are exact.

An earlier draft of this ADR quoted 37.2% from a `.gatehouse/pipeline.writ` four commits
stale, before #2971 narrowed `text-gates` and before `test-core` widened to `**`. It is
corrected here rather than quietly dropped, because the stale figure also passed a
cross-check against `gatehouse/scripts/scope-locality.sh` — both tools read the same stale
file, so the agreement confirmed the matcher and said nothing about the scopes.

## Why `test-core` declares `**`, measured rather than assumed

Narrowing it looked like a judgment call about what `nextest` reads. It is not; it is two
specific causes, and censusing the real read sites found both.

**Cause 1 — `crates/xtask` is in the gate.** Eighteen of the twenty-six files that read outside
their own crate are xtask's: `pipefail`, `push_auth`, `pin_parity`, `self_pin`, `gatehouse_pin`,
`workspace_members`, `action_inputs`, `gate_budget`, `coverage_floor`. They read `.github/**`,
`Cargo.toml` and `.line-ratchet.toml` **by design** — auditing the repository is their job. They
are **331 of 7234 tests, 4.6%**, and they hold the most expensive gate in the lane at `**`.

**Cause 2 — two product tests reach out of the tree.** `nucleus-task-compiler`'s
`goal_corpus.rs` reads `.github/workflows`, and `nucleus-node`'s `olog.rs` reads
`docs/olog/pod-snapshot-reuse.md`.

Measured over the same 400 commits, with xtask split out:

| `test-core` scope | hit rate |
|---|---|
| today, `**` | 0.3% |
| honest, **including** `.github/workflows/**` and `docs/olog/**` | **7.3%** |
| honest, **without** them | **25.1%** |

**Those two files cost eighteen points on the 1200-second gate**, because `.github/workflows/**`
is edited constantly — it is in `text-gates`'s and `ci-spec`'s scopes for that reason. The tests
are not wrong; they are repo-auditing tests living in product crates, and they belong with
xtask's, not in the product's test gate. This is a gate-topology change, not a test deletion.

With that and F-160 (gatehouse#92, which takes `lean-build` from uncacheable to **95.2%**):

> **9.3% → 34.3%. 309 gate-hours over 400 commits become 203.**

One caution the census earns. `crates/nucleus-action-key/src/escapes` contains `include_str!`
and `include_bytes!` spellings — including `"../../../../../etc/passwd"` — that are **string
literals under analysis**, not reads: its whole subject is where a crate's read set escapes.
A census that counted them would have widened the scope to the thing it was trying to shrink.

## Decision

### 1. The three tiers and the placement rule, as stated above.

### 2. A verdict is keyed by the run's INPUT CLOSURE, not by the tree.

The input closure is the content the run could have read. In a Firecracker pod that is,
to a first approximation, **the disk it started on** — and the lane already computes that
digest. `cache.json` carries `parent_scratch_sha256`, `sealed.json` carries
`sealed_scratch_sha256`, and `verify_gate_sequence` already refuses a step that did not
start from the disk the previous step left.

Six mechanisms are digests of things placed on that disk, each with its own binding rule
today:

| mechanism | what it digests |
|---|---|
| `scope` / `scope_hash` | tree files the patterns select |
| `env` | the image |
| `seeds` | a restored disk |
| `gate_tools_image` | the tools |
| `Recipe` (`sha256(to_vec(&recipe))`) | how the image was built |
| `Scope.externals` | named things outside the tree |

They are one object observed six times. Keying on the closure collapses them.

The closure is not *only* the disk, and this ADR does not pretend otherwise: environment,
clock, entropy and the mediator are also inputs. nucleus already attests the tractable
ones — `environment_inputs_sha256`, `environment_complete_sha256`, `launch_hash`,
`program_digest`. So the closure is a small tuple of already-attested digests hashed
together. It is still one number.

### 3. Bindings split into two kinds, and only one of them collapses.

`verify_receipt` today checks `gate_def`, `scope`, `env`, `tree`, `plan` in one chain, as
though they were the same kind of fact. They are not:

- **what the run consumed** — `scope`, `env`, `tree`, the probes. Collapses to one digest
  equality.
- **who authorized and signed it** — `plan`, `class`/tier floor, the trust window, log
  inclusion. Stays, and should.

That `tree` and `plan` sit adjacent in one conditional is why the tree binding was ever
load-bearing. They answer different questions.

### 4. Confinement is structural, not probed.

`FsProbe` exists to answer "could the command read outside its scope?" It is the right
question for the **runner** lane, where *"the source repository is on the same filesystem
— the runner just opened it."* It is the wrong question for a microVM: the nucleus lane
materializes **the scope's selection** into the pod, so a file outside the scope is not
denied, it is *absent*.

A canary probe in that lane would therefore pass because the path does not exist, and
report `Denied` having measured nothing. That is F-37's shape — *a conjunct that always
answers `true` is indistinguishable from one that works* — and it was designed and
discarded on 2026-09-20 for exactly that reason. It is recorded here because the next
person to reach for a probe should find the reason it was rejected, not the idea.

Under an input-closure key the question has no content: the disk is the world. Confinement
moves from an in-band runtime attestation to **unwritable**, which is the top of the
ladder ADR 0007 climbs.

### 5. Over-broad scopes become a performance bug, not a security bug.

Today an under-declared scope is a soundness hole: reuse a verdict that depended on bytes
the hash did not cover. The matcher's correctness is therefore a **trusted** property, and
it is subtle — `subsetGlob` is syntactic, so `**` subsumes only `**`.

Under a closure key the patterns decide *what the executor puts on the disk*, and the
disk's digest is what is checked. An under-declared scope becomes impossible — the disk
has what it has. An over-broad one costs cache hits and nothing else.

This is the largest consequence in the ADR, and it is what reduces the trusted base:

    gatehouse-scope leaves the TCB because the verifier stops reasoning about patterns.

`assurance/verifier-tcb.txt`, 2026-09-10: 5691 lines, of which `gatehouse-verify` is 478
and `gatehouse-scope` is 345. That file already names the deduplication half of this
("gatehouse-verify and gatehouse-scope leave when the certificate the kernel checks
becomes the decision rather than a parallel artifact"). This ADR supplies the other half:
shrinking what the certificate has to say. `prelude/verify.writ` keeps *one witness per
bound field*, so fewer bound fields is also less kernel.

## The keystone, named exactly

`verify_gate_sequence` in `crates/gatehouse-verify/src/nucleus.rs`:

```rust
match (index, &step.started_from, &previous_sealed) {
    (0, _, _) => {}                      // step 0: anything, including None
    (_, Some(started), Some(sealed)) if started == sealed => {}
    ...
}
```

**Step 0's disk is unchecked.** The lane proves every step continued the last one's disk
and never proves what the first disk was. That single arm is the difference between "a
chain of custody" and "a chain of custody starting from somewhere". Bind it to the
declared closure and the argument closes.

## Consequences

**Wired now:** `expectation_for` derives `scope_bound` from `Provenance::may_cross_trees()`
instead of hardcoding `false`, so an ASSERTED scope hash can never cross trees. This
changes no verdict today and is deliberately a no-op: `treeBindingMet_b` also requires
confinement, and the nucleus lane reports `FsProbe::Skipped`.

**Named targets, in cheapest-first order:**

1. **Narrow the over-broad scopes — this is the prerequisite, not the garnish.** `test-core`
   declares `**`; giving it the scope `clippy` already declares takes it from 0.3% to 25.6%
   on the most expensive gate in the lane. Pure efficiency, no TCB, unblocked. The writ `Gate`
   tuple has a single include list while the Rust `Scope` already has `exclude`
   ("excludes win, so a scope can never be widened by adding one") — the kernel checks a
   strictly less expressive type than the code implements. Of the 291 commits where the
   Rust gates fire, 36 (12.4%) changed no `.rs`/`.toml`/`.lock` file at all.
2. **Bind step 0's disk** to the declared closure.
3. **Key the verdict on the closure**, retiring the tree binding, `scope_bound` and the
   fs probe together.
4. **Then** `gatehouse-verify` and `gatehouse-scope` leave the TCB, against a much smaller
   certificate than they would otherwise have had to check.

**What this does not fix.** The executor still builds the disk. It is not trusted so much
as *audited*: reproducible builds let anyone recompute the digest, and the `refutations`
table already samples a hit against a re-run and quarantines a signer whose verdict
disagrees. That makes bit-reproducible image builds **load-bearing rather than a nicety** —
content-addressing without reproducibility is a cache nobody can audit.

And a gate that is not a function of its closure — a flaky test — stays broken. But it
acquires a number: **the refutation rate measures exactly how non-functional the gate
population is.** That mechanism is already built and currently has nothing to measure,
because cross-tree hits never happen.

## The eleven, re-scoped

Each stops needing its own design and becomes a placement question this ADR answers:

| issue | the fact, and where it belongs |
|---|---|
| #2556 / #2585 | "has a proof" → **attested** by a checker, with an anti-vacuity obligation |
| #2558 | the Firecracker boundary → **declared** in Rust's type system (a linear `PodResources`) |
| #2427 / #2484 | auth tiers, live compartment → **declared** ceiling, **checked** against use |
| #2501 | bids → **attested** certificate budget; the self-reported header path is deleted |
| #2496 / #2545 | eval work → **checked** by recompute, never wall-clock |
| #2452 | three `verified` constructors → **checked** by extraction, not module privacy |
| the image | the recipe → **declared** in writ, **attested** digest, **checked** by the kernel |

#2609 (Flux refinement) stays blocked on #2572 and is unaffected.
