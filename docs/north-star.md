# Nucleus North Star

## Vision

**Nucleus makes "agent jailbreak → silent damage" provably impossible by
construction, while remaining frictionless enough that small dev teams adopt it
like a linter.**

> Assume the agent is compromised. Constrain what it can do anyway.
> Prove the constraints hold.

## Flagship Safety Claim

**No external side effect occurs unless it is mediated by Nucleus and authorized
by a policy that can only stay the same or tighten during execution.**

Corollaries:

- **No exfiltration without an explicit sink capability.**
- **No "talk your way into more permissions" mid-run.**
- **No untrusted content reaching a sink without an approval/declassification gate.**

This is the apodictic core — logically compelled, machine-checkable, marketable.

### The Confidentiality Dual

The claim above is about **authority**: what a workload may *do*. Its dual is
about **confidentiality**: what a workload may *learn*. Both are needed, because
a tenant's first question is not "can this agent act" but "can another tenant's
agent read my secrets."

**Whatever an agent workload does — including when an adversary controls the
inputs feeding it — it can neither learn the secrets Nucleus holds on its behalf
nor those of any other pod, nor influence which of them get released; the sole
exception is a value a governor deliberately released with a single-use token,
and even then the adversary cannot steer which value that is. This covers
explicit flows through every mediated channel and excludes timing, cache, and
other microarchitectural channels, and excludes availability and
resource-contention channels such as a bounded pod pool; it is a theorem about
the code that ships, re-checked on every change, and a relying party can verify
from the outside that the pod they are talking to is the artifact the theorem is
about.**

The exclusions are **inside the sentence, not a footnote**, so the claim cannot
be quoted without its limits. Cross-pod confidentiality stated without them would
read as "immune to co-tenancy attacks" — the worst overclaim available to this
project, and one we have no basis for: Firecracker, the host kernel, and the
hardware are all in the TCB and none of them is modelled.

The **resource-contention** exclusion was added after the fact, and it is worth
saying why rather than letting it look like it was always there. The first
version excluded only timing, cache, and microarchitectural channels. Working
through the host state field by field (`cross-pod-view.md`) turned up
`firecracker_pool`: a bounded semaphore that pod spawn acquires with
`acquire_owned().await`. It **blocks**, so one tenant's pod delays another's, and
that channel is macroscopic and reliable — not microarchitectural at all. Under
the original wording a careful reader would have concluded the claim covered it,
and that the claim was false. It was. Possibilistic noninterference over values
conventionally says nothing about availability; the fix is to say so out loud,
which is what this sentence now does.

#### Status — what is proved, what is tested, what is not yet

Keeping these apart is a house rule, because a north star written in the present
tense is how a claim outruns its wiring. This table is a **machine-checked
ledger** (`scripts/check-north-star-ledger.sh`, run on every change): each row
names a clause of the sentence verbatim, carries exactly one status from
{PROVED, TESTED, NOT-YET}, an evidence handle CI can dereference, and the gate
that reds if the status regresses. The row count and the NOT-YET count are
pinned (`scripts/north-star-ledger-ratchet.txt`) — deleting a row or demoting a
status is a visible event, not an edit.

| # | Clause (verbatim from the sentence) | Status | Evidence | Falsified by |
| --- | --- | --- | --- | --- |
| C1 | "learn the secrets Nucleus holds on its behalf" | PROVED | `crates/portcullis-core/lean/IdentityMaterialNoninterferenceExtracted.lean#identity_material_never_reaches_the_workload`, `crates/portcullis-core/lean/ChannelAdmissionExtracted.lean#no_channel_delivers_secret_to_the_workload` | `.github/workflows/aeneas-ifc-scoped.yml` |
| C2 | "nor those of any other pod" | NOT-YET | `docs/cross-pod-view.md` | — |
| C3 | "nor influence which of them get released" | PROVED | `crates/portcullis-core/lean/PodMachineSpike.lean#noninterference` | `.github/workflows/portcullis-core-proven-lean.yml` |
| C4 | "a governor deliberately released with a single-use token" | PROVED | `crates/portcullis-core/lean/DeclassifySinkScopeExtracted.lean#no_second_apply`, `crates/portcullis/src/kernel/declassify_authority.rs#apply_declassification_token`, `crates/nucleus-tool-proxy/src/declassify.rs#apply_declassification` | `scripts/check-declassify-sink-scope-enforced.sh` |
| C5 | "cannot steer which value that is" | PROVED | `crates/portcullis-core/lean/DeclassifySinkScopeExtracted.lean#sink_outside_a_singleton_mask_denied`, `crates/portcullis/src/flow_graph.rs#effective_label` | `scripts/check-declassify-sink-scope-enforced.sh` |
| C6 | "every mediated channel" | NOT-YET | `crates/portcullis-core/lean/ChannelAdmissionExtracted.lean#no_channel_delivers_secret_to_the_workload`, `docs/architecture/mediated-set.md` | — |
| C7 | "a theorem about the code that ships" | TESTED | `.github/workflows/aeneas-ifc-scoped.yml`, `crates/nucleus-ifc-kernel/src/extracted/identity.rs` | `.github/workflows/aeneas-ifc-scoped.yml` |
| C8 | "re-checked on every change" | NOT-YET | `.github/workflows/aeneas-ifc-scoped.yml` | — |
| C9 | "verify from the outside" | TESTED | `crates/nucleus-identity/src/attestation.rs`, `crates/nucleus-node/src/posture.rs#admit_posture` | `.github/workflows/quickstart-boot.yml` |
*The clause fragments quote the sentence above, whose exclusions travel with
them: the claim covers explicit flows only, excluding timing, cache, and other
microarchitectural channels, and excluding availability and resource-contention
channels.*

What each status means, and what it deliberately does not:

- **C1 (PROVED)** — over the six modelled child-inheritance channels (Env,
  Argv, Cwd, Stdio, ExtraFd, Uid), the 11-kind × 3-principal delivery table,
  Aeneas-extracted from the shipping enforcement predicates, `sorry`-free,
  axiom-audited. Residuals, named: the `_ => OrdinaryData` classifier
  fallthrough is trusted, not proved; **mounts are not a modelled channel**.
- **C2 (NOT-YET)** — no artifact in the corpus mentions a second pod; the host
  is outside every model. `docs/cross-pod-view.md` is the design.
- **C3 (PROVED)** — the two-run noninterference theorem over the reference pod
  machine, whose step relation calls the extracted delivery oracle. Scope is
  honest: a coarse monitor LTS with an opaque workload, labelled Phase 0.
- **C4 (PROVED)** — the one-shot property is the absorbing `declass_step`
  machine (`no_second_apply`), proved over the Aeneas-extracted decision core;
  the live path enforces it via the kernel's spent-signature ledger
  (burn-on-success-only, fail-closed without trusted keys). The path is LIVE:
  `POST /v1/declassify` applies governor-signed tokens. "Governor" means a
  holder of a key configured in `NUCLEUS_DECLASSIFY_TRUSTED_KEYS` — a
  configured key signed the token, NOT that a human reviewed it. The key set is
  not workload-writable (`check-declassify-governor-keys-sealed.sh`).
- **C5 (PROVED)** — `sink_outside_a_singleton_mask_denied`, proved over the
  extracted `declass_release_ok`: a token whose signed mask admits only one
  sink does not release its data to any other. The shipping `FlowGraph` routes
  verdicts through the same decision core as a per-operation released view
  (`effective_label`); the released value and its mask are governor-signed, so
  the workload cannot steer which value is released. The full four-run
  robustness LTS over the pod machine remains a NOT-YET refinement (the
  executable two-run form ships as `declassify_scope.rs`).
- **C6 (NOT-YET)** — the six child-inheritance channels are proved total (the
  quantification is over the channel enum, so a new channel forces a match
  arm); the effect/API set is enumerated with named exclusions in
  `docs/architecture/mediated-set.md` with its lint reporting-only; the
  transport channels (vsock, pod-dir socket, in-guest HTTP, netns, DNS, node
  gRPC) have no unified inventory. "Every" is not yet earned.
- **C7 (TESTED)** — the theorems are about a scalar-only extracted restatement
  of the enforcement predicates, re-extracted from the current Rust on every
  proof-workflow run and bound to production by exhaustive parity tests and
  the boot-gate conformance replay. The surrounding kernel, classifier, and
  spawn path are covered by tests and lints, not by the theorem.
- **C8 (NOT-YET)** — the proof workflow is path-filtered; a change to the
  trusted classifier or the spawn path does not re-run it, and nothing checks
  that the call sites of the extracted predicates still exist.
- **C9 (TESTED)** — DICE-format measurements (kernel, rootfs, PodSpec+policy)
  embedded in the pod's SVID; `admit_posture` verifies a claimed
  `posture@digest` against a self-measured digest, fail-closed,
  perturbation-tested. The registry binding a posture NAME to the FM-5 proof
  is operator-asserted — no signed provenance binds artifact digest to
  theorem set yet.

The cross-pod leg is the open one, and it is deliberately sequenced audit-first:
a lookup keyed on something a guest can forge is a far likelier defect than a
flaw in the label lattice, and a real finding there is worth more than a theorem.
Per-caller identity at the node API is the enabling step — until the node can
tell *which* pod is calling, no cross-pod property is even statable, because the
system cannot assign a secret to a pod any more than the model can.

### Theoretical Foundation

This claim rests on the **capability safety theorem**: in an object-capability
(ocap) system, authority propagates only through explicit capability references.
If the enforcement boundary is capability-safe, no code inside it can acquire
authority it was not granted. This connects Nucleus to a 40-year lineage
(E language, KeyKOS, seL4, Capsicum) and is the formal basis for "prove the
boundary, not the model."

## Three Pillars

### Pillar A — Math That Survives (Kernel Semantics)

The math core is small and sharp:

1. **Capability lattice** (authority) — 12-dimensional product lattice with
   3-level capability states (Never/LowRisk/Always). Compare, combine, restrict
   permissions algebraically.

2. **Exposure lattice** (trust) — 3-bool semilattice tracking `private_data`,
   `untrusted_content`, and `exfil_vector`. When all three co-occur (uninhabitable state),
   the operation requires explicit approval. Exposure is monotone: it never
   decreases.

3. **Trace semantics** (time) — ordered record of actions, authority, and exposure
   at each step. Free monoid with homomorphic exposure accumulation.

4. **Monotonicity** (ratchet) — authority can only stay the same or tighten.
   Budget can only decrease. Exposure can only increase. The nucleus operator ν is
   idempotent and deflationary.

Key design choice: **prove properties about the enforcement boundary**, not
about LLM behavior. The agent is a black box. The kernel is the TCB.

**Current state:** 113 Kani harnesses + ~277 Lean 4 theorems verify the security
core in CI, covering lattice laws, uninhabitable state operator, Heyting algebra,
modal operators (S4), exposure monoid, graded monad laws, Galois connections,
fail-closed auth boundary, capability coverage theorem, budget monotonicity, and
delegation ceiling theorem. (Verus was evaluated and removed; verification
consolidated on Lean 4 + Kani — see the README verification table.) Phase 0-2
partially complete.

### Pillar B — Formal Methods as a Product Feature

Proofs are first-class artifacts, not academic exercises:

- **Kani bounded model checking** — 113 machine-checked harnesses over the Rust
  kernel's decision logic; complete over the finite lattice state space. CI-gated
  via `kani-nightly.yml`.
- **Lean 4 model** — ~277 kernel-checked theorems for the security core (capability
  Heyting algebra, IFC semilattice, taint monotonicity, exposure monoid,
  delegation); the Aeneas pipeline mechanically translates the core capability
  types from Rust to Lean so proofs run over generated code. CI-gated via
  `lean-build.yml` / `aeneas-ifc-scoped.yml`.
- **Differential testing** (planned) — Cedar pattern: millions of random inputs
  compared between Rust engine and Lean model.
- **Public Verified Claims page** — each claim maps to a proof artifact and
  code commit.
- **Continuous verification gates** — CI fails if a change violates a proven
  invariant. No regression path.

### Pillar C — Dead-Simple Developer Usability

A developer can get value in under 10 minutes. No lattice theory required.

- Install with `pip` (Python SDK) or `cargo` (Rust SDK)
- Run `nucleus audit` for immediate CI integration
- Wrap a workflow in a "safe session" with 10 lines of code
- Choose from built-in profiles, never think about lattices

## Product Surface

One mental model across all entry points, with value at every tier:

### Tier 0: `nucleus audit`

Fast value, no runtime required:

- Scan repo settings, MCP configs, agent configurations
- Emit PR comments / SARIF
- Generate a minimal safe profile + allowlist snippet
- **PLG funnel entry**: teams adopt this before committing to a runtime

### Tier 0.5: `nucleus observe`

Bridge from "I don't know what my agent does" to "here's a tight profile":

- Run alongside an existing agent, record all tool calls and side effects
- Suggest a minimal capability lattice policy based on observed behavior
- Output is formal (a lattice policy), not statistical (a behavioral baseline)
- **Differentiator from ARMO**: prescriptive output, not behavioral baseline

### Tier 1: `nucleus run --local`

Immediate felt safety:

- All side effects go through a local proxy
- No direct agent access except via the mediated gateway
- Approval prompts for risky actions (uninhabitable state triggers)
- Same policy language as Tier 2

### Tier 2: `nucleus run --vm`

Hard containment:

- Firecracker microVM boundary (Firecracker-based isolation)
- Default-deny egress, allowlisted DNS/hosts
- gRPC tool proxy inside the VM, SPIFFE workload identity
- Same policy language, same traces, same proofs
- **Target: <500ms cold start** via pre-warmed VM pools

Dev usability does not wait for Tier 2. But Tier 2 is the "serious people"
finish line.

### MCP Mediation (cross-tier)

MCP is the de facto agent-tool protocol. Nucleus is an MCP-aware mediator:

- Interposes on MCP tool calls, applies capability checks, records traces
- `nucleus run` accepts MCP server configs and proxies them through the policy
  engine
- Any MCP client gets enforcement for free — no SDK adoption required
- **Current state:** `nucleus-mcp` crate provides Claude Code ↔ tool-proxy
  bridging. Extend to general MCP mediation.

## The Python SDK

The "Hello World" experience should feel like `requests` + `pathlib`, not
like configuring SELinux.

### SDK Principles

- A developer should never need to think about lattices
- Unsafe actions are impossible to express without explicit approval steps
- Audit traces are produced automatically
- Intent-based API maps to built-in profiles

### Example

```python
from nucleus import Session, approve
from nucleus.tools import fs, net, git

with Session(profile="safe_pr_fixer") as s:
    readme = fs.read("README.md")           # ok
    fs.write("README.md", readme + "\n")    # ok (scoped)

    # risky: outbound fetch — explicit gate
    page = approve("fetch", net.fetch, "https://example.com")

    # forbidden: publish
    git.push("origin", "main")              # raises PolicyDenied
```

### SDK Ships With

- **Profiles**: `safe_pr_fixer`, `doc_editor`, `test_runner`, `triage_bot`,
  `code_review`, `codegen`, `release`, `research_web`, `read_only`, `local_dev`
- **Typed handles**: `FileHandle`, `NetResponse`, `CommandOutput` that carry
  exposure metadata
- **Exceptions**: `PolicyDenied`, `ApprovalRequired`, `BudgetExceeded`,
  `StateBlocked`
- **Trace export**: `session.trace.export_jsonl()`

**Current state (March 2026):** Draft Python SDK at `sdk/python/` with
intent-first API, mTLS/SPIFFE auth, and tool wrappers for fs/git/net.
Functional for direct tool-proxy connections.

## The Kernel Boundary

**The agent process must not have ambient authority.**

No direct egress. No direct filesystem beyond what is mediated. No token leaks.

The kernel is the only place where:

- Decisions are made (capability check)
- Approvals are validated (uninhabitable state gate)
- Traces are recorded (audit log)
- Exposure is tracked (monotone accumulation)

This is what makes formal verification tractable: the TCB is small (~10-15K
LOC of verified Rust), and every path through it either enforces the lattice
or panics. No fail-open. No silent degradation.

```
┌─────────────────────────────────────────────────────┐
│  Verified Core (Lean 4 + Kani)      ~10-15K LOC     │
│  ├── portcullis lattice engine     113 Kani proofs  │
│  ├── exposure guard + uninhabitable state        proven monotone  │
│  ├── permission enforcement        fail-closed      │
│  └── sandbox boundary              proven panics    │
├─────────────────────────────────────────────────────┤
│  Formal Model (Lean 4, hand-written) partial         │
│  ├── CapabilityLevel HeytingAlgebra Lean 4 proofs   │
│  ├── Aeneas pipeline (core types)  in progress      │
│  └── graded monad laws             planned          │
├─────────────────────────────────────────────────────┤
│  Differential Testing              planned          │
│  ├── Rust engine vs Lean model     cargo fuzz       │
│  └── Lean/Kani proof ratchet       CI-gated         │
├─────────────────────────────────────────────────────┤
│  Runtime (standard Rust)           ~70K LOC         │
│  ├── gRPC, tokio, tonic            Kani checks      │
│  ├── Firecracker + SPIFFE          integration      │
│  └── Tool proxy, audit, MCP        proptest         │
└─────────────────────────────────────────────────────┘
```

## Competitive Positioning

```
                    Formal Guarantees
                         ▲
                         │
                         │  ★ Nucleus (target)
                         │
    Papers ●             │
    (no product)         │
                         │
         AgentSpec ●     │
                         │
    ─────────────────────┼──────────────────► Dev Usability
                         │
              ARMO ●     │         E2B ●
                         │     Daytona ●
              CodeGate ● │  microsandbox ●
                         │
```

### Why Not X?

| Alternative | What it does | What it lacks |
|---|---|---|
| **E2B / Daytona / microsandbox** | Run code in Firecracker/Docker | No policy, no capability model, no exposure, no proofs. Ambient authority inside the box. |
| **AgentSpec** (ICSE 2026) | DSL for runtime rule enforcement | Ad-hoc rules, not lattice-based. No monotonicity guarantee. Rules are LLM-generated (95% precision — 5% are wrong). |
| **ARMO** | eBPF observe → baseline → enforce | Behavioral, not prescriptive. Must allow bad behavior before blocking it. No formal guarantees. |
| **Google Agent Sandbox** (GKE) | Pre-warmed VM pools, fast launch | Infrastructure-level only. No policy language, no exposure, no proofs. |
| **CodeGate** | Firecracker + locked pip installs | Single-purpose (supply chain). No general policy engine. |

**Nucleus's five differentiators:**

1. **Capability lattice with monotonicity proof** — authority is a
   mathematical ratchet, not a config file.
2. **Exposure tracking with uninhabitable state gate** — information flow control that
   blocks exfiltration by construction.
3. **"Prove the boundary, not the model"** — verify the enforcement kernel
   (tractable, seL4-style), not LLM behavior (impossible).
4. **Tiered value delivery** — `nucleus audit` gives value before any runtime
   commitment. Audit-first PLG funnel.
5. **Vendor-agnostic by design** — self-hosted runtime any orchestrator can
   target. No cloud lock-in.

### What to Learn From the Field

- **E2B's SDK ergonomics** — `pip install` + 3 lines = sandbox. Match this
  simplicity.
- **ARMO's progressive enforcement** — the observe → baseline → enforce UX is
  excellent for teams that don't know what policy to write. `nucleus observe`
  adopts this pattern but outputs formal policies, not behavioral baselines.
- **microsandbox's MCP integration** — MCP-native runtime is table-stakes.
  Nucleus must be an MCP-aware mediator.
- **AgentSpec's DSL readability** — trigger/predicate/action patterns are
  ergonomic. Policy authoring should be at least as readable.
- **Google's pre-warmed pools** — sub-second cold start is an infrastructure
  requirement for Tier 2.

## Formal Methods Ladder

Each rung is shippable independently.

### Rung 1 — Kani + Lean Proofs (in progress)

- 113 Kani harnesses + ~277 Lean theorems verified in CI (minimum gate)
- Covers: lattice laws, uninhabitable state operator, Heyting algebra, S4 modal
  operators, exposure monoid, graded monad laws, Galois connections, fail-closed
  auth, capability coverage, budget monotonicity, delegation ceiling
- **Key finding from proofs**: nucleus operator ν is NOT monotone (proven
  counterexample — uninhabitable state fires for y but not x). This was discovered by
  the proofs, not by tests. The proofs are working.

### Rung 2 — Lean 4 Model (partial)

- **Done**: hand-written kernel-checked proof of `CapabilityLevel` as a
  `HeytingAlgebra` (Mathlib-linked, 27-case `decide`). Discriminant
  correspondence enforced by `lean_tonat_matches_rust_discriminants` CI test.
  Kani R1/R2/R3 harnesses bridge the Lean proofs to bounded model checking.
- **Planned**: Aeneas/Charon pipeline translation (Rust MIR → LLBC → Lean)
  for the full portcullis crate; Mathlib links for broader algebraic structures;
  graded monad laws in Lean 4.

### Rung 3 — Differential Testing (planned, Phase 3)

- Cedar pattern: Rust engine vs Lean model on millions of random inputs
- Catches: serialization boundaries, encoding issues, discrepancies between
  verified model and production code
- CI-gated: every PR checked against the formal model

### Rung 4 — Extended TCB Verification (planned, Phase 4)

- Sandbox boundary, credential handling, tool proxy
- Kani bounded model checking for arithmetic paths
- Goal: full TCB machine-checked end to end

### Rung 5 — TCB Minimization

The moonshot is not "prove all the code." The moonshot is: **make the proven
kernel tiny enough that proving it is realistic.** This is how seL4 thinking
wins: reduce the surface you must trust.

## Supply Chain Integrity (Exposure Tracking Use Case)

The exposure lattice has a concrete day-one demo: supply chain safety.

- Package installs from untrusted registries carry `untrusted_content` exposure
- Exposed dependencies cannot reach sinks (network, filesystem writes) without
  explicit approval
- Combined with `exfil_vector` exposure on git push / network egress, the
  uninhabitable state gate blocks dependency-confusion attacks by construction
- This is what CodeGate does with a bespoke tool. Nucleus does it as a natural
  consequence of the exposure lattice.

## Success Criteria

### Dev Adoption

- A team gets value in **< 10 minutes**
- `pip install nucleus` + `nucleus audit` produces:
  - a clear pass/fail in CI
  - a minimal safe profile suggestion
  - an MCP allowlist snippet
- `nucleus observe` generates a first-pass policy from 30 minutes of agent
  observation

### Security

- "No direct agent calls except via proxy" is enforceable and demonstrable
- Traces are replayable and tamper-evident enough for incident review
- A red-team attempt produces a **PolicyDenied** or an approval request — not
  a leak

### Formal Methods

- Public "Verified Claims" matrix:
  - Claim → Proof artifact → Code hash
- CI fails if a change violates the proven model
- Proof count (Kani harnesses + Lean theorems) is monotonically non-decreasing (ratchet)

### Performance

- Tier 2 cold start: <500ms with pre-warmed pools
- Policy evaluation overhead: <1ms per decision
- Exposure tracking overhead: negligible (3-bool join)

## Iteration Plan

PR-sized increments that ship value while converging on the moonshot:

| PR | Scope | Ships |
|---|---|---|
| PR0 | North Star + Verified Claims doc | This document, claims table, threat model |
| PR1 | Python SDK skeleton | `Session`, exceptions, trace export, local proxy wiring |
| PR2 | Policy schema + canonical profiles | Tiny stable policy surface, "break the uninhabitable state" defaults |
| PR3 | Minimal kernel decision engine | Complete mediation for file/net/exec/publish, monotone session state |
| PR4 | Exposure plumbing | Exposure on handles, exposed-to-sink gating + approval |
| PR5 | Executable spec + model checking | Lock semantics early, prevent drift |
| PR6 | Proofs of the core invariants | Monotonicity + source-sink safety |
| PR7 | `nucleus observe` | Progressive discovery mode, formal policy output |
| PR8 | MCP mediation layer | General MCP interposition, not just Claude Code bridging |
| PR9 | VM mode hardening | Shrink ambient authority further, pre-warmed pools, <500ms target |
| PR10 | Attenuation tokens | Delegation that can only reduce power, "no escalation" cryptographically natural |

## The North Star Sentence

> **Nucleus is a runtime that makes it impossible for an agent to do something
> dangerous unless you explicitly gave it the power — and that boundary is small
> enough to prove.**

Others sandbox the agent. Nucleus proves the sandbox holds.

## Why Rust

Rust is the only language that satisfies all four requirements simultaneously:

1. **Near-C performance** — zero-cost abstractions, no GC, deterministic
   latency inside Firecracker microVMs
2. **Modern type system** — algebraic data types, pattern matching, traits,
   async/await, package ecosystem
3. **Formal verification** — Verus (SMT-based, SOSP 2025 Best Paper),
   Aeneas (Rust → Lean 4), Kani (bounded model checking), hax (Rust → F*)
4. **Safety certification** — Ferrocene qualified at ISO 26262 ASIL-D,
   IEC 61508 SIL 4, IEC 62304 Class C

## Precedents

- **AWS Nitro Isolation Engine** — formally verified Rust hypervisor (Verus +
  Isabelle/HOL). Deployed at AWS scale on Graviton5.
- **Atmosphere microkernel** (SOSP 2025 Best Paper) — L4-class microkernel
  verified with Verus. 7.5:1 proof-to-code ratio.
- **AWS Cedar** — formally verified authorization engine. Rust + Lean +
  differential testing. 1B auth/sec. Our architectural template.
- **libcrux** — formally verified post-quantum crypto in Rust via hax → F*.
  Shipping in Firefox.
- **AutoVerus** (OOPSLA 2025) — LLM agents auto-generate Verus proofs.
  137/150 tasks proven, >90% automation rate.

## References

- [Verus: Verified Rust for Systems Code](https://verus-lang.github.io/verus/)
- [Atmosphere: SOSP 2025 Best Paper](https://dl.acm.org/doi/10.1145/3731569.3764821)
- [AutoVerus: OOPSLA 2025](https://arxiv.org/abs/2409.13082)
- [AWS Nitro Isolation Engine](https://www.antstack.com/talks/reinvent25/aws-reinvent-2025---introducing-nitro-isolation-engine-transparency-through-mathematics-cmp359/)
- [AWS Cedar Formal Verification](https://www.amazon.science/blog/how-we-built-cedar-with-automated-reasoning-and-differential-testing)
- [Aeneas: Rust → Lean 4](https://aeneasverif.github.io/)
- [Ferrocene Qualified Rust Compiler](https://ferrocene.dev/)
- [libcrux: Verified Crypto via hax](https://github.com/cryspen/libcrux)
- [Systems Security Foundations for Agentic Computing](https://arxiv.org/abs/2512.01295)
- [AgentSpec: ICSE 2026](https://arxiv.org/abs/2503.18666)
- [Agent Behavioral Contracts](https://arxiv.org/html/2602.22302)
