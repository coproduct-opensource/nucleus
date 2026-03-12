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

2. **Taint lattice** (trust) — 3-bool semilattice tracking `private_data`,
   `untrusted_content`, and `exfil_vector`. When all three co-occur (trifecta),
   the operation requires explicit approval. Taint is monotone: it never
   decreases.

3. **Trace semantics** (time) — ordered record of actions, authority, and taint
   at each step. Free monoid with homomorphic taint accumulation.

4. **Monotonicity** (ratchet) — authority can only stay the same or tighten.
   Budget can only decrease. Taint can only increase. The nucleus operator ν is
   idempotent and deflationary.

Key design choice: **prove properties about the enforcement boundary**, not
about LLM behavior. The agent is a black box. The kernel is the TCB.

**Current state (March 2026):** 297 Verus proofs verified in CI covering
lattice laws, trifecta operator, Heyting algebra, modal operators (S4), taint
monoid, graded monad laws, Galois connections, fail-closed auth boundary,
capability coverage theorem, budget monotonicity, and delegation ceiling
theorem. Phase 0-2 partially complete.

### Pillar B — Formal Methods as a Product Feature

Proofs are first-class artifacts, not academic exercises:

- **Verus SMT proofs** — machine-checked invariants for the Rust kernel,
  erased at compile time (zero runtime overhead). CI-gated minimum: 297 proofs.
- **Lean 4 model** (planned) — deeper mathematical reasoning via Aeneas
  translation and Mathlib connections.
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
- Approval prompts for risky actions (trifecta triggers)
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
  taint metadata
- **Exceptions**: `PolicyDenied`, `ApprovalRequired`, `BudgetExceeded`,
  `TrifectaBlocked`
- **Trace export**: `session.trace.export_jsonl()`

**Current state (March 2026):** Draft Python SDK at `sdk/python/` with
intent-first API, mTLS/SPIFFE auth, and tool wrappers for fs/git/net.
Functional for direct tool-proxy connections.

## The Kernel Boundary

**The agent process must not have ambient authority.**

No direct egress. No direct filesystem beyond what is mediated. No token leaks.

The kernel is the only place where:

- Decisions are made (capability check)
- Approvals are validated (trifecta gate)
- Traces are recorded (audit log)
- Taint is tracked (monotone accumulation)

This is what makes formal verification tractable: the TCB is small (~10-15K
LOC of verified Rust), and every path through it either enforces the lattice
or panics. No fail-open. No silent degradation.

```
┌─────────────────────────────────────────────────────┐
│  Verified Core (Verus)              ~10-15K LOC     │
│  ├── portcullis lattice engine     297 proofs       │
│  ├── taint guard + trifecta        proven monotone  │
│  ├── permission enforcement        fail-closed      │
│  └── sandbox boundary              proven panics    │
├─────────────────────────────────────────────────────┤
│  Formal Model (Lean 4 via Aeneas)  planned          │
│  ├── lattice algebra               Mathlib links    │
│  ├── Heyting adjunction            Lean 4 proofs    │
│  └── graded monad laws             Lean 4 proofs    │
├─────────────────────────────────────────────────────┤
│  Differential Testing              planned          │
│  ├── Rust engine vs Lean model     cargo fuzz       │
│  └── AutoVerus proof generation    CI-gated         │
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
| **E2B / Daytona / microsandbox** | Run code in Firecracker/Docker | No policy, no capability model, no taint, no proofs. Ambient authority inside the box. |
| **AgentSpec** (ICSE 2026) | DSL for runtime rule enforcement | Ad-hoc rules, not lattice-based. No monotonicity guarantee. Rules are LLM-generated (95% precision — 5% are wrong). |
| **ARMO** | eBPF observe → baseline → enforce | Behavioral, not prescriptive. Must allow bad behavior before blocking it. No formal guarantees. |
| **Google Agent Sandbox** (GKE) | Pre-warmed VM pools, fast launch | Infrastructure-level only. No policy language, no taint, no proofs. |
| **CodeGate** | Firecracker + locked pip installs | Single-purpose (supply chain). No general policy engine. |

**Nucleus's five differentiators:**

1. **Capability lattice with monotonicity proof** — authority is a
   mathematical ratchet, not a config file.
2. **Taint tracking with trifecta gate** — information flow control that
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

### Rung 1 — Verus SMT Proofs (in progress)

- 297 proofs verified in CI (minimum gate)
- Covers: lattice laws, trifecta operator, Heyting algebra, S4 modal
  operators, taint monoid, graded monad laws, Galois connections, fail-closed
  auth, capability coverage, budget monotonicity, delegation ceiling
- **Key finding from proofs**: nucleus operator ν is NOT monotone (proven
  counterexample — trifecta fires for y but not x). This was discovered by
  the proofs, not by tests. The proofs are working.

### Rung 2 — Lean 4 Model (planned, Phase 1)

- Translate portcullis to Lean 4 via Aeneas
- Link to Mathlib for established algebraic structures
- Deeper reasoning: induction over recursive structures, higher-order
  properties that SMT solvers struggle with

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

## Supply Chain Integrity (Taint Tracking Use Case)

The taint lattice has a concrete day-one demo: supply chain safety.

- Package installs from untrusted registries carry `untrusted_content` taint
- Tainted dependencies cannot reach sinks (network, filesystem writes) without
  explicit approval
- Combined with `exfil_vector` taint on git push / network egress, the
  trifecta gate blocks dependency-confusion attacks by construction
- This is what CodeGate does with a bespoke tool. Nucleus does it as a natural
  consequence of the taint lattice.

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
- Verus proof count is monotonically non-decreasing (ratchet on proof count)

### Performance

- Tier 2 cold start: <500ms with pre-warmed pools
- Policy evaluation overhead: <1ms per decision
- Taint tracking overhead: negligible (3-bool join)

## Iteration Plan

PR-sized increments that ship value while converging on the moonshot:

| PR | Scope | Ships |
|---|---|---|
| PR0 | North Star + Verified Claims doc | This document, claims table, threat model |
| PR1 | Python SDK skeleton | `Session`, exceptions, trace export, local proxy wiring |
| PR2 | Policy schema + canonical profiles | Tiny stable policy surface, "break the trifecta" defaults |
| PR3 | Minimal kernel decision engine | Complete mediation for file/net/exec/publish, monotone session state |
| PR4 | Taint plumbing | Taint on handles, tainted-to-sink gating + approval |
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
