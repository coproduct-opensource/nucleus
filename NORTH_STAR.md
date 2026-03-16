# Nucleus North Star

**Nucleus makes "agent jailbreak to silent damage" provably impossible by construction, while remaining frictionless enough that small dev teams adopt it like a linter.**

> **Assume the agent is compromised. Constrain what it can do anyway. Prove the constraints hold.**

## Flagship Safety Claim (v0)

**No external side effect occurs unless it is mediated by Nucleus and authorized by a policy that can only stay the same or tighten during execution.**

Corollaries:

- No exfiltration without an explicit sink capability.
- No "talk your way into more permissions" mid-run.
- No untrusted content reaching a sink without an approval/declassification gate.

## Three Pillars

### Pillar A — Math that survives (Kernel Semantics)

1. **Capability lattice (authority):** compare, combine, and restrict permissions.
2. **Exposure lattice (trust):** track untrusted influence and gate sinks.
3. **Trace semantics (time):** what actions happened, in what order, under what authority.
4. **Monotonicity:** authority can only stay the same or tighten (a one-way ratchet).

Key design choice: prove properties about the **enforcement boundary**, not about agent behavior.

### Pillar B — Formal methods as a product feature

- Spec model (small, executable).
- Machine-checked proofs for invariants.
- Continuous verification gates in CI.
- Public "Verified Claims" page mapping each claim to a proof artifact and code commit.

### Pillar C — Dead-simple developer usability (Python-first)

- Install with `pip`.
- Run a scan in CI.
- Wrap a workflow in a "safe session" with 10 lines of code.

## Product Surface

| Tier | Command | What it does |
|------|---------|--------------|
| **0** | `nucleus audit` | Scan repo/agent configs, emit SARIF, generate safe profile. |
| **1** | `nucleus run --local` | All side effects through local proxy, approvals for risky actions. |
| **2** | `nucleus run --vm` | MicroVM boundary, default-deny egress, same policy language. |

## Python SDK Shape

```python
from nucleus import Session, approve
from nucleus.tools import fs, net, git

with Session(profile="safe_pr_fixer") as s:
    readme = fs.read("README.md")
    fs.write("README.md", readme + "\n")
    page = approve("fetch", net.fetch, "https://example.com")
    git.push("origin", "main")  # raises PolicyDenied
```

The SDK ships with:

- **Profiles** — declarative policy bundles for common work types.
- **Typed handles with exposure** — every value carries provenance metadata.
- **Exceptions** — `PolicyDenied`, `ApprovalRequired`, `BudgetExceeded`.
- **Trace export** — structured audit logs for every mediated action.

## Kernel Boundary Rule

The agent process must not have ambient authority. The kernel is the only place where decisions are made, approvals validated, and traces recorded.

## Formal Methods Ladder

| Rung | Artifact | Description |
|------|----------|-------------|
| **1** | Executable spec | TLA+ or Python model of the kernel semantics. |
| **2** | Machine-checked proofs | Lean/Coq proofs for monotonicity, sink safety, exposure gating. |
| **3** | Implementation alignment | Property tests, Kani/Verus proofs, boundary fuzzing. |
| **4** | TCB minimization | Reduce the trusted computing base as a measurable deliverable. |

## Verification North Star: verify-rust-std Equivalence

**Target:** Reach parity with AWS's [verify-rust-std](https://github.com/model-checking/verify-rust-std) effort in verification density — measured by proof-to-code ratio, not absolute count.

### Current State (March 2026)

| Metric | Nucleus (portcullis) | Workstream-KG | Combined |
|---|---|---|---|
| Verus SMT VCs | 297 | — | 297 |
| Kani BMC proofs | 32 | 30 | 62 |
| Verus↔prod conformance | 17 proptests | — | 17 |
| Runtime conservation laws | — | 10 | 10 |
| Unit tests | 597 | 1,895 | 2,492 |

### Targets

| Milestone | Verus VCs | Kani Proofs | What |
|---|---|---|---|
| **Current** | 297 | 62 | Lattice laws + BMC safety |
| **T1: 500/100** | 500 | 100 | Add Verus to conservation laws, Kani to Lyapunov monotonicity |
| **T2: 1000/200** | 1,000 | 200 | Verify reconciler convergence properties, executor pool fairness |
| **T3: verify-rust-std density** | — | — | Proof-to-code ratio ≥ AWS std lib effort |

### Credible Claims (honest framing)

- **"Most formally verified AI agent permission system"** — true today, zero competition
- **"Only project using both Verus AND Kani"** on the same codebase — SMT + BMC dual verification
- **"Only AI orchestrator with runtime conservation laws backed by formal verification"** — Gas Town, Agent Sandbox, Kagent have zero
- **NOT "most formally verified OSS project"** — seL4 (200K lines Isabelle proof) and CompCert are orders of magnitude ahead in absolute terms

### Strategy

1. **Maximize proof-to-code ratio** on the enforcement boundary (portcullis), not on application logic
2. **Automate harness generation** — follow Hifitime's pattern of auto-generating Kani harnesses for new functions
3. **Verus for algebraic properties** (lattice laws, monotonicity), **Kani for safety** (no panics, bounded behavior)
4. **Conservation laws bridge the gap** — runtime enforcement of invariants that are too expensive to statically verify

## Iteration Plan (PR-sized)

| PR | Scope |
|----|-------|
| **PR0** | North Star + Verified Claims doc |
| **PR1** | Python SDK skeleton |
| **PR2** | Policy schema + canonical profiles |
| **PR3** | Minimal kernel decision engine |
| **PR4** | Exposure plumbing |
| **PR5** | Executable spec + model checking |
| **PR6** | Proofs of the core invariants |
| **PR7** | VM mode hardening |
| **PR8** | Attenuation tokens |

## Success Metrics

- **Dev adoption:** value in under 10 minutes. `pip install` + `audit` produces pass/fail and a profile suggestion.
- **Security:** traces are replayable and tamper-evident. Red-teaming produces `PolicyDenied`, not a leak.
- **Formal methods:** public Verified Claims matrix. CI fails if a change violates a proven model.
