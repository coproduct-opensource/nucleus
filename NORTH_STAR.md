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
