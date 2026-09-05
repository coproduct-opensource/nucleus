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

### Current State (September 2026)

Verus was removed from the workspace (see `FORMAL_METHODS.md`); its role —
unbounded algebraic properties over the enforcement core — is now Lean 4 over
Aeneas-extracted Rust. The earlier "297 Verus VCs" line in this file was stale
for months; the numbers below are recomputed from the tree
(`grep -rc '#\[kani::proof\]' crates`).

| Metric | Count | Where |
|---|---|---|
| Kani BMC harnesses | 117 | portcullis 68, portcullis-core 25, ck-kernel 17, nucleus-ifc-kernel 6, nucleus-econ-kernels 1 (`scripts/formal-numbers.sh`) |
| Lean 4 theorems over **extracted** Rust | ~280 in the security core | IFC noninterference family, `decide_pure`, ck-policy gate, `chain_effective_authority`, certificate-chain monotonicity (`chain_attenuates`, #2451) |
| Open `sorry` holes | 23 across 10 files | research tier only (`CONJECTURES.md`); the proven tier is `sorry`-free and CI-gated |
| Budget conservation | Kani E1/E2 over the shipped `LedgerCore` | `Σ child allocations + consumed ≤ max` |

### Targets

| Milestone | Kani harnesses | Extracted Lean | What |
|---|---|---|---|
| **Current** | 115 | ~277 theorems | Lattice laws, BMC safety, IFC noninterference, budget conservation |
| **T1** | 150 | verify_certificate extracted (#2451) | Prove the certificate chain's monotonicity soundness over the real code |
| **T2** | 200 | identity/card verification extracted (#2452) | Reconciler convergence, executor pool fairness |
| **T3: verify-rust-std density** | — | — | Proof-to-code ratio ≥ AWS std lib effort |

### Credible Claims (honest framing)

- **"Most formally verified AI agent permission system"** — true today, zero competition
- **"Lean proofs over Aeneas-extracted production Rust, regenerated on every PR"** — the IFC core, the decision function, the amendment gate, and chain attenuation; not hand-written models of the code
- **"Only AI orchestrator with runtime conservation laws backed by formal verification"** — Gas Town, Agent Sandbox, Kagent have zero
- **NOT "most formally verified OSS project"** — seL4 (200K lines Isabelle proof) and CompCert are orders of magnitude ahead in absolute terms
- **NOT "uses both Verus and Kani"** — Verus is gone; do not repeat the old claim

### Strategy

1. **Maximize proof-to-code ratio** on the enforcement boundary (portcullis), not on application logic
2. **Automate harness generation** — follow Hifitime's pattern of auto-generating Kani harnesses for new functions
3. **Lean over extracted Rust for algebraic properties** (lattice laws, monotonicity, noninterference), **Kani for safety** (no panics, bounded behavior)
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
