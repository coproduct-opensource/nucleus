# Nucleus for OpenClaw Users

If you're running OpenClaw and worried about security, this guide explains how Nucleus solves the problems that [NemoClaw](https://github.com/NVIDIA/NemoClaw) and OpenShell address — but with formally verified math instead of just container isolation.

## The Problem You Already Know

OpenClaw's [one-click RCE vulnerability](https://www.crowdstrike.com/en-us/blog/what-security-teams-need-to-know-about-openclaw-ai-super-agent/) and [135,000 exposed instances](https://www.bitsight.com/blog/openclaw-ai-security-risks-exposed-instances) demonstrated that autonomous AI agents need more than sandbox containers. NemoClaw's OpenShell adds kernel-level isolation and declarative YAML policy — a solid first step. But [as Penligent's analysis shows](https://www.penligent.ai/hackinglabs/nvidia-openclaw-security-what-nemoclaw-changes-and-what-it-still-cannot-fix/), sandboxing alone doesn't solve the fundamental problem:

**The agent can modify its own policy.**

If your agent has write access to the filesystem and the policy is a YAML file on that filesystem, the agent can escalate its own permissions. Stanford Law Review's 2026 analysis put it bluntly: "Kill switches don't work if the agent writes the policy."

## How Nucleus Is Different

Nucleus replaces the YAML policy file with a **permission lattice** — a mathematical structure that the [Lean 4 theorem prover](https://lean-lang.org/) has verified cannot be escalated.

| | OpenShell (NemoClaw) | Nucleus |
|---|---|---|
| **Policy format** | YAML file | Permission lattice (Heyting algebra) |
| **Enforcement** | Kernel-level sandbox | Kernel-level sandbox + lattice intercept |
| **Can agent modify policy?** | Yes (if it has filesystem access) | No (lattice is immutable, meet is monotonically decreasing) |
| **Formal verification** | None | 62 Kani proofs + Lean 4 HeytingAlgebra instance |
| **Proof covers production code?** | N/A | Yes — Aeneas translates Rust MIR to Lean, proof is against generated code |
| **Permission granularity** | Binary (allow/deny per endpoint) | 12 dimensions with 3 levels each (Never/LowRisk/Always) |
| **Real-time observability** | Logs | OTLP spans with all 12 capability dimensions per verdict |
| **Fleet lockdown** | Per-container restart | Sub-second gRPC broadcast to all agents |
| **Compliance export** | Manual | `nucleus audit export --format soc2` from the witness chain |

## The Permission Lattice

Instead of a flat allow/deny list, Nucleus uses a 12-dimensional **capability lattice**:

```
read_files:  Always      (can read anything)
write_files: LowRisk     (auto-approved for safe paths)
edit_files:  LowRisk     (auto-approved for safe edits)
run_bash:    Never        (blocked entirely)
glob_search: Always      (can search file names)
grep_search: Always      (can search file contents)
web_search:  LowRisk     (auto-approved)
web_fetch:   LowRisk     (auto-approved for allowed domains)
git_commit:  LowRisk     (auto-approved)
git_push:    Never        (blocked entirely)
create_pr:   LowRisk     (auto-approved)
manage_pods: Never        (blocked entirely)
```

The lattice has three operations that are formally verified:

- **meet** (intersection): When combining permissions, you get the *minimum* of each dimension. An agent can never gain permissions through composition.
- **join** (union): The least upper bound. Used for escalation requests that require human approval.
- **implies** (Heyting implication): The right adjoint to meet, used for computing what permissions would need to be added.

The key property: `meet(current_permissions, anything) <= current_permissions`. This is proven by the Lean 4 kernel — not by a test suite, not by a fuzzer, but by the type-checker evaluating all cases.

## Quick Start

### 1. Scan your existing agent configs

```bash
cargo install --git https://github.com/coproduct-opensource/nucleus nucleus-audit

# Scan a PodSpec (Nucleus native format)
nucleus-audit scan --pod-spec agent.yaml

# Scan Claude Code settings
nucleus-audit scan --claude-settings .claude/settings.json

# Auto-discover all agent configs in the repo
nucleus-audit scan --auto
```

### 2. Run your agent inside Nucleus

```bash
# Start the tool-proxy (intercepts all tool calls)
nucleus-tool-proxy --spec agent.yaml --auth-secret $SECRET

# Your agent connects to the proxy instead of directly executing tools.
# Every tool call is checked against the permission lattice.
# Every verdict is logged in a tamper-evident audit chain.
```

### 3. Emergency lockdown

```bash
# Drop ALL agents to read-only in under 1 second
nucleus lockdown --reason "suspicious activity detected"

# Agents can still read files (for forensic investigation)
# but cannot write, execute commands, or push code.

# Restore when safe
nucleus lockdown --restore
```

### 4. Compliance export

```bash
# Generate SOC 2 Type II evidence from the audit chain
nucleus audit export --format soc2

# The same witness chain that enforces permissions
# generates the compliance report. One data source.
```

## The Formal Verification Stack

This is what makes Nucleus different from every other agent security tool:

### Kani Bounded Model Checking (CI, every PR)

62 harnesses that verify lattice invariants on every pull request:

```bash
# Runs in CI — catches regressions before they merge
cargo kani --harness proof_meet_monotonically_decreasing
cargo kani --harness proof_heyting_adjunction
cargo kani --harness proof_normalize_idempotent
```

### Lean 4 HeytingAlgebra Proof (kernel-checked)

The Lean 4 type-checker proves that `CapabilityLevel` (the 3-element permission type) satisfies the HeytingAlgebra axioms. This means the `meet` operation is mathematically guaranteed to be monotonically decreasing — an agent cannot escalate permissions through any sequence of lattice operations.

```bash
cd crates/portcullis-verified/lean
lake build PortcullisVerified  # kernel-checks all theorems
```

### Aeneas Pipeline (Rust → Lean 4, machine-translated)

The proof doesn't verify a hand-written model — it verifies the actual production Rust code via [Aeneas](https://github.com/AeneasVerif/aeneas):

```
portcullis-core (Rust source)
    → Charon (MIR extraction)
    → Aeneas (translation to pure Lean 4)
    → HeytingAlgebra proof (against generated types)
```

If someone changes the Rust `CapabilityLevel` enum, the Aeneas pipeline regenerates the Lean code, and the proof either still type-checks or CI fails.

## Architecture

```
                    ┌─────────────────────────┐
                    │   Your AI Agent         │
                    │   (OpenClaw, Claude,    │
                    │    custom, etc.)        │
                    └────────┬────────────────┘
                             │ tool calls
                             ▼
                    ┌─────────────────────────┐
                    │   nucleus-tool-proxy    │
                    │   (intercepts every     │
                    │    tool call)           │
                    │                         │
                    │   ┌─────────────────┐   │
                    │   │ Permission      │   │
                    │   │ Lattice         │   │  ← Formally verified
                    │   │ (Heyting        │   │    (Lean 4 + Kani)
                    │   │  algebra)       │   │
                    │   └─────────────────┘   │
                    │                         │
                    │   ┌─────────────────┐   │
                    │   │ OTLP Telemetry  │   │  ← Every verdict
                    │   │ (12 dimensions) │   │    to Grafana/Datadog
                    │   └─────────────────┘   │
                    │                         │
                    │   ┌─────────────────┐   │
                    │   │ Audit Chain     │   │  ← HMAC-signed,
                    │   │ (witness log)   │   │    tamper-evident
                    │   └─────────────────┘   │
                    └─────────────────────────┘
                             │
                    ┌────────┴────────┐
                    │  Sandbox        │
                    │  (Firecracker / │
                    │   Docker)       │
                    └─────────────────┘
```

## Comparison with NemoClaw

If you're already using NemoClaw, Nucleus can run alongside it:

- **NemoClaw** provides the container isolation (OpenShell runtime)
- **Nucleus** provides the permission lattice inside the container

NemoClaw's YAML policy becomes the *outer* boundary. Nucleus's lattice becomes the *inner*, mathematically verified boundary. The two are complementary, not competing.

## Status

- **Permission lattice**: Stable, formally verified, 62 Kani proofs + Lean 4 HeytingAlgebra
- **Tool proxy**: Works, tested, used in production by the [Coproduct](https://coproduct.one) platform
- **Fleet lockdown**: Sub-second via gRPC streaming, signal file fallback
- **OTLP telemetry**: Every verdict as an OTel span, compatible with Grafana/Datadog/Splunk
- **Compliance export**: SOC 2 format from the witness chain
- **Aeneas pipeline**: Proof covers production Rust (not a hand-written model)

## Learn More

- [Full README](../README.md) — complete documentation
- [Permission Lattice Theory](../crates/portcullis/README.md) — the math
- [Lean 4 Proofs](../crates/portcullis-verified/lean/) — kernel-checked theorems
- [Aeneas Pipeline](../crates/portcullis-core/) — Rust → Lean 4 translation
- [Security Policy](../SECURITY.md) — responsible disclosure

## License

MIT — the proofs are open source. You can audit them yourself.
