# Nucleus

[![CI](https://github.com/coproduct-opensource/nucleus/actions/workflows/ci.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/ci.yml)
[![Security Audit](https://github.com/coproduct-opensource/nucleus/actions/workflows/audit.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/audit.yml)
[![Cargo Deny](https://github.com/coproduct-opensource/nucleus/actions/workflows/deny.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/deny.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/coproduct-opensource/nucleus/badge)](https://securityscorecards.dev/viewer/?uri=github.com/coproduct-opensource/nucleus)
[![Docs](https://img.shields.io/badge/docs-github.io-blue)](https://coproduct-opensource.github.io/nucleus/)

**Security for AI agents that actually enforces.** Policy, enforcement, and audit — in one stack.

Your AI agent has access to secrets, processes untrusted content, and can push code. That's the [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) — and your YAML config file isn't stopping it.

Nucleus provides three layers of defense:

1. **Scan** — Static analysis of agent configurations to catch dangerous permission combinations *before* deployment
2. **Enforce** — Runtime permission envelopes in Firecracker microVMs that *cannot* be escalated
3. **Audit** — Hash-chained, cryptographically verifiable logs of every agent action

## Start Here: Audit Your Agent Config

```bash
cargo install nucleus-audit

# Scan a PodSpec for security issues
nucleus-audit scan --pod-spec your-agent.yaml

# Example output:
# ╔══════════════════════════════════════════════════════════════╗
# ║  Nucleus PodSpec Security Scan                              ║
# ╠══════════════════════════════════════════════════════════════╣
# ║  Pod: yolo-agent                                            ║
# ║  Policy: permissive                                         ║
# ║  Findings: 4 critical, 2 high, 1 medium                    ║
# ╠══════════════════════════════════════════════════════════════╣
# ║  [CRITICAL] Lethal trifecta: private data + untrusted       ║
# ║             content + exfiltration all at autonomous levels  ║
# ║  [CRITICAL] 7 credentials exposed — exceeds safe threshold  ║
# ║  [HIGH]     No network restrictions (full egress)           ║
# ║  [HIGH]     No VM isolation (no Firecracker/seccomp)        ║
# ╚══════════════════════════════════════════════════════════════╝
# Exit code: 1 (critical or high findings)
```

The scan checks for trifecta risk, permission surface area, network posture, isolation level, credential exposure, and timeout hygiene. Exit code is non-zero when critical or high findings exist — drop it into CI and block unsafe deployments.

```bash
# JSON output for CI pipelines
nucleus-audit scan --pod-spec agent.yaml --format json

# Cross-reference with runtime audit logs
nucleus-audit scan --pod-spec agent.yaml --audit-log /var/log/nucleus/agent.jsonl
```

## The Lethal Trifecta

The core security primitive. When an agent has all three capabilities at autonomous levels, prompt injection becomes data exfiltration:

```
  Private Data Access    +    Untrusted Content    +    Exfiltration Vector
  ─────────────────────       ──────────────────        ────────────────────
  read_files ≥ LowRisk       web_fetch ≥ LowRisk      git_push ≥ LowRisk
  read_env                    web_search ≥ LowRisk     create_pr ≥ LowRisk
  database access             user input processing    run_bash (curl, etc)
```

Nucleus detects this combination statically (via `nucleus-audit scan`) and enforces it at runtime (via `portcullis`). When the trifecta is complete, exfiltration operations require **explicit human approval** — the agent cannot bypass this.

## Runtime Enforcement

Each agent task runs inside an isolated Firecracker microVM. Side effects are only possible through an enforcing tool proxy.

**Properties that hold at runtime:**
- **Non-escalating envelope** — permissions can only tighten during execution, never silently relax (monotone in the order-theory sense)
- **Fail-closed network** — default-deny egress with DNS allowlisting; iptables drift kills the pod
- **Atomic budget tracking** — cost and token limits enforced lock-free; exhaustion halts the agent
- **Hash-chained audit** — every tool invocation is logged with cryptographic chaining; tampering is detectable
- **SPIFFE workload identity** — mTLS between components; no shared secrets on the wire

```rust
let executor = Executor::new(&policy, &sandbox, &budget);

// If trifecta is complete, this requires approval
executor.run("git push")?;
// Error: ApprovalRequired { operation: "git_push" }
```

## Permission Lattice

Permissions compose predictably via a mathematical lattice. This isn't academic decoration — it's what makes multi-agent workflows safe:

| Structure | What It Gives You |
|-----------|-------------------|
| **Quotient Lattice** | Trifecta detection is a nucleus operator — it's structural, not a regex |
| **Heyting Algebra** | Conditional permissions: "allow push *if* tests pass" has formal semantics |
| **Galois Connections** | Translate policies across trust domains without losing guarantees |
| **Graded Monad** | Risk accumulates through computation chains — you can't hide it |
| **Modal Operators** | Distinguish "guaranteed safe" (□) from "might be safe" (◇) |
| **Delegation Chains** | SPIFFE-backed delegation with a ceiling theorem — no escalation beyond parent |

412+ property-tested invariants. The lattice laws (commutative, associative, idempotent, absorption) are verified, not assumed.

For the theory: [docs/THEORY.md](docs/THEORY.md).

## Crates

| Crate | Purpose |
|-------|---------|
| **nucleus-audit** | `scan` PodSpecs for misconfigurations; `verify` hash-chained audit logs |
| **portcullis** | Permission lattice with 7 mathematical modules (~4800 LOC, 412+ tests) |
| **nucleus-node** | Node daemon (kubelet analogue) managing Firecracker microVMs |
| **nucleus-identity** | SPIFFE workload identity, mTLS, certificate management |
| **nucleus-tool-proxy** | Enforcing tool proxy running inside pods |
| **nucleus-mcp** | MCP server bridging to tool-proxy |
| **nucleus-spec** | PodSpec definitions (policy, network, credentials, isolation) |
| **nucleus-cli** | CLI for running tasks with enforced permissions |
| **nucleus** | Core enforcement: wraps OS APIs with policy checks |
| **nucleus-client** | Client signing utilities |
| **nucleus-guest-init** | Guest init for Firecracker rootfs |
| **nucleus-net-probe** | TCP probe for network policy tests |
| **trifecta-playground** | Interactive TUI demonstrating the permission lattice |

## Permission Profiles

```bash
nucleus profiles

# Available profiles:
#   read_only       File reading and search only
#   fix_issue       Write + bash + git commit (no push/PR)
#   code_review     Read + limited search
#   restrictive     Minimal permissions (default)
#   full            Everything (trifecta gates still enforced!)
```

## Custom Permissions

```toml
[capabilities]
read_files = "always"
write_files = "low_risk"
edit_files = "low_risk"
run_bash = "low_risk"
git_commit = "low_risk"
git_push = "never"        # Blocked entirely
web_fetch = "never"       # No untrusted content

[obligations]
approvals = ["run_bash"]  # Requires approval token

[budget]
max_cost_usd = 2.0
max_input_tokens = 50000
max_output_tokens = 5000

[time]
valid_hours = 1           # Expires after 1 hour
```

## Example PodSpecs

See [`examples/podspecs/`](examples/podspecs/) for real configurations:

- **`airgapped-review.yaml`** — Code review in a fully airgapped Firecracker VM with seccomp
- **`secure-codegen.yaml`** — Code generation with filtered network (crates.io, npm, GitHub only)
- **`permissive-danger.yaml`** — Intentionally insecure config for testing `nucleus-audit scan`

## Threat Model

**Protects against:**
- Prompt injection attempting side effects outside the permission envelope
- Misconfigured tool permissions (enforced at runtime, not advisory)
- Network policy drift inside the runtime (fail-closed)
- Budget exhaustion attacks (atomic tracking)
- Privilege escalation via delegation (ceiling theorem)
- Trust domain confusion (Galois connections)
- Audit log tampering (hash chain verification)

**Does not protect against:**
- Compromised host or kernel (enforcement stack is trusted)
- Malicious human approvals (social engineering)
- Side-channel attacks
- Kernel escapes from the microVM

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Your Agent                               │
├─────────────────────────────────────────────────────────────────┤
│  nucleus-cli / nucleus-audit scan                               │
│  (enforce at runtime / catch misconfigs before deploy)          │
├─────────────────────────────────────────────────────────────────┤
│                         nucleus                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │   Sandbox    │  │   Executor   │  │   AtomicBudget       │  │
│  │  (cap-std)   │  │  (process)   │  │   (lock-free)        │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                      portcullis                              │
│   Capabilities × Obligations × Paths × Commands × Budget × Time │
│   + Heyting Algebra + Galois Connections + Graded Monad + Modal │
├─────────────────────────────────────────────────────────────────┤
│                    nucleus-identity                             │
│           SPIFFE workload identity + mTLS + cert rotation       │
├─────────────────────────────────────────────────────────────────┤
│           Firecracker microVM / seccomp / netns                 │
│           (default-deny egress, DNS allowlisting)               │
└─────────────────────────────────────────────────────────────────┘
```

## Development

```bash
cargo build --workspace
cargo test --workspace
cargo run -p trifecta-playground  # Interactive demo
```

## What Works Today vs. What's Coming

**Runtime-enforced now:** MCP tool proxy (read/write/run), Firecracker isolation, default-deny egress, DNS allowlisting, iptables drift detection, time windows, atomic budgets, hash-chained audit, HMAC-signed approvals, SPIFFE identity.

**Policy-defined, not yet wired:** `web_fetch` MCP endpoint, `web_search`/`glob_search`/`grep_search` enforcement, seccomp attestation, Kani proofs in CI.

## Assurance Roadmap

Formal methods plan: `docs/assurance/formal-methods.md`. Hardening checklist: `docs/assurance/hardening-checklist.md`.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.

## References

- [The Lethal Trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) — Simon Willison
- [Container Hardening Against Agentic AI](https://securitytheatre.substack.com/p/container-hardening-against-agentic)
- [Lattice-based Access Control](https://en.wikipedia.org/wiki/Lattice-based_access_control) — Denning 1976, Sandhu 1993
- [cap-std](https://github.com/bytecodealliance/cap-std) — Capability-based filesystem
