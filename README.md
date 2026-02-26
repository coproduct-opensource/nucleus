# Nucleus

[![CI](https://github.com/coproduct-opensource/nucleus/actions/workflows/ci.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/ci.yml)
[![Security Audit](https://github.com/coproduct-opensource/nucleus/actions/workflows/audit.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/audit.yml)
[![Cargo Deny](https://github.com/coproduct-opensource/nucleus/actions/workflows/deny.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/deny.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/coproduct-opensource/nucleus/badge)](https://securityscorecards.dev/viewer/?uri=github.com/coproduct-opensource/nucleus)
[![Docs](https://img.shields.io/badge/docs-github.io-blue)](https://coproduct-opensource.github.io/nucleus/)

**Enforced permission envelopes for AI agents** — policy *and* enforcement, in one stack.

Nucleus is built around a blunt observation: **policy without enforcement is theater**.
If an agent can still read secrets, fetch untrusted content, and exfiltrate—your YAML is just vibes.

## What It Does

Nucleus runs each agent task inside an isolated runtime (Firecracker microVMs) and exposes side effects only through an enforcing tool proxy.

**Core properties**
- **Enforced side effects:** file IO, command execution, and network are only reachable through the proxy.
- **Non-escalating envelope:** permissions can only **tighten** or the task is **terminated**—never silently relaxed.
- **Composable policy:** permissions compose predictably across a workflow; dangerous combinations trigger additional gates.

*("Non-escalating" is monotone in the order-theory sense: movement is constrained to one direction.)*

## The Safety Primitive: Lethal Trifecta Gating

Nucleus bakes in a guardrail against the [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/):

```
┌─────────────────────────────────────────────────────────────────┐
│                    THE LETHAL TRIFECTA                          │
│                                                                 │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐     │
│   │   Private    │    │  Untrusted   │    │ Exfiltration │     │
│   │    Data      │ +  │   Content    │ +  │    Vector    │     │
│   │   Access     │    │  Exposure    │    │              │     │
│   └──────────────┘    └──────────────┘    └──────────────┘     │
│         ↓                    ↓                   ↓              │
│   read_files ≥ LowRisk   web_fetch ≥ LowRisk   git_push ≥ LowRisk │
│                          web_search ≥ LowRisk  create_pr ≥ LowRisk│
│                                                run_bash ≥ LowRisk │
│                                                                 │
│   When ALL THREE are autonomous → Prompt injection = Data theft │
└─────────────────────────────────────────────────────────────────┘
```

When all three are present at autonomous levels, Nucleus **adds approval obligations** to exfiltration operations.

```rust
let executor = Executor::new(&policy, &sandbox, &budget);

// If trifecta is complete, this requires approval
executor.run("git push")?;
// Error: ApprovalRequired { operation: "git_push" }
```

## Crates

| Crate | Description |
|-------|-------------|
| **lattice-guard** | Quotient lattice for permissions with mathematical framework (Heyting algebra, Galois connections, graded monads, modal operators) |
| **nucleus** | Core enforcement: wraps OS APIs with policy checks |
| **nucleus-cli** | CLI for running tasks with enforced permissions |
| **nucleus-node** | Node daemon (kubelet analogue) managing Firecracker VMs |
| **nucleus-identity** | SPIFFE-based workload identity with mTLS and certificate management |
| **nucleus-tool-proxy** | Tool proxy server running inside pods |
| **nucleus-mcp** | MCP server bridging to tool-proxy |
| **nucleus-audit** | Hash-chained audit log verifier |
| **nucleus-spec** | Shared PodSpec definitions |
| **nucleus-client** | Client signing utilities |
| **nucleus-guest-init** | Guest init for Firecracker rootfs |
| **nucleus-net-probe** | TCP probe for network policy tests |
| **trifecta-playground** | Interactive TUI demonstrating the permission lattice |

## What Works Today

### Runtime-Enforced (Real Controls, Not Config-Only)

- **MCP tool proxy:** `read`, `write`, `run` (enforced in the microVM)
- **Firecracker isolation** with default-deny egress in a dedicated netns (Linux)
- **DNS allowlisting** with pinned resolution (Linux)
- **iptables drift detection:** if policy changes, the pod is killed (fail-closed)
- **Time windows** enforced via monotonic clock
- **Atomic budget tracking** (cost/token limits, lock-free)
- **Hash-chained audit logs** (`nucleus-audit`)
- **HMAC-signed approval tokens** with nonce replay protection
- **SPIFFE workload identity** with mTLS support

### Mathematical Framework (lattice-guard)

- **Frame-theoretic nucleus operators** for type-safe quotient lattices
- **Heyting algebra** for conditional permissions via intuitionistic implication
- **Galois connections** for principled trust domain translation
- **Modal operators** (necessity □ / possibility ◇) for guaranteed vs achievable permissions
- **Graded monad** for composable risk tracking through computation chains
- **Property-tested lattice laws** (commutative, associative, idempotent, absorption)

### Defined But Not Fully Wired Yet

- `web_fetch` endpoint exists but MCP doesn't expose it yet
- `web_search`, `glob_search`, `grep_search` exist in the policy model but aren't enforced yet
- Seccomp is applied but not yet verified/attested
- Kani proofs exist locally, not in CI

## What It Is Not

- **Not a general agent platform:** the enforced tool surface is intentionally small right now.
- **Not a host-compromise solution:** the threat model assumes the enforcement stack is trusted.
- **Not kernel-escape prevention:** use microVMs/containers appropriately; harden the host.

## Quick Start

```bash
# Install the CLI + enforced tools
cargo install nucleus-cli
cargo install nucleus-mcp
cargo install nucleus-tool-proxy
cargo install nucleus-audit

# Run a task with Claude (enforced via tool-proxy + MCP)
nucleus run --profile fix-issue "Fix the bug in src/main.rs"

# List available permission profiles
nucleus profiles
```

Note: `nucleus run` uses `nucleus-node` (Firecracker) for enforcement and
connects via MCP to the in-VM tool proxy. You must provide:
- `NUCLEUS_NODE_URL`
- `NUCLEUS_NODE_AUTH_SECRET`
- `NUCLEUS_FIRECRACKER_KERNEL_PATH`
- `NUCLEUS_FIRECRACKER_ROOTFS_PATH`
- `NUCLEUS_FIRECRACKER_VSOCK_CID` and `NUCLEUS_FIRECRACKER_VSOCK_PORT`

**Current enforced tools:** read, write, run. That's it for now—other tools exist in the policy model but aren't wired to MCP yet.

**macOS users:** See [docs/quickstart/macos.md](docs/quickstart/macos.md) for Lima + Firecracker setup.

## Interactive Demo

The `trifecta-playground` TUI provides an interactive demonstration of the permission lattice:

```bash
cargo run -p trifecta-playground
```

Features:
- **Trifecta screen:** Toggle capabilities and watch risk levels change in real-time
- **Matrix view:** See all 11 capabilities across preset profiles
- **Hasse diagram:** Visualize the partial order of permission presets
- **Meet playground:** Compute the meet (∧) of two permission sets
- **Chain builder:** Build SPIFFE delegation chains and verify the ceiling theorem
- **Attack simulator:** See how common attack patterns are blocked

## Permission Profiles

```bash
nucleus profiles

# Available profiles:
#   ✅ read-only       File reading and search only
#   ✅ fix-issue       Write + bash + git commit (no push/PR)
#   ✅ restrictive     Minimal permissions (default)
#   🟡 code-review     Read + limited web search (web not wired)
#   🟡 web-research    Read + web search/fetch (web not wired)
#   🟡 full            Everything (trifecta still enforced!)
```

✅ = works now | 🟡 = policy defined, partial enforcement

## Custom Permissions

Create a `permissions.toml`:

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

```bash
nucleus run --config permissions.toml "Your task here"
```

## Threat Model

**Protects against:**
- Prompt injection attempting side effects outside the envelope
- Misconfigured tool permissions (enforced at runtime, not advisory)
- Drift in network policy inside the runtime (fail-closed)
- Budget exhaustion attacks (atomic tracking)
- Privilege escalation via delegation (ceiling theorem)
- Trust domain confusion (Galois connections)

**Does not protect against:**
- Compromised host or kernel (enforcement stack is trusted)
- Malicious human approvals (social engineering)
- Side-channel attacks
- Kernel escapes from the microVM

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Your Agent                                │
├─────────────────────────────────────────────────────────────────┤
│                       nucleus-cli                                │
│     (Claude wrapper, enforced via MCP + tool-proxy by default)   │
├─────────────────────────────────────────────────────────────────┤
│                         nucleus                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │   Sandbox    │  │   Executor   │  │   AtomicBudget       │  │
│  │  (cap-std)   │  │  (process)   │  │   (lock-free)        │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                      lattice-guard                               │
│   Capabilities × Obligations × Paths × Commands × Budget × Time  │
│   + Heyting Algebra + Galois Connections + Graded Monad + Modal  │
├─────────────────────────────────────────────────────────────────┤
│                    nucleus-identity                              │
│           SPIFFE workload identity + mTLS + cert rotation        │
├─────────────────────────────────────────────────────────────────┤
│                    Operating System                              │
│           (cap-std capabilities, atomic ops, quanta)             │
└─────────────────────────────────────────────────────────────────┘
```

## Why a Lattice?

The policy model uses a **permission lattice**—security-speak translation:

- **Composable policy** = predictable aggregate posture across a workflow
- **Meet operation** = tightening across composition (intersection of capabilities)
- **Monotone delegation** = no escalation beyond parent envelope (ceiling theorem)

The lattice is an implementation detail. What matters: permissions compose predictably, and dangerous combinations (the trifecta) trigger additional gates automatically.

### Mathematical Extensions

The `lattice-guard` crate provides advanced structures for principled permission modeling:

| Structure | Purpose |
|-----------|---------|
| **Frame/Nucleus** | Type-safe quotient lattices via the trifecta nucleus operator |
| **Heyting Algebra** | Conditional permissions: `(c ∧ a) ≤ b ⟺ c ≤ (a → b)` |
| **Galois Connections** | Security-preserving translation across trust domains |
| **Modal Operators** | Distinguish guaranteed (□) from achievable (◇) permissions |
| **Graded Monad** | Track risk through computation chains with monad laws |

For the PL theory motivation (graded monads, algebraic effects), see [docs/THEORY.md](docs/THEORY.md).

## Firecracker Notes

- Firecracker pods require `--proxy-auth-secret` and `--proxy-approval-secret` for signed tool and approval calls.
- The driver defaults to Firecracker; local is opt-in via `--allow-local-driver` (no VM isolation).
- Firecracker runs in a fresh network namespace by default (`--firecracker-netns=false` to disable).
- Default-deny iptables apply even without `spec.network` (no NIC unless policy is set).
- DNS allowlisting is enforced via `spec.network.dns_allow` (pinned at pod start).
- Guest IPv6 is disabled at boot.
- Audit logs are hash-chained and signed (verify with `nucleus-audit`).
- Guest init is the Rust binary `nucleus-guest-init`, baked into the rootfs.
- Run `scripts/firecracker/test-network.sh` to validate egress policy on Linux.

## Command Policy

Command enforcement supports both:
- **String allow/block** rules (fast, coarse)
- **Structured argv** patterns (precise)

```rust
use lattice_guard::{ArgPattern, CommandLattice, CommandPattern};

let mut cmds = CommandLattice::permissive();
cmds.allow_rule(CommandPattern::exact("cargo", &["test"]));
cmds.block_rule(CommandPattern {
    program: "bash".to_string(),
    args: vec![ArgPattern::AnyRemaining],
});

assert!(cmds.can_execute("cargo test --release"));
assert!(!cmds.can_execute("bash -c 'echo hi'"));
```

## Development

```bash
# Build all crates
cargo build --workspace

# Run tests
cargo test --workspace

# Run the interactive demo
cargo run -p trifecta-playground

# Run CLI in development
cargo run -p nucleus-cli -- run --profile fix-issue "Test task"
```

## Assurance Roadmap

Formal methods plan and minimal proof targets are tracked in `docs/assurance/formal-methods.md`.
Demo hardening criteria are tracked in `docs/assurance/hardening-checklist.md`.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.

## References

- [The Lethal Trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) - Simon Willison
- [Container Hardening Against Agentic AI](https://securitytheatre.substack.com/p/container-hardening-against-agentic)
- [Lattice-based Access Control](https://en.wikipedia.org/wiki/Lattice-based_access_control) - Denning 1976, Sandhu 1993
- [cap-std](https://github.com/bytecodealliance/cap-std) - Capability-based filesystem

<!-- Lattice orbit test: 2026-02-26T17:56:56Z -->
