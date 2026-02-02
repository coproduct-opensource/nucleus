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

## What Works Today

### Runtime-Enforced (Real Controls, Not Config-Only)

- ✅ **MCP tool proxy:** `read`, `write`, `run` (enforced in the microVM)
- ✅ **Firecracker isolation** with default-deny egress in a dedicated netns (Linux)
- ✅ **DNS allowlisting** with pinned resolution (Linux)
- ✅ **iptables drift detection:** if policy changes, the pod is killed (fail-closed)
- ✅ **Time windows** enforced via monotonic clock
- ✅ **Atomic budget tracking** (cost/token limits, lock-free)
- ✅ **Hash-chained audit logs** (`nucleus-audit`)

### Gated Execution

- ✅ **HMAC-signed approval tokens** with nonce replay protection

### Defined But Not Fully Wired Yet

- 🟡 `web_fetch` endpoint exists but MCP doesn't expose it yet
- 🟡 `web_search`, `glob_search`, `grep_search` exist in the policy model but aren't enforced yet
- 🟡 Seccomp is applied but not yet verified/attested
- 🟡 Kani proofs exist locally, not in CI

## What It Is Not

- **Not a general agent platform:** the enforced tool surface is intentionally small right now.
- **Not a host-compromise solution:** the threat model assumes the enforcement stack is trusted.
- **Not kernel-escape prevention:** use microVMs/containers appropriately; harden the host.

## The Safety Primitive: Lethal Trifecta Gating

Nucleus bakes in a guardrail against the [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/):

1. **Private data access** (reading files, secrets)
2. **Untrusted content** (web fetch, external input)
3. **Exfiltration vector** (git push, PRs, shell commands)

When all three are present at autonomous levels, Nucleus **adds approval obligations** to exfiltration operations.

```rust
let executor = Executor::new(&policy, &sandbox, &budget);

// If trifecta is complete, this requires approval
executor.run("git push")?;
// Error: ApprovalRequired { operation: "git_push" }
```

## Threat Model

**Protects against:**
- Prompt injection attempting side effects outside the envelope
- Misconfigured tool permissions (enforced at runtime, not advisory)
- Drift in network policy inside the runtime (fail-closed)
- Budget exhaustion attacks (atomic tracking)

**Does not protect against:**
- Compromised host or kernel (enforcement stack is trusted)
- Malicious human approvals (social engineering)
- Side-channel attacks
- Kernel escapes from the microVM

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

## Modes

- **Approval-free mode (default):** obligations cause hard-deny if no approval system is configured.
- **Approval-token mode:** obligations require a scoped, expiring HMAC token.
- **Break-glass mode (future):** elevated friction + extra audit for emergency access.

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
│  (Capabilities + Obligations + Paths + Commands + Budget + Time) │
├─────────────────────────────────────────────────────────────────┤
│                    Operating System                              │
│           (cap-std capabilities, atomic ops, quanta)             │
└─────────────────────────────────────────────────────────────────┘
```

## Why a Lattice? (For the Curious)

The policy model uses a **permission lattice**—security-speak translation:

- **Composable policy** = predictable aggregate posture across a workflow
- **Meet operation** = tightening across composition (intersection of capabilities)
- **Monotone delegation** = no escalation beyond parent envelope

The lattice is an implementation detail. What matters: permissions compose predictably, and dangerous combinations (the trifecta) trigger additional gates automatically.

For the PL theory motivation (graded monads, algebraic effects), see [docs/THEORY.md](docs/THEORY.md).

## Why Not Just Firecracker or gVisor?

Isolation alone doesn't express *semantic* policy. Nucleus adds:
- **Trifecta detection** (risk-aware gating, not just isolation)
- **Budgets** (time/cost ceilings enforced before side effects)
- **Approvals** (typed tokens + audit trail for sensitive ops)
- **Policy composition** (predictable across workflows)

Firecracker/gVisor remain the execution boundary; Nucleus is the policy engine.

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

## Assurance Roadmap

Formal methods plan and minimal proof targets are tracked in `docs/assurance/formal-methods.md`.
Demo hardening criteria are tracked in `docs/assurance/hardening-checklist.md`.

## Development

```bash
# Build all crates
cargo build --workspace

# Run tests
cargo test --workspace

# Run CLI in development
cargo run -p nucleus-cli -- run --profile fix-issue "Test task"
```

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.

## References

- [The Lethal Trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) - Simon Willison
- [Container Hardening Against Agentic AI](https://securitytheatre.substack.com/p/container-hardening-against-agentic)
- [cap-std](https://github.com/bytecodealliance/cap-std) - Capability-based filesystem
