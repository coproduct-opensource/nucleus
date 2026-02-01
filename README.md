# Nucleus

[![CI](https://github.com/coproduct-opensource/nucleus/actions/workflows/ci.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/ci.yml)
[![Security Audit](https://github.com/coproduct-opensource/nucleus/actions/workflows/audit.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/audit.yml)
[![Cargo Deny](https://github.com/coproduct-opensource/nucleus/actions/workflows/deny.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/deny.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/coproduct-opensource/nucleus/badge)](https://securityscorecards.dev/viewer/?uri=github.com/coproduct-opensource/nucleus)
[![Docs](https://img.shields.io/badge/docs-github.io-blue)](https://coproduct-opensource.github.io/nucleus/)

**Enforced permissions for AI agents** - policy + enforcement in one stack.

## What It Is

Nucleus pairs a **formal permission model** (lattice-guard) with **runtime enforcement** (nucleus). The key difference from policy-only systems: you cannot perform side effects without going through an enforcing API.

## Vision: Static Envelope, Dynamic Agent

Nucleus treats permission state as a **static envelope** around a dynamic agent:
policy invariants are normalized up front (ν), and **all side effects are
enforced at runtime** through the tool proxy. The envelope is intended to be
**monotone**: it can only tighten or terminate, never silently relax.

## Honest Progress (Current)

**Working today**
- Enforced CLI path via MCP + `nucleus-tool-proxy` (read/write/run).
- Runtime gating for approvals, budgets, and time windows.
- Firecracker driver with default‑deny egress in a dedicated netns (Linux).
- Immutable network policy drift detection (fail‑closed on iptables changes).
- Audit log with hash chaining (tamper‑evident).

**Partial / in progress**
- Web/search tools not yet wired in enforced mode.
- Approvals are runtime tokens; signed approvals are planned.
- Kani proofs exist; CI gating and formal proofs are planned.

**Not yet**
- DNS allowlisting and IPv6 egress controls.
- Audit signature verification tooling.

```rust
// Enforcement approach - cannot bypass
let sandbox = Sandbox::new(&policy, work_dir)?;
sandbox.write("file.txt", data)?;  // Enforced by capability handle

// There is no sandbox.write_unchecked() - enforcement is the only path
```

## Capability Model (Current)

Permissions are modeled as a product lattice with normalization (ν) that adds approval obligations when the lethal trifecta appears.

**Dimensions**
- **Capabilities**: per-operation autonomous permission level
- **Obligations**: per-operation approval requirement (gates execution)
- **Paths**: allow/block sets + optional work dir sandbox
- **Commands**: allow/block sets + optional structured argv patterns
- **Budget**: cost/token limits with atomic tracking
- **Time**: validity window with monotonic enforcement

**Capability levels**
- `Never < LowRisk < Always`

**Operations covered**
- `read_files`, `write_files`, `edit_files`
- `run_bash`
- `glob_search`, `grep_search`
- `web_search`, `web_fetch`
- `git_commit`, `git_push`, `create_pr`

**Obligations (approvals)**
- Any operation in `obligations.approvals` requires an approval token to execute.
- The trifecta constraint adds obligations for exfiltration operations when all three risk axes are present.

## Immutability Pitch (Monotone Security)

Security posture is intended to be **monotone**: once a pod is created, its
permissions and isolation guarantees should only tighten or be terminated,
never silently relax. This supports:

- **No privilege drift**: debugging exceptions don’t become permanent backdoors.
- **Auditability**: posture is explained by the creation spec + approval log.
- **Predictability**: you can bound worst‑case behavior without guessing runtime changes.

Implementation intent:
- Seccomp is fixed at Firecracker spawn.
- Network policy is applied once and verified against drift (fail‑closed monitor).
- Permission states are normalized via ν and only tightened after creation.
- Approvals are scoped, expiring tokens (roadmap).

## Quick Start

```bash
# Install the CLI + enforced tools
cargo install nucleus-cli
cargo install nucleus-mcp
cargo install nucleus-tool-proxy

# Run a task with Claude (enforced via tool-proxy + MCP)
nucleus run --profile fix-issue "Fix the bug in src/main.rs"

# List available permission profiles
nucleus profiles
```

Note: `nucleus run` uses `nucleus-node` (Firecracker) for enforcement and
connects via MCP to the in‑VM tool proxy. You must provide:
- `NUCLEUS_NODE_URL`
- `NUCLEUS_FIRECRACKER_KERNEL_PATH`
- `NUCLEUS_FIRECRACKER_ROOTFS_PATH`
- `NUCLEUS_FIRECRACKER_VSOCK_CID` and `NUCLEUS_FIRECRACKER_VSOCK_PORT`

Current enforced tools: read, write, run. Web/search tools are not yet wired.

## Firecracker Notes

- Firecracker pods require `--proxy-auth-secret` so the signed proxy can enforce auth.
- The local driver is opt-in via `--allow-local-driver` (no VM isolation).
- Use `--proxy-approval-secret` if approvals should be signed by a separate authority.
- Firecracker runs in a fresh network namespace by default (`--firecracker-netns=false` to disable); default-deny iptables apply even without `spec.network` (no NIC unless policy is set).
- Audit logs are hash-chained when enabled (tamper-evident).
- Guest init is the Rust binary `nucleus-guest-init`, baked into the rootfs.
- Run `scripts/firecracker/test-network.sh` to validate egress policy on Linux.

## The Lethal Trifecta (Runtime-Enforced)

The core security model prevents the [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/):

1. **Private Data Access** (reading files, secrets)
2. **Untrusted Content** (web fetch, external input)
3. **Exfiltration Vector** (git push, PRs, shell commands)

When all three are present at autonomous levels, Nucleus **adds approval obligations** to exfiltration operations at runtime.

```rust
let guard = MonotonicGuard::minutes(30);
let executor = Executor::new(&policy, &sandbox, &budget)
    .with_time_guard(&guard);

// If trifecta is complete, this requires approval
executor.run("git push")?;
// Error: ApprovalRequired { operation: "git push" }
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Your Agent                                │
├─────────────────────────────────────────────────────────────────┤
│                       nucleus-cli                                │
│     (Claude wrapper, enforced via MCP + tool-proxy by default)    │
├─────────────────────────────────────────────────────────────────┤
│                         nucleus                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │   Sandbox    │  │   Executor   │  │   AtomicBudget       │  │
│  │  (cap-std)   │  │  (process)   │  │   (lock-free)        │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                      lattice-guard                               │
│  (Capabilities + Obligations + Paths + Commands + Budget + Time)│
├─────────────────────────────────────────────────────────────────┤
│                    Operating System                              │
│           (cap-std capabilities, atomic ops, quanta)             │
└─────────────────────────────────────────────────────────────────┘
```

## Why Not Just Firecracker or gVisor?

Isolation alone doesn't express *semantic* policy. Nucleus adds:
- **Trifecta detection** (risk-aware gating, not just isolation)
- **Budgets** (time/cost ceilings enforced before side effects)
- **Approvals** (typed tokens + audit trail for sensitive ops)
- **Policy lattice** (composable, explicit permission states)

Firecracker/gVisor remain the execution boundary; Nucleus is the policy engine.

## Assurance Roadmap

Formal methods plan and minimal proof targets are tracked in `docs/assurance/formal-methods.md`.
Demo hardening criteria are tracked in `docs/assurance/hardening-checklist.md`.

## Permission Profiles

```bash
# List all profiles
nucleus profiles

# Available profiles:
#   read-only      File reading and search only
#   code-review    Read + limited web search
#   fix-issue      Write + bash + git commit (no push/PR)
#   full           Everything (trifecta still enforced!)
#   restrictive    Minimal permissions (default)
```

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

## Security Model

### What We Enforce

- ✅ File access via capability handles (symlink-safe)
- ✅ Command execution validated before spawning (CLI routes through `Executor`)
- ✅ Budget tracked atomically (no concurrent races)
- ✅ Time bounds via monotonic clock (manipulation-proof)
- ✅ Trifecta adds approval obligations for exfiltration
- ✅ Approvals require tokens (not just a boolean)
- ✅ Host-level egress allow/deny for Firecracker netns (Linux + iptables)

### What We Don't Enforce

- ❌ Kernel-level escapes (use containers/VMs)
- ❌ Host-level egress control for local driver or non-Linux
- ❌ Human approving bad actions (social engineering)
- ❌ Side-channel attacks

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
