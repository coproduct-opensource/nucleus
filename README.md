# Nucleus

[![CI](https://github.com/coproduct-opensource/nucleus/actions/workflows/ci.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/ci.yml)
[![Security Audit](https://github.com/coproduct-opensource/nucleus/actions/workflows/audit.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/audit.yml)
[![Cargo Deny](https://github.com/coproduct-opensource/nucleus/actions/workflows/deny.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/deny.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/coproduct-opensource/nucleus/badge)](https://securityscorecards.dev/viewer/?uri=github.com/coproduct-opensource/nucleus)

**Enforced permissions for AI agents** - policy + enforcement in one stack.

## What It Is

Nucleus pairs a **formal permission model** (lattice-guard) with **runtime enforcement** (nucleus). The key difference from policy-only systems: you cannot perform side effects without going through an enforcing API.

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

## Quick Start

```bash
# Install the CLI
cargo install nucleus-cli

# Run a task with enforced permissions (enforcement is mandatory)
nucleus run --profile fix-issue "Fix the bug in src/main.rs"

# List available permission profiles
nucleus profiles
```

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
│              (CLI with interactive approval)                     │
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

### What We Don't Enforce

- ❌ Kernel-level escapes (use containers/VMs)
- ❌ Network-level egress control inside the host OS
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
