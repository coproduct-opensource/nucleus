# lattice-guard

[![Crates.io](https://img.shields.io/crates/v/lattice-guard.svg)](https://crates.io/crates/lattice-guard)
[![Documentation](https://docs.rs/lattice-guard/badge.svg)](https://docs.rs/lattice-guard)
[![License](https://img.shields.io/crates/l/lattice-guard.svg)](LICENSE-MIT)

A **quotient lattice** for AI agent permissions that prevents the "lethal trifecta".

## The Lethal Trifecta

The [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) describes three capabilities that, when combined in an AI agent, create critical security vulnerabilities:

1. **Private Data Access** - reading files, credentials, secrets
2. **Untrusted Content Exposure** - web search, fetching URLs, processing external input
3. **Exfiltration Vector** - git push, PR creation, API calls, shell commands

When an agent has all three at autonomous levels, prompt injection attacks can exfiltrate private data without human oversight.

```text
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

## Solution: The Nucleus Operator

This crate models permissions as a product lattice **L** with a **lattice-guard** operator that projects onto the quotient lattice **L'** of safe configurations:

```text
L  = Capabilities × Obligations × Paths × Budget × Commands × Time
L' = { x ∈ L : ν(x) = x }  — the quotient of safe configurations

The lattice-guard ν satisfies:
• Idempotent:    ν(ν(x)) = ν(x)
• Deflationary:  ν(x) ≤ x
• Meet-preserving: ν(x ∧ y) = ν(x) ∧ ν(y)
```

When the trifecta is detected, exfiltration operations gain approval obligations. The quotient L' contains only configurations where this invariant holds.

See [THREAT_MODEL.md](THREAT_MODEL.md) for what this crate prevents and what it does NOT prevent.

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
lattice-guard = "0.1"
```

Basic usage:

```rust
use lattice_guard::{Operation, PermissionLattice, CapabilityLevel};

// Create a permission set with dangerous capabilities
let mut perms = PermissionLattice::default();
perms.capabilities.read_files = CapabilityLevel::Always;    // Private data
perms.capabilities.web_fetch = CapabilityLevel::LowRisk;    // Untrusted content
perms.capabilities.git_push = CapabilityLevel::LowRisk;     // Exfiltration

// The meet operation applies the lattice-guard and adds approval obligations
let safe = perms.meet(&perms);
assert!(safe.requires_approval(Operation::GitPush));
```

## Capability Levels

Permissions use a three-level lattice for autonomous capability:

| Level | Value | Description |
|-------|-------|-------------|
| `Never` | 0 | Never allow |
| `LowRisk` | 1 | Auto-approve for low-risk operations |
| `Always` | 2 | Always auto-approve |

Approval requirements are modeled separately as **Obligations**. The meet operation
takes the **minimum** of two capability levels (most restrictive).

## Lattice Properties

The permission lattice satisfies the algebraic lattice properties:

- **Commutative**: `a ∧ b = b ∧ a`
- **Associative**: `(a ∧ b) ∧ c = a ∧ (b ∧ c)`
- **Idempotent**: `a ∧ a = a`
- **Absorption**: `a ∧ (a ∨ b) = a`
- **Monotonic delegation**: `delegate(parent, request) ≤ parent`

These properties are verified by property-based tests using proptest.

## Components

### CapabilityLattice

Controls what tools/operations the agent can use autonomously:

```rust
use lattice_guard::{CapabilityLattice, CapabilityLevel};

let caps = CapabilityLattice {
    read_files: CapabilityLevel::Always,
    write_files: CapabilityLevel::LowRisk,
    edit_files: CapabilityLevel::LowRisk,
    run_bash: CapabilityLevel::Never,
    glob_search: CapabilityLevel::Always,
    grep_search: CapabilityLevel::Always,
    web_search: CapabilityLevel::LowRisk,
    web_fetch: CapabilityLevel::LowRisk,
    git_commit: CapabilityLevel::LowRisk,
    git_push: CapabilityLevel::LowRisk,
    create_pr: CapabilityLevel::LowRisk,
};
```

### Obligations

Obligations specify which operations require human approval:

```rust
use lattice_guard::{Obligations, Operation};

let mut obligations = Obligations::default();
obligations.insert(Operation::WebSearch);
obligations.insert(Operation::GitPush);
```

### PathLattice

Controls file system access with glob patterns and sandboxing:

```rust
use lattice_guard::PathLattice;
use std::path::Path;

// Block sensitive files
let paths = PathLattice::block_sensitive();
assert!(!paths.can_access(Path::new(".env")));
assert!(!paths.can_access(Path::new("secrets/api.key")));
assert!(paths.can_access(Path::new("src/main.rs")));

// Sandbox to a directory
let sandboxed = PathLattice::with_work_dir("/home/user/project");
```

### BudgetLattice

Controls cost and token limits with precision arithmetic:

```rust
use lattice_guard::BudgetLattice;

let mut budget = BudgetLattice::with_cost_limit(5.0);
assert!(budget.charge_f64(2.0));  // Returns true (within budget)
assert_eq!(budget.remaining_usd(), 3.0);
```

### CommandLattice

Controls shell command execution with proper parsing. Supports both string
allow/block rules and structured (program + argv) patterns:

```rust
use lattice_guard::CommandLattice;

let cmds = CommandLattice::default();
assert!(cmds.can_execute("cargo test"));
assert!(!cmds.can_execute("rm -rf /"));
assert!(!cmds.can_execute("\"sudo\" apt install"));  // Quoting bypass blocked

// Structured rules (program + args) for precision
let mut structured = CommandLattice::permissive();
structured.allow_rule(CommandPattern::exact("cargo", &["test"]));
structured.block_rule(CommandPattern {
    program: "bash".to_string(),
    args: vec![ArgPattern::AnyRemaining],
});
assert!(structured.can_execute("cargo test --release"));
assert!(!structured.can_execute("bash -c 'echo hi'"));
```

### TimeLattice

Controls temporal validity windows:

```rust
use lattice_guard::TimeLattice;

let time = TimeLattice::hours(2);
assert!(time.is_valid());
assert!(!time.is_expired());
```

## Delegation

Safely delegate permissions to subagents (monotonicity guaranteed):

```rust
use lattice_guard::PermissionLattice;

let parent = PermissionLattice::permissive();
let requested = PermissionLattice::default();

match parent.delegate_to(&requested, "code review task") {
    Ok(child_perms) => {
        // child_perms ≤ parent (guaranteed by the lattice structure)
        assert!(child_perms.leq(&parent));
    }
    Err(e) => println!("Delegation failed: {}", e),
}
```

## Builder Pattern

Use the builder for fluent construction:

```rust
use lattice_guard::{PermissionLattice, CapabilityLattice, BudgetLattice};

let perms = PermissionLattice::builder()
    .description("Code review task")
    .capabilities(CapabilityLattice::restrictive())
    .budget(BudgetLattice::with_cost_limit(1.0))
    .trifecta_constraint(true)
    .created_by("review-agent")
    .build();
```

## Preset Configurations

Common permission configurations:

```rust
use lattice_guard::PermissionLattice;

// Read-only: file reading and search only
let readonly = PermissionLattice::read_only();

// Code review: read + limited web search
let review = PermissionLattice::code_review();

// Fix issue: write + bash + git commit (PR requires approval)
let fix = PermissionLattice::fix_issue();

// Permissive: for trusted contexts (lattice-guard still enforced!)
let trusted = PermissionLattice::permissive();

// Restrictive: minimal permissions
let minimal = PermissionLattice::restrictive();
```

## Type-Safe Enforcement

Use `PermissionGuard` for compile-time enforcement:

```rust
use lattice_guard::{PermissionGuard, GuardedAction, GuardError};

// The GuardedAction type cannot be constructed without passing checks
fn execute_with_permission<A>(action: GuardedAction<A>) {
    // We know permission was checked because GuardedAction
    // can only be created by the guard system
    let inner = action.into_action();
    // ... execute
}
```

## Security Model

### What We Prevent

- Trifecta completion at autonomous levels
- Privilege escalation via delegation
- Budget inflation via negative charges
- Path traversal attacks
- Command injection via quoting
- Deserialization bypass of constraints
- Permission tampering (checksum verification)

### What We Do NOT Prevent

- Human approval of malicious actions (social engineering)
- Attacks within a single capability
- Side-channel attacks
- Kernel-level escapes

See [THREAT_MODEL.md](THREAT_MODEL.md) for the complete security model.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## References

- [The Lethal Trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) - Simon Willison
- [Container Hardening Against Agentic AI](https://securitytheatre.substack.com/p/container-hardening-against-agentic)
- [Nuclei in Locale Theory](https://ncatlab.org/nlab/show/lattice-guard) - nLab
