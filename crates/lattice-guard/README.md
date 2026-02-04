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

// Filesystem read-only: read + search with sensitive paths blocked
let fs_readonly = PermissionLattice::filesystem_readonly();

// Web research: read + web search/fetch
let research = PermissionLattice::web_research();

// Code review: read + limited web search
let review = PermissionLattice::code_review();

// Edit-only: write + edit without exec or web
let edit_only = PermissionLattice::edit_only();

// Local dev: write + shell without web
let local_dev = PermissionLattice::local_dev();

// Fix issue: write + bash + git commit (PR requires approval)
let fix = PermissionLattice::fix_issue();

// Release: git push/PR with approvals
let release = PermissionLattice::release();

// Network-only: web access only
let network_only = PermissionLattice::network_only();

// Database client: CLI access for db tools
let db_client = PermissionLattice::database_client();

// Permissive: for trusted contexts (lattice-guard still enforced!)
let trusted = PermissionLattice::permissive();

// Restrictive: minimal permissions
let minimal = PermissionLattice::restrictive();
```

## Mathematical Framework Extensions

The crate provides advanced mathematical structures for principled permission modeling:

### Frame Theory and Nucleus Operators

The nucleus operator is formalized as a proper frame-theoretic construct, enabling type-safe quotient lattices:

```rust
use lattice_guard::{
    frame::{Nucleus, TrifectaQuotient, SafePermissionLattice},
    PermissionLattice,
};

// Create the trifecta quotient nucleus
let nucleus = TrifectaQuotient::new();

// Project through the nucleus to get compile-time safety guarantee
let dangerous = PermissionLattice::permissive();
let safe = SafePermissionLattice::from_nucleus(&nucleus, dangerous);

// The inner lattice is guaranteed to be trifecta-safe
assert!(nucleus.is_fixed_point(safe.inner()));
```

The nucleus satisfies:
- **Idempotent**: `j(j(x)) = j(x)`
- **Deflationary**: `j(x) ≤ x`
- **Meet-preserving**: `j(x ∧ y) = j(x) ∧ j(y)`

### Heyting Algebra (Intuitionistic Implication)

Conditional permissions using the Heyting adjunction `(c ∧ a) ≤ b ⟺ c ≤ (a → b)`:

```rust
use lattice_guard::{
    heyting::{HeytingAlgebra, entails, permission_gap, ConditionalPermission},
    CapabilityLattice, CapabilityLevel,
};

let current = CapabilityLattice {
    read_files: CapabilityLevel::Always,
    ..CapabilityLattice::bottom()
};

let target = CapabilityLattice {
    read_files: CapabilityLevel::Always,
    web_fetch: CapabilityLevel::LowRisk,
    ..CapabilityLattice::bottom()
};

// Check entailment (does current imply target?)
assert!(entails(&current, &target) == false);

// Compute what's missing to reach target
let gap = permission_gap(&current, &target);
```

### Galois Connections (Trust Domain Translation)

Principled security label translation across trust domains:

```rust
use lattice_guard::{galois::presets, PermissionLattice};

// Create a bridge between internal and external domains
let bridge = presets::internal_external(
    "spiffe://internal.corp",
    "spiffe://partner.org",
);

// Translate permissions (security-preserving)
let internal = PermissionLattice::permissive();
let external = bridge.to_target(&internal);

// Round-trip shows information loss (deflationary closure)
let round_trip = bridge.round_trip(&internal);
assert!(round_trip.capabilities.leq(&internal.capabilities));
```

Available presets: `internal_external`, `production_staging`, `human_agent`, `read_only`.

### Modal Operators (Necessity and Possibility)

Distinguish what is **guaranteed** (□) from what is **achievable** (◇):

```rust
use lattice_guard::{
    modal::{ModalPermissions, ModalContext},
    PermissionLattice,
};

let perms = PermissionLattice::fix_issue();
let context = ModalContext::new(perms);

// Necessity: what can be done without approval
let guaranteed = context.necessary;

// Possibility: what could be achieved with escalation
let achievable = context.possible;

// Check if escalation is required
if context.requires_escalation() {
    println!("Operations needing approval: {:?}", context.escalation_required_for());
}
```

### Graded Monad (Composable Risk Tracking)

Track risk through computation chains with proper monad laws:

```rust
use lattice_guard::{
    graded::{Graded, RiskGrade, evaluate_with_risk},
    TrifectaRisk, PermissionLattice,
};

// Pure computation (no risk)
let safe: Graded<TrifectaRisk, i32> = Graded::pure(42);

// Chain computations, risk accumulates via composition
let result = safe
    .and_then(|x| Graded::new(TrifectaRisk::Low, x * 2))
    .and_then(|x| Graded::new(TrifectaRisk::Medium, x + 1));

assert_eq!(result.grade, TrifectaRisk::Medium); // max of grades

// Evaluate permission profile with automatic risk grading
let perms = PermissionLattice::fix_issue();
let graded = evaluate_with_risk(&perms, |p| p.description.clone());
```

The graded monad satisfies:
- **Left identity**: `pure(a).and_then(f) = f(a)`
- **Right identity**: `m.and_then(pure) = m`
- **Associativity**: `(m.and_then(f)).and_then(g) = m.and_then(|x| f(x).and_then(g))`

### Running the Examples

```bash
cargo run --example math_framework -p lattice-guard
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

### Security

- [The Lethal Trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) - Simon Willison
- [Container Hardening Against Agentic AI](https://securitytheatre.substack.com/p/container-hardening-against-agentic)
- [Lattice-based Access Control](https://en.wikipedia.org/wiki/Lattice-based_access_control) - Denning 1976, Sandhu 1993

### Mathematical Foundations

- [Nuclei in Locale Theory](https://ncatlab.org/nlab/show/nucleus) - nLab
- [Heyting Algebra](https://ncatlab.org/nlab/show/Heyting+algebra) - nLab
- [Galois Connections](https://en.wikipedia.org/wiki/Galois_connection) - Wikipedia
- [Graded Monads](https://ncatlab.org/nlab/show/graded+monad) - nLab
- [Modal Logic S4](https://plato.stanford.edu/entries/logic-modal/) - Stanford Encyclopedia
- [Sheaf Semantics for Noninterference](https://drops.dagstuhl.de/entities/document/10.4230/LIPIcs.FSCD.2022.5) - Sterling & Harper
