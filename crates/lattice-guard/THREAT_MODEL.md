# Threat Model

This document describes what lattice-guard protects against and, equally importantly, what it does NOT protect against.

## Overview

lattice-guard is a **permission lattice** that helps prevent the "lethal trifecta" attack in AI agents:

1. **Private Data Access** - reading files, credentials, secrets
2. **Untrusted Content Exposure** - web search, fetching URLs, external input
3. **Exfiltration Vector** - git push, PR creation, shell commands

When all three are present at autonomous levels, prompt injection attacks can exfiltrate private data.

## What We Prevent

### Trifecta Completion at Autonomous Levels

**Attack**: An agent configuration that allows autonomous (no human approval) access to all three trifecta elements.

**Prevention**: When the trifecta is detected (all three at `>= LowRisk`), exfiltration operations gain approval obligations, inserting a human checkpoint.

```
Private Data (Always) + Untrusted Content (LowRisk) + Exfiltration (LowRisk)
                                    ↓
                        Exfiltration requires approval
```

### Privilege Escalation via Delegation

**Attack**: A subagent requesting more permissions than its parent.

**Prevention**: The `delegate_to()` operation uses `meet()`, which always returns permissions `≤` parent. Mathematical property: `delegate(parent, request) ≤ parent`.

### Budget Inflation

**Attack**: Charging negative amounts to increase available budget.

**Prevention**:
- `charge()` rejects negative values
- `charge()` rejects zero values
- Uses `rust_decimal::Decimal` instead of `f64` to prevent precision exploits
- `charge_f64()` rejects NaN and Infinity

### Path Traversal

**Attack**: Using `../` sequences to access files outside the intended directory.

**Prevention**:
- Paths are canonicalized to resolve `..` and symlinks
- When `work_dir` is set, all paths must resolve within the sandbox
- Sensitive patterns (`.env*`, `*.key`, etc.) are blocked regardless of path

### Command Injection via Quoting

**Attack**: Using shell quoting tricks to bypass command blocklists (e.g., `"sudo"` instead of `sudo`).

**Prevention**:
- Commands are parsed using `shell-words` before checking against blocklists
- The actual command words are extracted, not just pattern-matched against the raw string
- Malformed commands (unbalanced quotes) are rejected

### Trifecta Bypass via Deserialization

**Attack**: Crafting a JSON payload with `trifecta_constraint: false` to disable the guard.

**Prevention**:
- Custom `Deserialize` implementation always sets `trifecta_constraint: true`
- The field value in JSON is ignored

### Permission Tampering

**Attack**: Modifying permissions after they're issued.

**Prevention**: `EffectivePermissions` includes a SHA-256 checksum of the lattice. `verify_integrity()` detects tampering.

## What We Do NOT Prevent

### Human Approval of Malicious Actions

**Limitation**: If a human approves a malicious action (e.g., clicking "Yes" on an exfiltration request), the system cannot prevent it.

**Why**: The trifecta guard adds approval obligations, not a hard deny. It relies on humans making good decisions.

**Mitigation**: Clear prompts, limited time windows, audit trails.

### Attacks Within a Single Capability

**Limitation**: If the agent has autonomous web_fetch AND autonomous read_files (but NO exfiltration), an attacker could still read data - they just can't exfiltrate it.

**Why**: We prevent the full attack chain, not individual steps.

**Mitigation**: Use more restrictive base permissions when possible.

### Side-Channel Attacks

**Limitation**: Timing attacks, error message oracle attacks, etc. are not addressed.

**Why**: This is a permission lattice, not a sandboxing runtime.

**Mitigation**: Use additional isolation (containers, seccomp, etc.).

### Kernel-Level Attacks

**Limitation**: If the agent can escape to kernel level, all bets are off.

**Why**: This is userspace permission modeling.

**Mitigation**: Use container isolation with seccomp profiles.

### Prompt Injection Leading to Subtler Attacks

**Limitation**: An injected prompt might convince the agent to do something harmful that doesn't involve the trifecta.

**Why**: We specifically target the data exfiltration attack pattern.

**Mitigation**: Defense in depth - prompt hardening, output filtering, monitoring.

### Race Conditions

**Limitation**: In a multi-threaded environment, permission checks and actions might race.

**Why**: This is a pure permission model, not a runtime enforcer.

**Mitigation**: Use the `PermissionGuard` trait for type-safe enforcement where the guard token must be passed to the action.

### Symbolic Link TOCTOU

**Limitation**: Time-of-check to time-of-use attacks with symlinks are partially mitigated but not fully prevented.

**Why**: We canonicalize paths, but the filesystem could change between check and use.

**Mitigation**: Use filesystem sandboxing (bind mounts, namespaces).

## Security Properties

### Monotonicity

Delegated permissions are always `≤` parent permissions:
```
∀ parent, child: delegate(parent, child) ≤ parent
```

### Trifecta Invariant

After applying the constraint, the trifecta cannot be complete at autonomous levels:
```
∀ caps: ¬is_trifecta_complete(apply_constraint(caps))
```

### Lattice Laws

The permission lattice satisfies standard lattice properties:
- **Commutative**: `a ∧ b = b ∧ a`
- **Associative**: `(a ∧ b) ∧ c = a ∧ (b ∧ c)`
- **Idempotent**: `a ∧ a = a`
- **Absorption**: `a ∧ (a ∨ b) = a`

These are verified by property-based tests using proptest.

## Trust Assumptions

1. **The Rust compiler is correct** - no memory safety issues in safe Rust
2. **Dependencies are not malicious** - we use well-known crates
3. **The system clock is accurate** - for time-based expiry
4. **Humans make reasonable decisions** - when approval is required
5. **The filesystem behaves correctly** - for path canonicalization

## Recommendations

1. **Always enable `trifecta_constraint`** - it's on by default
2. **Set `work_dir` for sandboxing** when using PathLattice
3. **Use short time windows** - `TimeLattice::minutes(30)` not `hours(24)`
4. **Use `PermissionGuard`** for type-safe enforcement
5. **Combine with container isolation** for defense in depth
6. **Audit delegation chains** - track `derived_from` links
7. **Monitor for budget exhaustion** - may indicate attack attempts

## Reporting Vulnerabilities

If you discover a security vulnerability in lattice-guard, please report it responsibly:

1. Do NOT open a public GitHub issue
2. Email security concerns to the maintainers
3. Allow 90 days for a fix before public disclosure

We take security seriously and will acknowledge your contribution.
