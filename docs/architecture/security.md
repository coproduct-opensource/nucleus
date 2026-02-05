# Security Architecture

Nucleus is built with security as a foundational principle, not an afterthought. This document describes the security guarantees, defense-in-depth layers, and compliance positioning.

## Executive Summary

**Nucleus provides:**
- Memory-safe runtime (100% Rust) eliminating ~70% of security vulnerabilities
- Cryptographic workload identity (SPIFFE/mTLS) instead of shared secrets
- Enforced permission boundaries (not advisory configuration)
- Defense-in-depth with multiple independent security layers

**Regulatory alignment:**
- CISA Secure by Design mandate (memory-safety roadmaps required by Jan 2026)
- NSA/CISA guidance on memory-safe programming languages
- White House directive on memory-safe code in critical infrastructure

---

## Memory Safety: The Foundation

### Why Rust Matters

According to Microsoft, Google, and NSA research, approximately **70% of security vulnerabilities** are memory safety issues:
- Buffer overflows
- Use-after-free
- Null pointer dereferences
- Double frees
- Data races

Rust eliminates these vulnerability classes at compile time through its ownership system. Every line of Nucleus is written in Rust with no unsafe escape hatches in security-critical paths.

### CISA Alignment

The Cybersecurity and Infrastructure Security Agency (CISA) now requires:
- Memory-safety roadmaps from critical infrastructure software providers (deadline: January 1, 2026)
- Adoption of memory-safe languages for new development
- Elimination of memory-unsafe code in security-critical components

Nucleus is **memory-safe by default**, requiring no roadmap transition.

---

## Identity: SPIFFE/mTLS

### No Shared Secrets

Traditional approaches use shared secrets (API keys, tokens) that can be:
- Leaked in logs
- Stolen from environment variables
- Intercepted in transit
- Replayed by attackers

Nucleus uses **SPIFFE workload identity**:

```
spiffe://trust-domain/ns/namespace/sa/service-account
```

Every workload receives a cryptographic identity (X.509 SVID) that:
- Cannot be forged without CA compromise
- Is bound to the workload, not a human-managed secret
- Enables mutual TLS (mTLS) for all service communication
- Supports automatic rotation without service disruption

### mTLS Everywhere

All communication between Nucleus components uses mutual TLS:
- Client authenticates to server
- Server authenticates to client
- Traffic is encrypted
- No party can impersonate another

```
┌─────────────────┐     mTLS      ┌─────────────────┐
│   Orchestrator  │──────────────>│   Tool Proxy    │
│                 │<──────────────│                 │
│ Client SVID     │               │ Server SVID     │
└─────────────────┘               └─────────────────┘
        │                                 │
        └───── Same Trust Domain ─────────┘
              (CA validates both)
```

---

## Isolation: Defense in Depth

Nucleus implements multiple independent security layers:

### Layer 1: Firecracker MicroVMs

Each agent task runs in a dedicated Firecracker microVM:
- Separate kernel instance
- Isolated memory space
- No shared filesystem (except explicit mounts)
- Hardware-enforced separation

### Layer 2: Network Namespace Isolation

Each pod gets its own network namespace:
- Default-deny egress
- Explicit DNS allowlisting
- iptables policy with drift detection (fail-closed)
- No access to host network

### Layer 3: Capability-Based Filesystem

File access uses cap-std for capability-based security:
- No ambient authority
- Must explicitly open files through capability handles
- Path traversal attacks blocked at syscall level

### Layer 4: Policy Enforcement (lattice-guard)

The permission lattice provides mathematical guarantees:
- Capabilities can only tighten through composition
- Dangerous combinations (trifecta) trigger additional gates
- No silent policy relaxation

### Layer 5: Environment Isolation

Spawned processes receive only explicitly allowed environment variables:
- Parent environment is cleared (`env_clear()`)
- Only allowlisted variables are passed
- Prevents secret leakage from orchestrator to sandbox

---

## The Lethal Trifecta

Nucleus specifically guards against the [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/):

```
Private Data    +    Untrusted Content    +    Exfiltration Vector
    │                      │                         │
    ▼                      ▼                         ▼
read_files              web_fetch                 git_push
glob_search             web_search                create_pr
grep_search                                       run_bash (curl)
```

When all three are present at autonomous levels, Nucleus:
1. Detects the dangerous combination
2. Adds approval obligations to exfiltration operations
3. Requires human-in-the-loop confirmation

This prevents prompt injection attacks from silently exfiltrating sensitive data.

---

## Input Validation

All external inputs are validated at API boundaries:

### Length Limits

| Input Type | Maximum Length | Rationale |
|------------|----------------|-----------|
| Glob/Regex patterns | 1,024 bytes | Prevent ReDoS |
| Search queries | 512 bytes | Prevent resource exhaustion |
| File paths | 4,096 bytes | Match filesystem limits |
| Command arguments | 16,384 bytes total | Prevent shell injection |
| stdin content | 1 MB | Prevent memory exhaustion |
| URLs | 2,048 bytes | Match browser limits |

### ReDoS Protection

Regular expression patterns are scanned for catastrophic backtracking:
- Nested quantifiers: `(a+)+`
- Overlapping alternation: `(a|a)+`
- Excessive repetition: `a{1000,}`

Dangerous patterns are rejected before execution.

### Path Validation

All paths are:
- Canonicalized to resolve symlinks and `..`
- Checked against sandbox boundaries
- Validated against allowlist/blocklist patterns

---

## Audit Logging

Every operation is logged with:
- Timestamp (monotonic + wall clock)
- Request ID (correlation)
- Operation type and parameters
- Outcome (success, denied, error)
- Principal identity (SPIFFE ID)
- Audit context (additional metadata)

### What Gets Logged

| Event Type | Details |
|------------|---------|
| Successful operations | Operation, subject, result |
| Policy denials | Reason, attempted operation |
| Validation failures | Field, error |
| Authentication failures | Reason, attempted identity |
| System errors | Error code, context |

### Hash-Chained Integrity

Audit logs are hash-chained using SHA-256:
- Each entry includes hash of previous entry
- Tampering is detectable
- Gaps are detectable
- Verified with `nucleus-audit`

---

## Error Handling

Error messages are sanitized before returning to clients:

| Internal | Sanitized |
|----------|-----------|
| `/var/sandbox/abc123/secrets/token.txt` | `[sandbox]/secrets/token.txt` |
| `/home/user/.config/credentials` | `[home]/.config/credentials` |
| `/etc/passwd` | `[path]` |

This prevents information disclosure that could aid attackers in understanding internal structure.

---

## Approval System

Security-sensitive operations require explicit approval:

### Approval Flow

1. Operation triggers approval requirement
2. Approval request generated with nonce
3. Human reviews and approves/denies
4. Approval token issued (HMAC-signed)
5. Token validated before operation proceeds
6. Token is single-use (nonce replay protection)

### Token Security

- HMAC-SHA256 signed
- Bound to specific operation
- Time-limited expiry
- Nonce prevents replay
- Cannot be forged without secret

---

## Budget Enforcement

Resource usage is tracked and limited:

### Cost Model

| Operation | Cost Basis |
|-----------|------------|
| Command execution | Base + per-second |
| File I/O | Per KB read/written |
| Network requests | Per request |
| Search operations | Per result/match |

### Enforcement

- Budget is checked before operation starts
- Reservation model prevents races
- Atomic tracking for concurrent access
- Operations fail cleanly when budget exhausted

---

## Compliance Positioning

### CISA Secure by Design

| Requirement | Nucleus Status |
|-------------|----------------|
| Memory-safe language | Rust (100%) |
| Memory-safety roadmap | Not needed (already compliant) |
| Input validation | Comprehensive |
| Secure defaults | Yes |

### SOC 2 Alignment

| Control | Implementation |
|---------|----------------|
| Access control | SPIFFE/mTLS, capability-based |
| Audit logging | Hash-chained, comprehensive |
| Change management | Policy as code |
| Incident response | Fail-closed, drift detection |

### OWASP Top 10

| Vulnerability | Mitigation |
|---------------|------------|
| Injection | Input validation, parameterized commands |
| Broken auth | mTLS, no shared secrets |
| Sensitive data exposure | Environment isolation, error sanitization |
| XXE | No XML parsing in critical paths |
| Broken access control | Capability-based, enforced policy |
| Security misconfiguration | Secure defaults, drift detection |
| XSS | Not applicable (no web UI) |
| Insecure deserialization | Serde with strict schemas |
| Using vulnerable components | cargo-deny, security audits |
| Insufficient logging | Comprehensive audit trail |

---

## Security Testing

### Automated

- **cargo-deny**: License and vulnerability scanning
- **cargo-audit**: CVE database checks
- **Property tests**: Lattice laws, ν properties
- **Adversarial tests**: Path traversal, command injection
- **mTLS tests**: Certificate validation, trust boundaries

### Planned

- **Fuzzing**: Command parsing, path normalization, policy deserialization
- **Formal verification**: Core lattice properties (Kani proofs)

---

## Non-Goals

Nucleus does not protect against:

| Threat | Reason |
|--------|--------|
| Host kernel compromise | Enforcement stack must be trusted |
| Side-channel attacks | Requires hardware mitigations |
| Malicious human approvals | Social engineering is out of scope |
| VM escape | Firecracker hardening is assumed |

---

## References

- [CISA Secure by Design](https://www.cisa.gov/secure-by-design)
- [NSA Guidance on Memory Safe Languages](https://media.defense.gov/2022/Nov/10/2003112742/-1/-1/0/CSI_SOFTWARE_MEMORY_SAFETY.PDF)
- [The Lethal Trifecta - Simon Willison](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)
- [SPIFFE Specification](https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/)
- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [Firecracker Security](https://firecracker-microvm.github.io/docs/security/)
