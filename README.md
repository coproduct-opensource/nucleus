# Nucleus

[![CI](https://github.com/coproduct-opensource/nucleus/actions/workflows/ci.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/ci.yml)
[![Security Audit](https://github.com/coproduct-opensource/nucleus/actions/workflows/audit.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/audit.yml)
[![Cargo Deny](https://github.com/coproduct-opensource/nucleus/actions/workflows/deny.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/deny.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/coproduct-opensource/nucleus/badge)](https://securityscorecards.dev/viewer/?uri=github.com/coproduct-opensource/nucleus)
[![Docs](https://img.shields.io/badge/docs-github.io-blue)](https://coproduct-opensource.github.io/nucleus/)

**A formally verified permission lattice and security runtime for AI agents.**

Nucleus is a security framework for AI agents that combines a mathematically verified permission algebra with a Firecracker-based enforcement runtime. The permission lattice has 297 SMT verification conditions checked by Z3. The GitHub Action works end-to-end today. This README tries to be honest about what's real and what isn't.

> **Versioning note:** v1.0 means the **interface contract is stable** (see [`STABILITY.md`](STABILITY.md)), not that the system is "production-secure by default." The lattice is heavily verified; the runtime is tested but not yet battle-hardened in production traffic.

## Start Here: Scan Your Agent Config

This works today. No runtime required. Not yet published to crates.io — install from source.

```bash
cargo install --git https://github.com/coproduct-opensource/nucleus nucleus-audit

# Scan a PodSpec for security issues
nucleus-audit scan --pod-spec your-agent.yaml

# Example output:
# ╔══════════════════════════════════════════════════════════════╗
# ║  Nucleus PodSpec Security Scan                              ║
# ╠══════════════════════════════════════════════════════════════╣
# ║  Pod: yolo-agent                                            ║
# ║  Policy: permissive                                         ║
# ║  Findings: 4 critical, 2 high, 1 medium                    ║
# ╠══════════════════════════════════════════════════════════════╣
# ║  [CRITICAL] Lethal trifecta: private data + untrusted       ║
# ║             content + exfiltration all at autonomous levels  ║
# ║  [CRITICAL] 7 credentials exposed — exceeds safe threshold  ║
# ║  [HIGH]     No network restrictions (full egress)           ║
# ║  [HIGH]     No VM isolation (no Firecracker/seccomp)        ║
# ╚══════════════════════════════════════════════════════════════╝
# Exit code: 1 (critical or high findings)
```

The scan checks for trifecta risk, permission surface area, network posture, isolation level, credential exposure, and timeout hygiene. Exit code is non-zero when critical or high findings exist — drop it into CI and block unsafe deployments.

```bash
# JSON output for CI pipelines
nucleus-audit scan --pod-spec agent.yaml --format json

# Verify hash-chained audit logs
nucleus-audit verify --audit-log /var/log/nucleus/agent.jsonl
```

## The Lethal Trifecta

The core security primitive. When an agent has all three capabilities at autonomous levels, prompt injection becomes data exfiltration:

```
  Private Data Access    +    Untrusted Content    +    Exfiltration Vector
  ─────────────────────       ──────────────────        ────────────────────
  read_files ≥ LowRisk       web_fetch ≥ LowRisk      git_push ≥ LowRisk
  read_env                    web_search ≥ LowRisk     create_pr ≥ LowRisk
  database access             user input processing    run_bash (curl, etc)
```

Nucleus detects this combination statically (via `nucleus-audit scan`) and enforces it at runtime (via `portcullis`). When the trifecta is complete, exfiltration operations require **explicit human approval** — the agent cannot bypass this.

The trifecta guard's monotonicity is formally proven: once an operation is denied, it stays denied for the rest of the session (proofs E1-E3 in `portcullis-verified`).

## What Nucleus Provides

Three layers, at different levels of maturity:

1. **Scan** (usable today) — Static analysis of agent PodSpecs. Catches dangerous permission combinations before deployment. Works as a standalone CLI tool.

2. **Enforce** (working in CI, not production-hardened) — Runtime permission envelopes. The tool proxy intercepts every agent side effect and checks it against the permission lattice. Both HTTP and MCP paths share identical security controls (MIME gating, DNS/URL allowlists, redirect verification). The `--local` path works end-to-end in GitHub Actions. The Firecracker path works on Linux+KVM but has no production deployment.

3. **Audit** (implemented, not production-tested) — Hash-chained, HMAC-signed logs of every agent action with optional S3 append-only remote sink. Local verification tool exists and works on generated test logs. S3 sink compiles into production binaries but has no integration test against real S3. No production audit logs exist yet.

## Current Status

| Component | Maturity | Evidence |
|-----------|----------|----------|
| **Permission lattice** (portcullis) | Verified | 43K LOC, 875 tests, 297 Verus VCs, 3 fuzz targets |
| **Trifecta detection** | Verified | Static scan + runtime guard, monotonicity proven (E1-E3) |
| **Web fetch security** | Tested | Unified MCP+HTTP path: MIME gating, DNS/URL allowlist, redirect verification, IPv6 |
| **Audit log verification** | Tested | HMAC-SHA256 + SHA-256 chain; optional S3 append-only sink (no integration test) |
| **PodSpec scanner** | Tested | Trifecta, credentials, network, isolation, timeout checks |
| **Permission profiles** | Tested | 14 named profiles backed by lattice constructors |
| **Tool proxy** (MCP enforcement) | Tested | 9,500 LOC, 119 tests; enforces agent sessions in GitHub Actions |
| **Firecracker isolation** | Tested | Real jailer invocation + iptables; Linux+KVM only |
| **Network enforcement** | Tested | Default-deny egress, DNS allowlisting, drift detection |
| **CI hardening** | Tested | 14 required status checks; mutation testing blocks surviving mutants |
| **Budget tracking** | Partial | AtomicBudget exists; pre-exec reservation works, post-exec accounting incomplete |
| **SPIFFE identity** | Implemented | mTLS + cert management code exists; no SPIRE deployment |
| **Command exfiltration detection** | Partial | Program-name matching; `bash -c` bypasses documented |
| **Lean 4 model** | Not started | Planned: Aeneas translation for deeper mathematical verification |

**Maturity key:** *Verified* = SMT proofs + tests. *Tested* = compiles, has passing tests, never deployed. *Partial* = works for some cases, known gaps. *Implemented* = code exists, minimal testing. *Not started* = in roadmap only.

## Permission Lattice

Permissions compose predictably via a mathematical lattice. This is the most mature part of Nucleus — 43K lines of Rust with 297 machine-checked verification conditions.

| Structure | What It Gives You | Status |
|-----------|-------------------|--------|
| **Quotient Lattice** | Trifecta detection as a structural nucleus operator | Verified (Verus) |
| **Heyting Algebra** | Conditional permissions with formal semantics | Verified (Verus) |
| **Galois Connections** | Policy translation across trust domains | Verified (Verus) |
| **Graded Monad** | Risk accumulation through computation chains | Verified (Verus) |
| **Modal Operators** | Distinguish "guaranteed safe" (□) from "might be safe" (◇) | Tested |
| **Delegation Chains** | SPIFFE-backed delegation with ceiling theorem | Tested |

For the theory: [docs/THEORY.md](docs/THEORY.md).

## Formal Verification

Nucleus uses [Verus](https://verus-lang.github.io/verus/) (SMT-based verification for Rust, SOSP 2025 Best Paper) to prove properties about the permission lattice.

**What's proven (297 verification conditions, machine-checked by Z3):**
- Lattice laws: idempotent, commutative, associative, absorptive for all 12 capability dimensions
- Nucleus operator: idempotent, deflationary, monotone, meet-preserving
- Heyting adjunction: a ∧ b ≤ c ⟺ a ≤ b → c
- Galois connection: adjunction, closure/kernel properties, monotonicity
- Graded monad: identity, associativity, composition laws
- Taint guard: monotonicity (E1), trace monotonicity (E2), denial monotonicity (E3)
- Trifecta: completeness detection, risk classification, session safety
- Delegation: transitivity, ceiling theorem, chain composition

**What's tested but not formally verified:**
- Modal operators (necessity/possibility, S4 axioms) — 16 property tests
- Weakening cost model — 15 property tests
- Full PermissionLattice composition — 130 proptest invariants
- Adversarial inputs — 70 OWASP-inspired attack scenarios

**What's planned but not started:**
- Lean 4 mathematical model via Aeneas (Phase 1)
- Full enforcement boundary verification (Phase 2 — started with E1-E3)
- Differential testing: Rust engine vs Lean model (Phase 3)
- Extended TCB verification: sandbox, credentials, tool proxy (Phase 4)

See the full roadmap: [docs/north-star.md](docs/north-star.md).

The Verus VC count is ratcheted in CI — it can only go up, never down (`.verus-minimum-proofs`). Merging to `main` requires 14 status checks to pass, including security audit, cargo deny, clippy, fmt, and per-crate test suites. Mutation testing (cargo-mutants) blocks merges when surviving mutants are detected.

## v1.0 Contract Surface

The v1.0 interfaces are designed for 15 years of growth. See [`STABILITY.md`](STABILITY.md) for the full frozen/open contract table.

**Frozen at v1.0** (breaking changes require v2.0):
- 12 core `Operation` variants + taint classifications
- 3 core `TaintLabel` variants + trifecta predicate
- `CapabilityLevel` enum (`Never`, `LowRisk`, `Always`)
- gRPC `NodeService` RPCs, HMAC signing protocol, audit hash chain

**Open for extension** (no version bump needed):
- New operations via `ExtensionOperation` on `CapabilityLattice` (fail-closed: unknown ops default to `Never`)
- New taint labels via `ExtensionTaintLabel` on `TaintSet` (don't affect core trifecta)
- New dangerous combinations via `ConstraintNucleus` (trifecta always slot 0, can't be removed)
- Versioned `ExecutionReceipt` with `v1_content_hash` for forward-compatible verification
- `WorkspaceGuard` trait for multi-agent shared taint (interface only in v1.0)

Proofs survive extensions by construction: products of lattices are lattices (universal property in **Lat**), powersets preserve join-semilattice laws, and composition of deflationary endomorphisms is deflationary. No Verus re-verification needed.

## Runtime Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Your Agent                               │
├─────────────────────────────────────────────────────────────────┤
│  nucleus-cli / nucleus-audit scan                               │
│  (enforce at runtime / catch misconfigs before deploy)          │
├─────────────────────────────────────────────────────────────────┤
│                         nucleus                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │   Sandbox    │  │   Executor   │  │   AtomicBudget       │  │
│  │  (cap-std)   │  │  (process)   │  │   (lock-free)        │  │
│  └──────────────┘  └──────────────┘  └──────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                      portcullis                                 │
│   Capabilities × Obligations × Paths × Commands × Budget × Time │
│   + Heyting Algebra + Galois Connections + Graded Monad + Modal │
├─────────────────────────────────────────────────────────────────┤
│                    nucleus-identity                             │
│           SPIFFE workload identity + mTLS + cert rotation       │
├─────────────────────────────────────────────────────────────────┤
│           Firecracker microVM / seccomp / netns                 │
│           (Linux + KVM required; not available on macOS)        │
└─────────────────────────────────────────────────────────────────┘
```

The enforcement path: Agent → MCP → tool-proxy (inside VM) → portcullis check → OS operation. Every side effect goes through the proxy. The proxy is the only process in the guest. Network egress is default-deny with iptables rules applied *before* the VM starts.

## Crates

| Crate | Purpose | Tests |
|-------|---------|-------|
| **portcullis** | Permission lattice: 9 algebraic modules | 875 |
| **portcullis-verified** | Verus SMT proofs for portcullis | 297 VCs |
| **nucleus-audit** | `scan` PodSpecs; `verify` hash-chained audit logs | 14 |
| **nucleus** | Enforcement: sandbox, executor, budget | 89 |
| **nucleus-node** | Node daemon managing Firecracker microVMs | 26 |
| **nucleus-tool-proxy** | MCP tool proxy running inside pods | 119 |
| **nucleus-mcp** | MCP server bridging to tool-proxy | 4 |
| **nucleus-identity** | SPIFFE workload identity, mTLS, certs | 44 |
| **nucleus-spec** | PodSpec definitions (policy, network, creds) | 21 |
| **nucleus-cli** | CLI for running tasks with enforced permissions | 12 |
| **nucleus-sdk** | Rust SDK for building sandboxed AI agents | 3 |
| **nucleus-client** | Client signing utilities | 8 |
| **nucleus-guest-init** | Guest init for Firecracker rootfs | 2 |
| **nucleus-net-probe** | TCP probe for network policy tests | 2 |
| **trifecta-playground** | Interactive TUI for exploring the lattice | — |

Total: ~1,550 test functions across the workspace. Proptest invariants each generate 256 random cases.

## Permission Profiles

```bash
nucleus profiles

# Available profiles:
#   restrictive        Minimal permissions (default)
#   read_only          File reading and search only
#   code_review        Read + limited search
#   edit_only          Write + edit, no execution
#   fix_issue          Write + bash + git commit (no push/PR)
#   safe_pr_fixer      Write + bash + commit + web fetch (no push/PR/search)
#   local_dev          Full local development, no network
#   web_research       Read + web access, no writes
#   network_only       Network access, no filesystem
#   release            Full pipeline including push + PR
#   full               Everything (trifecta gates still enforced!)
#   + 3 more domain-specific profiles
```

## Custom Permissions

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

## Example PodSpecs

See [`examples/podspecs/`](examples/podspecs/) for real configurations:

- **`airgapped-review.yaml`** — Code review in a fully airgapped Firecracker VM with seccomp
- **`secure-codegen.yaml`** — Code generation with filtered network (crates.io, npm, GitHub only)
- **`permissive-danger.yaml`** — Intentionally insecure config for testing `nucleus-audit scan`

## GitHub Action: Safe PR Fixer

Drop this into any repo to get nucleus-enforced issue fixes:

```yaml
- uses: coproduct-opensource/nucleus@v1.0.2
  with:
    issue-number: "123"
    api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    profile: safe_pr_fixer     # write + bash + commit + web fetch, no push/PR
    timeout: "600"
    # model: "claude-sonnet-4-20250514"   # default
```

**How it works:**
1. Installs `nucleus-cli`, `nucleus-tool-proxy`, and `nucleus-mcp` from [GitHub Releases](https://github.com/coproduct-opensource/nucleus/releases)
2. Installs Claude Code CLI
3. Builds a prompt from the issue body
4. Runs `nucleus run --local --profile safe_pr_fixer` — the tool-proxy enforces the permission lattice on every agent side effect
5. If the agent produced commits, a trusted CI script pushes the branch and opens a PR

The agent **cannot push or create PRs** — only the trusted CI wrapper does that. The `safe_pr_fixer` profile blocks `git_push`, `create_pr`, and `web_search`.

**Trust ladder:**
| Tier | What | Isolation |
|------|------|-----------|
| **Tier 0** | `nucleus-audit scan` in CI | Static analysis, no runtime |
| **Tier 1** | `nucleus run --local` (GitHub Action) | Tool-proxy lattice enforcement, no VM |
| **Tier 2** | `nucleus run` with Firecracker | microVM + netns + default-deny egress |

The GitHub Action uses Tier 1 (`--local`). Network enforcement relies on the permission lattice, not default-deny iptables. For full containment, use Tier 2 with Firecracker on Linux+KVM.

## Known Gaps

Documented in detail in [`SECURITY_TODO.md`](SECURITY_TODO.md). Key items:

- **Command exfiltration detection is program-name only.** `bash -c 'curl ...'` can bypass trifecta detection at the command lattice level. The Firecracker network policy is the real defense (default-deny egress), but the command-level check has known bypasses.
- **Path sandboxing is string-based.** Unicode normalization and symlink race conditions are not exhaustively tested. `cap-std` capability handles provide defense-in-depth.
- **Budget enforcement is partial.** Pre-execution reservation works when timeouts are set. Post-execution cost accounting (output tokens, refunds) is not implemented.
- **Formal verification covers the lattice algebra, not the full runtime.** The 297 Verus VCs verify portcullis properties. The tool proxy, network enforcement, and Firecracker integration are tested, not verified.
- **S3 audit sink is fire-and-forget.** Upload failures are logged but don't block the agent. No integration test against real S3 exists. Append-only semantics use `if_none_match("*")` PutObject preconditions — untested against eventual consistency.
- **Redirect following is reqwest default (10 hops).** The final URL is checked against DNS/URL allowlists after all redirects complete, but intermediate hops are not validated. An allowlisted domain with an open redirect to a non-allowlisted domain will be caught, but the request still reaches the intermediate servers.
- **`--local` mode has weaker isolation than Firecracker.** The tool-proxy enforces lattice permissions, but there is no VM boundary or default-deny network. Use Tier 2 (Firecracker) for high-security workloads.

## Threat Model

**Protects against:**
- Prompt injection attempting side effects outside the permission envelope
- Misconfigured tool permissions (enforced at runtime, not advisory)
- Network policy drift inside the runtime (fail-closed)
- Budget exhaustion attacks (atomic tracking, with caveats above)
- Privilege escalation via delegation (ceiling theorem)
- Trust domain confusion (Galois connections)
- Audit log tampering (hash chain verification)

**Does not protect against:**
- Compromised host or kernel (enforcement stack is trusted)
- Malicious human approvals (social engineering)
- Side-channel attacks
- Kernel escapes from the microVM
- `bash -c` indirection at the command parsing level (network policy is the backstop)

## Development

```bash
cargo build --workspace
cargo test --workspace
cargo run -p trifecta-playground  # Interactive lattice explorer
```

Requires Rust stable. Firecracker features require Linux with KVM. macOS development works for everything except VM isolation.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.

## References

- [The Lethal Trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/) — Simon Willison
- [Container Hardening Against Agentic AI](https://securitytheatre.substack.com/p/container-hardening-against-agentic)
- [Lattice-based Access Control](https://en.wikipedia.org/wiki/Lattice-based_access_control) — Denning 1976, Sandhu 1993
- [Verus: Verified Rust for Systems Code](https://verus-lang.github.io/verus/) — SOSP 2025 Best Paper
- [AWS Cedar Formal Verification](https://www.amazon.science/blog/how-we-built-cedar-with-automated-reasoning-and-differential-testing)
- [cap-std](https://github.com/bytecodealliance/cap-std) — Capability-based filesystem
