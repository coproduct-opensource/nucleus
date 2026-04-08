# Nucleus

[![CI](https://github.com/coproduct-opensource/nucleus/actions/workflows/ci.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/ci.yml)
[![Security Audit](https://github.com/coproduct-opensource/nucleus/actions/workflows/audit.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/audit.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/coproduct-opensource/nucleus/badge)](https://securityscorecards.dev/viewer/?uri=github.com/coproduct-opensource/nucleus)

**Nucleus prevents AI coding agents from combining untrusted input with privileged actions, and proves what was and wasn't allowed.**

Two primitives — `join` and `flows_to` — enforce information flow control with four algebraic laws. Once web content enters a session, it cannot silently reach `git push`. That property is [machine-checked](FORMAL_METHODS.md), not hoped.

```rust
let mut state = FlowState::bottom();          // clean session
state.join_operation(Operation::WebFetch);     // tainted by web content
assert!(!state.flows_to(SinkClass::GitPush));  // can't push tainted data
```

## Quick Start

```bash
cargo install --git https://github.com/coproduct-opensource/nucleus nucleus-claude-hook
nucleus-claude-hook --setup    # wires into your AI coding assistant
nucleus-claude-hook --smoke-test
```

Every tool call now flows through the permission kernel. The hook tracks data provenance and blocks dangerous combinations — like writing code derived from untrusted web content.

## What Gets Proved

| Claim | What it means for you | Evidence | Known gap |
|-------|----------------------|----------|-----------|
| Taint is monotone | Once web content contaminates a session, the agent cannot silently regain trusted status | [Lean 4 + Kani](docs/verified-claims.md#2-taint-is-monotone-no-silent-cleansing) | Depends on correct labeling at integration boundaries |
| Adversarial integrity absorbs | One drop of adversarial input contaminates the entire result — no dilution | [Lean 4](docs/verified-claims.md#3-adversarial-integrity-is-absorbing) | Content must be labeled adversarial at source |
| Obligation bypass is a type error | Side effects require a `DischargedBundle` that can only come from a passed policy check | [Compile-fail test](docs/verified-claims.md#6-obligation-bypass-is-a-type-error) | 146 call sites still bypass the effect layer ([#1216](https://github.com/coproduct-opensource/nucleus/issues/1216)) |
| Permissions are a Heyting algebra | Restricting permissions always produces a valid, less-permissive result | [Kani + Lean](docs/verified-claims.md#5-capability-lattice-is-a-distributive-heyting-algebra) | 13 dimensions may not cover every use case |
| Secret data cannot flow to public sinks | Session-level confidentiality ceiling prevents laundering through intermediaries | [21 unit tests + compile-fail](docs/verified-claims.md#7-confidentiality-downflow-is-enforced) | Mislabeled data bypasses the check |
| Receipt chains detect tampering | Hash-chained, signed audit trail for every agent action | [Tests](docs/verified-claims.md) | Append-only property not formally proved |

Full inventory: 165 Lean 4 theorems (zero `sorry`), 112 Kani BMC proofs, 297 Verus VCs, ~2,850 tests. [Verified Claims](docs/verified-claims.md) | [Formal Methods](FORMAL_METHODS.md) | [Production Delta](docs/production-delta.md)

## The Flow Algebra

| Law | What it means | What it enables |
|-----|---------------|-----------------|
| `a ⊔ b = b ⊔ a` | Join is commutative | Safe parallel execution |
| `a ⊔ (b ⊔ c) = (a ⊔ b) ⊔ c` | Join is associative | Order-independent ratchet |
| `a ⊔ a = a` | Join is idempotent | Provably safe caching |
| `a ≤ a ⊔ b` | Join is monotone | Taint never decreases |

## How Nucleus Stops Real Exploits

| CVE | Attack | Why it worked | Nucleus defense |
|-----|--------|---------------|-----------------|
| [CVE-2025-53773](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/) | Copilot RCE via prompt injection | Security was a JSON config flag the agent could edit | Security is compiled types (`Discharged<O>`), not config |
| [CVE-2025-32711](https://www.hackthebox.com/blog/cve-2025-32711-echoleak-copilot-vulnerability) | EchoLeak — zero-click exfiltration via hidden prompt in Word doc | No concept of "internal data cannot leave" | [Bidirectional IFC](docs/theory/ifc-semilattice.md) blocks internal→public flow |
| [MCP Tool Poisoning](https://arxiv.org/html/2509.10540v1) | Malicious MCP server injects hidden instructions | Tool responses treated as trusted | MCP responses labeled `Adversarial` at the type level |

## Three Deployment Tiers

| Tier | What | Isolation | Status |
|------|------|-----------|--------|
| **0 — Scan** | `nucleus-audit scan` in CI | Static analysis, no runtime | Usable today |
| **1 — Enforce** | `nucleus run --local` / Claude hook | Tool-proxy lattice enforcement | Working in CI |
| **2 — Isolate** | `nucleus run` with Firecracker | microVM + netns + default-deny egress | Linux+KVM only |

## Architecture

```
Agent → MCP → tool-proxy (inside VM) → portcullis check → OS operation
```

```
┌──────────────────────────────────────────────┐
│  nucleus-cli / nucleus-audit scan            │
├──────────────────────────────────────────────┤
│  nucleus (Sandbox + Executor + AtomicBudget) │
├──────────────────────────────────────────────┤
│  portcullis (7 control planes)               │
│  Capabilities × Obligations × Paths ×        │
│  Commands × Budget × Time + DPI              │
├──────────────────────────────────────────────┤
│  nucleus-identity (SPIFFE + mTLS)            │
├──────────────────────────────────────────────┤
│  Firecracker microVM / seccomp / netns       │
└──────────────────────────────────────────────┘
```

## Crates

<details>
<summary>User-facing tools (5 crates)</summary>

| Crate | Purpose |
|-------|---------|
| [**nucleus-claude-hook**](crates/nucleus-claude-hook/) | Hook for AI coding assistants: IFC kernel, compartments, provenance |
| [**nucleus-audit**](crates/nucleus-audit/) | Scan agent configs, verify audit trails, inspect provenance |
| [**nucleus-cli**](crates/nucleus-cli/) | Run AI agents under enforced permissions |
| [**nucleus-sdk**](crates/nucleus-sdk/) | Rust SDK for building sandboxed AI agents |
| [**exposure-playground**](crates/exposure-playground/) | Interactive TUI for exploring the permission lattice |

</details>

<details>
<summary>Core libraries (14 crates)</summary>

| Crate | Purpose |
|-------|---------|
| [**portcullis**](crates/portcullis/) | Permission lattice: algebraic modules, attenuation tokens, egress policy, DPI |
| [**portcullis-core**](crates/portcullis-core/) | Core types: `CapabilityLevel`, IFC labels, flow graph, witness bundles |
| [**ck-kernel**](crates/ck-kernel/) | Constitutional kernel: admission engine + lineage |
| [**ck-types**](crates/ck-types/) | Constitutional kernel core types and manifests |
| [**ck-policy**](crates/ck-policy/) | Constitutional kernel policy monotonicity checks |
| [**nucleus**](crates/nucleus/) | Enforcement: cap-std sandbox, executor, budget tracking |
| [**nucleus-tool-proxy**](crates/nucleus-tool-proxy/) | MCP tool proxy (permission enforcement gateway) |
| [**nucleus-mcp**](crates/nucleus-mcp/) | MCP server bridging to tool-proxy |
| [**nucleus-identity**](crates/nucleus-identity/) | SPIFFE workload identity, mTLS, certificate management |
| [**nucleus-ifc**](crates/nucleus-ifc/) | Standalone IFC library for AI agents |
| [**nucleus-memory**](crates/nucleus-memory/) | Governed memory with per-entry IFC labels |
| [**nucleus-spec**](crates/nucleus-spec/) | PodSpec definitions (policy, network, credentials) |
| [**nucleus-proto**](crates/nucleus-proto/) | Generated gRPC/Protobuf types |
| [**nucleus-client**](crates/nucleus-client/) | Client signing utilities + drand anchoring |

</details>

<details>
<summary>Infrastructure (5 crates)</summary>

| Crate | Purpose |
|-------|---------|
| [**nucleus-node**](crates/nucleus-node/) | Node daemon managing Firecracker microVMs + containers |
| [**nucleus-permission-market**](crates/nucleus-permission-market/) | Lagrangian pricing oracle for capability constraints |
| [**nucleus-guest-init**](crates/nucleus-guest-init/) | Guest init for Firecracker rootfs |
| [**ctf-engine**](crates/ctf-engine/) | Formally verified sandbox CTF challenge engine |
| [**ctf-server**](crates/ctf-server/) | HTTP API server for The Vault CTF |

</details>

Total: ~2,850 tests across the workspace (162K LOC Rust).

## Known Gaps

Documented in [`SECURITY_TODO.md`](SECURITY_TODO.md) and [`docs/production-delta.md`](docs/production-delta.md). Key items:

- **`bash -c` bypasses command-level checks.** Firecracker network policy is the real defense.
- **Path sandboxing is string-based.** `cap-std` provides defense-in-depth.
- **Budget enforcement is partial.** Pre-execution reservation works; post-execution accounting is not.
- **Formal verification covers the lattice, not the full runtime.** See [FORMAL_METHODS.md](FORMAL_METHODS.md).
- **Hook I/O boundary is unverified.** JSON parsing is a trusted edge.

## Threat Model

**Protects against:** prompt injection side effects, invisible Unicode injection, misconfigured permissions, network policy drift, budget exhaustion, privilege escalation via delegation, audit log tampering.

**Does not protect against:** compromised host/kernel, malicious human approvals, side-channel attacks, VM kernel escapes.

> **Versioning:** v1.0 means the **interface contract is stable** (see [`STABILITY.md`](STABILITY.md)), not "production-secure by default." The lattice is heavily verified; the runtime is tested but not yet battle-hardened.

## Development

```bash
cargo build --workspace
cargo test --workspace
make demo              # taint → block → receipt → compartment switch
```

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.

## References

- [The Uninhabitable State](https://simonwillison.net/2025/Jun/16/the-uninhabitable-state/) — Simon Willison
- [Lattice-based Access Control](https://en.wikipedia.org/wiki/Lattice-based_access_control) — Denning 1976, Sandhu 1993
- [Verus: Verified Rust for Systems Code](https://verus-lang.github.io/verus/) — SOSP 2025 Best Paper
