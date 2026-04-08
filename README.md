# Nucleus

[![CI](https://github.com/coproduct-opensource/nucleus/actions/workflows/ci.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/ci.yml)
[![Security Audit](https://github.com/coproduct-opensource/nucleus/actions/workflows/audit.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/audit.yml)
[![Cargo Deny](https://github.com/coproduct-opensource/nucleus/actions/workflows/deny.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/deny.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/coproduct-opensource/nucleus/badge)](https://securityscorecards.dev/viewer/?uri=github.com/coproduct-opensource/nucleus)
[![Docs](https://img.shields.io/badge/docs-github.io-blue)](https://coproduct-opensource.github.io/nucleus/)

**Open-source toolkit for building IFC-enforced applications.** Two primitives — `join` and `flows_to` — and four algebraic laws that make information flow control composable, provable, and practical.

```rust
use portcullis_core::flow_algebra::FlowState;
use portcullis_core::{Operation, SinkClass};

let mut state = FlowState::bottom();       // clean session
state.join_operation(Operation::WebFetch);  // tainted by web content
assert!(!state.flows_to(SinkClass::GitPush)); // can't push tainted data
```

### The Flow Algebra

| Law | What it means | What it enables |
|-----|---------------|-----------------|
| `a ⊔ b = b ⊔ a` | Join is commutative | Safe parallel execution |
| `a ⊔ (b ⊔ c) = (a ⊔ b) ⊔ c` | Join is associative | Order-independent ratchet |
| `a ⊔ a = a` | Join is idempotent | Provably safe caching |
| `a ≤ a ⊔ b` | Join is monotone | Taint never decreases |

Everything else — taint tracking, policy enforcement, caching, delegation, ZK verification — is derived from these four laws.

### What you can build with Nucleus

- **Secure coding agents** that provably can't exfiltrate data
- **Multi-agent systems** where children can't escalate beyond parents
- **Compliance pipelines** with cryptographic noninterference proofs
- **Any application** where "data X must never reach sink Y" needs to be enforced, not hoped

Built on a [formally verified permission lattice](FORMAL_METHODS.md): 76 Lean 4 theorems (zero `sorry`), Kani BMC proofs, ~2,850 tests.

> **Versioning note:** v1.0 means the **interface contract is stable** (see [`STABILITY.md`](STABILITY.md)), not that the system is "production-secure by default." The lattice is heavily verified; the runtime is tested but not yet battle-hardened.

## Why Nucleus

Every major LLM agent exploit in 2025-2026 succeeded because the framework had **no memory of data provenance**. Nucleus remembers where every byte came from — and the labels are permanent, monotonic, and type-enforced.

| CVE | What happened | Why it worked | Nucleus defense |
|-----|---------------|---------------|-----------------|
| [CVE-2025-53773](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/) | Copilot RCE — prompt injection writes config to disable all security checks, enables arbitrary shell exec | Security was a JSON config flag (`chat.tools.autoApprove`) that the agent could edit | Security is compiled types (`Discharged<O>`), not config. No file edit can disable obligation checking. |
| [CVE-2025-32711](https://www.hackthebox.com/blog/cve-2025-32711-echoleak-copilot-vulnerability) | EchoLeak — zero-click exfiltration of emails, Teams chats, OneDrive via hidden prompt in a Word doc | M365 Copilot had no concept of "this data is internal and cannot leave" | [Bidirectional IFC](docs/theory/ifc-semilattice.md): `session_conf_ceiling` blocks internal→public data flow. Once the session reads internal data, ALL outbound public writes are denied. |
| [MCP Tool Poisoning](https://arxiv.org/html/2509.10540v1) | Malicious MCP server injects hidden instructions in tool responses, steering the agent to exfiltrate data | Agent frameworks treat all tool responses as trusted | MCP responses are labeled `Adversarial` at the type level. `Labeled<T, Adversarial, Public>` cannot flow to verified sinks without explicit human `promote_integrity()`. |

### 10-line secure session (Python)

```python
from portcullis import Runtime, Profile

with Runtime.session(
    Profile.RESEARCH.with_capability("run_bash").without_capability("web_search"),
    "analyze SEC filings"
) as rt:
    page = rt.fetch_url("https://sec.gov/filing.html")
    page.data           # raises UntrustedAccess — adversarial data is gated
    raw = page.acknowledge("human reviewed for injection")
    rt.git_push("origin", "main")  # PolicyDenied: hint tells you exactly what to fix
```

### 10-line secure session (Rust)

```rust
let mut rt = NucleusRuntime::builder()
    .composed(PolicyProfile::Research.with(RuntimeCapability::RunBash))
    .task("analyze SEC filings")
    .build();

let fetch = rt.fetch_url("https://sec.gov/...")?;
// fetch.data(): &Labeled<Vec<u8>, Adversarial, Public>
// Passing this to a Trusted-gated function is a COMPILE ERROR
```

[Verified Claims](docs/verified-claims.md) — what is proved, what is not, and the [known gaps](docs/verified-claims.md#known-gaps).

## Who Is This For?

**Securing an AI coding assistant?** Install the hook, get IFC-based protection in 60 seconds.
[Quick Start](#quick-start) | [docs/quickstart-hook.md](docs/quickstart-hook.md)

**Building an AI platform?** Scan agent configs in CI, enforce permissions at runtime, audit everything.
[Static Analysis](#static-analysis) | [Runtime Enforcement](#runtime-enforcement)

**Formal methods researcher?** Heyting algebra permission lattice with Lean 4, Kani, and Verus proofs.
[FORMAL_METHODS.md](FORMAL_METHODS.md) | [docs/THEORY.md](docs/THEORY.md) | [Verified Claims](docs/verified-claims.md) | [Category Theory](docs/theory/index.md)

## Quick Start

```bash
cargo install --git https://github.com/coproduct-opensource/nucleus nucleus-claude-hook
nucleus-claude-hook --setup
# restart your AI coding assistant -- the hook is now active
```

Every tool call now flows through the Nucleus permission kernel. The hook tracks what data has entered your session and blocks dangerous combinations -- like writing code based on untrusted web content (the core prompt injection vector).

```bash
nucleus-claude-hook --smoke-test   # verify it works
nucleus-claude-hook --doctor       # diagnose issues
```

See the [hook README](crates/nucleus-claude-hook/README.md) for configuration and module architecture.

## Static Analysis

Scan agent configurations before deployment -- no runtime required:

```bash
cargo install --git https://github.com/coproduct-opensource/nucleus nucleus-audit

nucleus-audit scan --auto                              # auto-discover configs
nucleus-audit scan --claude-settings .claude/settings.json
nucleus-audit scan --mcp-config .mcp.json
nucleus-audit scan --pod-spec agent.yaml
```

| Format | What It Checks |
|--------|----------------|
| PodSpec YAML | Uninhabitable state, credentials, network, isolation, timeout, permissions |
| Claude Code settings | Uninhabitable state via allow/deny projection, Bash capability propagation, exfil patterns |
| MCP config | Server classification, `npx -y` supply chain risk, credentials, dangerous commands |

Exit code is non-zero when critical or high findings exist -- drop it into CI:

```yaml
- uses: coproduct-opensource/nucleus/scan@v1
  with:
    auto: true
```

See the [audit README](crates/nucleus-audit/README.md) for all subcommands and [`examples/`](examples/) for scannable configurations.

## Runtime Enforcement

Launch an AI session where every tool call flows through the permission lattice:

```bash
cargo install --git https://github.com/coproduct-opensource/nucleus nucleus-cli

nucleus shell                                    # default codegen profile
nucleus shell --profile safe_pr_fixer --dir ~/repo
nucleus shell --profile code_review --max-cost 5.00
```

Under the hood: Nucleus spawns `nucleus-tool-proxy` with your permission profile, routes all tools through it via MCP, and checks every side effect against the lattice in real-time.

See the [CLI README](crates/nucleus-cli/README.md) for all commands and profiles.

## The Uninhabitable State

The core security primitive. When an agent has all three capabilities at autonomous levels, prompt injection becomes data exfiltration:

```
  Private Data Access    +    Untrusted Content    +    Exfiltration Vector
  ---------------------       ------------------        --------------------
  read_files >= LowRisk       web_fetch >= LowRisk      git_push >= LowRisk
  read_env                    web_search >= LowRisk     create_pr >= LowRisk
  database access             user input processing     run_bash (curl, etc)
```

Nucleus detects this statically (`nucleus-audit scan`) and enforces at runtime (`portcullis`). When the uninhabitable state is complete, exfiltration requires **explicit human approval**.

The guard's monotonicity is formally proven: once denied, always denied for the session (proofs E1-E3).

## What Nucleus Provides

Three layers, at different maturity levels:

1. **Scan** (usable today) -- Static analysis of PodSpecs, Claude Code settings, and MCP configs. Catches dangerous permission combinations before deployment. Works as a CLI tool and [GitHub Action](#github-actions).

2. **Enforce** (working in CI, not production-hardened) -- Runtime permission envelopes via the tool proxy. Every agent side effect is checked against the permission lattice. The `--local` path works end-to-end in GitHub Actions. Firecracker path works on Linux+KVM.

3. **Audit** (implemented, not production-tested) -- Hash-chained, HMAC-signed logs of every agent action with optional S3 sink and drand time anchoring. Execution receipts capture workspace hash, audit chain tail, and token usage.

## Verification at a Glance

| Layer | Status | Evidence |
|-------|--------|----------|
| Permission lattice (portcullis) | Verified | 165 Lean theorems, 112 Kani proofs, 297 Verus VCs |
| Uninhabitable state detection | Verified | Static + runtime, monotonicity proven |
| Tool proxy enforcement | Tested | 154 tests, enforces in GitHub Actions CI |
| Audit + receipt chains | Tested | HMAC-SHA256 + Ed25519 signed chains |
| Firecracker isolation | Tested | Linux+KVM only |

Full component status and proof inventory: [**FORMAL_METHODS.md**](FORMAL_METHODS.md)

All proof counts are ratcheted in CI -- they can only go up, never down. Merging to `main` requires 16 status checks including security audit, mutation testing, Lean 4 type-checking, and fuzz testing.

## Crates

### User-Facing Tools

| Crate | Purpose |
|-------|---------|
| [**nucleus-claude-hook**](crates/nucleus-claude-hook/) | Hook for AI coding assistants: IFC kernel, compartments, provenance |
| [**nucleus-audit**](crates/nucleus-audit/) | Scan agent configs, verify audit trails, inspect provenance |
| [**nucleus-cli**](crates/nucleus-cli/) | Run AI agents under enforced permissions (`nucleus shell`, `nucleus run`) |
| [**nucleus-sdk**](crates/nucleus-sdk/) | Rust SDK for building sandboxed AI agents |
| [**exposure-playground**](crates/exposure-playground/) | Interactive TUI for exploring the permission lattice |

### Core Libraries

| Crate | Purpose |
|-------|---------|
| [**portcullis**](crates/portcullis/) | Permission lattice: algebraic modules, attenuation tokens, egress policy, DPI |
| [**portcullis-core**](crates/portcullis-core/) | Core types: `CapabilityLevel`, IFC labels, flow graph, witness bundles ([Aeneas target](FORMAL_METHODS.md)) |
| [**ck-kernel**](crates/ck-kernel/) | Constitutional kernel: admission engine + lineage (17 Kani proofs) |
| [**ck-types**](crates/ck-types/) | Constitutional kernel core types and manifests |
| [**ck-policy**](crates/ck-policy/) | Constitutional kernel policy monotonicity checks |
| [**nucleus**](crates/nucleus/) | Enforcement: cap-std sandbox, executor, budget tracking |
| [**nucleus-tool-proxy**](crates/nucleus-tool-proxy/) | MCP tool proxy running inside pods (permission enforcement gateway) |
| [**nucleus-mcp**](crates/nucleus-mcp/) | MCP server bridging to tool-proxy |
| [**nucleus-identity**](crates/nucleus-identity/) | SPIFFE workload identity, mTLS, certificate management |
| [**nucleus-ifc**](crates/nucleus-ifc/) | Standalone IFC library for AI agents |
| [**nucleus-memory**](crates/nucleus-memory/) | Governed memory with per-entry IFC labels |
| [**nucleus-spec**](crates/nucleus-spec/) | PodSpec definitions (policy, network, credentials) |
| [**nucleus-proto**](crates/nucleus-proto/) | Generated gRPC/Protobuf types |

### Infrastructure

| Crate | Purpose |
|-------|---------|
| [**nucleus-node**](crates/nucleus-node/) | Node daemon managing Firecracker microVMs + containers |
| [**nucleus-client**](crates/nucleus-client/) | Client signing utilities + drand anchoring |
| [**nucleus-permission-market**](crates/nucleus-permission-market/) | Lagrangian pricing oracle for capability constraints |
| [**nucleus-guest-init**](crates/nucleus-guest-init/) | Guest init for Firecracker rootfs |
| [**ctf-engine**](crates/ctf-engine/) | Formally verified sandbox CTF challenge engine |
| [**ctf-server**](crates/ctf-server/) | HTTP API server for The Vault CTF |
| [**ctf-mcp**](crates/ctf-mcp/) | MCP server for AI agents to play The Vault CTF |

Total: ~2,850 tests across the workspace (162K LOC Rust).

## Provenance

**Cryptographically prove which data in an AI agent's output the model never touched.**

Nucleus provides *negative provenance* -- proving specific values were extracted deterministically from source systems, with the AI model structurally excluded from the data path.

```
revenue: 383,285,000,000 -- Deterministic (source->parser->output hash chain verified)
summary: "Apple designs..." -- AIDerived (honestly labeled, no verification possible)
```

**How it works:**

1. **Fetch** -- WebFetch captures content + SHA-256 hash at source
2. **Parse** -- WASM sandbox extracts fields deterministically (zero-WASI, fuel-metered, model excluded)
3. **Bind** -- DeterministicBind routes parser output to schema field (rejects if ANY parent has AI taint)
4. **Prove** -- WitnessBundle records the hash chain; auditor re-executes independently
5. **Export** -- Per-field provenance output + W3C PROV-JSON + C2PA content credentials

**EU AI Act Article 50 ready.** Machine-readable provenance with `contains_ai_derived` flag.

See [docs/quickstart-provenance.md](docs/quickstart-provenance.md) for the full guide.

## Architecture

```
+---------------------------------------------------------------+
|                        Your Agent                              |
+---------------------------------------------------------------+
|  nucleus-cli / nucleus-audit scan                              |
|  (enforce at runtime / catch misconfigs before deploy)         |
+---------------------------------------------------------------+
|                         nucleus                                |
|  +--------------+  +--------------+  +----------------------+  |
|  |   Sandbox    |  |   Executor   |  |   AtomicBudget       |  |
|  |  (cap-std)   |  |  (process)   |  |   (lock-free)        |  |
|  +--------------+  +--------------+  +----------------------+  |
+---------------------------------------------------------------+
|                      portcullis                                |
|   7 control planes:                                            |
|   Capabilities x Obligations x Paths x Commands x Budget x    |
|   Time + DPI (DerivationClass, EffectKind, StorageLane)        |
+---------------------------------------------------------------+
|                    nucleus-identity                             |
|           SPIFFE workload identity + mTLS                      |
+---------------------------------------------------------------+
|           Firecracker microVM / seccomp / netns                |
|           (Linux + KVM required; not available on macOS)       |
+---------------------------------------------------------------+
```

The enforcement path: Agent -> MCP -> tool-proxy (inside VM) -> portcullis check -> OS operation.

See [docs/integrations.md](docs/integrations.md) for how Nucleus fits with k8s Agent Sandbox, agentsh, Tailscale, and SPIFFE.

## GitHub Actions

### Scan (deterministic, no API key)

```yaml
- uses: coproduct-opensource/nucleus/scan@v1
  with:
    auto: true
```

### Safe PR Fixer (LLM-powered, lattice-enforced)

```yaml
- uses: coproduct-opensource/nucleus@v1
  with:
    issue-number: "123"
    api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    profile: safe_pr_fixer
```

| Tier | What | Isolation |
|------|------|-----------|
| **0** | `nucleus-audit scan` in CI | Static analysis, no runtime |
| **1** | `nucleus run --local` (GitHub Action) | Tool-proxy lattice enforcement, no VM |
| **2** | `nucleus run` with Firecracker | microVM + netns + default-deny egress |

## Permission Profiles

```bash
nucleus profiles

# Canonical profiles:
#   safe-pr-fixer     Safe PR fixer -- no push, no PR creation
#   doc-editor        Documentation editor -- read all, write docs only, no network
#   test-runner       Test runner -- read source, execute tests, no source writes
#   triage-bot        Triage bot -- read, search, fetch context. No code changes
#   code-review       Code review -- read source, search web, no modifications
#   codegen           Code generation -- read/write/edit/run, network-isolated
#   release           Release -- full capabilities, approval required for push
#   research-web      Web research -- read files, search/fetch web, no writes
#   read-only         Read only -- read files and search, no writes or network
#   local-dev         Local dev -- read/write/edit/run/commit, no network
```

## Known Gaps

Documented in [`SECURITY_TODO.md`](SECURITY_TODO.md). Key items:

- **Command exfiltration detection is program-name only.** `bash -c 'curl ...'` bypasses command-level checks. Firecracker network policy is the real defense.
- **Path sandboxing is string-based.** Unicode normalization and symlink races not exhaustively tested. `cap-std` provides defense-in-depth.
- **Budget enforcement is partial.** Pre-execution reservation works; post-execution cost accounting is not implemented.
- **Formal verification covers the lattice, not the full runtime.** See [FORMAL_METHODS.md](FORMAL_METHODS.md) for the honest assessment.
- **`--local` mode has weaker isolation than Firecracker.** Use Tier 2 for high-security workloads.

## Threat Model

**Protects against:** prompt injection side effects, invisible Unicode injection, misconfigured permissions, network policy drift, budget exhaustion, privilege escalation via delegation, audit log tampering.

**Does not protect against:** compromised host/kernel, malicious human approvals, side-channel attacks, VM kernel escapes, `bash -c` indirection (network policy is the backstop).

## Development

```bash
cargo build --workspace
cargo test --workspace
cargo run -p exposure-playground  # Interactive lattice explorer
```

Requires Rust stable. Firecracker features require Linux with KVM. macOS works for everything except VM isolation.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.

## References

- [The Uninhabitable State](https://simonwillison.net/2025/Jun/16/the-uninhabitable-state/) -- Simon Willison
- [Lattice-based Access Control](https://en.wikipedia.org/wiki/Lattice-based_access_control) -- Denning 1976, Sandhu 1993
- [Verus: Verified Rust for Systems Code](https://verus-lang.github.io/verus/) -- SOSP 2025 Best Paper
- [Kubernetes Agent Sandbox](https://github.com/kubernetes-sigs/agent-sandbox) -- k8s SIG Apps standard
- [agentsh](https://www.agentsh.org/) -- Syscall-level policy enforcement
- [cap-std](https://github.com/bytecodealliance/cap-std) -- Capability-based filesystem
