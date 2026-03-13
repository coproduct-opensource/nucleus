# Nucleus

[![CI](https://github.com/coproduct-opensource/nucleus/actions/workflows/ci.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/ci.yml)
[![Security Audit](https://github.com/coproduct-opensource/nucleus/actions/workflows/audit.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/audit.yml)
[![Cargo Deny](https://github.com/coproduct-opensource/nucleus/actions/workflows/deny.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/deny.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/coproduct-opensource/nucleus/badge)](https://securityscorecards.dev/viewer/?uri=github.com/coproduct-opensource/nucleus)
[![Docs](https://img.shields.io/badge/docs-github.io-blue)](https://coproduct-opensource.github.io/nucleus/)

**A formally verified permission lattice and security runtime for AI agents.**

Nucleus is a security framework for AI agents that combines a mathematically verified permission algebra with a Firecracker-based enforcement runtime. The permission lattice has 297 SMT verification conditions checked by Z3 plus 32 bounded model checking proofs via Kani. The GitHub Action works end-to-end today. This README tries to be honest about what's real and what isn't.

> **Versioning note:** v1.0 means the **interface contract is stable** (see [`STABILITY.md`](STABILITY.md)), not that the system is "production-secure by default." The lattice is heavily verified; the runtime is tested but not yet battle-hardened in production traffic.

## Start Here: Scan Your Agent Config

This works today. No runtime required. Pre-built binaries ship with every [release](https://github.com/coproduct-opensource/nucleus/releases).

```bash
# From source
cargo install --git https://github.com/coproduct-opensource/nucleus nucleus-audit

# Or download a pre-built binary from GitHub Releases

# Auto-discover and scan all agent configs in the current repo
nucleus-audit scan --auto

# Or specify paths explicitly
nucleus-audit scan --pod-spec your-agent.yaml
nucleus-audit scan --claude-settings .claude/settings.json
nucleus-audit scan --mcp-config .mcp.json

# Scan everything at once — findings are merged, deduplicated, and source-attributed
nucleus-audit scan --pod-spec agent.yaml --claude-settings settings.json --mcp-config .mcp.json
```

**Supported formats:**

| Format | File | What It Checks |
|--------|------|----------------|
| PodSpec | `*.yaml` | Uninhabitable state, credentials, network, isolation, timeout, permissions |
| Claude Code settings | `settings.json` |  Uninhabitable state via allow/deny rules, Bash capability propagation, exfil patterns, safety bypasses, inline credentials, hooks |
| MCP config | `.mcp.json` | Well-known server classification, `npx -y` supply chain risk, external HTTP servers, plaintext credentials, auth headers, dangerous commands |

The Claude Code scanner projects `allow`/`deny` rules onto the portcullis `CapabilityLattice` and runs the same uninhabitable state analysis used for PodSpecs. **Unrestricted Bash implies all capabilities** — `cat` reads files, `curl` fetches web content, `grep` searches — so `["Edit", "Write", "Bash"]` correctly triggers a CRITICAL uninhabitable state even without explicit `Read` or `WebFetch` rules. Patterned Bash (e.g., `Bash(curl *)`) propagates only the relevant capability legs. A deny rule like `"Bash"` (bare, no pattern) demotes the exfiltration leg back to `Never`, breaking the uninhabitable state.

The MCP scanner classifies well-known server packages (database, filesystem, VCS, cloud, communication, browser) and flags `npx -y` with non-official packages as a supply chain risk.

Exit code is non-zero when critical or high findings exist — drop it into CI and block unsafe deployments.

```bash
# JSON output for CI pipelines
nucleus-audit scan --pod-spec agent.yaml --format json

# Verify hash-chained audit logs
nucleus-audit verify --audit-log /var/log/nucleus/agent.jsonl
```

### Example: The Hidden Uninhabitable state

A common config that *looks* safe — only Edit, Write, and Bash — but unrestricted Bash implies `cat` (read), `curl` (web), and `git push` (exfil):

```json
{ "permissions": { "allow": ["Edit", "Write", "Bash"], "deny": [] } }
```

```
$ nucleus-audit scan --claude-settings settings.json

  !! [CRITICAL] Lethal uninhabitable state in Claude Code settings
       The allow rules grant private data access (Read/Glob/Grep)
       + untrusted content (WebFetch/WebSearch) + exfiltration (Bash)
       without sufficient deny rules to break the uninhabitable state.

  !  [HIGH] Unrestricted Bash access
       Bash is allowed without pattern restrictions and no deny rules
       limit it.

  ══ Verdict: FAIL — critical issues must be resolved ══
```

Compare with a hardened config that restricts Bash to specific commands and denies exfil patterns:

```json
{ "permissions": {
    "allow": ["Read", "Bash(cargo *)", "Bash(git status)", "Bash(git diff *)"],
    "deny":  ["Bash(curl *)", "Bash(wget *)", "Read(.env)", "Read(*secret*)"],
    "ask":   ["Write", "Edit", "Bash(git push *)"]
} }
```

```
$ nucleus-audit scan --claude-settings settings.json
  ══ Verdict: PASS with advisories ══
```

### Example: MCP Server Classification

The scanner classifies well-known MCP server packages and flags `npx -y` supply chain risk:

```
$ nucleus-audit scan --mcp-config .mcp.json

  ~  [MEDIUM] Database access via MCP server 'postgres'
  ~  [MEDIUM] Filesystem access via MCP server 'filesystem'
  ~  [MEDIUM] Vcs access via MCP server 'github'
       This server provides BOTH private data access and
       exfiltration capability — two exposure legs in one server.
  ~  [MEDIUM] Auto-install unknown package in 'custom-tool': some-random-mcp-server
       This executes arbitrary code from npm on every invocation.
  -  [LOW] Auto-install official MCP package in 'postgres'
       Pinning to a specific version is recommended.

  ══ Verdict: PASS with advisories ══
```

See [`examples/`](examples/) for more configs: [Claude Code settings](examples/claude-settings/), [MCP configs](examples/mcp-configs/), [PodSpecs](examples/podspecs/).

## The Uninhabitable State

The core security primitive. When an agent has all three capabilities at autonomous levels, prompt injection becomes data exfiltration:

```
  Private Data Access    +    Untrusted Content    +    Exfiltration Vector
  ─────────────────────       ──────────────────        ────────────────────
  read_files ≥ LowRisk       web_fetch ≥ LowRisk      git_push ≥ LowRisk
  read_env                    web_search ≥ LowRisk     create_pr ≥ LowRisk
  database access             user input processing    run_bash (curl, etc)
```

Nucleus detects this combination statically (via `nucleus-audit scan`) and enforces it at runtime (via `portcullis`). When the uninhabitable state is complete, exfiltration operations require **explicit human approval** — the agent cannot bypass this.

The uninhabitable state guard's monotonicity is formally proven: once an operation is denied, it stays denied for the rest of the session (proofs E1-E3 in `portcullis-verified`).

## What Nucleus Provides

Three layers, at different levels of maturity:

1. **Scan** (usable today) — Static analysis of agent PodSpecs, Claude Code `settings.json`, and MCP configs. Catches dangerous permission combinations before deployment. Works as a standalone CLI tool and GitHub Action.

2. **Enforce** (working in CI, not production-hardened) — Runtime permission envelopes. The tool proxy intercepts every agent side effect and checks it against the permission lattice. Both HTTP and MCP paths share identical security controls (MIME gating, DNS/URL allowlists, redirect verification). The `--local` path works end-to-end in GitHub Actions. The Firecracker path works on Linux+KVM but has no production deployment.

3. **Audit** (implemented, not production-tested) — Hash-chained, HMAC-signed logs of every agent action with optional S3 append-only remote sink and drand cryptographic time anchoring. Node-side lifecycle events ensure all pods (including direct-task containers) have audit entries. Execution receipts capture workspace hash, audit chain tail, and token usage. Local verification tool works on generated test logs. S3 sink compiles into production binaries but has no integration test against real S3.

## Current Status

| Component | Maturity | Evidence |
|-----------|----------|----------|
| **Permission lattice** (portcullis) | Verified | 58K LOC, 942 tests, 297 Verus VCs, 32 Kani BMC proofs, 3 fuzz targets |
| ** Uninhabitable state detection** | Verified | Static scan + runtime guard, monotonicity proven (E1-E3, Kani B1-B9) |
| **Attenuation tokens** | Verified | Compact delegation credentials with Kani-proven invariants (D1-D7) |
| **Delegation chains** | Tested | Monotone attenuation with `meet_with_justification`, audit-reconstructable chains |
| **Unicode injection defense** | Tested | 8-category invisible character detection (bidi, tags, ZWJ); warn/strip/deny policy |
| **Execution receipts** | Tested | Cryptographic pod execution proof with token usage and cost tracking |
| **Permission market** | Tested | Lagrangian pricing oracle for multi-dimensional capability constraints |
| **Web fetch security** | Tested | Unified MCP+HTTP path: MIME gating, DNS/URL allowlist, redirect verification, IPv6 |
| **Audit log verification** | Tested | HMAC-SHA256 + SHA-256 chain; optional S3 append-only sink; node-side lifecycle events |
| **PodSpec scanner** | Tested | Uninhabitable state, credentials, network, isolation, timeout checks |
| **Claude Code scanner** | Tested |  Uninhabitable state via allow/deny projection, Bash capability propagation, exfil patterns, safety bypasses, credentials |
| **MCP config scanner** | Tested | Well-known server classification (15 packages), `npx -y` supply chain detection, HTTP servers, credentials |
| **Permission profiles** | Tested | 14 named profiles backed by lattice constructors |
| **Tool proxy** (MCP enforcement) | Tested | 149 tests; enforces agent sessions in GitHub Actions |
| **Firecracker isolation** | Tested | Real jailer invocation + iptables; Linux+KVM only |
| **Network enforcement** | Tested | Default-deny egress, DNS allowlisting, drift detection |
| **CI hardening** | Tested | 16 required status checks; mutation testing blocks surviving mutants |
| **Budget tracking** | Partial | AtomicBudget exists; pre-exec reservation works, post-exec accounting incomplete |
| **SPIFFE identity** | Implemented | mTLS + cert management code exists; no SPIRE deployment |
| **Command exfiltration detection** | Partial | Program-name matching; `bash -c` bypasses documented |
| **Lean 4 model** | Not started | Planned: Aeneas translation for deeper mathematical verification |

**Maturity key:** *Verified* = SMT proofs + tests. *Tested* = compiles, has passing tests, never deployed. *Partial* = works for some cases, known gaps. *Implemented* = code exists, minimal testing. *Not started* = in roadmap only.

## Permission Lattice

Permissions compose predictably via a mathematical lattice. This is the most mature part of Nucleus — 58K lines of Rust with 297 SMT verification conditions (Verus/Z3) and 32 bounded model checking proofs (Kani/CaDiCaL).

| Structure | What It Gives You | Status |
|-----------|-------------------|--------|
| **Quotient Lattice** |  Uninhabitable state detection as a structural nucleus operator | Verified (Verus) |
| **Heyting Algebra** | Conditional permissions with formal semantics | Verified (Verus) |
| **Galois Connections** | Policy translation across trust domains | Verified (Verus) |
| **Graded Monad** | Risk accumulation through computation chains | Verified (Verus) |
| **Attenuation Tokens** | Compact delegation credentials for wire transport | Verified (Kani D1-D7) |
| **Exposure Invariants** | Exposure-set monotonicity, uninhabitable state iff count==3 | Verified (Kani B1-B9) |
| **Modal Operators** | Distinguish "guaranteed safe" (□) from "might be safe" (◇) | Tested |
| **Delegation Chains** | Monotone attenuation with justification trails | Tested |

For the theory: [docs/THEORY.md](docs/THEORY.md).

## Formal Verification

Nucleus uses two complementary verification tools:
- [Verus](https://verus-lang.github.io/verus/) (SMT-based, SOSP 2025 Best Paper) — 297 verification conditions checked by Z3
- [Kani](https://model-checking.github.io/kani/) (bounded model checking) — 32 proofs checked by CaDiCaL SAT solver

**What's proven (297 Verus VCs + 32 Kani proofs):**

*Verus (SMT):*
- Lattice laws: idempotent, commutative, associative, absorptive for all 12 capability dimensions
- Nucleus operator: idempotent, deflationary, monotone, meet-preserving
- Heyting adjunction: a ∧ b ≤ c ⟺ a ≤ b → c
- Galois connection: adjunction, closure/kernel properties, monotonicity
- Graded monad: identity, associativity, composition laws
- Exposure guard: monotonicity (E1), trace monotonicity (E2), denial monotonicity (E3)
- Uninhabitable state: completeness detection, risk classification, session safety
- Delegation: transitivity, ceiling theorem, chain composition

*Kani (BMC):*
- B-series (9 proofs): Exposure set monoid identity/associativity, monotonicity, uninhabitable state-iff-count-equals-3, isolation lattice meet/join properties
- D-series (7 proofs): Attenuation token invariants — token ≤ parent, token ≤ requested cap, chained attenuation, delegation ceiling preservation
- E-series (3 proofs): Guard denial soundness, Clinejection defense, apply_record monotonicity
- Structural (13 proofs): Lattice distributivity, frame law, budget monotonicity, capability level ordering

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

Both proof counts are ratcheted in CI — they can only go up, never down (`.verus-minimum-proofs`, `.kani-minimum-proofs`). Merging to `main` requires 16 status checks to pass, including security audit, cargo deny, clippy, fmt, fuzz, mutation testing, and per-crate test suites.

## v1.0 Contract Surface

The v1.0 interfaces are designed for 15 years of growth. See [`STABILITY.md`](STABILITY.md) for the full frozen/open contract table.

**Frozen at v1.0** (breaking changes require v2.0):
- 12 core `Operation` variants + exposure classifications
- 3 core `ExposureLabel` variants + uninhabitable state predicate
- `CapabilityLevel` enum (`Never`, `LowRisk`, `Always`)
- gRPC `NodeService` RPCs (8 RPCs including streaming), HMAC signing protocol, audit hash chain
- `ExecutionReceipt` fields 1-8 (v1.0 frozen), with `v1_content_hash` for forward compatibility

**Open for extension** (no version bump needed):
- New operations via `ExtensionOperation` on `CapabilityLattice` (fail-closed: unknown ops default to `Never`)
- New exposure labels via `ExtensionExposureLabel` on `ExposureSet` (don't affect core uninhabitable state)
- New dangerous combinations via `ConstraintNucleus` (uninhabitable state always slot 0, can't be removed)
- Versioned `ExecutionReceipt` with `v1_content_hash` for forward-compatible verification
- `WorkspaceGuard` trait for multi-agent shared exposure (interface only in v1.0)

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
│   + Heyting Algebra + Galois + Graded Monad + Attenuation Tokens│
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
| **portcullis** | Permission lattice: 12 algebraic modules + attenuation tokens | 942 |
| **portcullis-verified** | Verus SMT proofs for portcullis | 297 VCs |
| **nucleus-audit** | `scan` PodSpecs, Claude Code settings, MCP configs; `verify` audit logs | 45 |
| **nucleus** | Enforcement: sandbox, executor, budget | 39 |
| **nucleus-node** | Node daemon managing Firecracker microVMs + containers | 39 |
| **nucleus-tool-proxy** | MCP tool proxy running inside pods (+ unicode audit, exit reports) | 149 |
| **nucleus-mcp** | MCP server bridging to tool-proxy | 4 |
| **nucleus-identity** | SPIFFE workload identity, mTLS, certs | 296 |
| **nucleus-spec** | PodSpec definitions (policy, network, creds, execution receipts) | 21 |
| **nucleus-proto** | Generated gRPC/Protobuf types for nucleus-node | — |
| **nucleus-permission-market** | Lagrangian pricing oracle for capability constraints | 28 |
| **nucleus-cli** | CLI for running tasks with enforced permissions | 12 |
| **nucleus-sdk** | Rust SDK for building sandboxed AI agents | 3 |
| **nucleus-client** | Client signing utilities + drand anchoring | 8 |
| **nucleus-guest-init** | Guest init for Firecracker rootfs | 2 |
| **nucleus-net-probe** | TCP probe for network policy tests | 2 |
| **exposure-playground** | Interactive TUI for exploring the lattice | — |

Total: ~1,700 test functions across the workspace (103K LOC Rust). Proptest invariants each generate 256 random cases. 32 Kani BMC proofs run in CI alongside 297 Verus VCs.

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
#   full               Everything (uninhabitable state gates still enforced!)
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

## Example Configs

See [`examples/`](examples/) for scannable configurations across all three formats:

**PodSpecs** ([`examples/podspecs/`](examples/podspecs/)):
- **`safe-pr-fixer.yaml`** — CI issue fixer: write + bash + commit, no push/PR (the GitHub Action profile)
- **`airgapped-review.yaml`** — Code review in a fully airgapped Firecracker VM with seccomp
- **`secure-codegen.yaml`** — Code generation with filtered network (crates.io, npm, GitHub only)
- **`permissive-danger.yaml`** — Intentionally insecure config for testing `nucleus-audit scan`

**Claude Code settings** ([`examples/claude-settings/`](examples/claude-settings/)):
- **`safe-restrictive.json`** — Scoped Bash patterns, deny rules for exfil, sandbox enabled
- **`hidden-uninhabitable state.json`** — The `["Edit", "Write", "Bash"]` trap: CRITICAL uninhabitable state via Bash propagation
- **`permissive-danger.json`** — Everything allowed, safety bypasses, plaintext credentials

**MCP configs** ([`examples/mcp-configs/`](examples/mcp-configs/)):
- **`safe-local.json`** — Single local filesystem server, no credentials
- **`typical-dev-stack.json`** — Postgres + filesystem + GitHub + unknown packages (shows server classification + supply chain warnings)
- **`permissive-danger.json`** — External HTTP server, plaintext credentials, dangerous commands

## GitHub Actions

### Deterministic Scan (no LLM, no API key)

Add to any CI pipeline — blocks PRs with unsafe agent configs:

```yaml
# Auto-discover all agent configs in the repo
- uses: coproduct-opensource/nucleus/scan@v1
  with:
    auto: true

# Or specify paths explicitly
- uses: coproduct-opensource/nucleus/scan@v1
  with:
    claude-settings: .claude/settings.json
    mcp-config: .mcp.json
    # pod-spec: path/to/podspec.yaml
    # format: text          # or json
```

Use `auto: true` to discover configs automatically, or provide explicit paths. Outputs `verdict` (PASS/WARN/FAIL) and `findings-json`. Non-zero exit code on critical or high findings.

### Safe PR Fixer (LLM-powered, lattice-enforced)

Drop this into any repo to get nucleus-enforced issue fixes:

```yaml
- uses: coproduct-opensource/nucleus@v1
  with:
    issue-number: "123"
    api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    profile: safe_pr_fixer     # write + bash + commit + web fetch, no push/PR
    timeout: "600"
    # model: "claude-sonnet-4-20250514"   # default
    # github-token: ${{ secrets.GH_PAT }}  # optional: override GITHUB_TOKEN for PR creation
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
| **Tier 0** | `nucleus-audit scan` in CI | Static analysis (PodSpec, Claude settings, MCP), no runtime |
| **Tier 1** | `nucleus run --local` (GitHub Action) | Tool-proxy lattice enforcement, no VM |
| **Tier 2** | `nucleus run` with Firecracker | microVM + netns + default-deny egress |

The GitHub Action uses Tier 1 (`--local`). Network enforcement relies on the permission lattice, not default-deny iptables. For full containment, use Tier 2 with Firecracker on Linux+KVM.

## Known Gaps

Documented in detail in [`SECURITY_TODO.md`](SECURITY_TODO.md). Key items:

- **Command exfiltration detection is program-name only.** `bash -c 'curl ...'` can bypass uninhabitable state detection at the command lattice level. The Firecracker network policy is the real defense (default-deny egress), but the command-level check has known bypasses.
- **Path sandboxing is string-based.** Unicode normalization and symlink race conditions are not exhaustively tested. `cap-std` capability handles provide defense-in-depth. Invisible Unicode character injection (Rules File Backdoor) is detected at the tool-proxy gateway layer with configurable policy (warn/strip/deny).
- **Budget enforcement is partial.** Pre-execution reservation works when timeouts are set. Post-execution cost accounting (output tokens, refunds) is not implemented.
- **Formal verification covers the lattice algebra, not the full runtime.** The 297 Verus VCs verify portcullis properties. The tool proxy, network enforcement, and Firecracker integration are tested, not verified.
- **S3 audit sink is fire-and-forget.** Upload failures are logged but don't block the agent. No integration test against real S3 exists. Append-only semantics use `if_none_match("*")` PutObject preconditions — untested against eventual consistency.
- **Redirect following is reqwest default (10 hops).** The final URL is checked against DNS/URL allowlists after all redirects complete, but intermediate hops are not validated. An allowlisted domain with an open redirect to a non-allowlisted domain will be caught, but the request still reaches the intermediate servers.
- **`--local` mode has weaker isolation than Firecracker.** The tool-proxy enforces lattice permissions, but there is no VM boundary or default-deny network. Use Tier 2 (Firecracker) for high-security workloads.

## Threat Model

**Protects against:**
- Prompt injection attempting side effects outside the permission envelope
- Invisible Unicode injection / Rules File Backdoor attacks (detected at gateway)
- Misconfigured tool permissions (enforced at runtime, not advisory)
- Network policy drift inside the runtime (fail-closed)
- Budget exhaustion attacks (atomic tracking, with caveats above)
- Privilege escalation via delegation (ceiling theorem + attenuation tokens)
- Trust domain confusion (Galois connections)
- Audit log tampering (hash chain verification + execution receipts)

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
cargo run -p exposure-playground  # Interactive lattice explorer
```

Requires Rust stable. Firecracker features require Linux with KVM. macOS development works for everything except VM isolation.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.

## References

- [The Uninhabitable State](https://simonwillison.net/2025/Jun/16/the-uninhabitable-state/) — Simon Willison
- [Container Hardening Against Agentic AI](https://securitytheatre.substack.com/p/container-hardening-against-agentic)
- [Lattice-based Access Control](https://en.wikipedia.org/wiki/Lattice-based_access_control) — Denning 1976, Sandhu 1993
- [Verus: Verified Rust for Systems Code](https://verus-lang.github.io/verus/) — SOSP 2025 Best Paper
- [AWS Cedar Formal Verification](https://www.amazon.science/blog/how-we-built-cedar-with-automated-reasoning-and-differential-testing)
- [cap-std](https://github.com/bytecodealliance/cap-std) — Capability-based filesystem
