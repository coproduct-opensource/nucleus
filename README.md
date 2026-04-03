# Nucleus

[![CI](https://github.com/coproduct-opensource/nucleus/actions/workflows/ci.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/ci.yml)
[![Security Audit](https://github.com/coproduct-opensource/nucleus/actions/workflows/audit.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/audit.yml)
[![Cargo Deny](https://github.com/coproduct-opensource/nucleus/actions/workflows/deny.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/deny.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/coproduct-opensource/nucleus/badge)](https://securityscorecards.dev/viewer/?uri=github.com/coproduct-opensource/nucleus)
[![Docs](https://img.shields.io/badge/docs-github.io-blue)](https://coproduct-opensource.github.io/nucleus/)

**Cryptographically prove which data in an AI agent's output the model never touched.**

Nucleus is the only system that provides *negative provenance* — proving specific values were extracted deterministically from source systems, with the AI model structurally excluded from the data path. Not confidence scores. Not "the model said it copied faithfully." Cryptographic proof, replay-verifiable by any auditor.

```
revenue: 383,285,000,000 — Deterministic (source→parser→output hash chain verified)
summary: "Apple designs..." — AIDerived (honestly labeled, no verification possible)
```

**EU AI Act Article 50 ready.** Machine-readable provenance with `contains_ai_derived` flag.
**FINRA/SEC compliant.** Immutable audit trail with Ed25519-signed receipt chains.

### How It Works

1. **Fetch** — WebFetch captures content + SHA-256 hash at source
2. **Parse** — WASM sandbox extracts fields deterministically (zero-WASI, fuel-metered, model excluded)
3. **Bind** — DeterministicBind routes parser output to schema field (flow graph rejects if ANY parent has AI-derived taint)
4. **Prove** — WitnessBundle records the hash chain; auditor re-executes the parser independently
5. **Export** — Per-field provenance output + W3C PROV-JSON for compliance tooling

Built on a formally verified permission lattice and Firecracker-based enforcement runtime.

**Verification assurance** (see [`FORMAL_METHODS.md`](FORMAL_METHODS.md) for the honest self-audit):

| Layer | Tool | Count | Scope |
|-------|------|-------|-------|
| **Proved** (unbounded) | Lean 4 + Mathlib | 165 theorems | HeytingAlgebra on 13-dim production lattice ([Aeneas](https://github.com/AeneasVerif/aeneas)-generated types), exposure tracker monotonicity/soundness, IFC flow rules, compartment proofs, declassification safety, delegation narrowing monotonicity, DerivationClass lattice laws |
| **Bounded-model-checked** | [Kani](https://github.com/model-checking/kani) BMC | 112 harnesses | DecisionToken linearity, lattice distributivity, exposure monoid laws, constitutional kernel invariants, flow enforcement rules, manifest admission, DPI witness requirements |
| **Tested** | Rust + CI | ~2,850 tests | Sandbox isolation, path/command restrictions, network policy, OWASP LLM Top 10 gauntlet, DPI red team, end-to-end |

This README tries to be honest about what's real and what isn't.

> **Versioning note:** v1.0 means the **interface contract is stable** (see [`STABILITY.md`](STABILITY.md)), not that the system is "production-secure by default." The lattice is heavily verified; the runtime is tested but not yet battle-hardened in production traffic.

## Start Here: Secure Claude Code in 60 Seconds

```bash
cargo install --git https://github.com/coproduct-opensource/nucleus nucleus-claude-hook
nucleus-claude-hook --setup
# restart Claude Code — the hook is now active
```

Every tool call now flows through the Nucleus permission kernel. The hook tracks what data has entered your session and blocks dangerous combinations — like writing code based on untrusted web content (the core prompt injection vector).

```bash
nucleus-claude-hook --smoke-test   # verify it works
nucleus-claude-hook --doctor       # diagnose issues
nucleus-claude-hook --version      # check installed version
```

See the [60-second quickstart](docs/quickstart-hook.md) for details on compartments, profiles, and configuration.

## Static Analysis: Scan Agent Configs

For pre-deployment analysis (no runtime required):

```bash
cargo install --git https://github.com/coproduct-opensource/nucleus nucleus-audit

nucleus-audit scan --auto                              # auto-discover configs
nucleus-audit scan --claude-settings .claude/settings.json  # Claude Code
nucleus-audit scan --mcp-config .mcp.json              # MCP servers
nucleus-audit scan --pod-spec agent.yaml               # PodSpecs
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

## Interactive Shell: Run Claude Code Under Nucleus

Launch an interactive Claude Code session where **every tool call flows through the nucleus permission lattice**. Built-in tools (Bash, Read, Write, etc.) are replaced by sandboxed equivalents enforced by the tool-proxy.

```bash
# Install nucleus CLI (includes shell, audit, profiles, token commands)
cargo install --git https://github.com/coproduct-opensource/nucleus nucleus-cli

# Launch with the default codegen profile
nucleus shell

# Use a specific profile and working directory
nucleus shell --profile safe_pr_fixer --dir ~/projects/my-repo

# Set a budget cap
nucleus shell --profile local_dev --max-cost 5.00

# Pass credentials as environment variables
nucleus shell --env LLM_API_TOKEN=your-token --env DATABASE_URL=postgres://...

# Record a kernel decision trace for post-hoc analysis
nucleus shell --profile codegen --kernel-trace ./trace.jsonl
```

**What happens under the hood:**
1. Nucleus spawns `nucleus-tool-proxy` with your chosen permission profile
2. An MCP config is generated that routes all tools through the proxy
3. Claude Code launches with only the sandboxed MCP tools visible — built-in tools are disabled
4. Every side effect (file read/write, bash, git, web fetch) is checked against the permission lattice in real-time
5. When the session ends, an audit summary shows all operations and any denials

```
$ nucleus shell --profile code_review
nucleus shell | profile=code_review budget=$5.00 timeout=7200s
  tools: read, glob, grep, web_fetch
  audit: /tmp/nucleus-shell-abc123/audit.log

> claude starts in interactive mode...

--- nucleus audit summary ---
  total entries: 47
  read_file: 32
  glob: 8
  grep: 7
  log: /tmp/nucleus-shell-abc123/audit.log
```

Use `--print-config` to inspect the generated MCP config without launching Claude (useful for custom integrations).

See [`nucleus profiles`](#permission-profiles) for the full list of available profiles.

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

The uninhabitable state guard's monotonicity is formally proven: once an operation is denied, it stays denied for the rest of the session (proofs E1-E3 in `portcullis`).

## What Nucleus Provides

Three layers, at different levels of maturity:

1. **Scan** (usable today) — Static analysis of agent PodSpecs, Claude Code `settings.json`, and MCP configs. Catches dangerous permission combinations before deployment. Works as a standalone CLI tool and GitHub Action.

2. **Enforce** (working in CI, not production-hardened) — Runtime permission envelopes. The tool proxy intercepts every agent side effect and checks it against the permission lattice. Both HTTP and MCP paths share identical security controls (MIME gating, DNS/URL allowlists, redirect verification). The `--local` path works end-to-end in GitHub Actions. The Firecracker path works on Linux+KVM but has no production deployment.

3. **Audit** (implemented, not production-tested) — Hash-chained, HMAC-signed logs of every agent action with optional S3 append-only remote sink and drand cryptographic time anchoring. Node-side lifecycle events ensure all pods (including direct-task containers) have audit entries. Execution receipts capture workspace hash, audit chain tail, and token usage. Local verification tool works on generated test logs. S3 sink compiles into production binaries but has no integration test against real S3.

## Current Status

| Component | Maturity | Evidence |
|-----------|----------|----------|
| **Permission lattice** (portcullis) | Verified | 162K LOC, 1,443 tests, 297 Verus VCs, 112 Kani BMC proofs, 3 fuzz targets |
| ** Uninhabitable state detection** | Verified | Static scan + runtime guard, monotonicity proven (E1-E3, Kani B1-B9) |
| **Attenuation tokens** | Verified | Compact delegation credentials with Kani-proven invariants (D1-D7) |
| **Delegation chains** | Verified | Monotone attenuation with `meet_with_justification`, audit-reconstructable chains, Lean proofs for delegation narrowing |
| **Unicode injection defense** | Tested | 8-category invisible character detection (bidi, tags, ZWJ); warn/strip/deny policy |
| **Execution receipts** | Tested | Cryptographic pod execution proof with token usage and cost tracking |
| **Permission market** | Tested | Lagrangian pricing oracle for multi-dimensional capability constraints |
| **Web fetch security** | Tested | Unified MCP+HTTP path: MIME gating, DNS/URL allowlist, redirect verification, IPv6 |
| **Audit log verification** | Tested | HMAC-SHA256 + SHA-256 chain; optional S3 append-only sink; node-side lifecycle events |
| **PodSpec scanner** | Tested | Uninhabitable state, credentials, network, isolation, timeout checks |
| **Claude Code scanner** | Tested |  Uninhabitable state via allow/deny projection, Bash capability propagation, exfil patterns, safety bypasses, credentials |
| **MCP config scanner** | Tested | Well-known server classification (15 packages), `npx -y` supply chain detection, HTTP servers, credentials |
| **Permission profiles** | Tested | 18 named profiles (10 canonical + 8 legacy) backed by lattice constructors |
| **Tool proxy** (MCP enforcement) | Tested | 154 tests; enforces agent sessions in GitHub Actions |
| **Firecracker isolation** | Tested | Real jailer invocation + iptables; Linux+KVM only |
| **Network enforcement** | Tested | Default-deny egress, DNS allowlisting, drift detection |
| **CI hardening** | Tested | 16 required status checks; mutation testing blocks surviving mutants |
| **Budget tracking** | Partial | AtomicBudget exists; pre-exec reservation works, post-exec accounting incomplete |
| **SPIFFE identity** | Implemented | mTLS + cert management code exists; no SPIRE deployment |
| **Command exfiltration detection** | Partial | Program-name matching; `bash -c` bypasses documented |
| **Sink classification** | Tested | First-class `SinkClass` enum with 13 typed categories (workspace, system, bash, HTTP egress, git, PR, email, memory, agent spawn, MCP, secret, cloud) |
| **Declassification tokens** | Tested | Artifact-scoped, time-bounded, HMAC-signed tokens for controlled information release with Lean proofs |
| **Egress policy** | Tested | Config-driven `EgressPolicy` with `HostPattern` matcher wired into `Kernel::decide()` via `EgressBroker` for bash command egress destination extraction |
| **Governed memory** | Tested | `GovernedMemory` with rebuttal history and `MemoryAuthority` for auditable agent memory |
| **Autonomy ceiling** | Tested | Org-level `AutonomyCeiling` cap wired via `NUCLEUS_AUTONOMY_CEILING` env var |
| **Causal ancestry** | Tested | Per-artifact `FlowGraph::causal_label()` queries replace flat per-session flow labels; kernel refactored for artifact-granular decisions |
| **Enterprise managed allowlists** | Tested | Organizational policy controls for managed tool and domain allowlists |
| **Signed manifests** | Tested | Ed25519 manifest signatures with verification in the admission pipeline |
| **Artifact-granular quarantine** | Tested | Per-node flow blocking for targeted quarantine without session-wide denial |
| **Trusted ancestry check** | Tested | Compartment-aware trusted ancestry verification for Execute transitions |
| **Delegation scope** | Tested | `DelegationScope` + `DelegationConstraints` for fine-grained delegation control |
| **Receipt chain** | Tested | `ReceiptChain` with hash-chain integrity for linked execution receipts across sessions, content integrity verification on export |
| **Compartment escalation warnings** | Tested | Warnings on compartment escalation; breakglass requires explicit reason string; skip-level transitions blocked |
| **Constitutional kernel** | Tested | `ck-kernel` admission engine with `AdmissionVerdict` that collects all deny reasons, `PolicyRuleSet` admissibility rules wired into `Kernel::decide()`, 17 Kani proofs |
| **Deep packet inspection (DPI)** | Verified | 7th control plane: `DerivationClass` (6th IFC label dimension), `EffectKind` (computation-step classification), `StorageLane` (dual-lane routing), `FieldEnvelope`/`RowEnvelope` (canonical labeled containers), `WitnessBundle` (data flow verification). 3 Kani proofs + 16 Lean theorems. Threaded through `Evidence`, `VerdictReceipt`, `FlowNode`, and `Kernel::decide()` |
| **Derivation-sink compatibility** | Tested | `check_flow()` enforces derivation class compatibility with sink classes; AI-derived data cannot reach verified sinks without witness |
| **SinkScope enforcement** | Tested | Delegation certificates carry `SinkScope` constraints (allowed paths, hosts, git refs) enforced in `Kernel::decide()` step 5b |
| **Token signature verification** | Tested | Ed25519 signature verification on `DeclassificationToken` and `FlowReceipt` before kernel applies effects |
| **Session file hardening** | Tested | 0600 permissions on session state files, directory read blocking, atomic writes with advisory locking |
| **Compaction laundering defense** | Tested | Memory compaction preserves taint labels and audit trail; prevents laundering adversarial labels |
| **OWASP LLM Top 10 gauntlet** | Tested | 70 attack scenarios covering all 9 OWASP LLM vulnerability categories (LLM01-LLM09) |
| **DPI flow red team** | Tested | 33 red team tests for causal flow graph attacks including AG02/AG03 memory poisoning, AG04 goal hijacking, AG05 delegation escalation |
| **Lean 4 proof (Aeneas)** | Verified | Lean 4 HeytingAlgebra instance on `CapabilityLevel` — the same type used in production (re-exported from `portcullis-core`). Aeneas translates Rust MIR to Lean; function correspondence proven via `rfl` (`meet_eq_inf`, `join_eq_sup`, `implies_eq_himp`). CI type-checks proofs and rejects `sorry`. 165 theorems across 10 proof libraries. |
| **OTLP permission telemetry** | Tested | Every tool call verdict emits an OTel span with all 13 capability dimensions, exposure state, lockdown status. VerdictSink trait ensures both HTTP and MCP paths produce telemetry. Supports gRPC and http/protobuf (Grafana Cloud). |
| **Fleet lockdown** | Tested | `nucleus lockdown` drops agents to read-only via gRPC streaming (sub-second). Lattice meet semantics: reads allowed for forensics, writes blocked. OR-semantics between signal file and gRPC stream. Label-based pod scoping. |

**Maturity key:** *Verified* = SMT proofs + tests. *Tested* = compiles, has passing tests, never deployed. *Partial* = works for some cases, known gaps. *Implemented* = code exists, minimal testing. *Not started* = in roadmap only.

## Permission Lattice

Permissions compose predictably via a mathematical lattice. This is the most mature part of Nucleus — 162K lines of Rust with 297 SMT verification conditions (Verus/Z3) and 112 bounded model checking proofs (Kani/CaDiCaL).

| Structure | What It Gives You | Status |
|-----------|-------------------|--------|
| **Quotient Lattice** |  Uninhabitable state detection as a structural nucleus operator | Verified (Verus) |
| **Heyting Algebra** | Conditional permissions with formal semantics | Verified (Verus) |
| **Galois Connections** | Policy translation across trust domains | Verified (Verus) |
| **Graded Monad** | Risk accumulation through computation chains | Verified (Verus) |
| **Deep Packet Inspection** | DerivationClass, EffectKind, StorageLane, FieldEnvelope, WitnessBundle — 7th control plane | Verified (Kani + Lean) |
| **Attenuation Tokens** | Compact delegation credentials for wire transport | Verified (Kani D1-D7) |
| **Exposure Invariants** | Exposure-set monotonicity, uninhabitable state iff count==3 | Verified (Kani B1-B9) |
| **Modal Operators** | Distinguish "guaranteed safe" (□) from "might be safe" (◇) | Tested |
| **Delegation Chains** | Monotone attenuation with justification trails, scope/constraints | Verified (Lean) |

For the theory: [docs/THEORY.md](docs/THEORY.md).

## Formal Verification

Nucleus uses three complementary verification tools:
- [Verus](https://verus-lang.github.io/verus/) (SMT-based, SOSP 2025 Best Paper) — 297 verification conditions checked by Z3
- [Kani](https://model-checking.github.io/kani/) (bounded model checking) — 112 proofs checked by CaDiCaL SAT solver
- [Lean 4](https://lean-lang.org/) + [Aeneas](https://github.com/AeneasVerif/aeneas) (kernel-checked) — 165 theorems: HeytingAlgebra on 13-dim lattice, exposure tracker, flow rules, compartment safety, declassification, decide_pure correctness, delegation narrowing monotonicity, DerivationClass lattice algebra

**What's proven (297 Verus VCs + 112 Kani proofs + 165 Lean 4 theorems + Lean 4 HeytingAlgebra):**

*Verus (SMT):*
- Lattice laws: idempotent, commutative, associative, absorptive for all 13 capability dimensions
- Nucleus operator: idempotent, deflationary, monotone, meet-preserving
- Heyting adjunction: a ∧ b ≤ c ⟺ a ≤ b → c
- Galois connection: adjunction, closure/kernel properties, monotonicity
- Graded monad: identity, associativity, composition laws
- Exposure guard: monotonicity (E1), trace monotonicity (E2), denial monotonicity (E3)
- Uninhabitable state: completeness detection, risk classification, session safety
- Delegation: transitivity, ceiling theorem, chain composition

*Kani (BMC, 112 proofs):*
- B-series (9 proofs): Exposure set monoid identity/associativity, monotonicity, uninhabitable state-iff-count-equals-3, isolation lattice meet/join properties
- D-series (7 proofs): Attenuation token invariants — token ≤ parent, token ≤ requested cap, chained attenuation, delegation ceiling preservation
- E-series (3 proofs): Guard denial soundness, Clinejection defense, apply_record monotonicity
- R-series (3 proofs): R1 Heyting adjunction, R2 pseudo-complement, R3 entailment — bridge proofs mirroring the Lean 4 HeytingAlgebra axioms
- Structural (13 proofs): Lattice distributivity, frame law, budget monotonicity, capability level ordering
- Additional (28 proofs): Normalize idempotent, conservation laws, Noetherian symmetry, refinement bridges
- CK-series (17 proofs): Constitutional kernel admission invariants in `ck-kernel`
- Manifest admission (5 proofs): `AdmissionVerdict` construction, manifest-based tool admission in `portcullis-core`
- Flow enforcement (5 proofs): Flow graph enforcement rules, taint propagation correctness in `portcullis-core`
- DPI-series (3 proofs): `FieldEnvelope` verified-lane readiness — AI-derived data requires witness, verified write requires witness, verified lane implies witness or deterministic derivation
- Delegation (3 proofs): Delegation scope narrowing, certificate constraint verification in `portcullis-core`
- Declassification (1 proof): Token signature verification correctness

*Lean 4 (kernel-checked, 165 theorems across 10 proof libraries, zero sorry):*
- HeytingAlgebra instance on `CapabilityLevel` (the production type, re-exported from `portcullis-core`)
- Function correspondence via `rfl`: `meet_eq_inf`, `join_eq_sup`, `implies_eq_himp` — the Lean kernel reduces both sides to identical terms
- Aeneas pipeline: Charon extracts Rust MIR, Aeneas translates to Lean, CI diffs against committed output and type-checks proofs
- Discriminant ordering invariant: compile-time assertion ensures declaration order = `#[repr(u8)]` values
- Delegation narrowing: monotone attenuation verified — narrowed delegations never exceed the parent scope
- DerivationClass lattice laws (16 theorems): commutativity, associativity, idempotency, monotonicity, absorption, no-silent-cleansing invariant
- DecidePure correctness (11 theorems): pure decision function properties verified against the kernel specification

**What's tested but not formally verified:**
- Modal operators (necessity/possibility, S4 axioms) — 16 property tests
- Weakening cost model — 15 property tests
- Full PermissionLattice composition — 130 proptest invariants
- Adversarial inputs — 162 red team tests: OWASP LLM Top 10 gauntlet (70), DPI flow red team (33), delegation chain attacks (12), identity security gauntlet (47)

**What's done but not yet at Verus/Kani level:**
- Aeneas/Charon pipeline for `CapabilityLevel` (type + functions verified in Lean 4). `CapabilityLattice` extension dimensions (`BTreeMap`) are not modeled — they are covered by proptest but not by Lean or Kani.

**What's planned:**
- Full enforcement boundary verification (Phase 2 — started with E1-E3)
- Kani I/O confinement proof (issue #260)
- Extended TCB verification: sandbox, credentials, tool proxy (Phase 4)

See the full roadmap: [docs/north-star.md](docs/north-star.md).

All proof counts are ratcheted in CI — they can only go up, never down (`.verus-minimum-proofs`, `.kani-minimum-proofs`). Merging to `main` requires 16 status checks to pass, including security audit, cargo deny, clippy, fmt, fuzz, mutation testing, Lean 4 type-checking, and per-crate test suites.

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
│   7 control planes:                                              │
│   Capabilities × Obligations × Paths × Commands × Budget × Time │
│   + DPI (DerivationClass, EffectKind, StorageLane, Envelopes)   │
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

`Kernel::decide()` runs 17 enforcement steps: isolation minimum, time, budget, delegation constraints (expiry/depth/scope), capability level, defense-in-depth isolation gate, egress policy, admissibility rules, enterprise allowlists, path check, command check, SinkScope from delegation certificates, flow control (flat label or causal DAG), static approval, and dynamic exposure gate. Each step can independently deny the operation with a typed reason.

## Crates

| Crate | Purpose | Tests |
|-------|---------|-------|
| **portcullis** | Permission lattice: 12 algebraic modules + attenuation tokens + egress policy + receipt chain + DPI enforcement | 1,443 |
| **portcullis-core** | Core types: `CapabilityLevel`, `SinkClass` (13 categories), `DeclassificationToken`, flow graph, policy rules, enterprise allowlists, signed manifests, delegation scope, manifests, `DerivationClass`, `EffectKind`, `StorageLane`, `FieldEnvelope`, `WitnessBundle` | 512 |
| **ck-kernel** | Constitutional kernel: admission engine, lineage store, `PolicyRuleSet` wiring, 17 Kani proofs | 40 |
| **ck-types** | Constitutional kernel core types: manifests, digests, policy lattice | 32 |
| **ck-policy** | Constitutional kernel policy subset and monotonicity checks | — |
| **nucleus-claude-hook** | Hook binary for AI coding assistants: 10 extracted modules (protocol, classify, session, init, build, cli, status, exit_codes, completions), IFC kernel, compartments, profiles, causal ancestry, quarantine | 108 |
| **nucleus-audit** | `scan` PodSpecs, AI assistant settings, MCP configs; `verify` audit logs | 66 |
| **nucleus** | Enforcement: sandbox, executor, budget | 39 |
| **nucleus-node** | Node daemon managing Firecracker microVMs + containers | 52 |
| **nucleus-tool-proxy** | MCP tool proxy running inside pods (+ unicode audit, exit reports) | 154 |
| **nucleus-mcp** | MCP server bridging to tool-proxy | — |
| **nucleus-identity** | SPIFFE workload identity, mTLS, certs | 191 |
| **nucleus-spec** | PodSpec definitions (policy, network, creds, execution receipts) | — |
| **nucleus-proto** | Generated gRPC/Protobuf types for nucleus-node | — |
| **nucleus-permission-market** | Lagrangian pricing oracle for capability constraints | 27 |
| **nucleus-cli** | CLI for running tasks with enforced permissions | 57 |
| **nucleus-sdk** | Rust SDK for building sandboxed AI agents | 28 |
| **nucleus-client** | Client signing utilities + drand anchoring | 22 |
| **nucleus-guest-init** | Guest init for Firecracker rootfs | 3 |
| **nucleus-net-probe** | TCP probe for network policy tests | — |
| **ctf-engine** | Capture-the-flag engine for security testing | — |
| **ctf-mcp** | CTF MCP server | — |
| **ctf-server** | CTF web server | — |
| **exposure-playground** | Interactive TUI for exploring the lattice | — |

Total: ~2,850 test functions across the workspace (162K LOC Rust). Proptest invariants each generate 256 random cases. 112 Kani BMC proofs run in CI alongside 297 Verus VCs and 165 Lean 4 theorems.

## Permission Profiles

```bash
nucleus profiles

# Canonical profiles (declarative YAML with uninhabitable_state analysis):
#   safe-pr-fixer      Safe PR fixer — no push, no PR creation
#   doc-editor         Documentation editor — read all, write docs only, no network
#   test-runner        Test runner — read source, execute tests, no source writes
#   triage-bot         Triage bot — read, search, fetch context. No code changes
#   code-review        Code review — read source, search web, no modifications
#   codegen            Code generation — read/write/edit/run, network-isolated, no push
#   release            Release — full capabilities, approval required for push and PR
#   research-web       Web research — read files, search/fetch web, no writes
#   read-only          Read only — read files and search, no writes or network
#   local-dev          Local dev — read/write/edit/run/commit, no network, no push
#
# Legacy profiles:
#   filesystem-readonly, network-only, edit-only, fix-issue,
#   database-client, demo, full, restrictive
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

## Where Nucleus Fits: Hexagonal Integration

Nucleus is the **permission algebra and enforcement kernel** — it doesn't own the sandbox, the network mesh, or the orchestrator. It integrates with each through clean port/adapter boundaries:

```
                        ┌─────────────────────────────────┐
                        │        Your Orchestrator         │
                        │  (workstream, langchain, custom) │
                        └──────────┬──────────────────────┘
                                   │ PodSpec + credentials.env
                                   ▼
┌──────────────────┐   ┌─────────────────────────┐   ┌──────────────────────┐
│   Network Mesh   │   │        NUCLEUS           │   │   Sandbox Runtime    │
│                  │   │                           │   │                      │
│  Tailscale       │◄──┤  portcullis (lattice)     ├──►│  k8s Agent Sandbox   │
│  · WireGuard     │   │  nucleus-audit (scan)     │   │  · gVisor            │
│  · node identity │   │  tool-proxy (enforce)     │   │  · Kata Containers   │
│  · ACL tags      │   │  nucleus-identity (SPIFFE)│   │  · SandboxWarmPool   │
│                  │   │  ck-kernel (constitutional)│   │                      │
│  or: Cilium,     │   │                           │   │  or: Firecracker,    │
│  Calico, plain   │   │     Ports (in):           │   │  Docker+gVisor,      │
│  WireGuard       │   │       gRPC PodSpec submit │   │  Colima              │
│                  │   │       MCP tool calls      │   │                      │
│                  │   │     Ports (out):           │   └──────────────────────┘
│                  │   │       sandbox lifecycle    │
│                  │   │       network policy       │   ┌──────────────────────┐
│                  │   │       audit log sink       │   │   Execution Policy   │
│                  │   │       identity attestation │   │                      │
└──────────────────┘   └─────────────────────────┘   │  agentsh             │
                                                       │  · syscall intercept │
                                                       │  · file/net/proc     │
                                                       │  · approval gates    │
                                                       │  · YAML policies     │
                                                       │                      │
                                                       │  or: seccomp,        │
                                                       │  AppArmor, SELinux   │
                                                       └──────────────────────┘
```

### Kubernetes Agent Sandbox

[`kubernetes-sigs/agent-sandbox`](https://github.com/kubernetes-sigs/agent-sandbox) is the Kubernetes SIG Apps standard for running AI agents in isolated pods. It provides the **sandbox runtime** — Nucleus provides the **permission algebra** that decides what the sandbox should allow.

**Integration point:** Nucleus generates the pod security context, network policy, and resource limits from a `PodSpec` that Agent Sandbox enforces via gVisor or Kata Containers.

```yaml
# Nucleus PodSpec → Agent Sandbox CRD
apiVersion: agent-sandbox.sigs.k8s.io/v1alpha1
kind: AgentSandbox
spec:
  isolation: gVisor                    # or kata
  warmPool: pre-booted                 # sub-second cold start
  # ↓ Generated by nucleus from permission profile
  securityContext:
    capabilities:
      drop: [ALL]
    readOnlyRootFilesystem: true
  networkPolicy:
    egress:                            # from portcullis network_allow
      - to: [{ipBlock: {cidr: "140.82.112.0/20"}}]  # github.com
      - to: [{ipBlock: {cidr: "108.138.0.0/15"}}]   # crates.io
```

**What each owns:**

| Concern | Nucleus | Agent Sandbox |
|---------|---------|---------------|
| What the agent may do | Permission lattice decides | — |
| How the sandbox is configured | Generates PodSpec | Enforces via gVisor/Kata |
| Network egress rules | Computes from `network_allow` | Applies as NetworkPolicy |
| Warm pool management | — | SandboxWarmPool CRD |
| Uninhabitable state detection | Static + runtime | — |
| Runtime syscall filtering | — | gVisor kernel intercept |

### agentsh

[agentsh](https://www.agentsh.org/) provides **execution-layer policy enforcement** — intercepting file, network, and process operations at the syscall level. Where Nucleus decides permissions algebraically, agentsh enforces them at the OS boundary.

**Integration point:** Nucleus computes the effective permission set; agentsh enforces it as a syscall-level policy inside the sandbox.

```
Nucleus (what)                    agentsh (how)
┌────────────────────┐            ┌─────────────────────┐
│ portcullis says:   │            │ Policy enforcement:  │
│   read_files: Yes  │  ──────►  │   file_read: allow   │
│   web_fetch: No    │  generate │   net_connect: deny   │
│   git_push: Ask    │  policy   │   proc_exec(git      │
│   run_bash: Scoped │            │     push): approve   │
└────────────────────┘            └─────────────────────┘
```

**Layered defense:**

| Layer | Tool | What It Catches |
|-------|------|-----------------|
| 1. Static scan | `nucleus-audit` | Dangerous configs before deployment |
| 2. Lattice enforcement | `nucleus-tool-proxy` | Permission violations at the MCP/tool level |
| 3. Syscall enforcement | `agentsh` | `bash -c` indirection, symlink races, raw socket access |
| 4. VM isolation | Agent Sandbox / Firecracker | Kernel-level containment |

Layer 3 (agentsh) closes the `bash -c` bypass documented in [Known Gaps](#known-gaps) — the command-level check Nucleus acknowledges as incomplete is enforced at the syscall level by agentsh.

### Tailscale + SPIFFE

[Tailscale](https://tailscale.com/) provides **encrypted mesh networking** with node-level identity. Nucleus's `nucleus-identity` crate provides **workload-level SPIFFE identity**. Together they cover both network transport and service authentication.

**Integration point:** Tailscale secures the network path between orchestrator and sandbox; SPIFFE SVIDs authenticate each agent workload within that mesh.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Tailscale Mesh (WireGuard)                       │
│                                                                     │
│  ┌──────────────┐         ┌──────────────┐       ┌──────────────┐  │
│  │ Orchestrator │  mTLS   │ Nucleus Node │  mTLS │ Agent Pod    │  │
│  │              │◄───────►│              │◄─────►│              │  │
│  │ SPIFFE:      │         │ SPIFFE:      │       │ SPIFFE:      │  │
│  │ spiffe://    │         │ spiffe://    │       │ spiffe://    │  │
│  │ cluster/     │         │ cluster/     │       │ cluster/     │  │
│  │ orchestrator │         │ nucleus-node │       │ agent/task-1 │  │
│  └──────────────┘         └──────────────┘       └──────────────┘  │
│                                                                     │
│  Transport: Tailscale (node auth, encrypted mesh, ACL tags)        │
│  Identity:  SPIFFE (workload auth, short-lived SVIDs, mTLS)        │
│  Policy:    Nucleus (permission lattice, capability attenuation)    │
└─────────────────────────────────────────────────────────────────────┘
```

**What each owns:**

| Concern | Tailscale | SPIFFE (nucleus-identity) | Nucleus (portcullis) |
|---------|-----------|---------------------------|----------------------|
| Network encryption | WireGuard mesh | — | — |
| Node authentication | Machine keys + ACL tags | — | — |
| Workload authentication | — | X.509 SVIDs, mTLS | — |
| Service authorization | ACL policies (coarse) | — | Capability lattice (fine) |
| Credential rotation | — | Short-lived certs | Attenuation tokens |
| Audit | Connection logs | Identity attestation | Hash-chained action logs |

**Tailscale ACL tags** provide coarse network segmentation (`tag:agent-sandbox` can only reach `tag:nucleus-node`). SPIFFE SVIDs provide cryptographic workload identity within that perimeter. Portcullis decides what each authenticated workload is allowed to do.

> **Note:** Tailscale's SPIFFE support is [requested but not yet shipped](https://github.com/tailscale/tailscale/issues/13842). Today, use Tailscale for mesh transport + ACLs, and SPIRE independently for workload identity. If Tailscale adds native SPIFFE, the integration tightens — Tailscale nodes could directly issue SVIDs to agent pods.

### Choosing Your Stack

| Deployment | Network | Sandbox | Policy | Identity |
|------------|---------|---------|--------|----------|
| **GitHub Actions** | GitHub runner network | `--local` (tool-proxy only) | Nucleus profiles | — |
| **Single machine** | localhost / Tailscale | Docker + gVisor | Nucleus + agentsh | API keys |
| **k8s cluster** | Cilium / Calico / Tailscale | Agent Sandbox (gVisor/Kata) | Nucleus PodSpec | SPIFFE via SPIRE |
| **Multi-cloud** | Tailscale mesh | Agent Sandbox + Firecracker | Nucleus + attenuation tokens | SPIFFE + Tailscale ACLs |

Nucleus is the invariant across all four: the same permission lattice, the same scan, the same audit chain. The sandbox, network, and identity layers are pluggable adapters.

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
- [Kubernetes Agent Sandbox](https://github.com/kubernetes-sigs/agent-sandbox) — k8s SIG Apps standard for isolated agent execution
- [agentsh](https://www.agentsh.org/) — Execution-layer syscall policy enforcement for AI agents
- [Tailscale](https://tailscale.com/) — WireGuard mesh networking with node identity and ACL tags
- [SPIFFE](https://spiffe.io/) — Secure Production Identity Framework for Everyone
- [How to sandbox AI agents in 2026](https://northflank.com/blog/how-to-sandbox-ai-agents) — MicroVMs, gVisor, and isolation strategies
