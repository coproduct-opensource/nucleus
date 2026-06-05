# Nucleus

### Don't trust the agent. Verify it.

*Signed identity, declared guarantees, receipts anyone can check.*

[![CI](https://github.com/coproduct-opensource/nucleus/actions/workflows/ci.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/ci.yml)
[![Security Audit](https://github.com/coproduct-opensource/nucleus/actions/workflows/audit.yml/badge.svg)](https://github.com/coproduct-opensource/nucleus/actions/workflows/audit.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/coproduct-opensource/nucleus/badge)](https://securityscorecards.dev/viewer/?uri=github.com/coproduct-opensource/nucleus)

**Nucleus is a vendor-agnostic secure runtime for AI agents: it enforces what an agent may do, proves the enforcement boundary is sound, attests how every result was produced, and federates identity and trust — without a single long-lived secret.**

> **Assume the agent is compromised. Constrain what it can do anyway. Prove the constraints hold.**

At its core is a small, dependency-free information-flow algebra. Two primitives — `join` and `flows_to` — enforce information-flow control under four algebraic laws. Once untrusted web content enters a session, it cannot silently reach a privileged sink like `git push`. That property is [machine-checked](FORMAL_METHODS.md), not hoped.

This is the **[lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)** — private data + untrusted content + an exfiltration sink — made safe by **non-interference**: attacker-tainted data cannot reach a consequential action, so a compromised agent cannot be turned into a *confused deputy*. We don't *detect* the prompt injection; we make its consequence impossible — and prove it. (Detection-based guardrails are probabilistic; this is a structural guarantee.)

```rust
let mut state = FlowState::bottom();           // clean session
state.join_operation(Operation::WebFetch);     // tainted by web content
assert!(!state.flows_to(SinkClass::GitPush));  // can't push tainted data
```

On top of that core, Nucleus adds three newer pillars — a **Constitutional Kernel** (policy may only tighten, never widen), **verifiable keyless identity & trust federation** (OIDC → SPIFFE, "Let's Encrypt for agents"), and **provenance envelopes with an independent verifier** (signed, portable bundles re-checkable in Rust, WASM/JS, or Python).

---

## See it in 90 seconds

Two runnable hooks, nothing to configure ([`just`](https://github.com/casey/just), or run the commands directly):

```sh
just demo     # 30s, in your terminal — information-flow control, 4 scenarios
just vault    # play "The Vault" in your browser
```

**`just demo`** (`cargo run -p nucleus-ifc --example ifc_demo`) — a prompt-injection write is **denied by adversarial *ancestry***, not by a classifier guessing at strings; a clean flow is allowed; a compartment transition clears taint; a deterministic bind excludes the model from the trust decision:

```
─ Scenario 1: Web injection blocked ─
  ModelPlan inherits Adversarial from WebContent
  ✗ Write DENIED — adversarial ancestry detected
─ Scenario 2: Clean workflow allowed ─
  ✓ Write ALLOWED — clean ancestry
```

**`just vault`** launches [**The Vault**](crates/ctf-engine/README.md) — a browser CTF where you try to exfiltrate a secret past a formally-verified permission lattice (Lean 4 + Kani-backed verdicts). Hosted at **https://nucleus-ctf.fly.dev**; point an LLM at its JSON/MCP API and watch it fail too.

---

## Quick Start

```bash
cargo install --git https://github.com/coproduct-opensource/nucleus nucleus-cli

nucleus audit [PATH]                # Tier 0: scan agent configs, no runtime (CI exit codes)
nucleus run --local "your task"     # Tier 1: run with enforced permissions (process-level, no VM)
```

Every tool call flows through the permission kernel. `nucleus run` tracks data provenance and blocks dangerous combinations — like writing code derived from untrusted web content.

> **Vendor neutrality.** The core library and the generic `credentials.env` / `PodSpec` interface are *intended* to be vendor-agnostic, but the surface is not fully clean today. Two things break it: (1) the *reference agent runner* shipped with `nucleus run`/`shell` is coupled to one specific assistant CLI (binary name, default model string, permission-bypass flag), and (2) `nucleus-spec` still hardcodes specific LLM-vendor hostnames and workload-identity defaults (see [Known Gaps](#known-gaps)). A PreToolUse hook for AI coding assistants lives in the external private orchestrator [nucleus-code](https://github.com/coproduct-opensource/nucleus-code), built on this runtime. Treat the runner as an integration *example*, not a vendor-agnostic component.

---

## What Gets Proved

| Claim | What it means for you | Evidence | Known gap |
|-------|----------------------|----------|-----------|
| Taint is monotone | Once web content contaminates a session, the agent cannot silently regain trusted status | [Lean 4 + Kani](docs/verified-claims.md#2-taint-is-monotone-no-silent-cleansing) | Depends on correct labeling at integration boundaries |
| Adversarial integrity absorbs | One drop of adversarial input contaminates the entire result — no dilution | [Lean 4](docs/verified-claims.md#3-adversarial-integrity-is-absorbing) | Content must be labeled adversarial at source |
| Unpoliced I/O is unconstructible | File/shell/git effects can only be obtained via `production_effects(policy)` — there is no policy-free constructor | [Sealed effect traits](docs/verified-claims.md#6-obligation-bypass-is-a-type-error) | Web fetch/search and agent-spawn effects are stubs; capability gate is coarse (`!= Never`) |
| Permissions are a Heyting algebra | Restricting permissions always produces a valid, less-permissive result | [Kani + Lean](docs/verified-claims.md#5-capability-lattice-is-a-distributive-heyting-algebra) | 13 dimensions may not cover every use case |
| Secret data cannot flow to public sinks | Session-level confidentiality ceiling prevents laundering through intermediaries | [Unit tests + compile-fail](docs/verified-claims.md#7-confidentiality-downflow-is-enforced) | Mislabeled data bypasses the check |
| Self-amendments may only tighten | An agent's policy manifest can drop, but never add, authority/IO/budget — escalations are rejected | [Kani BMC + tests](docs/verified-claims.md) | Constitutional kernel is a library; not yet wired into the live runtime |
| Provenance is independently re-verifiable | Forged provenance bundles are rejected by the same verifier you can run yourself | [CI-gated adversarial corpus](docs/verified-claims.md) | A green verify proves lineage is authentic + intact, **not** that the agent behaved well |

### Formal assurance, recounted (June 2026)

| Tool | Real count | Scope | CI gate |
|------|-----------|-------|---------|
| **Lean 4 + Mathlib** (kernel-checked) | ~277 theorems in the security core (more, incl. research formalizations) | Capability Heyting algebra, IFC semilattice, taint monotonicity, exposure monoid, delegation, **integrity noninterference over Aeneas-extracted Rust** | `lean-build.yml` rejects `sorry` in the Aeneas-bridged core only (`PortcullisCoreBridge.lean`, `DerivationProofs.lean`, `generated/PortcullisCore/`); `aeneas-ifc-scoped.yml` asserts a clean axiom set for the extracted integrity-noninterference theorem (`IntegrityNoninterferenceExtracted.lean`) |
| **Kani** (bounded model checking) | 113 harnesses | DecisionToken linearity, lattice adjunction, flow-graph isolation, constitutional-kernel admission contract | `kani-nightly.yml` (`cargo kani -p portcullis`) |
| **Tests** | ~4,400 (`#[test]` / `#[tokio::test]`) + ~47 `proptest` suites | Workspace-wide | `ci.yml` |
| **Code** | ~165K LOC Rust | — | — |

**Honest scope.** The Lean *security* core (lattice, IFC, exposure, noninterference) is `sorry`-free and present in the full `lake` build. Note what CI actually enforces: the per-PR `sorry`-rejection step in `lean-build.yml` greps only the Aeneas-bridged files (`PortcullisCoreBridge.lean`, `DerivationProofs.lean`, `generated/PortcullisCore/`), and the clean-axiom-set assertion in `aeneas-ifc-scoped.yml` covers only the one extracted integrity-noninterference theorem — neither gate spans the whole ~277-theorem core. The exploratory alignment-tax / cohomology formalizations are research-tier, are **not** yet fully discharged (**~80–85 open `sorry` goals** remain across those files — 83 on non-comment lines, ~96 raw occurrences), and are clearly separated from the core. Aeneas mechanically translates the core capability *types* from Rust to Lean so proofs run over generated code; ExposureSet/IFC use hand-written Lean models with structural correspondence tests, and exact function-level Rust↔Lean correspondence (that the Rust `meet` equals the Lean `meet`) is **not yet** proven. Kani is bounded — complete over the finite lattice state space, an approximation for string/path checks.

**No Verus.** Earlier docs cited "297 Verus VCs." Verus has been **removed** from the workspace; its guarantees are folded into the Lean 4 + Kani stack. A `proptest`-based conformance suite (`verus_conformance.rs`) is the surviving artifact — property tests, not SMT proofs.

[Verified Claims](docs/verified-claims.md) · [Formal Methods](FORMAL_METHODS.md) · [Production Delta](docs/production-delta.md)

---

## The Flow Algebra

| Law | What it means | What it enables |
|-----|---------------|-----------------|
| `a ⊔ b = b ⊔ a` | Join is commutative | Safe parallel execution |
| `a ⊔ (b ⊔ c) = (a ⊔ b) ⊔ c` | Join is associative | Order-independent ratchet |
| `a ⊔ a = a` | Join is idempotent | Provably safe caching |
| `a ≤ a ⊔ b` | Join is monotone | Taint never decreases |

Each of these four laws is backed by a named, passing test, and the four-valued Belnap policy bilattice that composes decisions (`Allow`/`Deny`/`Unknown`/`Conflict`) has kernel-checked, sorry-free Lean proofs.

### The information-flow core, precisely

Nucleus is built on a vendor-agnostic algebraic core (`portcullis-core`, dependency-free):

- **Capability lattice** — a Heyting algebra over **13** operation dimensions (read/write/exec/web/git/spawn/…), each a 3-level chain `Never < LowRisk < Always`, with pointwise `meet`/`join`/`implies`, a least-privilege builder, and work-type profiles (`read-only`, `research`, `codegen`, `review`). No LLM-vendor concepts appear in the core.
- **Bidirectional information-flow control** — a **6-dimension** `IFCLabel` (confidentiality, integrity, authority, provenance, freshness, derivation) implementing BLP down-flow containment **and** Biba up-flow taint. A causal-DAG `FlowTracker` joins labels across operations and **fails closed on unknown nodes**, with monotonic per-session taint and confidentiality ceilings.
- **Policy enforced by the type system** — I/O goes through sealed effect traits (`FileEffect`, `ShellEffect`, `GitEffect`); the only constructor for a real handler is `production_effects(policy)`, so unpoliced file/shell/git I/O is unconstructible. (Web fetch/search and agent-spawn effects on the real handler return `NotImplemented` and delegate to other crates.)
- **Governed memory** — a key-value store with per-entry IFC labels, authority classes, provenance flags, TTL, and `poisoned_entries()` detection for memory-poisoning attack classes.

This cluster carries **over a thousand passing library unit tests** (`portcullis-core` ~1081, `portcullis-effects` 69, `nucleus-spec` 32, `nucleus-memory` 17, `nucleus-ifc` 14, `portcullis-profiles` 4 — roughly **~1217** in total) plus ~95 Kani harnesses.

---

## The Three New Pillars

The sections below cover three large subsystems that landed after the original docs and were previously under-described. Each carries an honest status note.

### 1. Constitutional Kernel — policy that can only tighten

A self-contained library trio (`ck-types`, `ck-policy`, `ck-kernel`) that decides whether a proposed change to an agent's *own* policy manifest is allowed to ship. Its governing rule is **monotonicity**: a self-amendment may only *tighten* authority, never widen it. The admission engine rejects any change that adds a capability, widens the I/O surface, raises a resource budget, or drops a required proof obligation — and reports exactly which invariant was violated. Constitutional (kernel-adjacent) changes can never be self-merged; they require a threshold of distinct, cryptographically-verified human signatures. Every accepted amendment is content-addressed (BLAKE3), carries an Ed25519-signed witness bundle (`ring`), and is appended to a replayable lineage.

Documented adversarial defenses pass with tests: patch laundering, witness replay, lineage tampering, sandbox relaxation, and `policy_before` forgery are all rejected.

| Component | What it does | Status |
|---|---|---|
| `ck-policy` monotonicity checker | Pure function: rejects capability / IO / budget escalation and proof-requirement weakening | Working (tested) |
| `ck-kernel` admission engine + lineage | Validates parent/witness/signatures/monotonicity, appends signed lineage; constitutional path needs multi-sig human approval | Working (tested) |
| Ed25519 witness signatures | Real `ring` verification, fail-closed when no trusted keys configured | Working; enforcement **opt-in** (defaults to test-skip mode) |
| Kani proofs of the contract | 17 symbolic harnesses proving escalations are always rejected | Working; full run nightly, per-PR runs a count-regression gate |
| Runtime / PR-gate integration | Enforce admitted policy on live execution / every PR | **Roadmap** — library not yet wired in |

> **Status:** ~75 passing unit/integration tests; 17 Kani harnesses. **This is a well-tested library, not yet wired into the runtime** — no non-`ck` crate depends on it, and the sandbox enforces policy via the separate `portcullis` kernel. Signature verification defaults to `SkipForTesting`; you must opt in via `.with_signature_verifier()`. The PR-gating "Constitutional Gate" service described in `PolicyManifest.toml` is an external/closed component, **not** something this open-source repo demonstrates — treat it as roadmap.

### 2. Verifiable Identity & Trust Federation — keyless, vendor-neutral

A SPIFFE workload-identity and federation stack that turns a CI/runtime OIDC token into a SPIFFE id with **no long-lived secret**.

- **Keyless GitHub Actions OIDC → SPIFFE (`nucleus-github-oidc`) is proven live end-to-end.** A real GitHub OIDC token (mintable only inside a job with `id-token: write`) is validated against GitHub's real JWKS (RS256 sig, issuer/audience/exp, repo+org allowlist, replay), and the SPIFFE id is derived from the *verified* `repository` claim — never from `sub` — with a green CI run on record. A Fly.io Machine validator (`nucleus-fly-oidc`) implements the same pattern (synthetic-fixture-tested; no live demo yet). Shared primitives (`nucleus-oidc-core`) provide RFC 7517/8037 JWKS, OIDC discovery, and replay defense, with a CI gate (`ci/no-vendor-strings.sh`) enforcing vendor neutrality on every PR.
- **OIDC provider (`nucleus-oidc-provider`).** A stateless OP that mints EdDSA JWT-SVIDs with key rotation + grace windows, publishes RFC 8414 discovery + JWKS, and performs RFC 8693 token exchange — verifying the inbound `subject_token`'s Ed25519 signature and enforcing declarative federation rules.
- **Trust registry — "Let's Encrypt for agents" (`nucleus-trust-registry`).** A **non-custodial** (never a CA, never a keyholder) registry for SPIFFE *federation enrollment*: a fail-closed PR gate verifies a GitHub OIDC proof-of-control (pinning the **numeric org id** to defeat rename-squatting) and appends each trust-root binding to an append-only, witness-cosigned transparency log.
- **Witness & split-trust (`nucleus-witness`).** A C2SP `tlog-witness` server minting Ed25519 cosignatures under the full spec status matrix, with RFC 6962 consistency and rollback protection. Run your own **k-of-n witnesses across failure domains** so no single region, cloud account, or key store can forge or roll back your log — useful even to a single operator with zero counterparties.
- **Verify-before-you-act (`nucleus-agent-card`).** Secret-free, WASM-capable verification of signed agent cards that, by design, refuses to trust any key embedded in the card itself.

| Component | Status |
|---|---|
| Keyless GitHub Actions OIDC → SPIFFE | Working (proven **live E2E**) |
| OIDC core primitives (JWKS, discovery, replay) | Working |
| Agent cards (verify-before-you-act) | Working |
| SPIFFE identity + mTLS + did:web | Working |
| OIDC provider (mint + RFC 8693 exchange) | Alpha (static trust bundle; live SPIRE-Agent validation stubbed) |
| Trust registry (enrollment + transparency log) | Alpha (single maintainer + single witness; proves **org control**, not trust-domain ownership) |
| C2SP tlog-witness / Sigsum k-of-n | Alpha (in-memory store; **not** yet persistent) |
| Fly machine OIDC → SPIFFE | Alpha (no live-E2E demo) |

> **Status & honesty notes.** (1) The OIDC provider verifies inbound `subject_token` signatures only against a statically-configured trust bundle; live SPIRE-Agent-mediated validation (Workload API over UNIX socket) is **stubbed**. (2) The trust registry's OIDC proof establishes GitHub-**org** control of the enrolling repo, **not** ownership of the SPIFFE trust-domain name (a DNS-01-style proof is v2); the MVP trust base is a single maintainer + single witness — no threshold key ceremony. (3) The witness store is in-memory; a restart resets last-cosigned positions, so production requires durable storage. (4) Paid-tier/metering seams are documented-only — **no billing feature exists**.

### 3. Provenance Envelopes & the Public Verifier — signed, portable, independently checkable

Every agent session can be packaged as a **provenance bundle** — the agent's payload plus a signed lineage envelope proving how it was produced. Each lineage edge (one per tool call, LLM call, or derived artifact) carries a child SPIFFE id encoding its derivation, an Ed25519 signature, and a `prev_hash` link; the whole log is committed to an RFC 9162 Merkle tree with signed tree heads, inclusion/consistency proofs, and optional external-witness cosignatures (Nucleus + C2SP `tlog-witness`).

The point is **independent verification**. `verify_bundle` re-checks the entire bundle — per-edge signatures, hash chain, session membership, Merkle inclusion, cosignature thresholds, and payload binding — against a **trust anchor you supply out-of-band**. The bundle's own embedded keys are deliberately ignored. The same audited Rust verifier ships three ways:

| Surface | What it is | Status |
|---|---|---|
| `nucleus-envelope` (Rust) | Core `verify_bundle` + bundle builder | Working — 36 integration tests (73 total incl. unit tests) |
| `@coproduct/verify` (WASM/JS) | `verify(receipt, anchor)` one-liner; runs in browser/Node with zero service trust | Builds + smoke-tested; **npm publish gated** |
| `nucleus-verifier` (Python) | PyO3 backend binding | Builds; **no in-repo tests yet** |
| `nucleus-verifier-service` (HTTP) | Optional convenience verifier + transparency log | Deploy-ready (`fly.toml`; 26 integration / 70 total tests); **not yet hosted** |

A **CI-gated adversarial corpus** of 8 forged bundles (tampered edges, swapped signatures, truncation, attacker JWKS, unknown kid, foreign parent, non-pod root) **must** be rejected on every merge — `every_corpus_case_is_rejected` passes today. This is the security promise, not a slogan. For replication, `nucleus-bundle-cas` fetches bundles by BLAKE3 root over bao-verified `iroh-blobs` QUIC so a peer can't substitute or truncate bytes (alpha; single-operator split-trust, no discovery/mesh, pins pre-1.0 `iroh`).

> **Honest scope.** A green verification proves the lineage is *authentic and intact*. It does **not** prove the agent behaved well, that information-flow policy held, or that any computation was correct — those are separate guarantees. Issuing/signing identities is **demo-only** in this repo (`dev`-feature-gated `LocalIssuer`); production needs an external SPIFFE issuer and witness. The public verifier service is **not** live (no hosted endpoint resolves today); it is self-hostable and deploy-ready. The `@coproduct/verify` npm package and in-browser tamper demo are publish-gated; the compiled `.wasm` is a build product, not committed.

---

## How Nucleus Stops Real Exploits

| CVE / class | Attack | Why it worked | Nucleus defense |
|-----|--------|---------------|-----------------|
| [CVE-2025-53773](https://embracethered.com/blog/posts/2025/github-copilot-remote-code-execution-via-prompt-injection/) | Coding-assistant RCE via prompt injection | Security was a JSON config flag the agent could edit | Security is compiled types and sealed effect traits, not config |
| [CVE-2025-32711](https://www.hackthebox.com/blog/cve-2025-32711-echoleak-copilot-vulnerability) | EchoLeak — zero-click exfiltration via hidden prompt in a document | No concept of "internal data cannot leave" | [Bidirectional IFC](docs/verified-claims.md#7-confidentiality-downflow-is-enforced) blocks internal→public flow |
| [MCP Tool Poisoning](https://arxiv.org/html/2509.10540v1) | Malicious MCP server injects hidden instructions | Tool responses treated as trusted | MCP responses labeled `Adversarial` at the type level |
| Memory poisoning (MINJA / MemoryGraft) | Injected memories steer later behavior | Persistent stores treated as trusted | `GovernedMemory` labels each entry; `poisoned_entries()` surfaces contamination |

---

## Deployment Tiers

| Tier | What | Isolation | Platform | Status |
|------|------|-----------|----------|--------|
| **0 — Scan** | `nucleus audit [PATH]` in CI | Static analysis of PodSpec / MCP / settings configs; CI exit codes | any | Usable today (92 tests) |
| **1 — Enforce** | `nucleus run --local` / agent PreToolUse hook | Local tool-proxy routes every call through the lattice; **process-level** env + command isolation (no VM) | any host | Alpha |
| **2 — Isolate** | `nucleus run` via `nucleus-node` | Firecracker microVM + network namespace + default-deny egress + seccomp | **Linux + KVM only** | Alpha |

> Tier 1 is process-level (env-clear isolation, `cap-std`, command allowlist) — it is **not** kernel/container isolation and does not prevent kernel escapes or network exfiltration when `bash` is allowed. The agent PreToolUse-hook variant of Tier 1 (`nucleus run --hook`, `nucleus guard`) is **not** runnable from this repo: it shells out to a `nucleus-claude-hook` binary that lives in the external private orchestrator, and the in-repo install hint (`cargo install --path crates/nucleus-claude-hook`) is stale — that crate does not exist here. Tier 2 isolation requires Linux with `/dev/kvm`; on macOS the node returns an explicit "firecracker requires Linux" error, and the macOS test suite exercises config/allocation logic, not a live VM boot.

---

## Architecture

```
Agent → MCP → tool-proxy (inside VM) → portcullis check → OS operation
                  │
                  └─ emits signed lineage edges ─► provenance bundle ─► verify_bundle (Rust / WASM / Py)
```

```
┌───────────────────────────────────────────────────────────────┐
│  nucleus-cli  ·  nucleus audit [PATH]  ·  control-plane API    │  user-facing
├───────────────────────────────────────────────────────────────┤
│  ck-kernel / ck-policy / ck-types   (constitutional kernel)    │  policy admission
│   monotonic self-amendment · signed witness · lineage          │   (library, not yet runtime-wired)
├───────────────────────────────────────────────────────────────┤
│  nucleus (Sandbox + Executor + AtomicBudget + MonotonicGuard)  │  enforcement runtime
├───────────────────────────────────────────────────────────────┤
│  portcullis / portcullis-core / portcullis-effects             │  IFC core
│   13-dim Heyting capability lattice × 6-dim IFCLabel            │
│   sealed effect traits · FlowTracker · Belnap bilattice        │
├───────────────────────────────────────────────────────────────┤
│  identity & trust federation                                   │  keyless identity
│   oidc-core · github-oidc · fly-oidc · oidc-provider           │
│   trust-registry ("LE for agents") · witness (C2SP) · cards    │
├───────────────────────────────────────────────────────────────┤
│  provenance                                                    │  attestation
│   nucleus-lineage · nucleus-envelope · bundle-cas              │
│   verifier-service · verifier-js (WASM) · verifier-py          │
├───────────────────────────────────────────────────────────────┤
│  Firecracker microVM / seccomp / netns  (Linux + KVM)          │  isolation substrate
└───────────────────────────────────────────────────────────────┘
```

---

## Crates

The workspace contains **~47 crates** (42 workspace members + 5 excluded build targets), plus one orphan crate dir (`nucleus-policy`) not yet wired into the workspace. They are grouped below by function. Status reflects the most recent subsystem survey.

<details>
<summary><strong>User-facing tools</strong></summary>

| Crate | Purpose | Status |
|-------|---------|--------|
| [**nucleus-cli**](crates/nucleus-cli/) | Run agents under enforced permissions; ships the `nucleus` binary (`audit` / `run --local` / `run`) | Mixed — Tier 0 working; runner vendor-coupled; `--hook`/`guard` need an external binary |
| [**nucleus-audit**](crates/nucleus-audit/) | Scan configs; verify HMAC tool-proxy logs + SHA-256 receipt chains; provenance / SLSA / C2PA subcommands | Mixed — config scan + tool-proxy-log HMAC verification real; receipt-chain verifier checks hash chain, not yet Ed25519 sig |
| [**nucleus-sdk**](crates/nucleus-sdk/) | Rust client: tool-proxy + node clients, intent profiles, HMAC/mTLS | Working library (unit-tested) |
| [**exposure-playground**](crates/exposure-playground/) / **exposure-web** | TUI / WASM visualizer of the capability lattice | Demo — currently does **not** compile on this branch (portcullis feature-gate bug) |

</details>

<details>
<summary><strong>IFC core (the verified heart)</strong></summary>

| Crate | Purpose | Status |
|-------|---------|--------|
| [**portcullis-core**](crates/portcullis-core/) | 13-dim Heyting capability lattice, 6-dim IFCLabel, FlowTracker, governed memory, Belnap bilattice, Aeneas→Lean pipeline | Working (~1081 tests + ~31 Kani harnesses; fn-level Lean bridge in progress) |
| [**portcullis**](crates/portcullis/) | Higher-level permission planes: attenuation tokens, egress policy, DPI, kernel | Working |
| [**portcullis-effects**](crates/portcullis-effects/) | Sealed effect traits (`FileEffect`/`ShellEffect`/`GitEffect`/…) gated by `production_effects(policy)` | Alpha — file/shell/git do real I/O; web/spawn stubbed |
| [**portcullis-profiles**](crates/portcullis-profiles/) | Work-type presets (CodeReview/BugFix/DocsEdit/Research), vendor-neutral | Working |
| [**portcullis-python**](crates/portcullis-python/) | PyO3/maturin native bindings exposing the portcullis core to Python | Excluded build target (native bindings) |
| [**portcullis-zkvm-guest**](crates/portcullis-zkvm-guest/) | RISC-V zkVM guest (risc0-build) — proving target for core checks | Excluded build target (zkVM guest) |
| [**nucleus-ifc**](crates/nucleus-ifc/) | Standalone IFC API (re-export of the core FlowTracker) | Working |
| [**nucleus-memory**](crates/nucleus-memory/) | Governed memory with per-entry IFC labels + poisoning detection | Working |
| [**nucleus-spec**](crates/nucleus-spec/) | `PodSpec`, generic `credentials.env`, network/resource/seccomp specs, draft `workload_identity` | Alpha — `workload_identity` is a draft RFC with no runtime consumer; **still hardcodes specific LLM-vendor hostnames + workload-identity defaults** (see Known Gaps) |

</details>

<details>
<summary><strong>Constitutional kernel</strong></summary>

| Crate | Purpose | Status |
|-------|---------|--------|
| [**ck-types**](crates/ck-types/) | Manifest schema, BLAKE3 digests, Ed25519 witness bundles, subset/escalation order | Working (tested) |
| [**ck-policy**](crates/ck-policy/) | Pure `check_monotonicity(parent, child)` with per-axis diff report | Working (tested) |
| [**ck-kernel**](crates/ck-kernel/) | Admission engine + append-only lineage; 17 Kani harnesses | Working library — **not yet wired into the runtime** |
| [**nucleus-policy**](crates/nucleus-policy/) | Policy DSL for zero-permission-prompt agent authorization | Orphan — has a Cargo.toml but is **not** a workspace member; undescribed/unwired |

</details>

<details>
<summary><strong>Enforcement runtime & node</strong></summary>

| Crate | Purpose | Status |
|-------|---------|--------|
| [**nucleus**](crates/nucleus/) | `cap-std` sandbox, `AtomicBudget`, `MonotonicGuard`, env-clear `Executor` | Working (cross-platform, `#![deny(unsafe_code)]`) |
| [**nucleus-tool-proxy**](crates/nucleus-tool-proxy/) | Permission gateway: mTLS, SPIFFE policy, HMAC requests, tamper-evident JSONL audit | Working (~187 tests) |
| [**nucleus-mcp**](crates/nucleus-mcp/) | stdio MCP server bridging tool calls to the proxy with decision tracing | Working |
| [**nucleus-node**](crates/nucleus-node/) | kubelet-analogue daemon: pod lifecycle, netns, iptables, cgroups, seccomp, vsock | Alpha — Tier 2 paths Linux + KVM only |
| [**nucleus-guest-init**](crates/nucleus-guest-init/) | Firecracker guest init (mounts, net, secrets, exec proxy) | Alpha — Linux-only by design |
| [**nucleus-net-probe**](crates/nucleus-net-probe/) | Tiny TCP probe for network-policy integration tests | Working (test helper) |
| [**nucleus-otel-bootstrap**](crates/nucleus-otel-bootstrap/) | Shared OpenTelemetry OTLP bootstrap for server binaries (distributed tracing) | Working (shared infra) |

</details>

<details>
<summary><strong>Identity & trust federation</strong></summary>

| Crate | Purpose | Status |
|-------|---------|--------|
| [**nucleus-oidc-core**](crates/nucleus-oidc-core/) | Provider-agnostic OIDC primitives: JWKS, discovery, replay cache, federation dispatch | Working |
| [**nucleus-github-oidc**](crates/nucleus-github-oidc/) | Keyless GitHub Actions OIDC → SPIFFE | Working (proven **live E2E**) |
| [**nucleus-fly-oidc**](crates/nucleus-fly-oidc/) | Fly.io Machine OIDC → SPIFFE (validation half) | Alpha (no live-E2E demo) |
| [**nucleus-oidc-provider**](crates/nucleus-oidc-provider/) | OP: mints EdDSA JWT-SVIDs, RFC 8414 discovery, RFC 8693 token exchange | Alpha (static bundle; live SPIRE stubbed) |
| [**nucleus-trust-registry**](crates/nucleus-trust-registry/) | "Let's Encrypt for agents" — PR-rooted, OIDC-attested, transparency-logged enrollment | Alpha (single maintainer/witness; org-control, not domain-ownership) |
| [**nucleus-witness**](crates/nucleus-witness/) | C2SP `tlog-witness`, Sigsum k-of-n cosignatures | Alpha (in-memory store) |
| [**nucleus-agent-card**](crates/nucleus-agent-card/) | Sign/verify A2A-style agent cards; secret-free, WASM-usable verify | Working |
| [**nucleus-identity**](crates/nucleus-identity/) | SPIFFE IDs, mTLS, P-256 CSR/X.509, did:web, DPoP, SPIRE client | Working (SPIRE/resolver feature-gated) |

</details>

<details>
<summary><strong>Provenance & verification</strong></summary>

| Crate | Purpose | Status |
|-------|---------|--------|
| [**nucleus-lineage**](crates/nucleus-lineage/) | Per-call SPIFFE DAG, signed hash-chained edges, RFC 9162 Merkle log, C2SP witness client | Working (note: crate README is stale and *under*-claims) |
| [**nucleus-envelope**](crates/nucleus-envelope/) | Signed provenance bundle + `verify_bundle` (sigs, Merkle, cosignatures, payload binding) | Working (36 integration / 73 total tests) |
| [**nucleus-envelope-adversarial-corpus**](crates/nucleus-envelope-adversarial-corpus/) | 8 forged bundles that `verify_bundle` MUST reject — CI-gated | Working |
| [**nucleus-bundle-cas**](crates/nucleus-bundle-cas/) | BLAKE3 content-addressing + bao-verified `iroh-blobs` transport | Alpha (no discovery/mesh; pre-1.0 iroh) |
| [**nucleus-verifier-service**](crates/nucleus-verifier-service/) | Public verifier-as-a-service: `/v1/verify`, signed STH, RFC 9162 proofs | Alpha — deploy-ready (26 integration / 70 total tests), **not hosted** |
| **verifier-js** / [`@coproduct/verify`](sdks/verifier-js/) | WASM verifier + one-line `verify(receipt, anchor)` facade | Alpha — npm publish gated |
| [**verifier-py**](sdks/verifier-py/) | PyO3 `verify_bundle` binding | Alpha — no in-repo tests yet |

</details>

<details>
<summary><strong>Control plane, market & demos</strong></summary>

| Crate | Purpose | Status |
|-------|---------|--------|
| [**nucleus-control-plane**](crates/nucleus-control-plane/) | `JobSpec` → agent → signed verifiable `Bundle` orchestrator (ships only `MockJobRunner`) | Working (real drivers live downstream) |
| [**nucleus-control-plane-server**](crates/nucleus-control-plane-server/) | REST + gRPC + SSE API with SPIFFE JWT-SVID auth, idempotency, HMAC webhooks | Working |
| [**nucleus-permission-market**](crates/nucleus-permission-market/) | Lagrangian capability-pricing oracle, wired into the tool-proxy | Working (27 tests, verified invariants) |
| [**nucleus-proto**](crates/nucleus-proto/) / [**nucleus-client**](crates/nucleus-client/) | Generated gRPC/Protobuf types; client signing + drand anchoring | Working |
| **ctf-engine / ctf-server / ctf-mcp** | "The Vault" agent-exfil CTF over the **real** portcullis lattice (simulated tool I/O) | Demo — currently does **not** compile on this branch (same portcullis feature-gate bug) |

</details>

Python: `sdk/python/nucleus` ships a self-contained information-flow kernel (taint propagation, exposure accumulation; 168 passing tests). Native PyO3 bindings to the Rust core live in `portcullis-python` and `verifier-py`. The companion `nucleus_sdk` proxy client is self-labeled **pre-alpha / draft** (v0.0.0, "API will change").

---

## Known Gaps

Documented in [`SECURITY_TODO.md`](SECURITY_TODO.md) and [`docs/production-delta.md`](docs/production-delta.md). Key items, stated plainly:

- **The reference agent runner is not vendor-agnostic.** `nucleus run`/`shell` is currently hardcoded to one specific assistant CLI (binary name, default model string, and a permission-bypass flag), and some audit/MCP identifiers are named for that vendor. Only the core library and the generic `credentials.env` / `PodSpec` interface are vendor-agnostic today.
- **The agent PreToolUse-hook path is not runnable in this repo.** `nucleus run --hook` and `nucleus guard` shell out to a `nucleus-claude-hook` binary that is **not built here** (it moved to the external private orchestrator), and the in-repo install hint (`cargo install --path crates/nucleus-claude-hook`) is stale — that crate directory does not exist.
- **`nucleus-spec` still embeds specific LLM-vendor strings.** `package_registries()` hardcodes `api.anthropic.com`; the default `workload_identity` is `name: "anthropic"` / `audience: "https://api.anthropic.com"`; and doc-comment examples reference `https://api.openai.com` and an `openai-prod` logical name. All of these violate vendor neutrality and need generalizing (e.g. `api.example-llm.invalid` / `LLM_API_HOST` / a generic logical name) before the top-line "vendor-agnostic" claim is fully defensible.
- **`nucleus-policy` is an orphan crate.** It has a full Cargo.toml but is not a workspace member and is not wired into anything — it must be integrated or documented as a stub.
- **The constitutional kernel is a library, not yet runtime-wired.** It decides admissibility in isolation; it does not yet gate the live sandbox, and signature enforcement is opt-in.
- **The public verifier service is not hosted.** It is self-hostable and deploy-ready (`fly.toml`; 26 integration / 70 total tests); no hosted endpoint resolves today. The `@coproduct/verify` npm package and `/verify/` demo are publish-gated.
- **Tier 2 isolation is Linux + KVM only.** macOS test passes do not imply a live VM boot.
- **`bash -c` bypasses command-level checks.** Firecracker network policy is the real defense.
- **`verify-receipts` checks the hash chain, not yet the Ed25519 signature.** Tool-proxy-log HMAC verification *is* real; C2PA verification is feature-gated.
- **Issuance/signing of identities is demo-only.** `LocalIssuer` is `dev`-feature-gated; there is no SPIRE-backed JWT-SVID issuer in this repo.
- **The research-tier Lean formalizations are not discharged.** ~80–85 `sorry` goals remain in the exploratory alignment-tax / cohomology files; only the security core is `sorry`-free.
- **Some crate-level READMEs are stale** (`nucleus-lineage` under-claims; a few doc comments lag the code). The code/tests are the source of truth.

---

## Threat Model

**Protects against:** prompt-injection side effects, invisible Unicode injection, misconfigured permissions, network policy drift, budget exhaustion, privilege escalation via delegation, audit-log tampering, memory poisoning, substitution/truncation of provenance bundles, and silent policy widening (constitutional kernel).

**Does not protect against:** compromised host/kernel, malicious human approvals, side-channel attacks, VM kernel escapes — nor does a green provenance verification imply the agent *behaved well* or that any computation was *correct*.

> **Versioning:** v1.0 means the **interface contract is stable** (see [`STABILITY.md`](STABILITY.md)), not "production-secure by default." The lattice is heavily verified; the runtime is tested but not yet battle-hardened.

---

## Development

```bash
cargo build --workspace
cargo test --workspace
make demo              # taint → block → receipt → compartment switch
```

---

## License

Licensed under either of **Apache License, Version 2.0** or the **MIT license** at your option.

---

## References

- [The Uninhabitable State](https://simonwillison.net/2025/Jun/16/the-uninhabitable-state/) — Simon Willison
- [Lattice-based Access Control](https://en.wikipedia.org/wiki/Lattice-based_access_control) — Denning 1976, Sandhu 1993
- [SPIFFE — Secure Production Identity Framework for Everyone](https://spiffe.io/)
- [RFC 8693 — OAuth 2.0 Token Exchange](https://www.rfc-editor.org/rfc/rfc8693)
- [RFC 9162 — Certificate Transparency Version 2.0](https://www.rfc-editor.org/rfc/rfc9162)
- [C2SP — Community Cryptography Specification Project](https://github.com/C2SP/C2SP) (`tlog-witness`)
- [Aeneas — A Verification Toolchain for Rust](https://github.com/AeneasVerif/aeneas)
- [verify-rust-std](https://github.com/model-checking/verify-rust-std) — AWS's verification density benchmark
