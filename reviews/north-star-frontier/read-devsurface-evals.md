# Nucleus — Developer Surface and Evaluation/Measurement Story

Static read of `/home/user/nucleus` (no builds). Legend: **IMPL** = implemented and wired; **STUB/INERT** = code exists but not on a live path or refuses to run; **DOC-ONLY** = documented but nothing in this repo implements it. Line refs are `path:line`.

---

## 1. How a principal says "I authorize X" today

### 1.1 The vocabulary (what can be expressed)
The unit of authorization is a `PermissionLattice` resolved from a **profile**. Canonical profiles are YAML in `crates/portcullis/profiles/*.yaml` (10 files: codegen, code-review, doc-editor, local-dev, read-only, release, research-web, safe-pr-fixer, test-runner, triage-bot). Each profile expresses (`crates/portcullis/profiles/codegen.yaml:17-48`):
- 12 fixed capability dimensions × 3 levels (`never | low_risk | always`): read/write/edit files, run_bash, glob/grep, web_search/web_fetch, git_commit/git_push/create_pr, manage_pods (+ `spawn_agent` in the Python mirror, `sdk/python/nucleus/kernel.py:22-35`).
- `paths.blocked` globs; `budget.max_cost_usd / max_input_tokens / max_output_tokens`; `time.duration_hours`.
- Implicit "uninhabitable state" rule: if private-data + untrusted-content + exfil vectors are all ≥ low_risk, exfil ops get an approval obligation auto-added (`docs/permissions.md:82-100`).

Legacy profiles are Rust constructors (`crates/nucleus-cli/src/profiles.rs:48-62`: filesystem-readonly, network-only, edit-only, fix-issue, database-client, demo, permissive, restrictive). Aliases at `profiles.rs:36-46`.

A `PodSpec` YAML (`examples/podspecs/safe-pr-fixer.yaml`) adds `work_dir`, `timeout_seconds`, `policy: {type: profile, name}`, `network.dns_allow[]`, and `credentials.env`. Note the example ships `api.anthropic.com` in its DNS allowlist (line 24) — a vendor string in the OSS examples.

Level-0 programmatic policy: `PolicyCheck` trait + `all_of/any_of/first_match/Not` combinators + built-ins (`RequireApprovalFor`, `BudgetGate`, `RateLimit`, `DenyAdversarialTaint`…) documented in `docs/quickstart/policy.md:1-121`. Verdicts are 4-valued Belnap (`Allow/Deny/Unknown/Conflict`).

**What is NOT expressible today** (vs. clause 3 of the North Star): per-path *write* scoping beyond a blocklist; per-host network scoping at the profile level (only in PodSpec); per-command allowlists in YAML (only in the Rust `CommandLattice`); multi-principal / k-of-n approval at the profile level; explicit token *revocation* (only expiry — `grep revoke` finds only doc comments at `crates/portcullis/src/escalation.rs:177`, `manifest_enforcement.rs:4-30`); per-operation budgets; and any notion of "task" or "goal" scope.

### 1.2 Delegation chains — IMPL (CLI + tool-proxy)
`nucleus token mint|delegate|inspect|verify` (`crates/nucleus-cli/src/token.rs:38-130`): mint a root token from a profile + SPIFFE identity with `--expires-hours`; `delegate` attenuates to a child identity with a profile that must be ≤ parent and expiry ≤ parent; `verify --max-depth`. Delegation is monotone-meet (Lean-proved per README). The Python example `sdk/python/examples/delegation_forest.py` demonstrates orchestrator→sub-pod clamping with cascade-cancel. Runtime widening exists only via `POST /v1/escalate` (`crates/nucleus-tool-proxy/src/escalate.rs:25-45`), bounded by the approver's trace-chain ceiling and policy `max_grant`.

### 1.3 Approvals — IMPL, but the only human UI is a TTY prompt
- Proxy side: `POST /v1/approve` (`crates/nucleus-tool-proxy/src/main.rs:4319-4355`) accepts either a legacy HMAC `--approval-secret` or, preferred, an Ed25519 approver public-key roster with drand-anchored signatures (`main.rs:145-157`, `auth.rs:120-130`) so the guest holds no forgeable secret. Nonce replay-protected, rate-limited, audit-recorded with `ActorIdentity::Unknown` (line 4342 — the approve record does not bind *which* approver signed).
- Human side: `nucleus-mcp` opens `/dev/tty` and asks `Approve operation 'X'? [y/N]` (`crates/nucleus-mcp/src/main.rs:1382-1398`); no TTY ⇒ deny (fail-closed). Approval is one-shot (`kernel.grant_approval(op, 1)`, line 1072).
- In `nucleus run --local` the approval secret is injected into the MCP server's env (`crates/nucleus-cli/src/run.rs:910-915`), i.e. the approval credential lives in the process the model drives; privilege separation is by env var, not by principal.
- Python SDK: `Session.approve(op, action)` POSTs `/v1/approve` itself (`sdk/python/nucleus_sdk/session.py:138-160`, `client.py:154-160`) — the *caller* self-approves if it holds the approval secret. There is no Slack/web/webhook approval flow, no approval queue, no UI. The only "UI"s in the repo are a ratatui exposure playground (`crates/exposure-playground`, WASM twin `crates/exposure-web`) and a Leptos marketplace dashboard — neither is an authorization surface.

### 1.4 Fleet-level controls
`nucleus lockdown [--pod|--selector|--restore|--reason]` (`crates/nucleus-cli/src/lockdown.rs:19-42`) broadcasts read-only to all pods via node gRPC (a machine-local HMAC signal file, `lockdown.rs:45-58`). This is the closest thing to revocation.

### 1.5 Compartments / airlock — DOC-ONLY in this repo
`docs/quickstart-hook.md:27-45` and `templates/skills/{airlock,clearance,scan}/SKILL.md` describe `NUCLEUS_COMPARTMENT=research|draft|execute|breakglass:reason` with single-step escalation. `grep -r NUCLEUS_COMPARTMENT crates sdk` returns nothing: the implementation was in `nucleus-claude-hook`, which "moved to nucleus-code (private product repo)" (`Cargo.toml:83`). `docs/quickstart-hook.md:6` still says `cargo install --git … nucleus-claude-hook`, which cannot work from this tree. `docs/statusline.md` likewise targets the private hook.

---

## 2. Developer surface inventory

### 2.1 `nucleus` CLI (`crates/nucleus-cli/src/main.rs:78-160`, 18.3K LOC)
`audit` (Tier-0 config scan → text/SARIF, `audit.rs:33-49,691-790`), `trust`, `guard {audit,init,enable,status}` (MCP config scanner; probes `.claude/settings.json`, `.cursor/mcp.json`… `guard.rs:19-27`), `manifest`, `run`, `shell`, `setup`, `verify --tier2` (boots a real pod), `two-safety` (boot twice differing in a secret; noninterference check), `start/stop`, `lockdown`, `doctor`, `profiles`, `config`, `observe` (audit JSONL → least-privilege YAML profile, `observe.rs:15-31` — a real least-privilege ratchet), `replay`, `token`, `identity`, `node`, `lineage`, `lineage-verify-chain`, `envelope`, `envelope-verify`, `bundle`, `verify-attestation`, hidden `mediation-hook`.
- `nucleus audit export --format soc2` claimed in `docs/for-openclaw-users.md:36` — **DOC-ONLY** (no `export`/`soc2` in `audit.rs`).
- `nucleus run --vm` in `NORTH_STAR.md:46` — **DOC-ONLY**; `RunArgs` has `--local` and `--hook` (`run.rs:171-181`), default = node/Firecracker.

### 2.2 `nucleus run` / `shell` — the reference runner is single-vendor
`constants.rs:29` hardcodes `AGENT_CLI_BIN = "claude"`; `constants.rs:20-21` a denylist of that CLI's built-in tools; `run.rs:1060-1061` passes `--dangerously-skip-permissions --permission-mode bypassPermissions`; `mediation.rs:1-47` registers `nucleus mediation-hook` as a `PreToolUse` allowlist hook (exit 2 = block). The README admits this (`README.md:145`: "Treat the runner as an integration example, not a vendor-agnostic component"). `action.yml:12-14,72-75` installs `@anthropic-ai/claude-code` and defaults `model: claude-sonnet-4-20250514`, in direct tension with `steering.toml:16-21` (block-severity regex on `claude|anthropic` across `**/*.md,*.toml`) and `ci/no-vendor-strings.sh` (which only scans the two OIDC crates, lines 28-31). **Clause 1 ("any model") is satisfied at the kernel/proxy layer (generic `credentials.env`, HTTP/MCP ports) but not at the shipped runner.**

### 2.3 SDKs
- **Rust `nucleus-sdk`** (1.9K LOC): `Nucleus` facade over `ProxyClient` (HTTP) + `NodeClient` (gRPC), `Intent` enum → profile (`crates/nucleus-sdk/src/intent.rs:19-45`), HMAC or mTLS auth. IMPL.
- **Python `nucleus_sdk`** (2.1K LOC, "Draft. API will change." `sdk/python/README.md:5`): same intent model, `Session.fs/net/git`, `approve()`, `Trace`. Pod creation "not included yet" (README:41). Plus `sdk/python/nucleus/kernel.py` — a **pure-Python reimplementation** of the kernel "for easy integration with agent frameworks" (kernel.py:1-9). This is exactly the mirror pattern that `crates/nucleus-flow-replay/tests/kernel_vs_mirror.rs:1-22` found diverged 4.2% from the real kernel for AgentDojo; no parity test binds `kernel.py` to Rust.
- **`portcullis-python`** (PyO3, excluded from workspace, `Cargo.toml:90`): bilattice + combinators; "pip install portcullis". Real bindings, not a mirror.
- **`sdks/verifier-js`** (`@coproduct_inc/verifier-wasm` 0.1.0) and **`sdks/verifier-py`** (maturin): WASM/pyo3 wrappers over `nucleus-envelope` + `nucleus-ifc` so a relying party can `verify()` a receipt and `recompute()` the IFC verdict locally (`sdks/verifier-js/README.md:1-45`). IMPL; scope honestly stated as "over the declared inputs".
- **`crates/nucleus-node-binding`** is *not* a Node.js binding: it is a signed iroh `NodeId`↔passport binding (335 LOC, `README.md:1-20`).

### 2.4 Framework integrations
- **OpenClaw plugin** (`examples/openclaw-nucleus-plugin/src/index.ts`, 554 LOC): registers 8 `nucleus_*` tools that POST to the tool-proxy with HMAC headers, plus a `SKILL.md` telling the model to prefer them. Enforcement relies on the sandbox denying built-ins; README:21 cites `anthropics/secureclaw` (vendor string).
- **AgentDojo adapter** — see §3.2; currently raises at construction.
- **`docs/integrations.md`** (k8s agent-sandbox, agentsh, Tailscale) is architectural narrative; `grep agentsh crates` → nothing. **DOC-ONLY**. `docs/plugin-surface.md` enumerates 8 seams and honestly marks Apple-VZ driver as "what remains".
- `examples/claude-settings/*.json` are vendor-CLI settings files (allow/deny/ask lists) used as scan fixtures for `nucleus audit`.

### 2.5 Friction evidence
`docs/perf/RUBRIC-LEDGER.md` row 2/2b (2026-09-02/03): on a live `codegen` pod "**There is no file in the sandbox a `codegen` pod may read**", write returned `approval_required`, and `/work` was refused as `sandbox_escape` — the harness could not complete a read/write round-trip. Row 1: single pod submit→running 5,580 ms; N≥10 concurrent all failed on a 30 s health timeout. This is the most honest "clause 2" (useful work, low friction) data in the repo, and it is negative.

---

## 3. Evaluation and measurement story

### 3.1 What is measured and gated (all "nothing escaped" style)
| Artifact | Status | What it measures |
|---|---|---|
| `scoreboard.json` + `scripts/exemplar-scoreboard.sh` + `exemplar-scoreboard.yml` | IMPL, ratcheted, anti-Goodhart paired guards (`exemplar-scoreboard.sh:9-15`) | grep-derived code hygiene: extracted vs hand-model proofs, `sorry` count, permissive `.verify()` calls, unsafe blocks, mediation drift, bypass sites, effect stubs (9). |
| `scripts/north-star-ledger-ratchet.txt` + `check-north-star-ledger.sh` | IMPL; CLAUSES=9, NOT_YET=2, both pinned; every promotion/demotion logged with evidence handles | Status (PROVED/TESTED/NOT-YET) of the 9 clauses of the *confidentiality* sentence in `docs/north-star.md`. Purely a safety ledger. |
| `crates/nucleus-adversary-probe` (240 LOC) + `adversary-probe.yml` + `scripts/check-adversary-probe.sh` | IMPL, per-PR | In-guest attacker: PID-1 secret theft, rootfs tamper, exfil → `CONTAINED/BREACH/INCONCLUSIVE`. |
| `nucleus-egress-probe`, `-podlist-probe`, `-workload-probe`, `-net-probe` | IMPL, boot-gated | Backstops proven-applied-on-boot (netns default-deny, cross-pod list confinement, FM-5 env/fd posture). |
| `crates/nucleus-envelope-adversarial-corpus` (C01–C09, `src/cases.rs:17-221`) | IMPL, CI gate | Forged provenance bundles must be rejected. |
| `crates/nucleus-tool-proxy/tests/attack_corpus.json` | IMPL | 13 IFC source→sink vectors; 11 `enforced`, **2 `known_gap`**. |
| `red_team_harness.rs` (`--features red-team`) + `red-team-agent.yml` (nightly) | IMPL, vendor-agnostic env (`LLM_API_URL/KEY/MODEL`), keyless OIDC option | Live LLM tries to exfiltrate a canary; any success reds. Non-deterministic, nightly. |
| `tests/red_team_live.sh` | Depends on `claude` CLI + private `nucleus-claude-hook` (lines 8-10) | Cannot run from this tree. |
| `fuzz/fuzz_targets/*` (4 targets) | IMPL, manual (`fuzz/README.md`) | path/command/serde invariants. |
| `crates/ctf-engine` ("The Vault", 7 levels `src/level.rs:182-650`) + `ctf-server` MCP/JSON API | IMPL, hosted | Playable exfil challenge; runs `exposure_core::should_deny`, which `flow-replay/src/lib.rs:5-9` notes is **not the live path**. |
| Kani (118 harnesses), Lean (~1,028 theorems), `formal-numbers.yml`, `line-ratchet.yml`, `clippy-ratchet.yml` | IMPL | Proof/hygiene counts must match the tree. |
| `crates/nucleus-perf podburst` + `docs/perf/RUBRIC-LEDGER.md` | IMPL, manual loop | Pod start latency, concurrency wall, RSS. |

### 3.2 External benchmarks (AgentDojo) — present but INERT
`benchmarks/agentdojo/portcullis_defense/` has a full runner (`run_benchmark.py`, suites workspace/travel/banking/slack, 4 attack types, reports **utility rate and security rate** at lines 105-115 — the only place in the repo that computes a utility-vs-security pair). But `defense.py:96` and `defense.py:110` `raise NotImplementedError(_MIRROR_REMOVED)` at construction: the Python exposure mirror was deleted after `kernel_vs_mirror.rs` measured 4.2% disagreement with the real kernel over a 430-decision corpus (`defense.py:40-58`). The runner has no import of `nucleus-flow-replay`, no workflow references `agentdojo`/`portcullis-bench`, and `--dry-run` only checks tool-map coverage. **Net: zero AgentDojo numbers are producible or gated today.** The tool→operation mapping is preserved as data (`make_divergence_corpus.py:40-60`, ~80 tools → 14 `Operation`s).

### 3.3 The one frontier-shaped instrument: `nucleus-flow-replay`
`crates/nucleus-flow-replay` (384 LOC lib + CLI) replays JSONL tool-call traces through `Kernel::decide_term_with_flow` — the real HTTP-chokepoint path — with no model or network. Corpus: 155-line `corpus.jsonl`, 32-line `sink-sweep.jsonl`. `tests/sink_consequence_split.rs:3-5` records the key utility finding: "**100% of refusals are attributable to the session-wide taint ceiling** — once any adversarial content is observed, all outbound actions are denied regardless of what they would do." `report_what_grading_would_change` (lines 139-183) measures how many taint-caused refusals a graded policy would convert to approval/allow and asserts recovery > 0 and protection > 0. The graded response is wired as a `graded: bool` flag in `ifc_egress_verdict` (`crates/portcullis/src/exposure_core.rs:207-240`) — a real, if binary, lever on the frontier. This is the only artifact that measures *delegatable work retained*, and it is a unit test printing to stderr, not a tracked metric.

### 3.4 `nucleus-eval`, `nucleus-rubric`, `nucleus-oracle` — receipt formats, not harnesses
Despite the name, `crates/nucleus-eval` (437 LOC) is a **receipt → CreditEvent minting kernel**: recompute `produced == expected` counts, mint a credit bounded by recomputed pass-rate, mint a *debit* on overclaim (`lib.rs:1-50`). `nucleus-rubric` ranks by RecomputeVerified dimensions only; `nucleus-oracle` "grades RECORDED outputs. It executes nothing." (`README.md:17`). None run an agent, load a task suite, or produce a time series. They are honesty scaffolding for a future eval economy (`nucleus-creditworthiness`, `nucleus-permission-market` "Lagrangian permission pricing oracle").

### 3.5 Is there a frontier metric?
**No.** Every ratcheted number (scoreboard, north-star ledger, probe verdicts, corpora, formal counts) is monotone in *containment*. There is no tracked metric of the form "tasks completable under profile P without human approval", no utility baseline (AgentDojo path dead), no false-refusal rate, no approval-rate/latency, no per-profile "work envelope" history. `docs/north-star.md` (835 lines) never uses "frontier", "delegatable", or "useful work"; its ledger is the 9-clause confidentiality sentence. `NORTH_STAR.md:44-48` frames tiers by *enforcement depth* not by *work delegated*. The `observe` subcommand (least-privilege profile from traces) and `flow-replay`'s sink-split are the only seeds of a frontier measurement.

---

## 4. Summary against the five clauses
1. **Any model** — kernel/proxy/SDK/red-team harness are generic; the shipped `run/shell` runner, `action.yml`, quickstart-hook, statusline, skill templates, and `tests/red_team_live.sh` are bound to one vendor CLI or a private hook. README:145 discloses this.
2. **Useful real-world work** — 12 coarse capabilities; effects for web fetch/search/spawn are stubs (README:155; `scoreboard.json` effect_stubs=9); perf ledger shows a codegen pod that could not read or write; ~5.6 s pod start.
3. **As authorized** — profiles + attenuation tokens + escalation + lockdown are real; approvals are TTY-only, single approver, self-approvable from the SDK; no revocation, no multi-principal, no scoped writes.
4. **Structurally incapable** — this is where the effort is: probes, corpora, ratchets, Lean/Kani, mediation hook. Two attack vectors still `known_gap`; `bypass_sites: 2`.
5. **Continuously expand** — ratchets exist only for *safety* counts. No utility/frontier metric is tracked; the AgentDojo bridge is intentionally broken pending a flow-replay rewrite; `sink_consequence_split.rs` is the lone measurement of utility lost to the taint ceiling.
