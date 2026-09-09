# Verification — Clause 1 "any model" gaps (skeptical pass)

Method: every cited file/line re-read in /home/user/nucleus and /home/user/gatehouse (static; nothing built). For each gap I looked for the thing under another name/crate before ruling. Default was "refute unless confirmed by my own reading".

## Verdict table

| id | verdict | corrected impact |
|---|---|---|
| C1-G1 | confirmed | critical |
| C1-G2 | confirmed | high (was critical) |
| C1-G3 | partially-addressed | high |
| C1-G4 | partially-addressed | medium (was high) |
| C1-G5 | confirmed | high |
| C1-G6 | confirmed | medium |
| C1-G7 | confirmed (strengthened) | high (was medium) |
| C1-G8 | reframed | medium |

## C1-G1 — model process never beneath the boundary — CONFIRMED (critical)

Verified: `constants.rs:29` `AGENT_CLI_BIN = "claude"`; `:20-21` built-in denylist; the constant's own doc says the list "cannot be complete" and "the BOUNDARY is the PreToolUse hook" — i.e. the boundary is the vendor CLI honouring a hook. `run.rs:1022-1062` passes `--allowedTools/--disallowedTools/--settings` then `--dangerously-skip-permissions --permission-mode bypassPermissions`; `shell.rs:259-270` same launch. `run.rs:655` and `:772` set `workload: None` in both PodSpec builders, so Tier 2 confines the tool-proxy, not the model.

Counter-evidence weighed:
- The in-guest `WorkloadSpec` seam IS driven by a shipped component: `nucleus-node` boots pods from YAML with `workload:` (`examples/ctf/ctf-pod.yaml`, `examples/openclaw-demo/probe-pod.yaml`), and `tool-proxy/src/main.rs:1387-1416, 2170, 2196` `start_and_drain_workload` runs it; `quickstart-boot.yml:403-465` boot-gates it. `docs/plugin-surface.md` axis 1 documents `workload` + `OVERLAY_DIR` (`scripts/firecracker/build-rootfs.sh:523-556`) as THE agent seam and claims "Shipped: the OpenClaw/NemoClaw demo workload".
- BUT: every boot-gated workload is a probe (`nucleus-workload-probe`/`egress-probe`/`adversary-probe`); the OpenClaw demo runs its agent on the host with the proxy in-guest (`examples/openclaw-demo/README.md`); no agent has ever been run in-guest in CI. `workload_env` (`workload.rs:130-146`) hands the workload only `NUCLEUS_TOOL_PROXY_URL` + `NUCLEUS_TOOL_PROXY_AUTH_SECRET` — no MCP endpoint in the guest (the rmcp `--mcp` server is `default = []`, built by no workflow/Dockerfile: `docker/Dockerfile.node:47`, `Dockerfile.tool-proxy:41` build only `remote-audit`).
- README:145 and README "Known Gaps" (:435-436) already self-report the runner as a vendor-coupled example and the hook path as not runnable.

So the finder's evidence is accurate; the nuance is that the seam is a documented, node-driven, boot-tested mechanism for *probes*, not "no shipped runner drives it". Impact stays critical: for the reference product the boundary for the model process is cooperative in every tier. (See missed gap M3: putting the agent in-guest today would NOT give fs mediation either.)

## C1-G2 — MCP `run` wire-incompatible; second MCP server compiled out — CONFIRMED (high, not critical)

Verified: `nucleus-mcp/src/main.rs:94-96` `RunRequest{command: String}`, schema `:875-882` requires `command`, `:1170-1181` posts it to `/v1/run`. Proxy `main.rs:891-905` `RunRequest{args: Vec<String>, stdin, directory, timeout_seconds}`, no `#[serde(alias)]` anywhere in proxy main.rs; `run_command` (`:3251`) reads `req.args` directly, so `{command}` is a 4xx deserialisation error. `crates/nucleus-mcp` has no `tests/` dir; nothing in `tests/` or `e2e` drives the `run` tool end to end. `tool-proxy/Cargo.toml:18-23` `default = []`, `mcp = ["dep:rmcp","dep:schemars"]`; `mcp.rs:1` `#![allow(clippy::disallowed_types)] // #1216 MIGRATION TARGET`, `:9-10` HMAC skipped on stdio, `:60-62` `RunParams{args}`. No workflow/Dockerfile/script passes `--features mcp`. `run.rs:1068-1098` never pushes `mcp__nucleus__create_pod` although `nucleus-mcp/main.rs:844-846` computes `allow_manage_pods`.

Why high rather than critical: it is fail-closed, and a client that sends `args` works today — the OpenClaw plugin does exactly that (`examples/openclaw-nucleus-plugin/src/index.ts:278-315` sends `{args: params.args}`). The defect is the shipped reference runner's exec path, not the proxy. Effort small.

## C1-G3 — no decision API / adapters; hook private — PARTIALLY-ADDRESSED (high)

Verified: proxy routes `main.rs:2095-2124` are effect endpoints only; `grep v1/decide|authzen|a2a|PreToolUse|permissionDecision` in proxy+node src → nothing. `mediation.rs:65-90` allows only exact names with `NUCLEUS_MCP_TOOL_PREFIX` (`mcp__nucleus__`). `hook_adapter.rs:31-45` hard-codes one vendor's tool names, unknown→RunBash, `:51-80` substring heuristics; `classify_tool` callers = tests only (`attack_landscape.rs`). `docs/quickstart-hook.md:6` installs the private `nucleus-claude-hook`; 5 docs reference it. `sdk/python/nucleus/kernel.py:1-9` is a pure-Python reimplementation.

What already exists that the finder under-weighted:
- `examples/openclaw-nucleus-plugin` — a real adapter for a second, non-vendor framework: 8 tools POSTing to the proxy with HMAC (`index.ts`). Effect-routing, not a decide API, and skill-steered ("the agent follows voluntarily").
- `nucleus-mcp-guard` — a framework-agnostic stdio MCP proxy that mediates ANY agent↔MCP-server session through the proven IFC gate with "zero agent changes" (`lib.rs:1-30`). It is IFC-trifecta only (not the capability lattice), and a separate name-substring classifier.
- `portcullis-python` — a real pip binding of the Rust policy algebra (`crates/portcullis-python/src/lib.rs:1-25`), so "framework SDK = pure-Python mirror" is only half the story; but it exposes the algebra, not the live kernel + flow graph.
- `portcullis::says_admission::decide_operation`, `Kernel::decide_term_with_flow` exist as library APIs any Rust host can link.

Net: the absence of a protocol-shaped `/v1/decide` (allow/deny/ask/updated_input) reachable from a non-Rust framework is confirmed; adapters exist but are per-effect, per-framework examples. Impact high.

## C1-G4 — no foreign-authority ingress — PARTIALLY-ADDRESSED (medium)

Verified: `auth.rs:584-602` `AuthTier` = {SpiffeMtls, ApprovalEd25519Drand, ApprovalHmacDrand, HostVsock, Hmac}; no `at+jwt`/`authorization_details`/`act` consumption in proxy src.

Counter-evidence:
- Identity ingress from foreign ecosystems exists at the node: `nucleus-node/src/oidc.rs` verifies GitHub OIDC JWTs against GitHub JWKS (jti replay, repo allowlist) and issues SPIFFE certs; `nucleus-fly-oidc`; `nucleus-github-oidc/token_exchange.rs` is a vendor-neutral RFC 7523 client.
- `pod_authority.rs` case 2 re-roots an external mTLS caller's delegation cert with `provenance` "(RFC 8693 `act` semantics)".
- `portcullis/src/says_admission.rs` (DLC-D) is a signed capability-credential ingress with a Lean `admit_joint` no-false-admit theorem — but bound to nucleus cap atoms, and `set_dlc_admission` has ONLY test callers (`portcullis/tests/kernel_dlc_admission.rs`), none in proxy/node.
- `trust_gate.rs` consumes attestation JWTs but is "observational only" by design (#2438).

So: foreign *identity* enters; foreign *capability* objects (OAuth scope/RAR, ID-JAG, AP2 intent, rule files) do not. CLAUDE.md's integration pattern deliberately places translation in the orchestrator, so part of this is a design decision rather than a defect. Impact medium: it raises friction for clause 2/3, not a structural hole for clause 1.

## C1-G5 — subagent trees not first-class — CONFIRMED (high)

Verified: `portcullis-effects/src/lib.rs:767-776` `AgentSpawnEffect for RealEffects` → `NotImplemented`; `constants.rs:21` disallows `Agent`; `run.rs:1068-1098` no `create_pod`; `pod_mgmt.rs:198,707` `strip_requested_workload` (child pods carry no workload); `pod_authority.rs:24-56` child cert one hop below parent + `BudgetLedger` (well built, as stated). Additional confirming evidence the finder missed: `tool-proxy/src/session_token.rs:1-22` — the session `SignedTaskRef` is "present-not-consumed": verified once at boot, gates nothing yet ("a later PR gates RunBash on it"), and there is no per-request `x-nucleus-task-token` path in the proxy (`grep task-token` → session_token.rs only). `taskref_token.rs:316` `attenuate` exists in `nucleus-provenance-memory` with no proxy consumer. `examples/a2a-server` verifies cards; no attenuation (`grep attenuat|delegat` → none).

## C1-G6 — vendor-neutrality invariant unenforced; leaky defaults — CONFIRMED (medium)

Verified: `steering.toml:15-21` block-severity regex; zero consumers across .rs/.sh/.yml/.py/.toml. `ci/no-vendor-strings.sh:30-33` defaults to the two OIDC crates; `manifest-guards.yml:66`, `oidc-gates.yml:44-54` only. `nucleus-spec/src/lib.rs:379` `"api.anthropic.com"` in `NetworkSpec::default().dns_allow`, asserted at `:1659`; `action.yml:14` default model string, `:76-80` installs the vendor CLI; `guard.rs:240-247`; `Cargo.toml:24`; `token_exchange.rs:7` (docstring only — the code is neutral). 16 `# vendor-allow:` annotations exist as a nascent ledger but with no count/ratchet. README Known Gaps (:435-437) already self-reports these, including a `workload_identity` default `name: "anthropic"` the finder did not cite. Medium: hygiene, but the default-egress host is load-bearing for every pod that omits `network`.

## C1-G7 — zero multi-model/framework evidence — CONFIRMED and STRENGTHENED (high)

Verified: `red-team-agent.yml:96-103` one `LLM_MODEL` per run; `defense.py:96,110` `NotImplementedError`; `production-delta.md:82` "Not started"; `scoreboard.json` top-level keys = formal_verification/rust_craft/sandboxing/hygiene, no model/vendor/framework key; `north-star-ledger-ratchet.txt` has no model/vendor row; `north-star.md:667` bullet only; `red_team_live.sh:1-10` needs `claude` + private hook; `kernel.py:8` points to the private hook.
Strengthening: the "vendor-agnostic" harness is generic only in env-var NAMES. Its wire protocol is one vendor's Messages shape — `x-api-key` header (`red_team_harness.rs:88`), `api-version` header (`:816`), `tool_use` content blocks (`:789`), `input_schema` (`:769`), `stop_reason`/`content_block` handling. An OpenAI-compatible or open-weight endpoint cannot be driven without a second client. `examples/independent-conformance` is commerce-only (route_to_commons), not the kernel. Raised to high: clause 1 is not just unmeasured — the one measuring instrument is vendor-locked.

## C1-G8 — coding-assistant-shaped vocabulary — REFRAMED (medium)

What is wrong in the finder's framing: `PermissionLattice` (`portcullis/src/lattice.rs:60-80`) already carries effect-level scoping — `PathLattice{allowed, blocked, work_dir}` (glob sets), `CommandLattice`, `BudgetLattice`, `TimeLattice` — and `PodSpec.network` carries host/CIDR sets. A non-LLM workload CAN be least-privileged: each pod is admitted under its own `PolicySpec::Inline` lattice, meet-clamped to the caller's cert (`pod_authority.rs`). `Intent` (`nucleus-sdk/src/intent.rs`) is SDK sugar over profiles, not the authorization vocabulary. `PolicyManifest.toml` is the repo's own constitution for agents editing nucleus (header :1-8), not the runtime vocabulary — though its `tools_allow` naming one vendor's tools is a real G6-class leak in a nucleus crate's (ck-kernel) input format.

What survives, sharper: (a) `PathLattice::meet` (`path.rs:111-127`) is SYNTACTIC string-set intersection over glob patterns — `src/**` ⊓ `src/foo/**` = `NOTHING_ALLOWED`, not `src/foo/**` — so any framework/sub-agent that narrows a path scope loses everything; gatehouse's `subsetGlob`/`leqCap` (`prelude/ci.writ:51-73`, `gatehouse-types/src/lib.rs:85-96`) is semantic. (b) `WorkloadSpec` (`nucleus-spec/src/lib.rs:905-935`) declares no capability, so admission cannot check "workload's declared needs ≤ ceiling" — the pod policy is the only bound. (c) MCP tool→Operation classification is name-heuristic (`hook_adapter.rs:51-80`, `nucleus-cli/src/manifest.rs:416`). (d) gatehouse and nucleus are unconnected: gatehouse's only nucleus references are test repo names (`gatehouse-agent/tests/pod_spec.rs:19,215`), and `trusted-base.txt:128` executor sandbox UNPINNED/EXTERNAL. Corrected title: "Effect-level scoping exists in PermissionLattice but path meets are syntactic, workloads declare no Cap, and tool→effect mapping is name-heuristic". Medium.

## Missed gaps

M1. Live-LLM eval client is single-vendor on the wire (see G7): `red_team_harness.rs:88,769,789,816`.
M2. Budget is delegated to the vendor CLI: for the host-run agent, `BudgetLattice.max_cost_usd` is enforced only by passing `--max-budget-usd` to the vendor binary (`run.rs:454-455, 1048-1049`); nucleus has no budget meter on the Tier-1/2 host-agent path (`BudgetLedger` counts only pod creation, `pod_authority.rs`). Any other CLI ignores it → unequal guarantees.
M3. In-guest workload confinement is uid-drop + `env_clear` + netns only: no seccomp/Landlock/mount namespace on the workload (`grep seccomp|landlock|unshare` in `workload.rs` → none; guest-init:725 concerns the VMM), and the work dir is `chown`ed to the workload uid (`workload.rs:405-410`). An agent placed in-guest therefore reads/writes files DIRECTLY, bypassing `/v1/read`/`/v1/write` and the IFC taint that powers the uninhabitable-state gate. The two placements have unequal guarantees, and G1's direction ("agent inside the pod") needs fs mediation (Landlock/9p-through-proxy) to be equal.
M4. Session `SignedTaskRef` is present-not-consumed (`session_token.rs:1-22`): the per-task authority object any framework could present is verified at boot and gates nothing; no per-request token path exists.
M5. Mediation allowlist is bound to one client's MCP naming convention: `mediation.rs:75-82` denies any tool not prefixed `mcp__nucleus__` (`run.rs:949`); other MCP clients name server tools differently, so the "runtime allowlist hook" cannot be reused verbatim even if a client offered a compatible hook.
M6. Three divergent Python surfaces: `sdk/python/nucleus/kernel.py` (pure-Python kernel), `sdk/python/nucleus_sdk/{profiles,exposure}.py` (pure-Python lattice/exposure with their own tests), and `crates/portcullis-python` (Rust binding). None is parity-tested against the other; mirror drift is broader than kernel.py alone.
