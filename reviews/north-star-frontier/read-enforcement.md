# Nucleus enforcement boundary — static map (2026-09-08)

Scope: every path by which an agent action becomes a side effect, what mediates it, per tier. Static reading only; "implemented / stubbed / documented-only" called out. North-Star clauses referenced as (1)–(5).

## 0. The tiers as actually wired (`crates/nucleus-cli/src/run.rs`)

| Tier | Entry | Where the model process runs | Effect executor | Isolation |
|---|---|---|---|---|
| 0 | `nucleus audit` (`audit.rs:1-15`) | none | none | static scan of MCP configs / PodSpecs; no runtime claim |
| 1 | `nucleus run --local` (`run.rs:474-597`) | **host**, vendor CLI `claude` (`constants.rs:29`) spawned with `--dangerously-skip-permissions --permission-mode bypassPermissions` (`run.rs:1061-1062`) | `nucleus-tool-proxy` subprocess on host (`run.rs:518-537`), `ContainmentMode::Unsandboxed` (`pod_mgmt.rs:400`) | none: `env_clear` + cap-std for file tools; spawned commands are bare host processes (README.md:284 admits this) |
| 2 | `nucleus run` (Firecracker) (`run.rs:664-746`) | **still the host** — the agent CLI + `nucleus-mcp` run on the operator machine and talk HTTP to the proxy in the VM (`run.rs:685-712`) | tool-proxy as guest PID-1 successor (`guest-init/main.rs:50`), `Unsandboxed` declared (`pod_mgmt.rs:390-400`, TODO to derive `MicroVM` from DICE proof) | Firecracker + jailer + netns default-deny + seccomp verify (nucleus-node) |
| "hook" | `run --hook` (`run.rs:408-471`) | host | none | **documented-only / dead**: requires `nucleus-claude-hook` crate which does not exist in the tree (`ls crates` — no match; README.md:284 acknowledges) |

Tier 0/1/2 "mediation" of the *model's tool calls* is cooperative and vendor-specific in every tier: it rests on the agent CLI honoring `--disallowedTools` (`constants.rs:21`), `--allowedTools` (`run.rs:1032`), and a `PreToolUse` exit-2 hook (`mediation.rs:17-25,65-90`). `MediationGuard` (`run.rs:970-1002`) is a typestate proof that the *allowlist* is all `mcp__nucleus__*`; it cannot prove the CLI obeys. This is the whole boundary in Tier 1 and is still the boundary for the *model process* in Tier 2 (the VM confines tool execution, not the model). Clause (1) "any model": the runner is hard-coded to one vendor's CLI contract; clause (4): structural only for what happens *behind* the proxy.

## 1. Scoreboard "sandboxing" fields (`scripts/exemplar-scoreboard.sh:74-89`)

- `bypass_sites=2`: files under `crates/` (excluding examples) that contain `dangerously-skip-permissions|bypassPermissions` AND `allowedTools|mcp-config`. Hits: `crates/nucleus-cli/src/constants.rs` (a doc comment) and `crates/nucleus-cli/src/run.rs`. `shell.rs` (a third launch site, `shell.rs:259-264`) is not counted because it does not bypass permissions. So "2" is one real site plus a comment.
- `mediation_drift=0`: bypass files lacking `DISALLOWED_BUILTIN_TOOLS|--disallowedTools`. Both hits contain the constant name → 0. Purely lexical.
- `disallow_sites = bypass − drift = 2`.
- `effect_stubs=9`: `grep -c 'NotImplemented|NotWired'` over `portcullis-effects` + `portcullis-core`. Actual stubs: `WebEffect::fetch` and `::search` for `RealEffects` (`portcullis-effects/src/lib.rs:519,529`) and `AgentSpawnEffect::spawn` (`lib.rs:774`). The other 6 lines are the enum variant, its Display arm, a runtime match arm (`runtime.rs:495`) and three test lines (`lib.rs:2244,2438`, `runtime.rs:2076`). Real stub count is **3** (sync web fetch/search, agent spawn); `nucleus-machine`'s `FlyMachineDriver` is a separate `NotWired` skeleton (`nucleus-machine/src/lib.rs:11-16`) not counted.

## 2. Structural gates (implemented)

- **Sealed effect home**: `portcullis-effects::RealEffects` is unconstructible outside the crate; `PolicyEnforced<E>` wraps it (`lib.rs:6-12, 858-1090`). `run_argv` / `run_argv_async` / `NetEffect::fetch` take an `Authority` by value and *spend* it (`lib.rs:588-609`); `Authority` is built only from a `DischargedBundle`, which only `nucleus_ifc_kernel::discharge::preflight_action` mints. Un-preflighted spawn is a compile error (`nucleus/src/command.rs:366-368`).
- **Grep gates**: `scripts/check-mediation.sh` (scope: `nucleus`, `nucleus-tool-proxy`, `nucleus-mcp` src) forbids raw `Command::new`, reqwest `.send()`, `VsockStream::connect` outside allowlists. Spawn allowlist is one line (`workload.rs` `spawn_admitted`, `mediation-allowlist.txt`); net allowlist = `node_client.rs`, `art12_shipper.rs`, two audit-sink lines; vsock = `broker_client.rs`. `check-sealed-home.sh` pins the raw primitives inside portcullis-effects to exact lines. `check-mediation-dylint.sh` runs a call-graph lint, MEDIATED_CRATES = `portcullis_effects` only.
- **Lean**: `no_sink_reachable_without_discharge` (`portcullis-core/lean/MediationScopeExtracted.lean:450`) over the closed `SinkClass`/`Operation` enum — a theorem about the *model* of the API, not about the Rust callers.
- **Executor order** (`nucleus/src/command.rs:527-600`): `enforce_isolation` → `refuse_bad_argv` → `check_capability` → `CommandLattice::can_execute` → `reserve_budget` → `spawn_checked` → sealed `run_argv` with `env_clear` + allowlisted env (`spawn.rs:24-28`).
- **Sandbox**: `cap-std` `Dir::open_ambient_dir(work_dir)` (`sandbox.rs:87`), every method takes `Authority` + `DecisionToken`; read/write/edit capability levels enforced (`sandbox.rs:724-777`).
- **Trusted-base manifest** `sandbox-trusted-base.txt` + ratchet (`check-sandbox-trusted-base.sh`), 1 UNPINNED (cgroup-before-workload on a real boot; no KVM in CI for aarch64).

## 3. Effect classes

### 3.1 Filesystem (read/write/glob/grep)
- Tier 1/2: `POST /v1/read|write|glob|grep` (`tool-proxy/main.rs:2101-2106`) → `validation::validate_path` → `http_kernel_decide` (IFC flow graph, `main.rs:2819-2842`) → `run_gate::preflight_fs` → `Sandbox::write(_, Authority)` (`main.rs:3014-3100`). Structural: cap-std root, authority spend, receipts.
- Heuristic: `PathLattice` sensitive-file blocking is string/glob based (`portcullis/src/path.rs:266-330`; SECURITY_TODO §7 "Partial": unicode/NFC untested). `Sandbox::exists` requires no authority (`mediated-set.md:119` "tracked, not excused").
- Hole (Tier 1): `run` commands see the whole host FS; the file sandbox only fences the *file tools*.

### 3.2 Process exec
- Tier 1/2: `POST /v1/run` (`main.rs:3251-3450`) — args-array only, `preflight_runbash` (`run_gate.rs`) → `Executor::run_args` → sealed `run_argv`. Approval retry path re-mints discharge (`main.rs:3400-3430`).
- **Wire mismatch (implemented-but-broken)**: `nucleus-mcp` posts `{"command": String}` (`nucleus-mcp/src/main.rs:94-96, 1170-1181`; tool schema `main.rs:875-882`) but tool-proxy deserialises `{"args": Vec<String>}` with no alias (`tool-proxy/main.rs:891-905`; its own tests use `"args"` `tests_main.rs:74`). The shipped `run` tool through `nucleus run --local`/enforced cannot deserialise → 4xx. Fail-closed, but clause (2) "useful work" via exec is zero on the default path.
- Heuristic layers: `CommandLattice::can_execute` runs on the *space-joined* argv re-split by `shell_words` (`command.rs:552`; `portcullis/src/command.rs:216-236`), metachar set `| ; && || > >> < 2> &>` (`:571-576`), interpreter-flag blocks (SECURITY_TODO §3/§4 "Partial"). Git/PR classification is `argv[0] basename == git && argv[1] == push` (`command.rs:945-956`) — `git -C x push`, `make push`, scripts, `xargs` fall into the generic `run_bash` bucket.
- Host hardening (`hardening.rs`): no-new-privs + rlimits only under `ContainmentMode::HostHardened`, which the tool-proxy never sets; seccomp/Landlock explicitly deferred (`hardening.rs:16-22`). Executor `MicroVM` attestation is a TODO (`pod_mgmt.rs:397-400`); the executor in the guest believes it is `Unsandboxed`, so any policy demanding `microvm()` isolation fails closed *inside* the VM.
- Budget: reserved pre-spawn as base + per-second (`command.rs:885-903`); output/duration true-up pending (SECURITY_TODO §1).
- Legacy inside sealed home: `ShellEffect::run(&str)` and `GitEffect::{commit,push}` never spend their `_authority`, no `env_clear`, no cwd (`portcullis-effects/src/lib.rs:570-585, 720-760`); allowlisted as "legacy floor" in `sealed-home-allowlist.txt`. No production caller found (grep), but public API.

### 3.3 Network egress
- Tier 1/2 web_fetch/web_search: `/v1/web_fetch` (`main.rs:3495-3720`) → `validate_url` → kernel decide → `check_dns_allowlist` / `check_url_allowlist` (**empty list = allow all**, `web_fetch_policy.rs:38-41, 80-83`) → `preflight_web` → sealed `NetEffect::fetch` (`async_traits.rs`) → redirect re-check, MIME allowlist, body cap. No private-IP/metadata block found in the allowlist checker (only a test constructs 169.254.169.254, `web_fetch_policy.rs:388`) — in Tier 1 (no netns) an empty `network` spec means SSRF to link-local is reachable; in Tier 2 the netns default-deny is the backstop.
- Tier 2 physics: netns per pod, `iptables -P INPUT/OUTPUT/FORWARD DROP` (`nucleus-node/src/net.rs:397-407`), chain = deny-then-allow (`net.rs:705-731`) modelled by Lean `EgressConfinement`, IPv6 outside the model (`net.rs:744-757`, guest cmdline `ipv6.disable=1`). dnsmasq with no upstream when `dns_allow` set (`net.rs:315-357`); **with no `dns_allow`, no DNS proxy at all** — hostnames are unreachable only because of the DROP policy. In-guest probe `nucleus-egress-probe` proves default-deny applied on boot (x86_64 only, not a required check; `check-egress-probe.sh` is the no-boot falsifier).
- Backstopped-only channels (`mediated-set.md:74,80`): in-shell egress (`bash -c curl`, `/dev/tcp`) and raw sockets are *not* sink-mediated; fenced by netns only. In Tier 1 these are wide open.
- Tier 1: no netns; `NetworkSpec` ignored (`build_local_pod_spec` sets `network: None`, `run.rs:653`).

### 3.4 Credentialed egress / credentials
- Tier 2: host-performed broker (`nucleus-node/src/broker_perform.rs`), guest asks over vsock with `perform_line(Authority, …)` (`tool-proxy/src/broker_client.rs:173`); idempotency key mandatory; refuses with no capability (`egress.rs:312-320`) — never falls back to reading `credentials.env`. Broker secret delivered by guest-init over vsock before the workload exists (`guest-init/main.rs:225-230`). Host PDP is a coarse capability check; the fine gates (flow graph, taint ceiling) live only in the guest (`broker_perform.rs:19-27` — honest).
- Tier 1: no vsock/broker → credentialed egress refused (fail-closed). `credentials.env` from `--env` goes into the local PodSpec (`run.rs:623-641`) and only flows to a `workload` (none in `--local`).
- **Concrete Tier-1 hole**: `run_local` writes `mcp.json` with `NUCLEUS_MCP_AUTH_SECRET`, `NUCLEUS_MCP_APPROVAL_SECRET`, `NUCLEUS_MCP_SANDBOX_TOKEN` in a world-readable temp dir (`run.rs:880-935`); a permitted `run` command (a bare host process, `run` args not path-checked — only `directory` is, `main.rs:3295`) can `cat` it and then self-approve via `/v1/approve` (`main.rs:4320-4345`, nonce + rate limit but authority is the shared secret). Tier 1 approvals are therefore not a principal boundary. In Tier 2 the CLI hands `nucleus-mcp` **no** approval secret (`run.rs:701-703`) and approvals are Ed25519 pubkey-verified (`main.rs:1618-1650`), so the same channel is closed — at the cost that approvals via `nucleus run` can never be granted (usability, clause 3).
- FM-5 workload posture in guest: distinct uid (`workload.rs:263-282`), `close_range`, env classification refusing unknown `NUCLEUS_*` keys (`check-c1-inbound-fences.sh`), verified by `nucleus-workload-probe`.

### 3.5 Git / PR
No dedicated effect on the agent path; classified inside `run` by the heuristic above (`command.rs:829-856`) and mapped to `git_push`/`git_commit`/`create_pr` capabilities + approval obligations. `GitEffect` in portcullis-effects is a legacy unspent-authority impl (§3.2).

### 3.6 MCP tools
- `nucleus-mcp` exposes read/write/run/web_fetch/glob/grep/web_search and `create_pod|list_pods|pod_status|pod_logs|cancel_pod` (`nucleus-mcp/src/main.rs:850-1001`); nucleus-cli only ever grants the first seven (`run.rs:1068-1098`). Pod routes exist in the proxy only when a node client is configured (`main.rs:2117-2124`); `create_sub_pod` strips agent-requested workloads (`pod_mgmt.rs:707`) and is IFC-gated (SECURITY_TODO §11, ceiling wiring still OPEN).
- `nucleus-mcp-guard` (`proxy.rs`, `classify.rs`): stdio proxy in front of third-party MCP servers; taint by substring name-match rules (`classify.rs:14-16`), TOFU schema pinning, JSON-RPC deny. Heuristic classifier, structural refusal; operator-run, out of the mediation gate scope (`check-mediation.sh:52-59`).
- Memory: `/v1/memory/write|recall` (`memory.rs`) — in-process provenance-verified admission + flow-graph taint; no external side effect, and not exposed as an MCP tool by `nucleus-mcp`.
- Escalation / declassify: `/v1/escalate` (approver trace-chain verify, `escalate.rs:116`), `/v1/declassify` (Ed25519 governor token, `declassify.rs`). Both widen authority at runtime; authority is a *separate principal's* signature, so the workload can only replay what a governor signed.

### 3.7 Browser
No browser/computer-use effect exists (grep: only OIDC/agent-card hits). Out of the envelope entirely (clause 2).

### 3.8 Portcullis-WASI / zkVM
`portcullis-wasi` is a wasmtime host with import-set-by-capability + floating-label IFC (`host.rs:1-27`, `ifc.rs`) — **fixture-backed**: files/http/exec are in-memory seeded stores ("production swaps the closure bodies", `host.rs:20-24`). Correct model, not a shipped effect path. `portcullis-zkvm-guest` runs WASM *parsers* under RISC Zero for proof-of-parse (`lib.rs:1-14`); it is an attestation of pure computation, not an effect boundary.

## 4. TCB per tier

- Tier 1: host kernel; the vendor agent CLI (honours disallow/allow/hook — cooperative, no attestation); `nucleus-cli`, `nucleus-mcp`, `nucleus-tool-proxy`, `nucleus`, `portcullis-effects`, `portcullis-core`/`nucleus-ifc-kernel` (discharge), `cap-std`, `shell_words`, reqwest; the temp-dir secrets. Effectively the whole agent-side Rust stack plus an unattested third-party binary. Sandbox proof is Tier-3 HMAC minted by the CLI itself (`run.rs:503-507`) — proves nothing.
- Tier 2 (guest→host boundary, per `sandbox-trusted-base.txt`): KVM/host kernel, Firecracker VMM (EXTERNAL, CVE-refusal preflight `main.rs:2189-2200`), jailer (chroot/cgroup/uid drop, `firecracker_config.rs:371-527`), seccomp filter contents (EXTERNAL; only *applied* is verified, `firecracker_config.rs:897-960`), netns + iptables + dnsmasq (subprocess-driven), vsock workload API (9 commands, length-bounded, `workload_api_vsock.rs:653-730`), nucleus-node itself (identity CA, broker, PDP), guest-init, in-guest tool-proxy. The model process and `nucleus-mcp` on the host are *outside* the VM and are trusted only via the same cooperative CLI contract as Tier 1.
- What is machine-checked: lattice/IFC algebra (Lean, sorry-free core), discharge-reachability over the enum model, argv predicate (Kani), egress chain semantics (Lean, IPv4 only), netns plan invariants (Rust tests). What is not: the Rust↔Lean function correspondence (README.md:170), Firecracker/KVM, the agent CLI, the cooperative hook, and any Tier-1 property.

## 5. Bypass / hole summary (skeptical)

1. Model process is never confined in any tier; mediation is the vendor CLI's flag/hook contract (`run.rs:1022-1062`, `mediation.rs`). Clause (1)/(4).
2. `run` tool wire mismatch (`nucleus-mcp` `command` vs proxy `args`) — exec path dead by default. Clause (2).
3. Tier 1 secrets on disk reachable via any allowed `run` → self-approval. Clause (3)/(4).
4. Tier 2 approvals unobtainable through `nucleus run` (no secret handed to MCP); `--hook` mode references a nonexistent crate.
5. In-shell/raw-socket egress backstopped only by netns; in Tier 1 unfenced; `web_fetch` empty allowlists = allow-all, no private-range block.
6. Heuristic classifiers on the enforcement path: CommandLattice string re-split, git/PR argv shape, PathLattice glob, mcp-guard substring roles.
7. Executor containment never attested as `MicroVM` (TODO), host hardening never enabled by the proxy, seccomp/Landlock for children deferred.
8. `effect_stubs`/`bypass_sites` metrics are lexical (comment lines and test lines count); true stubs = 3 (`WebEffect::fetch/search`, `AgentSpawnEffect::spawn`).
9. SECURITY_TODO §8 cites `--unsafe-allow-claude`, which no longer exists (stale). §1, §3, §4, §7, §11 remain "Partial".
10. No measurement of the *envelope* (clause 5): scoreboard tracks drift/stubs, not "how much work is safely delegatable"; egress probe boot gate is x86_64-only and not required.
