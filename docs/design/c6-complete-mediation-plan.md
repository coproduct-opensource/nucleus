# C6 — "every mediated channel": a staged plan

**Status of this document:** SCOPING ONLY. No runtime change, no ledger change is
made here. This is the direction-setting note for the hardest, headline clause of
the confidentiality ledger (`docs/north-star.md`), written the way the
declassification arc (#2227–#2238) was scoped, so a direction can be approved
before any multi-PR execution.

> **Execution status (2026-08-11):** Phase 0 (inventory) landed — the closed
> `EgressChannel` table lives in `docs/architecture/mediated-set.md` with the
> `documented_inventory_equals_the_enum` parity test. Phase 1a (Tier-A theorem
> `no_sink_reachable_without_discharge`, #2241) and Phase 1b (the `mediated`
> lint enforced-at-zero over `portcullis-effects`, #2244) landed. C6 remains
> **NOT-YET**; Phase 2 (network backstop proven fail-closed on boot) and Phase 3
> (`effects()` hatch + bash-curl gap) are the remaining Tier-B work.

## 0. The clause, and why it is genuinely the hard one

C6 is the clause "*this covers explicit flows through **every mediated channel***"
(`docs/north-star.md:44`). C1 got the **inbound** half of "every channel" tractable
by a closed enum: `ChannelKind` (`crates/nucleus-ifc-kernel/src/extracted/channel.rs:78`),
Aeneas-extracted, over which `no_channel_delivers_secret_to_the_workload` is proved —
a new child-inheritance channel forces a `match` arm or the flagship will not compile.
That worked because the inbound surface is **finite and parent-controlled**: the set
of dimensions a spawned child inherits (env, argv, cwd, stdio, fd, uid, cmdline) is
fixed at the one `Command::new` the parent runs.

C6's outbound/effect half is harder for two structural reasons:

1. **The egress surface is open, not parent-controlled.** Once a shell is running,
   reaching the network is any of `curl`, `wget`, `nc`, `python -c`, `/dev/tcp`,
   a linked library — i.e. *any syscall*. There is no finite set of arms to force.
2. **There is a live runtime bypass, honestly recorded.** `production-delta.md:40`:
   `bash -c 'curl …'` never reaches `NetEffect::fetch`; one `(RunBash, BashExec)`
   authority buys arbitrary in-guest syscalls. `SinkClass::BashExec`
   (`crates/nucleus-ifc-kernel/src/ifc_ops.rs:227`) is a **heuristic label**, not a
   physical fact about what the command does — and its integrity floor is
   `Adversarial` (`run_gate.rs:39`), so on the discharge path every obligation for a
   bash command is *vacuously* satisfied. The command lattice blocks *program names*;
   it does not and cannot bound what a shell reaches.

So C6 cannot be closed by copying the ChannelKind move wholesale. It needs a
**two-tier** answer, below.

## 1. The channel inventory

Every way an agent workload can move data out or reach a sink. "Mediated" = the
effect is admitted only past a `preflight_action → DischargedBundle`
(`crates/portcullis-effects/src/runtime.rs`) and its verdict is decided on the single
proven `FlowGraph`. "Backstopped" = not mediated by the sink lattice, but physically
confined by the netns/Firecracker network policy.

| # | Channel | Site | Mediated today? | Fence that actually bites |
|---|---------|------|-----------------|---------------------------|
| 1 | Agent process spawn (sync/async) | `crates/nucleus/src` Executor → `portcullis-effects` `ShellEffect::run_argv[_async]` | **YES — type-enforced.** Raw spawn allowlist is EMPTY (`scripts/mediation-allowlist.txt`); un-preflighted spawn is a compile error | `DischargedBundle` by-value + grep-gate |
| 2 | Agent HTTP egress (`web_fetch`/`web_search`) | `run_gate.rs:99 preflight_web` → `NetEffect::fetch` (`portcullis-effects/src/async_traits.rs:140`) | **YES — type-enforced.** `HTTPEgress` sink floor is `Untrusted`, so trifecta guard bites on tainted session | `DischargedBundle` + `.send()` grep-gate |
| 3 | Agent filesystem write | `run_gate.rs:120 preflight_write` → `Sandbox::write(_proof)` | **YES — type-enforced.** All 22 `Sandbox` methods take an owned `Authority` | `DischargedBundle` + `cap-std` |
| 4 | Credentialed egress via broker (host performs call) | `crates/nucleus-tool-proxy/src/egress.rs`, `broker_client.rs:182` | **YES — type-enforced.** `perform_line` takes `Authority`; vsock frame covered by `VsockStream::connect` grep-gate | `DischargedBundle` + vsock grep-gate |
| 5 | **In-shell egress (`bash -c curl`, `/dev/tcp`, `python`, `nc`)** | inside the child spawned at #1 | **NO — this is the bypass.** Sink label is the heuristic `BashExec`; physically unmediated | **netns/iptables default-deny ONLY** (`crates/nucleus-node/src/net.rs:385 apply_default_deny`) — documented, not proven-applied |
| 6 | DNS (tunnel/exfil) | dnsmasq guest config | **Backstopped, proven-static.** `no-resolv`, no upstream → unlisted name fails locally (`production-delta.md:10`) | `the_dns_proxy_has_no_upstream_and_cannot_forward` |
| 7 | vsock (broker/task-token/SVID transport) | `broker_client.rs`, `nucleus-node/src/workload_api_vsock.rs` | **Partial.** Broker perform is mediated (#4); other vsock frames (task token, SVID fetch) are host-issued, peer-CID pinned to `VMADDR_CID_HOST` | kernel peer-CID drop; no agent authority to discharge |
| 8 | pod-dir Unix socket (container broker) | `BrokerTransport::PodDirSocket`, `prepare_socket` | **Partial.** Refuses container-runtime sockets; container path registers no identity so broker refuses | structural refusal, not a token |
| 9 | node gRPC (control plane) | `nucleus-tool-proxy/src/node_client.rs` (grep-gate whole-file infra) | **Out of set — infra.** Operator-provisioned endpoint, never agent-controlled | `mediated-set.md` exclusion |
| 10 | netns raw socket (`std::net`, any linked lib) | anywhere in the guest | **NO.** Same class as #5 | netns default-deny ONLY |
| 11 | Audit/Article-12 egress (S3, webhook) | `main.rs`, `art12_shipper.rs` (net allowlist) | **Out of set — infra.** Runtime's record OF the agent, operator sink | `mediated-set.md` exclusion |
| 12 | Effect escape hatch `NucleusRuntime::effects()` | `production-delta.md:48` (#1248) | **OPEN.** Returns raw `PolicyEnforced` bundle with no discharge/FlowTracker update | none — tracked open |

**Read of the table:** the *typed* effect API (1–4) is already at the North Star
floor — type-enforced, grep-backstopped. The exposure that keeps C6 honestly NOT-YET
is (a) the **open in-shell/raw-socket surface** (5, 10) whose only fence is a
*documented* netns policy, (b) the **transport channels** (7, 8) which have no unified
inventory, and (c) the **`effects()` escape hatch** (12). The inventory itself is the
first deliverable — today `docs/architecture/mediated-set.md` concedes the transport
set is incomplete and its lint is reporting-only.

## 2. The crux fork — closed-enum reframing vs effect-type total mediation

**Question:** can the egress/transport channels be made a closed enum so a new channel
forces a match arm (like `ChannelKind`), and is that decision Aeneas-extractable? Or is
the surface irreducibly open?

**Answer: split the surface. Neither pure option is right; the hybrid is.**

### Tier A — the mediated API surface IS already a closed enum. Close it as a theorem.
The set of effect *classes* an agent can request through the proxy is
`SinkClass` — a `#[repr(u8)]` closed enum of 19 variants
(`ifc_ops.rs:220`), paired with the `Operation` enum, both already Aeneas-facing. The
type system already makes an un-preflighted effect a **compile error**
(`portcullis-effects`, all 13 methods take `Authority` by value). What is missing is
the **theorem that lifts this to the channel dimension**, exactly as
`ChannelAdmissionExtracted.lean` did for inbound: quantify over the `SinkClass` enum
and prove *every consequential sink requires a `DischargedBundle`* — "a new sink class
forces a match arm and cannot be reached without a token." This is directly
Aeneas-extractable because `SinkClass`/`Operation` are scalar `#[repr(u8)]` enums, the
same shape `channel.rs` proves over. **This is the outbound analogue of the C1 move,
and it is feasible.**

### Tier B — the in-shell/raw-socket surface is irreducibly open. Do NOT enum it.
Channels 5 and 10 are any-syscall. Enumerating "the ways a shell reaches the network"
is unbounded whack-a-mole and any closed enum there would be a **false** closure — the
worst overclaim available. The right fence is **not** an effect enum but a
**total-mediation-by-construction argument at the network boundary**: the netns/iptables
default-deny egress policy, *promoted from documented to proven-fail-closed*. The CIDR
matcher is already proven (`EgressConfinementExtracted.lean`, 8 theorems incl.
`unmatched_is_dropped`, `deny_before_allow_wins`; `net.rs:659 egress_chain` returns the
ordered value the Lean fold consumes). The gap is the honest one stated in
`production-delta.md:9`: *"that iptables implements these semantics and applies the
rules at all is trusted, not proven."*

### Recommendation (I decide this fork; raise async for veto)
**Hybrid: effect-type total mediation over the closed `SinkClass`/`Operation` enum for
the API surface (Tier A, PROVED), plus a proven-fail-closed network backstop for the
irreducibly-open in-shell/raw surface (Tier B, PROVED-matcher + TESTED-on-boot).**
"Every mediated channel" then decomposes into a statement that is *true* rather than
aspirational: every channel is either (i) an API effect that the type system admits
only past a token and a theorem proves is enum-closed, or (ii) a raw egress that the
network layer default-denies by construction, proven at the matcher and observed on the
live guest. This mirrors the literature convergence: OpenShell/NemoClaw/Sandlock all
fence the open surface at the network/syscall boundary (deny-by-default egress, eBPF/
seccomp), not by trying to mediate every shell built-in — because you cannot.

**Runner-up rejected:** pure syscall-level total mediation (seccomp-user-notify / eBPF-
LSM reference monitor à la Sandlock/vRM). Soundest in the limit and worth a future arc,
but it moves a large new enforcement mechanism into the TCB and is a bigger bet than the
network backstop, which nucleus already has 8 theorems over. Reversible: Tier B's
boot-probe interface (below) is the same one an eBPF-LSM upgrade would satisfy, so
choosing the netns backstop now does not foreclose the stronger fence later.

## 3. The bash-curl / in-shell egress bypass

**Options:** (A) mediate in-shell egress — intercept `curl` inside the shell / route the
shell's netns through the mediating proxy; (B) make the netns/Firecracker network
policy a PROVEN fail-closed backstop (default-deny, allowlist only) rather than a
documented one.

**Recommendation: B, decisively.** Option A is unsound-by-construction: you cannot
enumerate the ways a shell reaches the network, so any in-shell interceptor is a
best-effort content filter — exactly the "detect prompt injection" posture nucleus
rejects. The categorical move is to stop pretending the *command layer* mediates egress
and make the *network layer* physically incapable of reaching a non-allowlisted host.
Concretely:
- Keep `SinkClass::BashExec` as an honest label, but **state in the model that bash's
  egress mediation IS the network backstop** (not the sink lattice) — remove the
  implication that the `BashExec` label bounds where a shell reaches.
- Promote `EgressConfinementExtracted` from "trusted iptables applies" to
  **observed-on-the-live-guest**: an in-guest boot probe (the `nucleus-workload-probe`
  pattern that closed C1 phase-2b) that asserts a connect to a non-allowlisted host
  **fails** and a DNS query for an unlisted name fails — a blocking boot-gate sentinel,
  perturbation-tested (add an allow-all rule → probe reds).

This is soundest (physical confinement, no content heuristic) and most testable (a
real guest process observably cannot reach the network off-allowlist).

## 4. The theorem + the runtime gate

### What is PROVED
- **Tier A total mediation (new):** over the closed `SinkClass`/`Operation` enum,
  *no consequential sink is reachable without a `DischargedBundle`* — quantified over
  the enum, Aeneas-extracted, axiom profile ⊆ `[propext, Classical.choice, Quot.sound]`,
  the `ChannelAdmissionExtracted.lean` shape. A new sink forces a match arm.
- **Tier B network matcher (existing, retained):** `unmatched_is_dropped`,
  `deny_before_allow_wins`, `rule_admits_implies_allow` over the extracted CIDR/port
  matcher — nothing egresses unless a rule admits it, deny precedes allow.
- **Compile-time enforcement (existing):** un-preflighted effect = compile error;
  affine `Authority` = replay is a compile error.

### What is TESTED (honestly not proved)
- **iptables actually applies the rules** on the live guest — in-guest boot probe,
  blocking gate. (The kernel/iptables implementation stays in the TCB, as the ledger
  sentence already declares.)
- **Sink-class label conformance** — the label the tool-proxy attaches matches the
  operation it mints obligations for.
- **The mediation lint promoted from reporting-only to enforcing at zero** — after its
  15 known `portcullis-effects` findings are resolved (`production-delta.md:20`).

### The runtime fail-closed gate
- **Type system (already live):** the primary gate — any effect without a token does
  not compile.
- **grep backstop (already live):** `scripts/check-mediation.sh` — spawn + net + vsock
  patterns; a raw primitive on the agent path fails the build.
- **Lint enforcing (to promote):** `nucleus_mediation_lint` from `Warn`/reporting to
  enforcing-at-zero — note it must gate on **report count, not exit status**
  (`cargo dylint` exits 0 even when a `Warn` fires; `production-delta.md:20`).
- **Network default-deny (to prove-on-boot):** `apply_default_deny` is the first thing
  the Firecracker driver does for a pod with a netns; the boot probe makes its
  application a test failure rather than a documented assumption.

## 5. Staged phases

Mirroring the declass arc: additive/parity first; risky live-egress-enforcement changes
boot-gated and DO-NOT-MERGE-until-green later.

**Phase 0 — Inventory + freeze (additive, no enforcement change).**
Land the §1 table into `docs/architecture/mediated-set.md`, replacing "the transport
channels … have no unified inventory" (`north-star.md:270`). Add a test that the
documented channel set equals a closed `EgressChannel` enum (so a new transport channel
forces a doc+enum edit). *DoD:* every channel enumerated with mediated/partial/none/
infra status; enum-vs-doc parity test green.

**Phase 1 — Close the API-effect enum as a theorem (additive/verdict-neutral).**
Prove Tier A: `no_sink_reachable_without_discharge` over `SinkClass`/`Operation`,
Aeneas-extracted. Resolve the 15 `portcullis-effects` lint findings and flip
`nucleus_mediation_lint` to enforcing-at-zero (count-based). *DoD:* Lean theorem, clean
axiom profile, zero `sorry`; lint enforcing at zero; grep-gate still green; perturbation
(add a sink method with no `Authority` → theorem reds).

**Phase 2 — Prove the network backstop fail-closed on the live path (boot-gated).**
Add the in-guest egress probe (the `nucleus-workload-probe` pattern): inside a booted
Firecracker microVM, assert a connect to a non-allowlisted host FAILS and an unlisted
DNS name fails; drain a PASS/FAIL sentinel; make the x86_64 `boot-a-real-pod` job a
blocking gate on it. *DoD:* blocking boot sentinel; perturbation (inject an allow-all
egress rule → probe reds); `production-delta.md` egress row upgraded from Partial to
split PROVED(matcher)+TESTED(iptables-applies-on-boot).

**Phase 3 — Shut the bash-curl honesty gap + close the escape hatch.**
State in the model that bash/raw-socket egress mediation IS the Phase-2 network backstop
(the `BashExec` label is not load-bearing for *where* a shell reaches). Close
`NucleusRuntime::effects()` (#1248) and the `read_to_string_for_search` residuals so no
typed path returns an un-discharged effect handle. *DoD:* no agent-path effect handle
without a discharge; `effects()` either removed or discharge-gated; documented that the
netns, not the sink label, bounds in-shell egress.

**Phase 4 — Ledger promotion (BLOCK: Brandon — outward claim wording).**
C6 → "every mediated channel **IN THE ENUMERATED SET {1–12}**" once Phase 1 lands; →
"every" only when Phases 2+3 shut the bash-curl bypass with a proven backstop AND the
`effects()` hatch is closed. *DoD:* `check-north-star-ledger.sh` row updated; ratchet
counts adjusted; the scoped-set phrasing is a visible, gated event.

## 6. The forks for Brandon

- **FORK 1 (crux, DECIDED → hybrid).** Closed-enum-at-effect-API vs syscall-level total
  mediation. Decided: **effect-type total mediation over the closed `SinkClass` enum
  (Tier A) + proven network backstop for the open surface (Tier B).** Runner-up:
  eBPF-LSM/seccomp-user-notify syscall monitor — reversible (Phase-2 probe interface is
  shared), deferred as a larger TCB bet. Within delegated design authority; raised for veto.
- **FORK 2 (bash-curl, DECIDED → network backstop).** Mediate in-shell egress vs proven
  default-deny netns. Decided: **network backstop** — in-shell interception is unsound
  by construction. Reversible: the boot-probe is the enforcement-agnostic acceptance test.
- **FORK 3 (ledger wording — BLOCK: Brandon).** Whether C6 gets an interim scoped status
  "*every mediated channel in the enumerated set {…}*" after Phase 1, or holds at NOT-YET
  until fully earned. This touches the outward-facing north-star sentence, so it is
  Brandon's call, not mine. Recommendation: the scoped interim, because it is the honest
  intermediate truth and keeps the ledger a live gate rather than a binary.
- **FORK 4 (TCB depth — DECIDED → TESTED-on-boot, revisit).** Accept "iptables applies
  the rules" as TESTED-on-boot now, vs invest in a directly-verifiable eBPF-LSM enforcer.
  Decided: **TESTED-on-boot**; eBPF-LSM is a separate future arc. Reversible.
