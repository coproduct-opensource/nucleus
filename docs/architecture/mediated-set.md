# The Mediated Set

Which code is inside the complete-mediation guarantee, which is outside, and why.

This page exists because the guarantee is **relative to a boundary**. "Every effect is
mediated" is meaningless until "which effects" is pinned down, and the Lean mediation
theorem's premise — *every effect entry point consumes a scoped `Authority`* — is only
discharged over the crates the `mediated` lint actually runs on. A set that is
described but not enforced is a claim, not a boundary.

## The set

| In the set | Why |
|---|---|
| `portcullis-effects` | The effect traits. All 13 methods take an `Authority` by value. |
| `nucleus` (`Sandbox`, `Executor`) | The other filesystem and process path. All 22 `DecisionToken`-taking `Sandbox` methods take an `Authority`; the `Executor` threads one to the spawn. |
| `portcullis-core::capability_traits` | The typed-context surface. Reachable from `NucleusRuntime::with_typed_context`, so it is agent-facing. |

Everything else is outside, and the guarantee says nothing about it.

## The egress channel inventory (C6)

The set above answers "which crates does the mediation lint run on". This section
answers the outbound question the C6 clause turns on: **every way an agent
workload can move data out or reach a sink**, each tagged with how thoroughly
that path is mediated. It is the §1 inventory of
`docs/design/c6-complete-mediation-plan.md`, landed here so the taxonomy is a
gated object rather than prose.

"Mediated" means the effect is admitted only past a `preflight_action →
DischargedBundle` (`crates/portcullis-effects/src/runtime.rs`) whose verdict is
decided on the single proven `FlowGraph`. "Backstopped" means it is not mediated
by the sink lattice but is physically confined by the netns/Firecracker
default-deny network policy.

Status vocabulary (the `Status` column, machine-stable):

- **`type-enforced`** — the effect method takes an owned `Authority` by value, so
  an un-preflighted call is a compile error, and the grep backstop
  (`scripts/check-mediation.sh`) catches raw primitives.
- **`backstopped-only`** — no sink-lattice mediation; the only fence is the
  netns/iptables default-deny egress policy
  (`crates/nucleus-node/src/net.rs:385` `apply_default_deny`), which is now
  **proven applied on boot** by the in-guest egress probe
  (`scripts/check-egress-probe.sh`, the x86_64 boot gate: an off-allowlist
  connect from inside the live guest returns `ENETUNREACH`; C6 phase 2).
- **`partial`** — some frames on the transport are mediated, the rest rest on a
  structural property (peer-CID pin, identity refusal) rather than a token.
- **`open-hole`** — a known unmediated path with no fence beyond "tracked open".
- **`infra-out-of-set`** — operator/host authority, never agent-controlled;
  excluded by the same reasoning as the "Excluded, with reasons" table below.

The closed `EgressChannel` enum
(`crates/nucleus-ifc-kernel/src/egress_channel.rs`) has exactly one variant per
row, keyed by the `Key` column, and the
`documented_inventory_equals_the_enum` parity test asserts the two agree on both
the key set and the `Status` of each row. **Adding an egress or transport
channel therefore requires editing both this table and the enum**, and changing
a channel's status requires editing both too — that is the categorical gate. C6
phase 1 proved the Tier-A total-mediation theorem over `SinkClass`/`Operation`
(`no_sink_reachable_without_discharge`); phase 2 promoted the network backstop to
proven-on-boot (`check-egress-probe.sh`); phase 3 closed the last `open-hole`
(channel 12, below). `no_channel_is_an_open_hole` now asserts the inventory holds
no open hole at all — the machine meaning of "every".

<!-- C6-INVENTORY-START -->

| # | Channel | Key | Site (verified file:line) | Status | Fence that actually bites |
|---|---------|-----|---------------------------|--------|---------------------------|
| 1 | Agent process spawn (sync/async) | `agent_spawn` | `crates/nucleus/src` Executor → `portcullis-effects` `ShellEffect::run_argv[_async]` | `type-enforced` | Raw-spawn allowlist is empty (`scripts/mediation-allowlist.txt`); un-preflighted spawn is a compile error + grep-gate |
| 2 | Agent HTTP egress (`web_fetch`/`web_search`) | `agent_http_egress` | `crates/nucleus-tool-proxy/src/run_gate.rs:99` `preflight_web` → `crates/portcullis-effects/src/async_traits.rs:140` `NetEffect::fetch` | `type-enforced` | `HTTPEgress` sink floor is `Untrusted`, trifecta guard bites on a tainted session; `DischargedBundle` + `.send()` grep-gate |
| 3 | Agent filesystem write | `agent_fs_write` | `crates/nucleus-tool-proxy/src/run_gate.rs` `preflight_write` → `Sandbox::write(_proof)` | `type-enforced` | Every `Sandbox` method takes an owned `Authority`; `DischargedBundle` + `cap-std` |
| 4 | Credentialed egress via broker (host performs call) | `broker_credentialed_egress` | `crates/nucleus-tool-proxy/src/egress.rs:309`, `broker_client.rs:173` `perform_line` | `type-enforced` | `perform_line` takes an `Authority`; the vsock frame is covered by the `VsockStream::connect` grep-gate |
| 5 | In-shell egress (`bash -c curl`, `/dev/tcp`, `python`, `nc`) | `in_shell_egress` | inside the child spawned at #1 | `backstopped-only` | Sink label `BashExec` (`crates/nucleus-ifc-kernel/src/ifc_ops.rs:226`) gates whether bash *runs* (integrity floor `Untrusted`), NOT where an already-running shell reaches; that is confined by `apply_default_deny` (`crates/nucleus-node/src/net.rs:385`), **proven applied on boot** by `scripts/check-egress-probe.sh` |
| 6 | DNS (tunnel/exfil) | `dns` | dnsmasq guest config | `backstopped-only` | `no-resolv`, no upstream → an unlisted name fails locally (`the_dns_proxy_has_no_upstream_and_cannot_forward`) |
| 7 | vsock (broker/task-token/SVID transport) | `vsock_transport` | `crates/nucleus-tool-proxy/src/broker_client.rs:223`, `crates/nucleus-node/src/workload_api_vsock.rs` | `partial` | Broker perform is mediated (#4); other frames are host-issued, peer-CID pinned to `VMADDR_CID_HOST` — no agent authority to discharge |
| 8 | pod-dir Unix socket (container broker) | `pod_dir_socket` | `crates/nucleus-node/src/broker_transport.rs` `BrokerTransport::PodDirSocket` | `partial` | The container path registers no identity, so the broker refuses — a structural refusal, not a token |
| 9 | node gRPC (control plane) | `node_grpc` | `crates/nucleus-tool-proxy/src/node_client.rs` (whole-file infra grep-gate) | `infra-out-of-set` | Operator-provisioned endpoint, never agent-controlled |
| 10 | netns raw socket (`std::net`, any linked lib) | `netns_raw_socket` | anywhere in the guest | `backstopped-only` | Same open class as #5 — `apply_default_deny` netns egress policy, **proven applied on boot** by `scripts/check-egress-probe.sh` |
| 11 | Audit / Article-12 egress (S3, webhook) | `audit_egress` | `crates/nucleus-tool-proxy/src/main.rs`, `art12_shipper.rs` (net allowlist) | `infra-out-of-set` | The runtime's record OF the agent, an operator sink |
| 12 | Effect escape hatch `NucleusRuntime::unmediated_effects` | `effects_escape_hatch` | `crates/portcullis-effects/src/runtime.rs:690` (#1248) | `type-enforced` | The raw `effects()` accessor is gone; `unmediated_effects` requires an `UnmediatedAccess` opt-in token + a `DischargedBundle` discharged against the strictest sink (`HTTPEgress`, fails on a tainted session) + a `FlowTracker` observe, and the returned effect methods take `Authority` by value. Fail-closed tested (`unmediated_preflight_denies_adversarial_session`) + all-profile isolation invariant. Audit-DAG granularity is coarse (one `OutboundAction` node per grant) |

<!-- C6-INVENTORY-END -->

**Read of the table:** the *typed* effect API (1–4) is at the North Star floor —
type-enforced, grep-backstopped. The three surfaces that once kept C6 honestly
NOT-YET are now closed: (a) the in-shell/raw-socket surface (5, 10) is confined by
the netns default-deny, **proven applied on boot** (`check-egress-probe.sh`); (b)
the partial transport channels (7, 8) rest on tested structural refusals (host-CID
pin `only_the_host_cid_is_accepted`; broker refusal by absence); and (c) the
`effects()` escape hatch (12) is closed (`unmediated_effects`, #1248). The
inventory now carries **no open hole** — `no_channel_is_an_open_hole` asserts it.
The remaining step to move C6 off NOT-YET is the ledger-promotion decision itself
(an outward-wording call recorded in `docs/north-star.md`); this page changes no
egress verdict, ledger row, or ratchet.

## What "agent-attributed" means

The distinction is not "does it touch the disk" but **on whose authority**. An effect
performed *because an agent asked for it* is in the set. An effect the runtime performs
to do its own job — spawn a jailer, serve HTTP, append to its own audit log, read its
own config at startup — is not, because there is no agent authority to discharge
against and no obligation that could meaningfully be checked.

Conflating the two would be worse than leaving them separate: it would mean minting
authorities for the runtime's own bookkeeping, which devalues the token.

## Excluded, with reasons

Run over the whole set, `mediated` reports 21 functions. Three were closed (below);
the rest are excluded deliberately:

| Excluded | Category | Reason |
|---|---|---|
| six `*::load_from_dir` loaders (`ComposeWorkflow`, `Compartmentfile`, `EnterpriseAllowlist`, `ManagedSettings`, `PolicyRuleSet`, `ParserRegistry`) | Config loading | Runtime startup, before any agent exists. There is no session to discharge against. |
| `sink::JsonlSink::{open, iter}`, `merkle::MerkleSink::*`, `merkle::read_checkpoints`, `audit_backend::FileAuditBackend::{append, count, load_all}` | Audit / lineage writing | The runtime recording what happened. |
| `file_signer::Pkcs8FileSigner::from_pkcs8_pem_file` | Key loading | Startup, operator-supplied material. |
| `Sandbox::new`, `PodRuntime::{new, with_approver}` | Construction | Creating the sandbox root before any agent holds it. |
| `Sandbox::{exists, exists_approved}` | **Signature-blocked, not judged safe** | These return `bool` with no error channel, so requiring an authority is a signature change rather than a check. Genuinely in the set by rights: `exists` is an information-disclosure probe. Tracked, not excused. |
| `nucleus`/`nucleus-tool-proxy` infrastructure | Jailer spawn, HTTP serving | The runtime's own process and network use. |

**The audit-sink exclusion is the one that deserves scrutiny**, because it is the case
where "outside the set" is not obviously benign: an unmediated write path exists, and
it writes attacker-influenced content (the subject of a denied action). Two things
bound it. The destination is fixed at construction and not agent-controlled. And
requiring an agent authority to write the audit log would let a *denied* agent suppress
its own denial record — the cure would be worse. That is a weaker argument than the
others on this page, and it is stated as such rather than buried.

## Closed rather than excluded

`portcullis_core::capability_traits::{read_file, write_file}` performed real
`std::fs` calls behind only a phantom-type capability check — no obligation discharge,
no `FlowTracker` update, no path allowlist — and were reachable from
`NucleusRuntime::with_typed_context`, whose own doctest demonstrated reading a file
that way.

Six of the eight operations in that module were already stubs returning "use the
mediated path". These two silently were not. They are now stubs matching their
siblings, which is the fail-closed direction: the typed context demonstrates
*compile-time capability checking* and is not an effect path.

They had no production callers.

`Sandbox::read_to_string_for_search` — the grep/search read path — took no
`DecisionToken` and carried a comment saying the caller *"must have already obtained a
GrepSearch decision"*. A convention where an enforcement belongs, and agent-reachable.
It now requires an `Authority` scoped to `(GrepSearch, AuditLogAppend)`.

That one has a cost worth naming: the search loop mints **one discharge per file**, so
a grep over N files runs N preflights. That is the affine model working as designed —
an `Authority` buys one read — and the alternative, one authority covering a whole
directory walk, is exactly the replay the by-value cutover removed. If the cost ever
matters, the answer is a coarser sink class, not a reusable token.

## Enforcement

The boundary is enforced by CI, not by this page:

```sh
cargo dylint --lib nucleus_mediation_lint -- \
  -p portcullis-effects -p portcullis-core -p nucleus
```

Adding a crate to the set means adding it to that invocation. Removing one means
editing this page and saying why.

**Soundness is relative to running over the whole set.** `mediated` analyses one crate
at a time and relies on cross-crate callees being covered by their own pass; linting
part of the set silently weakens the guarantee rather than failing loudly. See
`tools/nucleus-mediation-lint/README.md`.
