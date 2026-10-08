# ADR 0014 — The host decides: the guest's kernel may tighten, never grant

- Status: **proposed** (2026-10-08). Design and measurement only: this record moves no
  enforcement. The first implementation step is S1 below.
- Tracks: milestone M3 of the eval-cell programme, issue #2702 (L-1), ledger row **F12**.
- Rests on: [ADR 0013](0013-eval-cell.md) (the threat model: the agent holds root in its
  guest), [ADR 0007](0007-make-the-defect-unwritable.md) (rule ids cited below),
  [ADR 0011](0011-node-evidence-what-booted.md) and
  [ADR 0012](0012-the-federation-key-lives-in-the-tpm.md) (the host key that signs what the
  host decided is the node's own, rooted in its measured boot).
- Owner decisions it applies (2026-10-01): **D1** built-ins are confined structurally;
  **D2** taint is computed on the host, and the guest may only raise it; **D3** a model
  call is a declared inference sink; **D9** no host-agent mode on Tier 2. Survey
  recommendations it adopts: **D6** the guest kernel becomes tighten-only, then is
  deleted; **D10** the workspace is Untrusted by default.

## Context

ADR 0013 names the adversary: the agent, with root in its guest. Against that adversary,
anything the guest decides is something the agent can turn off. This record says which
decisions move to the host, in what order, over which wire, and what number has to be
reached before the host's answer is the enforced one.

### Where each decision is taken today (verified on `main` at `3eb5243d1`)

| Decision | Taken by | Enforced against guest root? |
|---|---|---|
| A tool call (read, write, glob, grep, run, web fetch and search, memory) | The guest's kernel: `Kernel::from_certificate` (`nucleus-tool-proxy/src/main.rs:1586`), through `mediation::decide_and_record` and `mcp.rs:398` | **No.** The guest enforces its own answer. The host decides the same call in shadow over vsock 1028 (`nucleus-node/src/host_decide.rs`) and enforces nothing. |
| Credentialed egress (broker perform and stream, vsock 1027) | The guest decides first (`mediation.rs:442`, `decide_effect_with_flow`), then the host decides again: `broker::pdp_decide` (`broker.rs:145`, `level_for(op) != Never` only) and the host's pod kernel (`host_decide/effects.rs`, taint, budget and action-bound approval) | **Yes**, by the host's second decision. The guest's first one only refuses more. |
| Taint | The guest's flow graph. The host keeps its own `HostTaint`, raised by guest `Observe` frames and by every broker response it delivers (`PodPolicy::observe_response`) | **Partly.** The host's label never falls, but it starts clean and learns about guest-local reads only from the guest. |
| Approvals | Guest-performed effects: the guest verifies a node-signed approval and calls `issue_approved_token`. Host-performed effects: host-owned, action-bound, single-use (`host_decide/effects.rs`) | Host-performed only. |
| Budget | Host-performed charges: the host's `SharedBudget`. A child pod's allocation: the node's ledger (`pod_authority.rs:1122`, `try_allocate` against the parent), with the parent's guest pre-checking its own kernel (`pod_mgmt.rs:337`). Anything else the guest kernel charges: the guest's own count | Host-performed charges and child allocations. |
| The signed record of what was authorized | Host-performed effects: the host's journal, signed with a key the guest never holds (`host_decide/evidence.rs`). The guest's mediation-receipt and authority-ledger signers still read `NUCLEUS_MEDIATION_SIGNING_KEY` (`art12_sink.rs:119`, `authority_ledger.rs:70`), which the node no longer serves (`FETCH_MEDIATION_KEY` is always refused, `workload_api_protocol.rs:173`). The guest's audit log is signed with a key the guest generates (#3293). | Host-performed only. The guest's own records are self-attested. |

Two things the 2026-10-01 survey listed as prerequisites are already done. First, the
host's policy state belongs to the pod, not to the connection: `PodPolicy` is one
`Arc<Mutex<_>>` shared by the decision listener and the broker, so a reconnect does not
reset it. Second, P1–P5 hold on `main` (`pod_api/trust_boundary.rs`): the guest never
holds the receipt or exit-report key, and a tainted, unapproved or over-budget perform is
refused, as is a reused approval.

### The P0b finding

The survey inferred that a `/v1/run` child under `ContainmentMode::MicroVM` ran as guest
root. That was confirmed and fixed by #3119 (`f937fc9a7`). `nucleus::ChildConfinement` is
now the one decider for the workload and for every `/v1/run` command. Under `MicroVM` a
root runtime's child drops to uid 65534, and a runtime that cannot drop refuses the spawn
(`nucleus/src/command.rs:101-118`, `hardening.rs:358`, exhaustive with no `_` arm, B-3).
On guests that carry them, the Landlock ruleset (#3273, 2.6.0) and the derived syscall
filter (#3285, 2.7.0) apply to the same children. #3119 is in every release from `v2.3.0`, and the guest floor is 2.4.0, so no
admitted guest lacks it. `/v1/run` is still not a workload-door route (`DoorRoute` has no
`Run`), which is deliberate and unchanged. Nothing is left to fix here.

### What deciding on the host can buy against guest root, and what it cannot

This is the point the rest of the record depends on, so it is stated before the design.
An effect belongs to one of three classes:

- **G, guest-performed and staying in the cell.** A read or write in the scratch disk, a
  process run in the guest. Guest root performs these without asking anyone. A host
  decision cannot prevent them, and ADR 0013 does not forbid them: a write inside scratch
  is not a contract-forbidden effect. What the host buys for class G is **state and
  record**: taint the guest cannot launder, approvals and budget it cannot replay, and a
  signed record it cannot forge.
- **H, host-performed and crossing the boundary.** Credentialed egress (the broker), a
  child pod, an approval, a declassification, the signed record. For class H, a host
  decision **is** containment: the effect does not happen unless the host performs it.
- **N, network leaving the namespace without the host performing it.** In-shell egress,
  DNS and raw sockets (mediated-set rows 5, 6 and 10). The host decision service never
  sees these. They belong to M4.

So M3's containment claim is about class H, using class G state the host computes
itself. Saying "the host decides every tool call" without this split would claim
containment of class G, which no decision service can give.

## Decision

### 1. Decision points, by effect class, in order

| Order | Decision | Class | Becomes |
|---|---|---|---|
| 1 | Taint | G → H | Host-computed from what the host itself observed (§3). The guest may only raise it, by `Observe`. |
| 2 | Approvals and budget | G, H | Host state for every operation (§4). An approval is a host ledger entry redeemed once, by value. |
| 3 | Credentialed egress | H | Decided once, on the decision channel. The broker stops deciding and **performs only against a decision id the host issued** (§6). |
| 4 | A tool call | G | Decided by the host. The guest enforces the stricter of the host's answer and its own (§2). |
| 5 | The signed record | H | Host-signed only. The guest's signing paths are deleted (§5). |

The order follows what is containment first. Taint (1) is what makes the decision about
egress (3) mean anything under guest root: a host that cannot see a guest-local read has
to assume it happened. Approvals and budget (2) are the state the host needs before it can
answer every call (4). The record (5) can only be host-signed once the host is the one
that decided.

### 2. What the guest kernel becomes (D6)

The guest keeps its kernel as defence in depth. It never widens the host's answer:

```text
enforced = stricter(host, guest)       Denied > ApprovalRequired > Allowed
```

`stricter` is one total function over `Outcome`, and it is the only way an enforced
outcome is formed (G-1). When both deny for different reasons, the host's reason is the
one recorded, because the host signs the record. A guest whose kernel is weaker, older or
missing gets the host's answer. A guest whose kernel is stricter refuses more, and the
host records the refusal as the guest reports it. The record never says "allowed" for
something the host denied.

Deleting the guest kernel (the second half of D6) is not part of M3. It waits until
standard pods have migrated and the guest floor has passed the release that carries the
host path.

### 3. Taint, from facts the host observed (D2, D10)

The host computes the pod's label as the lattice join of:

1. **Everything the host put into the cell at admission:** the scratch and data disks that
   `workspace_scan` reads before any driver runs, labelled Untrusted unless the spec's
   provenance says otherwise (D10); the spec; and the declared inputs. Credentials are
   withheld from the guest (`cred_split`), so they add nothing to the guest's label.
2. **Every response the host delivers:** broker replies (already done, `observe_response`),
   streamed replies, and whatever the node hands one pod from another.
3. **The guest's `Observe` frames.** These can only raise the label. `LabelRaise` has one
   consumer, the lattice join, so no frame can lower it.

The label is lowered only by a **declassification the host verifies**. The governor keys
that verify a declassification token move from the guest's environment
(`NUCLEUS_DECLASSIFY_TRUSTED_KEYS`) to the host. A key the guest holds is a key guest root
holds.

The consequence for an eval cell is intended and visible: an eval cell with an untrusted
workspace has the trifecta guard armed from boot. Its outbound effects that need a trusted
label are held for approval or declassification from the start, whether or not the guest
reports reading anything. This is the conservative reading of "the guest's silence is not
evidence" (A-2). In shadow it shows up as a host-stricter disagreement, classified as
**initial taint** (§10).

### 4. Approvals and budget as host state

- **Approvals.** `host_decide::effects::Approvals` already holds action-bound, single-use
  approvals for host-performed effects. It is extended to every operation. A guest-performed
  operation that needs approval gets `Verdict::ApprovalRequired { approval_id }`. The
  operator grants it on the host, and the guest's `Redeem` consumes it once
  (`DecisionLedger::redeem` and `consume` take ids by value; C-4, C-5). The guest's
  `issue_approved_token` then accepts only a host `Verdict::Allowed`. Verifying the
  node-signed approval in the guest (`GuestCapability::ApprovalByPublicKey`) becomes
  defence in depth.
- **Budget.** The host's `SharedBudget` is the only spending count. The guest kernel's
  budget is a projection of it (`PodPolicy::decide_effect` already projects it this way on
  the host), so a charge the guest kernel makes on its own is never what grants. Child
  allocations already come from the node's ledger (`pod_authority.rs:1122`). The parent
  guest's own charge (`pod_mgmt.rs:337`) stays as a tighten-only pre-check.

### 5. Receipts, host-signed only (P10)

The host's evidence journal (`host_decide/evidence.rs`, a key that is never in
`PodMaterial`, the guest environment or a workload-API reply) signs an authorization
record for **every** decision, not just for host-performed effects. The guest-side signing
paths that read `NUCLEUS_MEDIATION_SIGNING_KEY` are deleted, along with the
`FetchMediationKey` command arm. The node already refuses that command, so the arm is a
dead branch that still parses. The guest's own audit log (#3293) stays, documented as
guest-attested: it is evidence of what the guest said, never of what was authorized.
The verifiers (`nucleus-audit`, the JS and Python SDKs) accept an authorization record
only under the node's host key (C-2: evidence is minted by the checker).

### 6. The wire: the decision channel, vsock 1028 (G-1)

**One wire decides: the decision channel** (`nucleus-decision-protocol`,
`DECISION_VSOCK_PORT` = 1028). The broker channel (vsock 1027) stops deciding and becomes
a **performer**. A perform or stream frame carries the `DecisionId` the host issued for
it. The broker redeems that id from the pod's ledger with `consume(id, digest)`, by value,
where the digest is computed **by the host** from the request it is about to send (method,
resolved URL, credential header name, media type, payload hash; C-2). It then performs.
`pdp_decide` and the broker's own call into `PodPolicy::decide_effect` are deleted, not
kept in parity (G-1). Today a perform is decided twice inside the host (coarse in
`pdp_decide`, fine in `effects`), and a third time in the guest.

Why this channel and not the broker's:

- Its frames are the one wire declaration P7 built for exactly this. The parser is total,
  bounded and canonical, fuzzed, and destructured with no `..` on either side (E-1). The
  host numbers the frames (`SeqGate`). Ids are host-minted, `!Clone`, carry an epoch, and
  are spent by value (C-1, C-4, C-5).
- Approvals are already a verdict on it (`ApprovalRequired` / `Redeem`), and taint is
  already raise-only on it (`Observe`).
- The broker channel authenticates frames with a per-pod secret that the guest fetches
  (`FETCH_BROKER_SECRET`). M1 is retiring that secret for exactly the guest-root reason.
  The decision channel needs no secret: the per-pod vsock socket already names the pod,
  and under guest root the guest's identity carries no authority anyway, because the host
  decides from its own state.

The ledger moves from per-channel to per-pod, so a decision id issued on 1028 is
redeemable on 1027. Epochs stay per channel. Decision-id lookup is per pod.

**Runner-up:** decide host-performed effects at the broker, where the effect happens, and
use 1028 only for guest-performed ones. It is simpler and is what the host already does
for egress. It loses because each effect class would then be decided on a different wire
with a different record shape, and the guest would keep a reason to decide egress itself.
The plan's phrase "over the existing broker vsock channel" (#2702) is superseded by this
section. The choice is reversible until the broker's decide path is deleted, at step S5.

### 7. Failure semantics: no answer is a denial (ADR 0007 B, A, I-3)

In authoritative mode, the guest's call to the host has three outcomes, as a type rather
than a `Result<bool>` (A-1):

```rust
enum HostAnswer { Verdict(Verdict), Unreachable(HostUnavailable) }
```

`Unreachable` (connect failure, a timeout, a protocol error, a full queue, too many
sessions, a subject too long to carry) is enforced as `Denied`. The match that forms the
enforced outcome has no `_` arm (B-3, E-2). No `Option` stands for "the host had no
opinion" (B-2). On the host, `PolicyUnavailable` (the pod is revoked or its lock is
poisoned) closes the channel, which the guest sees as `Unreachable`, so it denies. The
broker refuses a perform with no decision id, an unknown id, a retired id or a
foreign-epoch id, and refuses a digest mismatch. Each refusal has a distinct reason
(I-3), and none of them falls back to deciding locally.

A host that is down denies everything. Availability is outside ADR 0013's claim: the agent
can always crash its own guest, and a host outage that fails closed is the same class of
event.

### 8. Latency budget

The decision now waits on a vsock round trip it used to skip:

| | Budget |
|---|---|
| Added round trip, guest-measured, p50 | ≤ 0.5 ms |
| Added round trip, guest-measured, p99 | ≤ 5 ms |
| Hard deadline (then `Unreachable`, so denied) | 2 s (the shadow worker's existing `DEADLINE`) |

**Not measured yet.** The shadow client does not time its exchanges, and nothing emits a
latency. S1 adds the measurement. Missing the budget blocks the flip (§10); it never turns
into an allow.

### 9. Guest compatibility

The floor stays **2.4.0**, which is what the `GuestCapability` table derives. The pin
stays **2.7.0**. Every guest-side change in M3 is a new `GuestCapability` row. Each row is
`Demand::Optional` or `Demand::When(GuestUse::EvalCell)`, so no row moves the floor (ADR
0013 rule 4 is the pattern):

| Row | Step | Demand |
|---|---|---|
| `HostDecideShadow` (exists, 2.3.0) | — | `Optional`, unchanged. Standard pods keep shadowing. |
| `HostDecideTelemetry` (new) | S1 | `Optional`: the guest prints its shadow tally and latency at shutdown. |
| `HostDecidedPerform` (new) | S5 | `When(EvalCell)`: perform and stream frames carry the host's decision id. |
| `HostDecides` (new) | S6 | `When(EvalCell)`: the guest enforces `stricter(host, guest)` and denies on `Unreachable`. |

Each row lands as `FirstShipped::NotYet`. **Until a release carries it, no pinned guest can
serve an eval cell** that requires it. To avoid stranding eval cells between a merge and a
release, the `When(EvalCell)` demand is switched on in the PR that bumps `GUEST_RELEASE`
to the release that ships the row, not in the PR that adds the row.

Eval cells require the new path. Standard pods keep the shadow path and migrate later,
by raising the floor past the release that carries `HostDecides`. That is an owner
decision, and it is outside M3.

### 10. The flip criterion: shadow to authoritative

**The corpus.** The *M3 shadow corpus* is every x86_64 `live-boot-evidence` bundle from
`quickstart-boot.yml` (artifact `live-boot-evidence-x86_64`), plus, from S2 on, the
operation-coverage pod in the same job. It is read by `cargo xtask host-decide-agreement`.
Agreement is measured only on honest traffic. Escape-lane runs are falsifiers, not part of
the corpus, because a hostile guest's `Shadow` report is not evidence of what it enforced.

**Disagreement classes.** Each class is computed from the record the host writes
(`host-decide-disagreements.jsonl`, guest and host outcome), and the classes are never
summed before they are judged:

| Class | Meaning | Tolerated in the window |
|---|---|---|
| guest stricter | the host would have allowed what the guest refused | **0**. Enforcing the host's answer would grant more. |
| host stricter | the host withholds more than the guest enforced | Only when attributed to a listed honest source: initial taint (§3), an approval granted in the guest only, guest-held declassification keys. **0 unattributed.** |
| differing reason | both refuse, for different reasons | **0 unattributed**: the signed record would name another cause. |
| unclassified | a disagreement with no record | **0** |

**The threshold.** The host becomes authoritative for eval cells (step S6) when one
window, of at least 14 consecutive days and at least 2,000 compared decisions, with at
least 50 compared decisions for every operation in the coverage set (S2), shows all of
the following:

1. agreement ≥ 99.5 % of compared decisions;
2. the class bounds above;
3. *not compared* (host faults plus guest `HostUnavailable`) ≤ 0.5 % of decisions, each
   one attributed. Teardown races are counted separately and do not consume the bound;
4. zero unreadable bundles. A window that contains one is restarted, not averaged;
5. the latency budget (§8) met.

The rate in (1) is the weakest of these five conditions. Conditions 2–4 are what can
actually stop a flip.

### 11. What this measures today

Read with this PR's reader (`cargo xtask host-decide-agreement`) over every
`live-boot-evidence-x86_64` bundle GitHub still held on 2026-10-08. That is 103 runs of
`quickstart-boot.yml` (push, merge-group and pull-request events), 2026-10-06T22:52Z to
2026-10-08T17:39Z, at 83 distinct commits:

| | |
|---|---|
| Pods with a decision channel | 206 (2 per run), all 206 reporting a teardown tally |
| Decisions compared | **200**: agree 200, disagree 0 |
| Agreement | **200/200 = 100.00 %** of compared decisions |
| Disagreement classes | host stricter 0, guest stricter 0, differing reason 0, unclassified 0 |
| Not compared | **6** host faults, all `PolicyUnavailable`: the posture pod's one decision arrived after the pod's policy was revoked at teardown (runs 37570296062, 37632643270, 37671016125, 37716703532, 37800156603, 37806146438) |
| Not visible in any artifact | the guest's `HostUnavailable` count (it is only in the guest's `/v1/health`), the operation behind each agreement, and latency |

**This does not clear the criterion, and the record says so.** The corpus is two decisions
per run. 103 of the 200 are the credentialed pod's `web_fetch` (the host's signed
`host-effects.jsonl` names it). The other 97 are the posture pod's one decision, whose
operation no log names. "100 %" here means that 200 decisions over at most two operations
agreed. It says nothing about the operations nobody exercised, or about decisions the
guest could not put to the host. Those are "could not measure", not agreement (A-2,
A-5).

### 12. The mediated set and ledger row F12

| Row (`docs/architecture/mediated-set.md`) | Today | After M3 |
|---|---|---|
| 5 in-shell egress, 6 DNS, 10 netns raw socket | `backstopped-only` | **Unchanged: M4.** M3 does not see this traffic. |
| 7 vsock (broker, task token, SVID) | `partial` | `mediated` at S5+S6: every vsock frame that causes an effect redeems a host-minted decision id. Workload-API frames carry no agent authority (M1 retires the served secrets). |
| 8 pod-dir socket (container broker) | `partial` | Unchanged. An eval cell refuses the container tier, so the row is outside the eval cell. |
| 9 node API (pod management) | `partial` | Unchanged. Child allocations are already the node's ledger. An eval cell reaches the node API only if its allowlist names the node. |

**F12** (the fine-grained decision point survives compromise of the guest it polices)
moves from NOT-YET to **TESTED** at S6. Its falsifier is the escape lane's guest-root
stage (below), driven to BREACH on the commit before the flip and CONTAINED after it.
PROVED would need `no_sink_reachable_without_discharge` stated over the host's broker and
node paths. That is not in M3.

**What M3 does not close:** egress the host does not perform (rows 5, 6 and 10, which is
M4); class-G effects inside the cell, which no decision service can contain; standard
pods, which stay in shadow until the owner raises the floor; timing and
microarchitectural channels; and anything a compromised guest prints on its console.

### 13. Implementation sequence

Each step is one PR. Each has a definition of done and an A-19 falsifier: the check is
driven red on the real defect (old behaviour restored), then green. Falsifiers that need a
hostile guest are run by the existing escape lane (#3106's canary, the guest-root mode of
M2, and #3338's verdict once it lands), never by new code in this programme's PRs.

| Step | What lands | Definition of done | A-19 falsifier |
|---|---|---|---|
| **S0** (this PR) | This ADR. `cargo xtask host-decide-agreement`. | The numbers in §11 come from the reader, at the run ids named. | Reader unit tests are driven red by restoring each defect it refuses: a tally read as zero, a vacuous 100 %, a missing log read as "no shadow", an unreported pod folded in, a differing reason misclassified (PR body). |
| **S1** Measurement complete | Node: the teardown tally as numeric fields, plus per-operation × outcome-pair counts, plus `Decide`s never reported at close, plus host service time. Guest (`HostDecideTelemetry`): its tally, `HostUnavailable` by kind, and round-trip p50/p99 on the console at shutdown. `live-boot-evidence` copies `host-decide-disagreements.jsonl` into the bundle. The reader consumes all of it, and an unclassified disagreement is exit 1. | The reader reports per-operation counts, host and guest *not compared* separately, and latency, from a real bundle. | A bundle whose tally says `disagree > 0` with its record file withheld exits non-zero (red) and passes with the file restored (green). A node built with the shadow listener disabled reads as "could not measure" (exit 2), never as agreement. |
| **S2** Operation coverage | A second pod in the live-boot job, honest traffic only: one permitted call and one refused call per door route and per broker operation. | The reader shows ≥ 1 compared decision per operation per run. | Remove one route from the workload and the coverage check reds, naming the operation. |
| **S3** Host taint from host facts (D2, D10) | `PodPolicy`'s `HostTaint` starts at the join of the admitted inputs (§3). Declassification is verified on the host. Shadow continues; host-stricter rows are attributed to initial taint. | New `trust_boundary` row `UnobservedTaintHeld` Holds: a pod with an untrusted workspace, whose guest sends no `Observe`, has its outbound push held by the host. | On `main` the row is Gap: the host's label is clean until a broker response, so a guest that stays silent is not held. Red on `main`, green after. Live: the escape lane's "silent read, then direct broker call" stage. |
| **S4** Approvals and budget on the host | `effects::Approvals` covers every operation. Guest approvals are redeemed with `Redeem`. The guest kernel's budget is reset from the host's projection on every verdict. | `trust_boundary` row `GuestLocalApprovalReuseRefused` Holds. The host's verdict for a guest-performed call reflects the pod's host budget. | On `main`, a guest-performed call that needs approval is released by the guest's own `issue_approved_token`, so the host never sees the grant and cannot refuse its reuse after a reconnect. Red on `main`, `Retired` after. |
| **S5** One decision wire (G-1) | The ledger becomes per-pod. Perform and stream frames carry a decision id (`HostDecidedPerform`). The broker redeems by value, against a digest it computes from the request. `pdp_decide` and the broker's own decide are deleted for eval cells. | An eval cell's broker refuses a perform with no id, a foreign or retired id, or an id minted for a different digest. | On `main`, a perform with no prior `Decide` is performed, because the broker decides by itself. Red on `main`, refused after. |
| *window* | Shadow continues over S1–S5 traffic until §10 holds. | §10, from the reader's output, quoted in S6's PR. | — |
| **S6** Authoritative for eval cells | The guest enforces `stricter(host, guest)` and denies on `Unreachable` (`HostDecides`). | The escape lane's guest-root stage "proxy killed, untrusted content read silently, broker called directly" is CONTAINED. F12 → TESTED. ADR 0013's self-escalation row → answered. | The same stage is BREACH on the commit before (S3 and S5 reverted): guest root's direct perform after a silent read is performed. |
| **S7** Receipts host-signed only (P10) | Every decision gets a host-signed record. The guest's `NUCLEUS_MEDIATION_SIGNING_KEY` paths and the `FetchMediationKey` arm are deleted. The live-boot bundle carries the host decision journal. | `nucleus-audit verify` and both SDK verifiers accept a decision record only under the node's host key. | A bundle whose decision record is signed by a guest-generated key is refused. Red against a verifier that accepted it. |

Order: S1 → S2 → (S3 ∥ S4) → S5 → window → S6 → S7. S7 may run beside S6. M4 (the
mediated network, rows 5, 6 and 10) follows. Standard-pod migration and deleting the guest
kernel come after M4, and both are owner decisions about the floor.

## Consequences

- No pod changes behaviour when this record is accepted. Every step before S6 is shadow,
  host state, or measurement.
- At S6 an eval cell's tool calls wait on a vsock round trip, and a host that does not
  answer denies. Standard pods are unaffected until the owner moves the floor.
- An eval cell with an untrusted workspace has its outbound effects held from boot (§3).
  That is the cost of not trusting the guest's silence, and it is visible in shadow before
  it is enforced.
- Between the S5/S6 merges and the next guest release, an eval cell's new requirements
  are switched on only by the release-bump PR (§9). No eval cell is stranded on a pin that
  cannot meet them.
- The live-boot corpus is thin today (§11). S1 and S2 are what make the flip criterion
  decidable at all. Until they land, the honest statement is "200 of 200 compared decisions
  agreed, over at most two operations".
