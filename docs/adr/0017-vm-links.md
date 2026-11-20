# ADR 0017 — Links between pods: every request from one pod to another is a host decision

- Status: **accepted** (owner, 2026-11-19, with "go ahead with L1–L3"). L1–L3 have
  landed; no step yet moves enforcement or adds a route (L4 does). The semantics were
  written first, in `crates/portcullis-core/lean/LinkTable.lean`, and the implementation is
  built to that meaning (§10 records what each step delivered).
- Owner decisions already taken (2026-11-19), each the strongest option considered:
  - **Transport:** a host relay over vsock (§1). The runner-up was IP routing between pod
    namespaces.
  - **Unlink:** it severs every live connection on the link before its receipt is signed
    (§3). The runner-up was to drain existing connections and refuse new ones.
  - **Exit:** an exit the node did not request (a crash, a timeout, the reaper) drops the
    pod's links and signs a receipt for each. A cancel through the API is refused while a
    link names the pod (§4). The runner-up was to leave links dangling.
  - **Per request, eval cells included:** the host admits a connection only along a link,
    and then decides every request over it before the relay delivers a byte, with the unit
    ADR 0015 decides (one HTTP/1.1 request). So links are served to eval cells and ADR 0015's
    promise holds for them unchanged (§1, §8). The runners-up were to keep eval cells
    link-free, or to decide eval-cell links per connection and amend ADR 0015's promise.
- Rests on:
  - [ADR 0001](0001-trust-domain-tenancy.md): a tenant is a trust domain, a non-owner is
    answered 404, and sharing across tenants is an explicit delegation;
  - [ADR 0009](0009-the-public-private-line.md): the record is neutral, key-free and
    checkable;
  - [ADR 0013](0013-eval-cell.md): the adversary holds root in its guest;
  - [ADR 0014](0014-the-host-decides.md): the host decides, and no answer is a denial;
  - [ADR 0015](0015-mediated-egress.md): the vsock listener and guest-relay pattern this
    record reuses.
- Touches claim **C2** ("nor those of any other pod", `docs/north-star.md`, NOT-YET). A link
  is a deliberate channel between two pods, so C2 is restated relative to the link graph
  (§7).

## Context

### Today a pod cannot reach another pod (verified at `5e8f7c85a`)

There is no pod-to-pod path. Five independent layers refuse one:

1. **No address to name.** Every guest has the same address, `192.168.241.2/30` with
   gateway `.1` (`crates/nucleus-node/src/net.rs`, near line 98). A guest has nothing it
   could use to address another pod.
2. **The deny floor.** Each pod's unique addresses live only on its veth link, inside
   `10.200.0.0/24`. That range is in `NODE_DENY_FLOOR` (`net.rs:82`), which `egress_chain`
   (`net.rs:775`) puts first in every pod's OUTPUT and FORWARD.
3. **The host-side link rules.** A host-veth address is local to the host, so
   `DropToHostBeforeNat` and `DropInput` (`crates/nucleus-node/src/host_link.rs`) drop it.
   The module names "another pod's link address" as a case it closes.
4. **The destination's own namespace.** `apply_default_deny` (`net.rs:524`) and
   `apply_host_policy` (`net.rs:846`) leave INPUT and FORWARD at DROP, admitting only
   loopback and ESTABLISHED,RELATED. There is no DNAT into a guest.
5. **Vsock is per pod.** Each guest's vsock device reaches only its own host-side
   listeners.

The netns ruleset is also watched. With `firecracker_netns_drift_check` on
(`crates/nucleus-node/src/main.rs:217`), the node takes a baseline with `snapshot_iptables`
(`net.rs:947`) and stops the VMM if the ruleset ever changes. A runtime rule that opened a
path between two pods would trip the monitor unless the baseline moved with it.

### Why a link is wanted

A controller outside nucleus can reconcile a tenant's declared plan onto a node: which pods
exist, at what size, and which may talk to which. The node API already covers the first two
(`POST /v1/pods`, `POST /v1/pods/{id}/cancel`, `GET /v1/pods/{id}/receipt`). The third has no
node effect. A plan of agent sandboxes that call each other has to be refused today, or
routed through the public internet.

This record adds that one effect, and keeps C2's guarantee for every pair of pods that is not
linked.

### Use cases (surveyed 2026-11-19)

Isolating one untrusted workload in a microVM is now the common baseline for running code an
agent wrote. What a single sandbox cannot express is the policy *between* workloads: which may
talk to which, over what, holding which credentials. That is the gap a link closes, and where a
plan admitted by a decided predicate (`mustReach` / `mustNotReach`) says more than a sandbox
configuration can. Ordered by how much the link and its per-request decision add:

| use case | what a link adds | the theorem it leans on |
|---|---|---|
| **Multi-agent pipelines** (planner, coder, reviewer, executor) | the pod that reads untrusted content is proved unable to reach the pod holding private data or credentials, so no single path assembles untrusted input, private data and a way out | `noninterference_unlinked`, plus the plan's `mustNotReach` claim decided at admission |
| **Tool servers in their own pods** (one per tool, reached by the agent only over a link) | a tool whose self-description overstates its scope still gets only the requests the host admits; its egress is its own pod's, decided per request; credentials stay host-side (ADR 0015) | `request_is_a_decision`, `connect_only_along_links` |
| **Agent code execution** (one sandbox per task) | mostly the existing isolation; links matter once a task needs a helper service (a database, a build cache) without public egress | `step_inv` |
| **Two-party data processing** (each party's workload in its own pod, joined by one decided channel) | "party A's raw data never reaches party B's pod" is a reachability claim admitted before boot, and the receipts are an audit trail anyone verifies offline | `noninterference_unlinked`, `receipts_replay_links` |
| **Evaluation and red-teaming** (eval cells, ADR 0013) | an evaluated model can be given a tool pod and nothing else, with every request it sends decided and journalled | `request_is_a_decision`, `untrusting_client_refused` |
| **CI for untrusted changes** | build steps that need a service pod get one link, not a network | `no_cross_tenant_link` |
| **Untrusted checkers between parties who distrust each other** (a buyer's and a seller's checker) | each runs in its own pod; the exchange between them is the only channel and is receipted | `receipts_replay_links` |

Where a link adds little: a single sandbox with no network and no secrets (plain isolation
suffices, and a per-request decision only adds latency), and throughput-bound or accelerator
work, where a relay per request is the wrong shape.

Two measurements decide whether the first three rows are practical, and neither is taken yet
(§9): pod creation, measured at about 3 s today (`docs/agency-frontier.md`) against
sub-second starts common for agent sandboxes, which the not-yet-started snapshot warm pool
(`docs/production-delta.md`) addresses; and the relay's added latency per request.

Background reading for the survey: the Confidential Computing Consortium's workload
governance paper (attestation alone does not meet a workload's own control objectives) and
the CNCF's confidential-containers admission write-up (the control plane is untrusted, so the
runtime checks pod specs), both 2025–2026.

## Decision

### 1. The path: a host relay over vsock, never a route between namespaces

**Recommended.** A link is a row in a host-held table: `(src, dst, port)`, read as "pod `src`
may open connections to `port` on pod `dst`". No IP path between pods is ever created. A
connection runs as follows:

- **In the source guest:** a relay started by guest-init listens on loopback, one port per
  link, the same pattern as ADR 0015's `127.0.0.1:3128`. It forwards each accepted connection
  to a new host listener, `VsockListener::PodLink`. The workload keeps its seccomp denial of
  `AF_VSOCK`.
- **On the host:** the link relay accepts on `PodLink`. For each connection it looks up the
  table. If the link is absent, or either pod is not live, it closes the connection. Otherwise
  it opens the destination guest's vsock with the host-initiated handshake the node already
  uses (`CONNECT <port>`, `crates/nucleus-node/src/vsock_bridge.rs:156`) and splices the two
  streams together.
- **In the destination guest:** a guest-init relay accepts on that vsock port and forwards to
  the workload's loopback port. Again, the workload never holds a vsock socket.

What this keeps unchanged:

- No netns, iptables or host-link rule is added, so the drift baseline does not move.
- Pods without a NIC can be linked. A link needs only the vsock device.
- The decision is per request. At connect time the host admits the connection only along a
  link in the table; after that the relay parses each HTTP/1.1 request, as ADR 0015's proxy
  does, and asks the host's pod policy (`host_decide`, the entry the egress proxy calls)
  before it delivers a byte. A refused request is answered by the relay and never reaches
  the destination. The decision is taken by the host, from host state, and never by either
  guest (ADR 0014).
- What a link carries is therefore what ADR 0015 can decide: HTTP/1.1, with TLS terminated
  at the relay when the source dials TLS. A raw byte stream or another protocol is not
  linkable; it is refused by name rather than relayed undecided.

**Runner-up: IP routing between namespaces.** Give each linked pod a routable link address,
and add FORWARD and DNAT rules for each link in the host namespace. It is weaker for four
reasons:

- it reopens the deny floor that exists to close exactly this path;
- every link becomes a runtime ruleset change on both pods, which the drift monitor treats
  as an attack;
- the fence becomes a rule list, which a node-side bug can open, instead of the absence of a
  path;
- both guests still hold a device that emits arbitrary frames at the host.

Its advantage is throughput, and that is measured before anyone argues for it (§9).

### 2. The table, and who may write it

- **`link`** is admitted only if all of these hold:
  - both pods are live on this node;
  - the caller's `CallerScope` (`crates/nucleus-node/src/auth.rs:142`) lets it manage
    **both** pods, by the existing `caller_may_manage` (`crates/nucleus-node/src/pod_api.rs:59`),
    applied to each;
  - both pods have the same trust domain (ADR 0001, `lineage_tenant`, `pod_api.rs:178`);
  - the row is not already in the table.
- **A pod the caller may not manage**, at either end, is answered **404**, identical whichever
  end it is (ADR 0001, item 3). A distinguishable refusal would tell the caller which of the
  two ids exists.
- **A link between two tenants is refused in v1.** If it is ever wanted, it is an explicit
  delegation certificate, as ADR 0001 says, never a looser equality check.
- **An existing row** is answered 409.
- **`unlink`** needs the same scope over the link's source pod, and the row must be present.
- Authorization today checks one pod at a time. The two-pod predicate is new code. It is one
  function, used by every link route, and it is the function the proof obligation in §7
  binds.

### 3. Unlink severs

`unlink l`:

1. removes the row;
2. closes every live connection the relay is carrying for `l`, both halves;
3. signs the receipt, only after both steps are done.

A receipt for `unlink` therefore states that no bytes cross `l` from then on. This is
`unlink_severs` in `LinkTable.lean`. Draining existing connections was rejected, because a
revoked link would then still carry data for an unbounded time.

### 4. Cancel and exit: no link ever names an absent pod

- **API cancel** (`cancel_pod`, `pod_api.rs:315`) of a pod that any link names is refused
  with 409, and the answer names the blocking links. Links are removed only by `unlink`, so
  every effect a caller causes is one it asked for.
- **An exit the node did not request** is a crash, a timeout, or a cascade from
  `pod_reaper` (`cleanup_after_exit`). It removes every link naming the pod, severs their
  connections, and signs one `drop-on-exit` receipt per link. A controller sees it as drift
  in the receipt stream, never as silence.
- **Teardown order.** `PodHandle::teardown` (`crates/nucleus-node/src/lifecycle.rs:143`) and
  the Firecracker cleanup (`crates/nucleus-node/src/firecracker_lifecycle.rs`) gain one step,
  "sever and drop this pod's links". It runs first, before identity is drained and before the
  VMM is stopped. A link spans two pods, so the step takes the link table's lock and never
  either pod's own teardown locks. That way two pods tearing down at once cannot deadlock on
  each other.

These are `cancel_refuses_linked` and `exit_drops_links` in `LinkTable.lean`. Together they
give "no row names an absent pod".

### 5. The API

| route | operation | answer |
|---|---|---|
| `POST /v1/pods/{src}/links` with `{dst, port}` | `Operation::LinkPods` | 200 with the signed receipt; 404 or 409 as in §2. A link is named by its row `(src, dst, port)`; it has no separate id |
| `DELETE /v1/pods/{src}/links/{dst}/{port}` | `Operation::UnlinkPods` | 200 with the signed receipt, after severing; 404 when the row is not there |
| `GET /v1/pods/{src}/links` | `Operation::ListLinks` | the rows naming `src` at either end, and the drop receipts signed for it |

- Each route is mapped in `operation_for_route` (`auth.rs:634`), which refuses an unmapped
  route. It is pinned by `operation_for_route_matches_every_declared_route_and_nothing_else`
  (`auth.rs:1088`). Every arm of `authorize_spiffe` (`auth.rs:395`) gains the new operations.
- The handlers live in a new module that merges its own `routes()`, as `workload_result` and
  `pod_api::effect_approvals` do. `main.rs` sits on its line ratchet, which `pod_api.rs`'s
  header explains.
- Each command declares its `Footprint` (`crates/nucleus-node/src/effect_footprint.rs`). It
  writes the link table and reads whether both pods are live.

### 6. Receipts

- `nucleus-receipt`'s `Projection` (`crates/nucleus-receipt/src/lib.rs:102`, which is
  `#[non_exhaustive]`) gains a `Link` variant. Its body is one of three kinds:
  - `link {src, dst, port}`;
  - `unlink {…, severed: n}`;
  - `drop-on-exit {…, exited: pod, severed: n}`.
- It is signed in the same envelope as execution claims (`sign_claim`,
  `crates/nucleus-node/src/workload_result.rs:85`): JCS, BLAKE3, Ed25519.
- The session is the source pod, and the issuer is the node.
- `receipts_replay_links` says that replaying a run's receipts onto the prior table gives
  the table afterwards. A checker holding the receipts can therefore tell whether the node's
  links match a plan, without asking the node.

### 7. The semantics, the proof obligations, and C2

**`crates/portcullis-core/lean/LinkTable.lean`** (core Lean, no `sorry`) models:

- pods, with their trust domain;
- the table;
- live connections, each carried by one link;
- caller scopes;
- the transitions `link`, `unlink`, `connect`, `request`, `cancel` and `exit`, each with its
  receipt;
- the host's per-request decision, as an arbitrary function: every theorem holds for any
  decision the policy makes.

| theorem | what it states |
|---|---|
| `connect_only_along_links` | a connection exists only while its link is in the table |
| `unlink_severs` | after `unlink l`, no live connection is carried by `l` |
| `no_cross_tenant_link` | `link` is admitted only when the caller manages both pods and they share a trust domain |
| `cancel_refuses_linked` | a cancel through the API never removes a pod that a link names |
| `exit_drops_links` | after an exit, no row names the exited pod |
| `receipts_replay_links` | replaying the receipts onto the prior table gives the table afterwards |
| `request_is_a_decision` | a request changes what a pod holds only if its connection is live, the pod is the connection's destination, and the host's decision admitted that request |
| `noninterference_unlinked` | a pod with no link from `p` is unaffected by any request `p` sends, whatever the host decides |
| `step_inv` | every transition keeps the invariant: connections ride links, and links join live pods of one trust domain |

**At implementation (L3),** `proof-obligations.toml` gains rows binding each piece of shipped
code to its theorem, extracted with Aeneas as the egress matcher is. The pieces are:

- the relay's admit function;
- the two-pod authorization predicate;
- the table operations.

`cargo xtask proof-obligations` then refuses a row whose theorem does not name the extracted
constant.

**C2.**
- `PodCrossView.lean`'s `cross_pod_noninterference` is stated over a host state with no
  channel between pods. With links, its honest form is `noninterference_unlinked`:
  noninterference for every pair the link graph does not join.
- The C2 row stays **NOT-YET** and gains `noninterference_unlinked` as an artifact.
- `docs/cross-pod-view.md` classifies the new `NodeState` field, the link table, in its
  field table.

### 8. Listener inventory

- `VsockListener` (`crates/nucleus-ifc-kernel/src/host_listener.rs`) gains `PodLink` on a
  port of its own. 1030 is proposed: 1027–1029 and 15012–15013 are taken, and
  `every_vsock_listener_has_its_own_port` holds the rule.
- Its `WorkloadReach` is `Filtered`. The workload reaches it only through the guest relay,
  and the listener answers only the links the table holds.
- The listener table in `docs/architecture/mediated-set.md` gains the row, which
  `documented_inventory_equals_the_enum` checks.
- **Eval cells:** `PodLink` is served to eval cells (owner decision, 2026-11-19). ADR 0015
  promises that every byte leaving an eval cell is a request the host decided. A link keeps
  that promise because the relay decides each request, the same unit and the same entry as
  the egress proxy (`request_is_a_decision`). An eval cell's link therefore carries HTTP/1.1
  only, as its egress does.

### 9. Guest compatibility, latency, measurement

- **Guest changes.** The source and destination relays are guest-init code. They land as new
  guest-capability rows, the way ADR 0015 §9 adds its relay. A pod whose guest is older than
  the floor that carries them is refused a link by name, never served one that half-works.
- **Not yet measured:** the relay's added latency and throughput against a direct path,
  connection setup time, and the relay's memory per connection. L5 measures them on a node.
  Until then this record claims no performance figure.

### 10. Implementation sequence

| step | what lands | moves enforcement? |
|---|---|---|
| L1 | `LinkTable.lean` with the theorems in §7; this record accepted | no |
| L2 | the `Projection::Link` variant and its receipt tests; the `PodLink` listener variant and its inventory row | no |
| L3 | the table, the two-pod predicate and the relay's admit function, extracted; the `proof-obligations.toml` rows | no (no route yet) |
| L4a | the control plane: the link routes, their authorization, signed receipts, a cancel of a linked pod refused (409), and links dropped with receipts on an exit the node did not request | only the cancel of a linked pod (now 409); no byte crosses a link yet |
| L4b | the host link relay (the data plane): the `PodLink` listener, admit along a link, decide each HTTP/1.1 request with the pod policy, sever on unlink and exit | yes, for the host half |
| L4c | the guest relays on both ends, behind their capability rows | yes: links become possible |
| L5 | measurement on a node (§9); C2's artifact list updated | no |

**What L1–L3 delivered (2026-11-19).**

- L1: `LinkTable.lean`, core Lean 4.30, no `sorry`, axioms within `propext`, `Classical.choice`,
  `Quot.sound`.
- L2: `Projection::Link` with sign, tamper and round-trip tests; `VsockListener::PodLink` on
  port 1030 (`documented_inventory_equals_the_enum` went red without its row).
- L3: `extracted/link.rs` (six scalar predicates; Aeneas translated all 61 functions of the
  scoped run, none opaque) and `links.rs` (the table, applying them; unit tests named after the
  theorems plus a property test of `step_inv` over random operation sequences).
  `LinkTableExtracted.lean` proves each predicate total and exact, and that `may_link`,
  `may_cancel` and `may_deliver` compute `LinkTable.admitLink` and the outcome of
  `LinkTable.step` for cancel and request. Six `proof-obligations.toml` rows bind them.
- Driven red, each on the real defect: dropping the trust-domain check from `links.rs` failed
  `no_cross_tenant_link` and `step_inv`; an exit that kept connections failed
  `exit_drops_links`; an extracted `may_link` without that check failed
  `LinkTableExtracted.lean`; a row naming a theorem that does not mention its function failed
  `cargo xtask proof-obligations`.
- Found on the way: the local Charon was 0.1.223 while CI pins 0.1.210, so the committed
  `generated-link/` is regenerated by CI's canonicalize step like every other slice; and
  `nucleus-node`'s test target does not compile on macOS (`FirecrackerConfig::without_devices`
  is Linux-only, a test calls it unconditionally), which predates this record.
- The workflow change (`aeneas-ifc-scoped.yml`) is a guardrail path: it needs the owner's
  hardware-key approval before it merges.

**What L4a delivered (2026-11-19).**

- `crates/nucleus-node/src/pod_links.rs`, merged by its own `routes()`:
  `POST /v1/pods/{src}/links` `{dst, port}`, `DELETE /v1/pods/{src}/links/{dst}/{port}` and
  `GET /v1/pods/{src}/links` (the links naming the pod and its drop receipts).
  `auth::Operation` gains `LinkPods`, `UnlinkPods` and `ListLinks`, mapped in
  `operation_for_route` and granted to tenants, CI identities and pods as the per-pod operations
  are; WHICH pods stays the caller scope's.
- Authorization stays the node's: a link resolves both ends through `get_pod_for_caller`, so an
  end outside the caller's scope is the same 404 whichever end it is. Only then does the table
  decide (both running, one trust domain, no self link, no duplicate), and its refusal is 409.
  An unlink resolves only its source (`may_unlink`), so it never answers whether the
  destination exists.
- Trust domain: the one a pod's certificate root was issued in (`lineage_tenant`). A pod with no
  federated owner is in the node-local domain, written `""`, so a tenant's pod and a node-local
  pod are never linked.
- Pods enter the table when a link names them and both are running, not at create, so
  `create_pod` is unchanged. The table's lock is async and held across a cancel, so no link is
  made between "no link names it" and the teardown.
- Receipts: `Projection::Link`, signed by `workload_result::sign_projection` (factored out of
  `sign_claim`, so the two cannot sign differently), the session being the source pod.
- Cancel through HTTP or gRPC refuses a linked pod: `ApiError::Conflict` (409),
  `FAILED_PRECONDITION` over gRPC. The reaper's timeout, exit cleanup and cascade, the drain, and
  an abandoned launch call `pod_gone`, which drops the pod's links and gives each surviving end a
  signed `drop-on-exit` receipt.
- Tests (`pod_links::tests`, the `handler_tests` fixture): receipts verify for link, unlink and
  drop; a node-wide caller cannot link two trust domains (409); a tenant naming another
  tenant's pod gets 404 as source or destination; a linked pod's cancel is 409 and changes
  nothing; the route-pinning test covers the three routes and two near misses. Driven red:
  resolving the destination without the caller's scope turned the cross-tenant 404 into a 409
  (the existence oracle); a cancel without the linked check failed
  `cancel_of_a_linked_pod_is_refused`.
- §5 changed to what was built: a link is named by its row, not an id, so `DELETE` takes
  `{dst}/{port}`; the operation is `ListLinks`; `GET` lists both ends' rows plus drop receipts;
  a made link answers 200, like the other signed-receipt routes.
- Found on the way: `nucleus-node`'s test target now builds on macOS (the write-extent test is
  gated to Linux, where its function exists); `cargo clippy --no-deps -D warnings` on macOS
  reports dead-code lints in Linux-only code (`landlock.rs`, `egress_proxy.rs`, `upstreams.rs`,
  `jailer_limits.rs`, `host_decide.rs`), none in files this step touched; CI runs clippy on
  Linux.

**What L4c delivered (2026-11-19).**

- `crates/nucleus-tool-proxy/src/link_relay.rs`, both guest halves, parsing nothing and
  deciding nothing (ADR 0013's adversary holds root in the guest):
  - outbound: a loopback listener at `127.0.0.1:3129` (3128 stays ADR 0015's), advertised to
    the workload as `NUCLEUS_LINK_PROXY=http://127.0.0.1:3129`, each connection spliced to the
    host's `PodLink` listener (vsock CID 2, port 1030). The workload speaks HTTP proxy protocol
    (absolute-form, or `CONNECT <name>:443` under E3); the host reads it.
  - inbound: a guest vsock listener on port 1031 admitting only the host's CID
    (`peer_is_host`). The host writes one line, `PORT <n>\n`; the relay connects to
    `127.0.0.1:<n>` and splices. A malformed line, a port outside 1..=65535, or a host that
    closes before the newline is dropped with nothing sent to the workload. The line is read
    byte by byte, so no request byte after it is lost.
  - severing: when the host's side ends, both streams drop at once; a workload half-close is
    passed on and the answer still flows back.
- `NUCLEUS_LINK_PROXY` is runtime-injected (a spec cannot point it elsewhere) and admitted as
  public runtime config (`workload.rs` `PUBLIC_RESERVED`). Bound before the workload starts, so
  the address is listening when the workload reads it. A relay that cannot bind logs and leaves
  the pod without links, never without its tool-proxy (PID 1).
- `GuestCapability::PodLinkRelay`: `FirstShipped::NotYet`, `Demand::Optional`.
  `the_pinned_release_serves_this_tree` requires every unreleased row to be optional, and the
  node cannot learn a Firecracker guest's release anyway; a guest without the relay carries no
  bytes on its links, which refuses nothing the host decided.
- Tests (macOS, through `DialHost`/`DialWorkload` seams over in-memory streams): bytes spliced
  both ways, outbound and inbound (including request bytes in the same write as the preamble);
  a closed host side closes the workload side within 5 s; a workload half-close still gets the
  answer; malformed, out-of-range and truncated preambles are refused; a non-host peer is
  refused and reaches no workload dial. Driven red: admitting a non-host peer failed
  `a_non_host_peer_is_refused_and_reaches_nothing`; a splice that kept going after the host's
  EOF failed `a_closed_host_side_closes_the_workload_side` (timed out).
- The Linux-only code (`VsockHost`, `start_in_guest`) cannot build on macOS and the crate cannot
  be cross-checked here (`ring` needs a cross C compiler); a verbatim copy type-checks against
  `tokio-vsock` 0.7 for `aarch64-unknown-linux-gnu`. It runs for the first time on a KVM host.
- Contract L4b must meet, found here: the host relay names the source pod by the vsock socket the
  connection arrives on (`{uds}_1030`, per pod), the destination by the link name in the request,
  and writes `PORT <link port>\n` to the destination's guest port 1031 only after its decision.
  The link-name format is L4b's to fix. The node should refuse a pod spec whose own vsock
  control port is 1031; until it does, such a pod runs without links.

**What L4b delivered, proxy side (2026-11-19).** `nucleus-egress-proxy --mode link` is the host
link relay: the same confined binary, parser, summary and decision channel as egress, with one
different upstream (`crates/nucleus-egress-proxy/src/link.rs`).

- **Link names.** `<dst-uuid>.link.nucleus.invalid` (canonical lower-case `8-4-4-4-12`; `.invalid`
  per RFC 6761, so a link name can never resolve outward). Absolute-form
  `http://<name>:<port>/…`, or `CONNECT <name>:443` terminated through E3 with a leaf for that
  name. The summary's URL carries the destination and port, so the decision frames are unchanged.
- **Modes are exclusive.** The egress proxy refuses a link name (`link_not_here`) and the link
  proxy refuses any other host (`not_a_link`), both before the node is asked.
- **Delivery** goes through the extracted `may_deliver(connection_live, host_admits)` only:
  `host_admits` is the node's allow, `connection_live` is whether the node announced this
  `(dst, port)` and has not severed it. Otherwise the node's own refusal, or `link_not_live`.
- **Upstream bytes** to the destination: `CONNECT <guest-port>\n`, `OK …`, `PORT <port>\n`
  (L4c's preamble), then the decided request re-serialised in origin form. Plain HTTP over vsock:
  TLS from the source ends at the relay.
- **Severing** is a one-way control pipe from the node, not a decision frame (the decision
  channel is strictly numbered request–answer; an unsolicited frame would poison it). A `SEVER`
  closes every live connection on that link at once, mid-response included. A control line that
  does not parse, or the pipe ending, drops every route and severs everything (fail closed).
- **Tests** (`serve_link_tests.rs`, in-process, macOS; 48 pass in the crate): an admitted request
  arrives with the handshake, the preamble and the decided request; a denied one opens zero
  connections; a link never announced, on another port, or severed opens zero; `SEVER` and a
  broken control pipe close a live connection mid-response; TLS over a link is terminated and
  delivered in clear; CL+TE, a pipelined second request, `Upgrade` and a non-TLS `CONNECT` are
  refused before the node is asked; each mode refuses the other's names.
- **Driven red:** delivering regardless of the node's answer failed
  `a_denied_request_never_reaches_the_destination`; a relay not raced against the sever signal
  failed both sever tests (timed out); an egress proxy that let link names through failed
  `the_egress_proxy_refuses_a_link_name`.
- **Not compiled for Linux here,** like E3: the `--mode link` start path in `main.rs` is
  Linux-only. Its pipe adapter (`control_pipe`) is compiled on every platform.

**What the node half of L4b must do** (not built):

1. **Start one link proxy per pod** that may hold links (eval cells included), the way
   `egress_proxy::start_for_pod` starts the egress one: stdin = the `PodLink` listener
   (`bind_guest_listener(uds, VsockListener::PodLink, …)`, `{uds}_1030`), stdout = a decision
   socketpair, `--mode link`, `--link-control-fd N` = the read end of a pipe, no `--deny-floor`,
   and `--tls-ca-fd` when the pod has a CA (its constraints must include the link names of the
   pod's links). The process is per source pod, so the source is the pod whose `{uds}_1030` the
   connection arrived on: never anything the guest says.
2. **Write control lines** to that pipe, one per change, `\n`-terminated:
   `LINK <dst-uuid> <port> 1031 <dst-vsock-uds-path>` when a link from this pod is made (the
   path is the destination's Firecracker `vsock.sock`, `jail.host_path(in_jail::VSOCK)`, which
   `FirecrackerPod` must now record), and `SEVER <dst-uuid> <port>` on unlink and on either end's
   exit, before the unlink or drop receipt is signed. Closing the pipe severs everything.
3. **Decide link requests** on the link proxy's decision channel: parse the summary, map the
   link name back to `(src, dst, port)`, require the row in `NodeState.links` (refuse with
   `RouteRefused` otherwise), then `PodPolicy::authorize_effect` exactly as egress does. Record
   the connection with `LinkTable::connect` and each delivered request with
   `LinkTable::request`, so receipts and `severed` lists name real connections.
4. **Confinement to check on Linux:** the link proxy must be able to `connect(2)` the
   destination's `vsock.sock` after Landlock (ABI V2 handles no connect right) from inside its
   namespaces as its unprivileged uid; jail ownership of that socket may need a group grant.

**Found by E3's node side (2026-11-19): two contracts above cannot hold as written.**

- **No inherited descriptor above stderr survives a confined exec.** The confinement hook marks
  every descriptor from 3 up close-on-exec (`nucleus::hardening`, `harden_child`). So
  `--link-control-fd N` cannot work any more than `--tls-ca-fd N` could. E3's CA now rides the
  decision channel (`--tls-ca-channel`, ADR 0015 §14); link control lines need the same kind of
  carrier (the decision channel, or a second socket the proxy connects to), not a pipe at fd N.
- **The CA cannot list future link names, and the proxy grants exact names only.** A link is made
  after admission, so the pod CA permits the link namespace as one DNS subtree,
  `link.nucleus.invalid`, and the table decides which link. But `TlsTermination.lean` models
  `permitted` as exact names (`permitted.contains`), and the proxy mints a leaf only for a name
  that is exactly a permitted entry (`PodCa::name_permitted`). So no leaf is ever minted for
  `<dst-uuid>.link.nucleus.invalid`, and TLS over a link is refused `NameNotPermitted`. Plain
  HTTP links are unaffected. Fixing it means the model, the extracted verdict and the proxy
  agreeing on subtree semantics for the link namespace, with the per-link check left to the table.

**What L4b delivered, node half, and the two hand-over repairs (2026-11-19).** L4b is built.

- **The proxy's carriers** (`crates/nucleus-egress-proxy`). `--tls-ca-fd` and
  `--link-control-fd` are gone. The CA bundle is read off the head of the decision channel
  (`--tls-ca-channel`, `tls::read_bundle`: the magic and two length-prefixed fields, bounded by
  `MAX_BUNDLE`, never a byte past the bundle). Control lines come over
  `--link-control-socket PATH`: a Unix socket the node binds in the pod directory, owns
  (`chown` to the proxy uid, mode 0600) and accepts exactly one connection on; the proxy
  connects once, before Landlock. The path is the node's, never the guest's.
- **TLS names in link mode.** `tls::Termination` carries one name predicate (`NamePermit`) that
  the leaf minter and the verdict both consult. Egress mode: exactly one of the CA's permitted
  names, as before. Link mode (`link::termination`): `<uuid>.link.nucleus.invalid` whose
  destination the node has announced a live `LINK` to (`Links::permits`), under a CA whose
  constraints include `link.nucleus.invalid` (checked at start, or the proxy refuses to start).
  This resolves the exact-names tension recorded above in the code; the Lean model's predicate
  form is the main session's.
- **The node half** (`crates/nucleus-node/src/link_proxy.rs`). Every Firecracker pod on a node
  with `--egress-proxy-bin` gets a link proxy, spawned and verified by the same
  `egress_proxy::spawn_confined` as the egress one, so the two cannot be confined differently.
  `LinkDecider` is the egress decider's `begin` and `finish` around one different route: the
  summary's origin must be the link name of a destination this pod has a row to on that port in
  `NodeState.links`, otherwise `RouteRefused` and the proxy connects nothing; then
  `authorize_effect` and the redeemed decision id exactly as egress. Each request asked about is
  recorded as `LinkTable::connect` then `LinkTable::request`. The table lock is held across the
  decision, so a row cannot be unmade between the check and the record.
- **Control lines** (`pod_links`). Making a link writes `LINK <dst> <port> 1031 <dst vsock.sock>`
  to the source's relay; unlink, and either end's exit, write `SEVER <dst> <port>` before the
  receipt is signed. A link port must be 1..=65535 (a port the proxy cannot carry would make its
  control line unparseable, and an unparseable line severs every link).
- **The CA's second holder.** An eval cell's CA is split by value (`MintedCa::split`): one half
  to the egress proxy, one to the link proxy, each handed over and wiped. Both holders are the
  same pod's proxies, which is what `ca_key_stays_in_proxy`'s `proxy p` names.
- **Port 1031** is `nucleus_spec::LINK_RELAY_GUEST_PORT`, one constant for the tool-proxy's
  relay and the node; a spec claiming it as `vsock.port` is refused at create
  (`PostureRefused::GuestPortReserved`).
- **TLS over a link uses port 443.** A source dials `CONNECT <name>:443`, so the row is
  `(src, dst, 443)` and the destination relay delivers the decided request in clear to the
  workload's `127.0.0.1:443`.
- **Tests on macOS** (`link_proxy_tests.rs`, the real link-mode proxy over a socketpair to the
  real `LinkDecider`, the real routes, control lines over a real Unix socket, a fake Firecracker
  mux): a request over a made link is decided by the table and the policy and delivered with
  `CONNECT 1031` and `PORT 8080`; a route the proxy holds but the table does not is refused by
  the node and the destination sees zero connections; unlink closes a held connection through
  the control socket and the proxy forgets the route; a link port of 0 or 70000 is refused
  before any control line; the node's CA half arrives over a socketpair, `read_bundle` stops at
  the bundle, and link termination admits a link name only once it is announced. Proxy crate: a
  TLS handshake for an unannounced link name mints no leaf and asks nothing; a CA without the
  link subtree is refused for link mode; `read_bundle` round-trips and refuses short, wrong and
  oversized channels. Spec: 1031 refused, 1030 and 1032 admitted.
- **Driven red:** a decider that routes without the table check failed
  `a_link_not_in_the_table_is_refused_by_the_node_and_nothing_is_connected`; an unlink that does
  not write `SEVER` failed `unlink_severs_a_live_connection_through_the_control_socket`; link-mode
  TLS that ignores announcements failed `tls_to_an_unannounced_link_name_gets_no_leaf` and
  `the_ca_arrives_on_the_channel_and_tls_admits_only_announced_links`. Each restored, green.
- **Only Linux can show:** that `harden_child` leaves stdin and stdout intact (both carriers ride
  them); that the confined proxy, as its unprivileged uid inside its namespaces, can `connect(2)`
  the control socket (the pod directory must be traversable by that uid; the socket is chowned
  to it) and, after Landlock, each destination's `vsock.sock` (the jail's; a group grant may be
  needed); that the proxy reads the CA before it connects the control socket, matching the
  node's order (hand over, then accept). None of `link_proxy::start_for_pod`, `LinkProxy::start`
  or the proxy's Linux `run` has been compiled for Linux here.
- **Found:** the table records one connection per request and has no `close`, so `conns` grows
  with every request on a long-lived link until unlink or exit clears it. The Lean model has no
  close transition either; adding one is a model change first.
  **Fixed (2026-11-19), model first:** `LinkTable.lean` gained `Op.close` with `close_conns`,
  `close_removes` and `connect_request_close_bounded` (a connection opened, given its one
  request and closed leaves the table no larger), `step_inv` and `receipts_replay_links` still
  hold (core Lean, `propext` and `Quot.sound` only), and `LinkTableExtracted` still builds.
  `links.rs` gained `LinkTable::close` (in the `step_inv` proptest mix; `close_removes` test),
  and the node closes each connection once its request is decided
  (`pod_links::Links::record_request`). `many_requests_over_a_link_leave_no_connection_open`
  sends 20 requests over one link and finds none open; with the close removed it found 20.

**The gauntlet (2026-11-19): written, not yet run.** L4 is not claimed working until it passes
on a real KVM host. The pieces:

- `crates/nucleus-link-probe`, the in-guest workload, laid into the rootfs by `OVERLAY_DIR`
  (no shell change): `serve <port>…` logs every request it receives; `send` sends n requests
  over a link, n to an unlinked port and n over TLS; `adversary` tries raw `AF_VSOCK` (to the
  host's 1030 and 1029 and other CIDs' 1031), a forged link name, CL/TE smuggling, a pipelined
  second request, `Upgrade`, a non-TLS `CONNECT`, TLS trusting a foreign CA, and 80 connections
  against the cap of 64. It reports sentinel lines; it decides nothing.
- `nucleus-cli` `host_evidence_live::links::links_gauntlet`, run by `cargo xtask links-live`, on
  a node started with `--egress-proxy-bin`. Its items and their verdicts:
  (a) differential conformance: N random link, unlink and cancel operations (default 2,000;
  `NUCLEUS_LINKS_OPS`) on 8 pods, each applied to the in-process `LinkTable` and to the live
  API, every answer compared, the first divergence a failure, each successful cancel replaced
  by a new pod; (b) every answered request reached the destination, no request to the unlinked
  port did, and nothing reached it unanswered, with answered ids looked up in the sender's
  host-effect journal; (c) no adversary attempt reached a socket or the destination; (d) an
  unknown pod at either end gets one identical 404, timings reported as Welch's t, not judged;
  (e) a linked pod's cancel is 409 and its reaper timeout leaves a drop receipt, 64 raced
  link/unlink pairs leave the row consistent with the 200s, an unlink mid-request and a node
  restart are recorded; (f) a pod nobody links receives nothing; (g) every collected receipt
  verifies with the executor public key alone. A JSON report holds every number; the run fails
  only on a `fail` item.
- `cargo xtask gauntlet-host-setup` prepares a fresh host: KVM and vsock, the musl build
  (with `nucleus-egress-proxy` and the probe), `build-rootfs.sh` with the probe overlay,
  `nucleus setup --artifacts local`, and the staged kernel, rootfs and binaries.
- **Not covered, and why:** links across trust domains (the harness mints only node-local
  identities; a second trust domain needs a federation enrolment it does not do); eval cells
  (they need an attested node: a vTPM AK pin and reference manifest, `docs/findings/
  attested-node-live-run.md`); 10,000 operations and 50,000 requests are knobs, not defaults;
  latency and throughput are not measured. (A TLS link once landed on the destination
  workload's port 443, which an unprivileged workload cannot bind; since `98aee0d22` the probe
  dials `CONNECT <name>:<port>` on the link's own port, as the proxy always allowed.)

**Local rehearsal (arm64, Apple container, nested KVM) — not the goal's x86 spot VM run
(2026-11-19).** Run on the owner's Mac while the x86 VM waited on IAM: an Apple M5 Pro,
`container` 1.4.1 with `--virtualization` and the L1 kernel built from
`docker/Containerfile.l1-kernel` (6.18.35, `CONFIG_KVM=y`, `CONFIG_VHOST_VSOCK=y`), a Debian
bookworm host container with Firecracker/jailer 1.17.0 and the pinned v2.6.0 aarch64 guest kernel,
12 vCPUs, 24 GB. aarch64 musl binaries of this branch; the rootfs from `build-rootfs.sh` with the
probe overlay. Nested and arm64: it says nothing about x86 timing, and it does not discharge the
goal.

- **Run 3, on `391e16f7f`, 200 operations, 6-pod pool: the gauntlet passed** (no `fail` item).
  - (a) differential conformance: 200 operations, every answer equal to the in-process
    `LinkTable`'s (93 done, 47 refused, 60 not found).
  - (b) per request: 50 of 50 linked requests answered and delivered, 50 of 50 to the unlinked
    port refused (403) with none delivered, 0 delivered unanswered. TLS over the link: 50
    refused, because these are not eval cells and only eval cells are minted a CA (`tls_other`).
  - (c) adversary, every attempt refused: raw `AF_VSOCK` to CID 2 ports 1030 and 1029 and to
    CIDs 3–5 port 1031 (`EPERM`, the workload seccomp), a forged link name, CL/TE smuggling, a
    pipelined second request, `Upgrade`, a non-TLS `CONNECT`, TLS trusting a foreign CA; the
    64-connection cap answered, as it should below the cap.
  - (d) 50 probes, one status (404), one body, mean 0.143 ms vs 0.147 ms, Welch's t −0.46.
  - (e1) link 200, cancel 409, drop receipt after the exit; (e2) 64 raced link/unlink tasks
    left the row consistent (2 links, 2 unlinks, row absent); (e3) recorded: an unlink mid-
    stream left 6 answered, 1 refused, 1 connection closed; (e4) recorded: after a node restart
    the listing is 404 with 0 rows. **The table is not persisted**, as expected.
  - (f) inconclusive in this run (fixed after, below); (g) 101 of 101 receipts verified with the
    executor public key alone.
- **Measured** (run 2, same commit; nested, not x86): pod create to running 2.78–3.44 s wall (12 pods, the node's
  boot breakdown); 50 linked requests sent serially in 3.32 s with refused and TLS requests
  interleaved (150 requests, about 22 ms each end to end through guest relay, link proxy, node
  decision, forwarder and destination relay). Link and unlink calls and sever latency were not
  timed separately.
- **Run 4, 2,000 operations: stopped** during item (a) after 14 minutes, when the Mac's free disk
  fell to the 12 GB floor this run set itself. No report; nothing failed before the stop.

Found by the rehearsal, each fixed with a test that fails before and passes after:

- **The link proxy could not reach the destination's jail** (`391e16f7f`). Its uid (65534)
  cannot traverse the destination's jail root (0700, the jail user's): all 103 admitted
  requests of the first run ended `LinkUnreachable`. The node now runs a forwarder per link in
  the source pod's directory (`link_proxy::Forwarder`); this also explains the x86 run's empty
  sender report, which predates the fix.
- **TLS over a link was pinned to port 443 by the probe and harness** (`d8a7ac92b`,
  `98aee0d22`); the proxy already used the `CONNECT` port.
- **The harness**: an unlinked canary that works reported nothing, so (f) could not pass (the
  probe now reports `listening`); items left their pods running and exhausted the node's vCPUs;
  an item that could not run ended the run without a report (all in `98aee0d22`).

Found and **not** fixed, because it changes the decision protocol's meaning (model-first work):

- **One late decision poisons a pod's links for good.** In the first run the node answered one
  request about 2.2 s after it was asked, after 103 answers of about 10 ms, with nothing logged
  in between; the proxy's 2 s deadline expired, and every later request on that pod was refused
  `HostUnavailable(Poisoned)`. Poisoning is ADR 0015's rule (a late answer could be credited to
  the wrong request). For links it turns one stall into a pod whose links never carry another
  byte. A resynchronisation (for example, numbered answers the proxy can discard when late) is a
  change to the decision channel's semantics and goes through its model first.
  **Fixed, model first (2026-11-19):** `DecisionChannel.lean` and ADR 0015 §14. A timed-out
  request is refused and its number owed; the late answer is dropped by number; the channel keeps
  working. `a_slow_answer_refuses_one_request_and_the_link_keeps_working` is the link-mode test
  (red under the old poisoning rule).

Rehearsal environment only, not product defects: Debian's `musl-gcc` on aarch64 runs the repo's
`.cargo/ld/real-ld` wrapper, which linked dynamically against a musl loader the guest does not
have (built with `COMPILER_PATH` cleared); a cgroup v2 root that still holds processes cannot
delegate controllers to the jailer (processes moved to a child group first); a Debian tarball made
without the empty `/proc`, `/sys`, `/dev` mount points stops guest-init.

**Connection-slot leak, found on the x86 gauntlet (2026-11-19).** Three x86 runs, one at the
decision-channel fix, each delivered exactly 63 of 200 linked requests; the rest ended 503. The
destination relay (`nucleus-tool-proxy` `link_relay`) used the outbound `splice`, which on the
workload's end-of-stream only half-closes toward the host and then waits for the host to close.
Nothing on the host side closes first: the proxy waits for the response to end, and a guest
half-close does not surface as EOF on the host's vsock socket. So every exchange stayed open and
held one of the source pod's 64 connection slots (`MAX_CONNECTIONS`); the 64th request on met
`TooManyConnections`. The same shape is a denial of service: a destination that never closes
exhausts its source's slots.

- Fix: the inbound side uses `splice_inbound`, which ends the exchange when either side ends (the
  server's end-of-stream, after its bytes are written; or the host's, the sever). Test
  `a_server_that_answers_and_closes_ends_the_inbound_exchange`, red on the old splice (5 s
  timeout).
- Backstop: the link proxy bounds each delivered exchange by `LINK_EXCHANGE_DEADLINE` (30 s), so
  a destination that never closes releases the source's slot. Test
  `a_destination_that_never_closes_releases_the_slot_after_the_deadline`, red without the
  deadline.
- Guard: `one_hundred_fifty_sequential_link_requests_are_all_delivered` (proxy slot accounting).
- **The harness counted the leak as a pass.** Item (b) failed only on missing or leaked
  deliveries; a linked request that ended 503 or with no response fell into no bucket. It now
  counts `linked_failed` and fails on any (`a_503_on_a_made_link_fails_item_b`, red on the old
  rule with the observed 63 and 137).
- Not yet shown on Linux: whether a guest-side full close surfaces promptly on the host's vsock
  socket (the fix relies on it; the deadline bounds it if not). The next x86 run measures it.

### The gauntlet on x86 KVM (2026-11-20, commit `e27cc34fd`)

**Host:** a throwaway GCP spot VM, `n2-standard-16` (16 vCPU, 62 GiB), us-east4-c, nested
virtualization, shielded vTPM, Ubuntu 24.04, kernel 7.0.0-1017-gcp, no service account, deleted
after the run. Built on the VM from the branch (`cargo xtask gauntlet-host-setup`), run with
`NUCLEUS_LINKS_OPS=2000 cargo xtask links-live --sudo`. Report:
`/var/tmp/links-gauntlet-e27.json` on the VM, kept outside the repository.

**Result: no item failed.**

| item | verdict | numbers |
|---|---|---|
| (a) model ↔ node differential | pass | 2,000 random operations on 8 pods, outcomes identical to `LinkTable`: 841 done, 706 refused, 453 not found |
| (b) per-request decisions | pass | 200/200 linked requests delivered, every one with a host decision in the journal; 200/200 unlinked refused; 0 leaked; 0 delivered undecided; 0 failed |
| (c) adversary (guest root) | pass | raw vsock to the host's 1029/1030 and to other CIDs' 1031 refused (`EPERM`); forged link name, CL/TE, pipelining, `Upgrade`, non-TLS `CONNECT`, foreign CA: refused or decided, none delivered |
| (d) isolation | pass | 200 probes, one status (404) and one body for an unknown source or destination; Welch t = 0.31 (timing reported, not judged) |
| (e1) cancel while linked, then exit | pass | 409, then a drop-on-exit receipt |
| (e2) 64 concurrent link/unlink tasks | pass | the row is consistent afterwards |
| (e3) unlink mid-request | recorded | 6 × 200, 1 × 403, 1 × closed (clocks not correlated) |
| (e4) node restart | recorded | the table is lost (404, 0 rows): it is not persisted |
| (f) canary with no link | pass | listening, received nothing |
| (g) offline receipt verification | pass | 847/847 verified with the node's public key alone |

**How it got there: four x86 runs, each failure a defect fixed with a red-driven test.**

1. Run 1 (`66ab86b9e`): (b) and (f) inconclusive. The link proxy (uid 65534) could not enter the
   destination's jail root (0700), so every admitted request was `LinkUnreachable`. Fixed by the
   node's per-link forwarder (`391e16f7f`), found first by the arm64 rehearsal.
2. Run 2 (`98aee0d22`): 63 of 200 linked requests delivered, the rest 503, and (b) still read
   "pass". Two defects: the destination guest relay waited for the host to close first, so every
   delivered exchange held one of the source pod's 64 slots (`e27cc34fd`: the relay ends on the
   server's end-of-stream; `LINK_EXCHANGE_DEADLINE` bounds a destination that never closes); and
   the harness had no bucket for a 503 (`e27cc34fd`: `linked_failed` fails the item).
3. A diagnostic run with the decision-channel fix (`e88e8cf22`) still stopped at 63, which ruled
   that cause out for this symptom. The fix stands on its own: one late answer had poisoned a
   pod's channel for good in the rehearsal.
4. Final run (`e27cc34fd`): the table above.

**Found on the VM, not yet fixed:** a node that dies leaves its confined proxies running
(reparented to PID 1, sockets open, the binary busy for the next install): 24 after run 1, 10
after the final run. A fix (parent-death signal on the confined child) is in progress.

**Not covered by this run:**
- TLS over a link: a pod CA is minted only for eval cells, and an eval cell needs an attested node
  (vTPM AK pin and reference manifest), which this VM did not configure. All 200 TLS requests were
  refused, as designed; TLS link termination is tested in-process only.
- Links across trust domains: every pod here was node-local; covered by L4a's handler tests and
  `no_cross_tenant_link`.
- Persistence across a node restart (e4): the next step is native Olog.

**Cost:** the VM ran about three hours. At spot list prices for `n2-standard-16`, plus a
150 GB standard disk, that is under $1, against a $10 ceiling.

## Consequences

- Accepting this record changes no pod's behaviour. Until L4, no link can exist.
- After L4, a linked pair can open connections to the linked port and nothing else, and every
  request over one is decided by the host before it is delivered. Every pair that is not
  linked keeps today's five layers, untouched.
- The relay is new TCB, on the host and in both guests. Its compromise is bounded to the
  links it carries. Its admit function is the proved part.
- The relay parses HTTP/1.1 and terminates TLS, as ADR 0015's proxy does, so it reuses that
  parser and its trust root rather than adding a second one. A link cannot carry a protocol
  the host cannot decide per request.
- A cancel of a linked pod now fails with 409 until the links go. A controller unlinks
  first. That is its plan's diff, stated rather than implied.

## What this does not claim

- That the shipped relay matches `LinkTable.lean`. That is L3's extraction and proof
  obligation. Until then the theorems are about a model.
- C2. It stays NOT-YET. This record narrows C2's statement to unlinked pairs. It does not
  prove the restated C2 against the running node.
- Any figure for throughput, latency or memory (§9).
- Links across nodes, or links between tenants. Each is out of v1, and each needs a decision
  of its own.
- Any protocol other than HTTP/1.1 over a link.
