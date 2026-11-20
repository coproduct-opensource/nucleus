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

**Found on the VM, fixed since (see the next paragraphs):** a node that dies leaves its confined
proxies running (reparented to PID 1, sockets open, the binary busy for the next install): 24
after run 1, 10 after the final run.

**Not covered by this run:**
- TLS over a link: a pod CA is minted only for eval cells, and an eval cell needs an attested node
  (vTPM AK pin and reference manifest), which this VM did not configure. All 200 TLS requests were
  refused, as designed; TLS link termination is tested in-process only.
- Links across trust domains: every pod here was node-local; covered by L4a's handler tests and
  `no_cross_tenant_link`.
- Persistence across a node restart (e4): the next step is native Olog.

**Cost:** the VM ran about three hours. At spot list prices for `n2-standard-16`, plus a
150 GB standard disk, that is under $1, against a $10 ceiling.

**Found on the VM, fixed: proxies outlived their node (2026-11-19).** When the node died or
was killed, every confined `nucleus-egress-proxy` it had spawned (egress and `--mode link`)
kept running under PID 1, its sockets open and its binary busy: 24 after the first run, 20
after the diagnostic one, and the next install failed `ETXTBSY`. The fix is in the one place
host services are confined (`harden_child`, `Isolation::NetnsThenDrop`): after the uid drop
(a credential change clears the signal), `prctl(PR_SET_PDEATHSIG, SIGKILL)`, then the race
check (if the spawner already died, `getppid()` is no longer it, and the spawn is refused).
The signal fires when the spawning *thread* exits, so `spawn_confined` documents why its
callers run on the runtime's long-lived worker threads (never `spawn_blocking`; the node has
no `block_in_place`). Test: `a_confined_child_dies_with_its_spawner` (Linux, root), which
SIGKILLs a spawner that started a child exactly as the node does and requires the child gone
within 1 s. Driven red: with signal 0 in place of `SIGKILL`, the child outlived its spawner
and the test failed.

### The gauntlet at full scale (2026-11-20, commit `b32cf4c91`)

**Scale:** `NUCLEUS_LINKS_OPS=10000 NUCLEUS_LINKS_REQUESTS=50000 NUCLEUS_LINKS_PROBES=10000`, on a
fresh VM of the same shape (`n2-standard-16` spot, nested virtualization, shielded vTPM, 150 GB
standard disk, a 6-hour maximum run so it deletes itself). The run took about 100 minutes
(09:43–11:25 UTC) while a mutation run shared the host at `nice 19`.

**Result: no item failed.**

| item | verdict | numbers |
|---|---|---|
| (a) model ↔ node differential | pass | 10,000 random operations on 8 pods, outcomes identical to `LinkTable`: 4,217 done, 3,650 refused, 2,133 not found |
| (b) per-request decisions | pass | 50,000 of each kind sent; 50,000/50,000 linked delivered, each with a host decision in the journal; 50,000/50,000 unlinked refused; 0 leaked, 0 undecided, 0 failed; 0 of 50,000 TLS requests answered (no pod CA on this node) |
| (c) adversary (guest root) | pass | as at `e27cc34fd`: every raw vsock and protocol attack refused or decided, none delivered |
| (d) isolation | pass | 10,000 probes, one status (404), one body; Welch t = −0.60 (reported, not judged) |
| (e1) cancel while linked, then exit | pass | link 200, cancel 409, then a drop-on-exit receipt |
| (e2) 64 concurrent link/unlink tasks | pass | 2 links and 2 unlinks answered 200; the row is absent afterwards, matching them |
| (e3) unlink mid-request | recorded | 5 × 200, 2 × 403, 1 × closed |
| (e4) node restart | recorded | the table is lost (404, 0 rows): not persisted until native Olog |
| (f) canary with no link | pass | listening, received nothing |
| (g) offline receipt verification | pass | 4,223/4,223 verified with the node's public key alone |

**Two harness defects, found only at scale, both of the kind "a pass that was not one".**

1. *(b) read "pass" on 19,162 of 50,000.* The sender was waited on for a fixed 900 s; at about
   20 requests per kind per second, 50,000 needs about 2,500 s. Nothing it sent failed, so the
   item passed. Fixed in `08f8c57fc`: the verdict counts what was sent, and a run that sent fewer
   than asked is inconclusive; the wait grows with the count. Test
   `a_run_that_sent_fewer_than_asked_is_not_a_pass`, red on the old rule with the run's numbers.
2. *(e1) failed and (e2) read "pass" with nothing linked.* The standing pods (pool, destination,
   canary) lived a fixed 3,600 s and the run took about 5,600 s, so by the chaos items the holder
   had exited: (e1)'s link was refused ("both pods must be running"), and (e2)'s 64 tasks all got
   409, which left the table "consistent" at 0 links done. Fixed in `b32cf4c91`: the lifetime
   grows with the run, and a race in which no link was made is inconclusive. Tests
   `standing_pods_outlive_a_full_scale_run` and `a_race_in_which_nothing_was_linked_is_not_a_pass`,
   both red on the old rules.

The run between them (`08f8c57fc`, 07:51–09:24) is the one that showed defect 2; its report and
this one are kept outside the repository with the earlier ones.

**Still not covered:** TLS over a link end to end (in-process tests only; this node has no pod
CA), links across trust domains (handler tests and `no_cross_tenant_link` only), persistence
across a restart (e4).

**VMs and cost.** Two throwaway spot VMs this day, both deleted by name and confirmed absent from
the instance list: the `n2-standard-16` above (07:11–12:52 UTC, both full-scale runs and mutation
run 1 and A) and an `n2-standard-32` for the remaining mutation runs (12:53–16:18 UTC). About 9
VM-hours. At an upper estimate of spot prices for these shapes, with two 150 GB standard disks,
that is under $5; with the earlier runs (under $1), well under the $10 ceiling. The figure is an
estimate from list prices: the job's credential cannot read billing.

### The gauntlet's own verdicts, given a meaning and bound (2026-11-20, commit `b779afac4`)

The owner ruled (2026-11-20) that the harness's pass/fail rules are decisions like any other
and are bound in `proof-obligations.toml`. The case for it is in this section's runs: three
times an item read "pass" when it had not observed what it claims, and each time the rule was
the defect.

- **Meaning first:** `crates/portcullis-core/lean/GauntletVerdict.lean`, plain Lean like
  `DecisionChannel.lean`. One shape decides every judged item, `judge bad enough`: bad fails;
  otherwise enough passes; otherwise inconclusive. Each item states its own "bad" and "enough".
  Theorems: `judge_pass_iff`, `judge_never_recorded`, `a_failed_linked_request_fails` (the 503
  finding), `a_short_run_never_passes` (the 19,162 finding), `an_empty_race_never_passes` and
  `a_consistent_race_passes` (the (e2) finding, and that the rule is not vacuous the other way),
  `canary_pass_iff`, `reportFails_iff`, `standing_outlives_sender` (the expired-pods finding),
  `full_scale_fits`, and worked examples decided on each run's own numbers.
- **One decider:** `nucleus_ifc_kernel::extracted::gauntlet`, twelve functions over integers and
  booleans. The harness (`nucleus-cli`, `host_evidence_live::links`) calls them for every judged
  item, including `Report::failed`, the receipt item without a key, and an item whose setup
  failed. Its own copies of the rules are gone. `Recorded` stays an explicit choice for (e3) and
  (e4). The Welch t is reported and not judged, so it is no decision.
- **Extracted and proved:** Charon/Aeneas translate the slice with the other 61 roots (77/77
  functions transparent, no axioms) into `generated-link/`, as pure additions.
  `GauntletVerdictExtracted.lean` proves each function computes the model for every input, and
  `standing_lifetime` for every input whose lifetime fits a `u64`. There is no `sorry`, and
  `#print axioms` shows only `propext`, `Classical.choice` and `Quot.sound`. Twelve rows bind
  them; `cargo xtask proof-obligations` holds 101 rows (lean-extracted 73).
- **Driven red, each on the real defect:** the old (e2) rule (no `links_done == 0` case) in the
  slice fails `race_is_model`; the old (b) rule without the sent count fails
  `per_request_is_model`; a row naming `canary_is_model` for `race` fails the binding check
  ("does not mention … race in its statement"); and the two new Rust tests in the slice fail on
  the old (e2) rule and on a base lifetime without its three hours.
- **Found on the way:** the local Aeneas (`d71d2e3`) translates a comparison returned as a value
  (`… || undecided > 0`) into a `Prop` where a `Bool` is needed, and the generated file did not
  compile. The slice returns literals from each branch instead (clippy's `needless_bool` and
  `if_same_then_else` are allowed there, with the reason in a comment). The binding check also
  refused all twelve rows until a CI workflow builds the proof file: `aeneas-ifc-scoped.yml`
  now carries the twelve roots, the two `lake build`s and the no-`sorry` scan. That is a
  guardrail path, so it needs the owner's hardware-key approval with the other three.
- **Live, with the bound rules deciding (2026-11-20, 17:38–19:04 UTC):** the full-scale gauntlet
  on a third throwaway x86 spot VM at `b779afac4`, `cargo xtask links-live` with 10,000 ops and
  50,000 requests per kind, exit 0, "no item failed". (a) Pass, 10,000/10,000 ops (4,217 done,
  3,650 refused, 2,133 not found, 8 pods). (b) Pass, 50,000/50,000 linked delivered, 50,000
  unlinked refused, nothing failed, missing, leaked or undecided. (c) Pass. (d) Pass, 10,000
  probes, one status (404), one body, Welch t 0.87 (reported). (e1) Pass: link 200, cancel 409,
  drop receipt seen. (e2) Pass on 1 link, 1 unlink, no row, so the race made a link this time and
  the non-vacuous branch decided it. (f) Pass, 0 received, seen listening. (g) Pass, 4,223/4,223
  receipts verified. (e3) and (e4) Recorded, as ruled. The kernel tests (2), the harness tests
  (11) and clippy were clean on the VM first. Report: 5,442 bytes, SHA-256
  `c6cd24a3d28ba9d66d4a99ca42bc7ef46f612d82e8b5de18d361ec3dae47f3f5`, kept with the session's
  reports (not committed: it names pod ids of a deleted VM). The VM ran 17:26–19:06 UTC, about
  1.7 VM-hours, and was deleted by name and confirmed absent from the instance list. The day's
  estimate stays under $7 against the $10 ceiling, from list prices as above.
- **Again after the merge with main (2026-11-20, 20:32–21:57 UTC, commit `87454f79f`):**
  the same full-scale run on the branch merged with main (`159e31033`) plus its fixups, on a
  fourth throwaway x86 spot VM. Exit 0 and "no item failed", with the same numbers: (a)
  10,000/10,000 ops (4,217 done, 3,650 refused, 2,133 not found); (b) 50,000/50,000 delivered and
  50,000 refused, nothing failed, missing, leaked or undecided; (c), (d) (Welch t 0.85), (e1),
  (e2) (1 link, 1 unlink, no row), (f) and (g) (4,223/4,223) pass; (e3) and (e4) recorded. Report
  5,442 bytes, SHA-256 `4e39f252aadfa5a1c5d636361aeb7f0b3108b971d65bda4be759079ac6081797`. Before
  it, on a separate VM: `cargo fmt --check`; CI's `cargo clippy --workspace --all-targets
  --all-features -- -D warnings` (nucleus-verifier-service excluded: its build script needs the
  verifier-js wasm package CI builds first); 893 and 1,294 tests passing, none failing; and
  `cargo xtask proof-obligations` (105 rows). The merge found four places where main had added a
  check the branch did not yet meet, each fixed in the merge's fixups: the `NodeState` census (the
  link table is `TenantShared`), ADR 0016's TLS acceptor census (the E3 proxy acceptor is
  `ServerAuthOnly`), main's detached cancel (now `cancel_unlinked`, one task holding the link
  lock across teardown), and the guest-capability cycle. The two VMs ran about 2 hours together,
  were deleted by name and confirmed absent; the day's estimate is under $9.

### Every new test driven red (2026-11-20, commit `b32cf4c91`)

**Claim, and how it is checked.** Each of the 109 tests this branch adds (`#[test]` and
`#[tokio::test]` functions in `git diff 5e8f7c85a..b32cf4c91`; `pdeath_parent_helper` is a
helper the parent-death test re-executes, not a test) failed on at least one defect, and passed
without it. The defects are of three kinds:

- **Mutants** from `cargo-mutants` 27.1.0, run with `--in-diff` over the branch's changed lines,
  on the throwaway VMs. A test counts when a mutant's log has `test <name> ... FAILED`. Four runs:

  | run | scope | caught | missed | timeout | unviable |
  |---|---|---|---|---|---|
  | 1 | every changed crate (stopped at 367 of 552) | 171 | 51 | 63 | 76 |
  | A | tool-proxy relay, receipt, spec | 17 | 4 | 17 | 7 |
  | B | `nucleus-node` link, CA, egress files; its new tests only (stopped at 18 of 130) | 10 | 1 | 7 | 0 |
  | C | 26 mutants chosen for the 12 node tests still without one | 12 | 10 | 2 | 2 |

- **Hand mutants** (16 tests), where `cargo-mutants` cannot reach: the harness's helper tests
  are in a `cfg(test)` module it does not mutate; a mutant in one crate is tested only against
  that crate's tests (`link_name` is in the egress proxy, its test in the node); and for a few
  tests no listed mutant failed them. Each was applied with `perl`, checked to have changed the
  file, run with `cargo test --exact`, and the unmutated test was run first as a control. All 16
  failed at a panic and none at a compile error.
- **Recorded defects** (5 tests): the gauntlet's own numbers under the rule the test replaced.

**How specific the evidence is.** For each test the table names the mutant that failed the fewest
tests. 33 tests have a mutant that failed that test alone; the other mutation rows name one that
also failed between 2 and 11 tests. A broad mutant shows the test can fail, not that it isolates
its defect. Two hand mutants fail their tests by a panic rather than at the assertion the test
names: the receipt mutant makes a `Link` projection unserializable, so both receipt tests fail at
signing, and the tamper test is not shown catching a tamper; the outbound splice mutant fails by
a resumed future, not at the EOF assertion.

**What the runs also found.**

- *The `local-driver` feature hid 11 tests.* `link_proxy`'s and `pod_links`'s tests are
  `cfg(all(test, feature = "local-driver"))`. Run 1 and run B's first baseline built without the
  feature, so those tests did not exist, and every mutant in those files could only be missed or
  timed out against the rest of the node suite. Run C passed `--features local-driver`; its
  baseline listed 22 tests where the earlier one listed 11.
- *Missed mutants that are gaps in the tests, not in the red evidence.* Across the runs, 66
  mutants were missed. Among them: against the 12 tests run C ran, `permitted_names` returning an empty list,
  `["xyzzy"]` or `[""]`, or losing its `!`, `LinkProxy::shutdown` replaced with `()`, and both
  `start_for_pod`s returning `Ok(None)` are missed (run B, which ran the CA tests, timed out on
  the `permitted_names` mutants, so whether those tests catch them is not known); the egress proxy's `decision.rs` (3) and `main.rs` (3) mutants are missed, as are 9 in
  the kernel's `links.rs`. The full lists are in each run's `missed.txt`, kept outside the
  repository with the gauntlet reports. They are the next tests to write.
- *Timeouts are not catches.* A run's timeout was first the test suite being slow on a loaded
  host (the node's suite takes 61 s idle; its census walks took over 300 s under eight parallel
  builds), and then the first full workspace build in each job's copy exceeding 1,500 s. Neither
  says anything about the mutant; no test above relies on a timeout.
- *Run configuration took five attempts, none of them a defect in the code.* (1) `cargo install`
  ran outside the tree and found no toolchain; (2) the baseline failed six key-custody tests
  because the launching shell's umask was 002, so temporary key directories were group-writable
  and the node correctly refused them; (3) a 60 s timeout also applied to the baseline;
  (4) filtering on `workload_api_vsock` pulled in the census walks; (5) the missing feature above.
  Each was a run setting. The steps were passed to the VM as temporary command files in the
  session scratchpad, which is shell outside the repository; nothing here was added to it.

| crate file | test | defect it failed on |
|---|---|---|
| `nucleus-cli/src/host_evidence_live/links.rs` | `links_gauntlet` | the live runs: (b)/(f) inconclusive at `66ab86b9e`, (b) 63/200 at `98aee0d22`, (e1) fail at `08f8c57fc` |
| `nucleus-cli/src/host_evidence_live/links.rs` | `a_503_on_a_made_link_fails_item_b` | the x86 run-2 numbers (63 delivered, 137 × 503) under the old rule |
| `nucleus-cli/src/host_evidence_live/links.rs` | `a_run_that_sent_fewer_than_asked_is_not_a_pass` | the full-scale run's numbers (19,162 of 50,000) under the old rule |
| `nucleus-cli/src/host_evidence_live/links.rs` | `a_race_in_which_nothing_was_linked_is_not_a_pass` | the old (e2) rule passed `links_done = 0` |
| `nucleus-cli/src/host_evidence_live/links.rs` | `standing_pods_outlive_a_full_scale_run` | the old fixed 3,600 s lifetime |
| `nucleus-cli/src/host_evidence_live/links.rs` | `a_canary_passes_only_when_seen_listening_and_untouched` | hand: canary passes when *not* listening |
| `nucleus-cli/src/host_evidence_live/links.rs` | `a_faithful_node_passes_and_the_mix_covers_every_answer` | hand: a refused unlink expected as 409, not 404 |
| `nucleus-cli/src/host_evidence_live/links.rs` | `one_flipped_node_answer_is_caught` | hand: `mismatches` filters every step out |
| `nucleus-cli/src/host_evidence_live/links.rs` | `the_api_mapping_is_pod_links` | hand: a refused unlink expected as 409, not 404 |
| `nucleus-cli/src/host_evidence_live/links.rs` | `welch_t_is_zero_for_equal_samples_and_large_for_shifted` | hand: `welch_t` sign flipped |
| `nucleus-cli/src/host_evidence_live/links.rs` | `the_report_fails_only_on_a_fail` | hand: `Report::failed` true on any non-pass |
| `nucleus-cli/src/host_evidence_live/links.rs` | `received_reads_ids_and_ports` | hand: `received` keeps only empty ids |
| `nucleus-egress-proxy/src/link.rs` | `uuids_and_link_names_round_trip_in_one_spelling` | `crates/nucleus-egress-proxy/src/link.rs:112:5: replace uuid_string -> String with "xyzzy".into()` (fails 10 tests) |
| `nucleus-egress-proxy/src/link.rs` | `control_lines_parse_exactly` | `crates/nucleus-egress-proxy/src/link.rs:212:9: delete match arm "LINK" in parse_control` (fails 1 test) |
| `nucleus-egress-proxy/src/link.rs` | `sever_signals_every_receiver_and_drops_the_route` | `crates/nucleus-egress-proxy/src/link.rs:257:9: replace Links::apply with ()` (fails 7 tests) |
| `nucleus-egress-proxy/src/link.rs` | `a_bad_control_line_severs_everything` | `crates/nucleus-egress-proxy/src/link.rs:280:9: replace Links::sever_all with ()` (fails 2 tests) |
| `nucleus-egress-proxy/src/serve_link_tests.rs` | `an_admitted_request_is_delivered_with_the_preamble` | `crates/nucleus-egress-proxy/src/serve.rs:673:31: replace == with != in upstream_request` (fails 3 tests) |
| `nucleus-egress-proxy/src/serve_link_tests.rs` | `a_denied_request_never_reaches_the_destination` | `crates/nucleus-egress-proxy/src/link.rs:365:5: replace deliverable -> bool with true` (fails 2 tests) |
| `nucleus-egress-proxy/src/serve_link_tests.rs` | `a_request_on_a_link_that_is_not_live_is_never_connected` | `crates/nucleus-egress-proxy/src/serve.rs:317:9: replace Proxy<D, R>::deliver_link -> Result<(), Refusal> with Ok(())` (fails 8 tests) |
| `nucleus-egress-proxy/src/serve_link_tests.rs` | `sever_closes_live_connections` | `crates/nucleus-egress-proxy/src/serve.rs:455:5: replace until_severed with ()` (fails 6 tests) |
| `nucleus-egress-proxy/src/serve_link_tests.rs` | `a_broken_control_channel_severs_live_connections` | `crates/nucleus-egress-proxy/src/link.rs:280:9: replace Links::sever_all with ()` (fails 2 tests) |
| `nucleus-egress-proxy/src/serve_link_tests.rs` | `tls_over_a_link_is_terminated_and_delivered` | `crates/nucleus-egress-proxy/src/link.rs:299:9: replace Links::has_dst -> bool with false` (fails 2 tests) |
| `nucleus-egress-proxy/src/serve_link_tests.rs` | `smuggling_shapes_are_refused_before_anything_is_connected` | `crates/nucleus-egress-proxy/src/serve.rs:620:5: replace read_body -> Result<Vec<u8>, Refusal> with Ok(vec![])` (fails 2 tests) |
| `nucleus-egress-proxy/src/serve_link_tests.rs` | `the_link_proxy_refuses_a_name_that_is_not_a_link` | `crates/nucleus-egress-proxy/src/link.rs:127:5: replace link_dst -> Option<u128> with Some(0)` (fails 16 tests) |
| `nucleus-egress-proxy/src/serve_link_tests.rs` | `the_egress_proxy_refuses_a_link_name` | `crates/nucleus-egress-proxy/src/refusal.rs:191:9: replace Refusal::code -> &'static str with ""` (fails 8 tests) |
| `nucleus-egress-proxy/src/serve_link_tests.rs` | `tls_to_an_unannounced_link_name_gets_no_leaf` | `crates/nucleus-egress-proxy/src/link.rs:299:9: replace Links::has_dst -> bool with true` (fails 1 test) |
| `nucleus-egress-proxy/src/serve_link_tests.rs` | `a_ca_without_the_link_subtree_is_refused_for_link_mode` | `crates/nucleus-egress-proxy/src/tls.rs:197:9: replace PodCa::permits_subtree -> bool with true` (fails 1 test) |
| `nucleus-egress-proxy/src/serve_link_tests.rs` | `tls_over_a_link_uses_the_connect_port` | `crates/nucleus-egress-proxy/src/link.rs:299:9: replace Links::has_dst -> bool with false` (fails 2 tests) |
| `nucleus-egress-proxy/src/serve_link_tests.rs` | `a_slow_answer_refuses_one_request_and_the_link_keeps_working` | `crates/nucleus-egress-proxy/src/link.rs:365:5: replace deliverable -> bool with true` (fails 2 tests) |
| `nucleus-egress-proxy/src/serve_link_tests.rs` | `a_destination_that_never_closes_releases_the_slot_after_the_deadline` | `crates/nucleus-egress-proxy/src/link.rs:365:5: replace deliverable -> bool with false` (fails 6 tests) |
| `nucleus-egress-proxy/src/serve_link_tests.rs` | `one_hundred_fifty_sequential_link_requests_are_all_delivered` | `crates/nucleus-egress-proxy/src/link.rs:365:5: replace deliverable -> bool with false` (fails 6 tests) |
| `nucleus-egress-proxy/src/serve_tests.rs` | `a_late_answer_is_dropped_and_the_channel_recovers` | `crates/nucleus-egress-proxy/src/request.rs:121:9: replace Scheme::as_str -> &'static str with ""` (fails 11 tests) |
| `nucleus-egress-proxy/src/serve_tests.rs` | `an_answer_with_an_unissued_number_poisons` | `crates/nucleus-egress-proxy/src/request.rs:121:9: replace Scheme::as_str -> &'static str with ""` (fails 11 tests) |
| `nucleus-egress-proxy/src/serve_tests.rs` | `a_node_owing_more_than_the_cap_poisons` | `crates/nucleus-egress-proxy/src/request.rs:121:9: replace Scheme::as_str -> &'static str with ""` (fails 11 tests) |
| `nucleus-egress-proxy/src/serve_tls_tests.rs` | `a_permitted_name_is_decided` | `crates/nucleus-egress-proxy/src/tls.rs:277:9: replace LeafMinter::minted -> usize with 0` (fails 1 test) |
| `nucleus-egress-proxy/src/serve_tls_tests.rs` | `a_name_outside_the_constraints_is_refused_and_no_leaf_is_minted` | `crates/nucleus-egress-proxy/src/tls.rs:188:9: replace PodCa::name_permitted -> bool with true` (fails 3 tests) |
| `nucleus-egress-proxy/src/serve_tls_tests.rs` | `a_client_trusting_another_ca_is_refused_and_recorded` | `crates/nucleus-egress-proxy/src/serve.rs:161:9: replace Proxy<D, R>::tls_journal -> Vec<TlsRecord> with vec![]` (fails 7 tests) |
| `nucleus-egress-proxy/src/serve_tls_tests.rs` | `sni_and_host_that_differ_are_fronting` | `crates/nucleus-egress-proxy/src/serve.rs:430:65: replace && with || in Proxy<D, R>::tunnel` (fails 1 test) |
| `nucleus-egress-proxy/src/serve_tls_tests.rs` | `a_connect_authority_that_differs_from_the_tls_name_is_fronting` | `crates/nucleus-egress-proxy/src/request.rs:330:8: delete ! in parse_origin_form` (fails 5 tests) |
| `nucleus-egress-proxy/src/serve_tls_tests.rs` | `an_expired_ca_is_refused` | `crates/nucleus-egress-proxy/src/tls.rs:241:5: replace now_unix -> u64 with 0` (fails 1 test) |
| `nucleus-egress-proxy/src/serve_tls_tests.rs` | `an_h2_only_client_gets_no_h2` | `crates/nucleus-egress-proxy/src/request.rs:258:62: replace != with == in parse_connect_head` (fails 10 tests) |
| `nucleus-egress-proxy/src/serve_tls_tests.rs` | `a_connect_that_does_not_speak_tls_is_refused` | `crates/nucleus-egress-proxy/src/request.rs:239:20: replace != with == in parse_connect_head` (fails 11 tests) |
| `nucleus-egress-proxy/src/serve_tls_tests.rs` | `without_a_ca_connect_is_refused_as_before` | `crates/nucleus-egress-proxy/src/serve.rs:214:9: replace Proxy<D, R>::handle -> Result<(), Stop> with Ok(())` (fails 30 tests) |
| `nucleus-egress-proxy/src/serve_tls_tests.rs` | `the_upstream_client_verifies_roots_and_name` | `crates/nucleus-egress-proxy/src/tls.rs:105:5: replace take -> Option<&'a[u8]> with None` (fails 16 tests) |
| `nucleus-egress-proxy/src/tls.rs` | `a_bundle_round_trips_and_its_facts_come_from_the_certificate` | `crates/nucleus-egress-proxy/src/tls.rs:176:9: replace PodCa::permitted -> &[String] with Vec::leak(Vec::new())` (fails 1 test) |
| `nucleus-egress-proxy/src/tls.rs` | `read_bundle_takes_exactly_the_bundle_from_the_channel` | `crates/nucleus-egress-proxy/src/tls.rs:212:12: replace != with == in read_bundle` (fails 1 test) |
| `nucleus-egress-proxy/src/tls.rs` | `read_bundle_refuses_a_short_a_wrong_or_an_oversized_channel` | `crates/nucleus-egress-proxy/src/tls.rs:210:5: replace read_bundle -> Result<Vec<u8>, CaError> with Ok(vec![])` (fails 2 tests) |
| `nucleus-egress-proxy/src/tls.rs` | `a_ca_that_would_vouch_for_any_name_is_refused` | `crates/nucleus-egress-proxy/src/tls.rs:105:5: replace take -> Option<&'a[u8]> with None` (fails 16 tests) |
| `nucleus-guest-init/src/egress_trust.rs` | `the_pod_ca_is_appended_to_the_guest_roots` | `crates/nucleus-guest-init/src/egress_trust.rs:57:39: replace == with != in checked_ca` (fails 2 tests) |
| `nucleus-guest-init/src/egress_trust.rs` | `without_guest_roots_the_bundle_is_the_pod_ca` | `crates/nucleus-guest-init/src/egress_trust.rs:57:39: replace == with != in checked_ca` (fails 2 tests) |
| `nucleus-guest-init/src/egress_trust.rs` | `a_reply_carrying_a_key_is_refused` | `crates/nucleus-guest-init/src/egress_trust.rs:51:5: replace checked_ca -> Result<&str, TrustError> with Ok("")` (fails 4 tests) |
| `nucleus-guest-init/src/egress_trust.rs` | `anything_but_one_certificate_is_refused` | `crates/nucleus-guest-init/src/egress_trust.rs:56:9: replace && with || in checked_ca` (fails 1 test) |
| `nucleus-guest-init/src/identity.rs` | `the_certificate_reply_is_the_pem_and_an_error_is_none` | `crates/nucleus-guest-init/src/identity.rs:642:5: replace parse_egress_ca -> Result<Option<String>, FetchError> with Ok(None)` (fails 1 test) |
| `nucleus-ifc-kernel/src/extracted/decision.rs` | `an_answer_applies_only_to_its_own_request` | hand: `disposition` inverts `is_owed` |
| `nucleus-ifc-kernel/src/extracted/decision.rs` | `a_deadline_poisons_only_a_broken_peer` | `crates/nucleus-ifc-kernel/src/extracted/decision.rs:49:23: replace || with && in on_deadline` (fails 1 test) |
| `nucleus-ifc-kernel/src/extracted/link.rs` | `every_guard_of_may_link_refuses_alone` | `crates/nucleus-ifc-kernel/src/extracted/link.rs:60:17: replace && with || in may_link` (fails 3 tests) |
| `nucleus-ifc-kernel/src/extracted/link.rs` | `a_link_matches_only_its_own_row` | `crates/nucleus-ifc-kernel/src/extracted/link.rs:38:21: replace && with || in link_matches` (fails 2 tests) |
| `nucleus-ifc-kernel/src/extracted/link.rs` | `names_is_either_end` | `crates/nucleus-ifc-kernel/src/extracted/link.rs:43:5: replace names -> bool with true` (fails 1 test) |
| `nucleus-ifc-kernel/src/extracted/link.rs` | `cancel_unlink_and_delivery_guards` | `crates/nucleus-ifc-kernel/src/extracted/link.rs:66:13: replace && with || in may_unlink` (fails 1 test) |
| `nucleus-ifc-kernel/src/extracted/tls.rs` | `each_refusal_fires_alone_and_in_order` | `crates/nucleus-ifc-kernel/src/extracted/tls.rs:42:17: replace || with && in tls_verdict` (fails 1 test) |
| `nucleus-ifc-kernel/src/extracted/tls.rs` | `a_leaf_needs_a_live_ca_and_a_permitted_name` | `crates/nucleus-ifc-kernel/src/extracted/tls.rs:61:13: replace && with || in may_issue_leaf` (fails 1 test) |
| `nucleus-ifc-kernel/src/links.rs` | `no_cross_tenant_link` | `crates/nucleus-ifc-kernel/src/links.rs:128:54: replace == with != in LinkTable::manages` (fails 1 test) |
| `nucleus-ifc-kernel/src/links.rs` | `connect_only_along_links` | `crates/nucleus-ifc-kernel/src/links.rs:247:9: replace LinkTable::invariant_holds -> bool with false` (fails 3 tests) |
| `nucleus-ifc-kernel/src/links.rs` | `unlink_severs` | `crates/nucleus-ifc-kernel/src/links.rs:171:35: delete ! in LinkTable::unlink` (fails 1 test) |
| `nucleus-ifc-kernel/src/links.rs` | `request_is_a_decision` | `crates/nucleus-ifc-kernel/src/extracted/link.rs:79:21: replace && with || in may_deliver` (fails 2 tests) |
| `nucleus-ifc-kernel/src/links.rs` | `cancel_refuses_linked_and_exit_drops_links` | `crates/nucleus-ifc-kernel/src/links.rs:231:9: replace LinkTable::exit -> Vec<Receipt> with vec![]` (fails 1 test) |
| `nucleus-ifc-kernel/src/links.rs` | `close_removes` | `crates/nucleus-ifc-kernel/src/links.rs:210:38: replace != with == in LinkTable::close` (fails 1 test) |
| `nucleus-ifc-kernel/src/links.rs` | `step_inv` | `crates/nucleus-ifc-kernel/src/extracted/link.rs:38:21: replace && with || in link_matches` (fails 2 tests) |
| `nucleus-link-probe/src/lib.rs` | `a_report_round_trips_through_a_noisy_console` | `crates/nucleus-link-probe/src/lib.rs:84:5: replace line -> String with String::new()` (fails 2 tests) |
| `nucleus-link-probe/src/lib.rs` | `listening_round_trips_through_a_noisy_console` | `crates/nucleus-link-probe/src/lib.rs:84:5: replace line -> String with String::new()` (fails 2 tests) |
| `nucleus-link-probe/src/lib.rs` | `ids_are_distinct_and_seeded` | `crates/nucleus-link-probe/src/lib.rs:104:5: replace request_id -> String with String::new()` (fails 1 test) |
| `nucleus-link-probe/src/lib.rs` | `status_and_head_parse` | `crates/nucleus-link-probe/src/lib.rs:120:5: replace status_of -> Option<u16> with None` (fails 1 test) |
| `nucleus-node/src/egress_proxy_tests.rs` | `https_hosts_are_the_https_routes_only` | `crates/nucleus-node/src/egress_proxy.rs:253:9: replace EgressRoutes::https_hosts -> Vec<String> with vec![]` (fails 1 test) |
| `nucleus-node/src/egress_proxy_tests.rs` | `a_confined_child_dies_with_its_spawner` | hand: signal 0 in place of `SIGKILL` |
| `nucleus-node/src/link_proxy_tests.rs` | `a_request_over_a_made_link_is_decided_by_the_table_and_delivered` | `crates/nucleus-node/src/pod_ca.rs:106:17: replace && with || in dns_name` (fails 2 tests) |
| `nucleus-node/src/link_proxy_tests.rs` | `a_link_not_in_the_table_is_refused_by_the_node_and_nothing_is_connected` | `crates/nucleus-node/src/link_proxy.rs:231:26: replace match guard links.has_row(row) with true in LinkDecider::step` (fails 1 test) |
| `nucleus-node/src/link_proxy_tests.rs` | `unlink_severs_a_live_connection_through_the_control_socket` | `crates/nucleus-node/src/pod_links.rs:152:9: replace Links::sever with ()` (fails 2 tests) |
| `nucleus-node/src/link_proxy_tests.rs` | `a_link_port_outside_tcp_is_refused_before_any_control_line` | hand: port check `&&` for `\|\|` |
| `nucleus-node/src/link_proxy_tests.rs` | `the_ca_arrives_on_the_channel_and_tls_admits_only_announced_links` | `crates/nucleus-node/src/pod_ca.rs:103:13: delete ! in dns_name` (fails 8 tests) |
| `nucleus-node/src/link_proxy_tests.rs` | `many_requests_over_a_link_leave_no_connection_open` | `C:crates__nucleus-node__src__link_proxy.rs_line_231_col_26_001` (fails 2 tests) |
| `nucleus-node/src/link_proxy_tests.rs` | `the_proxy_dials_the_nodes_forwarder_never_the_destination_jail` | `crates/nucleus-node/src/link_proxy.rs:176:9: replace <impl Drop for Forwarder>::drop with ()` (fails 1 test) |
| `nucleus-node/src/link_proxy_tests.rs` | `a_forwarder_path_under_the_vsock_prefix_is_refused` | hand: the vsock-prefix refusal removed |
| `nucleus-node/src/pod_ca_tests.rs` | `constraints_are_exactly_the_https_hosts_and_the_link_subtree` | `crates/nucleus-node/src/pod_ca.rs:103:13: delete ! in dns_name` (fails 8 tests) |
| `nucleus-node/src/pod_ca_tests.rs` | `no_https_hosts_still_constrains_to_the_link_namespace` | `crates/nucleus-node/src/pod_ca.rs:103:13: delete ! in dns_name` (fails 8 tests) |
| `nucleus-node/src/pod_ca_tests.rs` | `a_host_that_is_not_a_dns_name_is_refused` | `crates/nucleus-node/src/pod_ca.rs:104:17: replace && with || in dns_name` (fails 1 test) |
| `nucleus-node/src/pod_ca_tests.rs` | `not_after_is_no_later_than_the_pod_deadline` | `crates/nucleus-node/src/pod_ca.rs:103:13: delete ! in dns_name` (fails 8 tests) |
| `nucleus-node/src/pod_ca_tests.rs` | `a_deadline_past_the_clock_is_refused` | `crates/nucleus-node/src/pod_ca.rs:103:13: delete ! in dns_name` (fails 8 tests) |
| `nucleus-node/src/pod_ca_tests.rs` | `link_names_live_under_the_link_subtree` | hand: `link_name` drops the `.link.nucleus.invalid` suffix |
| `nucleus-node/src/pod_ca_tests.rs` | `the_handover_is_the_bundle_the_proxy_parses` | `crates/nucleus-node/src/pod_ca.rs:103:13: delete ! in dns_name` (fails 8 tests) |
| `nucleus-node/src/pod_ca_tests.rs` | `the_guest_sees_the_certificate_and_never_the_key` | `crates/nucleus-node/src/pod_ca.rs:103:13: delete ! in dns_name` (fails 8 tests) |
| `nucleus-node/src/pod_links.rs` | `link_list_unlink_with_verifying_receipts` | `crates/nucleus-node/src/pod_links.rs:267:8: delete ! in link_pods` (fails 6 tests) |
| `nucleus-node/src/pod_links.rs` | `no_cross_tenant_link` | `crates/nucleus-ifc-kernel/src/links.rs:128:54: replace == with != in LinkTable::manages` (fails 1 test) |
| `nucleus-node/src/pod_links.rs` | `cancel_of_a_linked_pod_is_refused` | `crates/nucleus-node/src/pod_links.rs:358:5: replace cancel_unlinked -> Result<(), ApiError> with Ok(())` (fails 1 test) |
| `nucleus-node/src/pod_links.rs` | `exit_drops_links_with_a_receipt_for_the_survivor` | `crates/nucleus-node/src/pod_links.rs:389:5: replace pod_gone with ()` (fails 1 test) |
| `nucleus-node/src/spec_posture_tests.rs` | `the_link_relay_port_is_the_runtimes` | `crates/nucleus-node/src/spec_posture.rs:171:5: replace admit -> Result<Option<AuditTarget>, PostureRefused> with Ok(None)` (fails 1 test) |
| `nucleus-node/src/workload_api_vsock.rs` | `the_guest_fetch_returns_the_certificate_only` | `crates/nucleus-node/src/pod_ca.rs:103:13: delete ! in dns_name` (fails 8 tests) |
| `nucleus-receipt/src/lib.rs` | `a_link_receipt_verifies` | hand: `Projection::Link` not serializable (fails at signing) |
| `nucleus-receipt/src/lib.rs` | `a_tampered_link_body_fails_verify` | hand: `Projection::Link` not serializable (fails at signing, not at the tamper) |
| `nucleus-receipt/src/lib.rs` | `a_link_projection_round_trips_with_its_kind` | `crates/nucleus-receipt/src/lib.rs:129:9: replace Projection::kind -> &'static str with ""` (fails 2 tests) |
| `nucleus-tool-proxy/src/link_relay.rs` | `the_preamble_is_exactly_port_n` | `crates/nucleus-tool-proxy/src/link_relay.rs:75:26: replace || with && in parse_preamble` (fails 1 test) |
| `nucleus-tool-proxy/src/link_relay.rs` | `a_port_outside_the_range_is_refused` | `crates/nucleus-tool-proxy/src/link_relay.rs:80:20: replace >= with < in parse_preamble` (fails 2 tests) |
| `nucleus-tool-proxy/src/link_relay.rs` | `a_non_host_peer_is_refused_and_reaches_nothing` | `crates/nucleus-tool-proxy/src/link_relay.rs:219:5: replace handle_inbound -> Result<(), InboundRefusal> with Ok(())` (fails 2 tests) |
| `nucleus-tool-proxy/src/link_relay.rs` | `a_malformed_or_out_of_range_preamble_is_refused` | `crates/nucleus-tool-proxy/src/link_relay.rs:93:33: replace + with - in read_preamble` (fails 1 test) |
| `nucleus-tool-proxy/src/link_relay.rs` | `inbound_bytes_are_spliced_both_ways_after_the_preamble` | `crates/nucleus-tool-proxy/src/link_relay.rs:88:5: replace read_preamble -> Result<u16, InboundRefusal> with Ok(0)` (fails 1 test) |
| `nucleus-tool-proxy/src/link_relay.rs` | `a_closed_host_side_closes_the_workload_side` | hand: outbound splice no longer ends on the host's close (panics on resume) |
| `nucleus-tool-proxy/src/link_relay.rs` | `a_workload_half_close_still_gets_the_answer` | `crates/nucleus-tool-proxy/src/link_relay.rs:111:5: replace splice with ()` (fails 2 tests) |
| `nucleus-tool-proxy/src/link_relay.rs` | `a_server_that_answers_and_closes_ends_the_inbound_exchange` | `crates/nucleus-tool-proxy/src/link_relay.rs:148:5: replace splice_inbound with ()` (fails 2 tests) |
| `nucleus-tool-proxy/src/link_relay.rs` | `a_closed_host_side_closes_the_inbound_workload_side` | hand: inbound splice waits for both directions (5 s timeout) |
| `nucleus-tool-proxy/src/link_relay.rs` | `outbound_bytes_are_spliced_both_ways` | `crates/nucleus-tool-proxy/src/link_relay.rs:174:5: replace serve_outbound with ()` (fails 1 test) |

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
