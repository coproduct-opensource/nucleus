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
