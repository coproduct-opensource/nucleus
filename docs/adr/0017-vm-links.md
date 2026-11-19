# ADR 0017 — Links between pods: a connection from one pod to another is a host decision, made per connection

- Status: **proposed** (2026-11-19). Design only: this record moves no enforcement and adds
  no route. Nothing below runs until the owner accepts it, and the first implementation
  step is L1 below. The semantics are written first, in
  `crates/portcullis-core/lean/LinkTable.lean` (same change), and the implementation is
  built to that meaning.
- Owner decisions already taken (2026-11-19), each the strongest option considered:
  - **Transport:** a host relay over vsock (§1). The runner-up was IP routing between pod
    namespaces.
  - **Unlink:** it severs every live connection on the link before its receipt is signed
    (§3). The runner-up was to drain existing connections and refuse new ones.
  - **Exit:** an exit the node did not request (a crash, a timeout, the reaper) drops the
    pod's links and signs a receipt for each. A cancel through the API is refused while a
    link names the pod (§4). The runner-up was to leave links dangling.
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
- The decision is per connection, at connect time. It is taken by the host, from host
  state, and never by either guest (ADR 0014).

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
| `POST /v1/pods/{src}/links` with `{dst, port}` | `Operation::LinkPods` | 201 with the link id and the signed receipt; 404 or 409 as in §2 |
| `DELETE /v1/pods/{src}/links/{id}` | `Operation::UnlinkPods` | 200 with the signed receipt, after severing |
| `GET /v1/pods/{src}/links` | `Operation::ListPodLinks` | the rows whose source is `src`, filtered by scope |

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
- the transitions `link`, `unlink`, `connect`, `cancel` and `exit`, each with its receipt.

| theorem | what it states |
|---|---|
| `connect_only_along_links` | a connection exists only while its link is in the table |
| `unlink_severs` | after `unlink l`, no live connection is carried by `l` |
| `no_cross_tenant_link` | `link` is admitted only when the caller manages both pods and they share a trust domain |
| `cancel_refuses_linked` | a cancel through the API never removes a pod that a link names |
| `exit_drops_links` | after an exit, no row names the exited pod |
| `receipts_replay_links` | replaying the receipts onto the prior table gives the table afterwards |
| `noninterference_unlinked` | a pod with no link from `p` is unaffected by `p` |

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
- **Eval cells:** `PodLink` is `NotServed` for eval cells in v1. ADR 0015 promises that every
  byte leaving an eval cell is a request the host decided. A link decides per connection,
  not per request, so serving it to an eval cell would weaken that promise. That needs its
  own owner decision.

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
| L4 | the routes, the teardown step, and the guest relays behind their capability rows | yes: links become possible |
| L5 | measurement on a node (§9); C2's artifact list updated | no |

## Consequences

- Accepting this record changes no pod's behaviour. Until L4, no link can exist.
- After L4, a linked pair can open connections to the linked port and nothing else. Every
  connection is decided by the host at connect time. Every pair that is not linked keeps
  today's five layers, untouched.
- The relay is new TCB, on the host and in both guests. Its compromise is bounded to the
  links it carries. Its admit function is the proved part.
- A cancel of a linked pod now fails with 409 until the links go. A controller unlinks
  first. That is its plan's diff, stated rather than implied.

## What this does not claim

- That the shipped relay matches `LinkTable.lean`. That is L3's extraction and proof
  obligation. Until then the theorems are about a model.
- C2. It stays NOT-YET. This record narrows C2's statement to unlinked pairs. It does not
  prove the restated C2 against the running node.
- Any figure for throughput, latency or memory (§9).
- Links across nodes, links between tenants, or links for eval cells. Each is out of v1, and
  each needs a decision of its own.
