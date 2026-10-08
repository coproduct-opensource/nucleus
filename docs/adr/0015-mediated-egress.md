# ADR 0015 — Mediated egress: every byte that leaves an eval cell is a request the host decided

- Status: **proposed** (2026-10-08). Design and measurement only: this record moves no
  enforcement. The first implementation step is E1 below.
- Tracks: milestone M4 of the eval-cell programme; issue #2698 (Q-3, its network half) and
  the second half of #2702 (L-1). ADR 0014 §12 leaves mediated-set rows 5, 6 and 10 to
  this record.
- Rests on: [ADR 0013](0013-eval-cell.md) (the adversary holds root in its guest),
  [ADR 0014](0014-the-host-decides.md) (the host's pod policy is the one decider; no
  answer is a denial; eval-cell requirements switch on in the PR that adds them),
  [ADR 0010](0010-a-credential-minted-per-exchange-never-stored.md) (the operator owns the
  upstream registry; a credential is minted per exchange on the host),
  [ADR 0007](0007-make-the-defect-unwritable.md) (rule ids cited below).
- Owner rule applied on every fork: recommend the **strongest** option, name its
  availability cost, and show the weaker option only as the runner-up with the reason it
  is weaker.

## Context

ADR 0014 splits effects into three classes. Class **N** is network traffic that leaves the
pod's namespace without the host performing it: in-shell egress (`curl`, `/dev/tcp`,
`nc`, a library's socket), DNS, and raw sockets. These are mediated-set rows 5, 6 and 10,
and today all three are `backstopped-only`. The only control is the per-pod netns chain
(`net::apply_host_policy`, `net::egress_chain`): an L3/L4 allowlist evaluated
first-match-wins over a DROP policy, which the Lean `EgressConfinement` theorem is stated
over.

Against guest root, that chain is the eval cell's only egress control. It is a real fence
for destinations nobody listed. For destinations somebody did list, it is not a decision
point:

- it sees addresses and ports, never a method, a path, a header or a body, so an agent
  can send anything to a listed address, including data it should not have sent;
- an L3 allowlist cannot tell two names on one address apart (mediated-set.md, "What the
  Workload column does not yet prove"), so a listed CDN address reaches every tenant
  behind it;
- credentialed egress is performed by the host (ADR 0010, `broker_perform`), but nothing
  stops guest root from also connecting directly to the listed address without the
  credential and without the decision;
- what comes back is never observed by the host, so the host's taint (ADR 0014 §3) learns
  nothing from it.

### What pods actually send today (measured)

Read with this PR's reader, `cargo xtask egress-census`, over the 21
`live-boot-evidence-x86_64` bundles that runs of `quickstart-boot.yml` uploaded between
2026-10-08T04:31Z (run 37727904973, `a6874fdf9`) and 2026-10-08T18:11Z (run
37822304144, `827394f5a`): 7 push, 7 merge-group and 7 pull-request runs, at 18
distinct commits. Nine further successful runs in the same window had no bundle to
download, and are not counted.

| | All 21 runs |
|---|---|
| Execution pod's profile | `standard` in 21 of 21. **No bundle holds an eval cell.** |
| Declared egress (execution pod) | `network.allow` 0 entries, `dns_allow` 0, credentialed upstreams 0, in every run. The spec carries `network: {allow: [], deny: []}`, so the pod gets a NIC, a netns and the default-deny chain with nothing on it. |
| Resolver the guest is told | `dns=1.1.1.1` (the node's `DEFAULT_DNS`) in 21 of 21, although no rule reaches it and no `dnsmasq` is started. |
| Direct connects from the guest | Exactly two destinations, both from `nucleus-egress-probe`: `1.1.1.1:443` and `8.8.8.8:53`, refused in 21 of 21 with `connection timed out`, which is the chain's DROP. Not one connect reached anything. |
| Adversary probe's exfil stage | `attempted=yes blocked=yes targets=2` in 21 of 21 (the stage does not name its targets). |
| Host-performed egress | One `web_fetch` per run (21 total), to `http://127.0.0.1:<port>`, the collector's plaintext loopback fixture, through the broker. |

**Could not measure**, and the reader prints each one on every run rather than reading
silence as zero (ADR 0007 A-2, A-5):

- **DNS queries.** No resolver is started without `dns_allow`, and `dnsmasq` is never
  started with query logging. Whether the guest sent any query at all is unrecorded.
- **Packets the fence dropped.** The chain has no counters or log target in the bundle
  (`snapshot_iptables` normalises counters away), so only the probe's own attempts are
  visible.
- **The credentialed pod's guest.** Its console is not in the bundle.
- **Eval cells.** None has ever been live-booted in CI, so nothing here is a measurement
  of an eval cell's traffic.
- **Latency and throughput** of any egress path. Nothing records them.

Two findings follow. First, the corpus contains **no permitted direct egress at all**:
everything the honest live boot sends either goes through the host (the broker) or is a
probe attempt that the fence drops. So moving rows 5, 6 and 10 behind a host proxy breaks
nothing that live boot exercises today. The flip side is that live boot also proves
nothing about the proxy's latency or about real upstream traffic. E1 adds that
measurement. Second, the mediated-set page said an off-allowlist connect "returns
`ENETUNREACH`". The evidence shows `connection timed out` in every run. Both are refusals,
but the page described a mechanism the bundle does not show. This PR corrects the page to
what the probe observes; the probe is unchanged.

## Decision

### 1. The path out: an eval cell has no NIC; its one way out is a vsock listener on the host

**Recommended: no network interface.** An eval cell's VMM is configured with no
`network-interfaces` entry, so no tap, bridge, veth or netns chain exists for it. Its
only way out is a new host listener, `VsockListener::EgressProxy` (vsock **1029**). The
host egress proxy serves that listener, one instance per pod (§7). Inside the guest, a
relay listens on loopback (`127.0.0.1:3128`) and forwards bytes to vsock 1029. The relay
is started by guest-init, so the workload keeps its seccomp denial of `AF_VSOCK`. The
workload's environment carries `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` pointing at the
relay. The guest is told no `dns=`.

- Rows 6 and 10 then have no path left to fence. The guest has no device that a packet
  could leave through, so a raw socket, ICMP, UDP, QUIC and a DNS query reach nothing at
  all, whatever guest root does.
- **This is host-verified.** The node writes the VMM's configuration itself
  (`firecracker_config::lower_network_interfaces`). For an eval cell it requires the
  lowered list to be empty, and it records that as admission evidence (C-2: the checker
  mints the evidence). The in-guest egress probe becomes defence in depth: its verdict is
  a guest's console line, and ADR 0013 does not count that as independent evidence.
- **It shrinks the TCB.** The VMM's virtio-net emulation, the host bridge, `br_netfilter`
  and the per-pod chain all leave the eval cell's attack surface.
- **Availability cost.** A tool that ignores proxy variables, or that resolves a name
  before it connects, fails inside an eval cell. Non-HTTP protocols (`git` over SSH, a
  database wire protocol, NTP) fail too. ADR 0013 rule 3 lets an eval cell list a bare
  address. Under M4 that entry is refused (§2), because an address is not something the
  proxy can decide on.

**Runner-up: keep the NIC, and let the netns admit only `gateway:proxy-port`.** This is
the shape #2702 and the plan describe, and it needs no new guest code for the path
itself. It is weaker for four reasons. Guest root still holds a device that emits
arbitrary frames to the host bridge (ARP, ICMP, UDP to the gateway, malformed TCP), and
the host still parses them in virtio-net and netfilter. The fence is still an iptables
chain that a node-side bug can open (`apply_default_deny` and `apply_host_policy` are two
code paths). "Every byte goes through the proxy" stays a property of a rule list instead
of the absence of a device. And the guest must still be told some resolver.

### 2. What the proxy decides, and on what

Every request the proxy receives becomes one decision by the host's pod policy, the same
`PodPolicy` that ADR 0014 makes the only decider (G-1). The proxy does not keep its own
ACL logic beside it.

- **The ACL is the operator's, never the caller's.** An eval cell may reach only upstreams
  named in the node's upstream registry (ADR 0010 §1: the operator owns the registry, and
  the spec only selects from it). Each registry entry gains `methods` and `paths` (globs
  over the path, matched after normalisation by the one function that already refuses
  traversal, `CredentialedEgressSpec::url_for_request`). A registry entry with no
  credential is allowed: it is a plain upstream. For an eval cell, `network.allow`,
  `network.url_allow` and `dns_allow` are refused by name once E6 lands. They are
  caller-written grants, and an address cannot be decided per request.
  - Availability cost: an operator has to register an upstream before any eval cell can
    reach it.
  - Runner-up: ACLs in the spec (`url_allow` extended with methods). It is weaker because
    the party being contained would write its own grant. The spec's ACL can only narrow a
    registry entry, never widen one.
- **Per request.** The proxy parses one HTTP/1.1 request and sends the node a canonical
  summary: method, normalised origin and path, header names, body length and a body
  hash. The node decides it on the ADR 0014 decision path. For an allow, it mints a
  decision id bound to a digest that the node computes from that summary (C-2). It then
  redeems the id by value before it answers the proxy (C-4; ADR 0014 §6's per-pod
  ledger). A credentialed upstream's credential is minted for that one exchange and
  handed to the proxy with the allow. The guest never sees it. Every decision, allow or
  refuse, is a record in the host journal (`host_decide/evidence.rs`) signed with the
  node's key.
- **The response is observed.** The proxy hands the node the response's status, media
  type and a body digest. The node raises the pod's taint with `observe_response`, as the
  broker already does. This is what lets ADR 0014 §3's host taint see in-shell traffic.
- **No answer is a denial** (ADR 0014 §7). If the node is unreachable, the 2 s decision
  deadline passes, the proxy is overloaded, or a summary does not parse, the request is
  refused, each with its own reason (I-3). There is no fallback to direct egress, because
  no path for one exists (§1).

### 3. DNS: the proxy resolves, and the guest has no resolver

**Recommended.** The proxy resolves the registry entry's host name on the host, from the
host's resolver. It resolves once per connection and connects to that address, refusing
any address in the node's deny floor (`NODE_DENY_FLOOR`, link-local and the pod pool),
loopback, or a private range unless the registry entry names it. That is the
DNS-rebinding defence. The guest gets no `dns=` and no resolver. For an eval cell,
`dnsmasq` is not started (it would not be anyway, since `dns_allow` is refused), so the
`pod_dns` listener does not exist for it. A client using a proxy never resolves the name
itself, because `CONNECT host:443` and absolute-form requests carry the name.

- Availability cost: tools that call `getaddrinfo` before honouring a proxy fail.
- **Runner-up:** keep a per-pod `dnsmasq` that answers registry names with the relay's
  address. It is weaker because it keeps a UDP and TCP parser on the host reachable from
  guest root, and a query name is still a channel to the host's log. It also needs a NIC,
  or a second vsock relay for DNS.

`dnsmasq` stays for **standard** pods. It goes away for them only when standard pods
migrate to the proxy, which needs the guest floor raised past the release that carries
§8's rows. That is an owner decision outside M4.

### 4. TLS: terminate, with a per-pod CA that only the host holds

**Recommended: terminate.** At admission the node mints a per-pod CA:

- ECDSA P-256 key;
- X.509 `nameConstraints` whose permitted subtrees are exactly the registry hosts the pod
  selected;
- valid for no longer than the pod's timeout.

The CA's private key goes only to that pod's proxy process (§7). It is never put in
`PodMaterial`, a workload-API reply or the guest's environment. The guest gets the CA
**certificate** only, and guest-init installs it into the guest's trust store
(`EgressProxyTrust`, §8). On `CONNECT host:443` the proxy completes TLS with the client
using a leaf certificate for `host`, minted on first use and cached for the pod. The leaf
offers ALPN `http/1.1` only. The proxy then reads requests in clear and decides each one
(§2). Toward the upstream the proxy is the TLS client: rustls, the webpki roots, and
hostname verification (B-6).

| | Terminate (recommended) | CONNECT with SNI ACL (runner-up) |
|---|---|---|
| Destination | the name, from SNI, cross-checked against the `Host` header | the SNI name only. Domain fronting (SNI ≠ `Host`) cannot be seen, and with ECH the SNI is not the name at all. |
| Method, path, headers | yes, per request | no |
| Request and response body | digest and length, per request; the response feeds host taint | no |
| Credential injection | yes, host-side, per exchange | impossible: the bytes are encrypted end to end |
| Per-request decision and journal | yes | one decision per tunnel, for its lifetime |
| TLSNotary hook (§10) | yes: the host is the TLS client | no |

**Certificate-pinned clients.** A client that pins the upstream's key, or ships its own
trust store, rejects the proxy's leaf. The handshake fails, and the proxy records a
refusal whose reason is `client_rejected_interception`, with the SNI name. That is the
outcome for an eval cell: **refused**, never tunnelled opaquely. The availability cost is
that pinned clients (some package managers, mobile SDKs, some vendor CLIs) do not work in
an eval cell unless they can be pointed at a trust store.

**Runner-up: CONNECT-only with SNI ACLs.** It needs no CA and no guest trust change, and
it works with pinned clients. It is weaker because the proxy sees a name and a byte
count, and nothing else. It cannot apply a method or path ACL, cannot inject a
credential, cannot observe a response for taint, and cannot tell domain fronting from an
honest request. Its verdict is "reachable", which is the L3 allowlist's verdict one layer
up.

**What is refused and what is opaque, for an eval cell:**

| Traffic | Outcome |
|---|---|
| HTTP/1.1, or HTTPS terminated by the proxy | decided per request |
| HTTP/2 from the guest | not offered (ALPN `http/1.1` only), so the guest-facing parser is HTTP/1.1 alone. Clients fall back. |
| `Upgrade` (WebSocket, h2c) | **refused.** After an upgrade the bytes are opaque frames that no request decision covers. |
| `CONNECT` whose first bytes are not a TLS ClientHello | **refused** (no raw TCP tunnels) |
| A pinned client | **refused** (the handshake fails), recorded with its reason |
| Raw TCP, UDP, ICMP, QUIC | no path (§1) |

Nothing is opaque. A future exception, for example an operator-registered opaque tunnel
for `git` over SSH, would be a new registry kind with its own ADR. It would read as
"opaque" in the journal, never as "decided".

### 5. Non-HTTP traffic: refused by default, with nothing to switch on

There is no non-HTTP egress for an eval cell in M4. Without a NIC, raw TCP, UDP and ICMP
have no path. Over the proxy, a CONNECT that is not TLS is refused (§4). Plain-HTTP
requests to a registry entry whose scheme is `http` are decided like HTTPS ones. A
registry entry cannot name a non-HTTP scheme: the registry parser refuses it, so the
refusal is a type and not a runtime branch (B-3).

### 6. The derived seccomp filter (#3285)

The derived class `SyscallClass::InetSocket` already denies `socket(AF_INET | AF_INET6)`
to workload children when `web_fetch` is `never` and the pod declares no egress
(`portcullis::seccomp_policy`, shipped in 2.7.0, required of every eval cell through
`WorkloadSyscallPolicy`). M4 keeps that rule and changes what "declares egress" reads for
an eval cell: the registry upstreams the pod selected, since `network.allow` and
`dns_allow` are refused for it. An eval cell with no upstream denies every inet socket to
its children. An eval cell with upstreams keeps `AF_INET`, and without a NIC the only
inet destination left is the guest's loopback, where the relay listens.

This filter is defence in depth, not TCB (ADR 0013): guest root is not under it. The
containment under guest root is §1's missing device and §2's host decision. The release
table remains the only check that a guest carries the filter (ADR 0013 rule 4).
**Runner-up:** use the filter as the egress control while keeping a NIC. Rejected,
because it is exactly the guest-side control the threat model discounts.

### 7. The proxy is now TCB: its hardening

The proxy is a service that guest root can reach, so it is the eval cell's answer to
ADR 0013's "zero-day in a reachable supporting proxy" row and also a new instance of it.
It is hardened accordingly.

| | Recommended |
|---|---|
| Language | Rust. TLS with rustls (no OpenSSL). HTTP with `hyper`, HTTP/1.1 server only toward the guest. No `unsafe` in the crate (`#![forbid(unsafe_code)]`). |
| Process | A separate binary, `nucleus-egress-proxy`, one process per eval cell, spawned by the node. **Not inside `nucleus-node`**, which holds the node's signing key, the federation key handle and every pod's state. |
| Privilege | The pod's unprivileged jailer uid, no capabilities, `no_new_privs`, its own seccomp filter verified active like the VMM's (fail-closed), Landlock with no filesystem access beyond its own socket, and cgroup limits on memory, pids and file descriptors. |
| Network | Its own network namespace. Outbound is allowed only to public addresses, behind the node's deny floor, so it cannot reach the node API on host loopback or any metadata service. |
| Secrets | The pod's CA key (per pod, dies with the pod), plus per-exchange credentials handed over with each allow (ADR 0010). No node key, and no other pod's anything. |
| Parser exposure | Toward the guest: the HTTP/1.1 request line and headers (8 KiB request line, 16 KiB of headers, 64 headers), a body streamed under the pod's egress byte budget, and a TLS server handshake. No HTTP/2, no WebSocket, no trailers, no proxy authentication. A `cargo fuzz` target over the guest-facing parser is part of E2's definition of done. |
| Talking to the node | One `socketpair`, framed by `nucleus-decision-protocol`'s existing total, bounded, canonical parser (E-1), never a new wire format. |

So a compromise of the proxy costs one pod's egress and that pod's current per-exchange
credential, which is the property `nucleus-tool-proxy/src/egress.rs` already argues for
("per-pod, and it must stay that way").

**Runner-up: run the proxy inside `nucleus-node`, reusing `broker_perform`.** It is fewer
moving parts, and the broker already performs credentialed HTTPS there. It is weaker
because a bug in a parser that guest root can reach would then run in the process that
holds the node's keys and every pod's policy. The credentialed broker path has that
exposure today, and E3 moves it onto the proxy too, so the broker's HTTP performer leaves
the node.

### 8. Pinned listener inventory (#3331)

`HostListener` gains `Vsock(VsockListener::EgressProxy)`, key `egress_proxy`, transport
`vsock:1029`, workload `filtered`, egress channel `in_shell_egress`. The workload reaches
it only through the guest's loopback relay, because its own `AF_VSOCK` stays denied. Its
port is written once, in `VsockListener::port`, and it is bound only through
`guest_socket::bind_guest_listener`. `every_vsock_listener_has_its_own_port` and
`documented_inventory_equals_the_enum` cover it unchanged.

The inventory also gains what each profile is served. That is one exhaustive function,
`HostListener::served(IsolationProfile) -> Served` (E-2, no `_` arm):

- for an eval cell, `pod_dns` and `allowlisted_egress` are `NotServed`;
- for a standard pod, `egress_proxy` is `NotServed` until standard pods migrate.

The table in `mediated-set.md` gains a column for it, and the parity test covers the
column. A node test asserts that the listeners the node actually builds for a pod equal
`served(profile)` (G-1: the inventory is the decider, never a second list).

### 9. Guest compatibility

The floor stays **2.4.0** and the pin stays **2.7.0**. The guest-side changes are new
`GuestCapability` rows. Each is `Demand::When(GuestUse::EvalCell)` and lands as
`FirstShipped::NotYet`, with the demand **switched on in the same PR that adds the row**
(ADR 0014 §9 as accepted). Until a release carries the rows, the node refuses every eval
cell by name, naming the missing row. An eval cell is never run on the NIC path while a
release is pending.

| Row | Step | What the guest does |
|---|---|---|
| `EgressRelay` | E4 | guest-init runs the loopback-to-vsock-1029 relay and gives the workload `HTTP(S)_PROXY`/`ALL_PROXY`. The tool-proxy's own `web_fetch` uses it too. |
| `EgressProxyTrust` | E4 | guest-init installs the per-pod CA certificate (fetched over the workload API) into the trust store and sets `SSL_CERT_FILE`. |
| `NicLessBoot` | E6, **only if needed** | guest-init and the egress probe boot and attest with no `nucleus.net`. E6 first boots 2.7.0 with no NIC and records what happens. The row is added only if that boot fails, and an unmeasured row is not added. |

Standard pods are unaffected. Moving them onto the proxy means raising the floor, which
is an owner decision outside M4.

### 10. Latency and throughput budget

| | Budget |
|---|---|
| Added per request on a reused connection, p50 | ≤ 2 ms (vsock and relay hop, plus the node decision: ADR 0014 §8 gives that ≤ 0.5 ms p50) |
| Added per request, p99 | ≤ 20 ms |
| First request to a new origin, extra | ≤ 30 ms (leaf mint plus the second TLS handshake) |
| Bulk download through the proxy | ≥ 100 MiB/s per pod |
| Concurrent connections per pod | 64; the 65th is refused with its own reason |
| Hard decision deadline | 2 s, then refused (ADR 0014 §7) |

**Not measured yet** (above: nothing records egress latency today). E1 and E2 measure it,
on the GCP builder and in live boot. A missed budget blocks E6. It never becomes a
fallback to direct egress, because there is no direct path to fall back to.

### 11. TLSNotary (#3325): an optional research hook, off the critical path

Because the proxy is the TLS client to every upstream, it holds TLSNotary's prover role
for every request an eval cell makes, not only credentialed ones. The hook is one
optional field on the host journal's outcome record, `presentation_sha256`. A record
without it reads **"not witnessed"**, never "verified" (A-2). No M4 step depends on it,
the latency budget above excludes it, and the designated-verifier question (who runs the
verifier, and why it is not the node operator) stays with #3325. Any contact with outside
parties about it is an owner decision.

### 12. ADR 0013's incident rows after M4

| Incident class | After M4 |
|---|---|
| Evaluation sandbox with live internet | **Answered under guest root** at E6. An eval cell has no NIC (host-verified from the VMM config the node wrote). Every request leaves through the host proxy, decided per request against the operator's registry, journaled, and refused when the host does not answer. The falsifier is E6's. |
| Zero-day in a reachable supporting proxy | The egress proxy is the reachable supporting proxy, hardened as §7 describes: one process per pod, unprivileged, sandboxed, no node keys, and a fuzzed HTTP/1.1-only guest-facing parser. Its own network namespace cannot reach the node API or a metadata address. Because the eval cell's registry names hosts only, another supporting service is reachable only if the operator registered it. **Status: answered by containment of the proxy, not by its absence.** A zero-day in the proxy costs one pod's egress. |

The other rows are unchanged by M4.

### 13. The mediated set after M4

`mediated` joins the status vocabulary: *every byte on this channel is a request the host
decided before it left, with a host-signed record.* The inventory gains a status per
profile, and a gate, `an_eval_cell_has_no_backstopped_row`, pins the eval-cell column.

| Row | Standard pod | Eval cell, after E6 |
|---|---|---|
| 5 in-shell egress | `backstopped-only` (unchanged) | `mediated`: the proxy, per request (§2) |
| 6 DNS | `backstopped-only` (unchanged) | `mediated`: only the proxy resolves, and only registry names (§3). The guest has no resolver and no NIC. |
| 10 netns raw socket | `backstopped-only` (unchanged) | `mediated`: no device. The only socket that leaves the guest is the relay's vsock to the proxy. |

The plan's M4 gate ("no backstopped rows") is met for the eval cell. It is not met for
standard pods, and this record does not claim it: migrating them is the floor decision
noted in §3 and §9.

### 14. Implementation sequence

Each step is one PR with a definition of done and an A-19 falsifier (ADR 0007 I-1): the
check is driven red on the real defect, with the old behaviour restored, and then green.
Falsifiers use honest traffic and the existing probes: `nucleus-egress-probe`, its
`NUCLEUS_EGRESS_PROBE_DENY_TARGETS`, and the escape lane (#3106's canary, with #3338's
verdict once it lands). **No step writes a new in-guest attack or escape probe.**

| Step | What lands | Definition of done | A-19 falsifier |
|---|---|---|---|
| **E0** (this PR) | This ADR. `cargo xtask egress-census`. | The table above comes from the reader, at the run ids named. | The reader's unit tests are driven red by restoring each defect it refuses: a missing file read as no egress, a reworded refusal read as a refusal, a reached destination overwritten by a later refusal line, an absent probe read as zero attempts, a torn journal line skipped (PR body). |
| **E1** Measurement | The live-boot collector adds the credentialed pod's console, a per-pod snapshot of the chain's packet counters taken before teardown, and a third, honest eval-cell pod (no egress). The census reads all three. | The reader reports dropped packets per run and one eval cell per run. | A bundle whose counter file is withheld reads as "could not measure" (exit 2), and red if it reads as zero drops. |
| **E2** Proxy process, host only | `nucleus-egress-proxy` (§7). `VsockListener::EgressProxy` and its row (§8). `HostListener::served`. The node spawns the proxy for an eval cell, with no guest using it yet. Decisions go through `PodPolicy` (§2). A fuzz target. | A host-side test sends a request over the vsock UDS: an in-registry request is decided, performed and journaled, and an off-registry one is refused with its reason. Latency and throughput are measured against §10. | With the `PodPolicy` call removed, the off-registry request is performed (red); restored, it is refused (green). `every_vsock_listener_has_its_own_port` reds on a port reused by the new variant. |
| **E3** TLS and credentials | The per-pod CA with name constraints, termination, and per-exchange credential injection. The broker's HTTP performer moves into the proxy. | `trust_boundary` row `EgressCaKeyNeverServed` holds. A credentialed upstream gets its header from the host, and the guest's request carries none. | Serve the CA key in `PodMaterial` and the row is Gap (red); remove it and the row holds (green). |
| **E4** Guest rows | `EgressRelay` and `EgressProxyTrust`, `When(EvalCell)`, switched on in this PR. | The node refuses an eval cell on 2.7.0, naming each row. Standard pods are unchanged. | With the demand set to `Optional`, an eval cell is admitted on 2.7.0 (red). |
| **E5** Release | A guest release carrying E4's rows, and the pin moved to it. | Eval cells are admissible again on the new pin. | — (a release) |
| **E6** No NIC | For an eval cell: no `network-interfaces`, required and recorded at admission; `network.allow`, `url_allow` and `dns_allow` refused by name; `dnsmasq` never started. | Live boot: the eval-cell pod's VMM config has no NIC, an in-registry fixture request succeeds through the proxy, an off-registry one is refused by the host and journaled, and the egress probe is CONTAINED. | The egress probe is pointed (by its existing `NUCLEUS_EGRESS_PROBE_DENY_TARGETS`) at the fixture's address, which an eval cell may list today. On the commit before E6 the connect succeeds, so a byte left without the proxy (red). After E6 it is refused (green). |
| **E7** The inventory | The per-profile status column, `mediated` in the vocabulary, `an_eval_cell_has_no_backstopped_row`. | The gate passes, and the plan's M4 gate is met for eval cells. | Set one eval-cell cell back to `backstopped-only` and the gate reds. |
| *R1* (optional) | The TLSNotary spike (#3325). | Not on the critical path. | — |

Order: E1 ∥ E2 → E3 → E4 → E5 → E6 → E7. E2's per-request decision ids use ADR 0014's
per-pod ledger (S5). If S5 has not landed, E2 calls `PodPolicy::decide_effect` directly,
the one decider either way, and S5 adds the id.

## Consequences

- No pod changes behaviour when this record is accepted. Before E4, everything is
  host-only or measurement.
- From E4 until E5's release, eval cells are refused by name. Their availability is traded
  for never running on the NIC path once the record says they should not.
- After E6, an eval cell reaches only operator-registered HTTP(S) upstreams, through
  clients that honour a proxy and accept the pod's CA. Pinned clients and non-HTTP tools
  do not work in it, and that is stated rather than discovered.
- The proxy is new TCB. Its compromise is bounded to one pod (§7). Its parser is fuzzed
  from E2 onward.
- Standard pods keep the netns fence and `dnsmasq` until the owner moves the floor. Rows
  5, 6 and 10 stay `backstopped-only` for them, and the inventory says so per profile.

## Owner decisions this record asks for

1. §1: no NIC for eval cells (runner-up: NIC with the netns admitting only the proxy).
2. §2: eval-cell egress only to operator-registered upstreams, with `network.allow`,
   `url_allow` and `dns_allow` refused for eval cells (runner-up: spec-written ACLs).
3. §4: TLS termination with a per-pod, name-constrained CA, and pinned clients refused
   (runner-up: CONNECT with SNI ACLs).
4. §7: the proxy as a separate per-pod sandboxed process, with the broker's performer
   moved into it (runner-up: inside `nucleus-node`).
