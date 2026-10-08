# Host listeners a pod can reach

Every service the **host** runs that a pod's guest can connect to, and what the
workload (the agent's uid, as opposed to guest-init or the mediating proxy)
should get when it tries.

The closed `HostListener` enum
(`crates/nucleus-ifc-kernel/src/host_listener.rs`) has exactly one variant per
row, keyed by the `Key` column. The `documented_inventory_equals_the_enum` test
asserts this table and the enum agree on the key set and, per row, on the
`Transport`, `Workload` and `Egress channel` cells. **Adding a host listener
therefore means editing both**, and moving a port means editing both.

The ports are written once, in `VsockListener::port`. The node binds a vsock
listener only through `guest_socket::bind_guest_listener`, which takes a
`VsockListener` and not a number, so a listener that is not a variant cannot be
bound (`every_vsock_bind_goes_through_the_typed_helper` in `nucleus-node`
enforces this for every `UnixListener::bind` in the node's production code). Two
variants cannot share a port (`every_vsock_listener_has_its_own_port`). That
second test is the defect this inventory came from: the node's
`--broker-vsock-port` defaulted to `15013`, the SPIFFE Workload API's port, so
on every broker-enabled pod the broker unlinked the SPIFFE socket and took its
path, and the standard Workload API was silently unreachable. The broker now
listens on `1027` and the flag is gone.

Status vocabulary (the `Workload` column):

- **`refused`**: the workload must not be able to connect at all. The fence today
  is the workload's seccomp filter, which denies `AF_VSOCK`. Guest root and the
  proxy can still connect; the host tells them apart by the once-served material,
  not by the connection. Moving that decision host-side is milestone M3 of the
  eval-cell plan.
- **`filtered`**: the workload may connect, and only what the pod's policy names
  is answered. Anything outside must be refused.

The `Egress channel` column names the row of the C6 inventory in
[`mediated-set.md`](mediated-set.md) this listener is an instance of.

<!-- HOST-LISTENERS-START -->

| Listener | Key | Transport | Workload | Egress channel | Where the host serves it |
|----------|-----|-----------|----------|----------------|--------------------------|
| JSON workload API (SVID, task token, per-pod material, each served once) | `workload_api` | `vsock:15012` | `refused` | `vsock_transport` | `crates/nucleus-node/src/workload_api_vsock.rs` `WorkloadApiVsockBridge::start` |
| Standard SPIFFE Workload API (gRPC) | `spiffe_workload_api` | `vsock:15013` | `refused` | `vsock_transport` | `crates/nucleus-node/src/workload_api_vsock.rs` `spawn_spiffe_listener` |
| Credential broker | `credential_broker` | `vsock:1027` | `refused` | `vsock_transport` | `crates/nucleus-node/src/broker_transport.rs` `BrokerListener::start` |
| Decision channel (host-decide shadow, #2702) | `decision_channel` | `vsock:1028` | `refused` | `vsock_transport` | `crates/nucleus-node/src/host_decide.rs` `DecideListener::start` |
| Per-pod DNS forwarder (`dnsmasq`, `no-resolv`), only when the pod names a DNS allowlist | `pod_dns` | `gateway:53` | `filtered` | `dns` | `crates/nucleus-node/src/net.rs` `start_dns_proxy` / `dnsmasq_config` |
| Whatever the pod's `network.allow` admits | `allowlisted_egress` | `allowlist` | `filtered` | `netns_raw_socket` | `crates/nucleus-node/src/net.rs` netns iptables |

<!-- HOST-LISTENERS-END -->

## What is deliberately not here

- **The node HTTP and gRPC APIs.** They listen in the host namespace (default
  `127.0.0.1:8080`) and must not be reachable from a pod at all.
- **Host-initiated vsock.** The tool-proxy's control port (`vsock.port` in the pod
  spec) is a listener in the GUEST that the host dials; the host does not listen
  there.
- **The proxy's workload door.** It is a Unix socket inside the guest, not a host
  service. Its route table is built from `DoorRoute::ALL`, which has no approval
  route (`nucleus-tool-proxy/src/workload_door.rs`).

## What the `Workload` column does not yet prove

The column states what the workload should get. Nothing yet connects from inside
a booted guest and holds it to that; in-guest probe stages for it are separate
work.

An L3 allowlist cannot tell two names on one address apart: a second host name
served from an allowed `IP:port` is reachable. That is the host egress proxy's job
(milestone M4).
