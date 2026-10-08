# nucleus-node

Node daemon that manages pods and exposes an HTTP API.

## Aggregate resource admission

Every create reserves the pod's requested memory plus 128 MiB of VMM overhead,
and its requested vCPUs, from one node-wide pool. Omitted pod sizes use the
existing 512 MiB / 1 vCPU defaults. Reservations include pods still booting.
Insufficient capacity returns HTTP 503 with requested and available amounts.
Failed or cancelled creates return their reservation; registered pods retain it
until teardown succeeds. Per-pod ceilings and cgroup limits still apply.

For registered container pods, Docker must confirm removal or report that the
container is already absent before either the concurrency slot or aggregate
reservation is released. Other removal errors remain visible to cancellation
callers, and the reaper retries cleanup on its next pass before recording the
exit and releasing authority. Docker daemon unavailability does not count as
successful removal.
If removal succeeds without an observed process exit code, status is `Exited`
with an unknown code. This confirms termination without reporting a successful
workload exit; a previously observed code is retained.

`--node-memory-mib` and `--node-vcpus` set the operator's total capacity.
Linux memory defaults to MemTotal, capped by finite visible cgroup-v2 ancestor
memory limits. Other hosts require an explicit memory value. CPU defaults to
available parallelism. `--host-reserve-memory-mib` defaults to 512 and
`--host-reserve-vcpus` defaults to 0; reserves are subtracted before pod admission.
An empty resulting pool prevents startup. Configure capacity explicitly when
other services share the host or memory restrictions are imposed by cgroup v1.

Firecracker cgroup v2 pods receive `memory.swap.max=0`; v1 pods receive a combined
`memory.memsw.limit_in_bytes` ceiling equal to the VMM memory ceiling, written
after the memory limit. Pod settings may lower these ceilings but cannot raise
them. The host must expose the corresponding swap-accounting control; a failed
limit write prevents launch. Container pods already set their combined
memory-plus-swap allowance equal to their memory allowance.
Before starting a container, the node reads Docker's accepted HostConfig back
and requires the admitted memory, memory-plus-swap, CPU and process limits.
A daemon that silently rewrites or omits a required limit causes launch rollback
with a named configuration error. This checks Docker's accepted configuration;
the daemon and host still provide the kernel enforcement.

The [v2 swap control](https://docs.kernel.org/admin-guide/cgroup-v2.html)
limits swap separately. The [v1 memory controller](https://docs.kernel.org/admin-guide/cgroup-v1/memory.html)
limits memory and swap together, so v1 does not promise that no page is ever
swapped; it bounds their total.

The state directory is exclusively locked for the node process's lifetime.
Stop the old node before starting a replacement, including when upgrading from
a version that did not take this lock. Keep the `node.lock` file in place; an
unlocked file left after exit is normal.

A Firecracker launch holds everything it acquires in one handle until the pod is
registered: the launch slot, network namespace and allocation, DNS proxy, jail
directory, VMM process, cgroup leaf, vsock bridge and signed proxy. A launch that
fails at any point stops its VMM and releases all of them before the error is
returned. The VMM and DNS proxy are spawned kill-on-drop, so a VMM whose handle the
node drops is killed rather than left running without an owner. This covers drops
inside a running node only.

When the node is stopped by a signal:

- **SIGTERM or SIGINT** drains it. The node stops admitting pods (a create gets
  `503`), waits for launches already admitted to register, then tears every pod
  down through its normal teardown and writes `pod_drained` to the pod's
  `lifecycle.log`. The drain has a 30 s deadline, under systemd's default 90 s stop
  timeout. A drain that cannot confirm every pod stopped names the stragglers and
  exits non-zero. Whatever stragglers still hold is reclaimed at the next start.
- **SIGKILL**, or a crash, runs nothing, so the VMMs keep running. At the next
  start, before serving, the node finds each one through its jail's cgroup
  (`/sys/fs/cgroup/<exec>/<pod id>`, the jailer's own placement) and its pod's
  network namespace. It never matches by process name. The node kills each VMM
  with `cgroup.kill`, waits until membership is empty, then removes the pod's
  host firewall rules, veth, namespace, cgroup and jail. If a stranded VMM is
  still alive after the kill, or its membership cannot be read, the node refuses
  to start and names it.

A parent-death signal does not replace the startup reclaim. The kernel clears
`PR_SET_PDEATHSIG` when the jailer drops to `--uid`/`--gid`, so a jailed VMM never
carries one.

With the container driver, startup lists containers on the configured Docker
daemon and removes this state directory's leftovers before serving requests.
Runtime authorization history is not resumable, so these workloads are stopped,
not resumed with a new budget. Host bind-mounted workspaces, specs and logs are
preserved. New containers carry node ownership and pod labels; older containers
are recognized by their exact `<state>/pods/<uuid>` bind at `/data/pod` and an
existing `pod.yaml`. Removal errors prevent startup; restart can retry after
the Docker service recovers. Use the same state directory and Docker daemon for
recovery. Moving state or switching drivers requires separate reconciliation.

Container creates run in a node-owned task. Cancelling the API create future does
not drop launch reservations while Docker is still processing create/start. A
successful result must be accepted by the calling request task; otherwise the
node cancels the registered pod and retries cleanup until removal is confirmed. Failed starts
also finish removal before returning their reservations.

Creates have a unique node-generated Docker name, so cleanup can find a
container even if its create response was lost. An uncertain transport error
keeps capacity reserved until that named container is found and removed; an
initial not-found response does not settle an in-flight create. If Docker never
created it, this conservative reservation remains held pending operator recovery.
This handoff does not prove the remote client received the HTTP/gRPC response.
These tasks survive request-task cancellation. Before contacting Docker, the
node also atomically writes and syncs a launch record under
`<state>/container-launches/`. It records the observed Docker ID before starting
or removing the container, and syncs record removal before returning resources.

On process restart, these records are reconciled before the container inventory
and before new admissions. A known container can be removed, or confirmed
already absent. An unresolved create that is still absent prevents startup and
names its retained record in the error; absence alone cannot settle a remote
request that might finish later. Once it appears, a later startup can confirm
ownership, persist its ID, and remove it. If it never appears, operator
reconciliation is still required. Do not erase a pending record merely because
an inventory is empty. This also covers a crash after container removal but
before record removal: the previously recorded ID makes absence conclusive.

## Outbound byte accounting

Firecracker pods share one `network.egress` ledger between broker PERFORM,
streamed broker uploads and direct IP traffic. The default allowance is 1 GiB
when no byte ceiling is declared. Broker paths reserve request-body bytes before
sending. Direct packets wait in a namespace-local NFQUEUE until the node reserves
their kernel-reported IP length from that same total and fixed-window allowance.
The node requests kernel segmentation before queueing offloaded packets.

The queue covers IPv4 and IPv6 packets leaving the pod namespace through its
peer veth, after filtering and before forwarding. Download bodies travel in the
opposite direction; outgoing acknowledgments and retransmissions still count.
The accounting unit is IP bytes at the queue, not physical wire bytes: Ethernet,
ARP and framing added after the queue are outside this count. Broker HTTP/TLS
transport overhead is also separate from its request-body accounting.

An over-budget packet is dropped before acceptance and total exhaustion closes
the queue for the pod's remaining life. A pace refusal drops the packet while
leaving the queue active, so normal TCP retries can progress in later windows.
This is a fixed-window policer, not a smooth traffic shaper. A single packet
larger than the per-window allowance cannot proceed; choose an allowance large
enough for ordinary packets. Streamed broker uploads still reserve the complete
staged body as one batch and must fit within one window.

Queue setup must complete before guest spawn. The host needs `ip`, `iptables`,
`ip6tables`, namespace privileges and `CONFIG_NETFILTER_NETLINK_QUEUE` plus the
NFQUEUE target. The Apple Container kernel fragment retains these features.
The [Netfilter queue API](https://netfilter.org/projects/libnetfilter_queue/doxygen/html/group__nfq__verd.html)
describes listener absence and bypass behavior.
Rules never enable queue bypass or fail-open: a missing listener or full queue
cannot allow unaccounted packets. Receiver failures disable new broker admissions
too. Shutdown closes the binding before network teardown; cancelled shutdown
retains the receiver for retry. A lifecycle record reports accepted IP bytes and
packets explicitly refused by the receiver (not kernel-only drops).

These guarantees apply to the Firecracker namespace path, not unmediated
container or local-driver traffic. They replace periodic link-counter accounting.

`--egress-staging-max-bytes` bounds reserved upload payload storage across all
pods, defaulting to 256 MiB. Each streamed upload reserves its configured
per-call maximum before creating its temporary file, retaining the reservation
through review and replay. The default 32 MiB per-call limit therefore admits
eight concurrent staged uploads, even if their actual payloads are smaller.
Insufficient capacity refuses the upload before credential retrieval or upstream
I/O; callers can retry after active uploads finish. The node requires enough
staging capacity for at least one maximum-size request at startup. This is a
payload reservation bound, not a filesystem quota or free-space measurement;
filesystem metadata and other users of the temporary directory are separate.

Development direct-spawn cgroups retain an ownership handle for the leaf created
by the launch. Teardown removes that leaf after the VMM stops; cancelled launches
retry a busy leaf for up to one second. Existing operator-created directories
and parent hierarchies are preserved. Failed cleanup is reported, and normal
teardown retains its capacity reservation until cleanup succeeds. Abrupt node
termination can still leave directories requiring startup reconciliation.

## Production confinement

Default builds require `--firecracker-jailer=true` and reject pod specs using
`SeccompSpec::Disabled` or `SeccompSpec::Custom` before allocating pod resources.
Custom filters remain refused until admission can validate a pinned BPF hash;
observing seccomp filter mode alone does not establish filter contents.
`--jailer-uid` / `NUCLEUS_JAILER_UID` must be nonzero in every build.

The existing development-only `local-driver` feature permits disabling the jailer
and selecting non-default seccomp policies. Do not enable this feature in
production. Failures name `JailerRequired`, `JailerRootUid`, `SeccompDisabled`, or
`SeccompUnpinned` so operators can identify the rejected setting.

## Host-spec enforcement

`--broker-enforcing` / `NUCLEUS_NODE_BROKER_ENFORCING` decides whether a guest
must run the spec this node admitted. When it is on, the node puts
`nucleus.host_spec=required` on the guest kernel command line and withholds
`credentials.env` values from the served spec. Guest-init then refuses a
`pod.yaml` baked into the rootfs. Before the node reports the pod running, it
waits for guest-init's `NUCLEUS_HOST_SPEC: READY`.

Since 2026-10-05 (#3205) this is on by default for the Firecracker driver. The
node resolves the setting once at startup, from the driver:

| Driver | Unset | `true` | `false` |
|---|---|---|---|
| `firecracker` | enforced | enforced | not enforced; startup logs a warn naming the weakened posture |
| `container`, `local`, `apple-vz` | not enforced | startup refused | not enforced |

- **Guest rootfs.** Enforcement needs guest-init that prints the `READY`
  handshake: the pinned 2.7.0 rootfs, or one built from this tree. To boot an
  older rootfs on Firecracker, set `NUCLEUS_NODE_BROKER_ENFORCING=false`.
- **`nucleus setup`.** The `node.env` it writes sets
  `NUCLEUS_NODE_DRIVER=firecracker` and `NUCLEUS_NODE_BROKER_ENFORCING=true`
  explicitly.
- **Broad egress.** Under enforcement, a pod whose network policy allows public
  address space without naming one host gets no workload API, so it cannot be
  served its spec. It fails to launch, where before it booted without an
  identity.

## Sealed rootfs syscall boundary

2026-10-04: the exemplar unsafe-block baseline moves from 4 to 7 for the three
Linux ioctl wrappers in `sealed_rootfs::sys`: `FS_IOC_GETFLAGS`,
`FS_IOC_SETFLAGS`, and `FICLONE`. Each borrows an owned, open `File`; the flags
calls use a live `c_int` pointer and reflink passes the source descriptor by
value. Each checks the syscall result. These calls implement the opt-in
immutable-copy cache; any failure falls back to normal placement and full
digest verification. The baseline records these reviewed FFI boundaries rather
than excluding them from measurement.
