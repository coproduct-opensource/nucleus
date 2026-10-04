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

The [v2 swap control](https://docs.kernel.org/admin-guide/cgroup-v2.html)
limits swap separately. The [v1 memory controller](https://docs.kernel.org/admin-guide/cgroup-v1/memory.html)
limits memory and swap together, so v1 does not promise that no page is ever
swapped; it bounds their total.

The state directory is exclusively locked for the node process's lifetime.
Stop the old node before starting a replacement, including when upgrading from
a version that did not take this lock. Keep the `node.lock` file in place; an
unlocked file left after exit is normal.

With the container driver, startup lists containers on the configured Docker
daemon and removes this state directory's leftovers before serving requests.
Runtime authorization history is not resumable, so these workloads are stopped,
not resumed with a new budget. Host bind-mounted workspaces, specs and logs are
preserved. New containers carry node ownership and pod labels; older containers
are recognized by their exact `<state>/pods/<uuid>` bind at `/data/pod` and an
existing `pod.yaml`. Removal errors prevent startup; restart can retry after
the Docker service recovers. Use the same state directory and Docker daemon for
recovery. Moving state or switching drivers requires separate reconciliation.

Cancellation during an unfinished Docker create/start still needs cleanup in
the current process; startup recovery covers leftovers at the next restart.

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

## Sealed rootfs syscall boundary

2026-10-04: the exemplar unsafe-block baseline moves from 4 to 7 for the three
Linux ioctl wrappers in `sealed_rootfs::sys`: `FS_IOC_GETFLAGS`,
`FS_IOC_SETFLAGS`, and `FICLONE`. Each borrows an owned, open `File`; the flags
calls use a live `c_int` pointer and reflink passes the source descriptor by
value. Each checks the syscall result. These calls implement the opt-in
immutable-copy cache; any failure falls back to normal placement and full
digest verification. The baseline records these reviewed FFI boundaries rather
than excluding them from measurement.
