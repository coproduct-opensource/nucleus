# nucleus-node

Node daemon that manages pods and exposes an HTTP API.

## Aggregate resource admission

Every create reserves the pod's requested memory plus 128 MiB of VMM overhead,
and its requested vCPUs, from one node-wide pool. Omitted pod sizes use the
existing 512 MiB / 1 vCPU defaults. Reservations include pods still booting.
Insufficient capacity returns HTTP 503 with requested and available amounts.
Failed or cancelled creates return their reservation; registered pods retain it
until teardown succeeds. Per-pod ceilings and cgroup limits still apply.

`--node-memory-mib` and `--node-vcpus` set the operator's total capacity.
Linux memory defaults to MemTotal, capped by finite visible cgroup-v2 ancestor
memory limits. Other hosts require an explicit memory value. CPU defaults to
available parallelism. `--host-reserve-memory-mib` defaults to 512 and
`--host-reserve-vcpus` defaults to 0; reserves are subtracted before pod admission.
An empty resulting pool prevents startup. Configure capacity explicitly when
other services share the host or memory restrictions are imposed by cgroup v1.

This pool tracks the node process's admitted pods. Reconciliation of surviving
external containers after node restart, aggregate staging-disk limits, and
additional swap policy remain separate resource-management work.

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
