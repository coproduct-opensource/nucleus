# nucleus-workload-probe

Minimal in-guest probe: run as a pod's `workload.command`, it asserts the FM-5 posture on the real workload child (no identity vars in its environment, no leaked file descriptors, dropped supplementary groups, read-only root) by reading its own `/proc/self/{environ,fd,status,mountinfo}`. Baked static into the musl rootfs like `nucleus-net-probe`. Verdict is a `NUCLEUS_WORKLOAD_PROBE: PASS`/`FAIL` sentinel on stdout+stderr plus the exit code; the tool-proxy drains the child stderr into the guest console log, where `nucleus verify --tier2` reads it.

The syscall-filter stage opens AF_VSOCK and attempts namespace and ptrace operations, requiring EPERM; positive controls require ordinary sockets and fork to remain available. Each operation runs in a separate child. The default posture probe includes this stage, and `--syscall-filter` runs it alone.

2026-10-04 (#3162): the measured exemplar unsafe-block count changes from 4 to 5 for this probe's single Linux `libc::syscall` wrapper. Its callers pass scalar arguments and null output pointers; socket descriptors are closed and forked children are reaped. The production hardening path retains its existing two unsafe blocks. The baseline also records workspace-lint adoption improving from 63 to 64 crates (96 total).

The C2 lineage probe is separate trusted instrumentation: CI enables guest-init's `ci-podlist-probe` feature to query the host over real vsock while ordinary workloads remain filtered. Release builds omit that feature.
