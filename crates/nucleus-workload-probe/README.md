# nucleus-workload-probe

Minimal in-guest probe: run as a pod's `workload.command`, it asserts the FM-5 posture on the real workload child (no identity vars in its environment, no leaked file descriptors, dropped supplementary groups, read-only root) by reading its own `/proc/self/{environ,fd,status,mountinfo}`. Zero dependencies; baked static into the musl rootfs like `nucleus-net-probe`. Verdict is a `NUCLEUS_WORKLOAD_PROBE: PASS`/`FAIL` sentinel on stdout+stderr plus the exit code; the tool-proxy drains the child stderr into the guest console log, where `nucleus verify --tier2` reads it.
