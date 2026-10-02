#!/usr/bin/env bash
# ACTIONS_RUNNER_HOOK_JOB_COMPLETED — runs as a synchronous step at the end of
# every job on the self-hosted scale set. Prints the job's sccache hit rate
# (counters zeroed by job-started.sh) and the pod's peak memory, so the two
# questions a slow job raises — "did the cache help?" and "was it starved?" —
# are answered in the job log itself, not by exec'ing into a pod that is
# already gone. Exit 0 always: instrumentation never fails a job.
set -u
echo "::group::sccache (this job)"
SCCACHE_DIR=/home/runner/.cache/sccache sccache --show-stats 2>/dev/null \
  | grep -E "Compile requests|Cache hits|Cache misses|Non-cacheable|Average" || echo "sccache: no server (job ran no rustc)"
echo "::endgroup::"
echo "::group::pod resources"
echo "memory.peak=$(awk '{printf "%.2fGi", $1/1073741824}' /sys/fs/cgroup/memory.peak 2>/dev/null || echo n/a) memory.max=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo n/a)"
echo "cpu.stat: $(tr '\n' ' ' < /sys/fs/cgroup/cpu.stat 2>/dev/null | cut -c1-160)"
echo "disk: $(df -h /home/runner/_work 2>/dev/null | tail -1 | awk '{print $3" used of "$2}')"
echo "::endgroup::"
exit 0
