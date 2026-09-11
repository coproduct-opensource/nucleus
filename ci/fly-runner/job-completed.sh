#!/usr/bin/env bash
# ACTIONS_RUNNER_HOOK_JOB_COMPLETED — runs as a synchronous step at the end of
# every job on the self-hosted scale set. Prints the job's sccache hit rate
# (counters zeroed by job-started.sh) and the pod's peak memory, so the two
# questions a slow job raises — "did the cache help?" and "was it starved?" —
# are answered in the job log itself, not by exec'ing into a pod that is
# already gone. Exit 0 always: instrumentation never fails a job.
set -u
echo "::group::sccache (this job)"
# WHERE this ran, on the same line-oriented format as the counters below, because
# `Average cache read hit` is meaningless without it once the pool spans regions.
#
# The build pool has to grow across regions: a volume pins its machine to that
# volume's HOST, so a full iad zone refuses the create (HTTP 412) forever while
# the volume-less gate pool floats to any zone with room. The 8 GB rootfs cap
# means a compile pool cannot drop the volume that causes the pin.
#
# Cross-region is not free and the size of the penalty is the open question.
# Tigris caches by request pattern, so a new region should warm up rather than
# stay slow — but "should" is not a measurement, and the object store is in ONE
# place while the machine reading it may not be. Baseline before any region but
# iad existed: 0.037-0.076 s per read at 1127-2558 reads per job, ~8-way
# parallel. Print the region beside the number so the next reader can subtract.
echo "placement: region=${FLY_REGION:-unknown} machine=${FLY_MACHINE_ID:-unknown} sccache=${SCCACHE_BUCKET:-local}"
sccache --show-stats 2>/dev/null \
  | grep -E "Compile requests|Cache hits|Cache misses|Non-cacheable|Average" || echo "sccache: no server (job ran no rustc)"
echo "::endgroup::"
echo "::group::pod resources"
echo "memory.peak=$(awk '{printf "%.2fGi", $1/1073741824}' /sys/fs/cgroup/memory.peak 2>/dev/null || echo n/a) memory.max=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo n/a)"
echo "cpu.stat: $(tr '\n' ' ' < /sys/fs/cgroup/cpu.stat 2>/dev/null | cut -c1-160)"
echo "disk: $(df -h /home/runner/_work 2>/dev/null | tail -1 | awk '{print $3" used of "$2}')"
echo "::endgroup::"
exit 0
