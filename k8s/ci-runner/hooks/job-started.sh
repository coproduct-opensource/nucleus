#!/usr/bin/env bash
# ACTIONS_RUNNER_HOOK_JOB_STARTED — runs as a synchronous step at the start of
# every job on the self-hosted scale set (k8s/ci-runner/values.yaml mounts it
# from the `runner-hooks` ConfigMap). Output lands in the job log.
#
# Instrumentation, not policy: it records what the pod looks like so a slow
# job can be read against its environment, and zeroes the sccache counters so
# the completed hook reports THIS job's hit rate rather than the pod's history.
set -u
echo "::group::runner pod"
echo "pod=$(hostname) nproc=$(nproc) mem=$(awk '/MemTotal/ {printf "%.1fGi", $2/1048576}' /proc/meminfo)"
echo "cgroup cpu.max=$(cat /sys/fs/cgroup/cpu.max 2>/dev/null || echo n/a) memory.max=$(cat /sys/fs/cgroup/memory.max 2>/dev/null || echo n/a)"
echo "sccache store: $(du -sh /home/runner/.cache/sccache 2>/dev/null | cut -f1 || echo n/a) at $(date -u +%FT%TZ)"
echo "::endgroup::"
SCCACHE_DIR=/home/runner/.cache/sccache sccache --zero-stats >/dev/null 2>&1 || true
exit 0
