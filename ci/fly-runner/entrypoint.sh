#!/usr/bin/env bash
set -euo pipefail
# The volume persists caches, never a checkout or executable search path. Every Machine
# starts from the pinned image; only the one-job JIT credential enters the worker.
mountpoint -q /data
mkdir -p /data/cache/sccache /data/cache/cargo /data/work
rm -rf /data/work
mkdir -p /data/work
chown runner:runner /data/work /data/cache /data/cache/sccache /data/cache/cargo
mkdir -p /home/runner/.cargo/registry
ln -s /data/cache/cargo /home/runner/.cargo/registry/cache
rm -rf /home/runner/_work
ln -s /data/work /home/runner/_work
chown -R runner:runner /home/runner/.cargo
export RUSTC_WRAPPER=sccache SCCACHE_DIR=/data/cache/sccache SCCACHE_CACHE_SIZE=12G
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=line-tables-only
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"
export ACTIONS_RUNNER_HOOK_JOB_STARTED=/usr/local/bin/job-started.sh
export ACTIONS_RUNNER_HOOK_JOB_COMPLETED=/usr/local/bin/job-completed.sh
jit=$(cat /run/runner-jit)
rm /run/runner-jit
cd /home/runner
# runuser changes uid without storing the administrator's GitHub or Fly tokens here.
exec timeout --signal=TERM --kill-after=30s 3600 runuser -u runner -- ./run.sh --jitconfig "$jit"
