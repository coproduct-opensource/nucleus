#!/usr/bin/env bash
set -euo pipefail
# One boot, one job. The manager writes this Machine's one-job JIT configuration to
# /run/runner-jit before each start; a boot without one is a warm-up (the image is now on this
# host) and exits at once, leaving the Machine stopped and ready. A volume at /data, when the
# pool has one, persists the sccache store and the cargo registry cache across jobs and never
# a checkout, a toolchain or an executable search path.
if [ ! -s /run/runner-jit ]; then
  echo "no job configuration: warm boot, exiting"
  exit 0
fi
if mountpoint -q /data; then
  mkdir -p /data/cache/sccache /data/cache/cargo
  rm -rf /data/work && mkdir -p /data/work
  chown runner:runner /data/work /data/cache /data/cache/sccache /data/cache/cargo
  mkdir -p /home/runner/.cargo/registry
  rm -rf /home/runner/.cargo/registry/cache
  ln -s /data/cache/cargo /home/runner/.cargo/registry/cache
  rm -rf /home/runner/_work
  ln -s /data/work /home/runner/_work
  export SCCACHE_DIR=/data/cache/sccache SCCACHE_CACHE_SIZE="${SCCACHE_CACHE_SIZE:-20G}"
else
  mkdir -p /home/runner/_work
  export SCCACHE_DIR=/home/runner/.cache/sccache SCCACHE_CACHE_SIZE="${SCCACHE_CACHE_SIZE:-2G}"
fi
chown -R runner:runner /home/runner/.cargo /home/runner/_work /home/runner/.cache 2>/dev/null || true
export RUSTC_WRAPPER=sccache
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=line-tables-only
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$(nproc)}"
export ACTIONS_RUNNER_HOOK_JOB_STARTED=/usr/local/bin/job-started.sh
export ACTIONS_RUNNER_HOOK_JOB_COMPLETED=/usr/local/bin/job-completed.sh
jit=$(cat /run/runner-jit)
rm -f /run/runner-jit
cd /home/runner
# runuser changes uid without storing the administrator's GitHub or Fly tokens here. The
# runner exits after its one job; the Machine's restart policy is "no", so it stops.
exec timeout --signal=TERM --kill-after=30s "${JOB_SECONDS:-3600}" runuser -u runner -- ./run.sh --jitconfig "$jit"
