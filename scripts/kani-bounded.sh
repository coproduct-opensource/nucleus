#!/usr/bin/env bash
# Linux CI wrapper: the Kani action installs the pinned toolchain, then
# invokes this command with its args. The child verifier inherits this cap.
set -euo pipefail
ulimit -v 8388608 # 8 GiB per process; fail the shard instead of killing the host.
exec cargo kani "$@"
