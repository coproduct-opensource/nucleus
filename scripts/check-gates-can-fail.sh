#!/usr/bin/env bash
# The gate of gates -- now a shim. The harness is `cargo xtask gates-can-fail`
# (crates/xtask/src/gates_can_fail/), which also replaced the shell input derivation (gate-inputs).
#
# WHY THIS FILE STILL EXISTS, given the Rust-not-shell mandate: it holds no logic.
# ci.yml calls the harness by this path, prepush.sh's `--baseline-only` call is
# what `xtask ci-spec local-coverage` credits, and the harness's own accounting
# globs scripts/check-*.sh and exempts this one by name. Same reasoning as
# scripts/check-line-ratchet.sh.
#
# Usage: see `cargo xtask gates-can-fail` (the arguments pass through unchanged).
set -euo pipefail
exec cargo run -q -p xtask -- gates-can-fail "$@"
