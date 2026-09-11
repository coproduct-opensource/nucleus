#!/usr/bin/env bash
# Line-count ratchet — now a shim. The gate is `cargo xtask line-ratchet`
# (crates/xtask/src/line_ratchet.rs), which splits it into the half decided by
# .line-ratchet.toml alone and the half that needs the tree.
#
# Usage: scripts/check-line-ratchet.sh [--strict]
#   --strict: exit 1 on a count violation (default: warn only)
#
# WHY THIS FILE STILL EXISTS, given the Rust-not-shell mandate: it holds no logic.
# `scripts/check-gates-can-fail.sh`'s `probe` helper is addressed by script path —
# it asserts that some workflow invokes `scripts/<gate>` with the same flags the
# probe uses, and fails a gate no workflow mentions. Deleting this path would make
# the red-then-green probe for the line ratchet report "no workflow invokes it",
# i.e. the conversion would silently vacate its own coverage check. The probe
# harness is load-bearing enough that it should be changed on purpose, in its own
# change, not as a side effect of porting one gate.
#
# The two defects this gate shipped were both in the parsing:
#   * `grep '^ceiling' | head -1` enforced only the first [[files]] entry while the
#     config declared several, and the others drifted (tool-proxy 4975 vs 4118);
#   * untracked sibling files were invisible until the sweep was added.
# Neither was a judgement anyone got wrong. Both are what a program has when it has
# `awk` and `head -1` instead of a parser. See gatehouse `docs/tiering.md`.
set -euo pipefail
exec cargo run -q -p xtask -- line-ratchet "$@"
