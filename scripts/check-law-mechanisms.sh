#!/usr/bin/env bash
# Law-mechanism gate — a mechanism declared dead must still be dead.
#
# A SHIM. The gate is `cargo xtask law-mechanisms`
# (crates/xtask/src/law_mechanisms.rs), reading
# scripts/law-mechanisms-manifest.txt. The script survives the "gates are Rust"
# convention for the same reason scripts/check-line-ratchet.sh does:
# scripts/check-gates-can-fail.sh addresses gates by script path, so deleting
# the shim would vacate this gate's own coverage check.
#
# Usage: scripts/check-law-mechanisms.sh
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"
exec cargo run -q -p xtask -- law-mechanisms "$@"
