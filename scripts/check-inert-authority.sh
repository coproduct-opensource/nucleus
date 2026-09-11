#!/usr/bin/env bash
# Inert-authority gate — a witness accepted and dropped is a gate that is
# present but does nothing.
#
# A SHIM. The gate is `cargo xtask inert-authority`
# (crates/xtask/src/inert_authority.rs), reading
# scripts/inert-authority-manifest.txt. The script survives the "gates are Rust"
# convention (#2760) for the reason scripts/check-law-mechanisms.sh does:
# scripts/check-gates-can-fail.sh addresses gates by script path, so deleting
# the shim would vacate this gate's own coverage check.
#
# Usage: scripts/check-inert-authority.sh
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"
exec cargo run -q -p xtask -- inert-authority "$@"
