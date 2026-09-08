#!/usr/bin/env bash
# CI configuration is sound (CI-1): the invariants the merge queue relies on,
# decided over a typed model of the workflows, the required-check ledger and
# the merge-queue pin. The decision lives in crates/ci-spec; this wrapper
# exists so the gate has a `scripts/check-*.sh` identity that
# check-gates-can-fail.sh can PROBE (perturb a twin's paths-ignore, expect
# red; restore, expect green).
#
# Exit 0 clean, 1 a violation, 2 could not look — the third is never a pass.
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"
exec cargo run -q -p xtask -- ci-spec check "$@"
