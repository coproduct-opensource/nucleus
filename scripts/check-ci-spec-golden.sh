#!/usr/bin/env bash
# The CI-model golden seal: ci/lean/CiSpec/Golden.lean is GENERATED from
# crates/ci-spec/tests/golden/queue_traces.json by `cargo xtask ci-spec
# gen-golden`, and the Lean kernel checks every vector by `decide`. This gate
# regenerates and diffs (the econ-lean golden-seal pattern): a vector edited
# in the JSON without regenerating, or a hand edit to the Lean, is red — so
# the Rust mirror and the Lean model are pinned to each other on every vector
# and cannot drift without a visible change.
#
# Exit 0 in sync, 1 drift, 2 could not regenerate (never a pass).
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

GOLDEN=ci/lean/CiSpec/Golden.lean
[ -f "$GOLDEN" ] || { echo "::error::$GOLDEN is missing; run cargo xtask ci-spec gen-golden"; exit 1; }

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
if ! cargo run -q -p xtask -- ci-spec gen-golden > "$tmp"; then
  echo "::error::could not regenerate $GOLDEN (gen-golden failed) — not a pass"
  exit 2
fi
# Non-vacuity: a regeneration that produced no vectors would diff clean
# against an empty file and certify nothing.
n="$(grep -c '^example' "$tmp" || true)"
[[ "$n" =~ ^[0-9]+$ ]] || n=0
if [ "$n" -lt 3 ]; then
  echo "::error::regenerated Golden.lean has $n example(s) — the generator saw no vectors"
  exit 2
fi
if ! diff -u "$GOLDEN" "$tmp"; then
  echo "::error::$GOLDEN is stale vs crates/ci-spec/tests/golden/queue_traces.json."
  echo "  Regenerate: cargo xtask ci-spec gen-golden > $GOLDEN"
  exit 1
fi
echo "ok: $GOLDEN matches its $n golden vectors"
