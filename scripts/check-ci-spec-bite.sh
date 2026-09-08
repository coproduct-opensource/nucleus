#!/usr/bin/env bash
# The CI-model bite is a CONTROLLED experiment (delegation_calc's
# check-tamarin-bite.sh doctrine, ported to Lean).
#
# ci/lean/CiSpec proves the merge-queue properties under the invariants
# crates/ci-spec decides; ci/lean/CiSpecBite.lean drops ONE hypothesis per
# theorem and proves the failure reachable on the 2026-09-05 shapes. Both
# build green on their own — which is exactly the shape of a pair that
# checks nothing if the bite quietly becomes a DIFFERENT model:
#
#   1. the bite redefines a `CiSpec` notion (its own `firesIgnore`) and the
#      counterexample is about that, not about the model ci-spec is pinned to;
#   2. the bite grows semantics (a new inductive event, a new structure) that
#      make its failure reachable for an unrelated reason.
#
# So this asserts the differential textually: the bite IMPORTS CiSpec, adds
# no `structure` / `inductive` / `class` / `instance` / `abbrev`, every `def`
# it declares is a closed constant (no `→` in its type — data, not a function
# that could shadow model semantics), and it states at least one theorem.
# Perturb the information, never the shape.
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

BITE=ci/lean/CiSpecBite.lean
[ -f "$BITE" ] || { echo "::error::$BITE is missing"; exit 1; }

# Strip block and line comments so prose about `structure` cannot trip it.
stripped="$(perl -0pe 's{/-.*?-/}{}gs; s{--[^\n]*}{}g' "$BITE")"

fail=0
if ! printf '%s\n' "$stripped" | grep -qE '^import CiSpec$'; then
  echo "::error::$BITE does not import CiSpec — the bite must be about the same model"; fail=1
fi
bad="$(printf '%s\n' "$stripped" | grep -nE '^\s*(structure|inductive|class|instance|abbrev)\b' || true)"
if [ -n "$bad" ]; then
  echo "::error::$BITE adds semantics (new types or instances); the bite may only drop hypotheses:"
  printf '%s\n' "$bad"; fail=1
fi
fndefs="$(printf '%s\n' "$stripped" | grep -nE '^\s*def\b' | grep -E '→|->' || true)"
if [ -n "$fndefs" ]; then
  echo "::error::$BITE declares function-typed defs; only closed constants are allowed:"
  printf '%s\n' "$fndefs"; fail=1
fi
n="$(printf '%s\n' "$stripped" | grep -cE '^\s*theorem\b' || true)"
[[ "$n" =~ ^[0-9]+$ ]] || n=0
if [ "$n" -lt 1 ]; then
  echo "::error::$BITE states no theorem — a bite with no attack lemma checks nothing"; fail=1
fi

if [ "$fail" -ne 0 ]; then exit 1; fi
echo "ok: CiSpecBite imports CiSpec, adds no semantics, and states $n theorem(s)"
