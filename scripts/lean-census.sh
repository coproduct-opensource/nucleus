#!/usr/bin/env bash
# lean-census.sh — honest first-party Lean proof census.
#
# Counts ONLY first-party authored Lean. Excludes, by construction:
#   .lake/, lake-packages/  — vendored Mathlib/std (NOT ours; the "9K files /
#                             7500 sorries" overclaim came from counting these)
#   .claude/                — transient git worktrees (working copies, not source)
#   external/, vendor/      — vendored third-party Lean libraries
#   generated/              — codegen output (reported separately, not as proofs)
#
# Run from a repo root: scripts/lean-census.sh
# Purpose: give docs ONE honest source of truth for Lean counts. Any doc citing
# Lean file/theorem/sorry totals should match this, NOT a raw find/grep that
# sweeps .lake/ and .claude/worktrees.
set -uo pipefail

EX=(--include='*.lean'
    --exclude-dir=.lake --exclude-dir=lake-packages
    --exclude-dir=.claude --exclude-dir=external
    --exclude-dir=vendor --exclude-dir=generated)

fp=$(grep -rlI '' "${EX[@]}" . 2>/dev/null | wc -l | tr -d ' ')
gen=$(find . -path '*/generated/*' -name '*.lean' \
        -not -path '*/.lake/*' -not -path '*/.claude/*' 2>/dev/null | wc -l | tr -d ' ')
thm=$(grep -rhcE '^[[:space:]]*(theorem|lemma) ' "${EX[@]}" . 2>/dev/null | awk '{s+=$1} END{print s+0}')
sf=$(grep -rlE '^[[:space:]]*sorry' "${EX[@]}" . 2>/dev/null | wc -l | tr -d ' ')
sc=$(grep -rhcE '^[[:space:]]*sorry' "${EX[@]}" . 2>/dev/null | awk '{s+=$1} END{print s+0}')
dec=$(grep -rlE ':=[[:space:]]*by[[:space:]]+trivial' "${EX[@]}" . 2>/dev/null | wc -l | tr -d ' ')

echo "lean census — $(basename "$(pwd)")  (first-party only)"
echo "  first-party lean files            : $fp"
echo "  generated lean files (excluded)   : $gen"
echo "  theorems + lemmas                 : $thm"
echo "  sorry-bearing files               : $sf  ($sc sorries)"
echo "  decorative (:= by trivial) files  : $dec"
