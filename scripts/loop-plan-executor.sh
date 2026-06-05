#!/usr/bin/env bash
# Plan Executor Loop
#
# Reads a plan file, checks each step against current code, implements
# incomplete steps, and opens a PR when all steps are complete.
# Terminates after PR is opened — does NOT invent new work.
#
# Usage:
#   ./scripts/loop-plan-executor.sh ~/.claude/plans/bright-knitting-mitten.md
#   ./scripts/loop-plan-executor.sh ~/.claude/plans/bright-knitting-mitten.md 15  # 15 min interval

set -euo pipefail

PLAN_FILE="${1:?Usage: $0 <plan-file> [interval-minutes]}"
INTERVAL_MINUTES="${2:-20}"
INTERVAL_SECONDS=$((INTERVAL_MINUTES * 60))
BRANCH=$(git rev-parse --abbrev-ref HEAD)
MAX_CYCLES=10  # safety valve

if [ ! -f "$PLAN_FILE" ]; then
    echo "Plan file not found: $PLAN_FILE"
    exit 1
fi

PLAN_CONTENT=$(cat "$PLAN_FILE")

PROMPT=$(cat <<'PROMPT_EOF'
You are a plan executor. Your ONLY job is to complete the plan below, then open a PR.

## Rules
1. Read the plan carefully. Check each step against the current codebase.
2. If an incomplete step exists: implement it, run tests, commit.
3. If ALL steps are complete AND a PR has not been opened: push the branch, open a PR with `gh pr create`, then output PLAN_COMPLETE.
4. If ALL steps are complete AND a PR already exists: output PLAN_COMPLETE.
5. Do NOT add features, tests, improvements, or refactoring beyond what the plan specifies.
6. Do NOT modify the plan file.
7. If you discover something worth doing that isn't in the plan, file a GitHub issue with `gh issue create`, do not implement it.
8. Each cycle: implement at most ONE step. Commit after each step passes tests.
9. If tests fail, fix the failure — do not skip to the next step.

## Plan
PROMPT_EOF
)

echo "Plan executor loop starting"
echo "  Plan: $PLAN_FILE"
echo "  Branch: $BRANCH"
echo "  Interval: ${INTERVAL_MINUTES}m"
echo "  Max cycles: $MAX_CYCLES"
echo ""

for cycle in $(seq 1 $MAX_CYCLES); do
    echo "=== Cycle $cycle / $MAX_CYCLES ($(date '+%H:%M:%S')) ==="

    output=$(echo "${PROMPT}

${PLAN_CONTENT}" | claude -p --output-format text 2>&1) || true

    echo "$output" | tail -5

    if echo "$output" | grep -q "PLAN_COMPLETE"; then
        echo ""
        echo "Plan complete. PR opened or already exists. Stopping."
        exit 0
    fi

    if [ "$cycle" -lt "$MAX_CYCLES" ]; then
        echo "Sleeping ${INTERVAL_MINUTES}m until next cycle..."
        sleep "$INTERVAL_SECONDS"
    fi
done

echo "Max cycles reached without completion. Review manually."
exit 1
