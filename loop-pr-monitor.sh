#!/usr/bin/env bash
# PR Monitor Loop
#
# Watches a PR for CI failures, fixes them, and merges when green.
# Terminates after successful merge.
#
# Usage:
#   ./scripts/loop-pr-monitor.sh                    # auto-detect PR from current branch
#   ./scripts/loop-pr-monitor.sh 363                # explicit PR number
#   ./scripts/loop-pr-monitor.sh 363 5              # 5 min interval

set -euo pipefail

PR_NUMBER="${1:-}"
INTERVAL_MINUTES="${2:-5}"
INTERVAL_SECONDS=$((INTERVAL_MINUTES * 60))
MAX_CYCLES=20  # safety valve (~100 min at 5m intervals)
MAX_FIX_ATTEMPTS=3  # don't loop on the same failure forever

if [ -z "$PR_NUMBER" ]; then
    PR_NUMBER=$(gh pr view --json number -q .number 2>/dev/null || echo "")
    if [ -z "$PR_NUMBER" ]; then
        echo "No PR found for current branch. Run the plan executor first."
        exit 1
    fi
fi

REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner)
fix_attempts=0
last_failure=""

echo "PR monitor loop starting"
echo "  PR: ${REPO}#${PR_NUMBER}"
echo "  Interval: ${INTERVAL_MINUTES}m"
echo "  Max cycles: $MAX_CYCLES"
echo "  Max fix attempts per failure: $MAX_FIX_ATTEMPTS"
echo ""

for cycle in $(seq 1 $MAX_CYCLES); do
    echo "=== Cycle $cycle / $MAX_CYCLES ($(date '+%H:%M:%S')) ==="

    # Check PR state
    pr_state=$(gh pr view "$PR_NUMBER" --json state,mergedAt,mergeable,statusCheckRollup \
        -q '{state: .state, merged: .mergedAt, mergeable: .mergeable, checks: [.statusCheckRollup[]? | {name: .name, status: .status, conclusion: .conclusion}]}' 2>&1)

    state=$(echo "$pr_state" | jq -r '.state')
    merged=$(echo "$pr_state" | jq -r '.merged')

    # Already merged?
    if [ "$state" = "MERGED" ] || [ "$merged" != "null" ]; then
        echo "PR #${PR_NUMBER} is merged. Done."
        exit 0
    fi

    # Closed without merge?
    if [ "$state" = "CLOSED" ]; then
        echo "PR #${PR_NUMBER} was closed without merging. Stopping."
        exit 1
    fi

    # Check CI status
    failed_checks=$(echo "$pr_state" | jq -r '.checks[] | select(.conclusion == "FAILURE" or .conclusion == "failure") | .name' 2>/dev/null || echo "")
    pending_checks=$(echo "$pr_state" | jq -r '.checks[] | select(.status != "COMPLETED") | .name' 2>/dev/null || echo "")

    if [ -n "$pending_checks" ]; then
        echo "Checks still running: $(echo "$pending_checks" | tr '\n' ', ')"
        echo "Waiting..."
        sleep "$INTERVAL_SECONDS"
        continue
    fi

    if [ -n "$failed_checks" ]; then
        echo "Failed checks: $(echo "$failed_checks" | tr '\n' ', ')"

        # Track fix attempts for the same failure
        current_failure=$(echo "$failed_checks" | sort | md5sum | cut -d' ' -f1)
        if [ "$current_failure" = "$last_failure" ]; then
            fix_attempts=$((fix_attempts + 1))
        else
            fix_attempts=1
            last_failure="$current_failure"
        fi

        if [ "$fix_attempts" -gt "$MAX_FIX_ATTEMPTS" ]; then
            echo "Failed $MAX_FIX_ATTEMPTS times on the same CI failure. Needs human review."
            gh pr comment "$PR_NUMBER" --body "CI fix loop exhausted after $MAX_FIX_ATTEMPTS attempts. Needs human review.

Failed checks: $(echo "$failed_checks" | tr '\n' ', ')" 2>/dev/null || true
            exit 1
        fi

        echo "Fix attempt $fix_attempts / $MAX_FIX_ATTEMPTS"

        # Get failure details and ask Claude to fix
        failure_logs=$(gh pr checks "$PR_NUMBER" --json name,state,description \
            -q '.[] | select(.state == "FAILURE") | "\(.name): \(.description)"' 2>/dev/null || echo "unknown failure")

        fix_prompt=$(cat <<FIX_EOF
A CI check failed on PR #${PR_NUMBER} (${REPO}). Fix the failure, commit, and push.

## Rules
1. Read the CI failure output carefully. Diagnose the root cause.
2. Fix ONLY what the CI failure requires. Do not refactor, improve, or add features.
3. Run the relevant tests locally before committing.
4. Commit with a message like "fix: <what the CI failure was>".
5. Push to the current branch.
6. If you cannot determine the fix, output NEEDS_HUMAN_REVIEW.
7. Do NOT modify CI configuration to skip or weaken checks.

## Failed checks
${failure_logs}

## CI output
$(gh run list --branch "$(git rev-parse --abbrev-ref HEAD)" --limit 1 --json databaseId -q '.[0].databaseId' 2>/dev/null | xargs -I{} gh run view {} --log-failed 2>/dev/null | tail -80 || echo "Could not fetch logs")
FIX_EOF
        )

        output=$(echo "$fix_prompt" | claude -p --output-format text 2>&1) || true
        echo "$output" | tail -5

        if echo "$output" | grep -q "NEEDS_HUMAN_REVIEW"; then
            echo "Claude cannot fix this CI failure. Needs human review."
            exit 1
        fi

        echo "Fix pushed. Waiting for CI..."
        sleep "$INTERVAL_SECONDS"
        continue
    fi

    # All checks passed — try to merge
    echo "All checks passed. Attempting merge..."
    mergeable=$(echo "$pr_state" | jq -r '.mergeable')

    if [ "$mergeable" = "MERGEABLE" ]; then
        if gh pr merge "$PR_NUMBER" --squash --auto 2>&1; then
            echo "PR #${PR_NUMBER} merge initiated. Waiting for completion..."
            sleep 10

            # Verify merge
            final_state=$(gh pr view "$PR_NUMBER" --json state -q .state 2>/dev/null || echo "UNKNOWN")
            if [ "$final_state" = "MERGED" ]; then
                echo "PR #${PR_NUMBER} merged successfully."
                exit 0
            else
                echo "Merge in progress (auto-merge enabled). State: $final_state"
                # Continue loop to verify
            fi
        else
            echo "Merge failed. Will retry next cycle."
        fi
    else
        echo "PR not yet mergeable (status: $mergeable). Waiting..."
    fi

    if [ "$cycle" -lt "$MAX_CYCLES" ]; then
        sleep "$INTERVAL_SECONDS"
    fi
done

echo "Max cycles reached. PR #${PR_NUMBER} still open. Review manually."
exit 1
