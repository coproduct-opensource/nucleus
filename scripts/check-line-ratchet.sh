#!/usr/bin/env bash
# Check that monitored files stay within their line-count ratchet ceiling.
# Called by CI on PRs and by the post-merge ratchet workflow.
#
# Usage: scripts/check-line-ratchet.sh [--strict]
#   --strict: exit 1 on violation (default: warn only)

set -euo pipefail

RATCHET_FILE=".line-ratchet.toml"
STRICT=false

if [[ "${1:-}" == "--strict" ]]; then
    STRICT=true
fi

if [[ ! -f "$RATCHET_FILE" ]]; then
    echo "No $RATCHET_FILE found — skipping line ratchet check"
    exit 0
fi

# Parse the TOML (simple grep — no toml parser needed for this flat structure)
CEILING=$(grep '^ceiling' "$RATCHET_FILE" | head -1 | sed 's/.*= *//')
TARGET=$(grep '^target' "$RATCHET_FILE" | head -1 | sed 's/.*= *//')
FILE_PATH=$(grep '^path' "$RATCHET_FILE" | head -1 | sed 's/.*= *"//' | sed 's/"//')

if [[ -z "$CEILING" || -z "$FILE_PATH" ]]; then
    echo "ERROR: Could not parse $RATCHET_FILE"
    exit 1
fi

if [[ ! -f "$FILE_PATH" ]]; then
    echo "ERROR: Monitored file not found: $FILE_PATH"
    exit 1
fi

ACTUAL=$(wc -l < "$FILE_PATH" | tr -d ' ')

echo "Line ratchet: $FILE_PATH"
echo "  actual:  $ACTUAL lines"
echo "  ceiling: $CEILING lines"
echo "  target:  $TARGET lines"
echo "  remaining: $((ACTUAL - TARGET)) lines to extract"

if [[ "$ACTUAL" -gt "$CEILING" ]]; then
    echo ""
    echo "VIOLATION: $FILE_PATH has $ACTUAL lines (ceiling: $CEILING)"
    echo "You added $((ACTUAL - CEILING)) lines above the ratchet ceiling."
    echo "Extract code into sub-modules to stay under the limit."
    if [[ "$STRICT" == "true" ]]; then
        exit 1
    fi
elif [[ "$ACTUAL" -le "$TARGET" ]]; then
    echo ""
    echo "TARGET REACHED: $FILE_PATH is at or below $TARGET lines!"
else
    echo ""
    echo "OK: $ACTUAL <= $CEILING"
fi
