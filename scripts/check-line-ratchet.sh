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

# Parse EVERY [[files]] entry, not just the first.
#
# This script used to read `grep '^ceiling' | head -1`, so it enforced only the
# FIRST entry — while .line-ratchet.toml declared three. The other two drifted
# far past their stated ceilings (tool-proxy 4975 vs a declared 4118; node 4042
# vs 3252) with CI reporting green the whole time. A gate that states a
# confident falsehood about what it enforces is worse than no gate, so the
# ceilings were reset to measured truth when this was fixed; they ratchet down
# from there.
#
# One awk pass emits "path ceiling target" per [[files]] block, so the global
# [ratchet] defaults cannot be mistaken for a file entry and no array-offset
# arithmetic is needed. Portable to bash 3.2 (macOS) — no `mapfile`.
ENTRIES=$(awk '
    /^\[\[files\]\]/ { infile = 1; path = ""; ceiling = ""; target = ""; next }
    /^\[/ && !/^\[\[files\]\]/ { infile = 0 }
    infile && /^path[ \t]*=/    { gsub(/.*= *"|"/, ""); path = $0 }
    infile && /^ceiling[ \t]*=/ { gsub(/.*= */, ""); ceiling = $0 }
    infile && /^target[ \t]*=/  { gsub(/.*= */, ""); target = $0
                                   if (path != "" && ceiling != "") print path, ceiling, target }
' "$RATCHET_FILE")

if [[ -z "$ENTRIES" ]]; then
    echo "ERROR: Could not parse any [[files]] entry from $RATCHET_FILE"
    exit 1
fi

violations=0
while read -r FILE_PATH CEILING TARGET; do
    [[ -z "$FILE_PATH" ]] && continue

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
        violations=$((violations + 1))
    elif [[ "$ACTUAL" -le "$TARGET" ]]; then
        echo ""
        echo "TARGET REACHED: $FILE_PATH is at or below $TARGET lines!"
    else
        echo ""
        echo "OK: $ACTUAL <= $CEILING"
    fi
    echo ""
done <<< "$ENTRIES"

if [[ "$violations" -gt 0 && "$STRICT" == "true" ]]; then
    exit 1
fi
