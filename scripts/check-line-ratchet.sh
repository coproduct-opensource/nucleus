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

echo "═══════════════════════════════════════════════════════════════════"
echo "Sweep: every crates/*/src/**/*.rs file NOT explicitly listed above"
echo "═══════════════════════════════════════════════════════════════════"
#
# Until this section existed, the ratchet enforced exactly the three files
# an [[files]] entry named — three, out of the several hundred .rs files in
# the workspace. A file that grew unbounded outside those three was
# invisible to this gate, the same shape of blind spot the header comment
# above already documents for "only the first entry": a control that only
# watches what someone remembered to list is not really watching. Found
# while a legitimate, well-justified change (the mTLS SPIFFE auth branch)
# routed its new logic into `auth.rs` specifically because that file had
# no ceiling at all — the untracked sibling of a tracked file is exactly
# where bloat hides from a partial gate.
#
# DEFAULT_CEILING applies to every swept file that has no [[files]] entry
# of its own. It is deliberately generous (2500 — see the seeding rationale
# below) rather than tuned per-file: the three explicit entries above exist
# because someone is actively watching or shrinking those specific files;
# the sweep's job is only to make sure nothing ELSE grows unnoticed, not to
# impose an extraction campaign on the other several hundred files that
# have never needed one.
DEFAULT_CEILING=$(awk '
    /^\[ratchet\]/ { inratchet = 1; next }
    /^\[/           { inratchet = 0 }
    inratchet && /^default_ceiling[ \t]*=/ { gsub(/.*= */, ""); print; exit }
' "$RATCHET_FILE")

if [[ -z "$DEFAULT_CEILING" ]]; then
    echo "ERROR: [ratchet] has no default_ceiling — cannot sweep untracked files"
    exit 1
fi

# The explicitly-covered paths, so the sweep does not re-check (and cannot
# double-count a violation for) a file that already has its own [[files]]
# entry above, however permissive or strict that entry is.
EXPLICIT_PATHS=$(printf '%s\n' "$ENTRIES" | awk '{print $1}')

swept=0
swept_violations=0
while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    if printf '%s\n' "$EXPLICIT_PATHS" | grep -qxF "$f"; then
        continue
    fi
    swept=$((swept + 1))
    actual=$(wc -l < "$f" | tr -d ' ')
    if [[ "$actual" -gt "$DEFAULT_CEILING" ]]; then
        echo "VIOLATION: $f has $actual lines (default ceiling: $DEFAULT_CEILING)"
        echo "  Either extract code to get back under the default, or — if this"
        echo "  file legitimately needs more room and someone is going to watch"
        echo "  it — give it its own [[files]] entry in $RATCHET_FILE seeded at"
        echo "  its measured size, the same way the three tracked files got theirs."
        swept_violations=$((swept_violations + 1))
        violations=$((violations + 1))
    fi
done < <(find crates -path '*/src/*' -name '*.rs' -not -path '*/target/*' 2>/dev/null | sort)

if [[ "$swept_violations" -eq 0 ]]; then
    echo "OK: $swept files swept, all <= $DEFAULT_CEILING lines"
else
    echo ""
    echo "$swept_violations of $swept swept files exceed the default ceiling ($DEFAULT_CEILING)"
fi
echo ""

if [[ "$violations" -gt 0 && "$STRICT" == "true" ]]; then
    exit 1
fi
