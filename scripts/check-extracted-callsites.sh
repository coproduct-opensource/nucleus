#!/usr/bin/env bash
# C8 — the extracted predicates are re-checked against LIVE code, not dead code.
#
# WHY THIS EXISTS
#
# The Aeneas-extracted predicates (`nucleus_ifc_kernel::extracted::*`) carry the
# flagship noninterference/mediation theorems, and `aeneas-ifc-scoped.yml`
# re-extracts + parity-tests + re-proves them on every change to their production
# domain (now `crates/nucleus-ifc-kernel/**`). But that proves the extracted
# slice EQUALS the production enforcement types — it does not prove the
# enforcement is still WIRED into the live path. A predicate proven about a
# function no shipping code calls is a proof about dead code, and the spawn path
# that calls it lives in `nucleus-tool-proxy`, a crate the proof workflow's
# trigger does not even cover.
#
# So this gate closes the call-site half: for each entry in
# `scripts/extracted-callsites-manifest.txt`, it asserts the named anchor still
# appears in a NON-test region of the named production file. Deleting the live
# call site reds the gate. It is cheap (grep only) and runs on every PR via
# ci.yml, so it covers the live-path crates the heavy proof job does not.
#
# ANTI-VACUITY (three guards, deliberately):
#   1. It greps the anchor in the PRODUCTION region only — `#[cfg(test)]` blocks
#      are brace-stripped — so a call that exists only in a test does not satisfy
#      it. It judges the RESULT (enforcement is wired), not that a symbol exists
#      somewhere.
#   2. It requires >=1 match per entry AND prints the per-entry count, so an
#      absent file or a renamed symbol is a loud red, not a silent zero.
#   3. The manifest pins COUNT=<n>; a family silently leaving coverage reds here.
#
# Usage: scripts/check-extracted-callsites.sh
set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

MANIFEST="scripts/extracted-callsites-manifest.txt"
[[ -f "$MANIFEST" ]] || { echo "ERROR: $MANIFEST not found"; exit 1; }

# Emit each production line (outside any #[cfg(test)] block) containing literal
# PAT. Brace-balanced cfg(test) stripping; skips comment lines. (Same shape as
# scripts/check-mediation.sh, the established production-region scanner.)
read -r -d '' AWK_PROG <<'AWK' || true
BEGIN { skip=0; brace=0; pending=0 }
{
    line=$0
    tmp=line; no=gsub(/\{/,"{",tmp)
    tmp=line; nc=gsub(/\}/,"}",tmp)
    if (skip==1) { brace += no - nc; if (brace <= 0) { skip=0; brace=0 } next }
    if (line ~ /#\[cfg\(test\)\]/) { pending=1; next }
    if (pending==1) {
        if (no>0) {
            skip=1; brace = no - nc; pending=0
            if (brace <= 0) { skip=0; brace=0 }
            next
        }
        if (line ~ /;/) { pending=0 }
    }
    stripped=line; sub(/^[[:space:]]+/,"",stripped)
    if (stripped ~ /^\/\//) { next }
    if (index(line, PAT) > 0) { printf "%s:%d:%s\n", FILENAME, FNR, line }
}
AWK

failures=0
entries=0
fail() { echo "  FAIL  $1"; failures=$((failures + 1)); }

pinned="$(grep -E '^COUNT=' "$MANIFEST" | head -1 | cut -d= -f2 | tr -d '[:space:]')"
if [[ -z "$pinned" ]]; then
    echo "ERROR: $MANIFEST must pin COUNT=<n>"; exit 1
fi

# Rows: CLASS | predicate | anchor | file | note
while IFS= read -r raw; do
    line="${raw%%#*}"                             # strip trailing comments
    [[ -z "${line// }" ]] && continue             # blank
    [[ "$line" == COUNT=* ]] && continue
    [[ "$line" != *"|"* ]] && continue            # not a table row

    IFS='|' read -r cls pred anchor file note <<< "$line"
    cls="$(echo "$cls" | xargs)"; pred="$(echo "$pred" | xargs)"
    anchor="$(echo "$anchor" | xargs)"; file="$(echo "$file" | xargs)"
    [[ -z "$cls" || -z "$pred" || -z "$anchor" || -z "$file" ]] && continue
    entries=$((entries + 1))

    case "$cls" in A|B|C) : ;; *) fail "$pred: unknown class '$cls' (want A|B|C)";; esac

    if [[ ! -f "$file" ]]; then
        fail "$pred: anchor file does not exist: $file (a moved/renamed enforcement file is NOT the same as isolated — report it)"
        continue
    fi

    count="$(awk -v PAT="$anchor" "$AWK_PROG" "$file" | wc -l | tr -d ' ')"
    if [[ "$count" -lt 1 ]]; then
        fail "$pred [$cls]: anchor '$anchor' has 0 production occurrences in $file — the extracted predicate's live call site is gone; the proof would be about dead code"
    else
        echo "  ok    $pred [$cls]: '$anchor' × $count in $file (production region)"
    fi
done < "$MANIFEST"

echo
# Population ratchet: the manifest cannot silently shrink.
if [[ "$entries" -ne "$pinned" ]]; then
    fail "manifest has $entries entries but pins COUNT=$pinned — a family left (or joined) coverage; update COUNT in the same change so the shift is on the record"
fi
# Non-vacuity: refuse to pass on an empty manifest.
if [[ "$entries" -lt 1 ]]; then
    echo "ERROR: no manifest entries parsed — the gate examined nothing and proved nothing"; exit 1
fi

if [[ "$failures" -gt 0 ]]; then
    echo "FAILED: $failures problem(s). An extracted predicate's live call site is missing —"
    echo "the theorem about it would be a proof about code that no longer ships."
    exit 1
fi
echo "OK: all $entries manifest-covered extracted predicates have a live production"
echo "call site (production region, test blocks excluded). COUNT=$pinned pinned."
