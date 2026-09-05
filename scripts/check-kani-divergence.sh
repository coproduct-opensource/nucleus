#!/usr/bin/env bash
# Every `cfg(kani)` divergence between the verified model and the shipped code
# is enumerated, justified, and ratcheted (#2574).
#
# WHY THIS EXISTS
#
# Kani verifies the crate compiled with `--cfg kani`. Every `#[cfg(not(kani))]`
# is code the proofs never see, and every `#[cfg(kani)]` outside a harness is
# code that exists ONLY for the proofs. Both are places where the property the
# harness proves and the property the binary has can differ. Today the largest
# family is `CapabilityLattice::extensions` / `ExposureSet::extensions`: the
# BTreeMap/BTreeSet fields are compiled out under Kani, so meet/join/leq, the
# certificate digest, and `UninhabitableState::is_triggered` all take a
# different path in the proof than in production. That is a legitimate
# tractability trade, but an UNLISTED one is a proof silently narrowed.
#
# So: every attribute-form `cfg(kani)` site in crates/**/*.rs must appear in
# kani-divergence.toml with a class and a justification, the inventory may not
# name a site that no longer exists, the declared `total` must equal the census,
# and — against a base ref — the total may only shrink.
#
# Usage:
#   scripts/check-kani-divergence.sh            # gate (exit 1 on any drift)
#   scripts/check-kani-divergence.sh --report   # print the census in inventory shape
#   scripts/check-kani-divergence.sh --count    # print the census total only
#
# Env:
#   KANI_DIVERGENCE_BASE=<git ref>   compare `total` against that ref's inventory;
#                                    growth fails unless KANI_DIVERGENCE_ALLOW_GROWTH=1
#
# A "site" is (file, attribute line, guarded line): the attribute exactly as
# written, and the first following line that is not an attribute, comment, or
# blank. Identical triples in one file are one entry with `count = N` — the
# sixteen `extensions: BTreeMap::new()` constructors in lattice.rs are one
# decision, not sixteen. A whole-file `#![cfg(kani)]` guards the file itself.
# Mentions inside comments and the `rustc-check-cfg` line in build.rs are not
# sites: they change nothing about what is compiled.

set -euo pipefail

INVENTORY="kani-divergence.toml"
MODE="gate"
case "${1:-}" in
    --report) MODE="report" ;;
    --count)  MODE="count" ;;
    "") ;;
    *) echo "usage: $0 [--report|--count]" >&2; exit 2 ;;
esac

SITE_RE='^[[:space:]]*#!?\[cfg\(kani\)\]|^[[:space:]]*#\[cfg\(not\(kani\)\)\]|^[[:space:]]*#\[cfg_attr\(kani[,)]'

# census: "file<TAB>attr<TAB>guards" one line per site (not yet deduplicated).
census() {
    local f
    grep -rlE --include='*.rs' --exclude-dir=target "$SITE_RE" crates 2>/dev/null | LC_ALL=C sort | while read -r f; do
        awk -v file="$f" '
            function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
            function emit(g) { printf "%s\t%s\t%s\n", file, attr, g; pending = 0 }
            {
                line = trim($0)
                if (pending) {
                    if (inattr) { if (line ~ /\]$/) inattr = 0; next }
                    if (line == "" || line ~ /^\/\//) next
                    if (line ~ /^#\[/) { if (line !~ /\]$/) inattr = 1; next }
                    emit(line)
                }
                if (line ~ /^#!\[cfg\(kani\)\]$/) {
                    attr = line; printf "%s\t%s\t%s\n", file, attr, "<whole file>"; next
                }
                if (line ~ /^#\[cfg\(kani\)\]$/ || line ~ /^#\[cfg\(not\(kani\)\)\]$/ || line ~ /^#\[cfg_attr\(kani[,)]/) {
                    attr = line; pending = 1; inattr = (line !~ /\]$/)
                }
            }
            END { if (pending) emit("<end of file>") }
        ' "$f"
    done
}

# dedup: "count<TAB>file<TAB>attr<TAB>guards"
census_grouped() {
    census | LC_ALL=C sort | uniq -c | sed -E 's/^[[:space:]]*([0-9]+) /\1\t/'
}

toml_escape() { sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'; }

if [[ "$MODE" == "count" ]]; then
    census | wc -l | tr -d ' '
    exit 0
fi

if [[ "$MODE" == "report" ]]; then
    total=$(census | wc -l | tr -d ' ')
    echo "# census: $total attribute-form cfg(kani) sites"
    echo "total = $total"
    census_grouped | while IFS=$'\t' read -r n file attr guards; do
        echo
        echo "[[site]]"
        echo "file = \"$file\""
        echo "attr = \"$(printf '%s' "$attr" | toml_escape)\""
        echo "guards = \"$(printf '%s' "$guards" | toml_escape)\""
        [[ "$n" -gt 1 ]] && echo "count = $n"
        echo "class = \"\""
        echo "why = \"\""
    done
    exit 0
fi

# ── gate ──────────────────────────────────────────────────────────────────

if [[ ! -f "$INVENTORY" ]]; then
    echo "ERROR: $INVENTORY not found — every cfg(kani) site must be inventoried"
    exit 1
fi

DECLARED_TOTAL=$(awk '/^total[ \t]*=/ { gsub(/.*=[ \t]*/, ""); print; exit }' "$INVENTORY")
if [[ -z "$DECLARED_TOTAL" ]]; then
    echo "ERROR: $INVENTORY has no top-level 'total = N'"
    exit 1
fi

# One awk pass turns every [[site]] block into "count<TAB>file<TAB>attr<TAB>guards",
# and rejects a block missing a field or an empty justification. Portable to
# bash 3.2 / BSD awk: no gensub, no mapfile.
INVENTORY_ROWS=$(awk '
    function unq(s) { sub(/^[ \t]*"/, "", s); sub(/"[ \t]*$/, "", s); gsub(/\\"/, "\"", s); gsub(/\\\\/, "\\", s); return s }
    function flush() {
        if (!insite) return
        if (file == "" || attr == "" || guards == "") { printf "BAD\tincomplete [[site]] ending at line %d (file/attr/guards required)\n", NR; bad = 1 }
        else if (class == "" || why == "") { printf "BAD\t%s: site \"%s\" needs a non-empty class and why\n", file, attr; bad = 1 }
        else printf "%d\t%s\t%s\t%s\n", count, file, attr, guards
    }
    /^\[\[site\]\]/ { flush(); insite = 1; file = ""; attr = ""; guards = ""; class = ""; why = ""; count = 1; next }
    insite && /^file[ \t]*=/   { sub(/^file[ \t]*=/, ""); file = unq($0) }
    insite && /^attr[ \t]*=/   { sub(/^attr[ \t]*=/, ""); attr = unq($0) }
    insite && /^guards[ \t]*=/ { sub(/^guards[ \t]*=/, ""); guards = unq($0) }
    insite && /^class[ \t]*=/  { sub(/^class[ \t]*=/, ""); class = unq($0) }
    insite && /^why[ \t]*=/    { sub(/^why[ \t]*=/, ""); why = unq($0) }
    insite && /^count[ \t]*=/  { sub(/^count[ \t]*=[ \t]*/, ""); count = $0 + 0 }
    END { flush(); if (bad) exit 3 }
' "$INVENTORY") || { echo "$INVENTORY_ROWS" | grep '^BAD' | sed 's/^BAD\t/ERROR: /'; exit 1; }

failures=0

expected=$(mktemp); actual=$(mktemp)
trap 'rm -f "$expected" "$actual"' EXIT

# Expand counts so a multiset diff is a plain line diff.
printf '%s\n' "$INVENTORY_ROWS" | awk -F'\t' '$1 > 0 { for (i = 0; i < $1; i++) printf "%s\t%s\t%s\n", $2, $3, $4 }' | LC_ALL=C sort > "$expected"
census | LC_ALL=C sort > "$actual"

ACTUAL_TOTAL=$(wc -l < "$actual" | tr -d ' ')
LISTED_TOTAL=$(wc -l < "$expected" | tr -d ' ')

unlisted=$(LC_ALL=C comm -13 "$expected" "$actual" || true)
stale=$(LC_ALL=C comm -23 "$expected" "$actual" || true)

if [[ -n "$unlisted" ]]; then
    echo "UNLISTED cfg(kani) sites (add each to $INVENTORY with a class and a justification):"
    printf '%s\n' "$unlisted" | awk -F'\t' '{ printf "  %s\n      %s\n      -> %s\n", $1, $2, $3 }'
    failures=$((failures + 1))
fi
if [[ -n "$stale" ]]; then
    echo "STALE inventory entries (site no longer in the tree — remove it and lower total):"
    printf '%s\n' "$stale" | awk -F'\t' '{ printf "  %s\n      %s\n      -> %s\n", $1, $2, $3 }'
    failures=$((failures + 1))
fi
if [[ "$DECLARED_TOTAL" -ne "$ACTUAL_TOTAL" ]]; then
    echo "TOTAL mismatch: $INVENTORY declares total = $DECLARED_TOTAL, the tree has $ACTUAL_TOTAL sites (inventory lists $LISTED_TOTAL)"
    failures=$((failures + 1))
fi

# Shrink-only ratchet against a base ref (CI passes the PR's base SHA).
if [[ -n "${KANI_DIVERGENCE_BASE:-}" ]]; then
    base="$KANI_DIVERGENCE_BASE"
    if ! git cat-file -e "$base^{commit}" 2>/dev/null; then
        git fetch --quiet --depth=1 origin "$base" || { echo "ERROR: cannot fetch base ref $base"; exit 1; }
        git cat-file -e "$base^{commit}" 2>/dev/null || base="FETCH_HEAD"
    fi
    if git cat-file -e "$base:$INVENTORY" 2>/dev/null; then
        BASE_TOTAL=$(git show "$base:$INVENTORY" | awk '/^total[ \t]*=/ { gsub(/.*=[ \t]*/, ""); print; exit }')
        if [[ -n "$BASE_TOTAL" && "$ACTUAL_TOTAL" -gt "$BASE_TOTAL" ]]; then
            if [[ "${KANI_DIVERGENCE_ALLOW_GROWTH:-0}" == "1" ]]; then
                echo "NOTE: divergence total grew $BASE_TOTAL -> $ACTUAL_TOTAL; growth explicitly allowed for this run"
            else
                echo "GROWTH: divergence total is $ACTUAL_TOTAL, base ($KANI_DIVERGENCE_BASE) had $BASE_TOTAL — the ceiling only shrinks."
                echo "  Prefer a Kani-tractable representation over a new cfg(kani) fork. If the fork is"
                echo "  the right call, an owner sets KANI_DIVERGENCE_ALLOW_GROWTH=1 (the 'kani-divergence-growth' PR label)."
                failures=$((failures + 1))
            fi
        else
            echo "ratchet: total $ACTUAL_TOTAL <= base $BASE_TOTAL"
        fi
    else
        echo "ratchet: base $KANI_DIVERGENCE_BASE has no $INVENTORY; nothing to shrink from"
    fi
fi

if [[ "$failures" -gt 0 ]]; then
    echo
    echo "FAIL: cfg(kani) divergence inventory out of sync ($failures problem class(es))."
    echo "      Run scripts/check-kani-divergence.sh --report for the census in inventory shape."
    exit 1
fi

echo "OK: $ACTUAL_TOTAL cfg(kani) sites, all inventoried and justified in $INVENTORY (total = $DECLARED_TOTAL)"
