#!/usr/bin/env bash
# Recount the formal-methods numbers the docs publish, and fail on drift.
#
# #2478: the headline counts (Kani harnesses, open `sorry` holes) live in
# FORMAL_METHODS.md, NORTH_STAR.md and CONJECTURES.md, and every one of them
# had drifted from the tree. This script is the single recount both a human
# and CI run; `--print` shows the fresh numbers, the default mode compares them
# with what the docs state and exits 1 on any mismatch.
#
# Counting rules (the docs cite this script for them):
#   * A Kani harness is a line whose first token is `#[kani::proof` — the
#     attribute, not the string `"#[kani::proof]"` inside nucleus-audit's own
#     counter, nor a doc comment that names the attribute (both of which a bare
#     `grep -rc` counts, which is how the docs came to say 117 for 115).
#   * A proof hole is a `sorry`/`admit` TERM in a .lean file, counted with the
#     same comment-aware awk the proven-tier CI gate uses; `.lake/` and
#     `experiments/` are not part of the tree the gate scans.
set -euo pipefail
cd "$(dirname "$0")/.."

mode="${1:-check}"

kani_count() { { grep -rE '^\s*#\[kani::proof' "$1" --include='*.rs' 2>/dev/null || true; } | wc -l | tr -d ' '; }
# "<crate> <count>" lines (plain arrays: macOS ships bash 3.2, no associative arrays).
KANI_LINES=""
total_kani=0
for d in crates/*/; do
  n="$(kani_count "$d")"
  if [ "$n" != "0" ]; then KANI_LINES="${KANI_LINES}$(basename "$d") $n
"; total_kani=$((total_kani + n)); fi
done

LEAN=crates/portcullis-core/lean
holes="$(cd "$LEAN" && awk 'BEGIN{depth=0} {line=$0; out=""; i=1; L=length(line); while(i<=L){two=substr(line,i,2); if(depth>0){ if(two=="-/"){depth--; i+=2; continue} if(two=="/-"){depth++; i+=2; continue} i++; continue } else { if(two=="/-"){depth++; i+=2; continue} if(two=="--"){break} out=out substr(line,i,1); i++ } } n=gsub(/(^|[^A-Za-z0-9._\x27])(sorry|admit)([^A-Za-z0-9_\x27]|$)/,"&",out); if(n>0) c[FILENAME]+=n} END{t=0; k=0; for(f in c){t+=c[f]; k++} print t, k}' $(find . -name '*.lean' -not -path './.lake/*' -not -path './experiments/*'))"
sorry_total="${holes% *}"; sorry_files="${holes#* }"

if [ "$mode" = "--print" ]; then
  echo "kani harnesses: $total_kani"
  printf "%b" "$KANI_LINES" | sort | sed 's/^/  /'
  echo "open sorry/admit holes: $sorry_total across $sorry_files files"
  exit 0
fi

fail=0
expect() { # expect <file> <regex> <fresh value> <what>
  local got
  got="$(grep -oE "$2" "$1" | head -1 | grep -oE '[0-9]+' | head -1 || true)"
  if [ "$got" != "$3" ]; then
    echo "::error file=$1::$4 says '${got:-<absent>}', fresh count is $3"; fail=1
  fi
}
expect FORMAL_METHODS.md 'Total: [0-9]+ Kani BMC harnesses repo-wide' "$total_kani" "Kani total"
expect FORMAL_METHODS.md '[0-9]+ open `sorry` proof holes across' "$sorry_total" "open sorry count"
expect FORMAL_METHODS.md 'proof holes across [0-9]+' "$sorry_files" "sorry file count"
expect NORTH_STAR.md '\| Kani BMC harnesses \| [0-9]+ \|' "$total_kani" "Kani total"
expect NORTH_STAR.md 'Open `sorry` holes \| [0-9]+ across [0-9]+' "$sorry_total" "open sorry count"
expect "$LEAN/CONJECTURES.md" '[0-9]+ proof-hole `sorry` terms across exactly' "$sorry_total" "manifest sorry count"
expect "$LEAN/CONJECTURES.md" 'across exactly [0-9]+ files' "$sorry_files" "manifest file count"
while read -r k n; do
  [ -n "$k" ] || continue
  expect FORMAL_METHODS.md "$k [0-9]+" "$n" "Kani count for $k"
done < <(printf "%b" "$KANI_LINES")

if [ "$fail" != "0" ]; then
  echo "formal-methods numbers drifted; run scripts/formal-numbers.sh --print and reconcile the docs."
  exit 1
fi
echo "formal-methods numbers agree with the tree: $total_kani Kani harnesses, $sorry_total holes across $sorry_files files."
