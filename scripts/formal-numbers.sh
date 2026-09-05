#!/usr/bin/env bash
# Recount the formal-methods numbers the docs publish, and fail on drift.
#
# #2478: the headline counts (Kani harnesses, open `sorry` holes) live in
# FORMAL_METHODS.md, NORTH_STAR.md and CONJECTURES.md, and every one of them
# had drifted from the tree. This script is the single recount both a human
# and CI run; `--print` shows the fresh numbers, the default mode compares them
# with what the docs state and exits 1 on any mismatch, and `--write` rewrites
# every number the check reads (the three docs, the bare-grep aside, the
# `.kani-minimum-proofs` census, and the `total =` of kani-divergence.toml when
# its entries already match the tree) so a drift is one command to fix instead
# of a reconciliation commit per PR — four ratchets collided across PRs on
# 2026-09-05 alone. `just census` is the alias.
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

bare_kani="$({ grep -rc '#\[kani::proof\]' crates --include='*.rs' 2>/dev/null || true; } | awk -F: '{s+=$2} END{print s+0}')"

if [ "$mode" = "--write" ]; then
  changed=0
  # rewrite <file> <sed-expr> <what>: apply, report when the file changed.
  rewrite() {
    local before; before="$(cat "$1")"
    sed -i.bak -E "$2" "$1" && rm -f "$1.bak"
    if [ "$before" != "$(cat "$1")" ]; then echo "  wrote $1: $3"; changed=1; fi
  }
  bt='`'
  rewrite FORMAL_METHODS.md 's/Total: [0-9]+ Kani BMC harnesses repo-wide/Total: '"$total_kani"' Kani BMC harnesses repo-wide/' "Kani total $total_kani"
  rewrite FORMAL_METHODS.md 's/([0-9]+) Kani BMC proofs in the '"$bt"'portcullis'"$bt"' crate \([0-9]+ repo-wide\)/\1 Kani BMC proofs in the '"$bt"'portcullis'"$bt"' crate ('"$total_kani"' repo-wide)/' "repo-wide aside $total_kani"
  rewrite FORMAL_METHODS.md 's/\| [0-9]+ harnesses repo-wide \(/| '"$total_kani"' harnesses repo-wide (/' "table total $total_kani"
  rewrite FORMAL_METHODS.md 's/a bare '"$bt"'grep -rc'"$bt"' says [0-9]+ because/a bare '"$bt"'grep -rc'"$bt"' says '"$bare_kani"' because/' "bare-grep aside $bare_kani"
  rewrite FORMAL_METHODS.md 's/[0-9]+ open '"$bt"'sorry'"$bt"' proof holes across [0-9]+/'"$sorry_total"' open '"$bt"'sorry'"$bt"' proof holes across '"$sorry_files"'/' "sorry $sorry_total across $sorry_files"
  while read -r k n; do
    [ -n "$k" ] || continue
    rewrite FORMAL_METHODS.md 's/(^|[^A-Za-z0-9_-])'"$k"' [0-9]+([^0-9]|$)/\1'"$k $n"'\2/g' "$k $n"
  done < <(printf "%b" "$KANI_LINES")
  breakdown="$(printf "%b" "$KANI_LINES" | sort -k2,2nr -k1,1 | awk '{printf "%s%s %s", (NR>1?", ":""), $1, $2}')"
  rewrite NORTH_STAR.md 's#\| Kani BMC harnesses \| [0-9]+ \| [^|]*#| Kani BMC harnesses | '"$total_kani"' | '"$breakdown"' ('"$bt"'scripts/formal-numbers.sh'"$bt"') #' "Kani total $total_kani"
  rewrite NORTH_STAR.md 's/\| \*\*Current\*\* \| [0-9]+ \|/| **Current** | '"$total_kani"' |/' "current $total_kani"
  rewrite NORTH_STAR.md 's/Open '"$bt"'sorry'"$bt"' holes \| [0-9]+ across [0-9]+/Open '"$bt"'sorry'"$bt"' holes | '"$sorry_total"' across '"$sorry_files"'/' "sorry $sorry_total across $sorry_files"
  rewrite "$LEAN/CONJECTURES.md" 's/[0-9]+ proof-hole '"$bt"'sorry'"$bt"' terms across exactly [0-9]+ files/'"$sorry_total"' proof-hole '"$bt"'sorry'"$bt"' terms across exactly '"$sorry_files"' files/' "manifest $sorry_total across $sorry_files"
  if [ -f .kani-minimum-proofs ] && [ "$(tr -d '[:space:]' < .kani-minimum-proofs)" != "$total_kani" ]; then
    echo "$total_kani" > .kani-minimum-proofs; echo "  wrote .kani-minimum-proofs: $total_kani"; changed=1
  fi
  if [ -f kani-divergence.toml ] && [ -x scripts/check-kani-divergence.sh ]; then
    fresh="$(scripts/check-kani-divergence.sh --count)"
    declared="$(awk '/^total[ \t]*=/ { gsub(/.*=[ \t]*/, ""); print; exit }' kani-divergence.toml)"
    if [ "$fresh" != "$declared" ]; then
      # Only the total is regenerable: a NEW site needs a justification entry,
      # which no script can invent. Say which it is.
      if scripts/check-kani-divergence.sh 2>/dev/null | grep -qE 'UNLISTED|STALE'; then
        echo "  kani-divergence.toml: total $declared -> tree $fresh, but entries are out of sync — run scripts/check-kani-divergence.sh and add/remove entries first"
      else
        rewrite kani-divergence.toml 's/^total = [0-9]+$/total = '"$fresh"'/' "divergence total $fresh"
      fi
    fi
  fi
  if [ "$changed" = 0 ]; then echo "formal-methods numbers already agree with the tree; nothing written"; fi
  exec "$0"
fi

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
