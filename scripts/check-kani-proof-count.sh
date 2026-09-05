#!/usr/bin/env bash
# Kani proof-count ratchet — the census of `#[kani::proof]` harnesses (#2561).
#
# WHY THIS EXISTS
#
# The required `Proof Count Ratchet` never asserted anything: the snippet it
# inlined in four workflow sites did `grep -rc … crates/portcullis-core/src/`,
# which on a DIRECTORY prints one `path:count` line per file, so the shell
# arithmetic errored, `PROOF_COUNT` was never set, and `[ "" -lt 72 ]` failed
# inside the `if` — which the gate read as "not less than", and passed. The
# same four copies drifted apart (one counted portcullis-core, others did
# not). One script, counted once, checked numerically, probed by the
# gate-of-gates.
#
# Usage:
#   scripts/check-kani-proof-count.sh --count    # print the integer total
#   scripts/check-kani-proof-count.sh --strict   # fail if total < .kani-minimum-proofs
#   scripts/check-kani-proof-count.sh --report   # per-crate breakdown (stdout)
#
# The floor in .kani-minimum-proofs is the CURRENT count, not a number below
# it: a floor of 110 against 117 harnesses lets seven proofs vanish unnoticed,
# and the gate-of-gates probe (delete one harness → red) only works at the
# exact count. Adding a harness means bumping the file in the same commit —
# the census moves with the code, on purpose.
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

MODE=${1:---strict}
FLOOR_FILE=.kani-minimum-proofs
PATTERN='#\[kani::proof\]'

count_in() { { grep -rho "$PATTERN" "$@" 2>/dev/null || true; } | wc -l | tr -d ' '; }

total=0
breakdown=""
for crate in crates/*/; do
    name=${crate%/}; name=${name#crates/}
    n=0
    for sub in src proofs; do
        [ -d "$crate$sub" ] || continue
        c=$(count_in "$crate$sub")
        case "$c" in ''|*[!0-9]*) echo "::error::non-numeric harness count '$c' for $crate$sub"; exit 2;; esac
        n=$((n + c))
    done
    if [ "$n" -gt 0 ]; then breakdown+="  $name: $n"$'\n'; total=$((total + n)); fi
done
case "$total" in ''|*[!0-9]*) echo "::error::non-numeric total '$total'"; exit 2;; esac

case "$MODE" in
  --count) echo "$total" ;;
  --report) printf 'Kani proof harnesses: %s\n%s' "$total" "$breakdown" ;;
  --strict)
    [ -f "$FLOOR_FILE" ] || { echo "::error::$FLOOR_FILE is missing"; exit 2; }
    floor=$(tr -d '[:space:]' < "$FLOOR_FILE")
    case "$floor" in ''|*[!0-9]*) echo "::error::$FLOOR_FILE does not hold an integer: '$floor'"; exit 2;; esac
    printf 'Kani proof harnesses: %s (floor %s)\n%s' "$total" "$floor" "$breakdown"
    if [ "$total" -lt "$floor" ]; then
        echo "::error::Kani proof count regression: $total < $floor — a harness was deleted or renamed away from #[kani::proof]; restore it or lower $FLOOR_FILE with the reason"
        exit 1
    fi
    if [ "$total" -gt "$floor" ]; then
        echo "::error::$total harnesses but $FLOOR_FILE says $floor — new harnesses must move the census: set $FLOOR_FILE to $total in this change"
        exit 1
    fi
    echo "ok: $total Kani harnesses, census exact"
    ;;
  *) echo "usage: $0 --count|--strict|--report"; exit 2 ;;
esac
