#!/usr/bin/env bash
# The Mutation Testing gate, made non-vacuous (#2562).
#
# WHY THIS EXISTS
#
# The required `Mutation Testing` check passed runs whose log said
#   ERROR cargo build failed in an unmutated tree, so no mutants were tested
# because the guard grepped the console for `Found [0-9]+ mutants`, which
# cargo-mutants prints BEFORE the baseline build fails, and the `| tee` on the
# run step (no pipefail) hid the tool's exit status. A gate that reads prose
# is a gate that reads the wrong line.
#
# This reads cargo-mutants' machine report instead: <out>/outcomes.json
# (`cargo mutants --output <out>`), and passes only when
#   * the report exists and parses;
#   * the console log carries no unmutated-tree / baseline-failure preamble;
#   * every mutant that was found was tested (tested == total_mutants);
#   * total_mutants > 0 (an empty run proves nothing);
#   * missed (survived) == 0;
#   * timeout and unviable are within the bounds given (they otherwise pass
#     silently: a timeout is an untested mutant, an unviable one a build error
#     the mutation caused — a few are expected, a flood means the run is not
#     measuring what it claims).
#
# Usage: scripts/check-mutants-report.sh <mutants.out dir> <console log> [max_timeout] [max_unviable]
#        scripts/check-mutants-report.sh --self-test
set -euo pipefail

self_test() {
    local t; t=$(mktemp -d); trap "rm -rf '$t'" EXIT
    local me; me="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
    # 1. the exact vacuous case: preamble in the log, no report
    mkdir -p "$t/none"
    printf 'Found 574 mutants to test\nERROR cargo build failed in an unmutated tree, so no mutants were tested\n' > "$t/none.log"
    if bash "$me" "$t/none" "$t/none.log" >/dev/null 2>&1; then echo "::error::self-test: the unmutated-tree failure PASSED"; exit 1; fi
    # 2. a clean report
    mkdir -p "$t/ok"
    cat > "$t/ok/outcomes.json" <<'J'
{"outcomes":[{"scenario":"Baseline","summary":"Success"},{"scenario":{"Mutant":{"file":"a.rs"}},"summary":"CaughtMutant"},{"scenario":{"Mutant":{"file":"b.rs"}},"summary":"CaughtMutant"}],
 "total_mutants":2,"missed":0,"caught":2,"timeout":0,"unviable":0,"success":0,"failure":0}
J
    printf 'Found 2 mutants to test\n2 mutants tested: 2 caught\n' > "$t/ok.log"
    bash "$me" "$t/ok" "$t/ok.log" >/dev/null 2>&1 || { echo "::error::self-test: the clean report FAILED"; exit 1; }
    # 3. a survivor
    mkdir -p "$t/miss"; sed 's/"missed":0,"caught":2/"missed":1,"caught":1/' "$t/ok/outcomes.json" > "$t/miss/outcomes.json"
    if bash "$me" "$t/miss" "$t/ok.log" >/dev/null 2>&1; then echo "::error::self-test: a MISSED mutant PASSED"; exit 1; fi
    # 4. found more than tested (a crashed run)
    mkdir -p "$t/partial"; sed 's/"total_mutants":2/"total_mutants":5/' "$t/ok/outcomes.json" > "$t/partial/outcomes.json"
    if bash "$me" "$t/partial" "$t/ok.log" >/dev/null 2>&1; then echo "::error::self-test: tested < total PASSED"; exit 1; fi
    # 5. timeouts over the bound
    mkdir -p "$t/to"; sed 's/"timeout":0/"timeout":3/; s/"total_mutants":2/"total_mutants":5/' "$t/ok/outcomes.json" > "$t/to/outcomes.json"
    if bash "$me" "$t/to" "$t/ok.log" 2 >/dev/null 2>&1; then echo "::error::self-test: timeouts over the bound PASSED"; exit 1; fi
    echo "ok: self-test — unmutated-tree failure, missed mutant, partial run and excess timeouts each red; a clean report green"
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit 0; fi

OUT=${1:?mutants.out dir}
LOG=${2:?console log}
MAX_TIMEOUT=${3:-5}
MAX_UNVIABLE=${4:-50}
fail=0

if grep -qE "unmutated tree|baseline.*(failed|FAILED)|cargo (build|test) failed" "$LOG" 2>/dev/null; then
    echo "::error::cargo-mutants could not build or test the UNMUTATED tree — no mutant was tested:"
    grep -E "unmutated tree|baseline|failed" "$LOG" | head -5
    fail=1
fi

REPORT="$OUT/outcomes.json"
if [ ! -s "$REPORT" ]; then
    echo "::error::$REPORT is missing or empty — cargo-mutants wrote no machine report, so 'no survived mutants' means nothing"
    exit 1
fi
jq -e . "$REPORT" >/dev/null 2>&1 || { echo "::error::$REPORT is not valid JSON"; exit 1; }

# Aggregate counts: cargo-mutants writes them at the top level of outcomes.json
# (total_mutants, caught, missed, timeout, unviable); fall back to counting the
# per-scenario summaries if a version moves them.
read -r total caught missed timeout unviable < <(jq -r '
  def n($k): (.[$k] // 0);
  if has("total_mutants") then [n("total_mutants"), n("caught"), n("missed"), n("timeout"), n("unviable")]
  else ([.outcomes[]? | select(.scenario != "Baseline")] as $m |
        [($m|length),
         ($m|map(select(.summary=="CaughtMutant"))|length),
         ($m|map(select(.summary=="MissedMutant"))|length),
         ($m|map(select(.summary=="Timeout"))|length),
         ($m|map(select(.summary=="Unviable"))|length)])
  end | @tsv' "$REPORT")
tested=$((caught + missed + timeout + unviable))

echo "mutants: total=$total tested=$tested caught=$caught missed=$missed timeout=$timeout unviable=$unviable"

if [ "$total" -le 0 ]; then echo "::error::0 mutants — an empty run proves nothing"; fail=1; fi
if [ "$tested" -ne "$total" ]; then echo "::error::$tested of $total mutants were tested — the run did not complete"; fail=1; fi
if [ "$missed" -ne 0 ]; then
    echo "::error::$missed mutant(s) SURVIVED in security-critical modules:"
    jq -r '.outcomes[]? | select(.summary=="MissedMutant") | .scenario.Mutant | "  \(.file):\(.line // "?") \(.function // "") — \(.replacement // .genre // "")"' "$REPORT" 2>/dev/null | head -20
    [ -s "$OUT/missed.txt" ] && head -20 "$OUT/missed.txt"
    fail=1
fi
if [ "$timeout" -gt "$MAX_TIMEOUT" ]; then echo "::error::$timeout mutants timed out (bound $MAX_TIMEOUT) — timeouts are untested mutants"; fail=1; fi
if [ "$unviable" -gt "$MAX_UNVIABLE" ]; then echo "::error::$unviable unviable mutants (bound $MAX_UNVIABLE) — the build is rejecting mutations wholesale"; fail=1; fi

[ "$fail" -eq 0 ] && echo "ok: $tested tested / $caught caught / $missed survived / $timeout timeout / $unviable unviable"
exit $fail
