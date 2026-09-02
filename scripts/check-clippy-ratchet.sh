#!/usr/bin/env bash
# Count violations of the ratcheted clippy lint set and compare to the ceiling.
#
# Mirrors scripts/check-line-ratchet.sh: `--strict` fails when the count is
# ABOVE the ceiling; `--count` just prints the number (used by the ratchet-down
# job on main).
set -euo pipefail
cd "$(dirname "$0")/.."

RATCHET_FILE=".clippy-ratchet.toml"
[ -f "$RATCHET_FILE" ] || { echo "::error::$RATCHET_FILE missing"; exit 1; }

# The lint list lives in the toml so the gate and its documentation cannot drift.
LINTS=$(sed -n '/^lints = \[/,/^]/p' "$RATCHET_FILE" | grep -oE '"[^"]+"' | tr -d '"')
[ -n "$LINTS" ] || { echo "::error::no lints parsed from $RATCHET_FILE"; exit 1; }

# Cargo caches per crate, and clippy re-emits warnings ONLY for crates it
# actually recompiles. Measured directly, three consecutive runs of this script
# returned 379, 306 and 351 for an unchanged tree — the number tracked cache
# state, not the code. A ratchet built on that would pass or fail at random.
#
# Touching the workspace sources forces every first-party crate to be
# re-analysed while dependency artifacts stay cached: correct AND fast.
find crates -name '*.rs' -not -path '*/target/*' -exec touch {} +

FLAGS=(-A clippy::all)
for l in $LINTS; do FLAGS+=(-W "$l"); done

# `-A clippy::all` first so ONLY the ratcheted lints are counted; without it the
# ordinary warning set would be mixed in and the number would mean nothing.
# Count UNIQUE (file, line, column, lint) sites, not raw messages. A file
# compiled as both lib and test yields the same warning twice, and the split
# varies with what cargo happens to rebuild -- which made consecutive runs
# report 406 and 404 for an unchanged tree. A site is the thing being ratcheted.
# Cargo exits nonzero when any crate fails to compile, and a crate that does
# not compile is never analysed -- so the count would silently shrink to
# "however much happened to build". Capture the run, count the sites, and
# report the failures rather than letting either disappear.
RAW=$(mktemp)
set +e
# RUSTFLAGS is cleared for the MEASUREMENT run. CI (setup-rust-toolchain)
# exports `-D warnings`, which promotes the tracked cast lints from `warning`
# to `error` — and the jq below selects on level. The count came back 0 on CI
# for exactly that reason while reading 457 locally: not a clean tree, an
# ambient flag leaking into a measurement.
#
# Counting is not gating. This script decides pass/fail from the count against
# the ceiling; it must not also inherit someone else's promotion policy.
RUSTFLAGS= cargo clippy --workspace --all-targets --keep-going --message-format=json -- "${FLAGS[@]}" >"$RAW" 2>/dev/null
set -e

FAILED=$(jq -r 'select(.reason=="compiler-message") | .message
                | select(.level=="error") | (.spans[]? | select(.is_primary) | .file_name)' "$RAW" \
         | cut -d/ -f2 | sort -u)

# Unique (file, line, column, lint) SITES, not raw messages: a file compiled as
# both lib and test yields the same warning twice, and which targets cargo
# rebuilds varies -- consecutive runs reported 406 then 404 on an unchanged
# tree before this dedupe.
COUNT=$(jq -r 'select(.reason=="compiler-message") | .message
           | select(.level=="warning" or .level=="error")
           | select((.code.code // "") | startswith("clippy::cast"))
           | (.spans[] | select(.is_primary)) as $s
           | "\($s.file_name):\($s.line_start):\($s.column_start):\(.code.code)"' "$RAW" \
  | sort -u | wc -l | tr -d ' ')
rm -f "$RAW"

if [ -n "$FAILED" ]; then
  # Never report a partial count as if it were whole.
  echo "::warning::crates that did NOT compile, so were NOT analysed:" >&2
  echo "$FAILED" | sed 's/^/  /' >&2
fi

case "${1:---count}" in
  --count) echo "$COUNT" ;;
  --strict)
    # NON-VACUITY FLOOR. A count of zero is not "the code got clean" — this
    # workspace has hundreds of tracked cast sites. Zero means the measurement
    # failed: clippy produced no countable output, which happens when the build
    # errors out before analysing anything. Without this, the ratchet PASSES on
    # a broken build, which is a gate that cannot go red.
    #
    # Found by its own falsifier (`ratchet-falsifier` in clippy-ratchet.yml):
    # setting the ceiling to 0 should have RED-ed and did not, because 0 > 0 is
    # false. The falsifier earned itself on its first CI run.
    if [ "$COUNT" -eq 0 ]; then
      echo "::error::the ratcheted-lint count came back 0, which this workspace \
cannot honestly produce. The clippy run failed to yield countable output — \
treat this as a broken measurement, not a clean tree."
      exit 1
    fi
    CEILING=$(grep '^ceiling' "$RATCHET_FILE" | head -1 | sed 's/.*= *//')
    echo "ratcheted clippy violations: $COUNT (ceiling $CEILING)"
    if [ "$COUNT" -gt "$CEILING" ]; then
      echo "::error::clippy ratchet exceeded: $COUNT > $CEILING."
      echo "  The tracked lints are numeric-cast lints, where a violation is a"
      echo "  truncation/sign bug waiting to happen rather than a style nit."
      echo "  Fix the new cast (or justify it with a scoped #[allow] and a comment)."
      exit 1
    fi
    echo "ok: at or below the ceiling"
    ;;
  *) echo "usage: $0 [--strict|--count]"; exit 2 ;;
esac
