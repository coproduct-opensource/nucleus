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

# The unanalysed declaration's OWN pin, checked before anything expensive runs.
#
# `.clippy-unanalysed.txt` says "PINNED may only SHRINK. Adding a crate here is a
# deliberate, dated act", and the two errors below tell a reader to "raise PINNED"
# and "lower PINNED" -- while nothing in the tree read that number. Verified
# 2026-09-11: no script, gate or workflow parsed it. So a crate could be added to
# the list, the count would shrink by its cast sites, and the pin would sit there
# saying 1 with nothing comparing it to anything. That is the shape gatehouse F-52
# records in its own CLAUDE.md: a file asserting a control that does not exist,
# and the assertion is what makes it dangerous, because a reader checks the pin
# and stops looking.
#
# The set checks further down need a full clippy run to know what FAILED. This one
# needs neither a build nor a toolchain -- it compares two numbers in one committed
# file -- so it runs first and fails fast.
UNANALYSED_FILE=".clippy-unanalysed.txt"
[ -f "$UNANALYSED_FILE" ] || { echo "::error::$UNANALYSED_FILE missing"; exit 1; }
PIN=$(grep -oE '^#[[:space:]]*PINNED[[:space:]]*=[[:space:]]*[0-9]+' "$UNANALYSED_FILE" | grep -oE '[0-9]+$' || true)
if [ -z "$PIN" ]; then
  echo "::error::$UNANALYSED_FILE carries no '# PINNED = <n>' line." >&2
  echo "The file's own header promises one, and the errors below tell a reader to" >&2
  echo "raise and lower it. A pin that is not there is worse than no pin: it reads" >&2
  echo "as a control while being prose." >&2
  exit 1
fi
ENTRIES=$(grep -vE '^\s*(#|$)' "$UNANALYSED_FILE" | sort -u | grep -c . || true)
if [ "$ENTRIES" != "$PIN" ]; then
  echo "::error::$UNANALYSED_FILE lists $ENTRIES crate(s) but PINNED = $PIN." >&2
  if [ "$ENTRIES" -gt "$PIN" ]; then
    echo "A crate was added and the pin was not raised. Every crate here is cast" >&2
    echo "sites MISSING from the ratcheted count, so growing this list lowers the" >&2
    echo "number without touching the ceiling. Raise PINNED in the same change and" >&2
    echo "say why, dated." >&2
  else
    echo "A crate was removed and the pin was not lowered. Lower PINNED in the same" >&2
    echo "change -- an un-lowered pin is slack the next addition inherits silently." >&2
  fi
  exit 1
fi

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
# The lint set is the one parsed from the toml at the top of this file, passed
# in rather than restated. It used to be `startswith("clippy::cast")`, which
# agreed with the toml only because every tracked lint happened to be a cast:
# the `-W` flags came from the toml and the COUNT came from a hardcoded prefix,
# so any non-cast lint added to `lints` would have been warned by clippy and
# then counted as zero. The ceiling would never move and the gate would report
# OK while tracking nothing -- a gate that cannot fail, which is exactly what
# `check-gates-can-fail.sh` exists to forbid.
COUNT=$(jq -r --arg lints "$LINTS" '($lints | split("\n") | map(select(length > 0))) as $tracked
           | select(.reason=="compiler-message") | .message
           | select(.level=="warning" or .level=="error")
           | (.code.code // "") as $c
           | select(($tracked | index($c)) != null)
           | (.spans[] | select(.is_primary)) as $s
           | "\($s.file_name):\($s.line_start):\($s.column_start):\(.code.code)"' "$RAW" \
  | sort -u | wc -l | tr -d ' ')
rm -f "$RAW"

# Never report a partial count as if it were whole. The set of crates clippy
# could not analyse is DECLARED in .clippy-unanalysed.txt and checked both ways:
# an undeclared failure means the count silently shrank, and a declared crate
# that now compiles means the declaration is stale and the count is about to
# rise. Before this, both were a `::warning::` that nothing failed on -- and the
# ceiling comment in .clippy-ratchet.toml records what that cost:
# "455 was never the workspace's real count; it was the count of the crates that
# happened to build."
DECLARED=$(grep -vE '^\s*(#|$)' "$UNANALYSED_FILE" 2>/dev/null | sort -u || true)
UNDECLARED=$(comm -23 <(printf '%s\n' "$FAILED" | grep -v '^$' | sort -u) <(printf '%s\n' "$DECLARED"))
STALE=$(comm -13 <(printf '%s\n' "$FAILED" | grep -v '^$' | sort -u) <(printf '%s\n' "$DECLARED"))

if [ -n "$FAILED" ]; then
  echo "::notice::crates not analysed (declared in $UNANALYSED_FILE):" >&2
  echo "$FAILED" | sed 's/^/  /' >&2
fi
if [ -n "$UNDECLARED" ]; then
  echo "::error::these crates did not compile and are NOT declared in $UNANALYSED_FILE:" >&2
  echo "$UNDECLARED" | sed 's/^/  /' >&2
  echo "The count below is missing their cast sites. Fix the crate, or declare it" >&2
  echo "with a dated reason and raise PINNED." >&2
  exit 1
fi
if [ -n "$STALE" ]; then
  echo "::error::these crates are declared unanalysable in $UNANALYSED_FILE but COMPILE now:" >&2
  echo "$STALE" | sed 's/^/  /' >&2
  echo "Remove them and lower PINNED. Expect the count to RISE: that is coverage" >&2
  echo "going up, not a regression." >&2
  exit 1
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
