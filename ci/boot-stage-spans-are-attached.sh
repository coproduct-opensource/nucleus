#!/usr/bin/env bash
# A `boot.stage` span must annotate the function it claims to measure.
#
# WHY: `wait_for_proxy_health` moved out of main.rs into guest_diagnosis (#2355)
# and its `#[tracing::instrument(... boot.stage = "proxy.health_wait")]` stayed
# behind. Rust attributes bind to the FOLLOWING item regardless of blank lines
# between them, so the attribute silently reattached to `serve_grpc` — a server
# that runs for the node's whole lifetime.
#
# That compiled, ran, and produced a boot trace in which 92% of pod-create wall
# time was `unaccounted` (#2374): the largest span in a launch had no
# instrumentation, and a long-lived task was mislabelled as a boot stage.
#
# Two mechanical checks. Neither can prove a span measures the RIGHT work, but
# both catch the way this actually broke.
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
files=$(grep -rl 'boot.stage' --include='*.rs' crates/ || true)
[ -n "$files" ] || { echo "::error::no boot.stage attributes found at all; the scan looks broken"; exit 1; }

# 1. A blank line between the attribute and its item. Legal Rust, and exactly how
#    the attribute got orphaned onto the wrong function.
# shellcheck disable=SC2086  # $files is a newline-separated list; splitting is intended
detached=$(awk '
  /#\[tracing::instrument.*boot\.stage/ { pending = 1; line = FILENAME ":" FNR; next }
  pending && /^[[:space:]]*$/ { print line "  (blank line before the item it annotates)"; pending = 0; next }
  pending { pending = 0 }
' $files)

if [ -n "$detached" ]; then
  echo "::error::boot.stage attributes separated from the item they annotate:"
  printf '%s\n' "$detached" | awk '{ print "  " $0 }'
  echo "  Rust binds an attribute to the next item regardless, so this is how a span"
  echo "  ends up measuring a function nobody meant to measure."
  fail=1
fi

# 2. Two functions claiming one stage name double-count it in the breakdown.
stages=$(grep -rhoE 'boot\.stage = "[a-z0-9_.]+"' --include='*.rs' crates/ | sed 's/.*= "//;s/"//' | sort)
n=$(printf '%s\n' "$stages" | wc -l | tr -d ' ')
if [ "$n" -lt 8 ]; then
  echo "::error::only $n boot.stage declarations parsed; the scan looks broken"
  exit 1
fi
dupes=$(printf '%s\n' "$stages" | uniq -d)
if [ -n "$dupes" ]; then
  echo "::error::boot.stage names claimed more than once (they double-count):"
  printf '%s\n' "$dupes" | awk '{ print "  " $0 }'
  fail=1
fi

[ "$fail" -eq 0 ] && echo "ok: $n boot.stage spans, each attached to its item, names unique"
exit $fail
