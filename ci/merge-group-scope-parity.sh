#!/usr/bin/env bash
# The gate's PATTERN must agree with the workflow's own declared `paths:`.
#
# WHY: `paths:` under `merge_group:` parses and is then ignored by GitHub, so
# each gated workflow re-implements its scope as a regex. Two copies of one
# fact drift. If someone widens `paths:` and forgets the regex, the merge queue
# silently stops running a proof that the PR still runs — a gate that is green
# because it never fires, which is the failure mode this repo keeps finding.
#
# So: every path prefix declared in the `on:` block must be matched by the
# gate's own PATTERN.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
found=0

for f in .github/workflows/*.yml; do
  grep -q 'id: scope' "$f" || continue
  found=$((found + 1))
  pattern=$(sed -n "s/^          PATTERN: '\(.*\)'\$/\1/p" "$f" | head -1)
  if [ -z "$pattern" ]; then
    echo "::error::$f has 'id: scope' but no PATTERN"; fail=1; continue
  fi
  n=0
  while IFS= read -r d; do
    [ -n "$d" ] || continue
    probe="${d%%\**}"                     # crates/x/lean/** -> crates/x/lean/
    [ -n "$probe" ] || continue
    n=$((n + 1))
    if ! printf '%s\n' "$probe" | grep -qE "$pattern"; then
      echo "::error::$(basename "$f"): declared path '$d' is NOT matched by the gate PATTERN"
      echo "    PATTERN: $pattern"
      fail=1
    fi
  done <<EOF
$(sed -n '/^on:/,/^permissions:/p' "$f" | sed -n -e 's/^ *- *"\([^"]*\)".*$/\1/p' -e "s/^ *- *'\([^']*\)'.*\$/\1/p" | sort -u)
EOF
  if [ "$n" -eq 0 ]; then
    # A gated workflow whose paths we cannot read makes this check green
    # without ever testing anything — the exact defect it exists to prevent.
    echo "::error::$(basename "$f"): gated, but no declared paths were parsed — check is vacuous here"
    fail=1
  else
    echo "ok: $(basename "$f") — $n declared paths matched"
  fi
done

if [ "$found" -eq 0 ]; then
  echo "::error::no gated workflows found — this check would be vacuous"; exit 1
fi
exit $fail
