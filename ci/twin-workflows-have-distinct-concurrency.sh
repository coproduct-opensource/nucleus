#!/usr/bin/env bash
#
# Two workflows may share a NAME. They must not share a CONCURRENCY GROUP.
#
# This repo pairs each path-filtered workflow with a `-noop` twin carrying the
# SAME `name:` and the SAME job name, so a required status context is reported
# on every PR whether or not the relevant paths changed. That part works.
#
# The hazard is that `${{ github.workflow }}` is the DISPLAY NAME, which the
# twins share by design. A concurrency group built from it is therefore
# IDENTICAL for both files:
#
#     group: ${{ github.workflow }}-${{ github.head_ref || github.ref }}
#     cancel-in-progress: <true on pull_request>
#
# The twins are meant to be mutually exclusive, but they are not: `paths-ignore`
# fires whenever ANY changed file falls outside its list, so a PR touching both
# a filtered path and an unfiltered one triggers BOTH. Sharing a group, whichever
# starts second cancels the first, and a CANCELLED check-run makes the PR's
# status rollup FAILURE even though nothing failed.
#
# Measured on one branch before the fix — the cancelled twin alternates:
#
#     sha 1d33c74e   dep-hygiene CANCELLED   dep-hygiene-noop success
#     sha c16a57b8   dep-hygiene success     dep-hygiene-noop CANCELLED
#
# All ten twin pairs in this repo shared a group. Every one of them could stall
# a PR on a check that never actually ran.
#
# Exit 0 clean, 1 on a collision.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

for f in .github/workflows/*.yml .github/workflows/*.yaml; do
    [[ -e "$f" ]] || continue
    name="$(grep -m1 '^name:' "$f" 2>/dev/null | sed 's/^name: *//' || true)"
    group="$(grep -m1 '^  group:' "$f" 2>/dev/null | sed 's/^ *group: *//' || true)"
    # A workflow with no explicit concurrency group cannot collide on one.
    [[ -n "$name" && -n "$group" ]] || continue
    # Tab-separated: the group expression itself contains `||`.
    printf '%s\t%s\t%s\n' "$name" "$group" "$f" >>"$tmp"
done

collisions="$(
    awk -F'\t' '
        { key = $1 FS $2; files[key] = files[key] " " $3; n[key]++ }
        END { for (k in n) if (n[k] > 1) { split(k, p, FS); print p[1] "\t" p[2] "\t" files[k] } }
    ' "$tmp"
)"

if [[ -n "$collisions" ]]; then
    echo "FAIL: workflows share a name AND a concurrency group." >&2
    echo "" >&2
    echo "They will cancel each other, and a cancelled check-run turns the PR's" >&2
    echo "status rollup FAILURE even though no test failed." >&2
    echo "" >&2
    while IFS=$'\t' read -r name group files; do
        echo "  name:  ${name}" >&2
        echo "  group: ${group}" >&2
        echo "  files:${files}" >&2
        echo "" >&2
    done <<<"$collisions"
    echo "Give each file its own group literal (e.g. 'foo-real-' / 'foo-noop-')," >&2
    echo "so cancel-in-progress still supersedes a run's OWN older attempts" >&2
    echo "without the twins killing one another." >&2
    exit 1
fi

echo "OK: no two workflows share both a name and a concurrency group."
exit 0
