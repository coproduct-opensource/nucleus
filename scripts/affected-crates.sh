#!/usr/bin/env bash
# Print the workspace crates a change touches, closed under reverse
# dependencies: the crates whose sources changed plus every workspace crate
# that (transitively) depends on one of them. A change to portcullis-core must
# re-test nucleus-node, not just portcullis-core.
#
# Usage:
#   scripts/affected-crates.sh <base-ref>            # from `git diff base...HEAD`
#   scripts/affected-crates.sh --crates a b c        # from an explicit list
#   scripts/affected-crates.sh <base-ref> --cargo    # as `-p a -p b ...`
#
# Prints nothing when nothing under crates/ changed. Exits 3 (and prints
# "ALL") when a workspace-wide file changed (Cargo.toml, Cargo.lock, .github/,
# rust-toolchain*), because then no per-crate scoping is sound.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

fmt=names
seeds=()
case "${1:-}" in
    --crates) shift; while [ $# -gt 0 ] && [ "$1" != "--cargo" ]; do seeds+=("$1"); shift; done ;;
    "") echo "usage: $0 <base-ref> [--cargo] | --crates <name>... [--cargo]" >&2; exit 2 ;;
    *)  base=$1; shift
        changed=$(git diff --name-only "$base...HEAD")
        if printf '%s\n' "$changed" | grep -qE '^(Cargo\.toml|Cargo\.lock|rust-toolchain(\.toml)?|\.cargo/|\.github/)'; then
            echo ALL; exit 3
        fi
        while read -r c; do [ -n "$c" ] && seeds+=("$c"); done < <(printf '%s\n' "$changed" | grep -oE '^crates/[^/]+' | sed 's#^crates/##' | sort -u)
        ;;
esac
[ "${1:-}" = "--cargo" ] && fmt=cargo
[ ${#seeds[@]} -eq 0 ] && exit 0

# Directory name -> package name, plus the workspace's path-dependency graph.
meta=$(cargo metadata --format-version 1 2>/dev/null)
# "pkg dep" edges between workspace members only.
edges=$(printf '%s' "$meta" | jq -r '
  .workspace_members as $ws
  | [.packages[] | select(.id as $i | $ws | index($i))] as $pk
  | ($pk | map({key: (.manifest_path | sub("/Cargo.toml$"; "") | sub(".*/"; "")), value: .name}) | from_entries) as $dir2name
  | ($pk | map(.name)) as $names
  | ($pk[] | .name as $n | .dependencies[] | select(.path != null) | select(.name as $d | $names | index($d)) | "\($n) \(.name)"),
    ($dir2name | to_entries[] | "DIR \(.key) \(.value)")')

declare -a affected=()
for s in "${seeds[@]}"; do
    n=$(printf '%s\n' "$edges" | awk -v d="$s" '$1=="DIR" && $2==d {print $3; exit}')
    [ -z "$n" ] && n=$s   # already a package name, or not a workspace member (kept; cargo will say so)
    affected+=("$n")
done
# Fixed point over reverse edges.
while :; do
    before=${#affected[@]}
    for a in "${affected[@]}"; do
        while read -r r; do
            [ -z "$r" ] && continue
            found=0; for x in "${affected[@]}"; do [ "$x" = "$r" ] && found=1 && break; done
            [ $found -eq 0 ] && affected+=("$r")
        done < <(printf '%s\n' "$edges" | awk -v d="$a" '$1!="DIR" && $2==d {print $1}')
    done
    [ ${#affected[@]} -eq "$before" ] && break
done
printf '%s\n' "${affected[@]}" | sort -u > /tmp/affected.$$
if [ "$fmt" = cargo ]; then
    sed 's/^/-p /' /tmp/affected.$$ | tr '\n' ' '; echo
else
    cat /tmp/affected.$$
fi
rm -f /tmp/affected.$$
