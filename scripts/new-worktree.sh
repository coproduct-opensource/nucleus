#!/usr/bin/env bash
# Bootstrap a git worktree that actually builds — fresh worktrees are missing
# two things the long-lived checkout has, and both failure modes look like
# unrelated errors hours later:
#
#   1. sdks/verifier-js/pkg/ (wasm-pack artifact): nucleus-verifier-service
#      include_str!s it, so any workspace-wide build/hook fails without it.
#   2. A warm target/: the pre-push hook's full-workspace test otherwise
#      builds a fresh ~4.5G target/ per worktree (one disk-full incident on
#      record).
#
# Usage: scripts/new-worktree.sh <branch> [base]   (base defaults to origin/main)
set -euo pipefail

branch="${1:?usage: scripts/new-worktree.sh <branch> [base]}"
base="${2:-origin/main}"
root="$(git rev-parse --show-toplevel)"
wt_root="${WORKTREE_ROOT:-$(dirname "$root")/.worktrees}"
wt_dir="$wt_root/$(basename "$root")-${branch//\//-}"

git -C "$root" fetch origin --quiet
git -C "$root" worktree add "$wt_dir" -b "$branch" "$base"

if [ -d "$root/sdks/verifier-js/pkg" ]; then
    cp -R "$root/sdks/verifier-js/pkg" "$wt_dir/sdks/verifier-js/pkg"
else
    echo "warn: $root/sdks/verifier-js/pkg not found — workspace-wide builds in the" >&2
    echo "      worktree will fail until you run: wasm-pack build sdks/verifier-js" >&2
fi

cat <<DONE
Worktree ready: $wt_dir

Reminders (each learned the hard way):
  - Share the warm build cache instead of growing a fresh 4.5G target/:
        export CARGO_TARGET_DIR=$root/target
    (or push with --no-verify after 'just preflight' — CI is authoritative)
  - If the PR is auto-merge-armed, DISARM before pushing follow-up commits
    (gh pr merge --disable-auto), then re-arm — the merge queue can take the
    PR without them, and the late push silently recreates a dead branch.
  - Never pipe 'git commit' through tail/head: the pipe eats the hook's
    exit code and a failed commit looks like a success.
  - When done: git worktree remove $wt_dir   (deletes its target/ too)
DONE
