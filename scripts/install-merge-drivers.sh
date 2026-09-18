#!/usr/bin/env bash
# Install this repository's merge drivers into THIS clone.
#
# A merge driver cannot be committed: git deliberately refuses to run one a
# repository defines for you, because a driver is arbitrary code. `.gitattributes`
# names the driver; this sets it up. Run it once per clone (and per worktree's
# parent repository).
#
# `keep-ours` resolves a derived file to the current branch's text so a rebase
# does not stop on a number that is about to be re-measured anyway. See
# `.gitattributes` for which files and why.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
git config merge.keep-ours.name "keep this branch's text; the value is re-measured afterwards"
git config merge.keep-ours.driver true
echo "installed: merge.keep-ours"
echo
echo "After a rebase that touched a derived file, record what the merged tree measures:"
echo "    cargo run -p xtask -- scorecard --write"
