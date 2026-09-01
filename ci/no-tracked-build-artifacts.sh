#!/usr/bin/env bash
# No build artifacts in git.
#
# `.gitignore` used to say `/target/`, which is anchored to the workspace root,
# so every NESTED target/ escaped it. One did: tools/nucleus-mediation-lint/target
# was committed — 2664 files, 1269 MB, including two 95.6 MB libclippy_utils
# rlibs. The HEAD tree is 20 MB without it. Every reader of this repository was
# downloading a compiler's output.
#
# It happened twice: the same mistake was repeated in the egress-lint branch
# (1141 files) within an hour of being discovered, because `cargo build` inside
# a tools/ crate followed by `git add -A` is an easy and invisible thing to do.
# A rule that is only a .gitignore line is a rule that gets re-broken.
#
# This is the check. It looks at what is TRACKED, not at the working tree,
# because the working tree is expected to be full of build output.
set -euo pipefail

# Directories that are build output by convention. `target/` is cargo's;
# `.lake/` is Lake's, and the Lean packages are large.
PATTERNS='/target/|^target/|/\.lake/|^\.lake/'

offenders="$(git ls-files | grep -E "$PATTERNS" || true)"

if [ -n "$offenders" ]; then
  count=$(printf '%s\n' "$offenders" | wc -l | tr -d ' ')
  echo "::error::$count tracked build-artifact file(s). These belong to a compiler, not to git:"
  printf '%s\n' "$offenders" | head -20 | sed 's/^/  /'
  if [ "$count" -gt 20 ]; then
    echo "  ... and $((count - 20)) more"
  fi
  echo ""
  echo "Fix: git rm -r --cached <dir>   (the files stay on disk)"
  echo "Then check .gitignore uses an UNANCHORED rule — 'target/', not '/target/'."
  exit 1
fi

# Non-vacuity. A grep that matches nothing looks identical to a grep whose
# pattern has rotted, and this repository has been bitten by exactly that shape
# more than once. Prove the matcher still works before trusting its silence.
probe="tools/example-crate/target/debug/libfoo.rlib"
if ! printf '%s\n' "$probe" | grep -qE "$PATTERNS"; then
  echo "::error::the matcher no longer recognises a known build-artifact path"
  echo "         ($probe) — this check would pass while detecting nothing."
  exit 1
fi

echo "OK: no tracked build artifacts (matcher verified against a known-bad path)."
