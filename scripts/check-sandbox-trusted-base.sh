#!/usr/bin/env bash
# Sandbox trusted-base gate — the manifest must reference tests that exist, and
# the unpinned set may only shrink.
#
# `sandbox-trusted-base.txt` enumerates everything a nucleus pod's isolation
# boundary rests on. A manifest is worth nothing if its references are not
# checked: "pinned_by:some_test" is prose until something confirms `some_test`
# is a real test in the tree. That is what this gate does, and it is the same
# discipline as a non-vacuity ledger whose witness theorems must exist and
# compile.
#
# THREE CHECKS
#
#   1. every `pinned_by:<name>` names a test function that EXISTS
#   2. the UNPINNED count does not rise (ratchet, both directions — if it falls,
#      lower the ceiling, because an allowance that is never tightened becomes a
#      budget)
#   3. every line parses into exactly one of pinned_by / UNPINNED / EXTERNAL, so
#      a component cannot be added without declaring which it is
#
# WHAT THIS GATE DOES NOT DO — declared, because a trusted-base manifest that
# hides its own gap is committing the error it exists to prevent:
#
#   * It cannot prove the manifest is COMPLETE. Nothing here says every real
#     component of the boundary has a line. That is the manifest's own fullness
#     failure and it is not closable from inside — the same limit the olog
#     assurance graph records about itself.
#   * It checks that a named test exists, NOT that the test is any good. A test
#     named `foo` that asserts `true` satisfies this gate.
#   * EXTERNAL entries are asserted, not verified. We cannot pin Firecracker's
#     device emulation from here; naming it is the whole contribution.
#
# Run locally: `bash scripts/check-sandbox-trusted-base.sh`

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

MANIFEST="sandbox-trusted-base.txt"
CEILING_FILE=".sandbox-unpinned-ceiling"

python3 - "$MANIFEST" "$CEILING_FILE" <<'PY'
import re
import subprocess
import sys

manifest, ceiling_file = sys.argv[1], sys.argv[2]

lines = [
    l.rstrip("\n")
    for l in open(manifest, encoding="utf-8")
    if l.strip() and not l.lstrip().startswith("#")
]

rust = subprocess.run(
    ["git", "ls-files", "crates/*.rs", "crates/**/*.rs"],
    capture_output=True, text=True, check=False,
).stdout.split()
corpus = ""
for p in rust:
    if p.endswith(".rs"):
        try:
            corpus += open(p, encoding="utf-8", errors="replace").read()
        except OSError:
            pass

errors, unpinned = [], 0
for raw in lines:
    if "|" not in raw:
        errors.append(f"unparseable line (no `|`): {raw.strip()}")
        continue
    component, claim = (s.strip() for s in raw.split("|", 1))
    if claim.startswith("pinned_by:"):
        test = claim.split(":", 1)[1].strip()
        # The test must exist as a real fn in the tree.
        if not re.search(rf"\bfn\s+{re.escape(test)}\s*\(", corpus):
            errors.append(
                f"{component}: names test `{test}`, which does not exist in crates/"
            )
    elif claim.startswith("UNPINNED:"):
        unpinned += 1
        if len(claim.split(":", 1)[1].strip()) < 20:
            errors.append(f"{component}: UNPINNED needs a real reason, not a word")
    elif claim.startswith("EXTERNAL:"):
        if len(claim.split(":", 1)[1].strip()) < 20:
            errors.append(f"{component}: EXTERNAL needs a real justification")
    else:
        errors.append(
            f"{component}: must declare pinned_by:/UNPINNED:/EXTERNAL:, got {claim[:40]!r}"
        )

try:
    ceiling = int(open(ceiling_file).read().strip())
except Exception:
    print(f"FAIL: missing or unreadable {ceiling_file}", file=sys.stderr)
    sys.exit(1)

print(f"sandbox trusted base: {len(lines)} components, {unpinned} UNPINNED "
      f"(ceiling {ceiling})")

if errors:
    print("", file=sys.stderr)
    for e in errors:
        print(f"  ✗ {e}", file=sys.stderr)
    print("", file=sys.stderr)
    print("A manifest whose references are not checked is prose.", file=sys.stderr)
    sys.exit(1)

if unpinned > ceiling:
    print(f"\nFAIL: the unpinned set grew {ceiling} -> {unpinned}. A component of "
          f"the isolation boundary was added without a test pinning it.",
          file=sys.stderr)
    sys.exit(1)
if unpinned < ceiling:
    print(f"\nFAIL: it shrank {ceiling} -> {unpinned}; lower the ceiling. An "
          f"allowance that is not tightened becomes a budget.", file=sys.stderr)
    sys.exit(1)

print("sandbox trusted-base gate: OK (every pin names a real test)")
PY
