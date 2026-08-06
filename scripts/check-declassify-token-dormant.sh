#!/usr/bin/env bash
# Declassify-token DORMANCY gate — the premise of a deferral, mechanized.
#
# WHY THIS EXISTS
#
# `DeclassificationToken::allowed_sinks` restricts which sinks declassified data
# may reach. It is signed (`canonical_bytes` count-prefixes it under the
# `nucleus-declass-v2` domain tag), proven (`DeclassifyProofs.lean`
# `sink_outside_allowlist_denied`), and documented — and it is **not enforced on
# the live path**. `FlowGraph::apply_token` raises the target node's label
# GLOBALLY via `modify_label`; `allows_sink()` has no non-test callers. A token
# scoped `allowed_sinks=[WebSearch]` therefore clears its node for GitPush too.
#
# Hardening that properly means operation-aware `gather_labels` (a declassified
# parent contributes its raised label only when the operation is in scope, else
# its original pre-declassify label) plus a per-node scope/original-label field.
# That is real surgery on the live IFC path.
#
# It was DEFERRED, on evidence: the signed-token path is **dormant**. Every
# `DeclassificationToken::new` and every `apply_token` / `apply_declassification_token`
# caller is under `#[cfg(test)]`. Nothing in production mints or applies one, so
# the over-grant is unreachable and the risk budget was better spent elsewhere.
#
# THE PROBLEM WITH THAT: the deferral rests on a premise nobody checks. The day
# someone wires a production caller — a perfectly reasonable thing to do, since
# the API is public and looks finished — the dormant over-grant silently becomes
# a live cross-scope exfiltration path, and the person doing the wiring has no
# reason to know. A deferral whose premise is only recorded in a memory is not a
# control. This gate makes the premise falsifiable: if the path stops being
# dormant, CI says so and points at what must be built first.
#
# So this gate does NOT assert the sink restriction is enforced (it is not). It
# asserts the ONLY reason it is currently safe not to be.
#
# Usage: scripts/check-declassify-token-dormant.sh
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

# The API's own definition sites (where the type and its appliers LIVE) are not
# callers. Everything else that names these symbols must be test code.
DEFINING_FILES=(
  "crates/portcullis-core/src/declassify.rs"          # the type + allows_sink
  "crates/portcullis/src/flow_graph.rs"               # apply_token / apply_token_verified
  "crates/portcullis/src/kernel/declassify_authority.rs" # kernel apply + one-shot ledger
)

# Symbols whose appearance OUTSIDE the defining files means a caller exists.
PATTERN='DeclassificationToken::new|apply_declassification_token|\.apply_token(_verified)?\('

fail=0
found_any=0

# Strip `#[cfg(test)]` modules and `mod tests` blocks, then look for callers.
# A python stripper rather than grep -v: a caller inside a test module is fine,
# and only a structural strip can tell the difference reliably.
report=$(python3 - "$PATTERN" "${DEFINING_FILES[@]}" <<'PY'
import re, subprocess, sys, os

pattern = re.compile(sys.argv[1])
defining = set(sys.argv[2:])

files = subprocess.run(
    ["git", "ls-files", "crates/*.rs", "*.rs"],
    capture_output=True, text=True, check=True,
).stdout.split()

def strip_test_code(src: str) -> str:
    """Blank out #[cfg(test)] items and any `mod tests` body, brace-matched."""
    out = []
    i = 0
    n = len(src)
    while i < n:
        m = re.compile(r'#\[cfg\(test\)\]|(?:pub\s+)?mod\s+tests\b').search(src, i)
        if not m:
            out.append(src[i:])
            break
        out.append(src[i:m.start()])
        # Walk to the first '{' after the marker, then brace-match to its close.
        j = src.find('{', m.start())
        if j == -1:
            # e.g. `#[cfg(test)] mod tests;` — a declaration, nothing to strip.
            eol = src.find('\n', m.start())
            i = n if eol == -1 else eol
            continue
        depth = 0
        k = j
        while k < n:
            if src[k] == '{':
                depth += 1
            elif src[k] == '}':
                depth -= 1
                if depth == 0:
                    break
            k += 1
        i = k + 1
    return ''.join(out)

hits = []
for f in files:
    if not f.endswith('.rs') or f in defining:
        continue
    # Test code by LOCATION: integration-test dirs, and the repo idiom of a
    # `#[cfg(test)] #[path = "foo_tests.rs"] mod tests;` sidecar file (the file
    # itself carries no cfg attribute — its INCLUSION is what is gated — so a
    # within-file strip cannot see it).
    if '/tests/' in f or f.startswith('tests/') or f.endswith('_tests.rs'):
        continue
    try:
        src = open(f, errors='replace').read()
    except OSError:
        continue
    if not pattern.search(src):
        continue
    stripped = strip_test_code(src)
    # Strip string literals across the WHOLE file, not per line: these symbols
    # are NAMED inside multi-line error messages ("… — use
    # apply_declassification_token() (fail-closed)"), where the opening quote is
    # on an earlier line, so a per-line strip cannot see that it is in a string.
    # A mention is not a call.
    stripped = re.sub(r'"(?:[^"\\]|\\.)*"', '""', stripped, flags=re.S)
    for line in stripped.split('\n'):
        s = line.strip()
        if s.startswith('//') or s.startswith('*'):
            continue
        if pattern.search(line):
            hits.append(f"{f}: {s[:100]}")

for h in hits:
    print(h)
raise SystemExit(1 if hits else 0)
PY
) && dormant=0 || dormant=$?

if [ "$dormant" -eq 0 ]; then
  echo "ok  declassify-token path is DORMANT — no production caller mints or applies a token."
  echo "    The unenforced allowed_sinks restriction is therefore unreachable, which is the"
  echo "    premise the deferral rests on. Premise still true."
else
  echo "FAIL a PRODUCTION caller of the declassification-token path now exists:"
  echo "$report" | sed 's/^/       /'
  echo ""
  echo "    This gate is not objecting to the caller. It is telling you that the caller"
  echo "    activates a KNOWN, UNENFORCED over-grant: allowed_sinks is signed, proven and"
  echo "    documented, but FlowGraph::apply_token raises the target node's label GLOBALLY"
  echo "    (modify_label), so a token scoped to one sink clears its node for EVERY sink."
  echo "    allows_sink() has no non-test callers."
  echo ""
  echo "    Before shipping a production path, enforce the scope: make gather_labels"
  echo "    operation-aware (a declassified parent contributes its raised label only when"
  echo "    the operation is in the token's allowed_sinks, else its pre-declassify label),"
  echo "    which needs a per-node declassify-scope + original-label field. Then delete"
  echo "    this gate in the same change — its whole job is to stop exactly this from"
  echo "    landing silently."
  fail=1
fi

exit $fail
