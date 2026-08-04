#!/usr/bin/env bash
# Fail-closed verifier gate — a verifier may never succeed when it cannot check.
#
# THE RULE
#
#   An ENFORCER may refuse when it cannot act.
#   A VERIFIER may never SUCCEED when it cannot check.
#
# "I was unable to look" and "I looked and it was fine" are different answers,
# and only one of them is safe to return from a function whose caller kills a
# process on Err and proceeds on Ok.
#
# THE INSTANCE THIS GATE WAS BUILT FROM (2026-07-26)
#
# `firecracker_config::verify_seccomp_active` had a platform stub:
#
#     #[cfg(not(target_os = "linux"))]
#     pub(crate) fn verify_seccomp_active(_pid: u32) -> Result<(), String> {
#         // Seccomp is Linux-only; skip verification on other platforms.
#         Ok(())
#     }
#
# Its caller in nucleus-node/src/main.rs is deliberately fail-closed, and says
# so: "a process whose seccomp filter cannot be confirmed active is killed and
# the launch is aborted rather than left running unconfined. The previous
# behavior only logged a warning and continued (fail-open)."
#
# The stub reintroduced exactly that fail-open behaviour for every non-Linux
# build, one layer below the comment that forbade it. Fixing the instance
# without gating the class lets it come back, so this gate exists.
#
# WHAT IT CHECKS
#
# Any `#[cfg(not(target_os = "..."))]`-gated function whose NAME says it
# verifies (verify_/check_/assert_/ensure_/validate_/is_/has_) and whose body
# returns success (`Ok(())`, `true`) is a failure. Cleanup and enforcement
# functions are untouched: `cleanup_network` returning Ok off Linux is correct,
# because there is genuinely nothing to clean up.
#
# WHAT IT DOES NOT CATCH — declared, because a gate that hides its own blind
# spot is the thing this repo keeps finding:
#   * a vacuous verifier that is not cfg-gated (an `if !supported { return
#     Ok(()) }` early return reads the same way and is invisible here);
#   * a verifier whose name does not say it verifies;
#   * a verifier that returns a success-shaped value other than Ok(())/true.
# This gate covers the platform-stub shape, which is the one that actually
# occurred, and no more.
#
# Run locally: `bash scripts/check-failclosed-verifiers.sh`

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

python3 - <<'PY'
import re
import subprocess
import sys

files = subprocess.run(
    ["git", "ls-files", "crates/*.rs", "crates/**/*.rs"],
    capture_output=True, text=True, check=False,
).stdout.split()

VERIFIER = re.compile(r"^(verify|check|assert|ensure|validate|is|has)_|^(is|has)[A-Z]")
SUCCEEDS = re.compile(r"\bOk\(\(\)\)|\breturn true\b|^\s*true\s*$", re.M)

violations = []
for path in files:
    if not path.endswith(".rs"):
        continue
    try:
        src = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        continue
    # A cfg(not(target_os = ...)) attribute, then the next fn, then its body.
    for m in re.finditer(
        r'#\[cfg\(not\(target_os\s*=\s*"[^"]+"\)\)\][\s\S]{0,240}?'
        r'fn\s+(\w+)[^{]*\{([\s\S]{0,400}?)\n\}',
        src,
    ):
        name, body = m.group(1), m.group(2)
        if VERIFIER.match(name) and SUCCEEDS.search(body):
            line = src[: m.start()].count("\n") + 1
            violations.append((path, line, name))

if violations:
    print("", file=sys.stderr)
    print("fail-closed verifier gate: a verifier reports SUCCESS on a platform "
          "where it cannot check.", file=sys.stderr)
    print("", file=sys.stderr)
    for path, line, name in violations:
        print(f"  ✗ {path}:{line}  {name}", file=sys.stderr)
    print("", file=sys.stderr)
    print("An enforcer may refuse when it cannot act; a verifier may never "
          "succeed when it cannot check.", file=sys.stderr)
    print("Return an Err naming the reason, so the caller's fail-closed branch "
          "runs instead of its success branch.", file=sys.stderr)
    sys.exit(1)

print("fail-closed verifier gate: OK (no cfg-gated verifier returns success)")
PY
