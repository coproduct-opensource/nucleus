#!/usr/bin/env bash
# Audit finding M-3 ratchet: forbid non-strict Ed25519 (`ed25519-dalek`)
# re-verification on any production trust path.
#
# Non-strict `VerifyingKey::verify(...)` uses the *cofactored* verification
# equation and accepts small-order / non-canonical public keys and `R`
# points. A single crafted "identity-triple" signature then verifies under
# multiple identities → key-substitution / weak signature-to-identity
# binding. The strict inherent method `VerifyingKey::verify_strict(...)`
# rejects those points. Every dalek trust-path re-verify MUST use
# `verify_strict`.
#
# This gate FAILS (exit 1) if any *production* (non-`#[cfg(test)]`) call to
# the dalek two-argument `.verify(msg, &sig)` reappears in a file that
# imports `ed25519_dalek`, unless the exact call is listed (with a reason)
# in scripts/verify-strict-allowlist.txt.
#
# Scope rationale (deliberately conservative to avoid false NEGATIVES):
#   * Only files that mention `ed25519_dalek` are scanned, so `ring`
#     (portcullis, nucleus-identity) and `p256` (nucleus-agent-card JWK)
#     `.verify(` paths — which are NOT dalek and have no `verify_strict` —
#     are never considered.
#   * `#[cfg(test)]` modules/items are stripped before matching, so
#     test-only `.verify(` calls do not trip the gate.
#   * Single-argument wrapper calls (e.g. `Receipt::verify(&vk)`,
#     `SignedTreeHead::verify(&witness)`) are NOT dalek leaf calls; the
#     two-argument `(_, &sig)` shape distinguishes the leaf. Any wrapper
#     that still trips the pattern is listed in the allowlist.
#
# Usage: scripts/check-verify-strict.sh
set -euo pipefail

cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

ALLOWLIST="scripts/verify-strict-allowlist.txt"

# Prefer ripgrep (fast, honours .gitignore); fall back to POSIX grep so the
# gate runs on any host or CI image without extra tooling.
list_dalek_files() {
    if command -v rg >/dev/null 2>&1; then
        rg -l --glob '*.rs' 'ed25519_dalek' crates
    else
        grep -rl --include='*.rs' 'ed25519_dalek' crates
    fi \
        | grep -vE '/(tests|benches)/'   # integration tests/benches are test-only
}

# Load allowlist: non-empty, non-comment lines are literal code snippets
# that are permitted to contain `.verify(` on a trust path (each with a
# reason in a preceding comment).
allow_snippets=()
if [[ -f "$ALLOWLIST" ]]; then
    while IFS= read -r line; do
        # Trim leading/trailing whitespace.
        trimmed="${line#"${line%%[![:space:]]*}"}"
        trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
        [[ -z "$trimmed" ]] && continue
        [[ "$trimmed" == \#* ]] && continue
        allow_snippets+=("$trimmed")
    done < "$ALLOWLIST"
fi

# AWK program that emits `path:lineno:code` for every production line
# (outside any #[cfg(test)] block) that contains a non-strict two-argument
# dalek `.verify(` call. Brace-balanced #[cfg(test)] block stripping.
read -r -d '' AWK_PROG <<'AWK' || true
BEGIN { skip=0; brace=0; pending=0 }
{
    line=$0
    # Count braces on this line without mutating the record we print.
    tmp=line; no=gsub(/\{/,"{",tmp)
    tmp=line; nc=gsub(/\}/,"}",tmp)

    if (skip==1) {
        brace += no - nc
        if (brace <= 0) { skip=0; brace=0 }
        next
    }
    if (line ~ /#\[cfg\(test\)\]/) { pending=1 }
    if (pending==1 && no>0) {
        skip=1
        brace = no - nc
        pending=0
        if (brace <= 0) { skip=0; brace=0 }
        next
    }
    # Skip comment lines (`//`, `///`, `//!`) — doc/example prose, not code.
    stripped=line; sub(/^[[:space:]]+/,"",stripped)
    if (stripped ~ /^\/\//) { next }
    # Production line. Flag non-strict, two-argument dalek verify:
    #   `.verify(` ... `,` ... `&` (a message and a &signature),
    # but never `.verify_strict(`.
    if (line ~ /\.verify[[:space:]]*\(/ && line !~ /verify_strict/ && line ~ /,[[:space:]]*&/) {
        printf "%s:%d:%s\n", FILENAME, FNR, line
    }
}
AWK

# Files in scope: production Rust sources that reference the dalek crate.
hits=()
while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    while IFS= read -r rec; do
        [[ -z "$rec" ]] && continue
        code="${rec#*:*:}"
        trimmed="${code#"${code%%[![:space:]]*}"}"
        trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
        allowed=0
        if [[ "${#allow_snippets[@]}" -gt 0 ]]; then
            for snip in "${allow_snippets[@]}"; do
                if [[ "$trimmed" == "$snip" ]]; then allowed=1; break; fi
            done
        fi
        [[ "$allowed" -eq 1 ]] && continue
        hits+=("$rec")
    done < <(awk "$AWK_PROG" "$f")
done < <(list_dalek_files || true)

if [[ "${#hits[@]}" -gt 0 ]]; then
    echo "M-3 verify-strict gate FAILED: non-strict dalek .verify(...) on a trust path:" >&2
    printf '  %s\n' "${hits[@]}" >&2
    echo >&2
    echo "Fix: use VerifyingKey::verify_strict(msg, &sig) instead of .verify(...)." >&2
    echo "If this is a legitimate non-dalek call, add the exact line to" >&2
    echo "$ALLOWLIST with a justifying comment." >&2
    exit 1
fi

echo "M-3 verify-strict gate PASSED: no non-strict dalek .verify(...) on any trust path."
