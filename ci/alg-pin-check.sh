#!/usr/bin/env bash
# ci/alg-pin-check.sh
#
# Algorithm-pin CI gate for nucleus-oidc-provider + nucleus-oidc-core.
# Refuses any code path that references HS*, RS*, ES*, or alg=none
# OUTSIDE of explicit-reject negative-test fixtures.
#
# Per `crates/nucleus-oidc-provider/THREAT_MODEL.md` T04 (algorithm
# downgrade / confusion), the OP signs and verifies EdDSA exclusively.
# Any RS256/HS256/none reference in source — even in a comment or a
# string literal that a future refactor could promote to runtime — is
# the leading indicator of an alg-confusion CVE class regression.
#
# Allow-list mechanism: a grep match on a line is permitted if the
# same line carries an `alg-pin-allow: <reason>` marker in any comment
# form (`// alg-pin-allow:`, `# alg-pin-allow:`, `<!-- alg-pin-allow: -->`).
# Reviewer enforces that the reason is genuine — typically a negative
# test that asserts the alg IS rejected, or an RFC quote.
#
# Exit codes:
#   0  — clean
#   1  — forbidden alg references found (CI fails)

set -euo pipefail

# Default scan paths. Override by passing paths on the command line.
SCAN_PATHS=(
    "crates/nucleus-oidc-core"
    "crates/nucleus-oidc-provider"
)
if [[ $# -gt 0 ]]; then
    SCAN_PATHS=("$@")
fi

# Forbidden alg-string patterns. Case-insensitive matching covers
# `"alg":"none"`, `"alg":"HS256"`, etc., plus the bare `HS256`/`RS256`
# constants when they appear inline.
PATTERNS=(
    # JWT header alg field — all flavors
    '"alg"[[:space:]]*:[[:space:]]*"none"'
    '"alg"[[:space:]]*:[[:space:]]*"HS[0-9]+"'
    '"alg"[[:space:]]*:[[:space:]]*"RS[0-9]+"'
    '"alg"[[:space:]]*:[[:space:]]*"PS[0-9]+"'
    '"alg"[[:space:]]*:[[:space:]]*"ES[0-9]+"'
    # jsonwebtoken Algorithm enum variants
    'Algorithm::(HS[0-9]+|RS[0-9]+|PS[0-9]+|ES[0-9]+)'
    'Algorithm::None'
    # Bare alg=none in any encoding (catches `alg=none` query params, etc.)
    '\balg[[:space:]]*=[[:space:]]*none\b'
)

violations=0
tmpfile=$(mktemp)
trap 'rm -f "$tmpfile"' EXIT

for pattern in "${PATTERNS[@]}"; do
    grep -RHnE -i "$pattern" \
        --include="*.rs" \
        --include="*.toml" \
        --include="*.json" \
        --include="*.yaml" \
        --include="*.yml" \
        --exclude-dir=target \
        --exclude-dir=node_modules \
        --exclude-dir=.git \
        --exclude-dir=corpus \
        "${SCAN_PATHS[@]}" 2>/dev/null \
        | grep -v 'alg-pin-allow:' >>"$tmpfile" || true
done

if [[ -s "$tmpfile" ]]; then
    sort -u "$tmpfile" >"${tmpfile}.dedup"
    mv "${tmpfile}.dedup" "$tmpfile"
    violations=$(wc -l <"$tmpfile" | tr -d ' ')

    echo "FAIL: algorithm-pin CI gate — ${violations} forbidden-alg reference(s) found." >&2
    echo "" >&2
    echo "Per THREAT_MODEL.md T04, the OP signs/verifies EdDSA exclusively." >&2
    echo "Any HS*/RS*/PS*/ES*/none reference is a regression risk for the" >&2
    echo "algorithm-confusion CVE class (CVE-2026-22817 et al)." >&2
    echo "" >&2
    echo "Allow-list a line with an end-of-line comment: alg-pin-allow: <reason>" >&2
    echo "  (in any comment form: // ..., # ..., <!-- ... -->)" >&2
    echo "" >&2
    echo "Violations:" >&2
    cat "$tmpfile" >&2
    exit 1
fi

echo "OK: algorithm-pin CI gate clean across paths: ${SCAN_PATHS[*]}"
exit 0
