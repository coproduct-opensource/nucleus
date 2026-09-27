#!/usr/bin/env bash
# ci/alg-pin-check.sh
#
# Algorithm-pin CI gate for nucleus-oidc-provider + nucleus-oidc-core +
# nucleus-federation. Refuses any code path that references HS*, RS*, ES*,
# or alg=none OUTSIDE of explicit-reject negative-test fixtures.
#
# nucleus-federation is a SECOND issuer with its own pin: it signs ES256 and
# nothing else (distinct `iss` from the EdDSA OP, so T04's one-issuer-one-
# algorithm property holds for each). Its extra checks are at the bottom:
# the pin constant exists once and says ES256, no other signing primitive
# appears in its source, and any bare algorithm-name literal carries a reason.
# What it may VERIFY for an outside issuer is operator config, drawn from an
# enum with no `none`/HS* variant.
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
    "crates/nucleus-federation"
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

# ── nucleus-federation: ES256 is the only SIGNING algorithm ───────────────
FED="crates/nucleus-federation"
for p in "${SCAN_PATHS[@]}"; do
    [[ "${p%/}" == "$FED" ]] || continue
    src="$FED/src"
    [[ -d "$src" ]] || continue

    # 1. The pin is declared exactly once, and it says ES256. `mint` writes
    #    this constant into every header; the signer is never asked.
    pins=$(grep -RHnE 'const SIGNING_ALG' --include="*.rs" "$src" || true)
    if [[ $(printf '%s\n' "$pins" | grep -c .) -ne 1 ]] \
        || ! printf '%s\n' "$pins" | grep -qE 'pub const SIGNING_ALG: &str = "ES256";'; then
        echo "$FED: SIGNING_ALG must be declared exactly once, as \"ES256\" (found: ${pins:-none})" >>"$tmpfile"
    fi

    # 2. No signing primitive other than ring's fixed-length P-256 ECDSA in
    #    production source. A second one is a second algorithm, whatever the
    #    constant says. (Tests may use others to build negative fixtures.)
    grep -RHnE 'jsonwebtoken::encode|EncodingKey|crypto::sign\(|ECDSA_P384_SHA384_(FIXED|ASN1)_SIGNING|ECDSA_P256_SHA256_ASN1_SIGNING|RSA_PKCS1_SHA|RSA_PSS_SHA|Ed25519KeyPair|hmac::(sign|Key)' \
        --include="*.rs" "$src" 2>/dev/null \
        | grep -v 'alg-pin-allow:' >>"$tmpfile" || true

    # 3. A bare algorithm-name literal in production source needs a reason on
    #    its line (the verification allowlist's names carry one each).
    grep -RHnE '"(HS|RS|PS|ES)[0-9]{3}"' --include="*.rs" "$src" 2>/dev/null \
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
