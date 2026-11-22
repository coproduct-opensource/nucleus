#!/usr/bin/env bash
# scripts/check-no-hmac-auth.sh
#
# Categorical denylist for the HMAC auth surface Move B deleted from
# nucleus-node — matching the house pattern `snapshot::PER_POD_SECRET_KEYS`
# already uses for retired per-pod secrets, and `ci/no-vendor-strings.sh`'s
# idiom for a grep-based CI gate.
#
# Move B replaced nucleus-node's shared-secret HMAC auth tier (HTTP and gRPC)
# with mandatory mTLS: no fallback exists any more, on purpose. The symbols
# below are RETIRED — their reappearance is not a stylistic regression, it is
# a downgrade surface silently reopening (see #2396 for what a silent auth
# mismatch costs). A deleted tier that can be re-added without this gate
# noticing is the same problem with extra steps.
#
# Scope is deliberately narrow, and the reason it was is now history:
# nucleus-tool-proxy kept its OWN HMAC tiers after Move B. Its request tier
# (`--auth-secret`) was deleted in #2446 step 3 and its approval tier
# (`AuthTier::ApprovalHmacDrand`, `--approval-secret`) on 2026-11-21; both
# flags are now refused by name at startup (`retired.rs`), and Rust tests,
# not this script, pin that. Extending this denylist to the tool-proxy would
# be new logic in shell, which the repository mandate forbids: a Rust gate is
# the place for it.
#
# Allow-list mechanism: a grep match on a line is permitted if the same line
# carries an end-of-line comment `// hmac-allow: <reason>`. Reviewer enforces
# that the reason is genuine (this file itself, a doc explaining the
# history, a negative test asserting the symbol is GONE).
#
# Exit codes:
#   0  — clean
#   1  — a retired symbol was found (CI fails)

set -euo pipefail

# nucleus-node: the crate Move B actually deleted this tier from.
NODE_SCAN_PATH="crates/nucleus-node"
# The two tool-proxy clients Move B converted to mTLS. (The tool-proxy's own
# HMAC tiers, once the reason for this narrow scope, are deleted.)
TOOL_PROXY_CLIENT_FILES=(
    "crates/nucleus-tool-proxy/src/node_client.rs"
    "crates/nucleus-tool-proxy/src/lockdown_client.rs"
)

# Patterns retired from nucleus-node's own HTTP/gRPC auth tier.
NODE_PATTERNS=(
    'NUCLEUS_NODE_AUTH_SECRET'
    'NUCLEUS_NODE_AUTH_MAX_SKEW_SECS'
    '\bAuthMethod::Hmac\b'
    '\bAuthConfig::new\b'
    '\bReplayCache\b'
    '\bverify_http\(' # node's own HMAC HTTP verifier (tool-proxy has its own, unrelated, same-named fn in a different crate — this pattern is scoped to $NODE_SCAN_PATH only)
    '\bverify_grpc\(' # node's own HMAC gRPC verifier
    '\bauthenticate_grpc_request\([^)]*,' # the retired 4-arg (method, auth_config, mtls_enabled) signature; the live one takes only `request`
    '\-\-http-mtls-self-issued'
    '\-\-grpc-tls-self-issued'
    'NUCLEUS_NODE_HTTP_MTLS_SELF_ISSUED'
    'NUCLEUS_NODE_GRPC_TLS_SELF_ISSUED'
)

# Patterns retired from the two mTLS-converted tool-proxy clients: any HMAC
# signing on the node_client/lockdown_client hop is a regression back to the
# pre-Move-B design, whatever it's named.
CLIENT_PATTERNS=(
    'sign_http_headers'
    'sign_hmac'
    '\bhmac::Hmac\b'
    'auth_secret\s*:\s*(Vec<u8>|String|&\[u8\])'
)

violations=0
tmpfile=$(mktemp)
trap 'rm -f "$tmpfile"' EXIT

if [[ -e "$NODE_SCAN_PATH" ]]; then
    for pattern in "${NODE_PATTERNS[@]}"; do
        grep -RHnE "$pattern" \
            --include="*.rs" \
            --exclude-dir=target \
            "$NODE_SCAN_PATH" 2>/dev/null \
            | grep -v 'hmac-allow:' >>"$tmpfile" || true
    done
fi

for f in "${TOOL_PROXY_CLIENT_FILES[@]}"; do
    [[ -e "$f" ]] || continue
    for pattern in "${CLIENT_PATTERNS[@]}"; do
        grep -HnE "$pattern" "$f" 2>/dev/null \
            | grep -v 'hmac-allow:' >>"$tmpfile" || true
    done
done

if [[ -s "$tmpfile" ]]; then
    sort -u "$tmpfile" -o "$tmpfile"
    violations=$(wc -l <"$tmpfile" | tr -d ' ')
    echo "FAIL: retired HMAC auth symbol(s) found — $violations" >&2
    echo "" >&2
    echo "Move B deleted nucleus-node's HMAC auth tier and converted" >&2
    echo "node_client.rs/lockdown_client.rs to mTLS. mTLS is mandatory now," >&2
    echo "with no fallback — reintroducing any of these reopens exactly the" >&2
    echo "downgrade surface that deletion closed." >&2
    echo "" >&2
    echo "(nucleus-tool-proxy's HMAC tiers are deleted and refused by name" >&2
    echo "in its own Rust code; they are not scanned here.)" >&2
    echo "" >&2
    echo "Allow-list a line by appending: hmac-allow: <reason>" >&2
    echo "" >&2
    cat "$tmpfile" >&2
    exit 1
fi

echo "OK: no retired HMAC auth symbols found"
exit 0
