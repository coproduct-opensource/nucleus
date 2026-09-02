#!/usr/bin/env bash
# There must be exactly ONE place that decides what SPIFFE ID a certificate
# carries.
#
# WHY: this parse existed in six independent copies, each looping the SAN list
# and returning the FIRST entry starting with `spiffe://`. The X.509-SVID
# standard requires exactly one URI SAN and requires validators to REJECT
# certificates carrying more, so first-match was an impersonation vector: a
# certificate naming both `spiffe://td/victim` and `spiffe://td/attacker` was
# accepted and resolved by DER encoding order. Two of those copies —
# `nucleus-node`'s auth path and the tool-proxy's mTLS path — decide who a peer
# IS, so two components could disagree about the same peer.
#
# Consolidating fixed it once. This stops it growing back: a new local SAN loop
# reintroduces the bug silently, because the code looks reasonable in isolation.
set -euo pipefail
cd "$(dirname "$0")/.."

# The one legitimate implementation.
OWNER="crates/nucleus-identity/src/certificate.rs"

# A CSR is not an SVID: it has no cA field and no key usage to check, so
# `ca/self_signed.rs` extracting a requested SAN from a CertificationRequest is
# a genuinely different operation and is not covered by this rule.
CSR_READER="crates/nucleus-identity/src/ca/self_signed.rs"

hits=$(grep -rln 'GeneralName::URI' --include='*.rs' crates/ 2>/dev/null \
       | grep -v "^${OWNER}$" \
       | grep -v "^${CSR_READER}$" \
       || true)

if [ -n "$hits" ]; then
  echo "::error::a SPIFFE URI SAN is being parsed outside $OWNER:"
  echo "$hits" | sed 's/^/  /'
  echo "  Use nucleus_identity::spiffe_uri_from_svid (DER) or"
  echo "  spiffe_uri_from_parsed_svid (already-parsed cert) instead. They enforce"
  echo "  the X.509-SVID rules that a local loop will not."
  exit 1
fi

# Non-vacuity: if the owner ever stops containing the parse, this check would
# pass by scanning for something that no longer exists anywhere.
if ! grep -q 'GeneralName::URI' "$OWNER"; then
  echo "::error::$OWNER no longer parses URI SANs — this check has nothing to anchor to"
  exit 1
fi

echo "ok: one SVID validator ($OWNER)"
