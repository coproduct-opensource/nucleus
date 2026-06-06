#!/usr/bin/env bash
# Dependency-duplication ceiling (gap G1) — a RATCHET, not a single-version claim.
#
# The workspace currently carries known duplicate versions of a few
# security-critical crates. A naive "exactly one version" gate would be both
# false (there are several) and impossible to satisfy without a risky dependency
# unification (the ed25519-dalek 2→3 collapse, deliberately HELD for a careful
# tested pass). So instead this caps the version count per watched crate at a
# documented ceiling: NEW drift (a PR that introduces another version) fails CI,
# while the existing debt is visible and paid down by *lowering* a ceiling when a
# unification lands. Never raise a ceiling without recording why below.
#
# Honest framing for PROOFS.md / pitches: dependency hygiene here is RATCHETED,
# not single-version. See docs/PROOFS.md.
#
# Why a count-ceiling script and not cargo-deny's native per-crate
# `deny-multiple-versions` (EmbarkStudios/cargo-deny#365): that flag enforces
# EXACTLY ONE version (would fail today, since the dalek collapse is held) and
# needs exact-version `[[bans.skip]]` allowlists that break spuriously on a
# transitive patch bump (=2.2.0 → =2.2.1). A count-ceiling is version-agnostic
# within a line, AND it can enforce the ratchet *down* (fail when a crate drops
# below its ceiling so the win gets locked in) — neither of which cargo-deny
# does. The global `[bans] multiple-versions` stays "warn" to avoid breaking
# main on the many benign transitive dups.
#
# Usage: scripts/check-dep-ceiling.sh
#   Exits non-zero if any watched crate exceeds its ceiling (or — to force the
#   ratchet down — is strictly *below* it, which means the ceiling should be
#   lowered in this same commit).

set -euo pipefail

# watched-crate ceilings. Format: "<crate> <max-distinct-versions>".
#
# ed25519-dalek = 2
#   v2.2.0        ← workspace default ("2"): econ-kernels, externality,
#                   witness-olog, nucleus-node; + transitively via jsonwebtoken v10.
#   v3.0.0-pre.7  ← pinned by envelope, lineage, oidc-*, verifier-service,
#                   trust-registry, witness, control-plane-server; + via iroh.
#   PLAN: collapse to 1 by moving the workspace default to v3 once a tested pass
#         confirms jsonwebtoken + nucleus-node build on dalek 3 (HELD — risky).
#
# sha2 = 3
#   v0.9.9   ← drand-verify v0.6.2 (nucleus-client → cli/mcp/node/sdk/tool-proxy)
#   v0.10.9  ← workspace default (econ-kernels, witness-olog, …)
#   v0.11.0  ← ed25519-dalek v3.0.0-pre.7 / iroh path
#   PLAN: drops to 2 when drand-verify passes sha2 0.9; to 1 when the dalek
#         unification settles sha2 on one minor.
CEILINGS=(
  "ed25519-dalek 2"
  "sha2 3"
)

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

# Full workspace tree once; count distinct "<crate> vX.Y.Z" lines per crate.
# `--workspace --all-features` so a feature-gated extra version is still caught.
tree="$(cargo tree --workspace --all-features 2>/dev/null)"

fail=0
ratchet=0
for entry in "${CEILINGS[@]}"; do
  name="${entry%% *}"
  ceiling="${entry##* }"
  # Match the crate name exactly at a tree node, capture its version tokens.
  versions="$(printf '%s\n' "$tree" \
    | grep -oE "(^|[│├└─ ])${name} v[0-9][A-Za-z0-9.+-]*" \
    | grep -oE "v[0-9][A-Za-z0-9.+-]*" \
    | sort -u || true)"
  count="$(printf '%s\n' "$versions" | grep -c . || true)"

  echo "── ${name}: ${count} version(s) (ceiling ${ceiling})"
  printf '%s\n' "$versions" | sed 's/^/     /'

  if [[ "$count" -gt "$ceiling" ]]; then
    echo "  ✖ VIOLATION: ${name} has ${count} versions, ceiling is ${ceiling}."
    echo "    A new duplicate slipped in. Unify it, or (only with justification)"
    echo "    raise the ceiling in scripts/check-dep-ceiling.sh."
    fail=1
  elif [[ "$count" -lt "$ceiling" ]]; then
    echo "  ↓ RATCHET: ${name} is down to ${count} (< ceiling ${ceiling})."
    echo "    Lower the ceiling to ${count} in this commit to lock the win in."
    ratchet=1
  else
    echo "  ✓ at ceiling"
  fi
done

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
if [[ "$ratchet" -ne 0 ]]; then
  echo ""
  echo "A watched crate dropped below its ceiling — tighten the ratchet."
  exit 1
fi
echo ""
echo "All watched crates within their duplication ceilings."
