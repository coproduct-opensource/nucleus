#!/usr/bin/env bash
# Dependency-duplication ceiling (gap G1) — a RATCHET, not a single-version claim.
#
# The workspace carries known duplicate versions of a few security-critical
# crates. A naive "exactly one version" gate would be impossible to satisfy while
# transitive deps force multiple lines (e.g. sha2). So instead this caps the
# version count per watched crate at a documented ceiling: NEW drift (a PR that
# introduces another version) fails CI, while the existing debt is visible and
# paid down by *lowering* a ceiling when a unification lands. ed25519-dalek is now
# unified across ALL first-party crates (default builds resolve a single v3); the
# ceiling stays 2 only because c2pa (provenance SDK) still pins v2 under
# --all-features. Never raise a ceiling without recording why below.
#
# Honest framing for PROOFS.md / pitches: dependency hygiene here is RATCHETED,
# not single-version. See docs/PROOFS.md.
#
# Why a count-ceiling script and not cargo-deny's native per-crate
# `deny-multiple-versions` (EmbarkStudios/cargo-deny#365): that flag enforces
# EXACTLY ONE version (sha2 can't satisfy that — transitive deps force 3) and
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
# ed25519-dalek = 2  (FIRST-PARTY UNIFIED — default builds resolve a SINGLE v3)
#   v3.0.0-pre.7  ← the unified line: workspace default + envelope/lineage/oidc-*/
#                   verifier/trust-registry/witness/node + iroh (pins it exactly).
#                   jsonwebtoken no longer pulls v2 either (aws_lc_rs backend).
#   v2.2.0        ← ONLY c2pa v0.85.2 (content-provenance SDK; direct dep), pulled
#                   in by nucleus-envelope/audit's c2pa features. `cargo tree`
#                   (default features) shows a single v3; this ceiling uses
#                   --all-features, which surfaces c2pa's v2. Drops to 1 when c2pa
#                   moves to dalek 3 (upstream) — not ours to force.
#
# sha2 = 3
#   v0.9.9   ← drand-verify v0.6.2 (nucleus-client → node/tool-proxy; dormant)
#   v0.10.9  ← age (oidc-provider) + rust-embed-utils
#   v0.11.0  ← workspace default + iroh + ed25519-dalek v3 path
#   PLAN: drops to 2 when drand-verify is dropped/replaced (kills 0.9); to 1 when
#         age + rust-embed-utils reach sha2 0.11. See the sha2-unification effort.
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
