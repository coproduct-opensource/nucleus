#!/usr/bin/env bash
# WASM dependency-closure gate (gap G1).
#
# `nucleus-verifier-wasm` (sdks/verifier-js) is the recompute SDK: it pulls the
# proven kernels (envelope, lineage, ifc, econ-kernels, externality, witness-olog)
# and re-derives the cleared price / settlement split / commons routing / required
# bond IN THE BROWSER — no trust in the verifier service. It must therefore
# compile to wasm32-unknown-unknown, which means its ENTIRE dependency closure has
# to be wasm-compatible. The classic break is a native-only crypto crate
# (`ring`) sneaking into the closure transitively — it fails to wasm-compile, and
# a full `wasm-pack build` to discover that is slow. This asserts, at the cargo
# tree level, that the forbidden native-only crates stay out of the wasm closure.
#
# This is a fast pre-flight; it does NOT replace the wasm-pack build, it fails
# faster and with a clearer message when a dependency bump pulls `ring` in.
#
# Usage: scripts/check-wasm-closure.sh

set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
manifest="$root/sdks/verifier-js/Cargo.toml"

# Native-only crates that cannot compile to wasm32-unknown-unknown. `ring` is the
# one that actually bites (vendored C/asm); the rest are defensive.
FORBIDDEN=(ring openssl-sys)

echo "WASM closure gate: nucleus-verifier-wasm (target wasm32-unknown-unknown)"

# `--target wasm32-unknown-unknown` resolves cfg(target_arch) deps as they would
# be for the real wasm build. The crate is workspace-excluded, so use --manifest-path.
tree="$(cargo tree --manifest-path "$manifest" --target wasm32-unknown-unknown 2>/dev/null)"

fail=0
for c in "${FORBIDDEN[@]}"; do
  if printf '%s\n' "$tree" | grep -qE "(^|[│├└─ ])${c} v[0-9]"; then
    echo "  ✖ VIOLATION: '${c}' is in the wasm32 closure — it will not wasm-compile."
    echo "    Trace it with:"
    echo "      cargo tree --manifest-path sdks/verifier-js/Cargo.toml \\"
    echo "        --target wasm32-unknown-unknown -i ${c}"
    echo "    Then feature-gate or replace the dependency that pulls it."
    fail=1
  else
    echo "  ✓ '${c}' absent from the wasm closure"
  fi
done

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
echo ""
echo "WASM closure is clean — no native-only crates."
