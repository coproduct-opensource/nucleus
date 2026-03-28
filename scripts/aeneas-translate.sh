#!/usr/bin/env bash
# Aeneas pipeline: portcullis-core → Lean 4
#
# Translates the dependency-free portcullis-core crate from Rust MIR
# into pure functional Lean 4 code for HeytingAlgebra verification.
#
# Prerequisites:
#   - Nix with flakes enabled, OR:
#   - Charon (https://github.com/AeneasVerif/charon) with nightly-2026-02-07
#   - Aeneas (https://github.com/AeneasVerif/aeneas) OCaml build
#
# Usage:
#   # With Nix (recommended):
#   nix run .#translate
#
#   # Without Nix:
#   ./scripts/aeneas-translate.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CORE_DIR="$ROOT_DIR/crates/portcullis-core"
OUTPUT_DIR="$CORE_DIR/lean/generated"

echo "=== Aeneas Pipeline: portcullis-core → Lean 4 ==="
echo ""

# Step 1: Charon MIR extraction
echo "Step 1: Extracting Rust MIR with Charon..."
cd "$CORE_DIR"

if command -v charon &>/dev/null; then
    charon --cargo --crate portcullis-core
elif command -v nix &>/dev/null; then
    echo "  (using nix run for charon)"
    nix run github:aeneasverif/aeneas#charon -- --cargo --crate portcullis-core
else
    echo "ERROR: Neither 'charon' nor 'nix' found in PATH."
    echo "Install Nix: https://nixos.org/download.html"
    echo "Or build Charon: https://github.com/AeneasVerif/charon"
    exit 1
fi

LLBC_FILE="$CORE_DIR/portcullis-core.llbc"
if [ ! -f "$LLBC_FILE" ]; then
    echo "ERROR: Charon did not produce $LLBC_FILE"
    exit 1
fi
echo "  ✓ MIR extracted: $LLBC_FILE"

# Step 2: Aeneas translation
echo ""
echo "Step 2: Translating LLBC → Lean 4 with Aeneas..."
mkdir -p "$OUTPUT_DIR"

if command -v aeneas &>/dev/null; then
    aeneas -backend lean "$LLBC_FILE" -dest "$OUTPUT_DIR"
elif command -v nix &>/dev/null; then
    echo "  (using nix run for aeneas)"
    nix run github:aeneasverif/aeneas -- -backend lean "$LLBC_FILE" -dest "$OUTPUT_DIR"
else
    echo "ERROR: Neither 'aeneas' nor 'nix' found in PATH."
    exit 1
fi

echo "  ✓ Lean files generated in $OUTPUT_DIR/"
ls -la "$OUTPUT_DIR/"

# Step 3: Verify (if lake is available)
echo ""
if command -v lake &>/dev/null && [ -f "$CORE_DIR/lean/lakefile.lean" ]; then
    echo "Step 3: Verifying with lake build..."
    cd "$CORE_DIR/lean"
    lake build
    echo "  ✓ Lean verification passed"
else
    echo "Step 3: Skipped (lake not in PATH or lakefile.lean not found)"
    echo "  To verify: cd $CORE_DIR/lean && lake build"
fi

echo ""
echo "=== Pipeline complete ==="
