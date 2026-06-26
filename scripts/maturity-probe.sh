#!/usr/bin/env bash
# maturity-probe.sh — compute EXACT, CI-driven maturity metrics and emit
# shields.io endpoint badge JSONs + a maturity.json snapshot.
#
# Design principle (the honesty rule): this script is BOTH the badge source AND
# a CI gate input — the README numbers are COMPUTED here, never hand-authored,
# so they cannot drift from reality. Pair with ratchets in CI (sorries and
# decorative stubs must not increase).
#
# Excludes vendored Mathlib (.lake), worktrees (.claude), vendored libs
# (external/vendor), and codegen (generated) — see scripts/lean-census.sh.
#
# Usage: scripts/maturity-probe.sh [OUT_DIR]   (default OUT_DIR=badges)
# Emits: $OUT_DIR/{theorems,sorries,decorative,rust-stubs}.json (shields endpoint)
#        maturity.json (full snapshot)
# The axiom-footprint badge is emitted by scripts/axiom-audit.sh (needs `lake`).
set -uo pipefail

OUT_DIR="${1:-badges}"
mkdir -p "$OUT_DIR"

EX=(--include='*.lean'
    --exclude-dir=.lake --exclude-dir=lake-packages
    --exclude-dir=.claude --exclude-dir=external
    --exclude-dir=vendor --exclude-dir=generated)

# ── Lean first-party metrics ────────────────────────────────────────────────
lean_files=$(grep -rlI '' "${EX[@]}" . 2>/dev/null | wc -l | tr -d ' ')
theorems=$(grep -rhcE '^[[:space:]]*(theorem|lemma) ' "${EX[@]}" . 2>/dev/null | awk '{s+=$1} END{print s+0}')
sorry_files=$(grep -rlE '^[[:space:]]*sorry' "${EX[@]}" . 2>/dev/null | wc -l | tr -d ' ')
sorries=$(grep -rhcE '^[[:space:]]*sorry' "${EX[@]}" . 2>/dev/null | awk '{s+=$1} END{print s+0}')
decorative=$(grep -rlE ':=[[:space:]]*by[[:space:]]+trivial' "${EX[@]}" . 2>/dev/null | wc -l | tr -d ' ')

# ── Rust stub markers (zero-stubs axis) ─────────────────────────────────────
RX=(--include='*.rs' --exclude-dir=target --exclude-dir=.lake --exclude-dir=.claude)
rust_stubs=$(grep -rhcE '\b(todo!|unimplemented!)\s*\(' "${RX[@]}" . 2>/dev/null | awk '{s+=$1} END{print s+0}')
ignored_tests=$(grep -rhcE '^[[:space:]]*#\[ignore' "${RX[@]}" . 2>/dev/null | awk '{s+=$1} END{print s+0}')

# A green metric (0 = good) is green when 0, else red/orange.
zero_color() { [ "$1" -eq 0 ] && echo brightgreen || echo orange; }

badge() { # name label message color
  printf '{"schemaVersion":1,"label":"%s","message":"%s","color":"%s"}\n' \
    "$2" "$3" "$4" > "$OUT_DIR/$1.json"
}

badge theorems   "lean theorems"   "$theorems"            blue
badge sorries    "sorries"         "$sorries"             "$(zero_color "$sorries")"
badge decorative "decorative stubs" "$decorative"         "$(zero_color "$decorative")"
badge rust-stubs "rust stubs"      "$((rust_stubs + ignored_tests))" "$(zero_color "$((rust_stubs + ignored_tests))")"

cat > maturity.json <<JSON
{
  "schemaVersion": 1,
  "repo": "$(basename "$(pwd)")",
  "lean": {
    "first_party_files": $lean_files,
    "theorems_lemmas": $theorems,
    "sorry_bearing_files": $sorry_files,
    "sorries": $sorries,
    "decorative_stubs": $decorative
  },
  "rust": {
    "todo_unimplemented": $rust_stubs,
    "ignored_tests": $ignored_tests
  }
}
JSON

# README snippet (injected between <!-- MATURITY:START/END --> markers). No
# timestamp — so the block changes only when the NUMBERS change (no daily churn).
cat > "$OUT_DIR/_table.md" <<MD
| Lean files | Theorems / lemmas | Sorries | Decorative stubs | Rust stubs |
|---:|---:|---:|---:|---:|
| $lean_files | $theorems | $sorries (in $sorry_files files) | $decorative | $((rust_stubs + ignored_tests)) |

_First-party only (excludes \`.lake/\` Mathlib + worktrees). A theorem count is not a strength claim — see [PROOFS.md](docs/PROOFS.md)._
MD

echo "maturity-probe — $(basename "$(pwd)")"
echo "  lean: $lean_files files, $theorems thm/lemma, $sorries sorries ($sorry_files files), $decorative decorative"
echo "  rust stubs: $rust_stubs todo!/unimplemented! + $ignored_tests #[ignore]"
echo "  wrote $OUT_DIR/{theorems,sorries,decorative,rust-stubs}.json + maturity.json"
