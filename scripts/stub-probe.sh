#!/usr/bin/env bash
# stub-probe.sh — track the DANGEROUS stub count, not the meaningless raw one.
#
# A `todo!()` panics loudly; the danger is code that AFFIRMS without checking or
# returns FAKE data dressed as real. This probe (from the nucleus stub audit)
# tracks those shapes and ratchets them to zero. It scans `crates/` ONLY —
# never `.` — so build dirs (target/, examples/, sdks/) can't inject phantoms
# (the raw-count bug that once reported 207 todo!()s that did not exist).
#
# Emits: $OUT_DIR/dangerous-stubs.json (shields endpoint) + prints the breakdown.
# Exit non-zero (CI gate) if a must-be-zero category regresses.
set -uo pipefail

OUT_DIR="${1:-badges}"
SRC="crates"
mkdir -p "$OUT_DIR"

# Non-test grep over first-party crate sources only.
nt() { grep -rnE "$1" --include='*.rs' "$SRC" 2>/dev/null | grep -vE '/target/|/tests/|/examples/|#\[cfg\(test\)\]'; }

# (1) AFFIRMING VERIFIERS — a verifier-named fn whose body emits an affirmative
#     verdict but calls NO hash/signature primitive. The nightmare: a checker
#     that returns "valid" without checking. Per-fn body scan via awk.
affirming=""
for f in $(grep -rlE 'fn [a-z_]*(verif|valid|check|attest|chain)' --include='*.rs' "$SRC" 2>/dev/null | grep -vE '/target/|/tests/'); do
  hit=$(awk '
    /fn [a-z_]*(verif|valid|check|attest|chain)/ { infn=1; depth=0; body=""; name=$0 }
    infn {
      body=body"\n"$0
      depth += gsub(/{/,"{"); depth -= gsub(/}/,"}")
      if (depth<=0 && body ~ /{/) {
        affirm = (body ~ /chain_valid[^=]*true|"verified"|chain intact|Ok\(true\)|intact|: valid/)
        prim   = (body ~ /Sha256|sha2|blake3|Hasher|\.update\(|hmac|Hmac|sign_message|verify_strict|\.verify\(|ed25519|Ed25519/)
        test   = (body ~ /#\[cfg\(test\)\]|mod tests/)
        if (affirm && !prim && !test) print FILENAME": "name
        infn=0
      }
    }' "$f")
  [ -n "$hit" ] && affirming="$affirming$hit"$'\n'
done
# Exclude the genuine verifiers (they DO call primitives — confirmed by audit).
affirming=$(printf '%s' "$affirming" | grep -vE 'verify_tool_proxy_log|verify_bundle|nucleus-recompute|verify_receipt\b|cfg\(kani\)' | grep -c . || true)

# (2) VENDOR COUPLING — a hardcoded LLM-vendor endpoint outside tests/comments
#     (breaches the vendor-neutrality mandate).
# `.contains(` excludes test assertions that CHECK for a vendor string (incl.
# the vendor-neutrality test asserting ABSENCE) — only flag strings being ADDED.
vendor=$(nt 'api\.(anthropic|openai)\.com' | grep -vE '//|/// |assert|\.contains\(|name:|audience:|"[a-z_]+":' | grep -c . || true)

# (3) HELP/BODY MISMATCH — help/doc text claims a crypto primitive the binary
#     does not perform (seed: the audited over-claim).
mismatch=$(grep -rnE 'Ed25519 signatures \+ SHA-256' --include='*.rs' "$SRC" 2>/dev/null | grep -vc '/target/' || true)

# (4) SILENT FAKE RETURNS — non-test fn returning a constant success with no
#     mock/fake/stub/deny marker (informational: dangerous SHAPE, may be unreachable).
silent=$(nt 'Ok\(vec!\[\]\)|Ok\(Vec::new\(\)\)|Ok\(true\)' | grep -vEi 'mock|fake|stub|deny|recording|simulat' | grep -c . || true)

# (5) RAW SCAFFOLDS — informational only, NOT the badge (loud/honest).
scaffolds=$(grep -rnE 'todo!|unimplemented!|NotImplemented|NotWired' --include='*.rs' "$SRC" 2>/dev/null | grep -vc '/target/' || true)
ignores=$(grep -rcE '^[[:space:]]*#\[ignore' --include='*.rs' "$SRC" 2>/dev/null | awk -F: '{s+=$2} END{print s+0}')

# The GATED dangerous count uses only the ROBUST, exact signals (help/doc claims
# a primitive the body lacks; a vendor endpoint being ADDED in non-test code).
# `affirming_verifiers` + `silent_fake_returns` stay INFORMATIONAL — the fn-body
# awk scan has test-fn / constructor false-positives, so gating on it would cry
# wolf; a future AST-based (cfg(test)-aware) pass can promote it to a gate.
DANGER=$((vendor + mismatch))

color=brightgreen; [ "$DANGER" -gt 0 ] && color=red
printf '{"schemaVersion":1,"label":"dangerous stubs","message":"%s","color":"%s"}\n' "$DANGER" "$color" > "$OUT_DIR/dangerous-stubs.json"

cat > stub-report.json <<JSON
{
  "dangerous_stub_count": $DANGER,
  "affirming_verifiers": $affirming,
  "vendor_coupling": $vendor,
  "help_body_mismatch": $mismatch,
  "silent_fake_returns": $silent,
  "raw_scaffolds_informational": $scaffolds,
  "ignored_tests": $ignores
}
JSON

echo "stub-probe — $(basename "$(pwd)")  (crates/ only)"
echo "  DANGEROUS = $DANGER  (affirming_verifiers=$affirming vendor_coupling=$vendor help_body_mismatch=$mismatch)"
echo "  silent_fake_returns=$silent (informational)  raw_scaffolds=$scaffolds  #[ignore]=$ignores"

# RATCHET (CI gate): the ROBUST dangerous categories must be zero / frozen.
# affirming_verifiers + silent_fake_returns are reported above for human review
# but are NOT gated (awk body-scan false-positives).
rc=0
[ "$mismatch" -eq 0 ] || { echo "::error::help/doc claims a crypto primitive the body lacks"; rc=1; }
[ "$vendor" -le "${VENDOR_BASELINE:-0}" ] || { echo "::error::new vendor coupling (api.anthropic/openai.com being added)"; rc=1; }
exit $rc
