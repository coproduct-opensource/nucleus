#!/usr/bin/env bash
# exemplar-scoreboard.sh — the MECHANICAL layer of the "top-1% exemplar" probe.
#
# Computes exact, greppable metrics across the four domains (formal verification,
# Rust craft, sandboxing, category theory) that the exemplar audit surfaced, each
# with a ratchet direction. CI fails on regression; an autonomous loop closes the
# worst grindable metric one instance at a time and the number moves.
#
# ANTI-GOODHART: each "lower-is-better" metric is PAIRED with a guard so it can't
# be gamed by deletion (you can't cut `permissive_verify` by deleting the verifier
# — the paired `verify_calls` must not drop; you can't cut `vacuous_lean` by
# deleting theorems — the paired `lean_theorems` must not drop). The probe prints
# both; the ratchet checks both. The deepest gaming (cosmetic-but-typechecks) is
# caught by the periodic ADVERSARIAL workflow, not grep — see docs.
#
# Scope: the nucleus repo (run from its root). Lean-heavy metrics (clean axiom
# footprint) are produced by axiom-audit.sh in its own CI and read here if present.
set -uo pipefail
OUT="${1:-scoreboard.json}"

RS=(--include='*.rs' --exclude-dir=target --exclude-dir=.lake --exclude-dir=.claude)
LN=(--include='*.lean' --exclude-dir=.lake --exclude-dir=.claude)
nt() { grep -rnE "$1" "${RS[@]}" crates 2>/dev/null | grep -vE '/tests/|_test\.rs|#\[cfg\(test\)\]|//|///'; }

# ── Formal verification ──────────────────────────────────────────────────────
# extraction frontier: proven-over-EXTRACTED-Rust vs hand-model (the machine-
# readable ProofStatus split is the honest signal).
extracted=$(grep -rhoE 'ExtractedKernelChecked' "${RS[@]}" crates 2>/dev/null | wc -l | tr -d ' ')
handmodel=$(grep -rhoE 'HandModelKernelChecked' "${RS[@]}" crates 2>/dev/null | wc -l | tr -d ' ')
sorry_admit=$(grep -rhcE '^[[:space:]]*(sorry|admit)' "${LN[@]}" crates 2>/dev/null | awk '{s+=$1} END{print s+0}')
lean_theorems=$(grep -rhcE '^[[:space:]]*(theorem|lemma) ' "${LN[@]}" crates 2>/dev/null | awk '{s+=$1} END{print s+0}')
# vacuity: True-typed theorems + axiom:True (worse). Paired guard = lean_theorems.
vacuous_lean=$(grep -rhcE ':=[[:space:]]*by[[:space:]]+trivial|:[[:space:]]*True[[:space:]]*:=|axiom[[:space:]].*:[[:space:]]*True' "${LN[@]}" crates 2>/dev/null | awk '{s+=$1} END{print s+0}')

# ── Rust craft ───────────────────────────────────────────────────────────────
# permissive (malleable) signature verify on non-test paths. Scoped to a
# SIGNATURE context (a bare `.verify(` over all methods over-counts ~2.5x — it
# catches hash/cert/config verifies). This is a conservative SUPERSET of the
# real Ed25519 trust sites (greppable typing can't be exact), so it's a
# don't-INCREASE ratchet, not a target-zero. Paired guard = sig verify_calls,
# so you can't game it by deleting the verifier (count would drop, guard fails).
SIGCTX='sig|signature|vk|verifying|pubkey|public_key|ed25519'
permissive_verify=$(nt '\.verify\(' | grep -v 'verify_strict' | grep -iE "$SIGCTX" | wc -l | tr -d ' ')
verify_calls=$(nt '\.verify(_strict)?\(' | grep -iE "$SIGCTX" | wc -l | tr -d ' ')
unsafe_blocks=$(nt '\bunsafe[[:space:]]+(\{|fn|impl)' | wc -l | tr -d ' ')
crates_total=$(find crates -maxdepth 2 -name Cargo.toml 2>/dev/null | wc -l | tr -d ' ')
crates_lints_ws=$(grep -rlE '^\s*workspace\s*=\s*true' --include=Cargo.toml crates 2>/dev/null | xargs grep -lE '\[lints\]' 2>/dev/null | wc -l | tr -d ' ')

# ── Sandboxing / hard controls ───────────────────────────────────────────────
# complete-mediation drift: a claude-launch site that bypasses permissions but
# omits the built-in disallow list (the gap #1 class). Should be 0.
bypass_sites=$(grep -rlE 'dangerously-skip-permissions|bypassPermissions' "${RS[@]}" crates 2>/dev/null | wc -l | tr -d ' ')
disallow_sites=$(grep -rlE 'DISALLOWED_BUILTIN_TOOLS|--disallowedTools' "${RS[@]}" crates 2>/dev/null | wc -l | tr -d ' ')
mediation_drift=$(( bypass_sites > disallow_sites ? bypass_sites - disallow_sites : 0 ))
effect_stubs=$(grep -rhcE 'NotImplemented|NotWired' "${RS[@]}" crates/portcullis-effects crates/portcullis-core 2>/dev/null | awk '{s+=$1} END{print s+0}')

# ── Hygiene ──────────────────────────────────────────────────────────────────
stale_verus=$(find . -type d -name '.verus' -not -path '*/target/*' 2>/dev/null | wc -l | tr -d ' ')

# clean axiom footprint (from axiom-audit.sh badge if present)
axiom_badge="badges/axiom-footprint.json"
clean_axioms="$( [ -f "$axiom_badge" ] && grep -oE '"message":"[^"]*"' "$axiom_badge" | sed 's/.*:"//;s/"//' || echo 'n/a' )"

cat > "$OUT" <<JSON
{
  "formal_verification": {
    "extracted_proofs": $extracted, "handmodel_proofs": $handmodel,
    "extraction_ratio_pct": $(( (extracted+handmodel)>0 ? extracted*100/(extracted+handmodel) : 0 )),
    "sorry_admit": $sorry_admit, "vacuous_lean": $vacuous_lean,
    "lean_theorems_GUARD": $lean_theorems, "clean_axiom_footprint": "$clean_axioms"
  },
  "rust_craft": {
    "permissive_verify": $permissive_verify, "verify_calls_GUARD": $verify_calls,
    "unsafe_blocks": $unsafe_blocks,
    "crates_total": $crates_total, "crates_lints_workspace": $crates_lints_ws,
    "lints_adoption_pct": $(( crates_total>0 ? crates_lints_ws*100/crates_total : 0 ))
  },
  "sandboxing": {
    "mediation_drift": $mediation_drift, "bypass_sites": $bypass_sites,
    "disallow_sites": $disallow_sites, "effect_stubs": $effect_stubs
  },
  "hygiene": { "stale_verus_dirs": $stale_verus }
}
JSON

echo "exemplar scoreboard — $(basename "$(pwd)")"
echo "  FV : extraction ${extracted}/$((extracted+handmodel)) | sorry/admit $sorry_admit | vacuous-lean $vacuous_lean (of $lean_theorems thm) | clean-axioms $clean_axioms"
echo "  RUST: permissive .verify $permissive_verify (of $verify_calls) | unsafe $unsafe_blocks | lints.workspace $crates_lints_ws/$crates_total"
echo "  SANDBOX: mediation-drift $mediation_drift (bypass $bypass_sites / disallow $disallow_sites) | effect-stubs $effect_stubs"
echo "  HYGIENE: stale .verus dirs $stale_verus"
echo "  -> $OUT"
