#!/usr/bin/env bash
# axiom-audit.sh — the REAL clean-axiom-footprint probe.
#
# For each PROVEN-tier theorem, collect its axiom dependencies (Lean's
# `collectAxioms` over the proof DAG — catches `sorryAx` a textual grep misses)
# and classify:
#   clean   = axioms ⊆ {propext, Quot.sound, funext}  (pure CIC, no choice)
#   sorryAx = depends on `sorry`/`admit` transitively  (NOT actually proven)
# Emits badges/axiom-footprint.json ("N clean / M") — red if any sorryAx.
#
# Scope: the Mathlib-FREE proven modules (build + audit with NO Mathlib cache,
# so this runs locally AND in CI). Set AXIOM_AUDIT_MODULES to override.
# (Mathlib-using proven libs — PortcullisCoreBridge etc. — are a CI extension
# once `lake exe cache get` has run.)
set -uo pipefail

OUT_DIR="${1:-badges}"
L="crates/portcullis-core/lean"
mkdir -p "$OUT_DIR"

# Proven-tier libs (mirror portcullis-core-proven-lean.yml). Mathlib-free ones
# are auto-selected below so this works without the Mathlib olean cache.
PROVEN="PortcullisCoreBridge IntegrityNoninterferenceExtracted ExposureProofs FlowProofs FlowGraphProofs DecidePureProofs DeclassifyProofs CompartmentProofs DelegationProofs DerivationProofs IFCSemilatticeProofs DelegationCategoryProofs GaloisConnectionProofs AttenuationProofs SemanticIFC MonoidalPermissionProofs ConstructiveSecurity WasiWorldFunctor WasiIfcBoundary BelnapDecisionProofs RepairAlgebraProofs"

if [ -n "${AXIOM_AUDIT_MODULES:-}" ]; then
  MODS="$AXIOM_AUDIT_MODULES"
else
  # Audit the FULL proven tier. Mathlib-using libs need the olean cache (CI's
  # `lake exe cache get`, or a warm local .lake) — `lake build` below fetches/
  # builds it. Per-module auditing avoids cross-module name collisions.
  MODS=""
  for m in $PROVEN; do
    [ -f "$L/$m.lean" ] && MODS="$MODS $m"
  done
fi
MODS="$(echo "$MODS" | xargs)"   # trim
[ -n "$MODS" ] || { echo "::error::no auditable modules found"; exit 1; }
echo "auditing modules: $MODS"

# Build the target oleans (Mathlib-free → fast, no cache needed).
( cd "$L" && lake build $MODS ) || { echo "::error::lake build failed"; exit 1; }

# Audit PER MODULE — importing all targets into one file collides on shared
# type names (e.g. two modules each define `CheckResult`). One `lean` run per
# module (oleans already built above), accumulate the totals.
clean=0; audited=0; sorried=0
for m in $MODS; do
  gen="$L/_AxiomAudit.lean"
  {
    echo "import $m"
    echo "import Lean"
    echo "open Lean Elab Command in"
    echo "run_cmd do"
    echo "  let env ← getEnv"
    echo "  let mods := env.header.moduleNames"
    echo "  let allowed : List Name := [\`\`propext, \`\`Quot.sound, \`\`funext]"
    echo "  let mut audited := 0"
    echo "  let mut clean := 0"
    echo "  let mut sorried := 0"
    echo "  for (nm, info) in env.constants.toList do"
    echo "    if (info matches .thmInfo _) && !nm.isInternal then"
    echo "      if let some idx := env.getModuleIdxFor? nm then"
    echo "        if mods[idx.toNat]! == \`$m then"
    echo "          audited := audited + 1"
    echo "          let axs ← collectAxioms nm"
    echo "          if axs.contains \`\`sorryAx then sorried := sorried + 1"
    echo "          if (axs.filter (fun a => !allowed.contains a)).isEmpty then clean := clean + 1"
    echo "  logInfo s!\"RESULT clean={clean} audited={audited} sorryAx={sorried}\""
  } > "$gen"
  out="$( cd "$L" && lake env lean "$(basename "$gen")" 2>&1 )"
  rc=$?
  rm -f "$gen"
  line="$(echo "$out" | grep -oE 'RESULT clean=[0-9]+ audited=[0-9]+ sorryAx=[0-9]+' | head -1)"
  [ $rc -eq 0 ] && [ -n "$line" ] || { echo "::error::audit failed for $m (rc=$rc)"; echo "$out" | tail -12; exit 1; }
  c=$(echo "$line" | sed -E 's/.*clean=([0-9]+).*/\1/')
  a=$(echo "$line" | sed -E 's/.*audited=([0-9]+).*/\1/')
  s=$(echo "$line" | sed -E 's/.*sorryAx=([0-9]+).*/\1/')
  echo "  $m: $c/$a clean ($s sorryAx)"
  clean=$((clean + c)); audited=$((audited + a)); sorried=$((sorried + s))
done

color=brightgreen
[ "$clean" -lt "$audited" ] && color=yellow
[ "$sorried" -gt 0 ] && color=red
printf '{"schemaVersion":1,"label":"clean axiom footprint","message":"%s/%s","color":"%s"}\n' \
  "$clean" "$audited" "$color" > "$OUT_DIR/axiom-footprint.json"

echo "axiom-footprint: $clean clean / $audited audited ($sorried sorryAx) -> $OUT_DIR/axiom-footprint.json"
# Ratchet: any sorryAx in the PROVEN tier is a hard failure (a "proven" theorem
# that secretly depends on sorry).
[ "$sorried" -eq 0 ] || { echo "::error::$sorried proven-tier theorem(s) depend on sorryAx"; exit 1; }
