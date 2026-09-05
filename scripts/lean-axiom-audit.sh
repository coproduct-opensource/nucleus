#!/usr/bin/env bash
# Generated per-theorem axiom audit for a Lean project (#2567).
#
# WHY THIS EXISTS
#
# Five workflows used to grep `#print axioms` output for `sorryAx`. That catches
# `sorry`/`admit` and nothing else: a top-level `axiom foo : P` passes, a
# `native_decide` passes, and the proven tier's audit listed theorem names by
# hand, so a theorem nobody added to the list was never audited at all. This
# script replaces those greps with a walk over EVERY declaration the compiled
# oleans define under a root namespace (leanprover-community/axiom-audit, a
# dependency-free Lean tool built under the project's own toolchain), and
# applies one policy:
#
#   * a declaration may depend only on {propext, Classical.choice, Quot.sound};
#   * `native_decide` (its `<decl>._native.native_decide.ax_*` axiom, or
#     `Lean.ofReduceBool` on older toolchains) is tolerated ONLY for
#     declarations named, one per line, in <project>/.axiom-audit-exceptions —
#     per theorem, never per workflow, so nothing is laundered;
#   * `sorryAx` and any home-rolled axiom fail, always;
#   * the audit must have covered at least as many declarations as the
#     project's sources declare with `theorem`/`lemma` (a positive-count guard:
#     an audit that silently covered nothing cannot pass);
#   * `axiom <name> :` declarations in the project's own sources are ratcheted against
#     <project>/.axiom-ratchet (absent = 0).
#
# Usage:
#   scripts/lean-axiom-audit.sh <project-dir> <root>[,<root>...]
#   scripts/lean-axiom-audit.sh <project-dir> --self-test
#
# <root> is a module/namespace root (`Ck`, `Nucleus`, `FlowProofs`, …); several
# roots are audited in one call for projects whose proven tier is many
# `lean_lib`s. Run after `lake build` of the audited libraries. `--self-test`
# compiles a fixture with `axiom`, `admit` and `native_decide` into a temp
# search path and asserts each is caught — the gate proves it can go red
# (scripts/check-gates-can-fail.sh discipline).
set -euo pipefail

PROJECT=${1:?project dir}
MODE=${2:?root list or --self-test}
cd "$PROJECT"
PROJECT_ABS=$(pwd)

ALLOWED='["propext","Classical.choice","Quot.sound"]'
EXC_FILE=.axiom-audit-exceptions
RATCHET_FILE=.axiom-ratchet

need() { command -v "$1" >/dev/null 2>&1 || { echo "::error::$1 is required"; exit 2; }; }
need lake; need jq

# The tool is a `require` of the project (lakefile) and builds from the
# committed manifest — never `lake update` here (it would rewrite lean-toolchain).
lake build axiom-audit >/dev/null 2>&1 || { echo "::error::lake build axiom-audit failed in $PROJECT_ABS"; exit 2; }

# Apply the policy to one JSON report. Prints violations; returns 1 on any.
# $1 = report path, $2 = exceptions file (may be absent).
apply_policy() {
    local report=$1 exc=$2
    local excs='[]'
    if [ -f "$exc" ]; then
        excs=$(grep -vE '^\s*(#|$)' "$exc" | jq -R . | jq -s .)
    fi
    jq -r --argjson allowed "$ALLOWED" --argjson excs "$excs" '
      def native_of($d): ($d + "._native.native_decide.ax_");
      def owner($ax): ($ax | capture("^(?<o>.*)\\._native\\.native_decide\\.ax_") | .o) // null;
      # a declaration is fine when every non-allowed axiom it uses is the
      # native_decide axiom of a theorem NAMED in the exceptions file — the
      # theorem that introduced native_decide is the one disclosed; theorems
      # that merely depend on it inherit that disclosure, nothing else does.
      def tolerated($decl; $axs):
        ($axs | map(select(. as $a | ($allowed | index($a)) | not)) | all(
          (. == "Lean.ofReduceBool" and ($excs | index($decl)) != null)
          or (owner(.) as $o | $o != null and (($excs | index($o)) != null))
        ));
      .violations[] | select(tolerated(.decl; .axioms) | not) | "  \(.decl) depends on \(.axioms | join(", "))"
    ' "$report"
}

# Count the source-level theorem/lemma declarations under the project (its own
# sources, not .lake). A lower bound the audit must meet.
source_theorem_count() {
    { grep -rhoE '^\s*(private |protected |noncomputable )*(theorem|lemma)\s' --include='*.lean' --exclude-dir=.lake . 2>/dev/null || true; } | wc -l | tr -d ' '
}

self_test() {
    local t; t=$(mktemp -d)
    # expanded now: the trap fires after this function's locals are gone
    trap "rm -rf '$t' '$PROJECT_ABS/AuditFixture.lean'" EXIT
    # `lean` insists the input lives under the project root (module system).
    cat > AuditFixture.lean <<'EOF'
axiom fixtureAxiom : True
theorem viaAdmit : 1 + 1 = 2 := by admit
theorem viaNative : 2 + 2 = 4 := by native_decide
theorem clean : 3 + 3 = 6 := rfl
EOF
    lake env lean -o "$t/AuditFixture.olean" AuditFixture.lean >/dev/null 2>&1 || { echo "::error::self-test fixture did not compile"; exit 2; }
    rm -f AuditFixture.lean
    set +e
    lake env sh -c "LEAN_PATH=\"$t:\$LEAN_PATH\" axiom-audit --root AuditFixture --json" > "$t/report.json" 2>"$t/err.txt"
    local rc=$?
    set -e
    [ "$rc" = 1 ] || { echo "::error::self-test: expected exit 1 from the tool on the fixture, got $rc"; cat "$t/err.txt"; exit 1; }
    local out; out=$(apply_policy "$t/report.json" /dev/null || true)
    for want in fixtureAxiom viaAdmit viaNative; do
        echo "$out" | grep -q "^  $want " || { echo "::error::self-test: the audit did not flag '$want'"; echo "$out"; exit 1; }
    done
    echo "$out" | grep -q "^  clean " && { echo "::error::self-test: the audit flagged the clean theorem"; exit 1; }
    # a per-theorem exception tolerates native_decide for THAT theorem only
    printf 'viaNative\n' > "$t/exc"
    out=$(apply_policy "$t/report.json" "$t/exc" || true)
    echo "$out" | grep -q "^  viaNative " && { echo "::error::self-test: the exception for viaNative was not honoured"; exit 1; }
    echo "$out" | grep -q "^  viaAdmit " || { echo "::error::self-test: the exception leaked to viaAdmit"; exit 1; }
    echo "ok: self-test — axiom, admit and native_decide each red; a per-theorem exception tolerates only its theorem"
}

if [ "$MODE" = "--self-test" ]; then self_test; exit 0; fi

fail=0
total_audited=0
IFS=',' read -r -a ROOTS <<< "$MODE"
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
for root in "${ROOTS[@]}"; do
    set +e
    lake exe axiom-audit --root "$root" --json > "$t/$root.json" 2>"$t/$root.err"
    rc=$?
    set -e
    if [ "$rc" = 2 ]; then echo "::error::axiom-audit could not run for root $root:"; cat "$t/$root.err"; jq -r '.error // empty' "$t/$root.json" 2>/dev/null | head -3; exit 2; fi
    n=$(jq -r '.audited // 0' "$t/$root.json")
    total_audited=$((total_audited + n))
    if [ "$n" = 0 ]; then echo "::error::root $root: nothing audited ($(jq -r '.error // "no declarations"' "$t/$root.json"))"; fail=1; continue; fi
    v=$(apply_policy "$t/$root.json" "$EXC_FILE" || true)
    if [ -n "$v" ]; then
        echo "::error::root $root: declarations outside the allowlist {propext, Classical.choice, Quot.sound}:"
        echo "$v"; fail=1
    else
        echo "ok: root $root — $n declaration(s), axioms used: $(jq -r '.axiomsUsed | join(", ")' "$t/$root.json")"
    fi
done

# Positive-count guard against the sources.
src=$(source_theorem_count)
if [ "$total_audited" -lt "$src" ]; then
    echo "::error::audited $total_audited declaration(s) but the sources declare $src theorem/lemma(s) — a root is missing from the audit"
    fail=1
else
    echo "ok: audited $total_audited declaration(s) ≥ $src source theorem/lemma(s)"
fi

# `axiom` ratchet over the project's own sources.
# `axiom <name> :` / `axiom <name> (` — a real declaration, not the word in a
# doc comment (BudgetConservation.lean has "axiom; edges after used theorem").
ax=$({ grep -rhoE "^\s*(private |protected )?axiom\s+[A-Za-z_][A-Za-z0-9_.']*\s*[:(]" --include='*.lean' --exclude-dir=.lake . 2>/dev/null || true; } | wc -l | tr -d ' ')
ceiling=0; [ -f "$RATCHET_FILE" ] && ceiling=$(tr -d ' \n' < "$RATCHET_FILE")
if [ "$ax" -gt "$ceiling" ]; then
    echo "::error::$ax top-level 'axiom' declaration(s) in $PROJECT (ceiling $ceiling in $RATCHET_FILE)"; fail=1
else
    echo "ok: $ax top-level axiom declaration(s) (ceiling $ceiling)"
fi

exit $fail
