#!/usr/bin/env bash
# The pre-push gate: everything CI would red in its first minute, run locally
# in about one. Five of the seven reds on 2026-09-05 were catchable here.
#
#   scripts/prepush.sh            # cheap tier (~1 min): gate scripts, ratchets,
#                                 # census, actionlint, fmt, per-feature check of
#                                 # the crates this branch touches
#   scripts/prepush.sh --full     # + clippy, tests of the affected crates, and
#                                 # the heavy gate scripts (several minutes)
#
# Compares against origin/main (override with PREPUSH_BASE). Wire it as a hook
# with `just hooks`.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1
BASE=${PREPUSH_BASE:-origin/main}
FULL=0; [ "${1:-}" = "--full" ] && FULL=1
fail=0; pass=0
run() {   # run <label> <cmd...>
    local label=$1; shift
    local out; out=$(mktemp)
    if "$@" >"$out" 2>&1; then pass=$((pass+1)); printf '  ok    %s\n' "$label"
    else fail=$((fail+1)); printf '  FAIL  %s\n' "$label"; sed 's/^/        /' "$out" | tail -25; fi
    rm -f "$out"
}
have() { command -v "$1" >/dev/null 2>&1; }

git fetch -q origin main 2>/dev/null || true
changed=$(git diff --name-only "$BASE...HEAD" 2>/dev/null || true)
affected=$(scripts/affected-crates.sh "$BASE" 2>/dev/null); arc=$?
[ "$arc" = 3 ] && affected=ALL

echo "prepush against $BASE — $(printf '%s\n' "$changed" | grep -c .) file(s) changed; affected crates: $(printf '%s' "$affected" | tr '\n' ' ')"

# ── cheap tier ────────────────────────────────────────────────────────────
echo "gate scripts:"
for s in check-declassify-governor-keys-sealed check-dep-ceiling check-extracted-callsites \
         check-failclosed-verifiers check-ingest-hashed check-mediation check-no-hmac-auth \
         check-north-star-ledger check-sandbox-trusted-base check-sealed-home \
         check-test-helpers-not-in-production check-verify-strict check-wasm-closure \
         check-kani-divergence check-kani-proof-count; do
    [ -x "scripts/$s.sh" ] || continue
    case $s in
        check-kani-proof-count) run "$s --strict" bash "scripts/$s.sh" --strict ;;
        *) run "$s" bash "scripts/$s.sh" ;;
    esac
done
run "check-line-ratchet --strict" bash scripts/check-line-ratchet.sh --strict
[ -x scripts/formal-numbers.sh ] && run "formal-numbers (census vs docs)" bash scripts/formal-numbers.sh
if printf '%s\n' "$changed" | grep -q '^\.github/workflows/'; then
    if have actionlint; then
        wf=(); while read -r f; do wf+=("$f"); done < <(printf '%s\n' "$changed" | grep '^\.github/workflows/.*\.ya\?ml$')
        run "actionlint" actionlint "${wf[@]}"
    else echo "  skip  actionlint (not installed: brew install actionlint)"; fi
fi
if printf '%s\n' "$changed" | grep -qE '^scripts/.*\.sh$|^ci/.*\.sh$'; then
    if have shellcheck; then
        sh=(); while read -r f; do sh+=("$f"); done < <(printf '%s\n' "$changed" | grep -E '^(scripts|ci)/.*\.sh$')
        run "shellcheck -S error (changed scripts)" shellcheck -S error "${sh[@]}"
    else echo "  skip  shellcheck (not installed)"; fi
fi
if printf '%s\n' "$changed" | grep -q '\.rs$'; then
    run "cargo fmt --check" cargo fmt --all -- --check
    # The class of red that only shows without a feature: check every feature
    # combination of the touched crates, not just --all-features.
    if [ "$affected" = ALL ]; then
        echo "  skip  cargo hack (workspace-wide change; run 'cargo hack check --each-feature' yourself)"
    elif [ -n "$affected" ] && have cargo-hack; then
        pk=$(printf '%s\n' "$affected" | sed 's/^/-p /' | tr '\n' ' ')
        # shellcheck disable=SC2086
        run "cargo hack check --each-feature ($(printf '%s' "$affected" | tr '\n' ' '))" env RUSTFLAGS="-D warnings" cargo hack check --each-feature --no-dev-deps $pk
    fi
fi

# ── full tier ─────────────────────────────────────────────────────────────
if [ "$FULL" = 1 ] && printf '%s\n' "$changed" | grep -q '\.rs$'; then
    run "cargo clippy --all-targets --all-features -D warnings" cargo clippy --all-targets --all-features -- -D warnings
    if [ "$affected" = ALL ] || [ -z "$affected" ]; then
        run "cargo test --workspace (lib, bins, tests)" cargo test --all-features --lib --bins --tests
    else
        pk=$(printf '%s\n' "$affected" | sed 's/^/-p /' | tr '\n' ' ')
        # shellcheck disable=SC2086
        run "cargo test (affected: lib, bins, tests)" cargo test --all-features --lib --bins --tests $pk
        # shellcheck disable=SC2086
        run "cargo test --doc (affected)" cargo test --all-features --doc $pk
    fi
    for s in check-declassify-sink-scope-enforced check-declassify-value-bound check-c1-inbound-fences; do
        [ -x "scripts/$s.sh" ] && run "$s" bash "scripts/$s.sh"
    done
    if [ -z "$(git status --porcelain)" ]; then run "check-gates-can-fail" bash scripts/check-gates-can-fail.sh
    else echo "  skip  check-gates-can-fail (needs a clean tree)"; fi
fi

echo
if [ "$fail" -gt 0 ]; then echo "prepush: $fail FAILED, $pass ok — fix before pushing"; exit 1; fi
echo "prepush: all $pass ok"
