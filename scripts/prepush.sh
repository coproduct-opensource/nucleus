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
for s in check-declassify-governor-keys-sealed check-dep-ceiling check-extracted-callsites check-law-mechanisms \
         check-failclosed-verifiers check-ingest-hashed check-mediation check-no-hmac-auth \
         check-north-star-ledger check-sandbox-trusted-base check-sealed-home \
         check-test-helpers-not-in-production check-verify-strict check-wasm-closure \
         check-kani-divergence check-kani-proof-count check-gate-defs-match-plan; do
    [ -x "scripts/$s.sh" ] || continue
    case $s in
        check-kani-proof-count) run "$s --strict" bash "scripts/$s.sh" --strict ;;
        *) run "$s" bash "scripts/$s.sh" ;;
    esac
done
run "check-line-ratchet --strict" bash scripts/check-line-ratchet.sh --strict
# Three gates CI decides that this file did not, measured 2026-09-20 by pushing five branches
# green and watching CI red on each. All three already existed in the tree; none was a cost
# trade-off, just a list nobody reconciled. Timed before adding: 0 s and 3 s, against a fast
# gauntlet of about a minute. `check-clippy-ratchet` is the fourth and is NOT here -- 53 s warm
# and minutes cold, so it sits in --full below with the other clippy work.
run "check-gate-defs-match-plan" bash scripts/check-gate-defs-match-plan.sh
run "ci-spec check" cargo run -q -p xtask -- ci-spec check
# The gauntlet checking its own list. Cheap, and the only thing that stops a gate being added to
# CI and never reaching the fast path -- which is how three of today's five misses happened.
run "ci-spec local-coverage" cargo run -q -p xtask -- ci-spec local-coverage

# The Lean gates. Declared NOT-LOCAL on 2026-09-20 on the assumption that a developer has no
# Lean toolchain -- which was never tested and is wrong: `lean-toolchain` pins v4.30.0 and elan
# fetches it, none of these four projects `require` mathlib, and their `.lake` dirs are 1-3 MB.
# Measured warm: 5 s, 4 s, 2 s, 1 s. Four required contexts that CI alone was deciding.
# UNROLLED on purpose. A `for d in ...` loop hides the paths from
# `ci-spec local-coverage`, which checks that a declared decider appears VERBATIM in this file --
# and it caught the loop immediately. A list a checker cannot read is a list nobody reconciles,
# which is the whole reason that gate exists.
lean_build() {
    [ -f "$1/lakefile.lean" ] || return 0
    if have lake; then run "$2" sh -c "cd '$1' && lake build"
    else echo "  skip  $2 — lake not installed"; fi
}
lean_build ci/lean                          "lake build (ci/lean)"
lean_build crates/ck-policy/lean            "lake build (crates/ck-policy/lean)"
lean_build crates/nucleus-econ-kernels/lean "lake build (crates/nucleus-econ-kernels/lean)"
lean_build crates/nucleus-rubric/lean       "lake build (crates/nucleus-rubric/lean)"
run "check-lean-libs-built" bash scripts/check-lean-libs-built.sh
run "policy-kernel parity (K4)" cargo test -q -p nucleus-policy-kernel
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
if [ "$FULL" = 1 ]; then
    # 53 s warm, minutes cold: real, and not worth a minute on every push. It reds when a crate
    # that was unanalysable starts compiling, which is how a one-line feature gate turned out to
    # restore clippy coverage over a whole crate (#2979).
    run "check-clippy-ratchet --strict" bash scripts/check-clippy-ratchet.sh --strict
fi
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
