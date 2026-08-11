#!/usr/bin/env bash
# Enforcing mediation gate (dylint) — the SEALED EFFECT BOUNDARY admits no
# unmediated raw I/O sink.
#
# This is the enforcement half of C6's complete-mediation program. Phase 1a
# landed the Lean Tier-A theorem (`no_sink_reachable_without_discharge`); this
# discharges its premise over the real Rust: every publicly reachable path to a
# raw I/O primitive inside the mediated set passes through a function demanding
# an `Authority` by value.
#
# WHAT IS GATED
#
# The `mediated` dylint pass is invoked over `portcullis-effects` — the sealed
# agent-effect boundary. `cargo dylint -- -p <crate>` compiles and lints the
# whole workspace dependency closure, but the pass emits the "reaches raw I/O,
# demands no `Authority`" finding ONLY for crates in its `MEDIATED_CRATES` set
# (currently `portcullis_effects`). The host runtime's own infrastructure I/O —
# config loaders, audit/lineage persistence, keyless-identity fetch, attestation
# clients, sandbox setup — is out of scope by the same reasoning that puts jailer
# spawn and HTTP serving out of scope: it is not agent-attributed effect. This is
# a CRATE scope, not a call-site allowlist; within a mediated crate every such
# site is still reported.
#
# WHAT IS NOT GATED (advisory)
#
# The pass also reports unresolved calls (`dyn`/fn-pointer/closure) as a
# call-graph-soundness signal, for EVERY crate. Those are printed but NOT counted
# here: a higher-order call is a call-graph observation, not an unmediated sink,
# and the effect home legitimately uses closures (the `harden` spawn hook, the
# `with_typed_context` callback). Brandon's decision (C6 phase 1b): closure
# reports stay advisory; only the unmediated-I/O count gates.
#
# EXIT-STATUS TRAP
#
# `cargo dylint` exits 0 even when the `Warn`-level pass reports, so exit status
# is NOT the signal — COUNT the findings. A crate that fails to COMPILE reports
# zero findings, which would be a false green; that is guarded explicitly.
#
# REDS-ON-REVERT
#
# `--self-test` proves the gate can fail on its own subject: it appends an
# unmediated raw-I/O sink to the sealed effect home, asserts the count goes
# non-zero, and restores. Run in the mediated CI job (which has the pinned dylint
# toolchain) BEFORE the real enforcement. A gate that cannot fail is not a gate.
#
# Usage:
#   DYLINT_LIBRARY_PATH=<dir with built dylib> scripts/check-mediation-dylint.sh
#   DYLINT_LIBRARY_PATH=<...>                   scripts/check-mediation-dylint.sh --self-test
set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

LIB=nucleus_mediation_lint
# The mediated set's compile entry point. `-p portcullis-effects` compiles and
# lints portcullis-effects itself plus its whole dependency closure, so the
# closure's infra crates also pass through the (scoped) pass — which is exactly
# how we prove the scope holds within it.
MEDIATED_ENTRY=portcullis-effects
IO_PATTERN='but demands no `Authority`'
CLOSURE_PATTERN='cannot see past this'

: "${DYLINT_LIBRARY_PATH:?set DYLINT_LIBRARY_PATH to the directory holding the built ${LIB} dylib}"

# Sets globals IO_TOTAL and COMPILE_FAIL from a run over the mediated entry point.
count_io() {
    IO_TOTAL=0
    COMPILE_FAIL=0
    local out io clo
    echo "::group::mediated over ${MEDIATED_ENTRY} (+ dependency closure)"
    out=$(cargo dylint --lib "$LIB" -- -p "$MEDIATED_ENTRY" 2>&1) || true
    echo "$out"
    echo "::endgroup::"
    if printf '%s\n' "$out" | grep -qE 'could not compile|Compilation failed'; then
        echo "::error::${MEDIATED_ENTRY} failed to compile under the lint — zero findings would be a false green."
        COMPILE_FAIL=1
    fi
    io=$(printf '%s\n' "$out" | grep -c "$IO_PATTERN" || true)
    clo=$(printf '%s\n' "$out" | grep -c "$CLOSURE_PATTERN" || true)
    echo "mediated: ${io} unmediated-I/O finding(s), ${clo} closure/unresolved (advisory, not gated)"
    IO_TOTAL=$io
}

self_test() {
    local target=crates/portcullis-effects/src/lib.rs
    local backup
    backup=$(mktemp)
    cp "$target" "$backup"
    # Restore on ANY exit — a half-perturbed effect home left behind is worse
    # than no check.
    # shellcheck disable=SC2064
    trap "cp '$backup' '$target'; rm -f '$backup'" EXIT INT TERM

    cat >> "$target" <<'RS'

// --- reds-on-revert probe (appended by scripts/check-mediation-dylint.sh --self-test) ---
// A publicly reachable raw filesystem sink that demands no Authority — exactly
// what the enforcing gate exists to forbid inside the sealed effect home. If the
// gate does NOT red on this, it has stopped detecting its own subject.
pub fn __mediation_gate_selftest_unmediated_sink(p: &std::path::Path) {
    let _ = std::fs::write(p, b"");
}
RS

    count_io
    # Restore now so the assertion below runs against a clean tree regardless.
    cp "$backup" "$target"
    rm -f "$backup"
    trap - EXIT INT TERM

    if [ "$COMPILE_FAIL" -ne 0 ]; then
        echo "::error::self-test could not compile the effect home — cannot prove the gate fires."
        return 1
    fi
    if [ "$IO_TOTAL" -lt 1 ]; then
        echo "::error::reds-on-revert FAILED: an unmediated raw-I/O sink in portcullis-effects"
        echo "         produced ${IO_TOTAL} finding(s) (expected >= 1). The enforcing gate"
        echo "         cannot detect its own subject and is therefore not a gate."
        return 1
    fi
    echo "reds-on-revert OK: an unmediated sink in the effect home produced ${IO_TOTAL} finding(s); the gate fires."
    return 0
}

case "${1:-}" in
    --self-test)
        self_test
        exit $?
        ;;
    "")
        count_io
        if [ "$COMPILE_FAIL" -ne 0 ]; then
            exit 1
        fi
        if [ "$IO_TOTAL" -ne 0 ]; then
            echo "::error::the sealed effect boundary reached raw I/O without demanding an \
Authority (${IO_TOTAL} finding(s)). Every path to a raw sink inside portcullis-effects must \
take an Authority by value and spend it. See tools/nucleus-mediation-lint/README.md."
            exit 1
        fi
        echo "OK: the sealed effect boundary admits no unmediated raw I/O sink (0 findings)."
        exit 0
        ;;
    *)
        echo "usage: $0 [--self-test]" >&2
        exit 2
        ;;
esac
