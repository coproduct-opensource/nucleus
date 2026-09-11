#!/usr/bin/env bash
# Unobserved-ingest ratchet (dylint) — the SOURCE-SIDE dual of the mediation gate.
#
# `mediated` asks: does every path to an effect cross an authority boundary?
# This asks the other half: does every path that ingests external bytes reach an
# observe? Bytes that enter a session unobserved create no flow node, so the IFC
# gate cannot see them and every theorem downstream is conditioned on an
# antecedent nothing enforces.
#
# WHY A RATCHET, NOT A ZERO GATE
#
# See `.observed-ratchet.toml`. In one line: the agent-facing crate also does
# infrastructure I/O, the two live together, and scoping by handler would be a
# hand-maintained list. The count is 28 and may only shrink.
#
# EXIT-STATUS TRAP
#
# `cargo dylint` exits 0 even when a `Warn`-level pass reports, so exit status is
# NOT the signal — COUNT the findings. A crate that fails to COMPILE reports zero
# findings, which would be a false green; that is guarded explicitly.
#
# REDS-ON-REVERT
#
# `--self-test` proves the gate can fail on its own subject: it deletes the
# `http_observe_command_output` call from `run_command` — the exact defect this
# pass was written after, `/v1/run` returning subprocess stdout while observing
# nothing — and asserts the count rises ABOVE the ceiling. Asserting "non-zero"
# would prove nothing here, because the clean tree is already non-zero.
#
# Usage:
#   DYLINT_LIBRARY_PATH=<dir with built dylib> scripts/check-observed-dylint.sh
#   DYLINT_LIBRARY_PATH=<...>                  scripts/check-observed-dylint.sh --self-test
set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

LIB=nucleus_observed_lint
ENTRY=nucleus-tool-proxy
PATTERN='is reachable'
RATCHET_FILE=.observed-ratchet.toml

[ -f "$RATCHET_FILE" ] || { echo "::error::$RATCHET_FILE missing"; exit 1; }
CEILING=$(grep -E '^ceiling *= *[0-9]+' "$RATCHET_FILE" | head -1 | grep -oE '[0-9]+')
[ -n "$CEILING" ] || { echo "::error::no ceiling parsed from $RATCHET_FILE"; exit 1; }

: "${DYLINT_LIBRARY_PATH:?set DYLINT_LIBRARY_PATH to the directory holding the built ${LIB} dylib}"

# Sets globals FOUND and COMPILE_FAIL.
count_observed() {
    FOUND=0
    COMPILE_FAIL=0
    local out
    echo "::group::observed over ${ENTRY}"
    out=$(cargo dylint --lib "$LIB" -- -p "$ENTRY" 2>&1) || true
    echo "$out"
    echo "::endgroup::"
    if printf '%s\n' "$out" | grep -qE 'could not compile|Compilation failed'; then
        echo "::error::${ENTRY} failed to compile under the lint — zero findings would be a false green."
        COMPILE_FAIL=1
    fi
    FOUND=$(printf '%s\n' "$out" | grep -c "$PATTERN" || true)
    echo "observed: ${FOUND} unobserved-ingest finding(s), ceiling ${CEILING}"
}

self_test() {
    local target=crates/nucleus-tool-proxy/src/main.rs
    local backup
    backup=$(mktemp)
    cp "$target" "$backup"
    # Restore on ANY exit — a tool-proxy left missing its observe is worse than
    # no check.
    # shellcheck disable=SC2064
    trap "cp '$backup' '$target'; rm -f '$backup'" EXIT INT TERM

    # Delete the observation `/v1/run` makes of its own subprocess output. This
    # is the defect the pass was written after: found by reading, fixed by hand,
    # and invisible to everything else in the repository.
    if ! grep -q 'http_observe_command_output' "$target"; then
        echo "::error::self-test anchor missing: no http_observe_command_output call in ${target}."
        return 1
    fi
    sed -i.bak '/http_observe_command_output/d' "$target" && rm -f "${target}.bak"

    count_observed
    local perturbed=$FOUND
    local failed=$COMPILE_FAIL

    cp "$backup" "$target"
    rm -f "$backup"
    trap - EXIT INT TERM

    if [ "$failed" -ne 0 ]; then
        echo "::error::self-test could not compile ${ENTRY} — cannot prove the gate fires."
        return 1
    fi
    if [ "$perturbed" -le "$CEILING" ]; then
        echo "::error::reds-on-revert FAILED: deleting run_command's observe produced ${perturbed}"
        echo "         finding(s) against a ceiling of ${CEILING} (expected > ${CEILING}). The gate"
        echo "         cannot detect its own subject and is therefore not a gate."
        return 1
    fi
    echo "reds-on-revert OK: deleting run_command's observe took the count to ${perturbed} (> ${CEILING}); the gate fires."
    return 0
}

case "${1:-}" in
    --self-test)
        self_test
        exit $?
        ;;
    "")
        count_observed
        if [ "$COMPILE_FAIL" -ne 0 ]; then
            exit 1
        fi
        if [ "$FOUND" -gt "$CEILING" ]; then
            echo "::error::unobserved ingest rose to ${FOUND}, above the ceiling of ${CEILING}."
            echo "         Bytes that enter a session without an observation are invisible to the"
            echo "         IFC gate. Observe them, or lower the ceiling in ${RATCHET_FILE} with a"
            echo "         reason if this count is genuinely correct now."
            exit 1
        fi
        if [ "$FOUND" -lt "$CEILING" ]; then
            echo "::notice::unobserved ingest fell to ${FOUND}, below the ceiling of ${CEILING}."
            echo "          Lower the ceiling in ${RATCHET_FILE} in this change to keep the gain."
        fi
        echo "OK: ${FOUND} unobserved-ingest finding(s), at or below the ceiling of ${CEILING}."
        exit 0
        ;;
    *)
        echo "usage: $0 [--self-test]" >&2
        exit 2
        ;;
esac
