#!/usr/bin/env bash
# Exhaustive-destructure gate (dylint) — ADR 0007 E-1.
#
# No `..` in a record pattern over a policy or delegation record. For those
# records the field list IS the authority: a `..` means a field added later is
# handled by nobody, and on the delegation path that is a child pod inheriting a
# capability its parent never decided to grant.
#
# WHY THIS GATES AT ZERO
#
# Unlike `observed`, whose ceiling is 28, this one can. The pass is scoped by
# RECORD TYPE rather than by crate, and the six types it watches have zero
# rest-patterns across the whole workspace — production and test — measured
# 2026-09-11. Crate scoping was measured too and rejected: the policy crates
# carry 284 production rest-patterns (portcullis 145, portcullis-core 61,
# nucleus-tool-proxy 42), almost all of them correct, so a crate-wide ban would
# be hundreds of exceptions and a lint everyone suppresses.
#
# EXIT-STATUS TRAP
#
# `cargo dylint` exits 0 even when a `Warn`-level pass reports, so exit status is
# NOT the signal — COUNT the findings. A crate that fails to COMPILE reports zero
# findings, which would be a false green; that is guarded explicitly.
#
# REDS-ON-REVERT
#
# `--self-test` perturbs the REAL subject rather than a fixture: it replaces the
# bound fields of `create_sub_pod`'s `PodSpecInner` destructure with `..` — the
# exact shape ADR 0006 C4.2 removed — and asserts the count goes non-zero.
#
# Usage:
#   DYLINT_LIBRARY_PATH=<dir with built dylib> scripts/check-rest-pattern-dylint.sh
#   DYLINT_LIBRARY_PATH=<...>                  scripts/check-rest-pattern-dylint.sh --self-test
set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

LIB=nucleus_rest_pattern_lint
PATTERN='whose fields are the authority'
# The crates where the watched records are actually destructured: the delegation
# handler, the crate that defines the specs, the node that consumes them, and the
# lattice's own crate. The pass is type-scoped, so this list is about WHERE TO
# LOOK, not about what counts.
ENTRIES=(nucleus-tool-proxy nucleus-spec nucleus-node portcullis)

: "${DYLINT_LIBRARY_PATH:?set DYLINT_LIBRARY_PATH to the directory holding the built ${LIB} dylib}"

count_rest() {
    FOUND=0
    COMPILE_FAIL=0
    local args=() out
    for e in "${ENTRIES[@]}"; do args+=(-p "$e"); done
    echo "::group::rest_pattern_on_policy_path over ${ENTRIES[*]}"
    out=$(cargo dylint --lib "$LIB" -- "${args[@]}" --all-features 2>&1) || true
    echo "$out"
    echo "::endgroup::"
    if printf '%s\n' "$out" | grep -qE 'could not compile|Compilation failed'; then
        echo "::error::an entry crate failed to compile under the lint — zero findings would be a false green."
        COMPILE_FAIL=1
    fi
    FOUND=$(printf '%s\n' "$out" | grep -c "$PATTERN" || true)
    echo "rest_pattern_on_policy_path: ${FOUND} finding(s)"
}

self_test() {
    local target=crates/nucleus-tool-proxy/src/pod_mgmt.rs
    local backup
    backup=$(mktemp)
    cp "$target" "$backup"
    # Restore on ANY exit — a delegation handler left destructuring with `..` is
    # the defect itself.
    # shellcheck disable=SC2064
    trap "cp '$backup' '$target'; rm -f '$backup'" EXIT INT TERM

    # Collapse the forwarded-field block back into a `..`: the shape C4.2
    # removed, and the one this gate exists to keep out.
    python3 - "$target" <<'PY'
import sys
p = sys.argv[1]
lines = open(p).read().split('\n')
try:
    start = next(i for i, l in enumerate(lines) if l.strip().startswith('work_dir: _work_dir,'))
    end = next(i for i in range(start, len(lines)) if lines[i].strip() == '} = &spec.spec;')
except StopIteration:
    sys.exit("self-test anchor missing: create_sub_pod's PodSpecInner destructure not found")
del lines[start:end]
lines.insert(start, '        ..')
open(p, 'w').write('\n'.join(lines))
PY
    if [ $? -ne 0 ]; then
        echo "::error::self-test could not perturb ${target}."
        return 1
    fi

    count_rest
    local perturbed=$FOUND
    local failed=$COMPILE_FAIL

    cp "$backup" "$target"
    rm -f "$backup"
    trap - EXIT INT TERM

    if [ "$failed" -ne 0 ]; then
        echo "::error::self-test could not compile the perturbed tree — cannot prove the gate fires."
        return 1
    fi
    if [ "$perturbed" -lt 1 ]; then
        echo "::error::reds-on-revert FAILED: collapsing create_sub_pod's destructure to \`..\`"
        echo "         produced ${perturbed} finding(s) (expected >= 1). The gate cannot detect"
        echo "         its own subject and is therefore not a gate."
        return 1
    fi
    echo "reds-on-revert OK: a \`..\` on the delegation path produced ${perturbed} finding(s); the gate fires."
    return 0
}

case "${1:-}" in
    --self-test)
        self_test
        exit $?
        ;;
    "")
        count_rest
        if [ "$COMPILE_FAIL" -ne 0 ]; then
            exit 1
        fi
        if [ "$FOUND" -ne 0 ]; then
            echo "::error::${FOUND} record pattern(s) on a policy path use \`..\`. For these records the"
            echo "         field list IS the authority: a field the pattern does not mention is one"
            echo "         nobody decided about, and on a delegation path that is a capability granted"
            echo "         by default. Name every field; bind it to \`_name\` with a reason if"
            echo "         forwarding it unclamped is the standing decision."
            exit 1
        fi
        echo "OK: no \`..\` in a record pattern on a policy path (0 findings)."
        exit 0
        ;;
    *)
        echo "usage: $0 [--self-test]" >&2
        exit 2
        ;;
esac
