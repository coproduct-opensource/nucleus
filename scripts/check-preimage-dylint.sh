#!/usr/bin/env bash
# Digest-preimage gate (dylint) — `debug_format_in_preimage`.
#
# A value formatted for humans must not reach a hash or signature preimage.
# `Debug` and `Display` are presentation, not encoding: neither is covered by
# semver, both get changed for readability by someone who has no idea a digest
# depends on one, and a derived `Debug` changes silently when a variant gains a
# field. A chain anchored on one is only verifiable inside a single build.
#
# THE TWO DEFECTS THIS WAS BUILT FROM
#
#   crates/portcullis/src/audit.rs         `AuditEntry::content_hash` hashed
#                                          `format!("{:?}", self.event)` — the
#                                          link in the audit chain that
#                                          `executor_sig` then signs.
#   crates/portcullis-core/src/            `ProvenanceNode::compute_id` did the
#     provenance_node.rs                   same with a node kind, inside a
#                                          content address.
#
# Both now build their preimage from an exhaustive match over an explicit
# encoding, tagged and length-prefixed. That is why this gates at ZERO rather
# than at a baseline: the population it watches is empty and staying empty is
# the claim.
#
# WHY `--all-features` IS LOAD-BEARING
#
# `compute_id` sits behind `#[cfg(any(feature = "artifact", feature =
# "wasm-sandbox"))]`. Without the flag the pass compiles a crate that does not
# contain the thing it is looking for and reports a confident zero — the same
# trap the egress pass documents for `DrandClient::new`.
#
# EXIT-STATUS TRAP
#
# `cargo dylint` exits 0 even when a `Warn`-level pass reports, so exit status
# is NOT the signal — COUNT the findings. A crate that fails to COMPILE reports
# zero findings, which would also be a false green; that is guarded explicitly.
#
# REDS-ON-REVERT
#
# `--self-test` perturbs the REAL subject, not a fixture: it puts
# `content_hash`'s `format!("{:?}", self.event)` back and asserts the count goes
# non-zero. On an all-zero gate this is the only thing standing between "clean"
# and "the pass never loaded", so it runs before the enforcing pass every time.
#
# Usage:
#   DYLINT_LIBRARY_PATH=<dir with built dylib> scripts/check-preimage-dylint.sh
#   DYLINT_LIBRARY_PATH=<...>                  scripts/check-preimage-dylint.sh --self-test
set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

LIB=nucleus_preimage_lint
PATTERN='a value formatted for humans reaches'
# The crates where a preimage anchors a security claim: the audit chain and its
# executor signature, the content addresses, the signed receipt envelope, the
# transparency log and its signed notes, the launch attestation, the bundle
# verifier, and `program_digest`. Crates that merely hash something are not in
# scope; this list is a claim about WHERE A FORKED DIGEST BREAKS A GUARANTEE.
ENTRIES=(
    portcullis
    portcullis-core
    nucleus-receipt
    nucleus-lineage
    nucleus-identity
    nucleus-envelope
    nucleus-spec
)

: "${DYLINT_LIBRARY_PATH:?set DYLINT_LIBRARY_PATH to the directory holding the built ${LIB} dylib}"

count_preimage() {
    FOUND=0
    COMPILE_FAIL=0
    local args=() out
    for e in "${ENTRIES[@]}"; do args+=(-p "$e"); done
    echo "::group::debug_format_in_preimage over ${ENTRIES[*]}"
    out=$(cargo dylint --lib "$LIB" -- "${args[@]}" --all-features 2>&1) || true
    echo "$out"
    echo "::endgroup::"
    if printf '%s\n' "$out" | grep -qE 'could not compile|Compilation failed'; then
        echo "::error::an entry crate failed to compile under the pass — zero findings would be a false green."
        COMPILE_FAIL=1
    fi
    FOUND=$(printf '%s\n' "$out" | grep -c "$PATTERN" || true)
    echo "debug_format_in_preimage: ${FOUND} finding(s)"
}

self_test() {
    local target=crates/portcullis/src/audit.rs
    local backup
    backup=$(mktemp)
    cp "$target" "$backup"
    # Restore on ANY exit — a hash chain left keyed on `Debug` is the defect.
    # shellcheck disable=SC2064
    trap "cp '$backup' '$target'; rm -f '$backup'" EXIT INT TERM

    # Put the original defect back: the framed absorption of `digest_parts`
    # becomes the one `format!("{:?}", ..)` it replaced.
    python3 - "$target" <<'PY'
import sys
p = sys.argv[1]
src = open(p).read()
framed = """        for (tag, part) in self.event.digest_parts() {
            hasher.update(tag.as_bytes());
            hasher.update(b"\\x00");
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }"""
if framed not in src:
    sys.exit("self-test anchor missing: content_hash's framed absorption not found")
open(p, 'w').write(src.replace(
    framed,
    '        hasher.update(format!("{:?}", self.event).as_bytes());',
    1,
))
PY
    if [ $? -ne 0 ]; then
        echo "::error::self-test could not perturb ${target}."
        return 1
    fi

    count_preimage
    local perturbed=$FOUND
    local failed=$COMPILE_FAIL

    cp "$backup" "$target"
    rm -f "$backup"
    trap - EXIT INT TERM

    if [ "$failed" -ne 0 ]; then
        echo "::error::self-test could not compile the perturbed tree — cannot prove the pass fires."
        return 1
    fi
    if [ "$perturbed" -lt 1 ]; then
        echo "::error::reds-on-revert FAILED: restoring content_hash's \`format!(\"{:?}\", event)\`"
        echo "         produced ${perturbed} finding(s) (expected >= 1). The pass cannot detect the"
        echo "         defect it was written for, so the zero below means nothing."
        return 1
    fi
    echo "reds-on-revert OK: the original defect produced ${perturbed} finding(s); the pass is live."
    return 0
}

case "${1:-}" in
    --self-test)
        self_test
        exit $?
        ;;
    "")
        count_preimage
        if [ "$COMPILE_FAIL" -ne 0 ]; then
            exit 1
        fi
        if [ "$FOUND" -ne 0 ]; then
            echo "::error::${FOUND} formatted value(s) reach a digest or signature preimage."
            echo "         \`Debug\` and \`Display\` are presentation, not encoding: a rename or a"
            echo "         readability edit forks the digest, and a derived \`Debug\` stops"
            echo "         committing a field the moment someone removes it. Give the type a"
            echo "         pinned encoding built from an exhaustive match, and absorb each part"
            echo "         tagged and length-prefixed. \`PermissionEvent::digest_parts\` and"
            echo "         \`ProvenanceNodeKind::digest_tag\` are the two worked examples."
            exit 1
        fi
        echo "OK: no formatted value reaches a preimage in the watched crates (0 findings)."
        exit 0
        ;;
    *)
        echo "usage: $0 [--self-test]" >&2
        exit 2
        ;;
esac
