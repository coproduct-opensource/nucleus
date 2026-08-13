#!/usr/bin/env bash
# The gate of gates: every check-*.sh must FAIL on its own subject.
#
# WHY THIS EXISTS
#
# Over two days, ten defects in this repo were found and every one was green.
# The ones with the widest blast radius were not in the runtime — they were in
# the things watching it:
#
#   * two flagship Lean proofs that no CI job compiled (#2162);
#   * three theorem builds whose failure reported success, because `cmd | tee`
#     under GitHub's default `bash -e` shell returns TEE's exit status;
#   * the VENDOR-NEUTRALITY gate, whose script exits 1 into a discarded
#     pipeline — and whose `if: failure()` PR-comment step therefore never fired;
#   * a cargo-mutants job that printed "All mutants caught by tests" when the
#     run had crashed, because its checker gates on `grep -q SURVIVED || pass`.
#
# Each was found one at a time, by accident, while doing something else. A gate
# that cannot fail is indistinguishable from a gate that passes, and nothing in
# this repo was checking the difference.
#
# So: for each gate, introduce a REAL violation of the property it names, assert
# it exits non-zero, restore, and assert it exits zero again. Both halves are
# required — a gate that fails on everything is as useless as one that fails on
# nothing, and only the restore half can tell them apart.
#
# HONEST COVERAGE
#
# Not every gate has a perturbation here yet. The uncovered ones are LISTED, not
# omitted, and their count is a ratchet that may only shrink — because a meta-gate
# that silently covered half the gates would be the exact vacuity it exists to
# find.
#
# Usage: scripts/check-gates-can-fail.sh
set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

# A dirty tree cannot be safely perturbed: the restore step would have to guess
# what was yours. Refuse rather than risk it — `git checkout -- <file>` has
# destroyed uncommitted work in this repo before.
if [[ -n "$(git status --porcelain)" ]]; then
    echo "ERROR: the working tree is dirty. This script edits real files and"
    echo "restores them from a copy; running it over uncommitted work risks that"
    echo "work. Commit or stash first."
    exit 1
fi

RESTORE_FROM=""
RESTORE_TO=""
restore() {
    if [[ -n "$RESTORE_FROM" && -f "$RESTORE_FROM" ]]; then
        cp "$RESTORE_FROM" "$RESTORE_TO"
        rm -f "$RESTORE_FROM"
    fi
}
# Restore on ANY exit, including a signal — a half-perturbed tree left behind by
# an interrupted run is worse than no check.
trap restore EXIT INT TERM

failures=0
covered=0

# probe <gate-script> <ci-flags> <file-to-perturb> <description> <perturb-command...>
#
# `ci-flags` must be exactly how CI invokes the gate, and is CHECKED against the
# workflow files below — running a gate differently from CI is how a local green
# and a CI red diverge, and this script would otherwise be the newest instance of
# that. `check-line-ratchet.sh` only exits 1 with `--strict`; probing it without
# the flag reported the gate as broken when the gate was fine.
probe() {
    local gate="$1" ci_flags="$2" target="$3" desc="$4"
    shift 4

    # The invocation must match the workflows, or this script is testing
    # something CI does not run.
    #
    # FIRST: is it run by CI AT ALL? The flag comparison below cannot answer
    # that — a gate no workflow mentions yields an empty `in_ci`, which equals
    # the common `ci_flags=""` and passes. So "CI runs it with no flags" and "CI
    # never runs it" were the same result, and an unwired gate probed as green.
    # That is how `check-test-helpers-not-in-production.sh` shipped invoked by
    # zero workflows. Absence of a match is not evidence of a bare invocation.
    local workflow_hits
    workflow_hits="$(grep -rl "scripts/$gate" .github/workflows/ 2>/dev/null | wc -l | tr -d ' ')"
    if [[ "$workflow_hits" -eq 0 ]]; then
        echo "  FAIL  $gate — no workflow under .github/workflows/ invokes it"
        echo "        The gate can fail locally and never run. A gate CI does not"
        echo "        call enforces nothing, however carefully it is written."
        failures=$((failures + 1))
        return
    fi

    local in_ci
    in_ci="$(grep -rhoE "scripts/$gate[^\"']*" .github/workflows/ 2>/dev/null | head -1 | sed "s|scripts/$gate||" | xargs || true)"
    if [[ "$in_ci" != "$ci_flags" ]]; then
        echo "  FAIL  $gate — CI invokes it as '$gate $in_ci' but this probe uses '$gate $ci_flags'"
        echo "        Probing a gate differently from CI tests something CI does not run."
        failures=$((failures + 1))
        return
    fi

    if [[ ! -f "scripts/$gate" ]]; then
        echo "  ERROR: scripts/$gate does not exist"
        failures=$((failures + 1))
        return
    fi

    RESTORE_TO="$target"
    RESTORE_FROM="$(mktemp)"
    cp "$target" "$RESTORE_FROM"

    "$@" "$target"

    local perturbed_rc=0
    # shellcheck disable=SC2086 — ci_flags is a deliberate word-split.
    bash "scripts/$gate" $ci_flags >/dev/null 2>&1 || perturbed_rc=$?

    restore
    RESTORE_FROM=""

    local restored_rc=0
    # shellcheck disable=SC2086
    bash "scripts/$gate" $ci_flags >/dev/null 2>&1 || restored_rc=$?

    covered=$((covered + 1))
    if [[ "$perturbed_rc" -eq 0 ]]; then
        echo "  FAIL  $gate — $desc did NOT fail the gate (exit 0)"
        echo "        The gate cannot detect the thing it is named for."
        failures=$((failures + 1))
    elif [[ "$restored_rc" -ne 0 ]]; then
        echo "  FAIL  $gate — still failing (exit $restored_rc) after restore"
        echo "        Either the restore is broken or the gate fails on everything,"
        echo "        and a gate that always fails detects nothing either."
        failures=$((failures + 1))
    else
        echo "  ok    $gate — RED on $desc, GREEN when restored"
    fi
}

# ── Perturbations ─────────────────────────────────────────────────────────
# Each introduces a real violation of the gate's OWN stated property, not a
# syntax error that would fail any check.

append_line() { printf '%s\n' "$2" >> "$1"; }

perturb_line_ratchet() {
    # The ratchet caps file length. Push a monitored file past its ceiling.
    for _ in $(seq 1 400); do echo "// gate-of-gates padding" >> "$1"; done
}

perturb_mediation() {
    # A raw process spawn on the agent effect path, which must go through the
    # discharge-gated effect API.
    append_line "$1" 'fn _gate_of_gates() { let _ = std::process::Command::new("sh"); }'
}

perturb_sealed_home() {
    # A raw spawn inside the sealed home that is not on its allowlist.
    append_line "$1" 'fn _gate_of_gates_unlisted() { let _ = Command::new("definitely-not-allowlisted"); }'
}

perturb_verify_strict() {
    # Non-strict dalek verification: the cofactored form audit finding M-3 forbids.
    # The gate matches the dalek TWO-ARGUMENT shape `.verify(msg, &sig)` — the
    # `&` is part of the pattern, and a probe written as `.verify(m, s)` slips
    # past it and reports the gate as broken.
    append_line "$1" 'use ed25519_dalek::Verifier;'
    append_line "$1" 'fn _gate_of_gates_weak(k: &ed25519_dalek::VerifyingKey, m: &[u8], s: ed25519_dalek::Signature) -> bool { k.verify(m, &s).is_ok() }'
}

perturb_failclosed() {
    # A VERIFIER that reports success on a platform where it cannot check. The
    # gate matches a `cfg(not(target_os = ...))` stub whose name starts with
    # verify/check/assert/ensure/validate/is/has and whose body returns Ok(()).
    cat >> "$1" <<'RS'

#[cfg(not(target_os = "linux"))]
fn verify_gate_of_gates_stub() -> Result<(), String> {
    Ok(())
}
RS
}

perturb_ingest_hashed() {
    # An agent-input ingest that does not content-address what it observed.
    append_line "$1" 'fn _gate_of_gates_ingest(f: &mut FlowTracker) { f.observe(NodeKind::WebFetch); }'
}

perturb_lean_lib_unbuilt() {
    # A `lean_lib` no workflow builds, nothing imports, and that is not on the
    # gate's allowlist — the gate's exact subject. Appended to a lakefile whose
    # package declares no `@[default_target]`, so a bare `lake build` would not
    # cover it either.
    cat >> "$1" <<'LEAN'

lean_lib «GateOfGatesUnbuiltProbe» where
  roots := #[`GateOfGatesUnbuiltProbe]
LEAN
}

perturb_test_helpers_in_prod() {
    # `test-helpers` reachable from a SHIPPING build, which is the gate's whole
    # subject: with it on, `discharge::test_helpers::bundle_for` mints a
    # DischargedBundle with no preflight from production code.
    #
    # nucleus-ifc-kernel is ALREADY a normal [dependencies] edge of
    # nucleus-tool-proxy, so this only adds a feature to an existing edge — it
    # creates no new dependency and therefore no Cargo.lock change (features are
    # not recorded in the lockfile). That is why this gate is probeable and the
    # other two are not; they need a genuine graph change.
    sed -i.gate-bak \
        's|^nucleus-ifc-kernel = { path = "../nucleus-ifc-kernel", version = "1.0.0" }$|nucleus-ifc-kernel = { path = "../nucleus-ifc-kernel", version = "1.0.0", features = ["test-helpers"] }|' \
        "$1"
    rm -f "$1.gate-bak"
    # If the manifest line is reworded, the sed above silently no-ops and the
    # probe reports the gate as broken when the gate is fine. Fail loudly instead.
    if ! grep -q 'nucleus-ifc-kernel.*features = \["test-helpers"\]' "$1"; then
        echo "  ERROR: the nucleus-ifc-kernel dependency line changed shape;"
        echo "         this perturbation no longer applies and must be updated."
        return 1
    fi
}

perturb_trusted_base() {
    # A manifest entry pinned by a test that does not exist — the gate's whole
    # subject is that `pinned_by:` is prose until something confirms the test.
    append_line "$1" 'gate_of_gates_fake_component pinned_by:definitely_not_a_real_test_anywhere'
}

# The EXACT defect the North Star ledger gate was built for: the status row
# that claimed "tested on the live path" for the declassification token while
# the dormancy gate asserted that path has no production caller. Not a
# synthetic perturbation — this row is quoted verbatim from the table as it
# stood when the gate was written, so a gate that greens on it has stopped
# detecting its own founding defect.
perturb_ledger_restore_false_row() {
    local f="$1"
    local legacy='| Declassification is single-use and not adversary-steerable | **Proved** in the model; **tested** on the live path (spent-token set keyed on the Ed25519 signature) |'
    if ! awk -v legacy="$legacy" '
        $0 ~ /^\| C4 \|/ { print legacy; hit = 1; next }
        { print }
        END { exit hit ? 0 : 1 }
    ' "$f" > "$f.gate-tmp"; then
        rm -f "$f.gate-tmp"
        echo "  ERROR: no '| C4 |' row found in $f;"
        echo "         the ledger's C4 row moved and this perturbation must be updated."
        return 1
    fi
    mv "$f.gate-tmp" "$f"
}

echo "Probing whether each gate fails on its own subject..."
echo

# Revert the sink-scope enforcement: widen the applied mask to admit EVERY sink,
# so a token scoped to one sink clears its node for all of them again — the
# exact over-grant the enforcement gate exists to catch. The two-oracle graph
# binding then sees off-mask operations get the released view and reds.
perturb_declassify_unscope() {
    local f="$1"
    sed -i.gate-bak \
        's/sink_mask: token.sink_mask(),/sink_mask: 0xFFFFu16,/' \
        "$f"
    rm -f "$f.gate-bak"
    # If the field assignment is reworded, the sed silently no-ops and the probe
    # reports the gate as broken when it is fine. Fail loudly instead.
    if ! grep -q 'sink_mask: 0xFFFFu16,' "$f"; then
        echo "  ERROR: apply_token's 'sink_mask: token.sink_mask()' line changed shape;"
        echo "         this perturbation no longer applies and must be updated."
        return 1
    fi
}

# A caller of set_trusted_keys OUTSIDE kernel construction — the exact event the
# seal gate exists to catch. Appended to a workload-reachable handler module so
# it is unambiguously not a construction site.
perturb_governor_keys_unsealed() {
    local f="$1"
    cat >> "$f" <<'RS'

#[allow(dead_code)]
fn _gate_of_gates_unseal(k: &mut nucleus::portcullis::kernel::Kernel) {
    k.set_trusted_keys(vec![[0u8; 32]]);
}
RS
}

# Neuter the reserved-namespace fail-safe (C1 fence D): make its OrdinaryData
# guard always false, so an unclassified NUCLEUS_* key is no longer refused at
# admission. The gate's `an_unclassified_reserved_namespace_key_is_refused` test
# then reds. (Fence B, the uid distinctness, is the gate's other subject; one
# perturbation is enough to prove the gate can fail.)
perturb_c1_inbound_fence() {
    local f="$1"
    sed -i.gate-bak \
        's/&& entry.material == MaterialKind::OrdinaryData/\&\& false/' \
        "$f"
    rm -f "$f.gate-bak"
    if grep -q '&& entry.material == MaterialKind::OrdinaryData' "$f"; then
        echo "  ERROR: admit()'s reserved-namespace guard changed shape;"
        echo "         this perturbation no longer applies and must be updated."
        return 1
    fi
}

# Neuter VALUE-BINDING: make FlowGraph::value_binding_ok always true, so a
# substituted value is no longer refused ContentMismatch — the exact over-release
# the value-bound gate exists to catch. The gate's kernel_token /
# declassify_rehome_egress / four-run substitution tests then red.
perturb_declassify_value_unbind() {
    local f="$1"
    sed -i.gate-bak \
        's|committed != \[0u8; 32\] && recorded == Some(committed)|{ let _ = (committed, recorded); true }|' \
        "$f"
    rm -f "$f.gate-bak"
    # If value_binding_ok's body is reworded, the sed silently no-ops and the probe
    # reports the gate as broken when it is fine. Fail loudly instead.
    if ! grep -q 'let _ = (committed, recorded); true' "$f"; then
        echo "  ERROR: FlowGraph::value_binding_ok's body changed shape;"
        echo "         this perturbation no longer applies and must be updated."
        return 1
    fi
}

perturb_extracted_callsite() {
    local f="$1"
    # Break the live call to the extracted ident_may_deliver predicate (the FM-5
    # delivery guard, manifest class A). Its production occurrence count drops to
    # zero, so check-extracted-callsites.sh must red — a theorem about a predicate
    # nothing on the live path calls is a proof about dead code.
    sed -i.gate-bak \
        's|if !ident_may_deliver(entry.material|if !ident_may_deliver_REMOVED(entry.material|' \
        "$f"
    rm -f "$f.gate-bak"
    if ! grep -q 'ident_may_deliver_REMOVED' "$f"; then
        echo "  ERROR: the ident_may_deliver call site in workload.rs changed shape;"
        echo "         this perturbation no longer applies and must be updated."
        return 1
    fi
}

probe check-line-ratchet.sh   "--strict" crates/portcullis/src/kernel.rs \
      "400 lines past the ceiling"            perturb_line_ratchet
probe check-mediation.sh      "" crates/nucleus-tool-proxy/src/egress.rs \
      "a raw Command::new on the agent path"  perturb_mediation
probe check-sealed-home.sh    "" crates/portcullis-effects/src/lib.rs \
      "an un-allowlisted spawn in the sealed home" perturb_sealed_home
probe check-verify-strict.sh  "" crates/nucleus-identity/src/lib.rs \
      "a non-strict dalek .verify()"          perturb_verify_strict
probe check-failclosed-verifiers.sh "" crates/nucleus-identity/src/lib.rs \
      "a verifier returning Ok where it cannot check" perturb_failclosed
probe check-ingest-hashed.sh  "" crates/nucleus-tool-proxy/src/egress.rs \
      "an unwitnessed .observe() ingest"      perturb_ingest_hashed
probe check-sandbox-trusted-base.sh "" sandbox-trusted-base.txt \
      "a pinned_by naming a nonexistent test" perturb_trusted_base
probe check-test-helpers-not-in-production.sh "" crates/nucleus-tool-proxy/Cargo.toml \
      "test-helpers enabled on a non-dev edge"  perturb_test_helpers_in_prod
probe check-lean-libs-built.sh "" crates/portcullis-core/lean/lakefile.lean \
      "a lean_lib nothing builds"               perturb_lean_lib_unbuilt
probe check-declassify-sink-scope-enforced.sh "" crates/portcullis/src/flow_graph.rs \
      "the applied sink mask widened to admit every sink" \
      perturb_declassify_unscope
probe check-declassify-governor-keys-sealed.sh "" crates/nucleus-tool-proxy/src/declassify.rs \
      "a set_trusted_keys caller outside kernel construction" \
      perturb_governor_keys_unsealed
probe check-north-star-ledger.sh "" docs/north-star.md \
      "the original overclaiming declassification status row restored" \
      perturb_ledger_restore_false_row
probe check-c1-inbound-fences.sh "" crates/nucleus-tool-proxy/src/workload.rs \
      "the reserved-namespace fence D neutered" \
      perturb_c1_inbound_fence
probe check-declassify-value-bound.sh "" crates/portcullis/src/flow_graph.rs \
      "value_binding_ok neutered to accept a substituted value" \
      perturb_declassify_value_unbind

probe check-extracted-callsites.sh "" crates/nucleus-tool-proxy/src/workload.rs \
      "the live ident_may_deliver call site removed" \
      perturb_extracted_callsite

# ── Uncovered, listed rather than omitted ─────────────────────────────────
#
# A perturbation for these needs a duplicate crate version or a non-wasm
# dependency — a real lockfile change, which this script will not make.
UNCOVERED=(
    "check-dep-ceiling.sh          needs a real duplicate crate version"
    "check-wasm-closure.sh         needs a non-wasm dependency added"
)
# Was 5. Three were paid down once their detection was read rather than guessed
# at. The remaining two need a Cargo.lock change, which this script will not make.
UNCOVERED_CEILING=2

# ── Self-falsified elsewhere, not here ────────────────────────────────────
#
# These gates PROVE they can fail — but on a toolchain this job does not have, so
# their reds-on-revert runs in their OWN workflow job rather than through probe()
# above. They are NOT "uncovered": each has a live falsifier that fails CI if the
# gate stops detecting its subject. They are listed here so the accounting stays
# honest (a gate that is neither probed, nor uncovered, nor here would still be
# flagged UNACCOUNTED) and so the location of each falsifier is on the record.
#
#   check-mediation-dylint.sh — needs the pinned dylint nightly + cargo-dylint
#     (this job runs only stable Rust). Its `--self-test` appends an unmediated
#     raw-I/O sink to the sealed effect home and asserts the finding count goes
#     non-zero; it runs in the `mediated` job of dylint-separation.yml, BEFORE the
#     enforcing run, every CI invocation.
#   check-egress-probe.sh — is itself a falsifier, not a watcher of an external
#     subject: it reconstructs the net::apply_default_deny fence in a netns and
#     asserts the probe PASSes with it present, FAILs when OUTPUT is opened
#     (State 2 — the reds-on-regression), and FAILs on an empty target list
#     (State 3 — the anti-vacuity guard). Those two perturbations run every CI
#     invocation in the `egress-probe-falsifier` job of quickstart-boot.yml. It is
#     not probed here because it needs netns + iptables + sudo, and because its
#     perturbation is internal — there is no external subject for this script to
#     break.
#   check-adversary-probe.sh — likewise a self-falsifier for the in-pod adversary:
#     it reconstructs each attack surface and asserts the probe reports CONTAINED
#     when confined, BREACH:<stage> when a surface is opened (reds-on-regression),
#     and INCONCLUSIVE when the positive control is dead (anti-vacuity), plus a
#     meta-anti-leak check. Those perturbations run every CI invocation in the
#     'adversary-probe-falsifier' job of adversary-probe.yml; the perturbation is
#     internal, so there is no external subject for this script to break.
SELF_FALSIFIED=(
    "check-mediation-dylint.sh    --self-test in the 'mediated' job (dylint-separation.yml)"
    "check-egress-probe.sh        States 2+3 in the 'egress-probe-falsifier' job (quickstart-boot.yml)"
    "check-adversary-probe.sh     BREACH+INCONCLUSIVE states in the 'adversary-probe-falsifier' job (adversary-probe.yml)"
)

echo
echo "Covered: $covered gate(s) probed."
echo "Uncovered: ${#UNCOVERED[@]} (ceiling $UNCOVERED_CEILING) — these have no perturbation yet:"
for u in "${UNCOVERED[@]}"; do echo "    $u"; done
echo "Self-falsified in-workflow: ${#SELF_FALSIFIED[@]} — reds-on-revert runs on a toolchain this job lacks:"
for s in "${SELF_FALSIFIED[@]}"; do echo "    $s"; done

if [[ "${#UNCOVERED[@]}" -gt "$UNCOVERED_CEILING" ]]; then
    echo
    echo "VIOLATION: uncovered gate count rose above $UNCOVERED_CEILING."
    echo "A new gate was added without a perturbation proving it can fail."
    failures=$((failures + 1))
fi

# ── The ratchet's own completeness ────────────────────────────────────────
#
# The ceiling above compares UNCOVERED against itself, which is not a check of
# anything: UNCOVERED is a hand-maintained list, so a gate that is NEITHER
# probed NOR listed is invisible to it and the count does not move. That is not
# hypothetical — `check-test-helpers-not-in-production.sh` arrived in the broker
# arc and this script did not notice, because nothing here ever asked what gates
# exist.
#
# "Nothing references X" is also true when X is not in the domain being searched.
# So derive the domain instead of declaring it: glob the gates, subtract the ones
# probed above and the ones listed as uncovered, and fail on the remainder. Now
# adding a gate forces a decision — write a perturbation, or say why you cannot.
declare -a UNACCOUNTED=()
declare -a UNWIRED=()
for path in scripts/check-*.sh; do
    gate="$(basename "$path")"
    # This script is the prober, not a subject; it has no perturbation of itself.
    [[ "$gate" == "check-gates-can-fail.sh" ]] && continue

    # Wiring is checked for EVERY gate, not just the probed ones. probe() also
    # checks this, but it only sees gates that have a perturbation — an
    # UNCOVERED gate could be unwired and nothing would say so.
    if [[ "$(grep -rl "scripts/$gate" .github/workflows/ 2>/dev/null | wc -l | tr -d ' ')" -eq 0 ]]; then
        UNWIRED+=("$gate")
    fi

    grep -qE "^probe[[:space:]]+$gate([[:space:]]|$)" "$0" && continue
    printf '%s\n' "${UNCOVERED[@]}" | grep -q "^$gate[[:space:]]" && continue
    printf '%s\n' "${SELF_FALSIFIED[@]}" | grep -q "^$gate[[:space:]]" && continue
    UNACCOUNTED+=("$gate")
done

if [[ "${#UNWIRED[@]}" -gt 0 ]]; then
    echo
    echo "VIOLATION: ${#UNWIRED[@]} gate(s) are not invoked by any workflow:"
    for g in "${UNWIRED[@]}"; do echo "    $g"; done
    echo "A gate that CI never calls enforces nothing. Add it to a workflow, or"
    echo "delete it — an uncalled script in scripts/ reads as protection that"
    echo "is not there."
    failures=$((failures + 1))
fi

if [[ "${#UNACCOUNTED[@]}" -gt 0 ]]; then
    echo
    echo "VIOLATION: ${#UNACCOUNTED[@]} gate(s) are neither probed nor listed as uncovered:"
    for g in "${UNACCOUNTED[@]}"; do echo "    $g"; done
    echo "Add a probe() for it, or add it to UNCOVERED with the reason a"
    echo "perturbation is not available. An unaccounted gate is one this script"
    echo "silently exempted, which is the exact failure it exists to catch."
    failures=$((failures + 1))
fi

# NON-VACUITY of the accounting itself: if the glob matched nothing, or the
# `probe` grep matched everything, the loop above would report a clean sheet
# without having examined anything.
gate_count=$(ls scripts/check-*.sh 2>/dev/null | wc -l | tr -d ' ')
if [[ "$gate_count" -lt 2 ]]; then
    echo
    echo "ERROR: found $gate_count gate script(s) under scripts/. The glob is wrong,"
    echo "so the accounting above examined nothing and proved nothing."
    failures=$((failures + 1))
else
    echo "accounting: $gate_count gate script(s) found, $covered probed, ${#UNCOVERED[@]} listed uncovered, ${#UNACCOUNTED[@]} unaccounted"
fi

echo
if [[ "$failures" -gt 0 ]]; then
    echo "FAILED: $failures problem(s). A gate that cannot fail is not a gate."
    exit 1
fi
echo "OK: every probed gate REDs on its own subject and GREENs when restored."
