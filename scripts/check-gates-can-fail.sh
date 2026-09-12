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

    # Every non-comment invocation in the workflows, flags only. A comment that
    # merely mentions the script is not an invocation (the proof-count note in
    # kani-nightly.yml was read as flags "(#2561): the"), and a gate CI calls
    # two ways — `--count` inside a $(...) and `--strict` as the gate — is
    # probed as the gate, so ANY invocation may match the probe's flags.
    local invocations in_ci
    invocations="$(grep -rhE "scripts/$gate" .github/workflows/ 2>/dev/null | grep -vE '^[[:space:]]*#' | grep -oE "scripts/${gate}[^\"'\`)]*" | sed "s|scripts/$gate||" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' || true)"
    if ! printf '%s\n' "$invocations" | grep -qxF -- "$ci_flags"; then
        in_ci="$(printf '%s\n' "$invocations" | head -1)"
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

    # Did the perturbation DO anything? A perturbation whose pattern no longer
    # matches the file is a no-op, the gate then passes on an unchanged tree,
    # and the probe reports "the gate cannot detect the thing it is named for" —
    # which sends whoever reads it to debug a gate that is working correctly.
    # #2582 moved the Lean builds from a bare `lake build` step to a pinned
    # action, and `perturb_default_target_unbuilt` went on deleting a line that
    # no longer existed. A probe whose perturbation changes nothing is not a
    # probe, exactly as a gate that cannot fail is not a gate.
    if cmp -s "$target" "$RESTORE_FROM"; then
        echo "  FAIL  $gate — the perturbation for '$desc' changed $target not at all"
        echo "        It is a no-op, so this probe tests nothing. The file moved"
        echo "        under it: update the perturbation to match what is there now."
        restore
        RESTORE_FROM=""
        failures=$((failures + 1))
        return
    fi

    local perturbed_rc=0
    # ci_flags is a deliberate word-split. The directive below carries no trailing
    # prose: shellcheck parses the rest of the line as more key=value pairs, so an
    # em-dash and a sentence made it emit SC1125 and IGNORE the disable entirely --
    # a suppression that suppressed nothing.
    # shellcheck disable=SC2086
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

# One probe for a gate that is a `cargo xtask` subcommand rather than a shell
# script. Same contract as probe(): perturb a REAL subject, the gate must go red,
# restore it, the gate must go green. The wiring check is the same question asked
# of the workflows, and comment lines are stripped for the reason the derivation
# above explains.
# A gate CI invokes BOTH bare and with a flag, probed on the flagged form too.
#
# `probe_xtask`'s CI-parity guard asks whether SOME invocation is bare, and passes when one is.
# That is right as far as it goes — probing bare then tests a command CI really runs — but it
# leaves a flagged sibling unprobed while the accounting counts the subcommand as covered. The
# harness derives its domain from `xtask -- <sub>`, so `allowlist-gates` and
# `allowlist-gates --parity` are one name to it and the second mode is invisible.
#
# That matters here specifically: `--parity` is the mode that checks the Rust harness implements
# every gate its shell scripts announce. A mode nothing probes is a gate that cannot fail.
probe_xtask_flagged() {
    local sub="$1" flags="$2" target="$3" desc="$4"
    shift 4

    local invocations
    invocations="$(grep -rhE "xtask -- ${sub}" .github/workflows/*.yml 2>/dev/null \
        | grep -vE '^[[:space:]]*#' \
        | grep -oE "xtask -- ${sub}[^\"'\`|]*" \
        | sed -E "s/xtask -- $sub//; s/^[[:space:]]+//; s/[[:space:]]+\$//")"
    if ! printf '%s\n' "$invocations" | grep -qxF -- "$flags"; then
        echo "  FAIL  xtask $sub $flags — no workflow invokes it with exactly those flags."
        echo "        CI runs: $(printf '%s' "$invocations" | tr '\n' '/')"
        echo "        Probing a form CI does not run tests something CI does not run."
        failures=$((failures + 1))
        return
    fi
    if [[ ! -f "$target" ]]; then
        echo "  ERROR: $target does not exist"
        failures=$((failures + 1))
        return
    fi

    RESTORE_TO="$target"
    RESTORE_FROM="$(mktemp)"
    cp "$target" "$RESTORE_FROM"

    "$@" "$target"

    if cmp -s "$target" "$RESTORE_FROM"; then
        echo "  FAIL  xtask $sub $flags — the perturbation for '$desc' changed $target not at all"
        restore
        RESTORE_FROM=""
        failures=$((failures + 1))
        return
    fi

    local perturbed_rc=0
    # shellcheck disable=SC2086
    cargo run -q -p xtask -- "$sub" $flags >/dev/null 2>&1 || perturbed_rc=$?
    restore
    RESTORE_FROM=""
    local restored_rc=0
    # shellcheck disable=SC2086
    cargo run -q -p xtask -- "$sub" $flags >/dev/null 2>&1 || restored_rc=$?

    covered=$((covered + 1))
    if [[ "$perturbed_rc" -eq 0 ]]; then
        echo "  FAIL  xtask $sub $flags — $desc did NOT fail the gate (exit 0)"
        failures=$((failures + 1))
    elif [[ "$restored_rc" -ne 0 ]]; then
        echo "  FAIL  xtask $sub $flags — still failing (exit $restored_rc) after restore"
        failures=$((failures + 1))
    else
        echo "  ok    xtask $sub $flags — RED on $desc, GREEN when restored"
    fi
}

probe_xtask() {
    local sub="$1" target="$2" desc="$3"
    shift 3

    local invocations
    invocations="$(grep -rhE "xtask -- $sub" .github/workflows/*.yml 2>/dev/null \
        | grep -vE '^[[:space:]]*#' \
        | grep -oE "xtask -- ${sub}[^\"'\`|]*" \
        | sed -E "s/xtask -- $sub//; s/^[[:space:]]+//; s/[[:space:]]+\$//")"
    if [[ -z "$(printf '%s' "$invocations")" ]] && ! grep -rhE "xtask -- $sub" .github/workflows/*.yml 2>/dev/null | grep -qvE '^[[:space:]]*#'; then
        echo "  FAIL  xtask $sub — no workflow invokes it"
        failures=$((failures + 1))
        return
    fi
    # CI-PARITY. probe() has carried this guard for shell gates since a probe ran a
    # gate with different flags than CI does; probe_xtask shipped WITHOUT it and
    # invokes flaglessly, so a gate CI calls with arguments would be probed as a
    # different command and nothing would say so. `scoreboard-ratchet` is exactly
    # that shape — CI passes `--current scoreboard.json --baseline ...`, and
    # `scoreboard.json` is generated in the job and is not in the tree.
    if ! printf '%s\n' "$invocations" | grep -qx ""; then
        echo "  FAIL  xtask $sub — CI invokes it with flags ($(printf '%s' "$invocations" | head -1))"
        echo "        but probe_xtask runs it bare. Probing a gate differently from CI"
        echo "        tests something CI does not run."
        failures=$((failures + 1))
        return
    fi
    if [[ ! -f "$target" ]]; then
        echo "  ERROR: $target does not exist"
        failures=$((failures + 1))
        return
    fi

    RESTORE_TO="$target"
    RESTORE_FROM="$(mktemp)"
    cp "$target" "$RESTORE_FROM"

    "$@" "$target"

    # A perturbation that changed nothing is not a probe — same argument, and the
    # same failure mode, as the shell half records.
    if cmp -s "$target" "$RESTORE_FROM"; then
        echo "  FAIL  xtask $sub — the perturbation for '$desc' changed $target not at all"
        restore
        RESTORE_FROM=""
        failures=$((failures + 1))
        return
    fi

    local perturbed_rc=0
    cargo run -q -p xtask -- "$sub" >/dev/null 2>&1 || perturbed_rc=$?
    restore
    RESTORE_FROM=""
    local restored_rc=0
    cargo run -q -p xtask -- "$sub" >/dev/null 2>&1 || restored_rc=$?

    covered=$((covered + 1))
    if [[ "$perturbed_rc" -eq 0 ]]; then
        echo "  FAIL  xtask $sub — $desc did NOT fail the gate (exit 0)"
        failures=$((failures + 1))
    elif [[ "$restored_rc" -ne 0 ]]; then
        echo "  FAIL  xtask $sub — still failing (exit $restored_rc) after restore"
        failures=$((failures + 1))
    else
        echo "  ok    xtask $sub — RED on $desc, GREEN when restored"
    fi
}

# probe_xtask for a subcommand CI invokes WITH FLAGS, where one of those flags
# names a file the job generates and the tree does not carry.
#
# `probe_xtask` refuses this shape on purpose: probing bare what CI runs with
# arguments tests a command CI never runs. The answer is not to relax that, it is
# to state both invocations and check they correspond. So this takes the flags CI
# is asserted to pass and the flags the probe will pass, requires the first to be
# exactly what the workflow declares, and requires the two to differ ONLY in the
# generated path -- which is named, not inferred. A drift in CI's flags fails here
# rather than being silently probed around.
#
# probe_xtask_generated <sub> <target> <desc> <ci_flags> <generated> <local_path> <gen_fn> <perturb_fn>
probe_xtask_generated() {
    local sub="$1" target="$2" desc="$3" ci_flags="$4" generated="$5" local_path="$6" gen_fn="$7" perturb_fn="$8"

    local invocations
    invocations="$(grep -rhE "xtask -- $sub" .github/workflows/*.yml 2>/dev/null \
        | grep -vE '^[[:space:]]*#' \
        | grep -oE "xtask -- ${sub}[^\"'\`|]*" \
        | sed -E "s/xtask -- $sub//; s/^[[:space:]]+//; s/[[:space:]]+\$//")"
    if [[ -z "$(printf '%s' "$invocations")" ]]; then
        echo "  FAIL  xtask $sub — no workflow invokes it"
        failures=$((failures + 1))
        return
    fi
    # CI-PARITY, kept rather than waived: the declared flags must be what CI runs.
    # `--` ends option parsing: $ci_flags begins with `--`, and without it grep reads
    # the pattern as its own flags and dies with "invalid option".
    if ! printf '%s\n' "$invocations" | grep -qxF -- "$ci_flags"; then
        echo "  FAIL  xtask $sub — CI invokes it as: $(printf '%s' "$invocations" | head -1)"
        echo "        but this probe claims parity with: $ci_flags"
        echo "        Update the probe to match CI, or CI to match the probe."
        failures=$((failures + 1))
        return
    fi
    # ...and the probe's own flags may differ ONLY by the generated file's path.
    local expected_local="${ci_flags/$generated/$local_path}"
    if [[ "$expected_local" == "$ci_flags" ]]; then
        echo "  FAIL  xtask $sub — '$generated' does not appear in CI's flags, so there is"
        echo "        nothing for the probe to substitute; use probe_xtask instead."
        failures=$((failures + 1))
        return
    fi

    if ! "$gen_fn" "$local_path"; then
        echo "  FAIL  xtask $sub — could not generate $local_path for the probe"
        failures=$((failures + 1))
        return
    fi
    if [[ ! -s "$local_path" ]]; then
        echo "  FAIL  xtask $sub — $gen_fn produced nothing; an empty input is not a probe"
        failures=$((failures + 1))
        return
    fi
    if [[ ! -f "$target" ]]; then
        echo "  ERROR: $target does not exist"
        failures=$((failures + 1))
        return
    fi

    RESTORE_TO="$target"
    RESTORE_FROM="$(mktemp)"
    cp "$target" "$RESTORE_FROM"

    "$perturb_fn" "$target"

    if cmp -s "$target" "$RESTORE_FROM"; then
        echo "  FAIL  xtask $sub — the perturbation for '$desc' changed $target not at all"
        restore
        RESTORE_FROM=""
        failures=$((failures + 1))
        return
    fi

    local perturbed_rc=0
    # shellcheck disable=SC2086
    cargo run -q -p xtask -- "$sub" $expected_local >/dev/null 2>&1 || perturbed_rc=$?
    restore
    RESTORE_FROM=""
    local restored_rc=0
    # shellcheck disable=SC2086
    cargo run -q -p xtask -- "$sub" $expected_local >/dev/null 2>&1 || restored_rc=$?

    covered=$((covered + 1))
    if [[ "$perturbed_rc" -eq 0 ]]; then
        echo "  FAIL  xtask $sub — $desc did NOT fail the gate (exit 0)"
        failures=$((failures + 1))
    elif [[ "$restored_rc" -ne 0 ]]; then
        echo "  FAIL  xtask $sub — still failing (exit $restored_rc) after restore"
        failures=$((failures + 1))
    else
        echo "  ok    xtask $sub — RED on $desc, GREEN when restored"
    fi
}

# ── Perturbations ─────────────────────────────────────────────────────────
# Each introduces a real violation of the gate's OWN stated property, not a
# syntax error that would fail any check.

append_line() { printf '%s\n' "$2" >> "$1"; }

perturb_law_mechanism_wired() {
    # A mechanism the manifest declares dead gains a production call site.
    # `ProvenanceDAG` is a complete content-addressed Merkle DAG that nothing
    # constructs; one production mention is the whole failure.
    #
    # Appending to a .rs file does not trigger a crate build here: the gate is
    # `cargo run -p xtask`, which compiles xtask and then greps the tree.
    append_line "$1" 'fn _gate_of_gates() { let _: Option<ProvenanceDAG> = None; }'
}

perturb_inert_authority_added() {
    # A new witness is accepted and dropped. `Authority` is in the manifest's
    # WITNESS vocabulary and this file has no row, so the site is undeclared --
    # which is the growth the gate exists to refuse.
    #
    # Appending to a .rs file does not trigger a crate build here: the gate is
    # `cargo run -p xtask`, which compiles xtask and then greps the tree.
    append_line "$1" 'fn _gate_of_gates_inert(_authority: Authority) {}'
}

perturb_inert_authority_paid() {
    # The OTHER direction, and it needs its own probe: a declared site is fixed
    # (the binding is named, so the body may read it) and the row is left
    # behind. The pin is exact in both directions, so a stale row is a finding
    # too -- without this probe, only growth would be proven detectable.
    # `-i.gate-bak`, like every other perturbation in this file. Bare `sed -i`
    # is GNU-only: BSD sed reads the next argument as the backup SUFFIX and then
    # the filename as the script, which dies with "command c expects \ followed
    # by text". So on macOS this probe changed nothing and reported itself as a
    # no-op — the harness caught that correctly, and said so, for anyone who ran
    # it locally. Line 268 was the only `sed -i` here missing the suffix.
    sed -i.gate-bak 's/_verified: &VerifiedGrant/verified: \&VerifiedGrant/' "$1"
    rm -f "$1.gate-bak"
}

perturb_dead_code_ratchet() {
    # One more tolerated allowance than the crate's ceiling permits. The gate
    # covers two properties, so it needs a perturbation for each — a probe on
    # only the manifest half would leave the ratchet half unproven.
    append_line "$1" '#[allow(dead_code)]'
    append_line "$1" 'fn _gate_of_gates_unused() {}'
}

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

perturb_ring_ed25519() {
    # SECURITY_TODO #16 sibling scan: a cofactored `ring::signature::ED25519`
    # verify on a production path. The gate matches the algorithm constant
    # itself, so the probe names it in a plain (non-test) function.
    append_line "$1" 'fn _gate_of_gates_ring(k: &[u8], m: &[u8], s: &[u8]) -> bool { ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, k).verify(m, s).is_ok() }'
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

perturb_default_target_unbuilt() {
    # A package whose libs are `@[default_target]` but which NO workflow builds.
    # The one workflow that builds nucleus-ifc-kernel/lean now does it through
    # leanprover/lean-action with `build: "true"`; before #2582 it was a bare
    # `lake build` step. Both forms are turned off here, so the probe keeps
    # working whichever the workflow uses. Before #2564 the coverage gate
    # counted `@[default_target]` alone as "built" and this package read as
    # covered while its 19 theorems were never elaborated in CI.
    local tmp; tmp="$(mktemp)"
    sed -e '/run: LEAN_NUM_THREADS=4 lake build$/d' \
        -e 's/^\([[:space:]]*\)build: "true"$/\1build: "false"/' "$1" > "$tmp"
    cat "$tmp" > "$1"; rm -f "$tmp"
}

perturb_kani_harness_deleted() {
    # One `#[kani::proof]` attribute removed: the harness becomes an ordinary
    # function and the census drops by one. The ratchet is exact (#2561), so
    # this must be red; a floor below the true count would let it pass.
    local tmp; tmp="$(mktemp)"
    awk 'BEGIN{done=0} /#\[kani::proof\]/ && !done {done=1; next} {print}' "$1" > "$tmp"; cat "$tmp" > "$1"; rm -f "$tmp"
}

perturb_compiler_online() {
    # A network crate appended to the task compiler's manifest. It lands in
    # whichever dependency table is last, which is why the gate reads every
    # table and not only [dependencies].
    printf '\nreqwest = "0.12"\n' >> "$1"
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

perturb_twin_paths_ignore() {
    # Drop one entry from the noop twin's paths-ignore. The lists must be
    # set-equal to the real twin's paths (ci-spec I1); a PR touching the
    # dropped path now fires BOTH twins under one context name.
    sed -i.gate-bak '/^      - "\.kani-minimum-proofs"$/d' "$1"
    rm -f "$1.gate-bak"
    if grep -q '"\.kani-minimum-proofs"' "$1"; then
        echo "  ERROR: the kani-nightly-noop paths-ignore entry changed shape;"
        echo "         this perturbation no longer applies and must be updated."
        return 1
    fi
}

perturb_ci_assurance_overclaim() {
    # Flip CI-10 (the strict-rebase livelock, NOT-YET) to PROVED, citing a
    # theorem that does not exist. Two independent reds: the pinned NOT-YET
    # count no longer matches, and the evidence handle does not dereference.
    sed -i.gate-bak 's/^| CI-10 | \(.*\) | NOT-YET | `ci\/merge-queue.toml#strict` | — |$/| CI-10 | \1 | PROVED | `ci\/lean\/CiSpec\/Queue.lean#T8_strict_livelock` | `scripts\/check-ci-spec.sh` |/' "$1"
    rm -f "$1.gate-bak"
    if ! grep -q '^| CI-10 | .* | PROVED | `ci/lean/CiSpec/Queue.lean#T8_strict_livelock`' "$1"; then
        echo "  ERROR: the CI-10 row changed shape; this perturbation must be updated."
        return 1
    fi
}

perturb_golden_lean() {
    # One extra line in the generated file: the regeneration no longer
    # matches, which is the seal's whole subject.
    append_line "$1" '-- gate-of-gates: a hand edit the generator would not produce'
}

perturb_bite_semantics() {
    # A new type in the bite: the differential is no longer about CiSpec's
    # model. Appended after the namespace closes, so the file stays valid
    # Lean and only the no-new-semantics rule is violated.
    append_line "$1" 'structure GateOfGatesProbe where'
    append_line "$1" '  x : Nat'
}

perturb_cancel_in_progress() {
    # A merge_group-triggered workflow that cancels in-flight runs
    # unconditionally (ci-spec I4): a newer run aborts a queue entry.
    sed -i.gate-bak 's/^  cancel-in-progress: .*$/  cancel-in-progress: true/' "$1"
    rm -f "$1.gate-bak"
    if ! grep -q '^  cancel-in-progress: true$' "$1"; then
        echo "  ERROR: the zizmor.yml concurrency block changed shape;"
        echo "         this perturbation no longer applies and must be updated."
        return 1
    fi
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

perturb_no_hmac_auth() {
    # Reintroduce a retired symbol — the exact regression this gate exists to
    # catch (a deleted HMAC auth tier silently coming back).
    echo 'const _GATE_PROBE: &str = "NUCLEUS_NODE_AUTH_SECRET";' >> "$1"
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

perturb_kani_divergence_unlisted() {
    # A brand-new production fork the inventory does not know about: a
    # `#[cfg(not(kani))]` guarding a real function. Exactly the gate's subject —
    # an unlisted divergence (and one more than the base, so the shrink ratchet
    # would also bite in CI).
    cat >> "$1" <<'RUST'

#[cfg(not(kani))]
pub fn gate_of_gates_unlisted_divergence_probe() -> bool {
    true
}
RUST
}

perturb_assurance_required_pin() {
    # The count of claims whose falsifier produces no required context, moved past any honest
    # value. 255 by KEY, never by editing the number in place: only eight non-NOT-YET claims
    # exist, so no real pin can reach it and it can never equal what it replaces.
    awk '{ if ($0 ~ /^UNREQUIRED_FALSIFIERS=/) print "UNREQUIRED_FALSIFIERS=255"; else print }' "$1" > "$1.tmp" && mv "$1.tmp" "$1"
}

perturb_lean_toolchain_split() {
    # Two first-party Lean versions. The gate's own stake line says why it matters: "two Lean
    # versions cannot share a .lake cache, and the second one rebuilds everything."
    sed -i.bak 's|leanprover/lean4:v4\.30\.0-rc2|leanprover/lean4:v4.29.0|' "$1" && rm -f "$1.bak"
}

perturb_self_pin_sha() {
    # The repo pins a SHA of itself in a workflow `uses:`. Point it at a commit that does not
    # exist: the gate must refuse rather than call a missing commit agreement. It exits 2 ("could
    # not look"), which is red and is the right red — a pin nobody can resolve is not a pin.
    sed -i.bak 's|\(uses: coproduct-opensource/nucleus/[^@]*@\)[0-9a-f]\{40\}|\10000000000000000000000000000000000000000|' "$1" && rm -f "$1.bak"
}

perturb_allowlist_pin() {
    # An allowlist grows past its pinned size. 255 rather than a literal edit of
    # the current value: there are only a handful of entries, so no honest pin can
    # reach it, and it can never accidentally equal the value it replaces — which
    # is how a value-matched perturbation goes vacuous.
    awk '{ if ($0 ~ /^mediation\/net=/) print "mediation/net=255"; else print }' "$1" > "$1.tmp" && mv "$1.tmp" "$1"
}

perturb_push_auth_strip() {
    # Take the push's own credential away, leaving it to rely on whatever actions/checkout
    # left behind -- the live 2026-09-11 state. Deletes by matching the COMMAND, never the
    # token expression: a probe keyed on a literal value stops perturbing silently when its
    # subject moves, which is the 2026-09-07 incident this file already records.
    sed -i.bak '/git remote set-url origin/d' "$1" && rm -f "$1.bak"
}

perturb_coverage_floor() {
    # Lower the floor rather than write the tests -- the live temptation: on 2026-09-11 a PR
    # missed this floor by 0.02 points and the one-character fix was right here. Matches the
    # FLAG and rewrites whatever value follows, never matching the value itself.
    sed -i.bak -E 's/(--fail-under-lines )[0-9.]+/\182.4/' "$1" && rm -f "$1.bak"
}

perturb_gate_budget_timeout() {
    # The live 2026-09-11 defect: the action's timeout as large as the job's own, so GitHub
    # kills the job before the runner can report and the overrun comes back `cancelled`.
    # Matches the KEY and rewrites the value, never matching the value -- the 2026-09-07
    # incident where a probe keyed on a literal silently stopped perturbing anything when
    # the subject moved. `timeout-minutes` is untouched: it has a hyphen, so `timeout: `
    # cannot match it.
    sed -i.bak -E 's/^( *)timeout: "[0-9]+"/\1timeout: "9999"/' "$1" && rm -f "$1.bak"
}
# pipefail: a new pipeline in a block that has no pipefail. This is the growth direction the
# ratchet exists to refuse -- a pipe added to an unguarded block, where every command but the
# last can fail unseen. `a2a-tck.yml`'s first `run:` block has no pipe and no guard today, so
# adding one there moves the population by exactly one.
perturb_pipefail_new_unguarded_pipe() {
    local f="$1"
    perl -0pi -e 's/(\n( +)run: \|\n)/$1$2  cat \/etc\/hostname | tr -d "\\n"\n/ if !$done++;' "$f"
}


perturb_wasm_closure_forbid_present() {
    # "needs a non-wasm dependency added" is true, and it is not the only thing this
    # gate decides. It also decides, for each crate in its committed FORBIDDEN list,
    # whether that crate is in the wasm32 closure -- and THAT detection is the fragile
    # half: a `grep -qE "(^|[│├└─ ])${c} v[0-9]"` over `cargo tree` output, keyed on box
    # drawing characters. If cargo ever changes that format the gate passes forever and
    # nothing says so. Declaring a crate that IS present exercises exactly that path.
    # `serde` is in the closure by inspection; matches the ARRAY, never a crate name.
    sed -i.bak -E 's/^FORBIDDEN=\((.*)\)$/FORBIDDEN=(\1 serde)/' "$1" && rm -f "$1.bak"
}

perturb_dep_ceiling_raise() {
    # The OTHER direction of this gate, and the one its uncovered entry did not see.
    # "needs a real duplicate crate version" is true for the drift half -- you cannot
    # conjure a second `sha2` line from a shell script. But the gate also fails when a
    # watched crate sits STRICTLY BELOW its ceiling, because an unclaimed win is debt
    # the next PR inherits. Raising a ceiling above the actual count exercises exactly
    # that half, and the declaration it perturbs is committed. Matches the KEY (the
    # crate name) and rewrites whatever count follows, never matching the count.
    sed -i.bak -E 's/^([[:space:]]*"[a-z0-9_-]+) [0-9]+"/\1 9"/' "$1" && rm -f "$1.bak"
}

gen_exemplar_scoreboard() {
    bash scripts/exemplar-scoreboard.sh "$1" >/dev/null 2>&1
}

perturb_exemplar_baseline() {
    # Claim a perfect score the tree does not have. `sorry_admit` is lower-is-better,
    # so a baseline of 0 makes the CURRENT count a regression against it -- which is
    # the gate's own rule, not a malformed file. Matches the KEY and rewrites whatever
    # number follows, never matching the value.
    sed -i.bak -E 's/("sorry_admit"[[:space:]]*:[[:space:]]*)[0-9]+/\10/' "$1" && rm -f "$1.bak"
}

perturb_fly_pool_volumes() {
    # The exact configuration the manager refuses, and the one that was committed:
    # requires_volume with no volumes for eight machines, so the machines past the
    # end of the list compile onto the root filesystem and run out of disk.
    sed -i.bak 's/"requires_volume":false/"requires_volume":true/' "$1" && rm -f "$1.bak"
}
# workspace-members: a crate dropped from the members list. This is the real mistake -- the
# list is explicit, not a glob, so forgetting one is the normal way a crate ends up outside
# the workspace, invisible to every `--workspace` command and failing nothing.
perturb_workspace_member_dropped() {
    local f="$1"
    perl -0pi -e 's/^\s*"crates\/nucleus-audit",[^\n]*\n//m' "$f"
}

# allowlist-gates --parity: a shell script gains a gate the Rust harness has not ported. This is
# the real shape -- `check-verify-strict.sh` carried two gates and the port took one -- reproduced
# on a different script so the probe does not depend on that one defect staying fixed.
perturb_unported_shell_gate() {
    local f="$1"
    printf '%s\n' 'echo "unported gate PASSED: a question the Rust harness does not ask."' >> "$f"
}


# One more by-reference site on an affine type: the calling convention defeating
# the affine intent the type declares, which is the whole of what `linearity`
# counts. ADR 0007 C-4, and `f7f9719b` is the defect it generalises.
perturb_convergence_linearity() {
    append_line "$1" 'fn _gate_of_gates_affine(_a: &portcullis_effects::Authority) {}'
}

probe_xtask convergence crates/nucleus-tool-proxy/src/run_gate.rs \
    "one more affine type taken by reference" perturb_convergence_linearity
probe_xtask assurance-required ci/assurance-required-ratchet.txt \
    "a claim whose falsifier the merge queue does not gate on, past the pin" perturb_assurance_required_pin
probe_xtask pin-parity ci/lean/lean-toolchain \
    "two first-party Lean versions in one tree" perturb_lean_toolchain_split
probe_xtask self-pin .github/workflows/scan.yml \
    "a self-pin naming a commit that does not exist" perturb_self_pin_sha
probe_xtask allowlist-gates ci/allowlist-gates.txt \
    "an allowlist grown past its pinned size" perturb_allowlist_pin

probe_xtask_flagged allowlist-gates --parity scripts/check-ingest-hashed.sh \
    "a shell gate the Rust harness never ported" perturb_unported_shell_gate
probe_xtask fly-pools ci/fly-runner/manager.toml \
    "the committed POOLS default the manager refuses" perturb_fly_pool_volumes

probe_xtask pipefail .github/workflows/a2a-tck.yml \
    "a pipeline added to a block with no pipefail" perturb_pipefail_new_unguarded_pipe
probe_xtask workspace-members Cargo.toml \
    "a crate dropped from the workspace members list" perturb_workspace_member_dropped
probe_xtask_generated scoreboard-ratchet scripts/exemplar-baseline.json \
    "a baseline claiming a score the tree does not have" \
    "--current scoreboard.json --baseline scripts/exemplar-baseline.json" \
    "scoreboard.json" "$(mktemp -t scoreboard).json" \
    gen_exemplar_scoreboard perturb_exemplar_baseline
probe_xtask push-auth .github/workflows/clippy-ratchet.yml \
    "a CI push relying on the checkout's ambient credential" perturb_push_auth_strip
probe_xtask coverage-floor .github/workflows/coverage-matrix.yml \
    "a coverage floor lowered without moving its pin" perturb_coverage_floor
probe_xtask gate-budget .github/workflows/gatehouse-shadow.yml \
    "a gate timeout its job kills before the runner can report" perturb_gate_budget_timeout

probe check-line-ratchet.sh   "--strict" crates/portcullis/src/kernel.rs \
      "400 lines past the ceiling"            perturb_line_ratchet
probe check-dep-ceiling.sh    "" scripts/check-dep-ceiling.sh \
      "a ceiling above the count it caps"     perturb_dep_ceiling_raise
probe check-wasm-closure.sh   "" scripts/check-wasm-closure.sh \
      "a crate forbidden that is in the closure" perturb_wasm_closure_forbid_present
probe check-law-mechanisms.sh "" crates/portcullis/src/lattice.rs \
      "a declared-dead mechanism gains a production call site" perturb_law_mechanism_wired
probe check-law-mechanisms.sh "" crates/portcullis/src/budget.rs \
      "one allowance past the crate's dead-code ceiling" perturb_dead_code_ratchet
probe check-inert-authority.sh "" crates/portcullis/src/lattice.rs \
      "a new witness accepted and dropped"    perturb_inert_authority_added
probe check-inert-authority.sh "" crates/nucleus-cli/src/grant.rs \
      "a declared site fixed, its row left behind" perturb_inert_authority_paid
probe check-mediation.sh      "" crates/nucleus-tool-proxy/src/egress.rs \
      "a raw Command::new on the agent path"  perturb_mediation
probe check-sealed-home.sh    "" crates/portcullis-effects/src/lib.rs \
      "an un-allowlisted spawn in the sealed home" perturb_sealed_home
probe check-verify-strict.sh  "" crates/nucleus-identity/src/lib.rs \
      "a non-strict dalek .verify()"          perturb_verify_strict
probe check-verify-strict.sh  "" crates/ck-types/src/witness.rs \
      "a cofactored ring ED25519 verify"      perturb_ring_ed25519
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
probe check-lean-libs-built.sh "" .github/workflows/ifc-lean.yml \
      "a default_target package no workflow bare-builds" perturb_default_target_unbuilt
probe check-kani-proof-count.sh "--strict" crates/portcullis/src/kani.rs \
      "a deleted Kani harness"                  perturb_kani_harness_deleted
probe check-task-compiler-offline.sh "" crates/nucleus-task-compiler/Cargo.toml \
      "a network crate in the task compiler"    perturb_compiler_online
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

probe check-no-hmac-auth.sh "" crates/nucleus-node/src/auth.rs \
      "a retired NUCLEUS_NODE_AUTH_SECRET reference reintroduced" \
      perturb_no_hmac_auth

# CI-1 (crates/ci-spec): the CI configuration itself. Two probes, one per
# founding-defect class: a twin whose paths-ignore drifted from the real
# twin's paths (both twins fire, or neither), and a merge_group-triggered
# workflow that cancels its own in-flight runs (ejects a queue entry).
probe check-ci-spec.sh "" .github/workflows/kani-nightly-noop.yml \
      "a noop twin missing one of the real twin's paths" \
      perturb_twin_paths_ignore
probe check-ci-spec.sh "" .github/workflows/zizmor.yml \
      "cancel-in-progress true under merge_group" \
      perturb_cancel_in_progress

# The CI-model bite (ci/lean/CiSpecBite.lean) may only DROP hypotheses of
# CiSpec theorems; new semantics would make its counterexamples about a
# different model. The gate is textual, so its subject is a planted type.
probe check-ci-spec-bite.sh "" ci/lean/CiSpecBite.lean \
      "a structure declared in the bite" \
      perturb_bite_semantics

# The golden seal between the Rust queue mirror and the Lean model: a hand
# edit to the generated Golden.lean (or a JSON vector changed without
# regenerating) must diff red.
probe check-ci-spec-golden.sh "" ci/lean/CiSpec/Golden.lean \
      "a hand-edited golden vector" \
      perturb_golden_lean

# The CI assurance ledger: promoting a NOT-YET row to PROVED without lowering
# the pin (and without a theorem behind it) is the exact overclaim it exists
# to catch — the same founding defect as the North Star ledger's C4.
probe check-ci-assurance-ledger.sh "" docs/assurance/ci-assurance.md \
      "a NOT-YET row promoted to PROVED with no evidence or pin change" \
      perturb_ci_assurance_overclaim

probe check-kani-divergence.sh "" crates/portcullis/src/capability.rs \
      "an unlisted cfg(not(kani)) fork" \
      perturb_kani_divergence_unlisted

# ── Uncovered, listed rather than omitted ─────────────────────────────────
#
# A perturbation for these needs a duplicate crate version or a non-wasm
# dependency — a real lockfile change, which this script will not make.
UNCOVERED=(
    # 2026-09-11: the xtask half of the domain became VISIBLE today. These eight
    # were never exempted by decision — they were outside the glob, so nothing
    # asked. Listing them is the point: each now owes a perturbation or a reason,
    # and the ceiling below only shrinks. Two of the ten are probed already.
    "xtask ci-spec                 reads live branch protection; a perturbation needs the GitHub API, not a file"
    "xtask gatehouse-pin           takes --gatehouse <path>; the probe needs a gatehouse checkout this script does not have"
    "xtask lean-action-builds      needs a Lean toolchain to reach its verdict"
    "xtask line-ratchet            probed through scripts/check-line-ratchet.sh, which is the same decision procedure"
    "xtask policy-gate             runs ck-kernel admission on a manifest amendment; needs a real amendment"
)
# Was 5. Three were paid down once their detection was read rather than guessed
# at. The remaining two need a Cargo.lock change, which this script will not make.
# 2 -> 10 on 2026-09-11, and the direction is the honest part: this is not a
# relaxation, it is ten gates entering the domain at once. Eight of them were
# listed above and owed a perturbation; it may only shrink from here.
#
# 10 -> 8 the same day: pin-parity and self-pin now have one. Both were listed
# "perturbation not yet written" and "needs care" after my first two attempts at
# them were NO-OPS — guesses at what the gates read, which left the gate passing
# on an unchanged tree. The working pair came from reading the code instead:
# pin-parity compares first-party lean-toolchain files for one value, so two
# versions reds it; self-pin resolves a `uses: .../nucleus/<dir>@<sha>` against
# the clone, so a SHA that does not exist reds it (exit 2, "could not look",
# which is the right red -- a pin nobody can resolve is not a pin).
#
# 2026-09-11, 8 -> 7: `scoreboard-ratchet` gets a probe. It was the only entry whose
# stated reason was "perturbation not yet written" rather than a named obstacle, and
# the obstacle turned out to be real but surmountable: CI passes `--current
# scoreboard.json`, a file the job generates, so `probe_xtask`'s CI-parity guard
# refused it. `probe_xtask_generated` keeps that guard -- it asserts CI's flags are
# exactly what the probe claims -- and allows the probe's flags to differ only in the
# generated path, which is named rather than inferred. The generator costs 4s.
#
# 2026-09-11, 7 -> 6: `check-dep-ceiling.sh` gets a probe. Its stated obstacle --
# "needs a real duplicate crate version" -- was true for only ONE of the two things
# it checks. The gate also fails when a watched crate sits strictly BELOW its
# ceiling, and raising a ceiling above the actual count exercises that half from a
# committed declaration. The same shape as scoreboard-ratchet above: the exemption
# named a real obstacle and stopped there.
#
# 2026-09-12, 6 -> 5: `check-wasm-closure.sh` gets a probe, by the same reading that
# freed the previous two. "Needs a non-wasm dependency added" is true of the CLOSURE
# half and silent about the DETECTION half -- a grep over `cargo tree` keyed on box
# drawing characters, which would pass forever if cargo changed its output. Declaring
# a present crate forbidden exercises that path from a committed list.
UNCOVERED_CEILING=5

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
#     non-zero; it runs in the `dylint` job of dylint-separation.yml, BEFORE the
#     enforcing run, every CI invocation.
#   check-observed-dylint.sh — same toolchain reason as its sibling above. Its
#     `--self-test` DELETES `run_command`'s observation of its own subprocess
#     output — the defect the pass was written after — and asserts the count
#     rises ABOVE the ceiling. Asserting "non-zero" would prove nothing there:
#     the clean tree is 28, because the agent-facing crate also does
#     infrastructure I/O (see .observed-ratchet.toml). It runs in the `dylint`
#     job of dylint-separation.yml, BEFORE the enforcing run, every invocation.
#   check-rest-pattern-dylint.sh — same toolchain reason as its siblings. Its
#     `--self-test` collapses `create_sub_pod`'s `PodSpecInner` destructure back
#     to `..` — the shape ADR 0006 C4.2 removed — and asserts the count goes
#     non-zero. It perturbs the REAL subject rather than a fixture, which is
#     what makes a green run evidence about the delegation path. Gates at ZERO,
#     unlike its `observed` sibling, because the pass is scoped by record TYPE
#     and those types have no rest-patterns workspace-wide. Runs in the `dylint`
#     job of dylint-separation.yml, BEFORE the enforcing run, every invocation.
#   check-egress-probe.sh — is itself a falsifier, not a watcher of an external
#     subject: it reconstructs the net::apply_default_deny fence in a netns and
#     asserts the probe PASSes with it present, FAILs when OUTPUT is opened
#     (State 2 — the reds-on-regression), and FAILs on an empty target list
#     (State 3 — the anti-vacuity guard). Those two perturbations run every CI
#     invocation in the `egress-probe-falsifier` job of quickstart-boot.yml. It is
#     not probed here because it needs netns + iptables + sudo, and because its
#     perturbation is internal — there is no external subject for this script to
#     break.
#   check-clippy-ratchet.sh — its perturbation needs a full workspace clippy run
#     (minutes, and `--keep-going` over every crate); this job runs fast greps on
#     stable Rust and would be the wrong place to spend that. The
#     `ratchet-falsifier` job in clippy-ratchet.yml lowers the ceiling below the
#     measured count and asserts `--strict` exits non-zero, then restores it and
#     asserts zero — the same two-sided perturbation probe() would make, run
#     every CI invocation beside the gate it falsifies.
#   check-adversary-probe.sh — likewise a self-falsifier for the in-pod adversary:
#     it reconstructs each attack surface and asserts the probe reports CONTAINED
#     when confined, BREACH:<stage> when a surface is opened (reds-on-regression),
#     and INCONCLUSIVE when the positive control is dead (anti-vacuity), plus a
#     meta-anti-leak check. Those perturbations run every CI invocation in the
#     'adversary-probe-falsifier' job of adversary-probe.yml; the perturbation is
#     internal, so there is no external subject for this script to break.
#   check-mutants-report.sh — its subject is a cargo-mutants outcomes.json that
#     exists only after a mutants run, so there is no tree file to perturb here.
#     Its `--self-test` builds four synthetic reports (unmutated-tree failure,
#     a missed mutant, a partial run, excess timeouts) and asserts each is red
#     and a clean one green; it runs in the `mutants` job of
#     coverage-matrix.yml before the enforcing step, every CI invocation.
SELF_FALSIFIED=(
    "check-mediation-dylint.sh    --self-test in the 'Dylint passes (one pod)' job (dylint-separation.yml)"
    "check-observed-dylint.sh    --self-test in the 'Dylint passes (one pod)' job (dylint-separation.yml)"
    "check-rest-pattern-dylint.sh    --self-test in the 'Dylint passes (one pod)' job (dylint-separation.yml)"
    "check-preimage-dylint.sh    --self-test in the 'Dylint passes (one pod)' job (dylint-separation.yml)"
    "check-egress-probe.sh        States 2+3 in the 'egress-probe-falsifier' job (quickstart-boot.yml)"
    "check-adversary-probe.sh     BREACH+INCONCLUSIVE states in the 'adversary-probe-falsifier' job (adversary-probe.yml)"
    "check-clippy-ratchet.sh     ceiling-below-actual in the 'ratchet-falsifier' job (clippy-ratchet.yml)"
    "check-mutants-report.sh     --self-test in the 'mutants' job (coverage-matrix.yml)"
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
    printf '%s\n' "${UNCOVERED[@]}" | grep -q "^${gate}[[:space:]]" && continue
    printf '%s\n' "${SELF_FALSIFIED[@]}" | grep -q "^${gate}[[:space:]]" && continue
    UNACCOUNTED+=("$gate")
done

# The SECOND half of the domain, and it was missing entirely until 2026-09-11.
#
# The loop above globs `scripts/check-*.sh`, so a gate that is not a shell script
# is not in the domain being searched -- which is the very sentence this section
# opens with, applied to itself. nucleus now runs TEN gates as `cargo xtask`
# subcommands, and not one of them had a perturbation: allowlist-gates, ci-spec,
# fly-pools, gatehouse-pin, lean-action-builds, line-ratchet, pin-parity,
# policy-gate, scoreboard-ratchet, self-pin. They were not exempted by decision;
# they were invisible. gatehouse's port of this script already derives its domain
# from the subcommand list for exactly this reason.
#
# Derived from the WORKFLOWS rather than from a list here, on the same argument
# the shell half uses: a hand-kept list is a membership test and cannot say that
# everything run is listed. Comment lines are stripped first, because
# coverage-matrix.yml contains the prose "added to xtask -- so including the lock
# left the 46 minutes", which a naive match reads as a gate named `so`. That is
# the identical trap probe() already records for shell gates ("a comment that
# merely mentions the script is not an invocation"), and it is live in this repo
# today rather than hypothetical.
declare -a XTASK_GATES=()
while IFS= read -r sub; do
    [[ -z "$sub" ]] && continue
    XTASK_GATES+=("$sub")
done < <(
    grep -rhoE '^[^#]*xtask -- [a-z][a-z-]*' .github/workflows/*.yml 2>/dev/null \
        | grep -oE 'xtask -- [a-z][a-z-]*' \
        | sed 's/xtask -- //' \
        | sort -u
)

for sub in "${XTASK_GATES[@]}"; do
    gate="xtask $sub"
    # Both probe forms count as coverage: probe_xtask for a bare invocation,
    # probe_xtask_generated for one CI runs with flags naming a generated file.
    grep -qE "^probe_xtask(_generated)?[[:space:]]+$sub([[:space:]]|$)" "$0" && continue
    printf '%s\n' "${UNCOVERED[@]}" | grep -q "^${gate}[[:space:]]" && continue
    UNACCOUNTED+=("$gate")
done

# NON-VACUITY of the half just added: if the derivation matched nothing, every
# xtask gate would be accounted for by having vanished from the domain.
if [[ "${#XTASK_GATES[@]}" -lt 5 ]]; then
    echo
    echo "ERROR: derived only ${#XTASK_GATES[@]} xtask gate(s) from the workflows."
    echo "The derivation is wrong, so the accounting below exempted every gate it"
    echo "failed to see -- which is the failure this script exists to catch."
    exit 2
fi

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
