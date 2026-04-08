#!/usr/bin/env bash
# Nucleus demo: taint -> block -> algebraic laws -> delegation
# Run: make demo (or ./scripts/demo.sh)
set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
RESET='\033[0m'

step() { echo -e "\n${BOLD}${CYAN}[$1/${TOTAL_STEPS}] $2${RESET}"; }
ok()   { echo -e "    ${GREEN}$1${RESET}"; }
deny() { echo -e "    ${RED}$1${RESET}"; }

# Run a single named test silently, return its exit code
run_test() {
    cargo test -p portcullis-core --lib "flow_algebra::tests::$1" -- --exact --quiet >/dev/null 2>&1
}

TOTAL_STEPS=4

echo -e "${BOLD}Nucleus Flow Algebra Demo${RESET}"
echo "Two primitives. Four laws. Everything derives."

# ── Step 1: Build ──────────────────────────────────────────────────────
step 1 "Building flow algebra tests..."
cargo test -p portcullis-core --lib flow_algebra --no-run --quiet 2>&1 | tail -1
ok "Built."

# ── Step 2: Clean session vs tainted session ───────────────────────────
step 2 "Policy enforcement: clean session allowed, tainted session blocked"
echo ""
echo "    state = FlowState::from_label(trusted())"
echo "    state.flows_to(WorkspaceWrite)?"
run_test clean_state_flows_to_workspace \
    && ok "ALLOWED -- trusted session can write to workspace" \
    || deny "UNEXPECTED FAILURE"

echo ""
echo "    state = FlowState::from_label(trusted())"
echo "    state.join(adversarial())           // tainted by web content!"
echo "    state.flows_to(GitPush)?"
run_test tainted_state_blocked_from_git_push \
    && ok "DENIED -- tainted session cannot push" \
    || deny "UNEXPECTED FAILURE"

# ── Step 3: Algebraic laws hold ────────────────────────────────────────
step 3 "Verifying algebraic laws (the math that makes this work)"
echo ""
run_test law_commutative \
    && ok "Commutativity:  a join b = b join a        (parallel is safe)" \
    || deny "FAILED"
run_test law_associative \
    && ok "Associativity:  a join (b join c) = (a join b) join c  (ratchet order irrelevant)" \
    || deny "FAILED"
run_test law_idempotent \
    && ok "Idempotency:    a join a = a               (caching is safe)" \
    || deny "FAILED"
run_test law_monotone \
    && ok "Monotonicity:   a <= a join b              (taint never decreases)" \
    || deny "FAILED"

# ── Step 4: Delegation narrowing ──────────────────────────────────────
step 4 "Delegation: child agents cannot escalate beyond parents"
echo ""
echo "    parent is tainted, child is clean"
echo "    child_within_parent(tainted_parent, clean_child)?"
run_test clean_child_escapes_tainted_parent \
    && ok "DENIED -- clean child cannot escape tainted parent (escalation blocked)" \
    || deny "UNEXPECTED FAILURE"

echo ""
echo -e "${BOLD}Demo complete.${RESET}"
echo ""
echo "What you saw:"
echo "  1. Trusted data flows to workspace writes; tainted data is blocked from git push"
echo "  2. All four algebraic laws hold -- commutativity, associativity, idempotency, monotonicity"
echo "  3. Child agents cannot escalate beyond their parent's taint level"
echo ""
echo "These properties are machine-checked:"
echo "  Lean 4:  165 theorems (zero sorry)  -- make -C crates/portcullis-core/lean build"
echo "  Kani:    112 BMC proofs             -- cargo kani -p portcullis"
echo "  Verus:   297 SMT VCs               -- see .github/workflows/verus.yml"
echo ""
echo "Full test suite: cargo test --workspace (~2,850 tests)"
