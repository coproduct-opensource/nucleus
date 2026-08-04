#!/usr/bin/env bash
# The discharge seal holds only while `test-helpers` stays out of production.
#
# WHY THIS EXISTS
#
# `nucleus_ifc_kernel::discharge::test_helpers::bundle_for` mints a
# `DischargedBundle` with NO preflight. That is correct and necessary — tests
# must be able to exercise effect sites — and it is gated behind a `test-helpers`
# feature that three crates enable, all of them from `[dev-dependencies]`.
#
# `broker_client::perform_line` takes an `Authority`, which is constructible only
# from a `DischargedBundle`, whose constructor is private to the discharge
# module. That signature is what turns "a PerformRequest is composed only past a
# minted DischargedBundle" from a sentence in a doc comment into a compile-time
# obligation.
#
# It stops being an obligation the moment `test-helpers` is enabled through a
# NORMAL dependency edge anywhere in the graph, because Cargo unifies features
# per build: `bundle_for` becomes callable from production code and anyone can
# mint the proof. Nothing would fail. Every test would stay green — tests already
# have the feature on, so they cannot notice.
#
# One line moving from `[dev-dependencies]` to `[dependencies]` is the whole
# distance between a real gate and a decorative one.
#
# WHY THE RESOLVED GRAPH AND NOT A MANIFEST GREP
#
# Grepping Cargo.toml for `features = ["test-helpers"]` under `[dependencies]`
# would miss transitive enabling — some other crate turning on
# `portcullis-core/test-helpers` as a normal dep pulls
# `nucleus-ifc-kernel/test-helpers` with it (portcullis-core/Cargo.toml declares
# exactly that mapping). `cargo tree --edges features,no-dev` reports what a
# production build actually resolves, which is the question being asked.
#
# A NOTE ON `cargo tree`
#
# `-e features` alone does NOT exclude dev edges; the default edge set still
# includes them, so it reports `test-helpers` as present and looks alarming.
# `no-dev` is the flag that answers "what does a production build see". This
# script exists partly because that distinction cost a wrong conclusion once.
#
# Usage: scripts/check-test-helpers-not-in-production.sh
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

# Crates that ship and are on the agent effect path. A `DischargedBundle` minted
# without preflight in any of these defeats the discharge boundary.
CRATES=(nucleus-tool-proxy nucleus-node nucleus-mcp)

violations=0
for crate in "${CRATES[@]}"; do
    if ! cargo metadata --no-deps --format-version 1 2>/dev/null \
        | grep -q "\"name\":\"${crate}\""; then
        echo "ERROR: $crate is not a workspace member — this gate is watching a crate that moved"
        exit 1
    fi

    found=$(cargo tree --edges features,no-dev -p "$crate" 2>/dev/null \
        | grep -c 'test-helpers' || true)

    echo "test-helpers in $crate (production build): $found"
    if [[ "$found" -ne 0 ]]; then
        echo ""
        echo "VIOLATION: $crate resolves \`test-helpers\` in a NON-dev build."
        echo ""
        echo "  discharge::test_helpers::bundle_for mints a DischargedBundle with no"
        echo "  preflight. With this feature on in production, any code in $crate can"
        echo "  mint the proof that broker_client::perform_line demands, and the"
        echo "  compile-time obligation becomes decorative."
        echo ""
        echo "  Every test will still pass — tests already enable the feature, so they"
        echo "  cannot see this. Find it with:"
        echo "      cargo tree --edges features,no-dev -p $crate | grep -B5 test-helpers"
        echo "  and move the enabling entry back to [dev-dependencies]."
        violations=$((violations + 1))
    fi
done

# NON-VACUITY. If `test-helpers` stopped existing, or the feature were renamed,
# every check above would report 0 and this gate would pass while enforcing
# nothing. So assert the feature is real AND that a dev build genuinely resolves
# it — the same query that must return 0 above must return non-zero here.
dev_found=$(cargo tree --edges features -p nucleus-tool-proxy 2>/dev/null \
    | grep -c 'test-helpers' || true)
if [[ "$dev_found" -eq 0 ]]; then
    echo ""
    echo "ERROR: \`test-helpers\` does not appear in nucleus-tool-proxy's DEV feature"
    echo "graph either. The feature has been renamed or removed, so the checks above"
    echo "are passing without enforcing anything. Update this gate to the new name."
    exit 1
fi
echo "non-vacuity: dev build resolves test-helpers ($dev_found edges), production does not"

if [[ "$violations" -gt 0 ]]; then
    exit 1
fi

echo "OK: the discharge seal is not reachable from any shipping build"
