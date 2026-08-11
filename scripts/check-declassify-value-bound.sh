#!/usr/bin/env bash
# Declassify VALUE-BINDING enforcement gate — C4 (single-use, live) + C5 (value
# non-steering) falsifier.
#
# WHY THIS EXISTS
#
# The declassification story earns two flagship rows only if three things hold
# together on the graph the live egress verdict reads (`state.flow_graph`):
#
#   * VALUE-BINDING (C5): a governor-signed token releases ONLY for a node whose
#     monitor-recomputed ingest `content_hash` EQUALS the token's signed
#     `content_commitment`. A substituted value ⇒ `ContentMismatch`, fail-closed,
#     and NON-burning (the token stays usable). This is `FlowGraph::value_binding_ok`
#     and the `authorize_release` / `apply_token_verified` paths that route through
#     it.
#   * FOUR-RUN ROBUSTNESS (C5, relational): over runs that differ only in
#     attacker-controlled recorded content, a release yields EXACTLY the committed
#     value or denies — the attacker can force a deny, never a different value.
#   * SINGLE-USE + FLIP, LIVE (C4): applying a valid token on the live graph FLIPS
#     the egress verdict Deny→Pass for exactly the committed value at exactly the
#     signed sinks, and an identical replay is denied (the shared one-shot burn
#     ledger). This is the #2235 re-home: the apply lands on `state.flow_graph`,
#     the graph egress reads — NOT the kernel's separate, never-populated graph.
#
# This gate runs the tests that red if any of those stops holding, AND asserts —
# by inspection of the shipping endpoint — that `POST /v1/declassify` still
# applies on `state.flow_graph`. That last check is the falsifier for the exact
# regression #2235 fixed: re-pointing the endpoint at the orphan kernel graph
# makes declassification inert again (NodeNotFound on the read graph) while every
# unit test that constructs its own graph stays green. The dead-mechanism inversion
# that demoted C4 must never be able to return silently.
#
# Usage: scripts/check-declassify-value-bound.sh
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

echo "Asserting declassification is VALUE-BOUND, single-use, and live on the graph egress reads..."

ENDPOINT="crates/nucleus-tool-proxy/src/declassify.rs"

# ── (1) The endpoint applies on the LIVE graph, not the orphan kernel graph ──
# #2235 re-homed the apply onto state.flow_graph. If the endpoint is re-pointed
# at the kernel's own graph (`kernel.apply_declassification_token(&token)`, the
# self-graph variant), declassification goes inert end-to-end (the read graph is
# never populated) and C4 collapses back to a dead mechanism. Assert the wiring
# the live claim rests on.
[[ -f "$ENDPOINT" ]] || { echo "FAIL: $ENDPOINT not found"; exit 1; }
if ! grep -q 'apply_declassification_token_on' "$ENDPOINT"; then
    echo "FAIL: $ENDPOINT no longer calls apply_declassification_token_on —"
    echo "      the apply must land on the caller-supplied live graph, not the"
    echo "      kernel's own (never-populated) flow_graph. This is the #2235 regression."
    exit 1
fi
if ! grep -q 'state\.flow_graph' "$ENDPOINT"; then
    echo "FAIL: $ENDPOINT no longer locks state.flow_graph — the declassification"
    echo "      scope would land on a graph the egress verdict never reads (inert)."
    exit 1
fi

# ── (2) Value-binding + single-use + flip, over the kernel apply on the LIVE-typed graph ──
# kernel_token: mint/apply/replay + ContentMismatch (substitution refused, not burned).
# declassify_rehome_egress: the C4 flip-back Deny→Pass on ONE graph + the fail-open
#   boundary matrix (substituted value, unsigned sink, replay, second secret, poison).
cargo test -p portcullis --features crypto --test kernel_token --test declassify_rehome_egress

# ── (3) Four-run VALUE non-steering + the u64-tag↔32-byte parity binding ──
# declassify_scope: four_run_released_value_is_not_attacker_steerable (relational,
#   over four attacker-varied runs) + authorize_release_value_binding_matches_the_
#   extracted_decision (the 32-byte ContentHash ⇔ u64-tag parity the proof abstracts).
cargo test -p portcullis --features crypto --test declassify_scope

echo "ok  declassification is value-bound (ContentMismatch on substitution),"
echo "    single-use, and applied on the live graph the egress verdict reads."
