#!/usr/bin/env bash
# Declassify sink-scope ENFORCEMENT gate — the successor to the dormancy gate.
#
# WHY THIS EXISTS
#
# `DeclassificationToken::allowed_sinks` restricts which sinks declassified data
# may reach. It used to be signed, proven, documented — and NOT enforced: the
# token path was dormant, and `scripts/check-declassify-token-dormant.sh`
# asserted the ONLY reason that was safe (no production caller). That premise is
# now spent: `POST /v1/declassify` (nucleus-tool-proxy) is a live governor
# caller, and the scope is enforced in `FlowGraph` as a per-node released VIEW —
# a token clears its node for the operations it signed and NO others.
#
# This gate replaces the dormancy premise with the property itself: a token
# scoped to sink S clears its node for S and ONLY S, at most once. It runs the
# tests that would fail if that stopped being true —
#
#   * the two-oracle graph binding (portcullis `declassify_scope`): in-mask
#     verdicts equal a released oracle, off-mask verdicts equal the token-free
#     oracle — so an unscoped release (mask widened to admit everything) reds it;
#   * the exhaustive extracted parity (`extracted::declassify`,
#     `declassify::` in portcullis-core): `mask_admits` ↔ `allows_sink` over the
#     whole 2^13 × 13 domain, and the one-shot absorbing machine.
#
# So this gate does NOT re-assert dormancy (the path is live). It asserts the
# scope is enforced, which is what makes the live path safe.
#
# Usage: scripts/check-declassify-sink-scope-enforced.sh
set -euo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

echo "Asserting the declassification sink scope is enforced (not just declared)..."

# The graph-level binding: a token scoped to S clears its node for S and only S.
cargo test -p portcullis --features crypto --test declassify_scope

# The extracted decision core the graph routes through, and its exhaustive
# parity with the token's own allowlist API + the one-shot machine.
cargo test -p nucleus-ifc-kernel --lib extracted::declassify
cargo test -p portcullis-core --lib declassify::

echo "ok  declassification sink scope is enforced: a token clears its node for"
echo "    its signed sinks and only those, at most once."
