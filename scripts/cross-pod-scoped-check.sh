#!/usr/bin/env bash
# C2 (cross-pod NI) — pod A's SCOPED listing excludes sibling pod B, on a running
# node, over the real HTTP request path with a real per-pod caller token.
#
# WHY THIS EXISTS
#
# `cross-pod-lineage-check.sh` proves the node records the lineage the filter
# reads; the pod_api ownership tests prove the filter predicate; #2252 drives the
# auth+filter functions. This is the one that ties them together on a running
# node: an orchestrator pod A, presenting ITS OWN node-minted caller token, calls
# the management API and gets a listing SERVER-SIDE-SCOPED to its own lineage —
# so a non-lineage sibling B is excluded, while an operator (no pod token) sees
# both.
#
# It runs KVM-free: the local driver presents each orchestrator pod's caller
# identity by env (NUCLEUS_POD_ID / NUCLEUS_POD_CALLER_TOKEN); the token is
# `derive_token(caller_secret,id)`, so its unforgeability rests on the node-only
# `caller_secret`, not on any transport.
#
# Getting the SAME scoped call on the REAL Firecracker path is NOT merely a
# transport swap (an earlier version of this header implied it was). It needs three
# things the local driver supplies by env that a booted guest does not have:
#   G1 — the pod's own id over vsock. guest-init now fetches `pod_id` alongside the
#        token via FETCH_POD_CALLER_TOKEN, so a caller IDENTITY can form. Without it
#        the guest is unidentified and the node serves the OPERATOR view (all pods)
#        — the fail-OPEN direction, which would make a two-pod boot "pass" vacuously.
#        [LANDED — this brick.]
#   G2 — DROPPED for the chosen route. The HTTP path needs the pod-mgmt config
#        (node URL + node auth secret) in the guest; the vsock route below does
#        not, because the per-pod vsock socket IS the authentication (the node
#        already knows which pod that socket belongs to). No node management
#        secret ever ships into a guest — the keyless, minimal-TCB direction.
#   G3 — a guest->node management ROUTE. `/v1/pods` is served on the host TCP
#        listener only, and the orchestrator pod runs default-deny netns; the vsock
#        bridge is host->guest. The chosen shape is a scoped `PodList` over the
#        workload-API vsock command enum, its caller BOUND to the socket's pod id,
#        filtered by the same `caller_may_manage` predicate. Two bricks:
#          brick 1 [LANDED] factored that set filter out of `collect_pod_infos`
#            (`pod_api::scope_to_caller`) and added the cross-pod SET-exclusion
#            test, so the vsock path runs the identical, tested selection.
#          brick 2 [LANDED] adds `WorkloadApiCommand::PodList` + a read-only
#            `PodListView` (frozen to the socket's pod id, holds no node secret) +
#            dispatch. It WIDENS the guest->host vsock surface, so it deliberately
#            trips the guest-request-surface pin-tests (the human-notice signal),
#            and it turned the stale `..._is_exactly_three` pin — which silently
#            covered only 3 of 9 commands — into a full-surface pin.
# The guest->node ROUTE now exists on the real path. What REMAINS for C2:
#   G4 — the two-pod Firecracker boot that exercises it end to end (pod A booted,
#        POD_LIST over its real vsock, sibling B absent). Runs on Lima nucleus-kvm
#        (needs /dev/kvm). Until G4 proves it live AND Brandon promotes the claim,
#        C2 stays NOT-YET, and this local-driver check remains the KVM-free proof
#        of the identical auth+filter composition.
#
# Path exercised: A's workload → A's tool-proxy `POST /v1/pod/list`
# (`pod_mgmt::list_sub_pods`) → `node_client.list_pods()` attaching A's
# x-nucleus-pod-id/token → node `auth_middleware` (node-auth HMAC + identify) →
# `pod_api::collect_pod_infos` → `caller_may_manage(Some(A), …)` server-side filter.
#
# THE LINEAGE TOOTH (why a third pod C exists). B-exclusion + "strict subset of
# operator" is satisfied even by a filter broken to SELF-ONLY: {A} ⊊ {A,B} holds
# and B is absent, yet nothing lineage-scoped was proven. So A also creates its
# OWN child C (through A's proxy, so the node records parent=A), and the check
# asserts C ∈ A's listing. A self-only filter drops C and reds here; only a
# genuinely lineage-scoped filter passes. This is the discrimination the live G4
# boot must also make — hence C, not just B.
#
# Usage: scripts/cross-pod-scoped-check.sh
set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

PORT="${NUCLEUS_SCOPED_TEST_PORT:-8103}"
URL="http://127.0.0.1:$PORT"
SECRET="$(printf 'a%.0s' {1..64})"
WORK="$(mktemp -d)"
NODE_PID=""
cleanup() { [[ -n "$NODE_PID" ]] && kill "$NODE_PID" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT INT TERM

NODE="${NUCLEUS_NODE_BIN:-}"; CLI="${NUCLEUS_CLI_BIN:-}"; TP="${NUCLEUS_TOOL_PROXY_BIN:-}"
if [[ -z "$NODE" || -z "$CLI" || -z "$TP" ]]; then
    echo "building nucleus-node (local-driver) + nucleus-cli + nucleus-tool-proxy…"
    cargo build -p nucleus-node --features local-driver -p nucleus-cli -p nucleus-tool-proxy \
        >/dev/null 2>&1 || { echo "ERROR: build failed"; exit 1; }
    NODE=target/debug/nucleus-node; CLI=target/debug/nucleus; TP=target/debug/nucleus-tool-proxy
fi
for b in "$NODE" "$CLI" "$TP"; do [[ -x "$b" ]] || { echo "ERROR: missing binary $b"; exit 1; }; done
TP="$(cd "$(dirname "$TP")" && pwd)/$(basename "$TP")"

"$NODE" --auth-secret "$SECRET" --proxy-auth-secret "$SECRET" --proxy-approval-secret "$SECRET" \
    --listen "127.0.0.1:$PORT" --state-dir "$WORK/state" --driver local --allow-local-driver \
    --tool-proxy-path "$TP" >"$WORK/node.log" 2>&1 &
NODE_PID=$!
ready=0
for _ in $(seq 1 40); do
    [[ "$(curl -s -o /dev/null -w '%{http_code}' "$URL/v1/health" 2>/dev/null)" == "200" ]] && { ready=1; break; }
    sleep 0.25
done
[[ "$ready" -eq 1 ]] || { echo "ERROR: node not healthy"; tail -20 "$WORK/node.log"; exit 1; }

N() { "$CLI" node --url "$URL" --auth-secret "$SECRET" "$@" 2>/dev/null | grep -viE "Starting nucleus|config_path"; }

# Pod A: an orchestrator (holds manage_pods) with pod-mgmt enabled, so its
# tool-proxy carries A's caller token and can call the management API.
cat > "$WORK/a.yaml" <<YAML
apiVersion: nucleus/v1
kind: Pod
metadata: { name: orch-a, labels: { enable_pod_mgmt: "true" } }
spec:
  work_dir: .
  timeout_seconds: 120
  policy: { type: profile, name: orchestrator }
  budget_model: { base_cost_usd: 0.000001, cost_per_second_usd: 0.0001 }
  seccomp: { mode: default }
YAML
# Pod B: an ordinary sibling (node-created, NOT A's child).
cat > "$WORK/b.yaml" <<YAML
apiVersion: nucleus/v1
kind: Pod
metadata: { name: sibling-b }
spec:
  work_dir: .
  timeout_seconds: 120
  policy: { type: profile, name: read-only }
  budget_model: { base_cost_usd: 0.000001, cost_per_second_usd: 0.0001 }
  seccomp: { mode: default }
YAML
# Pod C: A's OWN child, created THROUGH A's proxy so the node records parent=A.
cat > "$WORK/c.yaml" <<YAML
apiVersion: nucleus/v1
kind: Pod
metadata: { name: child-c }
spec:
  work_dir: .
  timeout_seconds: 120
  policy: { type: profile, name: read-only }
  budget_model: { base_cost_usd: 0.000001, cost_per_second_usd: 0.0001 }
  seccomp: { mode: default }
YAML

RA="$(N create "$WORK/a.yaml")"
A="$(printf '%s' "$RA" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null)"
APROXY="$(printf '%s' "$RA" | python3 -c "import sys,json; print(json.load(sys.stdin)['proxy_addr'])" 2>/dev/null)"
RB="$(N create "$WORK/b.yaml")"
B="$(printf '%s' "$RB" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null)"
[[ -n "$A" && -n "$B" && "$A" != "$B" && -n "$APROXY" ]] || { echo "ERROR: pod creation failed (A=$A B=$B proxy=$APROXY)"; tail -20 "$WORK/node.log"; exit 1; }

# A creates its own child C through its proxy's /v1/pod/create — the node records
# parent=A from A's authenticated identity, so C is genuinely in A's lineage (the
# tooth a self-only filter cannot satisfy). Same proxy path as the list call, so
# no request-borne auth: A's identity is baked into its proxy.
CPAYLOAD="$(python3 -c "import json; print(json.dumps({'spec_yaml': open('$WORK/c.yaml').read(), 'reason': 'g4 lineage control: A creates its own child C'}))")"
RC="$(curl -s -X POST "$APROXY/v1/pod/create" -H 'content-type: application/json' -d "$CPAYLOAD" 2>/dev/null)"
C="$(printf '%s' "$RC" | python3 -c "import sys,json; print(json.load(sys.stdin)['pod_id'])" 2>/dev/null)"
[[ -n "$C" && "$C" != "$A" && "$C" != "$B" ]] || { echo "ERROR: child C creation via A's proxy failed (C=$C): $RC"; tail -20 "$WORK/node.log"; exit 1; }

N pods > "$WORK/operator.json"
curl -s -X POST "$APROXY/v1/pod/list" -H 'content-type: application/json' -d '{}' > "$WORK/scoped.json" 2>/dev/null

cat > "$WORK/check.py" <<'PY'
import sys, json
a, b, c, op_path, sc_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
def ids(path):
    d = json.load(open(path))
    pods = d if isinstance(d, list) else d.get("pods", [])
    return {p["id"] for p in pods}
op, sc = ids(op_path), ids(sc_path)
errs = []
# Positive controls: A, B, and C genuinely exist (so any absence below is
# EXCLUSION by the filter, not "never created").
if a not in op: errs.append("operator listing missing A (%s)" % a)
if b not in op: errs.append("operator listing missing sibling B (%s) -- cannot conclude B was excluded vs never created" % b)
if c not in op: errs.append("operator listing missing child C (%s) -- cannot conclude C-inclusion means anything" % c)
# The property: A's scoped listing has A, INCLUDES its own child C, EXCLUDES B.
if a not in sc: errs.append("A's scoped listing does NOT contain A -- the token did not authenticate")
if c not in sc: errs.append("A's scoped listing does NOT contain its OWN child C (%s) -- the filter is NOT lineage-scoped; a self-only filter looks exactly like this, so excluding B proves nothing about lineage" % c)
if b in sc: errs.append("A's scoped listing CONTAINS sibling B (%s) -- cross-pod isolation FAILED (token not applied / filter bypassed)" % b)
# Discriminating: scoped is exactly {A,C} here and a STRICT subset of operator
# {A,B,C} -- so scoping happened AND it kept the lineage member.
if not sc: errs.append("A's scoped listing is EMPTY -- not a valid positive result")
elif not (sc < op): errs.append("A's scoped listing (%d) is not a strict subset of operator (%d) -- no scoping occurred" % (len(sc), len(op)))
print("\n".join(errs) if errs else "OK")
PY
result="$(python3 "$WORK/check.py" "$A" "$B" "$C" "$WORK/operator.json" "$WORK/scoped.json")"

if [[ "$result" != "OK" ]]; then
    echo "FAILED: cross-pod scoped listing did not scope A's lineage on the running node:"
    sed 's/^/  /' <<<"$result"
    echo "  A=$A  B=$B  C=$C"
    echo "--- operator ---"; sed 's/^/  /' <<<"$(cat "$WORK/operator.json")"
    echo "--- A scoped ---"; sed 's/^/  /' <<<"$(cat "$WORK/scoped.json")"
    exit 1
fi

echo "OK: on a running node, pod A's authenticated /v1/pod/list (A's own caller token)"
echo "returned A and its OWN child C but EXCLUDED sibling B — a strict subset of the"
echo "operator view that sees all three. The server-side caller_may_manage filter"
echo "scoped the listing to A's lineage (self + direct children), not merely to self."
