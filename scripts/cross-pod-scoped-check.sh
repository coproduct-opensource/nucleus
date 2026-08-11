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
# It runs KVM-free: the local driver now presents each orchestrator pod's caller
# token (NUCLEUS_POD_ID / NUCLEUS_POD_CALLER_TOKEN, env-parity with what guest-init
# fetches over vsock in Firecracker — the token is `derive_token(caller_secret,id)`
# either way, so its unforgeability rests on the node-only `caller_secret`, not on
# the vsock transport). The full Firecracker two-pod boot (token delivered over the
# REAL vsock) is a separate increment; this exercises the identical auth+filter
# composition on a booted node in an ordinary CI lane.
#
# Path exercised: A's workload → A's tool-proxy `POST /v1/pod/list`
# (`pod_mgmt::list_sub_pods`) → `node_client.list_pods()` attaching A's
# x-nucleus-pod-id/token → node `auth_middleware` (node-auth HMAC + identify) →
# `pod_api::collect_pod_infos` → `caller_may_manage(Some(A), …)` server-side filter.
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

RA="$(N create "$WORK/a.yaml")"
A="$(printf '%s' "$RA" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null)"
APROXY="$(printf '%s' "$RA" | python3 -c "import sys,json; print(json.load(sys.stdin)['proxy_addr'])" 2>/dev/null)"
RB="$(N create "$WORK/b.yaml")"
B="$(printf '%s' "$RB" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null)"
[[ -n "$A" && -n "$B" && "$A" != "$B" && -n "$APROXY" ]] || { echo "ERROR: pod creation failed (A=$A B=$B proxy=$APROXY)"; tail -20 "$WORK/node.log"; exit 1; }

N pods > "$WORK/operator.json"
curl -s -X POST "$APROXY/v1/pod/list" -H 'content-type: application/json' -d '{}' > "$WORK/scoped.json" 2>/dev/null

cat > "$WORK/check.py" <<'PY'
import sys, json
a, b, op_path, sc_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
def ids(path):
    d = json.load(open(path))
    pods = d if isinstance(d, list) else d.get("pods", [])
    return {p["id"] for p in pods}
op, sc = ids(op_path), ids(sc_path)
errs = []
# Positive control 1: B genuinely exists (the exclusion isn't "B never booted").
if a not in op: errs.append("operator listing missing A (%s)" % a)
if b not in op: errs.append("operator listing missing sibling B (%s) -- cannot conclude B was excluded vs never created" % b)
# The property: A's scoped listing has A, excludes B.
if a not in sc: errs.append("A's scoped listing does NOT contain A -- the token did not authenticate")
if b in sc: errs.append("A's scoped listing CONTAINS sibling B (%s) -- cross-pod isolation FAILED (token not applied / filter bypassed)" % b)
# Discriminating: scoped is a STRICT subset of operator (proves scoping happened).
if not sc: errs.append("A's scoped listing is EMPTY -- not a valid positive result")
elif not (sc < op): errs.append("A's scoped listing (%d) is not a strict subset of operator (%d) -- no scoping occurred" % (len(sc), len(op)))
print("\n".join(errs) if errs else "OK")
PY
result="$(python3 "$WORK/check.py" "$A" "$B" "$WORK/operator.json" "$WORK/scoped.json")"

if [[ "$result" != "OK" ]]; then
    echo "FAILED: cross-pod scoped listing did not isolate A from B on the running node:"
    sed 's/^/  /' <<<"$result"
    echo "  A=$A  B=$B"
    echo "--- operator ---"; sed 's/^/  /' <<<"$(cat "$WORK/operator.json")"
    echo "--- A scoped ---"; sed 's/^/  /' <<<"$(cat "$WORK/scoped.json")"
    exit 1
fi

echo "OK: on a running node, pod A's authenticated /v1/pod/list (A's own caller token)"
echo "returned A but EXCLUDED sibling B — a strict subset of the operator view that sees"
echo "both. The server-side caller_may_manage filter scoped the listing by A's identity."
