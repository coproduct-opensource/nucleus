#!/usr/bin/env bash
# C2 (cross-pod NI) — the node records pod lineage on the LIVE path.
#
# WHY THIS EXISTS
#
# The cross-pod scoping the management API enforces (`pod_api::caller_may_manage`)
# is only as sound as the `parent_pod_id` lineage it reads. That predicate is
# unit-tested, pinned to the `PodCrossView.lean` model, and driven through the
# auth+filter request path (`pod_b_cannot_observe_pod_a_across_the_auth_and_filter_path`).
# What none of those exercise is the OTHER half on a RUNNING node: that the real
# create API, over signed HTTP, actually records the lineage the filter then
# reads, and that the listing serves it.
#
# This boots the real `nucleus-node` process with the KVM-free `local-driver`
# (so it runs in ordinary CI, no Firecracker), creates three pods through the
# real signed `POST /v1/pods` — two node-created siblings A and B, and a child of
# A — and asserts the operator listing serves the recorded lineage: A's child has
# `parent_pod_id == A`, and A and B are top-level (`parent_pod_id` absent).
#
# Scope, stated honestly: this is the create→record→serve half. It does NOT
# exercise the SCOPED filter on the running node — that needs a pod's own caller
# token, which is derived from a node-only secret and served over the per-pod
# vsock (deliberately unforgeable), so it requires a real Firecracker pod. The
# scoped filter is covered at the function level; this covers the lineage it
# depends on.
#
# Usage: scripts/cross-pod-lineage-check.sh
set -uo pipefail
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

PORT="${NUCLEUS_LINEAGE_TEST_PORT:-8097}"
URL="http://127.0.0.1:$PORT"
SECRET="$(printf 'a%.0s' {1..64})"   # 64 hex chars → a usable (non-empty, non-world-known) 32-byte key
WORK="$(mktemp -d)"
NODE_PID=""

cleanup() {
    [[ -n "$NODE_PID" ]] && kill "$NODE_PID" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# ── Binaries ────────────────────────────────────────────────────────────────
NODE="${NUCLEUS_NODE_BIN:-}"
CLI="${NUCLEUS_CLI_BIN:-}"
TP="${NUCLEUS_TOOL_PROXY_BIN:-}"
if [[ -z "$NODE" || -z "$CLI" || -z "$TP" ]]; then
    echo "building nucleus-node (local-driver) + nucleus-cli + nucleus-tool-proxy…"
    cargo build -p nucleus-node --features local-driver -p nucleus-cli -p nucleus-tool-proxy \
        >/dev/null 2>&1 || { echo "ERROR: build failed"; exit 1; }
    NODE=target/debug/nucleus-node
    CLI=target/debug/nucleus
    TP=target/debug/nucleus-tool-proxy
fi
for b in "$NODE" "$CLI" "$TP"; do [[ -x "$b" ]] || { echo "ERROR: missing binary $b"; exit 1; }; done
TP="$(cd "$(dirname "$TP")" && pwd)/$(basename "$TP")"

# ── Boot the real node (local driver, no KVM) ───────────────────────────────
"$NODE" --auth-secret "$SECRET" --proxy-auth-secret "$SECRET" --proxy-approval-secret "$SECRET" \
    --listen "127.0.0.1:$PORT" --state-dir "$WORK/state" --driver local --allow-local-driver \
    --tool-proxy-path "$TP" >"$WORK/node.log" 2>&1 &
NODE_PID=$!

ready=0
for _ in $(seq 1 40); do
    if [[ "$(curl -s -o /dev/null -w '%{http_code}' "$URL/v1/health" 2>/dev/null)" == "200" ]]; then
        ready=1; break
    fi
    sleep 0.25
done
if [[ "$ready" -ne 1 ]]; then
    echo "ERROR: node did not become healthy on $URL"; tail -20 "$WORK/node.log"; exit 1
fi

N() { "$CLI" node --url "$URL" --auth-secret "$SECRET" "$@" 2>/dev/null | grep -viE "Starting nucleus|config_path"; }

# A minimal, no-network pod spec (local driver).
spec() {
cat <<YAML
apiVersion: nucleus/v1
kind: Pod
metadata:
  name: $1
spec:
  work_dir: .
  timeout_seconds: 60
  policy: { type: profile, name: demo }
  budget_model: { base_cost_usd: 0.000001, cost_per_second_usd: 0.0001 }
  seccomp: { mode: default }
YAML
}
id_of() { python3 -c "import sys,json; print(json.load(sys.stdin)['id'])"; }

spec pod-a > "$WORK/a.yaml"; spec pod-b > "$WORK/b.yaml"; spec pod-a-child > "$WORK/ac.yaml"

A="$(N create "$WORK/a.yaml" | id_of)"
B="$(N create "$WORK/b.yaml" | id_of)"
N create "$WORK/ac.yaml" --parent-pod-id "$A" >/dev/null

[[ -n "$A" && -n "$B" && "$A" != "$B" ]] || { echo "ERROR: pod creation did not yield two distinct ids (A=$A B=$B)"; exit 1; }

# ── The assertion: the listing serves the recorded lineage ──────────────────
N pods > "$WORK/listing.json"
LISTING="$(cat "$WORK/listing.json")"
result="$(python3 - "$A" "$B" "$WORK/listing.json" <<'PY'
import sys, json
a, b, path = sys.argv[1], sys.argv[2], sys.argv[3]
pods = json.load(open(path))
by_name = {p["name"]: p for p in pods}
errs = []
for n in ("pod-a", "pod-b", "pod-a-child"):
    if n not in by_name:
        errs.append(f"{n} missing from the listing")
if not errs:
    if by_name["pod-a-child"].get("parent_pod_id") != a:
        errs.append(f"pod-a-child parent_pod_id={by_name['pod-a-child'].get('parent_pod_id')} != A ({a})")
    if by_name["pod-a"].get("parent_pod_id") is not None:
        errs.append(f"pod-a is top-level but has parent_pod_id={by_name['pod-a'].get('parent_pod_id')}")
    if by_name["pod-b"].get("parent_pod_id") is not None:
        errs.append(f"pod-b is top-level but has parent_pod_id={by_name['pod-b'].get('parent_pod_id')}")
    # Non-vacuity: A's child's parent is A specifically, and A != B.
    if by_name["pod-a-child"].get("parent_pod_id") == b:
        errs.append("pod-a-child's parent is B, not A — lineage was misrecorded")
print("\n".join(errs) if errs else "OK")
PY
)"

if [[ "$result" != "OK" ]]; then
    echo "FAILED: the running node did not record/serve lineage correctly:"
    sed 's/^/  /' <<<"$result"
    echo "--- listing ---"; sed 's/^/  /' <<<"$LISTING"
    exit 1
fi

echo "OK: on a live node, POST /v1/pods recorded lineage (pod-a-child.parent == pod-a;"
echo "pod-a and pod-b top-level) and the listing served it — the input the cross-pod"
echo "filter (caller_may_manage) reads is correct on the running path."
