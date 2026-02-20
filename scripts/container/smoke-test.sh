#!/usr/bin/env bash
# Smoke test for nucleus-node container driver (Colima / Docker Desktop).
#
# Usage:
#   colima start
#   bash scripts/container/smoke-test.sh
#
# The script builds a tiny Alpine test image, starts nucleus-node with
# --driver container, and exercises the full pod lifecycle via HTTP API.
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT_DIR"

NODE_ADDR=${NODE_ADDR:-127.0.0.1:8091}
AUTH_SECRET=${AUTH_SECRET:-smoke-secret}
PROXY_AUTH_SECRET=${PROXY_AUTH_SECRET:-smoke-proxy}
APPROVAL_SECRET=${APPROVAL_SECRET:-smoke-approval}
TEST_IMAGE="nucleus-smoke:latest"
STATE_DIR=$(mktemp -d)
NODE_PID=""
SPEC_FILE=""
PASSED=0
FAILED=0

# ── helpers ──────────────────────────────────────────────────────────────

red()   { printf '\033[0;31m%s\033[0m\n' "$*"; }
green() { printf '\033[0;32m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }

pass() { PASSED=$((PASSED + 1)); green "[pass] $1"; }
fail() { FAILED=$((FAILED + 1)); red  "[FAIL] $1: $2"; }

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    red "missing required command: $1"
    exit 1
  fi
}

cleanup() {
  if [ -n "${SPEC_FILE}" ] && [ -f "${SPEC_FILE}" ]; then
    rm -f "${SPEC_FILE}"
  fi
  if [ -n "${NODE_PID}" ]; then
    kill "${NODE_PID}" >/dev/null 2>&1 || true
    wait "${NODE_PID}" >/dev/null 2>&1 || true
  fi
  rm -rf "${STATE_DIR}"
  docker rmi "${TEST_IMAGE}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# HMAC-SHA256 signing.
# Message format: "{timestamp}.{actor}.{body_bytes}"
# Returns: "timestamp signature actor"
sign_request() {
  local secret="$1" body_file="$2" actor="${3:-smoke-test}"
  local ts
  ts=$(date +%s)
  local prefix="${ts}.${actor}."
  local sig
  sig=$( ( printf '%s' "$prefix"; cat "$body_file" ) \
    | openssl dgst -sha256 -hmac "$secret" -hex 2>/dev/null \
    | sed 's/^.* //' )
  echo "${ts} ${sig} ${actor}"
}

# Signed curl: POST with HMAC headers.
signed_post() {
  local url="$1" body_file="$2"
  local parts
  parts=$(sign_request "${AUTH_SECRET}" "$body_file")
  local ts sig actor
  ts=$(echo "$parts"  | cut -d' ' -f1)
  sig=$(echo "$parts" | cut -d' ' -f2)
  actor=$(echo "$parts" | cut -d' ' -f3)
  curl -sS -X POST \
    -H "x-nucleus-timestamp: ${ts}" \
    -H "x-nucleus-signature: ${sig}" \
    -H "x-nucleus-actor: ${actor}" \
    -H "content-type: application/x-yaml" \
    --data-binary @"${body_file}" \
    "${url}"
}

# Signed curl: GET with HMAC headers (empty body).
signed_get() {
  local url="$1"
  local ts
  ts=$(date +%s)
  local actor="smoke-test"
  local prefix="${ts}.${actor}."
  local sig
  sig=$(printf '%s' "$prefix" \
    | openssl dgst -sha256 -hmac "${AUTH_SECRET}" -hex 2>/dev/null \
    | sed 's/^.* //')
  curl -sS \
    -H "x-nucleus-timestamp: ${ts}" \
    -H "x-nucleus-signature: ${sig}" \
    -H "x-nucleus-actor: ${actor}" \
    "${url}"
}

# ── preflight ────────────────────────────────────────────────────────────

bold "=== nucleus container driver smoke test ==="

require curl
require jq
require openssl
require docker
require cargo

bold "[preflight] checking docker..."
if ! docker info >/dev/null 2>&1; then
  red "Docker not reachable. Is Colima running?"
  red "  colima start"
  exit 1
fi
pass "docker reachable"

# ── build test image ─────────────────────────────────────────────────────

bold "[build] building ${TEST_IMAGE}..."
docker build -q -t "${TEST_IMAGE}" -f scripts/container/Dockerfile.smoke-test . >/dev/null
pass "${TEST_IMAGE} built"

# ── start nucleus-node ───────────────────────────────────────────────────

bold "[node] starting nucleus-node (container driver)..."
# Ensure DOCKER_HOST is set for bollard (Colima socket isn't at /var/run/docker.sock)
if [ -z "${DOCKER_HOST:-}" ]; then
  COLIMA_SOCK="${HOME}/.colima/default/docker.sock"
  if [ -S "$COLIMA_SOCK" ]; then
    export DOCKER_HOST="unix://${COLIMA_SOCK}"
    bold "[node] DOCKER_HOST=${DOCKER_HOST}"
  fi
fi
RUST_LOG=info,nucleus_node=debug \
  cargo run -p nucleus-node --release -- \
    --driver container \
    --listen "${NODE_ADDR}" \
    --auth-secret "${AUTH_SECRET}" \
    --proxy-auth-secret "${PROXY_AUTH_SECRET}" \
    --proxy-approval-secret "${APPROVAL_SECRET}" \
    --container-image "${TEST_IMAGE}" \
    --container-network bridge \
    --state-dir "${STATE_DIR}" \
    >"${STATE_DIR}/node.log" 2>&1 &
NODE_PID=$!

# Wait for health endpoint
bold "[health] waiting for /v1/health..."
HEALTHY=0
for _ in $(seq 1 120); do
  if curl -fsS "http://${NODE_ADDR}/v1/health" >/dev/null 2>&1; then
    HEALTHY=1
    break
  fi
  # Check if the process died during startup (e.g. compile error)
  if ! kill -0 "$NODE_PID" 2>/dev/null; then
    red "nucleus-node process exited during startup"
    cat "${STATE_DIR}/node.log"
    exit 1
  fi
  sleep 0.5
done

if [ "$HEALTHY" -ne 1 ]; then
  red "nucleus-node failed to start within 60s"
  red "log tail:"
  tail -20 ${STATE_DIR}/node.log
  exit 1
fi
pass "/v1/health ok"

# ── test: auth required ──────────────────────────────────────────────────

bold "[auth] testing unauthenticated request..."
HTTP_CODE=$(curl -sS -o /dev/null -w "%{http_code}" \
  -X POST -H "content-type: application/x-yaml" \
  -d "apiVersion: nucleus/v1" \
  "http://${NODE_ADDR}/v1/pods")
if [ "$HTTP_CODE" = "401" ]; then
  pass "unauthenticated POST -> 401"
else
  fail "unauthenticated POST" "expected 401, got ${HTTP_CODE}"
fi

# ── test: create pod ─────────────────────────────────────────────────────

bold "[pod] creating test pod..."
SPEC_FILE=$(mktemp)
cat > "${SPEC_FILE}" <<'YAML'
apiVersion: nucleus/v1
kind: Pod
metadata:
  name: smoke-test
  labels:
    nucleus.io/container-image: "nucleus-smoke:latest"
    nucleus.io/proxy-mode: "false"
    nucleus.io/network: "bridge"
spec:
  work_dir: /
  timeout_seconds: 30
  credentials:
    env:
      LLM_API_TOKEN: "test-token-123"
  policy:
    type: profile
    name: demo
YAML

RESP=$(signed_post "http://${NODE_ADDR}/v1/pods" "${SPEC_FILE}")
POD_ID=$(echo "$RESP" | jq -r '.id // empty')

if [ -z "$POD_ID" ]; then
  fail "create pod" "no id in response: ${RESP}"
  bold "log tail:"
  tail -30 ${STATE_DIR}/node.log
  exit 1
fi
pass "created pod ${POD_ID}"

# ── test: poll lifecycle ─────────────────────────────────────────────────

bold "[lifecycle] polling pod state..."
TERMINAL=0
EXIT_CODE=""
for _ in $(seq 1 60); do
  PODS_RESP=$(signed_get "http://${NODE_ADDR}/v1/pods")
  POD_STATE=$(echo "$PODS_RESP" | jq -r --arg id "$POD_ID" \
    '.[] | select(.id == $id) | .state // empty')

  # Check for exited state (serde snake_case: {"exited":{"code":0}})
  if echo "$POD_STATE" | jq -e '.exited' >/dev/null 2>&1; then
    EXIT_CODE=$(echo "$POD_STATE" | jq -r '.exited.code // "null"')
    TERMINAL=1
    break
  fi
  # Also handle string forms
  if [ "$POD_STATE" = "exited" ] || [ "$POD_STATE" = "Exited" ]; then
    EXIT_CODE="0"
    TERMINAL=1
    break
  fi
  sleep 0.5
done

if [ "$TERMINAL" -ne 1 ]; then
  fail "lifecycle" "pod did not reach terminal state within 30s"
  echo "Last state: ${POD_STATE:-unknown}"
  echo "Last response: ${PODS_RESP}"
  tail -30 ${STATE_DIR}/node.log
else
  if [ "$EXIT_CODE" = "0" ]; then
    pass "pod exited with code 0"
  else
    fail "lifecycle" "expected exit code 0, got ${EXIT_CODE}"
  fi
fi

# ── test: verify logs ────────────────────────────────────────────────────

bold "[logs] fetching pod logs..."
LOGS=$(signed_get "http://${NODE_ADDR}/v1/pods/${POD_ID}/logs")

# Check NUCLEUS_ARTIFACT lines
if echo "$LOGS" | grep -q 'NUCLEUS_ARTIFACT.*commit.*abc123smoke'; then
  pass "NUCLEUS_ARTIFACT commit sha=abc123smoke"
else
  fail "artifact: commit" "not found in logs"
fi

if echo "$LOGS" | grep -q 'NUCLEUS_ARTIFACT.*file_modified.*src/main.rs'; then
  pass "NUCLEUS_ARTIFACT file_modified path=src/main.rs"
else
  fail "artifact: file_modified" "not found in logs"
fi

if echo "$LOGS" | grep -q 'NUCLEUS_ARTIFACT.*pr_url'; then
  pass "NUCLEUS_ARTIFACT pr_url"
else
  fail "artifact: pr_url" "not found in logs"
fi

# Check credential passthrough
if echo "$LOGS" | grep -q 'LLM_API_TOKEN=test-token-123'; then
  pass "credential passthrough LLM_API_TOKEN"
else
  fail "credential passthrough" "LLM_API_TOKEN not found in logs"
fi

# ── test: container cleanup ──────────────────────────────────────────────

bold "[cleanup] checking container removal..."
sleep 1  # give node a moment to clean up
# Pod containers are named with their UUID prefix
SHORT_ID=$(echo "$POD_ID" | cut -c1-12)
REMAINING=$(docker ps -a --filter "name=${SHORT_ID}" --format '{{.ID}}' 2>/dev/null || true)
if [ -z "$REMAINING" ]; then
  pass "container removed after exit"
else
  # Container might still be present but stopped — check
  fail "container cleanup" "container still present: ${REMAINING}"
fi

# ── summary ──────────────────────────────────────────────────────────────

echo ""
bold "════════════════════════════════════════"
if [ "$FAILED" -eq 0 ]; then
  green "ALL ${PASSED} TESTS PASSED"
else
  red "${FAILED} FAILED, ${PASSED} passed"
  exit 1
fi
