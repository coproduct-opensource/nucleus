# Local Testing Quickstart

Test Nucleus permission enforcement locally without Kubernetes or Firecracker.

## Prerequisites

- Rust toolchain (1.75+)
- `curl` and `jq` for testing

## 1. Build the Tool Proxy

```bash
cargo build -p nucleus-tool-proxy --release
```

## 2. Start the Tool Proxy

```bash
./target/release/nucleus-tool-proxy \
  --spec examples/openclaw-demo/pod.yaml \
  --listen 127.0.0.1:8080 \
  --auth-secret demo-secret \
  --approval-secret approval-secret \
  --audit-log /tmp/nucleus-demo-audit.log
```

The `demo` profile includes the trifecta (read + web + bash), so all bash commands require approval.

## 3. Test Permission Enforcement

Create a helper function for signed requests:

```bash
nucleus_call() {
  local ENDPOINT=$1
  local BODY=$2
  local TIMESTAMP=$(date +%s)
  local ACTOR="test"
  local MESSAGE="${TIMESTAMP}.${ACTOR}.${BODY}"
  local SIGNATURE=$(echo -n "${MESSAGE}" | openssl dgst -sha256 -hmac "demo-secret" | awk '{print $2}')

  curl -s -X POST "http://127.0.0.1:8080/v1/${ENDPOINT}" \
    -H "Content-Type: application/json" \
    -H "X-Nucleus-Timestamp: ${TIMESTAMP}" \
    -H "X-Nucleus-Actor: ${ACTOR}" \
    -H "X-Nucleus-Signature: ${SIGNATURE}" \
    -d "${BODY}"
}
```

### Test Cases

**Read allowed file (should succeed):**
```bash
nucleus_call "read" '{"path":"README.md"}' | jq -r '.contents[:100]'
# Output: # Nucleus...
```

**Read sensitive file (should be blocked):**
```bash
nucleus_call "read" '{"path":".env"}' | jq '.error'
# Output: "nucleus error: access denied: path '.env' blocked by policy"
```

**Run git status (requires approval due to trifecta):**
```bash
nucleus_call "run" '{"command":"git status"}' | jq '.'
# Output: {"error":"nucleus error: approval required...","kind":"approval_required"}
```

**Run bash -c (blocked by command policy + trifecta):**
```bash
nucleus_call "run" '{"command":"bash -c \"echo hi\""}' | jq '.kind'
# Output: "approval_required"
```

## 4. Verify Audit Log

```bash
cat /tmp/nucleus-demo-audit.log | jq '{event, subject, result}'
```

Each entry includes:
- Hash-chained integrity (`prev_hash`, `hash`)
- HMAC signature (`signature`)
- Actor tracking

## Expected Results

| Test | Expected | Reason |
|------|----------|--------|
| Read README.md | Success | Allowed path |
| Read .env | Blocked | Sensitive path pattern |
| git status | Approval required | Trifecta active (read + web + bash) |
| bash -c | Approval required | Shell interpreter blocked + trifecta |

## Why Trifecta Triggers

The `demo` profile has:
- `read_files: Always` (private data access)
- `web_fetch: LowRisk` (untrusted content)
- `run_bash: LowRisk` (exfiltration vector)

All three legs of the "lethal trifecta" are present, so Nucleus automatically requires approval for exfiltration operations (`run_bash`, `git_push`, `create_pr`).

This protects against prompt injection attacks that could steal secrets via web content.

## Test with Network-Isolated Profile

For testing without trifecta protection, use the `codegen` profile which has no web access:

```yaml
# codegen-pod.yaml
apiVersion: nucleus/v1
kind: Pod
metadata:
  name: codegen-test
spec:
  work_dir: .
  timeout_seconds: 3600
  policy:
    type: profile
    name: codegen
```

```bash
./target/release/nucleus-tool-proxy \
  --spec codegen-pod.yaml \
  --listen 127.0.0.1:8080 \
  --auth-secret demo-secret \
  --approval-secret approval-secret \
  --audit-log /tmp/codegen-audit.log
```

With `codegen`, bash commands will succeed without approval (no trifecta because `web_fetch: Never`).

---

## Next Steps

- [Kubernetes Quickstart](./kubernetes.md) - Production deployment
- [Permission Profiles](../permissions.md) - All available profiles
- [OpenClaw Integration](../../examples/openclaw-demo/README.md) - Full OpenClaw adapter setup
