# Local Testing Quickstart

Test Nucleus permission enforcement locally without Kubernetes or Firecracker.

## Prerequisites

- Rust toolchain (1.75+)
- `curl` and `jq` for testing

## 1. Build the CLI and the Tool Proxy

```bash
cargo build -p nucleus-cli -p nucleus-tool-proxy -p nucleus-mcp --release
export PATH="$PWD/target/release:$PATH"
```

## 2. Start the Tool Proxy

`nucleus shell --print-config` starts a tool proxy for the current directory and
keeps it running until Ctrl+C. It mints a short-lived identity for the run (the
proxy's sandbox proof) and serves on a peer-verified Unix socket, so there is no
shared secret to choose or pass:

```bash
nucleus shell --profile demo --print-config
# ...
# Tool-proxy: unix:///tmp/nucleus-shell-<id>/p.sock
# Audit log: ...
```

Copy the socket path from the `Tool-proxy:` line. The proxy admits callers by the
kernel-reported credentials of the connecting process; requests carry no
signature.

The `demo` profile includes the uninhabitable state (read + web + bash), so all bash commands require approval.

## 3. Test Permission Enforcement

In another terminal, create a helper function:

```bash
SOCK=/tmp/nucleus-shell-<id>/p.sock   # from the Tool-proxy: line

nucleus_call() {
  local ENDPOINT=$1
  local BODY=$2
  curl -s --unix-socket "${SOCK}" -X POST "http://localhost/v1/${ENDPOINT}" \
    -H "Content-Type: application/json" \
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

**Run git status (requires approval due to uninhabitable state):**
```bash
nucleus_call "run" '{"command":"git status"}' | jq '.'
# Output: {"error":"nucleus error: approval required...","kind":"approval_required"}
```

**Run bash -c (blocked by command policy + uninhabitable state):**
```bash
nucleus_call "run" '{"command":"bash -c \"echo hi\""}' | jq '.kind'
# Output: "approval_required"
```

## 4. Verify Audit Log

Use the path from the `Audit log:` line:

```bash
jq '{event, subject, result}' <audit-log-path>
```

Each entry includes:
- Hash-chained integrity (`prev_hash`, `hash`)
- An Ed25519 signature from a key only the proxy holds (`signature`)
- Actor tracking

## Expected Results

| Test | Expected | Reason |
|------|----------|--------|
| Read README.md | Success | Allowed path |
| Read .env | Blocked | Sensitive path pattern |
| git status | Approval required |  Uninhabitable state active (read + web + bash) |
| bash -c | Approval required | Shell interpreter blocked + uninhabitable state |

## Why  Uninhabitable state Triggers

The `demo` profile has:
- `read_files: Always` (private data access)
- `web_fetch: LowRisk` (untrusted content)
- `run_bash: LowRisk` (exfiltration vector)

All three legs of the "uninhabitable state" are present, so Nucleus automatically requires approval for exfiltration operations (`run_bash`, `git_push`, `create_pr`).

This protects against prompt injection attacks that could steal secrets via web content.

## Test with Network-Isolated Profile

For testing without uninhabitable state protection, use the `codegen` profile which has no web access:

```bash
nucleus shell --profile codegen --print-config
```

With `codegen`, bash commands will succeed without approval (no uninhabitable state because `web_fetch: Never`).

---

## Next Steps

- [Kubernetes Quickstart](./kubernetes.md) - Production deployment
- [Permission Profiles](../permissions.md) - All available profiles
- [OpenClaw Integration](../../examples/openclaw-demo/README.md) - Full OpenClaw adapter setup
