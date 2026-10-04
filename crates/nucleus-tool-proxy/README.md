# nucleus-tool-proxy

HTTP JSON tool proxy that runs inside a pod (VM) and enforces nucleus policies.

## Ordinary HTTP clients

`nucleus-egress-http` exposes one registered broker upstream on guest loopback.
Build it with `cargo build -p nucleus-tool-proxy --bin nucleus-egress-http` and
include the executable in the guest image. Both the guest layer and release
rootfs builder include it. Use it as the pod's workload command to manage the
listener and harness together, under the same workload UID:

```text
nucleus-egress-http --upstream model-api --listen 127.0.0.1:18081 -- /opt/harness/bin/agent task
```

The adapter binds before launching the command after `--`, passes its arguments
verbatim, and sets `NUCLEUS_EGRESS_HTTP_URL` to the bound listener URL. The
orchestrator configures the harness's API base using this URL or the fixed
listen address. The command inherits the workload's filtered environment,
working directory and captured standard streams. Its exit status becomes the
adapter's exit status; the listener closes when the command exits. SIGINT or
SIGTERM stops and reaps the direct child. The enclosing pod supervisor remains
responsible for containment and descendant cleanup. Without a command, the
adapter runs as a standalone listener until stopped.

For the legacy rootfs builder, the adapter must be beside `PROXY_BIN` in the
build directory. A normal package build produces both executables. Image
assembly copies the adapter after applying overlays and fails if it is absent.

`NUCLEUS_TOOL_PROXY_URL` supplies the runtime's Unix workload door; `--door`
can also supply an absolute `unix:///...` socket path. Configure the harness's
API base to use the local listener. A request to `/v1/inference` becomes a
door request to `/v1/egress/model-api/v1/inference`. The upstream registration
and credential stay on the host. No real credential belongs in the harness.

The adapter accepts POST paths containing plain, nonempty ASCII segments
(`A-Z`, `a-z`, digits, `-._~`), excluding `.` and `..`. Queries, percent
escapes, other methods, and absolute URLs are refused. Only Content-Type and
`x-nucleus-approval-wait-seconds` request headers pass through; authentication,
cookies, and guest approval headers do not. Responses preserve status,
Content-Type, and Retry-After, and stream incrementally. Redirects are returned
without Location and never followed. There are no automatic retries.

The default total deadline is 300 seconds, including approval and response
streaming; `--timeout-seconds` accepts 1–3600. Match the harness's request
deadline to the intended approval wait. Disconnecting the client cancels the
adapter's pending request. The adapter does not authorize effects: the Unix
peer check, proxy policy, and host broker remain on every request path.
