# nucleus-egress-http

An unprivileged compatibility client for harnesses that speak HTTP. It runs as
part of the admitted workload at the workload UID, inside the pod's containment.
It is a separate executable and package from the privileged tool proxy.

```sh
cargo build -p nucleus-egress-http
nucleus-egress-http --door unix:///run/nucleus/workload.sock \
  --upstream model-api --listen 127.0.0.1:18081 -- /opt/harness/bin/agent task
```

The listener binds only IPv4 loopback. Its outgoing client is fixed to the
runtime-provided Unix workload door, with redirects and environment proxies
disabled. Requests select paths under one operator-registered broker upstream;
they cannot select a TCP destination or another door route. The adapter holds no
provider credentials. The door and host broker retain policy and approval
responsibility. The workload receives the actual local endpoint through
`NUCLEUS_EGRESS_HTTP_URL`.

The optional child is the declared harness launched inside the existing workload
containment. The adapter preserves its exit status and stops/reaps the direct
child on termination; the pod supervisor owns descendant containment and cleanup.
See the [proxy integration guide](../nucleus-tool-proxy/README.md) for PodSpec
wiring and approval waiting. The guest layer and release builder include this
executable explicitly alongside the proxy. When supplying custom rootfs build
inputs, set `EGRESS_HTTP_BIN` to this binary separately from `PROXY_BIN`.
