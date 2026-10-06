# nucleus-egress-http

An unprivileged compatibility client for harnesses that speak HTTP. It runs as
part of the admitted workload at the workload UID, inside the pod's containment.
It is a separate executable and package from the privileged tool proxy.

```sh
cargo build -p nucleus-egress-http
nucleus-egress-http --upstream model-api \
  --export HARNESS_BASE_URL=model-api --placeholder HARNESS_TOKEN \
  -- /opt/harness/bin/agent task
```

Each `--upstream` must be one the pod declared: the runtime gives the workload
`NUCLEUS_EGRESS_<NAME>_URL` (a `unix://` URL into the workload door) for every
credentialed upstream the operator's registry admitted, and the adapter refuses
any other name by name before the command starts. Each upstream gets its own
IPv4 loopback listener (an ephemeral port, or `--listen` for a single upstream),
and the command is told its `http://127.0.0.1:<port>` origin under the same
`NUCLEUS_EGRESS_<NAME>_URL` key. With exactly one upstream it is also in
`NUCLEUS_EGRESS_HTTP_URL`. `--export VAR=NAME` writes it under the harness's own
variable, so nucleus never needs to know that variable's name. `--placeholder
VAR` sets a fixed non-secret value for a harness that will not start without a
credential variable. The adapter never forwards it, and the host injects the
real credential.

Only a process running as the adapter's own uid may connect. The kernel reports
each loopback socket's owner in `/proc/net/tcp`, and a peer owned by any other
uid, including root, is dropped. Without that check, the adapter would lend the
workload's door identity to anything on guest loopback. The door then checks the
adapter's uid with `SO_PEERCRED`. The adapter refuses to bind where it cannot
read `/proc/net/tcp`, which means it runs only on Linux.

The outgoing client is fixed to the runtime-provided Unix workload door, with
redirects and environment proxies disabled. Requests select paths under the
listener's own upstream. They cannot select a TCP destination, another upstream
or another door route. GET and POST are forwarded, with a query held to the rule
the host applies (`nucleus_spec::workload_egress::check_query`: bounded, and no
credential-looking parameter names). Request headers are forwarded only when
`guest_may_propose_header` admits them, which never includes `Authorization`,
`Cookie` or `Proxy-Authorization`; the host then forwards only the names the
operator's registry lists for that upstream. That is enough for a git client to
fetch and push over smart HTTP: see
[`examples/egress-git-remote`](../../examples/egress-git-remote/README.md). The adapter holds no provider credentials. The door and
host broker keep policy, metering and approval responsibility.

The optional child is the declared harness, launched inside the existing
workload containment. The adapter preserves its exit status and stops and reaps
the direct child on termination. The pod supervisor owns descendant containment
and cleanup. See the [proxy integration guide](../nucleus-tool-proxy/README.md)
for PodSpec wiring and approval waiting. The guest layer and release builder
include this executable explicitly alongside the proxy. When supplying custom
rootfs build inputs, set `EGRESS_HTTP_BIN` to this binary separately from
`PROXY_BIN`.
