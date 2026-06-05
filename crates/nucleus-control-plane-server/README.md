# nucleus-control-plane-server

The server that wraps [`nucleus-control-plane`](../nucleus-control-plane),
exposing job submission and provenance-bundle delivery over **both REST and
gRPC**.

[![docs.rs](https://img.shields.io/docsrs/nucleus-control-plane-server)](https://docs.rs/nucleus-control-plane-server)

For the MVP this is a single-process server with an in-memory job registry and a
shared JSONL lineage sink. A `MockJobRunner` is registered under the name
`"mock"` so end-to-end smoke testing works **without any vendor SDKs**.

## REST API

| Method + path | Purpose |
|---|---|
| `POST /v1/jobs` | submit a job |
| `GET /v1/jobs/{job_id}` | job status |
| `POST /v1/jobs/{job_id}/cancel` | cancel a job |
| `GET /v1/jobs/{job_id}/bundle` | fetch the provenance bundle |
| `GET /healthz` | liveness |

## gRPC API

The same `JobService` from [`nucleus-proto`](../nucleus-proto) is served
alongside REST, with a 1:1 mapping:

| gRPC | REST |
|---|---|
| `JobService.Submit` | `POST /v1/jobs` |
| `JobService.Get` | `GET /v1/jobs/{id}` |

Per the workspace convention the gRPC port is **HTTP port + 1000** (default REST
`127.0.0.1:8080`, gRPC `0.0.0.0:9080`); set `--grpc-bind ""` to disable the gRPC
surface.

## Running

```bash
nucleus-control-plane-server \
  --bind 127.0.0.1:8080 \
  --grpc-bind 0.0.0.0:9080 \
  --log ./nucleus-lineage.jsonl
```

The server publishes the issuer's JWKS so clients can fetch the out-of-band trust
anchor for `nucleus envelope-verify --trust-jwks`. Outbound job-completion
webhooks are delivered via the `webhook` module.

## Library

`build_app`, `RunnerRegistry`, `resolve_spiffe_auth`, and `build_demo_state` are
exposed from the crate root so the server can be embedded or integration-tested
in-process. Real agent runners are registered in the `RunnerRegistry` by name;
the core stays vendor-agnostic (see `nucleus-control-plane`).

## License

MIT
