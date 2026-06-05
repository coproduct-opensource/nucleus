# nucleus-otel-bootstrap

Shared OpenTelemetry OTLP bootstrap for nucleus server binaries.

[![docs.rs](https://img.shields.io/docsrs/nucleus-otel-bootstrap)](https://docs.rs/nucleus-otel-bootstrap)

Wires `tracing` → `tracing-opentelemetry` → `opentelemetry-otlp` so every server
(verifier, control-plane, OIDC OP, …) emits trace spans to a collector when
configured, and falls through to stderr-only logging when not. One helper, called
once in `main`, so the observability setup is identical across binaries.

## Usage

```rust,ignore
use nucleus_otel_bootstrap::{init, OtelGuard};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Hold the guard for the whole process: dropping it flushes pending spans.
    let _otel: OtelGuard = init("nucleus-verifier-service")?;
    // ...your server here; spans propagate to the collector...
    Ok(())
}
```

The returned `OtelGuard` must live until the server finishes serving — dropping
it flushes spans emitted near shutdown, which would otherwise be lost.

## Activation

OTLP export turns on when `OTEL_EXPORTER_OTLP_ENDPOINT` is set (the canonical
[OTel env var][envs]); with no endpoint, the subscriber still installs
`fmt` + `EnvFilter` logging and the OTel pieces are no-ops.

| Env var | Effect |
|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | collector endpoint; **presence enables export** |
| `OTEL_SERVICE_NAME` | overrides the `service_name` argument |
| `OTEL_PROPAGATORS` | defaults to `tracecontext,baggage` (W3C) |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `grpc` (default) or `http/protobuf` |

[envs]: https://opentelemetry.io/docs/languages/sdk-configuration/general/

## Scope

This crate sets up **trace** export (spans). It is the single place server
binaries call so trace context propagates uniformly via W3C Trace Context.

## License

MIT
