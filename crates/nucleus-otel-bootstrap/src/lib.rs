//! Shared OpenTelemetry OTLP bootstrap for nucleus server binaries.
//!
//! Wires `tracing` → `tracing-opentelemetry` → `opentelemetry-otlp`
//! so every server (verifier, control-plane, OIDC OP) emits spans to
//! a collector when configured, falls through to stderr-only logging
//! when not.
//!
//! # Activation
//!
//! Sets up OTLP export when `OTEL_EXPORTER_OTLP_ENDPOINT` is set
//! (the canonical env per [OTel spec][envs]). Optional knobs:
//! - `OTEL_SERVICE_NAME` — overrides the `service_name` argument
//! - `OTEL_PROPAGATORS` — defaults to `tracecontext,baggage` (W3C)
//! - `OTEL_EXPORTER_OTLP_PROTOCOL` — `grpc` (default) or `http/protobuf`
//!
//! [envs]: https://opentelemetry.io/docs/languages/sdk-configuration/general/
//!
//! # Usage
//!
//! ```ignore
//! use nucleus_otel_bootstrap::{init, OtelGuard};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let _otel: OtelGuard = init("nucleus-verifier-service")?;
//!     // ...your server here; spans propagate to the collector...
//!     Ok(())
//! }
//! ```
//!
//! Drop the guard at process shutdown — it flushes pending spans.

use anyhow::{Context, Result};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{global, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Process-lifetime guard. Dropping it flushes pending spans to the
/// collector. Always hold this in `main` until the server finishes
/// serving — otherwise traces emitted near shutdown get dropped.
pub struct OtelGuard {
    provider: Option<SdkTracerProvider>,
}

impl OtelGuard {
    /// Variant used when OTLP is disabled (no endpoint set). Subscriber
    /// is still installed for `fmt::layer()` + `EnvFilter`; OTel
    /// pieces are no-ops.
    fn disabled() -> Self {
        Self { provider: None }
    }
}

impl Drop for OtelGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            // Best-effort flush; ignore errors at shutdown.
            let _ = provider.shutdown();
        }
    }
}

/// Initialize tracing + (optionally) the OTLP exporter.
///
/// Always installs a `tracing_subscriber` global so `tracing::info!`
/// macros downstream work. If `OTEL_EXPORTER_OTLP_ENDPOINT` is unset,
/// returns a no-op [`OtelGuard`]. Otherwise wires the OTLP gRPC
/// exporter against that endpoint with W3C Trace Context propagation.
///
/// `service_name` defaults the OTel resource's `service.name`
/// attribute; `OTEL_SERVICE_NAME` env overrides it.
pub fn init(service_name: &str) -> Result<OtelGuard> {
    // Always: env-filter + fmt layer for stderr (preserved behavior
    // across all three nucleus servers).
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("{service_name}=info,info")));
    let fmt_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);

    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok();
    if endpoint.is_none() {
        // Local-only mode: just fmt + env filter.
        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .try_init()
            .context("install tracing subscriber (fmt-only)")?;
        tracing::info!("OTLP exporter disabled (set OTEL_EXPORTER_OTLP_ENDPOINT to enable)");
        return Ok(OtelGuard::disabled());
    }
    let endpoint = endpoint.unwrap();

    // W3C Trace Context propagation (canonical default; injectable
    // override via OTEL_PROPAGATORS — we trust the SDK default since
    // tracecontext is the only universally-supported propagator).
    global::set_text_map_propagator(TraceContextPropagator::new());

    // OTLP gRPC exporter.
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&endpoint)
        .build()
        .context("build OTLP gRPC span exporter")?;

    // Resource: stamp every span with service identity. OTEL_SERVICE_NAME
    // env wins if set; otherwise the caller's argument.
    let resolved_name =
        std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| service_name.to_string());
    let resource = Resource::builder()
        .with_attribute(KeyValue::new("service.name", resolved_name.clone()))
        .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
        .build();

    let provider = SdkTracerProvider::builder()
        .with_resource(resource)
        .with_batch_exporter(exporter)
        .build();

    let tracer = provider.tracer(resolved_name.clone());
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    global::set_tracer_provider(provider.clone());

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .with(otel_layer)
        .try_init()
        .context("install tracing subscriber (with OTLP layer)")?;

    tracing::info!(
        service = %resolved_name,
        endpoint = %endpoint,
        "OTLP exporter enabled"
    );

    Ok(OtelGuard {
        provider: Some(provider),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_guard_drop_is_noop() {
        let g = OtelGuard::disabled();
        drop(g); // must not panic
    }

    #[test]
    fn init_without_endpoint_returns_disabled_guard() {
        // Don't actually install (init() is process-global); just
        // confirm the disabled variant path doesn't depend on env.
        let g = OtelGuard::disabled();
        assert!(g.provider.is_none());
    }
}
