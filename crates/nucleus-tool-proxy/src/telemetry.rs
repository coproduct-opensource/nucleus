//! Permission telemetry — OTLP spans for every tool call verdict.
//!
//! Provides OTel layer setup and the `VerdictCapabilities` / `VerdictExposure`
//! structs consumed by `ToolProxyVerdictSink::record()` when it creates
//! `tracing::info_span!` entries.
//!
//! Verdict recording itself lives in `verdict_sink.rs`, which creates a
//! proper `tracing::info_span!` with duration and trace context propagation.
//! When the `otel` feature is active, `tracing-opentelemetry` exports these
//! as OTLP spans with parent-child relationships.
//!
//! Enable with `--features otel` and set `OTEL_EXPORTER_OTLP_ENDPOINT`.

/// Flattened capability levels for telemetry emission.
/// Uses u8 values (0=Never, 1=LowRisk, 2=Always) for metrics aggregation.
pub struct VerdictCapabilities {
    pub read_files: u8,
    pub write_files: u8,
    pub edit_files: u8,
    pub run_bash: u8,
    pub glob_search: u8,
    pub grep_search: u8,
    pub web_fetch: u8,
    pub web_search: u8,
    pub git_commit: u8,
    pub git_push: u8,
    pub create_pr: u8,
    pub manage_pods: u8,
}

impl From<&portcullis::CapabilityLattice> for VerdictCapabilities {
    fn from(caps: &portcullis::CapabilityLattice) -> Self {
        Self {
            read_files: caps.read_files as u8,
            write_files: caps.write_files as u8,
            edit_files: caps.edit_files as u8,
            run_bash: caps.run_bash as u8,
            glob_search: caps.glob_search as u8,
            grep_search: caps.grep_search as u8,
            web_fetch: caps.web_fetch as u8,
            web_search: caps.web_search as u8,
            git_commit: caps.git_commit as u8,
            git_push: caps.git_push as u8,
            create_pr: caps.create_pr as u8,
            manage_pods: caps.manage_pods as u8,
        }
    }
}

/// Flattened exposure state for telemetry emission.
#[derive(Default)]
pub struct VerdictExposure {
    pub private_data: bool,
    pub untrusted_content: bool,
    pub exfil_vector: bool,
    pub is_uninhabitable: bool,
}

/// Initialize OpenTelemetry tracing layer (when `otel` feature is enabled).
///
/// Call this during startup. If `OTEL_EXPORTER_OTLP_ENDPOINT` is set,
/// configures an OTLP exporter that sends traces to the specified endpoint.
/// Otherwise, falls back to stdout-only tracing.
#[cfg(feature = "otel")]
#[allow(dead_code)]
pub fn init_otel_layer() -> Option<
    tracing_opentelemetry::OpenTelemetryLayer<
        tracing_subscriber::Registry,
        opentelemetry_sdk::trace::Tracer,
    >,
> {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig as _;

    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok()?;
    let protocol =
        std::env::var("OTEL_EXPORTER_OTLP_PROTOCOL").unwrap_or_else(|_| "grpc".to_string());

    // Support both gRPC (default) and http/protobuf (Grafana Cloud).
    // Set OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf for Grafana Cloud.
    let exporter = match protocol.as_str() {
        "http/protobuf" => opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .build()
            .ok()?,
        _ => opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(&endpoint)
            .build()
            .ok()?,
    };

    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(runtime_resource())
        .build();

    let tracer = provider.tracer("nucleus-permission");

    // Install the provider globally so shutdown works
    opentelemetry::global::set_tracer_provider(provider);

    Some(tracing_opentelemetry::layer().with_tracer(tracer))
}

/// Shutdown OpenTelemetry (flush pending spans).
/// Replaces the global provider with a noop, dropping the real one which
/// triggers flush of all pending spans. Called on the tool-proxy's exit path
/// after the server future completes.
#[cfg(feature = "otel")]
pub fn shutdown_otel() {
    let noop = opentelemetry::trace::noop::NoopTracerProvider::new();
    opentelemetry::global::set_tracer_provider(noop);
}

/// Retains and flushes guest-kernel memory observations for the proxy lifetime.
#[cfg(feature = "otel")]
pub(crate) struct MemoryMetricsGuard(opentelemetry_sdk::metrics::SdkMeterProvider);

#[cfg(feature = "otel")]
impl Drop for MemoryMetricsGuard {
    fn drop(&mut self) {
        if let Err(error) = self.0.shutdown() {
            tracing::warn!(%error, "memory metrics shutdown failed");
        }
    }
}

/// Guest and local proxies observe their own kernel; this is separate from host
/// node measurements. Export configuration stays aligned with verdict tracing.
#[cfg(feature = "otel")]
pub(crate) fn init_memory_metrics() -> Result<Option<MemoryMetricsGuard>, String> {
    use opentelemetry_otlp::WithExportConfig as _;
    let Ok(endpoint) = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT") else {
        return Ok(None);
    };
    let protocol = std::env::var("OTEL_EXPORTER_OTLP_PROTOCOL").unwrap_or_else(|_| "grpc".into());
    let exporter = match protocol.as_str() {
        "http/protobuf" => opentelemetry_otlp::MetricExporter::builder()
            .with_http()
            .build(),
        _ => opentelemetry_otlp::MetricExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .build(),
    }
    .map_err(|error| format!("memory metrics exporter: {error}"))?;
    let resource = runtime_resource();
    let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(exporter)
        .with_interval(std::time::Duration::from_secs(5))
        .build();
    let provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
        .with_view(nucleus_otel_bootstrap::runtime_metrics_view)
        .with_resource(resource)
        .with_reader(reader)
        .build();
    nucleus_otel_bootstrap::register_runtime_metrics(&provider);
    Ok(Some(MemoryMetricsGuard(provider)))
}

/// Both signals share one identity for the lifetime of this process.
#[cfg(feature = "otel")]
fn runtime_resource() -> opentelemetry_sdk::Resource {
    static RESOURCE: std::sync::OnceLock<opentelemetry_sdk::Resource> = std::sync::OnceLock::new();
    RESOURCE
        .get_or_init(|| {
            nucleus_otel_bootstrap::with_instance_id(
                opentelemetry_sdk::Resource::builder()
                    .with_service_name(
                        std::env::var("OTEL_SERVICE_NAME")
                            .unwrap_or_else(|_| "nucleus-tool-proxy".into()),
                    )
                    .build(),
            )
        })
        .clone()
}

#[cfg(all(test, feature = "otel"))]
mod tests;
