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
            .with_endpoint(&endpoint)
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
        .with_resource(
            opentelemetry_sdk::Resource::builder()
                .with_service_name("nucleus-tool-proxy")
                .build(),
        )
        .build();

    let tracer = provider.tracer("nucleus-permission");

    // Install the provider globally so shutdown works
    opentelemetry::global::set_tracer_provider(provider);

    Some(tracing_opentelemetry::layer().with_tracer(tracer))
}

/// Shutdown OpenTelemetry (flush pending spans).
/// Replaces the global provider with a noop, dropping the real one which
/// triggers flush of all pending spans.
#[cfg(feature = "otel")]
#[allow(dead_code)]
pub fn shutdown_otel() {
    let noop = opentelemetry::trace::noop::NoopTracerProvider::new();
    opentelemetry::global::set_tracer_provider(noop);
}
