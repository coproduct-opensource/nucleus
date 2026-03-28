//! Permission telemetry — OTLP spans for every tool call verdict.
//!
//! Emits structured OpenTelemetry spans with permission state, exposure,
//! and verdict details. Plugs into any OTLP-compatible backend (Grafana,
//! Datadog, Splunk, Jaeger).
//!
//! Enable with `--features otel` and set `OTEL_EXPORTER_OTLP_ENDPOINT`.

/// Record a tool call verdict as a tracing event with structured attributes.
///
/// This function emits a tracing event (not a span) with all permission
/// context. When the `otel` feature is enabled and an OTLP exporter is
/// configured, these events flow to the telemetry backend as span events.
///
/// Without the `otel` feature, this still emits structured JSON via the
/// standard `tracing` subscriber — useful for local debugging and JSONL logs.
#[allow(dead_code, clippy::too_many_arguments)]
pub fn record_verdict(
    operation: &str,
    subject: &str,
    verdict: &str,
    deny_reason: Option<&str>,
    capabilities: &VerdictCapabilities,
    exposure: &VerdictExposure,
    lattice_checksum: &str,
    agent_identity: Option<&str>,
    session_id: &str,
    lockdown_active: bool,
) {
    tracing::info!(
        target: "nucleus_permission",
        verdict = verdict,
        operation = operation,
        subject = subject,
        deny_reason = deny_reason.unwrap_or(""),
        cap_read_files = capabilities.read_files,
        cap_write_files = capabilities.write_files,
        cap_edit_files = capabilities.edit_files,
        cap_run_bash = capabilities.run_bash,
        cap_web_fetch = capabilities.web_fetch,
        cap_web_search = capabilities.web_search,
        cap_git_push = capabilities.git_push,
        exposure_private_data = exposure.private_data,
        exposure_untrusted_content = exposure.untrusted_content,
        exposure_exfil_vector = exposure.exfil_vector,
        exposure_uninhabitable = exposure.is_uninhabitable,
        lattice_checksum = lattice_checksum,
        agent_identity = agent_identity.unwrap_or("unknown"),
        session_id = session_id,
        lockdown_active = lockdown_active,
        "permission_verdict",
    );
}

/// Flattened capability levels for telemetry emission.
/// Uses u8 values (0=Never, 1=LowRisk, 2=Always) for metrics aggregation.
#[allow(dead_code)]
pub struct VerdictCapabilities {
    pub read_files: u8,
    pub write_files: u8,
    pub edit_files: u8,
    pub run_bash: u8,
    pub web_fetch: u8,
    pub web_search: u8,
    pub git_push: u8,
}

impl From<&portcullis::CapabilityLattice> for VerdictCapabilities {
    fn from(caps: &portcullis::CapabilityLattice) -> Self {
        Self {
            read_files: caps.read_files as u8,
            write_files: caps.write_files as u8,
            edit_files: caps.edit_files as u8,
            run_bash: caps.run_bash as u8,
            web_fetch: caps.web_fetch as u8,
            web_search: caps.web_search as u8,
            git_push: caps.git_push as u8,
        }
    }
}

/// Flattened exposure state for telemetry emission.
#[allow(dead_code)]
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

    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .with_endpoint(&endpoint)
        .build()
        .ok()?;

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
/// In opentelemetry 0.31+, shutdown happens when the provider is dropped.
/// Call this to force a flush before process exit.
#[cfg(feature = "otel")]
#[allow(dead_code)]
pub fn shutdown_otel() {
    // The provider is held globally via set_tracer_provider.
    // Dropping it triggers flush. For explicit shutdown, we'd need
    // to store the provider handle — for now, this is a no-op and
    // the provider flushes on process exit.
}
