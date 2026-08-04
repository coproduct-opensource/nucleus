//! Per-stage timing for pod creation.
//!
//! `nucleus verify --tier2` reports one number ("pod created in N ms") that is
//! wall clock around a single blocking POST. This module decomposes it: every
//! boot-path segment owner carries an `#[instrument]` span with a
//! `boot.stage` field, and [`BootTraceLayer`] records each span's
//! open→close duration, grouped under the root `pod.create` span
//! (`create_pod_internal`).
//!
//! When the root closes, the layer emits a single `boot_trace` event with the
//! per-stage breakdown AND the reconciliation figure:
//! `unaccounted = wall - sum(top-level stages)`. A large `unaccounted` is a
//! finding (unmeasured work), not an error to hide — a profiler that always
//! sums to 100% has stopped being able to say it missed something. Stages
//! nested inside another stage are shown prefixed `+` and excluded from the
//! sum so nothing is counted twice.
//!
//! Spans and the breakdown event are emitted at INFO: the node must run with
//! `RUST_LOG=info` (or a `boot_trace=info` directive) for any of this to
//! appear.

use std::path::Path;
use std::time::Instant;

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::Subscriber;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

/// Field name every boot-stage span carries. `#[instrument]` call sites must
/// spell this literally (`fields(boot.stage = "..."`)); the layer
/// matches on it.
const STAGE_FIELD: &str = "boot.stage";

/// Stage name of the root span (`create_pod_internal`). Its wall clock is what
/// the per-stage sum reconciles against.
const ROOT_STAGE: &str = "pod.create";

/// Installs the node's global subscriber: JSON fmt to stdout (the format the
/// node has always logged; anything parsing its logs depends on it), env
/// filter, [`BootTraceLayer`], and — with the `otel` feature and
/// `OTEL_EXPORTER_OTLP_ENDPOINT` set — the OTLP export layer. With the
/// endpoint unset the node makes no outbound telemetry connection at all.
pub(crate) fn init_tracing() -> Result<TracingGuard, String> {
    let filter = tracing_subscriber::EnvFilter::from_default_env();
    let fmt = tracing_subscriber::fmt::layer().json();
    let stack = tracing_subscriber::registry()
        .with(filter)
        .with(fmt)
        .with(BootTraceLayer);
    #[cfg(feature = "otel")]
    {
        let otel = nucleus_otel_bootstrap::otel_layer("nucleus-node")
            .map_err(|e| format!("OTLP exporter init failed: {e}"))?;
        match otel {
            Some((layer, guard)) => {
                stack
                    .with(layer)
                    .try_init()
                    .map_err(|e| format!("tracing init failed: {e}"))?;
                tracing::info!("OTLP exporter enabled");
                Ok(TracingGuard { _otel: Some(guard) })
            }
            None => {
                stack
                    .try_init()
                    .map_err(|e| format!("tracing init failed: {e}"))?;
                Ok(TracingGuard { _otel: None })
            }
        }
    }
    #[cfg(not(feature = "otel"))]
    {
        stack
            .try_init()
            .map_err(|e| format!("tracing init failed: {e}"))?;
        Ok(TracingGuard {})
    }
}

/// Held by `main` for the process lifetime; dropping it flushes pending OTLP
/// spans when export is active.
pub(crate) struct TracingGuard {
    #[cfg(feature = "otel")]
    _otel: Option<nucleus_otel_bootstrap::OtelGuard>,
}

/// Times a synchronous, non-yielding closure as a boot stage. For call sites
/// where the stage is an expression rather than a function (`command.spawn()`)
/// and an `#[instrument]` attribute has nothing to attach to. Must not be
/// given anything that awaits — the span guard is held across the call.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn time_sync<T>(stage: &'static str, f: impl FnOnce() -> T) -> T {
    let span = tracing::info_span!("boot_stage", boot.stage = stage);
    let _guard = span.enter();
    f()
}

/// One closed stage span, recorded under its `pod.create` root.
#[derive(Debug, Clone)]
struct StageRecord {
    stage: String,
    /// Milliseconds from root-span open to this span's open.
    offset_ms: u128,
    dur_ms: u128,
    /// True when another stage span (besides the root) encloses this one;
    /// nested stages are excluded from the reconciliation sum.
    nested: bool,
}

/// Span-extension marker for any boot-stage span.
struct StageStart {
    stage: String,
    started: Instant,
    offset_ms: Option<u128>,
}

/// Span-extension accumulator, present only on the root span.
#[derive(Default)]
struct RootAgg {
    pod_id: Option<String>,
    records: Vec<StageRecord>,
}

/// Records boot-stage span durations and emits the breakdown when the root
/// `pod.create` span closes. Spans without the `boot.stage` field are
/// ignored entirely.
pub(crate) struct BootTraceLayer;

impl<S> Layer<S> for BootTraceLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut visitor = StageVisitor::default();
        attrs.record(&mut visitor);
        let Some(stage) = visitor.stage else { return };
        let Some(span) = ctx.span(id) else { return };

        let mut offset_ms = None;
        if stage != ROOT_STAGE {
            for ancestor in span.scope().skip(1) {
                let ext = ancestor.extensions();
                if ext.get::<RootAgg>().is_some() {
                    if let Some(root_start) = ext.get::<StageStart>() {
                        offset_ms = Some(root_start.started.elapsed().as_millis());
                    }
                    break;
                }
            }
        }

        let mut ext = span.extensions_mut();
        if stage == ROOT_STAGE {
            ext.insert(RootAgg::default());
        }
        ext.insert(StageStart {
            stage,
            started: Instant::now(),
            offset_ms,
        });
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        // The root span declares `pod_id` as an empty field and records it
        // after the Uuid exists; pick it up for the breakdown event.
        let mut visitor = PodIdVisitor::default();
        values.record(&mut visitor);
        let Some(pod_id) = visitor.pod_id else { return };
        let Some(span) = ctx.span(id) else { return };
        let mut ext = span.extensions_mut();
        if let Some(agg) = ext.get_mut::<RootAgg>() {
            agg.pod_id = Some(pod_id);
        }
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else { return };
        let (stage, dur_ms, offset_ms) = {
            let ext = span.extensions();
            match ext.get::<StageStart>() {
                Some(s) => (
                    s.stage.clone(),
                    s.started.elapsed().as_millis(),
                    s.offset_ms,
                ),
                None => return,
            }
        };

        let is_root = span.extensions().get::<RootAgg>().is_some();
        if is_root {
            // Take the accumulator out (extension locks dropped) before
            // emitting, so the event dispatch never re-enters a held lock.
            let agg = span
                .extensions_mut()
                .remove::<RootAgg>()
                .unwrap_or_default();
            let (measured_ms, unaccounted_ms, stages) = summarize(&agg.records, dur_ms);
            tracing::info!(
                target: "boot_trace",
                pod_id = %agg.pod_id.unwrap_or_default(),
                wall_ms = dur_ms as u64,
                measured_ms = measured_ms as u64,
                unaccounted_ms,
                stages = %stages,
                "pod boot breakdown (unaccounted = wall - sum of top-level stages; \
                 a large value means unmeasured work, which is a finding)"
            );
            return;
        }

        let mut nested = false;
        for ancestor in span.scope().skip(1) {
            let is_ancestor_root = ancestor.extensions().get::<RootAgg>().is_some();
            if is_ancestor_root {
                let mut ext = ancestor.extensions_mut();
                if let Some(agg) = ext.get_mut::<RootAgg>() {
                    agg.records.push(StageRecord {
                        stage,
                        offset_ms: offset_ms.unwrap_or(0),
                        dur_ms,
                        nested,
                    });
                }
                return;
            }
            if ancestor.extensions().get::<StageStart>().is_some() {
                nested = true;
            }
        }
        // No root ancestor: the span ran outside a pod.create (e.g. a health
        // probe of an existing pod). Nothing to attribute it to; drop it.
    }
}

/// Pure summary: (sum of top-level stage durations, wall − sum, rendered
/// stage list ordered by start offset, nested stages prefixed `+`).
fn summarize(records: &[StageRecord], wall_ms: u128) -> (u128, i64, String) {
    let mut ordered: Vec<&StageRecord> = records.iter().collect();
    ordered.sort_by_key(|r| r.offset_ms);
    let measured: u128 = ordered.iter().filter(|r| !r.nested).map(|r| r.dur_ms).sum();
    let unaccounted = wall_ms as i64 - measured as i64;
    let stages = ordered
        .iter()
        .map(|r| {
            format!(
                "{}{}={}ms@+{}ms",
                if r.nested { "+" } else { "" },
                r.stage,
                r.dur_ms,
                r.offset_ms
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    (measured, unaccounted, stages)
}

#[derive(Default)]
struct StageVisitor {
    stage: Option<String>,
}

impl Visit for StageVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == STAGE_FIELD {
            self.stage = Some(value.to_string());
        }
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == STAGE_FIELD {
            self.stage = Some(format!("{value:?}").trim_matches('"').to_string());
        }
    }
}

#[derive(Default)]
struct PodIdVisitor {
    pod_id: Option<String>,
}

impl Visit for PodIdVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "pod_id" {
            self.pod_id = Some(value.to_string());
        }
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "pod_id" {
            self.pod_id = Some(format!("{value:?}").trim_matches('"').to_string());
        }
    }
}

/// Console-log markers whose position in the captured `firecracker.log` dates
/// the guest's boot milestones. Kernel lines carry `[ N.NNNNNN]` timestamps;
/// guest-init's own stderr lines do not, so those are reported as `>=t` lower
/// bounds from the last kernel timestamp seen before them.
const GUEST_MARKERS: &[&str] = &[
    "Run /init as init process",
    "fetched identity",
    "failed to fetch identity",
    "fetched broker capability over vsock",
    "no broker capability over vsock",
    "fetched session task token over vsock",
    "failed to fetch session task token over vsock",
    "fetched DLC admission provisioning",
    "failed to fetch DLC admission provisioning",
];

/// Emits the guest-side boot timeline parsed from the pod's console log.
/// Best-effort by design: a missing or unparseable log must never affect the
/// launch — the pod is already up when this runs.
pub(crate) async fn log_guest_console_timeline(log_path: &Path) {
    let console = match tokio::fs::read_to_string(log_path).await {
        Ok(c) => c,
        Err(err) => {
            tracing::debug!(target: "boot_trace", %err, "no guest console log to parse");
            return;
        }
    };
    let timeline = guest_timeline(&console);
    if timeline.is_empty() {
        return;
    }
    tracing::info!(
        target: "boot_trace",
        timeline = %timeline,
        "guest console timeline (kernel-clock seconds; >=t marks an untimestamped \
         guest-init line dated by the last kernel timestamp before it)"
    );
}

/// Pure parse of a captured console log into an ordered timeline string.
fn guest_timeline(console: &str) -> String {
    let mut out = Vec::new();
    let mut first_ts: Option<f64> = None;
    let mut last_ts: Option<f64> = None;
    for line in console.lines() {
        let ts = parse_kernel_ts(line);
        if let Some(t) = ts {
            if first_ts.is_none() {
                first_ts = Some(t);
                out.push(format!("kernel_first@{t:.3}"));
            }
            last_ts = Some(t);
        }
        for marker in GUEST_MARKERS {
            if line.contains(marker) {
                match ts {
                    Some(t) => out.push(format!("'{marker}'@{t:.3}")),
                    None => out.push(format!("'{marker}'@>={:.3}", last_ts.unwrap_or(0.0))),
                }
            }
        }
    }
    if let Some(t) = last_ts {
        out.push(format!("kernel_last@{t:.3}"));
    }
    out.join(" | ")
}

/// Parses the leading `[ N.NNNNNN]` kernel timestamp, if the line has one.
fn parse_kernel_ts(line: &str) -> Option<f64> {
    let rest = line.strip_prefix('[')?;
    let end = rest.find(']')?;
    rest[..end].trim().parse::<f64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(stage: &str, offset_ms: u128, dur_ms: u128, nested: bool) -> StageRecord {
        StageRecord {
            stage: stage.to_string(),
            offset_ms,
            dur_ms,
            nested,
        }
    }

    #[test]
    fn summarize_sums_top_level_and_reports_gap() {
        let records = vec![
            rec("prepare_jail", 10, 200, false),
            rec("attestation.hash", 300, 3000, false),
            rec("proxy.health_wait", 3400, 4000, false),
        ];
        let (measured, unaccounted, stages) = summarize(&records, 8000);
        assert_eq!(measured, 7200);
        assert_eq!(unaccounted, 800);
        assert!(stages.starts_with("prepare_jail=200ms@+10ms"));
    }

    #[test]
    fn summarize_excludes_nested_stages_from_the_sum() {
        let records = vec![
            rec("net.setup", 0, 500, false),
            rec("net.dns_proxy", 100, 300, true),
        ];
        let (measured, unaccounted, stages) = summarize(&records, 600);
        assert_eq!(measured, 500, "nested stage must not double-count");
        assert_eq!(unaccounted, 100);
        assert!(stages.contains("+net.dns_proxy=300ms"));
    }

    #[test]
    fn summarize_reports_negative_unaccounted_rather_than_hiding_it() {
        // Overlapping stages summing past wall clock must show up as a
        // negative gap, not saturate to zero — either way the instrument has
        // to say something is off.
        let records = vec![rec("a", 0, 500, false), rec("b", 0, 500, false)];
        let (_, unaccounted, _) = summarize(&records, 700);
        assert_eq!(unaccounted, -300);
    }

    #[test]
    fn summarize_orders_stages_by_start_offset() {
        let records = vec![rec("late", 500, 10, false), rec("early", 5, 10, false)];
        let (_, _, stages) = summarize(&records, 600);
        let early = stages.find("early").unwrap();
        let late = stages.find("late").unwrap();
        assert!(early < late);
    }

    #[test]
    fn kernel_timestamp_parses_and_rejects() {
        assert_eq!(
            parse_kernel_ts("[    0.123456] Linux version"),
            Some(0.123456)
        );
        assert_eq!(parse_kernel_ts("[   12.5] foo"), Some(12.5));
        assert_eq!(parse_kernel_ts("[WARN] not a timestamp"), None);
        assert_eq!(parse_kernel_ts("no brackets"), None);
    }

    #[test]
    fn guest_timeline_brackets_untimestamped_markers() {
        let console = "\
[    0.000000] Linux version 6.1\n\
[    0.800000] Run /init as init process\n\
fetched identity: spiffe://example/pod\n\
[    1.200000] random: crng init done\n\
fetched session task token over vsock\n";
        let tl = guest_timeline(console);
        assert!(tl.contains("kernel_first@0.000"));
        assert!(tl.contains("'Run /init as init process'@0.800"));
        // Marker after the 0.8 kernel line but before the 1.2 one.
        assert!(tl.contains("'fetched identity'@>=0.800"));
        assert!(tl.contains("'fetched session task token over vsock'@>=1.200"));
        assert!(tl.contains("kernel_last@1.200"));
    }

    #[test]
    fn guest_timeline_is_empty_for_a_log_with_nothing_recognizable() {
        assert!(guest_timeline("plain firecracker chatter\n").is_empty());
    }
}
