//! Read-only Linux memory telemetry. Missing measurements are never zero (ADR A-2).
use std::{
    fs, io,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use opentelemetry::{KeyValue, metrics::MeterProvider};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    Resource,
    metrics::{PeriodicReader, SdkMeterProvider},
};

pub(crate) fn provider(endpoint: &str, resource: Resource) -> Result<SdkMeterProvider> {
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()
        .context("build OTLP metrics exporter")?;
    let reader = PeriodicReader::builder(exporter)
        .with_interval(Duration::from_secs(5))
        .build();
    let provider = SdkMeterProvider::builder()
        .with_view(crate::runtime_metrics_view)
        .with_resource(resource)
        .with_reader(reader)
        .build();
    register(&provider);
    crate::resources::register(&provider);
    Ok(provider)
}

pub(crate) fn register(provider: &SdkMeterProvider) {
    let meter = provider.meter("nucleus.memory");
    // Observable instruments avoid retaining a stale last value after a read failure.
    for (name, unit, kind) in [
        ("nucleus.memory.bytes", "By", Kind::Bytes),
        ("nucleus.memory.observation.success", "1", Kind::Success),
    ] {
        meter
            .u64_observable_gauge(name)
            .with_unit(unit)
            .with_callback(move |observer| {
                for point in collect().into_iter().filter(|p| p.kind == kind) {
                    observer.observe(point.value, &point.attributes());
                }
            })
            .build();
    }
    meter
        .f64_observable_gauge("nucleus.memory.pressure")
        .with_unit("%")
        .with_callback(|observer| {
            for point in collect().into_iter().filter(|p| p.kind == Kind::Pressure) {
                #[expect(clippy::cast_precision_loss, reason = "OpenTelemetry observes f64; these come from integer counters (microseconds, \
              centi-percent) whose magnitudes are far below 2^53, so the conversion is exact in \
              the range that occurs. An #[expect] rather than an #[allow] so it stops compiling \
              if the source type ever changes out from under the bound.")]
                observer.observe(point.value as f64 / 100.0, &point.attributes());
            }
        })
        .build();
    meter
        .u64_observable_counter("nucleus.memory.events")
        .with_unit("{event}")
        .with_callback(|observer| {
            for point in collect().into_iter().filter(|p| p.kind == Kind::Event) {
                observer.observe(point.value, &point.attributes());
            }
        })
        .build();
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Bytes,
    Pressure,
    Success,
    Event,
}
struct Point {
    kind: Kind,
    scope: String,
    field: String,
    value: u64,
}
impl Point {
    fn attributes(&self) -> [KeyValue; 2] {
        [
            KeyValue::new("memory.scope", self.scope.clone()),
            KeyValue::new("memory.field", self.field.clone()),
        ]
    }
}
fn push(out: &mut Vec<Point>, kind: Kind, scope: &str, field: &str, value: u64) {
    out.push(Point {
        kind,
        scope: scope.into(),
        field: field.into(),
        value,
    });
}
pub(super) fn read(path: &Path) -> io::Result<String> {
    use io::Read;
    let mut text = String::new();
    // procfs reports zero st_size; bound actual reads rather than trusting metadata.
    fs::File::open(path)?
        .take(65537)
        .read_to_string(&mut text)?;
    if text.len() > 65536 {
        return Err(io::Error::other("memory telemetry file exceeds 64 KiB"));
    }
    Ok(text)
}
fn number(text: &str) -> Option<u64> {
    text.trim().parse().ok()
}
pub(super) fn field(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let mut words = line.split_whitespace();
        (words.next()? == key)
            .then(|| words.next().and_then(number))
            .flatten()
    })
}
fn sample_kib_fields(out: &mut Vec<Point>, scope: &str, path: &Path, keys: &[&str]) {
    let text = read(path);
    for key in keys {
        let value = text.as_ref().ok().and_then(|s| {
            s.lines().find_map(|line| {
                let mut words = line.split_whitespace();
                if words.next()? != *key {
                    return None;
                }
                let value = number(words.next()?)?;
                (words.next()? == "kB")
                    .then(|| value.checked_mul(1024))
                    .flatten()
            })
        });
        let field = key.trim_end_matches(':');
        push(out, Kind::Success, scope, field, u64::from(value.is_some()));
        if let Some(value) = value {
            push(out, Kind::Bytes, scope, field, value);
        }
    }
}
fn collect() -> Vec<Point> {
    let mut out = Vec::new();
    sample_kib_fields(
        &mut out,
        "host",
        Path::new("/proc/meminfo"),
        &["MemTotal:", "MemAvailable:", "SwapTotal:", "SwapFree:"],
    );
    sample_kib_fields(
        &mut out,
        "process",
        Path::new("/proc/self/status"),
        &[
            "VmRSS:",
            "VmHWM:",
            "RssAnon:",
            "RssFile:",
            "RssShmem:",
            "VmSwap:",
        ],
    );
    pressure(&mut out, "host", Path::new("/proc/pressure/memory"));
    let paths = read(Path::new("/proc/self/cgroup")).and_then(|groups| {
        read(Path::new("/proc/self/mountinfo")).and_then(|mounts| cgroup_paths(&groups, &mounts))
    });
    match paths {
        Ok(paths) => {
            push(&mut out, Kind::Success, "cgroup", "discovery", 1);
            for (depth, path) in paths.iter().enumerate() {
                sample_cgroup(&mut out, &format!("cgroup.{depth}"), path);
            }
        }
        Err(_) => push(&mut out, Kind::Success, "cgroup", "discovery", 0),
    }
    out
}
fn sample_cgroup(out: &mut Vec<Point>, scope: &str, path: &Path) {
    let current = read(&path.join("memory.current"))
        .ok()
        .and_then(|s| number(&s));
    for key in [
        "memory.current",
        "memory.peak",
        "memory.max",
        "memory.high",
        "memory.swap.current",
        "memory.swap.max",
    ] {
        let text = read(&path.join(key));
        let parsed = text.as_ref().ok().and_then(|s| number(s));
        let unlimited = matches!(key, "memory.max" | "memory.high" | "memory.swap.max")
            && text.as_ref().is_ok_and(|s| s.trim() == "max");
        push(
            out,
            Kind::Success,
            scope,
            key,
            u64::from(parsed.is_some() || unlimited),
        );
        if let Some(value) = parsed {
            push(out, Kind::Bytes, scope, key, value);
            if matches!(key, "memory.max" | "memory.high") {
                if let Some(current) = current {
                    push(
                        out,
                        Kind::Bytes,
                        scope,
                        &format!("{key}.headroom"),
                        value.saturating_sub(current),
                    );
                }
            }
        }
    }
    for (file, keys, kind) in [
        (
            "memory.stat",
            &[
                "pgfault",
                "pgmajfault",
                "pgscan",
                "pgsteal",
                "workingset_refault_anon",
                "workingset_refault_file",
                "workingset_activate_anon",
                "workingset_activate_file",
                "workingset_restore_anon",
                "workingset_restore_file",
            ][..],
            Kind::Event,
        ),
        (
            "memory.stat",
            &[
                "anon",
                "file",
                "kernel",
                "shmem",
                "slab",
                "inactive_file",
                "active_file",
                "file_mapped",
                "file_dirty",
                "file_writeback",
            ][..],
            Kind::Bytes,
        ),
        (
            "memory.events",
            &["low", "high", "max", "oom", "oom_kill", "oom_group_kill"][..],
            Kind::Event,
        ),
    ] {
        let text = read(&path.join(file));
        for key in keys {
            let value = text.as_ref().ok().and_then(|s| field(s, key));
            push(
                out,
                Kind::Success,
                scope,
                &format!("{file}.{key}"),
                u64::from(value.is_some()),
            );
            if let Some(value) = value {
                push(out, kind, scope, &format!("{file}.{key}"), value);
            }
        }
    }
    pressure(out, scope, &path.join("memory.pressure"));
}
fn pressure(out: &mut Vec<Point>, scope: &str, path: &Path) {
    let text = read(path);
    for class in ["some", "full"] {
        for window in ["avg10", "avg60", "avg300"] {
            let value = text
                .as_ref()
                .ok()
                .and_then(|s| s.lines().find(|l| l.starts_with(&format!("{class} "))))
                .and_then(|line| {
                    line.split_whitespace()
                        .find_map(|word| word.strip_prefix(&format!("{window}=")))
                })
                .and_then(|s| s.parse::<f64>().ok())
                .filter(|v| v.is_finite() && (0.0..=100.0).contains(v));
            let key = format!("{class}.{window}");
            push(out, Kind::Success, scope, &key, u64::from(value.is_some()));
            // Basis points preserve sub-percent pressure without float gauges.
            if let Some(value) = value {
                #[expect(
                    clippy::cast_possible_truncation,
                    clippy::cast_sign_loss,
                    reason = "a PSI percentage is 0..=100 and rounded before conversion, so it \
                              neither truncates meaningfully nor goes negative. An #[expect] \
                              rather than an #[allow] so it stops compiling if the source ever \
                              stops being a bounded percentage."
                )]
                let centi_percent = (value * 100.0).round() as u64;
                push(out, Kind::Pressure, scope, &key, centi_percent);
            }
        }
    }
}
fn unescape(text: &str) -> String {
    text.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}
pub(super) fn cgroup_paths(groups: &str, mounts: &str) -> io::Result<Vec<PathBuf>> {
    let group = groups
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .ok_or_else(|| io::Error::other("no cgroup v2 membership"))?;
    if Path::new(group)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(io::Error::other("cgroup path outside visible namespace"));
    }
    for line in mounts.lines() {
        let Some((before, after)) = line.split_once(" - ") else {
            continue;
        };
        if after.split_whitespace().next() != Some("cgroup2") {
            continue;
        }
        let fields: Vec<_> = before.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        let root = PathBuf::from(unescape(fields[3]));
        let mount = PathBuf::from(unescape(fields[4]));
        let Ok(relative) = Path::new(group).strip_prefix(&root) else {
            continue;
        };
        let leaf = mount.join(relative);
        let mut paths = Vec::new();
        for path in leaf.ancestors() {
            paths.push(path.to_path_buf());
            if path == mount {
                return Ok(paths);
            }
            if paths.len() >= 64 {
                return Err(io::Error::other("cgroup ancestry exceeds telemetry bound"));
            }
        }
    }
    Err(io::Error::other(
        "no visible cgroup v2 mount for membership",
    ))
}

#[cfg(test)]
mod tests;
