//! Bounded Linux resource counters. Raw kernel units are converted at export.
use std::path::Path;

use opentelemetry::{KeyValue, metrics::MeterProvider};
use opentelemetry_sdk::metrics::SdkMeterProvider;

use crate::memory::{cgroup_paths, field, read};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Time,
    Bytes,
    Events,
    Success,
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
            KeyValue::new("resource.scope", self.scope.clone()),
            KeyValue::new("resource.field", self.field.clone()),
        ]
    }
}
fn observation(out: &mut Vec<Point>, scope: &str, field: &str, kind: Kind, value: Option<u64>) {
    out.push(Point {
        kind: Kind::Success,
        scope: scope.into(),
        field: field.into(),
        value: u64::from(value.is_some()),
    });
    if let Some(value) = value {
        out.push(Point {
            kind,
            scope: scope.into(),
            field: field.into(),
            value,
        });
    }
}

pub(crate) fn register(provider: &SdkMeterProvider) {
    let meter = provider.meter("nucleus.resources");
    meter
        .f64_observable_counter("nucleus.resource.time")
        .with_unit("s")
        .with_description("Cumulative CPU or stall time; fields overlap and must not be summed")
        .with_callback(|observer| {
            for p in collect().into_iter().filter(|p| p.kind == Kind::Time) {
                observer.observe(p.value as f64 / 1_000_000.0, &p.attributes());
            }
        })
        .build();
    for (name, unit, kind) in [
        ("nucleus.resource.io.bytes", "By", Kind::Bytes),
        ("nucleus.resource.events", "{event}", Kind::Events),
    ] {
        meter
            .u64_observable_counter(name)
            .with_unit(unit)
            .with_callback(move |observer| {
                for p in collect().into_iter().filter(|p| p.kind == kind) {
                    observer.observe(p.value, &p.attributes());
                }
            })
            .build();
    }
    meter
        .u64_observable_gauge("nucleus.resource.observation.success")
        .with_unit("1")
        .with_callback(|observer| {
            for p in collect().into_iter().filter(|p| p.kind == Kind::Success) {
                observer.observe(p.value, &p.attributes());
            }
        })
        .build();
}

fn collect() -> Vec<Point> {
    let mut out = Vec::new();
    for resource in ["cpu", "memory", "io"] {
        pressure(
            &mut out,
            "host",
            resource,
            &Path::new("/proc/pressure").join(resource),
        );
    }
    let paths = read(Path::new("/proc/self/cgroup")).and_then(|groups| {
        read(Path::new("/proc/self/mountinfo")).and_then(|mounts| cgroup_paths(&groups, &mounts))
    });
    out.push(Point {
        kind: Kind::Success,
        scope: "cgroup".into(),
        field: "discovery".into(),
        value: u64::from(paths.is_ok()),
    });
    if let Ok(paths) = paths {
        for (depth, path) in paths.iter().enumerate() {
            sample_cgroup(&mut out, &format!("cgroup.{depth}"), path);
        }
    }
    out
}

fn sample_cgroup(out: &mut Vec<Point>, scope: &str, path: &Path) {
    let cpu = read(&path.join("cpu.stat"));
    for (key, kind) in [
        ("usage_usec", Kind::Time),
        ("user_usec", Kind::Time),
        ("system_usec", Kind::Time),
        ("throttled_usec", Kind::Time),
        ("nr_periods", Kind::Events),
        ("nr_throttled", Kind::Events),
    ] {
        observation(
            out,
            scope,
            &format!("cpu.{key}"),
            kind,
            cpu.as_ref().ok().and_then(|text| field(text, key)),
        );
    }
    for resource in ["cpu", "memory", "io"] {
        pressure(
            out,
            scope,
            resource,
            &path.join(format!("{resource}.pressure")),
        );
    }
    let io = read(&path.join("io.stat"));
    for (key, kind) in [
        ("rbytes", Kind::Bytes),
        ("wbytes", Kind::Bytes),
        ("dbytes", Kind::Bytes),
        ("rios", Kind::Events),
        ("wios", Kind::Events),
        ("dios", Kind::Events),
    ] {
        observation(
            out,
            scope,
            &format!("io.{key}"),
            kind,
            io.as_ref().ok().and_then(|text| io_total(text, key)),
        );
    }
}

fn pressure(out: &mut Vec<Point>, scope: &str, resource: &str, path: &Path) {
    let text = read(path);
    for class in ["some", "full"] {
        let total = text.as_ref().ok().and_then(|text| {
            text.lines().find_map(|line| {
                let mut words = line.split_whitespace();
                if words.next()? != class {
                    return None;
                }
                words
                    .find_map(|word| word.strip_prefix("total="))?
                    .parse()
                    .ok()
            })
        });
        observation(
            out,
            scope,
            &format!("{resource}.pressure.{class}"),
            Kind::Time,
            total,
        );
    }
}

// Aggregate devices to keep metric cardinality independent of device churn.
// Missing fields, malformed records or overflow invalidate the entire sum.
fn io_total(text: &str, key: &str) -> Option<u64> {
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .try_fold(0_u64, |sum, line| {
            let mut words = line.split_whitespace();
            let (major, minor) = words.next()?.split_once(':')?;
            major.parse::<u32>().ok()?;
            minor.parse::<u32>().ok()?;
            let mut values = words
                .filter_map(|word| word.split_once('='))
                .filter(|(name, _)| *name == key);
            let value = values.next()?.1.parse::<u64>().ok()?;
            if values.next().is_some() {
                return None;
            }
            sum.checked_add(value)
        })
}

#[cfg(test)]
mod tests;
