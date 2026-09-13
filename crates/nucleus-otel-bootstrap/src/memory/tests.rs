use super::*;

#[test]
fn discovers_every_visible_ancestor_and_respects_mount_root() {
    let paths = cgroup_paths(
        "0::/system.slice/node.service\n",
        "24 20 0:22 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n",
    )
    .unwrap();
    assert_eq!(
        paths,
        [
            "/sys/fs/cgroup/system.slice/node.service",
            "/sys/fs/cgroup/system.slice",
            "/sys/fs/cgroup"
        ]
        .map(PathBuf::from)
    );
    let paths = cgroup_paths(
        "0::/tenant/node\n",
        "24 20 0:22 /tenant /custom\\040mount rw - cgroup2 cgroup rw\n",
    )
    .unwrap();
    assert_eq!(
        paths,
        ["/custom mount/node", "/custom mount"].map(PathBuf::from)
    );
}

#[test]
fn unavailable_or_hidden_cgroup_is_not_healthy() {
    assert!(cgroup_paths("1:memory:/node", "").is_err());
    assert!(
        cgroup_paths(
            "0::/../../outside",
            "24 20 0:22 / /sys/fs/cgroup rw - cgroup2 cgroup rw"
        )
        .is_err()
    );
    assert!(
        cgroup_paths(
            "0::/other",
            "24 20 0:22 /tenant /sys/fs/cgroup rw - cgroup2 cgroup rw"
        )
        .is_err()
    );
    let mut points = Vec::new();
    sample_cgroup(
        &mut points,
        "missing",
        Path::new("/this-cgroup-does-not-exist"),
    );
    assert!(
        points
            .iter()
            .all(|p| p.kind == Kind::Success && p.value == 0)
    );
}

#[test]
fn unlimited_malformed_and_zero_are_distinct() {
    assert_eq!(number("max\n"), None);
    assert_eq!(number("broken"), None);
    assert_eq!(number("0\n"), Some(0));
    assert_eq!(field("anon 123\nfile 456\n", "anon"), Some(123));
    assert_eq!(field("anon 123\n", "file"), None);
}

#[test]
fn samples_headroom_cache_pressure_and_events_without_inventing_unlimited_bytes() {
    let dir = tempfile::tempdir().unwrap();
    for (name, text) in [
        ("memory.current", "900"),
        ("memory.max", "1000"),
        ("memory.high", "800"),
        ("memory.swap.max", "max"),
        (
            "memory.stat",
            "anon 300\nfile 600\nkernel 20\npgmajfault 9\npgscan 100\npgsteal 80\n",
        ),
        ("memory.events", "high 7\nmax 3\noom 1\noom_kill 1\n"),
        (
            "memory.pressure",
            "some avg10=1.23 avg60=0.42 avg300=0.01 total=42\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
        ),
    ] {
        fs::write(dir.path().join(name), text).unwrap();
    }
    let mut points = Vec::new();
    sample_cgroup(&mut points, "cgroup.0", dir.path());
    let value = |kind, field| {
        points
            .iter()
            .find(|p| p.kind == kind && p.field == field)
            .map(|p| p.value)
    };
    assert_eq!(value(Kind::Bytes, "memory.max.headroom"), Some(100));
    assert_eq!(value(Kind::Bytes, "memory.high.headroom"), Some(0));
    assert_eq!(value(Kind::Bytes, "memory.stat.anon"), Some(300));
    assert_eq!(value(Kind::Bytes, "memory.stat.file"), Some(600));
    assert_eq!(value(Kind::Bytes, "memory.swap.max"), None);
    assert_eq!(value(Kind::Success, "memory.swap.max"), Some(1));
    assert_eq!(value(Kind::Success, "memory.peak"), Some(0));
    assert_eq!(value(Kind::Event, "memory.events.oom_kill"), Some(1));
    assert_eq!(value(Kind::Pressure, "some.avg10"), Some(123));
    assert_eq!(value(Kind::Event, "memory.stat.pgmajfault"), Some(9));
    assert_eq!(value(Kind::Event, "memory.stat.pgscan"), Some(100));
    assert_eq!(value(Kind::Event, "memory.stat.pgsteal"), Some(80));
    fs::write(dir.path().join("memory.current"), "unreadable-value").unwrap();
    let mut points = Vec::new();
    sample_cgroup(&mut points, "cgroup.0", dir.path());
    assert!(!points.iter().any(|p| p.field.ends_with("headroom")));
}

#[test]
fn exporter_collects_registered_observations_after_instrument_handles_drop() {
    use opentelemetry_sdk::metrics::InMemoryMetricExporter;
    let exporter = InMemoryMetricExporter::default();
    let provider = SdkMeterProvider::builder()
        .with_periodic_exporter(exporter.clone())
        .build();
    register(&provider);
    provider.force_flush().unwrap();
    let exported = exporter.get_finished_metrics().unwrap();
    assert!(
        exported
            .iter()
            .flat_map(|r| r.scope_metrics())
            .flat_map(|s| s.metrics())
            .any(|m| m.name() == "nucleus.memory.observation.success")
    );
    provider.shutdown().unwrap();
}

#[test]
fn process_and_host_bytes_validate_units_overflow_and_read_failures() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("status");
    fs::write(
        &path,
        "VmRSS: 42 kB\nVmHWM: 2 MB\nVmSwap: 18446744073709551615 kB\n",
    )
    .unwrap();
    let mut points = Vec::new();
    sample_kib_fields(
        &mut points,
        "process",
        &path,
        &["VmRSS:", "VmHWM:", "VmSwap:", "RssAnon:"],
    );
    let values: Vec<_> = points.iter().filter(|p| p.kind == Kind::Bytes).collect();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0].value, 42 * 1024);
    assert_eq!(values[0].field, "VmRSS");
    assert_eq!(
        points
            .iter()
            .filter(|p| p.kind == Kind::Success && p.value == 0)
            .count(),
        3
    );
    fs::remove_file(&path).unwrap();
    points.clear();
    sample_kib_fields(&mut points, "process", &path, &["VmRSS:", "VmHWM:"]);
    assert_eq!(points.len(), 2);
    assert!(
        points
            .iter()
            .all(|p| p.kind == Kind::Success && p.value == 0)
    );
}
