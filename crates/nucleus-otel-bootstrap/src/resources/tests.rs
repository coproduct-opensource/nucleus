use super::*;

#[test]
fn io_aggregation_rejects_partial_corrupt_or_overflowed_observations() {
    assert_eq!(
        io_total("8:0 rbytes=10\n8:16 rbytes=32\n", "rbytes"),
        Some(42)
    );
    assert_eq!(io_total("", "rbytes"), Some(0));
    for text in [
        "8:0 wbytes=10",
        "8:0 rbytes=bad",
        "broken rbytes=10",
        "8:0 rbytes=10 rbytes=20",
        "8:0 rbytes=18446744073709551615\n8:1 rbytes=1",
    ] {
        assert_eq!(io_total(text, "rbytes"), None, "{text}");
    }
}

#[test]
fn stalled_throttled_and_io_bound_workloads_are_distinguishable() {
    let dir = tempfile::tempdir().unwrap();
    for (file, text) in [
        (
            "cpu.stat",
            "usage_usec 2000000\nuser_usec 1500000\nsystem_usec 500000\nthrottled_usec 250000\nnr_periods 20\nnr_throttled 3\n",
        ),
        (
            "cpu.pressure",
            "some avg10=1.00 total=10000\nfull avg10=0.00 total=0\n",
        ),
        (
            "io.pressure",
            "some avg10=9.00 total=90000\nfull avg10=4.00 total=40000\n",
        ),
        (
            "io.stat",
            "8:0 rbytes=4096 wbytes=10 rios=1 wios=1 dbytes=0 dios=0\n8:1 rbytes=2048 wbytes=20 rios=2 wios=2 dbytes=0 dios=0\n",
        ),
    ] {
        std::fs::write(dir.path().join(file), text).unwrap();
    }
    let mut points = Vec::new();
    sample_cgroup(&mut points, "cgroup.0", dir.path());
    let value = |kind, key| {
        points
            .iter()
            .find(|p| p.kind == kind && p.field == key)
            .map(|p| p.value)
    };
    assert_eq!(value(Kind::Time, "cpu.usage_usec"), Some(2_000_000));
    assert_eq!(value(Kind::Time, "cpu.throttled_usec"), Some(250_000));
    assert_eq!(value(Kind::Events, "cpu.nr_throttled"), Some(3));
    assert_eq!(value(Kind::Time, "cpu.pressure.some"), Some(10_000));
    assert_eq!(value(Kind::Time, "io.pressure.full"), Some(40_000));
    assert_eq!(value(Kind::Bytes, "io.rbytes"), Some(6144));
    assert_eq!(value(Kind::Events, "io.rios"), Some(3));
    assert_eq!(value(Kind::Time, "memory.pressure.some"), None);
    assert_eq!(value(Kind::Success, "memory.pressure.some"), Some(0));
    std::fs::remove_file(dir.path().join("cpu.stat")).unwrap();
    let mut missing = Vec::new();
    sample_cgroup(&mut missing, "cgroup.0", dir.path());
    assert!(
        !missing
            .iter()
            .any(|p| p.kind == Kind::Time && p.field == "cpu.usage_usec")
    );
    assert!(
        missing
            .iter()
            .any(|p| p.kind == Kind::Success && p.field == "cpu.usage_usec" && p.value == 0)
    );
}

#[test]
fn malformed_pressure_is_unknown_not_zero() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pressure");
    std::fs::write(&path, "some total=NaN\nfull total=-1\n").unwrap();
    let mut points = Vec::new();
    pressure(&mut points, "host", "cpu", &path);
    assert_eq!(points.len(), 2);
    assert!(
        points
            .iter()
            .all(|p| p.kind == Kind::Success && p.value == 0)
    );
}

#[test]
fn bounded_resource_series_fit_the_sdk_view() {
    let dir = tempfile::tempdir().unwrap();
    let mut points = Vec::new();
    for depth in 0..64 {
        sample_cgroup(&mut points, &format!("cgroup.{depth}"), dir.path());
    }
    assert!(points.len() + 7 < 4096);
    assert!(points.iter().all(|p| p.kind == Kind::Success));
}
