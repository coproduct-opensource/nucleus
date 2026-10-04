//! #3130: a pod's size has a node ceiling, and every pod runs under node-derived cgroup limits.

use super::*;

fn spec(inner: &str) -> PodSpec {
    serde_json::from_str(&format!(
        r#"{{"apiVersion":"nucleus/v1","kind":"Pod","spec":{inner}}}"#
    ))
    .expect("test spec parses")
}

fn with_cgroup(file: &str, value: &str) -> PodSpec {
    spec(&format!(
        r#"{{"cgroup":{{"path":"/sys/fs/cgroup/nucleus/p","settings":[{{"file":"{file}","value":"{value}"}}]}}}}"#
    ))
}

fn value_of<'a>(cg: &'a NodeCgroup, file: &str) -> Option<&'a str> {
    cg.settings()
        .iter()
        .find(|s| s.file == file)
        .map(|s| s.value.as_str())
}

/// The finding: nothing bounded the size a spec could ask for. Each of these was admitted on main.
#[test]
fn a_size_above_the_node_ceiling_is_refused_by_name() {
    let ceilings = PodCeilings::defaults();
    for (inner, field) in [
        (r#"{"resources":{"memory_mib":1048576}}"#, "memory_mib"),
        (r#"{"resources":{"memory_mib":8193}}"#, "memory_mib"),
        (r#"{"resources":{"memory_mib":0}}"#, "memory_mib"),
        (r#"{"resources":{"cpu_cores":32}}"#, "cpu_cores"),
        (r#"{"resources":{"cpu_cores":5}}"#, "cpu_cores"),
        (r#"{"resources":{"cpu_cores":0}}"#, "cpu_cores"),
        (r#"{"resources":{"huge_pages":"2M"}}"#, "huge_pages"),
    ] {
        let e = admit(&spec(inner), &ceilings).expect_err(inner);
        assert!(e.to_string().contains(field), "{inner}: {e}");
    }
}

/// The control: up to the ceiling is admitted, the default size is admitted, and an operator who
/// raises a ceiling or offers huge pages is obeyed.
#[test]
fn a_size_within_the_ceiling_is_admitted_unchanged() {
    let ceilings = PodCeilings::defaults();
    for inner in [
        "{}",
        r#"{"resources":{}}"#,
        r#"{"resources":{"memory_mib":8192,"cpu_cores":4}}"#,
    ] {
        admit(&spec(inner), &ceilings).expect(inner);
    }
    let big = spec(r#"{"resources":{"memory_mib":65536,"cpu_cores":32,"huge_pages":"2M"}}"#);
    admit(&big, &PodCeilings::new(65536, 32, HugePagesOffer::Offered))
        .expect("the operator raised every ceiling");
    // Never clamped: the size the VM and the cgroup are built from is the size asked for.
    assert_eq!(PodSize::of(&big).memory_mib(), 65536);
    assert_eq!(PodSize::of(&big).vcpus(), 32);
}

/// The finding's second half: a spec with no `cgroup` ran with no limit at all. It now gets the
/// node's, derived from the default size.
#[test]
fn a_spec_with_no_resources_and_no_cgroup_still_gets_finite_limits() {
    let v2 = node_cgroup(&spec("{}"), CgroupVersion::V2).expect("node cgroup");
    assert_eq!(
        value_of(&v2, "memory.max"),
        Some(
            ((DEFAULT_MEMORY_MIB + VMM_OVERHEAD_MIB) * MIB)
                .to_string()
                .as_str()
        )
    );
    assert_eq!(value_of(&v2, "cpu.max"), Some("100000 100000"));
    assert_eq!(value_of(&v2, "memory.swap.max"), Some("0"));
    assert_eq!(value_of(&v2, "pids.max"), Some("64"));
    assert_eq!(
        value_of(&v2, "hugetlb.2MB.max"),
        None,
        "no huge pages asked for"
    );

    let v1 = node_cgroup(&spec("{}"), CgroupVersion::V1).expect("node cgroup");
    for file in [
        "memory.limit_in_bytes",
        "memory.memsw.limit_in_bytes",
        "cpu.cfs_period_us",
        "cpu.cfs_quota_us",
        "pids.max",
    ] {
        let v = value_of(&v1, file).unwrap_or_else(|| panic!("{file} missing: {v1:?}"));
        assert!(v.parse::<u64>().is_ok(), "{file}={v} is a finite number");
    }
    let period = v1
        .settings()
        .iter()
        .position(|s| s.file == "cpu.cfs_period_us");
    let quota = v1
        .settings()
        .iter()
        .position(|s| s.file == "cpu.cfs_quota_us");
    assert!(period < quota, "the period is written before the quota");
    assert_eq!(
        value_of(&v1, "memory.memsw.limit_in_bytes"),
        value_of(&v1, "memory.limit_in_bytes")
    );
    let memory = v1
        .settings()
        .iter()
        .position(|s| s.file == "memory.limit_in_bytes");
    let combined = v1
        .settings()
        .iter()
        .position(|s| s.file == "memory.memsw.limit_in_bytes");
    assert!(memory < combined, "memory precedes the combined limit");
}

#[test]
fn the_limits_follow_the_admitted_size() {
    let s = spec(r#"{"resources":{"memory_mib":2047,"cpu_cores":3,"huge_pages":"2M"}}"#);
    let cg = node_cgroup(&s, CgroupVersion::V2).expect("node cgroup");
    assert_eq!(
        value_of(&cg, "memory.max"),
        Some(((2047 + VMM_OVERHEAD_MIB) * MIB).to_string().as_str())
    );
    assert_eq!(value_of(&cg, "cpu.max"), Some("300000 100000"));
    // Rounded up to whole 2 MiB pages: 2048 MiB.
    assert_eq!(
        value_of(&cg, "hugetlb.2MB.max"),
        Some((2048 * MIB).to_string().as_str())
    );
    assert_eq!(cg.controllers(), ["memory", "cpu", "pids", "hugetlb"]);
}

/// A spec may lower a node limit and set other limiting files; it may not raise, lift, or reach
/// past the controllers.
#[test]
fn a_spec_cgroup_setting_may_only_lower_a_node_limit() {
    let ceilings = PodCeilings::defaults();
    let node_mem = (DEFAULT_MEMORY_MIB + VMM_OVERHEAD_MIB) * MIB;
    for (file, value) in [
        ("memory.max", "max".to_string()),
        ("memory.max", (node_mem + 1).to_string()),
        ("memory.max", "8G".to_string()),
        ("memory.limit_in_bytes", "-1".to_string()),
        ("memory.swap.max", "1".to_string()),
        ("memory.memsw.limit_in_bytes", (node_mem + 1).to_string()),
        ("cpu.max", "max 100000".to_string()),
        ("cpu.max", "200000 100000".to_string()),
        ("cpu.max", "1 0".to_string()),
        ("cpu.cfs_quota_us", "-1".to_string()),
        ("cpu.cfs_period_us", "1000".to_string()),
        ("pids.max", "max".to_string()),
        ("hugetlb.2MB.max", "1048576".to_string()),
        ("cgroup.procs", "1".to_string()),
        ("cgroup.subtree_control", "+memory".to_string()),
        ("tasks", "1".to_string()),
        ("devices.allow", "a".to_string()),
        ("release_agent", "/bin/sh".to_string()),
    ] {
        let s = with_cgroup(file, &value);
        let e = admit(&s, &ceilings).expect_err(&format!("{file}={value}"));
        assert!(
            matches!(&e, ResourceRefused::CgroupSetting { file: f, .. } if f == file),
            "{file}={value}: {e}"
        );
        assert!(
            node_cgroup(&s, CgroupVersion::V2).is_err(),
            "the renderer refuses what admit refuses: {file}={value}"
        );
    }

    for (file, value, v2) in [
        ("memory.max", "268435456", Some("268435456")),
        ("cpu.max", "50000 100000", Some("50000 100000")),
        ("pids.max", "16", Some("16")),
        ("cpu.weight", "42", Some("42")),
    ] {
        let s = with_cgroup(file, value);
        admit(&s, &ceilings).unwrap_or_else(|e| panic!("{file}={value}: {e}"));
        let cg = node_cgroup(&s, CgroupVersion::V2).expect("node cgroup");
        assert_eq!(value_of(&cg, file), v2, "{file}");
        assert_eq!(
            cg.settings().iter().filter(|s| s.file == file).count(),
            1,
            "a lowered limit replaces the node's in place"
        );
        assert!(value_of(&cg, "memory.max").is_some());
        assert!(value_of(&cg, "pids.max").is_some());
    }
}

#[test]
fn the_operator_flags_parse_with_finite_defaults() {
    #[derive(clap::Parser)]
    struct A {
        #[command(flatten)]
        c: PodCeilingArgs,
    }
    let a = <A as clap::Parser>::parse_from(["n"]);
    assert_eq!(a.c.max_pod_memory_mib, DEFAULT_MAX_POD_MEMORY_MIB);
    assert_eq!(a.c.max_pod_vcpus, DEFAULT_MAX_POD_VCPUS);
    assert_eq!(a.c.pod_huge_pages, HugePagesOffer::Refused);
    for bad in [
        ["n", "--max-pod-vcpus", "33"],
        ["n", "--max-pod-vcpus", "0"],
        ["n", "--max-pod-memory-mib", "0"],
    ] {
        assert!(<A as clap::Parser>::try_parse_from(bad).is_err(), "{bad:?}");
    }
    let a = <A as clap::Parser>::parse_from([
        "n",
        "--max-pod-memory-mib",
        "16384",
        "--pod-huge-pages",
        "offered",
    ]);
    assert_eq!(a.c.ceilings().max_memory_mib, 16384);
    assert_eq!(a.c.ceilings().huge_pages, HugePagesOffer::Offered);
}
