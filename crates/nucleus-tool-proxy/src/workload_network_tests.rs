use super::*;

fn spec() -> WorkloadSpec {
    serde_json::from_value(serde_json::json!({"command":"/bin/true"})).unwrap()
}

#[test]
fn legacy_workloads_do_not_request_or_serialize_new_namespaces() {
    let spec = spec();
    assert_eq!(spec.network_namespace, None);
    assert_eq!(spec.user_namespace_uid, None);
    let wire = serde_json::to_value(spec).unwrap();
    assert!(wire.get("network_namespace").is_none());
    assert!(wire.get("user_namespace_uid").is_none());
}

#[test]
fn unsupported_namespaces_are_refused_at_admission_not_silently_shared() {
    for mode in [
        nucleus::ContainmentMode::Unconfigured,
        nucleus::ContainmentMode::Unsandboxed,
        nucleus::ContainmentMode::HostHardened,
    ] {
        for network in [
            None,
            Some(nucleus_spec::WorkloadNetworkNamespace::PrivateLoopback),
        ] {
            let mut spec = spec();
            spec.network_namespace = network;
            spec.user_namespace_uid = Some(1001);
            let error = WorkloadLaunch::build(
                &spec,
                "http://127.0.0.1:1",
                std::path::Path::new("/tmp"),
                &[],
            )
            .admit(
                mode,
                nucleus::UnsandboxedOptIn::Explicit,
                nucleus::LandlockWaiver::Absent,
            )
            .unwrap_err();
            assert!(error.0.contains("require MicroVM"), "{error}");
        }
    }
}

#[test]
fn root_or_unmapped_user_namespace_ids_are_refused() {
    for uid in [0, u32::MAX] {
        let mut spec = spec();
        spec.user_namespace_uid = Some(uid);
        let error = WorkloadLaunch::build(
            &spec,
            "http://127.0.0.1:1",
            std::path::Path::new("/tmp"),
            &[],
        )
        .admit(
            nucleus::ContainmentMode::MicroVM,
            nucleus::UnsandboxedOptIn::Absent,
            nucleus::LandlockWaiver::Absent,
        )
        .unwrap_err();
        assert!(error.0.contains("UID must be nonzero"), "{error}");
    }
}

#[test]
fn legacy_workloads_do_not_request_or_serialize_a_workspace_bind() {
    let spec = spec();
    assert_eq!(spec.workspace_bind, None);
    assert!(
        serde_json::to_value(spec)
            .unwrap()
            .get("workspace_bind")
            .is_none()
    );
    let bound: WorkloadSpec = serde_json::from_value(serde_json::json!({
        "command": "/bin/true",
        "workspace_bind": {"source": "src", "target": "/data/work/nucleus/nucleus"}
    }))
    .unwrap();
    assert_eq!(
        bound.workspace_bind,
        Some(nucleus_spec::WorkspaceBind {
            source: "src".into(),
            target: "/data/work/nucleus/nucleus".into()
        })
    );
    // A writable or exec bind is not sayable: the field set is closed.
    assert!(
        serde_json::from_value::<WorkloadSpec>(serde_json::json!({
            "command": "/bin/true",
            "workspace_bind": {"source": "src", "target": "/data/work/x", "writable": true}
        }))
        .is_err()
    );
}

fn bind(source: &str, target: &str) -> WorkloadSpec {
    let mut spec = spec();
    spec.workspace_bind = Some(nucleus_spec::WorkspaceBind {
        source: source.into(),
        target: target.into(),
    });
    spec
}

fn admit_bind(spec: &WorkloadSpec, mode: nucleus::ContainmentMode) -> Refused {
    let work = tempfile::tempdir().unwrap();
    std::fs::create_dir(work.path().join("src")).unwrap();
    WorkloadLaunch::build(spec, "http://127.0.0.1:1", work.path(), &[])
        .admit(
            mode,
            nucleus::UnsandboxedOptIn::Explicit,
            nucleus::LandlockWaiver::Absent,
        )
        .unwrap_err()
}

#[test]
fn a_workspace_bind_is_refused_off_microvm() {
    for mode in [
        nucleus::ContainmentMode::Unconfigured,
        nucleus::ContainmentMode::Unsandboxed,
        nucleus::ContainmentMode::HostHardened,
    ] {
        let error = admit_bind(&bind("src", "/data/work/nucleus/nucleus"), mode);
        assert!(error.0.contains("require MicroVM"), "{mode:?}: {error}");
    }
}

/// Under MicroVM the bind is checked before the confinement, so each refusal
/// names the bind, on any host.
#[test]
fn a_workspace_bind_the_launcher_must_not_make_is_refused_at_admission() {
    for (source, target, why) in [
        (
            "../etc",
            "/data/work/nucleus/nucleus",
            "relative path of plain names",
        ),
        (
            "/etc",
            "/data/work/nucleus/nucleus",
            "relative path of plain names",
        ),
        ("absent", "/data/work/nucleus/nucleus", "does not exist"),
        ("src", "/etc/nucleus/x", "not strictly under /data/work"),
        ("src", "/work/x", "not strictly under /data/work"),
        ("src", "/data/work", "not strictly under /data/work"),
        ("src", "/data/work/../run", "absolute path of plain names"),
    ] {
        let error = admit_bind(&bind(source, target), nucleus::ContainmentMode::MicroVM);
        assert!(
            error.0.contains("workspace bind refused") && error.0.contains(why),
            "{source} -> {target}: {error}"
        );
    }
}
