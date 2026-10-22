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
