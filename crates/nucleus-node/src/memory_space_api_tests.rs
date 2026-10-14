use super::*;

fn auth(id: &str) -> AuthContext {
    AuthContext::from_spiffe(id.into())
}

#[test]
fn only_a_tenant_root_declares_and_only_for_itself() {
    let root = "spiffe://test.local/ns/system/sa/tenant-a";
    assert_eq!(
        tenant_root(&CallerScope::NodeWide, &auth(root)).unwrap(),
        TenantKey::of(root)
    );
    let federated = "spiffe://tenant-b.example/agent";
    assert_eq!(
        tenant_root(
            &CallerScope::Tenant("tenant-b.example".into()),
            &auth(federated)
        )
        .unwrap(),
        TenantKey::of(federated)
    );
    assert!(tenant_root(&CallerScope::Pod(Uuid::new_v4()), &auth(root)).is_err());
    assert!(tenant_root(&CallerScope::CiPrincipal(root.into()), &auth(root)).is_err());
}

/// Every field of a policy request is required, and none of them names a tenant: no default
/// audience, mode, view or expiry, and no way to ask for the legacy audience.
#[test]
fn a_policy_request_names_no_tenant_and_has_no_defaults() {
    let ok = r#"{"audience":{"kind":"workspace","selector":{"team":"a"}},"mode":"read_propose","view":{"schema":["string"],"ceiling":"internal"},"may_publish":true,"allocation_bytes":4096,"expiry":{"kind":"until_revoked"},"authority":{"kind":"tenant_root"}}"#;
    assert!(serde_json::from_str::<CreatePolicy>(ok).is_ok());
    let with_tenant = ok.replacen('{', r#"{"tenant":"x","#, 1);
    assert!(serde_json::from_str::<CreatePolicy>(&with_tenant).is_err());
    let no_expiry = ok.replace(r#","expiry":{"kind":"until_revoked"}"#, "");
    assert!(serde_json::from_str::<CreatePolicy>(&no_expiry).is_err());
    let no_view = ok.replace(r#""view":{"schema":["string"],"ceiling":"internal"},"#, "");
    assert!(serde_json::from_str::<CreatePolicy>(&no_view).is_err());
    let legacy = ok.replace(
        r#"{"kind":"workspace","selector":{"team":"a"}}"#,
        r#"{"kind":"tenant_all_legacy"}"#,
    );
    assert!(serde_json::from_str::<CreatePolicy>(&legacy).is_err());
    let decision = ok.replace(
        r#"{"kind":"tenant_root"}"#,
        &format!(r#"{{"kind":"decision","id":"{}"}}"#, "a".repeat(64)),
    );
    assert!(serde_json::from_str::<CreatePolicy>(&decision).is_ok());
}

#[test]
fn every_memory_route_is_an_operation_and_no_pod_declares_a_space() {
    use crate::auth::Operation;
    use axum::http::Method;
    let (policy, binding) = (Uuid::new_v4(), Uuid::new_v4());
    for (method, path, op) in [
        (
            Method::POST,
            "/v1/memory/spaces".to_owned(),
            Operation::MemorySpaces,
        ),
        (
            Method::GET,
            "/v1/memory/spaces".to_owned(),
            Operation::MemorySpaces,
        ),
        (
            Method::POST,
            "/v1/memory/spaces/notes/revoke".to_owned(),
            Operation::MemorySpaces,
        ),
        (
            Method::POST,
            format!("/v1/memory/spaces/notes/policies/{policy}/revoke"),
            Operation::MemorySpaces,
        ),
        (
            Method::POST,
            "/v1/memory/spaces/notes/policies".to_owned(),
            Operation::MemoryBinding,
        ),
        (
            Method::POST,
            format!("/v1/memory/bindings/{binding}/publish"),
            Operation::MemoryBinding,
        ),
    ] {
        assert_eq!(
            crate::auth::operation_for_route(&method, &path),
            Some(op),
            "{method} {path}"
        );
    }
    let authz = crate::auth::AuthorizationPolicy::new("nucleus.local");
    let pod = auth(&format!(
        "spiffe://nucleus.local/ns/pods/sa/{}",
        Uuid::new_v4()
    ));
    let ci = auth("spiffe://nucleus.local/ns/github/sa/repo");
    let orchestrator = auth("spiffe://nucleus.local/ns/default/sa/orchestrator");
    assert!(authz.authorize(&pod, Operation::MemorySpaces).is_err());
    assert!(authz.authorize(&pod, Operation::MemoryBinding).is_ok());
    assert!(authz.authorize(&ci, Operation::MemorySpaces).is_err());
    assert!(authz.authorize(&ci, Operation::MemoryBinding).is_err());
    assert!(
        authz
            .authorize(&orchestrator, Operation::MemorySpaces)
            .is_ok()
    );
}

/// Over the real handlers: the tenant root declares a space and a workspace policy, a run is
/// bound and its branch published, a later run of the workspace is given it, and every step is
/// receipted in the node's log. A pod cannot declare a space, nor publish a binding it does not
/// hold, and a publish onto a head that moved is a conflict naming the head.
#[cfg(feature = "local-driver")]
#[tokio::test]
async fn the_tenant_root_declares_binds_and_publishes_over_http() {
    use crate::memory_provisioning::{LineageRoot, MemoryArgs, Subject};
    use crate::memory_space::PodLabels;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use nucleus_provenance_memory::{
        ContentHash, Epoch, JournalLocation, MAX_JOURNAL_BYTES, MemoryDerivation, MemoryRecord,
        Patch, PublishedJournal, PublisherBinding, SchemaType, SourceClass, StoreInvariants,
        TransformRegistry, read_unlocked, recompute::derive_label,
    };
    use std::os::unix::fs::PermissionsExt;
    use tower::ServiceExt;

    struct Anyone;
    impl nucleus_provenance_memory::ReachCheck for Anyone {
        fn admit(&self, _: nucleus_provenance_memory::JournalPart, _: u32) -> Result<(), String> {
            Ok(())
        }
    }

    let dir = tempfile::tempdir().unwrap();
    let mut state = crate::pod_api::handler_tests::state(&dir);
    let memory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(memory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    state.memory = std::sync::Arc::new(
        MemoryArgs::rooted(memory.path().to_owned())
            .load(&state.host_roots, &state.state_dir, &state.authority)
            .unwrap(),
    );
    let app = routes().with_state(state.clone());
    let root = "spiffe://nucleus.local/ns/default/sa/orchestrator";
    let call = |method: Method, path: String, caller: CallerScope, body: String| {
        let app = app.clone();
        async move {
            let response = app
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("content-type", "application/json")
                        .extension(AuthContext::from_spiffe(root.into()))
                        .extension(caller)
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
                .await
                .unwrap();
            (
                status,
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            )
        }
    };

    let space = r#"{"space":"notes","schema":["string","json"],"quota_bytes":1048576}"#;
    let (status, _) = call(
        Method::POST,
        "/v1/memory/spaces".into(),
        CallerScope::Pod(Uuid::new_v4()),
        space.into(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a pod is no tenant root");
    let (status, created) = call(
        Method::POST,
        "/v1/memory/spaces".into(),
        CallerScope::NodeWide,
        space.into(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");

    let policy = r#"{"audience":{"kind":"workspace","selector":{"team":"a"}},"mode":"read_propose","view":{"schema":["string"],"ceiling":"secret"},"may_publish":true,"allocation_bytes":65536,"expiry":{"kind":"until_revoked"},"authority":{"kind":"tenant_root"}}"#;
    let (status, created) = call(
        Method::POST,
        "/v1/memory/spaces/notes/policies".into(),
        CallerScope::NodeWide,
        policy.into(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{created}");

    // A run of the workspace, created by the tenant root.
    let team = std::collections::BTreeMap::from([("team".to_owned(), "a".to_owned())]);
    let mut spec: nucleus_spec::PodSpec = serde_json::from_str(
        r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{"policy":{"type":"profile","name":"default"}}}"#,
    )
    .unwrap();
    spec.metadata
        .labels
        .insert("nucleus.io/memory-namespace".into(), "notes".into());
    let bind = || {
        let request = state
            .memory
            .request(
                &spec,
                &crate::driver::DriverKind::Container,
                crate::container_mediation::ContainerMediation::ToolProxy,
            )
            .unwrap();
        state
            .memory
            .provision(
                request,
                &Subject {
                    pod: Uuid::new_v4(),
                    owner: root,
                    lineage: LineageRoot::Known(Uuid::new_v4()),
                    labels: PodLabels::TenantAuthenticated(&team),
                    run_ends: crate::memory_provisioning::now_unix() + 3600,
                },
                &state.state_dir,
                &state.authority,
                None,
            )
            .unwrap()
            .unwrap()
    };
    let run_a = bind();
    let (binding, namespace, directory) = {
        let registry = state.memory.registry().unwrap().lock().unwrap();
        let held = registry.bindings.values().next().unwrap();
        let (_, namespace) = held.store();
        (
            held.binding_id,
            namespace,
            memory
                .path()
                .join("bindings")
                .join(held.binding_id.to_string()),
        )
    };
    let _ = run_a;
    let derivation = MemoryDerivation::RawIngest {
        source_class: SourceClass::Web,
        source_hash: ContentHash::of_canonical_bytes(b"from run a"),
    };
    let label = derive_label(&derivation, &[]);
    let note = MemoryRecord::new("from run a", SchemaType::String, label, derivation);
    {
        let transforms = TransformRegistry::new();
        let loc = JournalLocation::new(&directory.join("memory.jsonl"), &namespace).unwrap();
        let mut branch = PublishedJournal::open(loc, &Anyone, &transforms).unwrap();
        let head = branch.head().unwrap();
        branch
            .publish(
                &Patch::new(head, vec![note.clone()]),
                head,
                PublisherBinding::operator_direct(),
                Epoch::PRE_BINDING,
                &StoreInvariants::new(usize::MAX, MAX_JOURNAL_BYTES),
                &transforms,
            )
            .unwrap();
    }
    let (status, listed) = call(
        Method::GET,
        "/v1/memory/spaces".into(),
        CallerScope::NodeWide,
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let genesis = listed[0]["high_water"].clone();
    let (status, stale) = call(
        Method::POST,
        format!("/v1/memory/bindings/{binding}/publish"),
        CallerScope::Pod(Uuid::new_v4()),
        serde_json::json!({ "expected": genesis }).to_string(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "another pod cannot publish this binding: {stale}"
    );
    let (status, published) = call(
        Method::POST,
        format!("/v1/memory/bindings/{binding}/publish"),
        CallerScope::NodeWide,
        serde_json::json!({ "expected": genesis }).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{published}");
    assert_eq!(published["head"]["version"], 1);
    let (status, conflict) = call(
        Method::POST,
        format!("/v1/memory/bindings/{binding}/publish"),
        CallerScope::NodeWide,
        serde_json::json!({ "expected": genesis }).to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{conflict}");

    let run_b = bind();
    let given = read_unlocked(
        &JournalLocation::new(&run_b.directory.join("memory.jsonl"), &run_b.namespace).unwrap(),
        &Anyone,
        &TransformRegistry::new(),
    )
    .unwrap();
    assert_eq!(given, vec![note], "run B is given what run A published");

    let log = std::fs::read_to_string(crate::memory_flow::flow_log_path(&state.state_dir)).unwrap();
    for event in [
        "memory_space_created",
        "memory_policy_created",
        "memory_snapshot_delivery",
        "memory_publish_authorized",
    ] {
        assert!(log.contains(event), "{event} is receipted");
    }
    let (status, refused) = call(
        Method::POST,
        "/v1/memory/spaces/notes/revoke".into(),
        CallerScope::NodeWide,
        String::new(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{refused}");
    assert!(
        std::fs::read_to_string(crate::memory_flow::flow_log_path(&state.state_dir))
            .unwrap()
            .contains("memory_space_revoked")
    );
}
