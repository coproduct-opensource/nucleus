use super::*;
use crate::host_decide::{PodPolicy, evidence::Evidence};
use std::sync::atomic::{AtomicUsize, Ordering};

struct Active {
    count: Arc<AtomicUsize>,
    dropped: tokio::sync::mpsc::UnboundedSender<()>,
}
impl Drop for Active {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::SeqCst);
        let _ = self.dropped.send(());
    }
}

async fn saturated(revoke_directly: bool) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("broker.sock");
    let listener = prepare_socket(&path).unwrap();
    let evidence = Evidence::create(
        uuid::Uuid::new_v4(),
        dir.path(),
        Arc::new(ed25519_dalek::SigningKey::from_bytes(&[23; 32])),
    )
    .unwrap();
    let policy = PodPolicy::new(
        portcullis::kernel::Kernel::new(PermissionLattice::permissive()),
        evidence,
    );
    let mut store = nucleus_cred_broker::CredentialStore::new();
    store.insert(
        "model-api",
        nucleus_cred_broker::Credential::new("test-token"),
    );
    let active = Arc::new(AtomicUsize::new(0));
    let (entered, mut enters) = tokio::sync::mpsc::unbounded_channel();
    let (dropped, mut drops) = tokio::sync::mpsc::unbounded_channel();
    let count = active.clone();
    let caller: UpstreamCaller = Arc::new(move |_call| {
        let active = Active {
            count: count.clone(),
            dropped: dropped.clone(),
        };
        active.count.fetch_add(1, Ordering::SeqCst);
        entered.send(()).unwrap();
        Box::pin(async move {
            let _active = active;
            std::future::pending().await
        })
    });
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(serve_broker(
        listener,
        PodBroker {
            host_policy: policy.clone(),
            identity: PodIdentity::observed_by_host("spiffe://nucleus/pod/revoke"),
            policy: Arc::new(PermissionLattice::permissive()),
            credentials: Arc::new(PodCredentials::static_only(store)),
            broker_secret: Some(Arc::new(b"test-capability".to_vec())),
            upstreams: Arc::new(vec![RegistryEntry::env(
                nucleus_spec::CredentialedEgressSpec {
                    name: "model-api".into(),
                    upstream: "https://upstream.invalid".into(),
                    credential_env: "LLM_TOKEN".into(),
                    header: "authorization".into(),
                    value_prefix: "Bearer ".into(),
                },
            )]),
            caller,
            egress: serving_tests::test_egress_arc(),
            streams: serving_tests::test_streams(),
        },
        async {
            let _ = stopped.await;
        },
    ));
    let mut clients = Vec::new();
    for i in 0..MAX_CONCURRENT_CONNECTIONS {
        let frame = serde_json::json!({"operation":"WebFetch", "target":"model-api", "justification":"test", "idempotency_key":format!("call-{i}"), "path":"/call", "body":[1,2,3]}).to_string();
        let signed = nucleus_cred_protocol::frame::sign(b"test-capability", &frame);
        let mut client = UnixStream::connect(&path).await.unwrap();
        client
            .write_all(format!("{signed}\n").as_bytes())
            .await
            .unwrap();
        clients.push(client);
    }
    for _ in 0..MAX_CONCURRENT_CONNECTIONS {
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), enters.recv())
                .await
                .unwrap(),
            Some(())
        );
    }
    assert_eq!(active.load(Ordering::SeqCst), MAX_CONCURRENT_CONNECTIONS);
    if revoke_directly {
        PodPolicy::revoke(&policy);
        for _ in 0..MAX_CONCURRENT_CONNECTIONS {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(3), drops.recv())
                    .await
                    .unwrap(),
                Some(())
            );
        }
    }
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .expect("shutdown must observe its signal while saturated")
        .unwrap();
    assert_eq!(
        active.load(Ordering::SeqCst),
        0,
        "no detached upstream work after shutdown"
    );
    assert!(PodPolicy::available(&policy).is_err());
    assert!(
        policy
            .lock()
            .unwrap()
            .preflight_effect(
                nucleus_decision_protocol::ArgsDigest::new([1; 32]),
                portcullis::Operation::WebFetch,
                "https://upstream.invalid/call",
                100,
                crate::upstreams::CallCharge::free()
            )
            .is_err()
    );
    let outcomes = std::fs::read_to_string(
        dir.path()
            .join(nucleus_spec::host_effect::outcome::LOG_FILE),
    )
    .unwrap();
    assert_eq!(outcomes.lines().count(), MAX_CONCURRENT_CONNECTIONS);
    for line in outcomes.lines() {
        let record: nucleus_spec::host_effect::outcome::SignedOutcome =
            serde_json::from_str(line).unwrap();
        assert_eq!(
            record.outcome.termination,
            nucleus_spec::host_effect::outcome::Termination::Interrupted
        );
    }
    drop(clients);
}

#[tokio::test]
async fn shutdown_drains_all_calls_even_when_every_connection_slot_is_occupied() {
    saturated(false).await;
}

#[tokio::test]
async fn revocation_cancels_calls_on_existing_connections_without_waiting_for_shutdown() {
    saturated(true).await;
}
