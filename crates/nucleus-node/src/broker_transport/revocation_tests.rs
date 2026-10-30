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

/// A broker serving `calls` connections, each with an effect in flight: the
/// upstream call never answers, so each holds its affine outcome observer.
struct InFlight {
    dir: tempfile::TempDir,
    policy: crate::host_decide::SharedPodPolicy,
    active: Arc<AtomicUsize>,
    drops: tokio::sync::mpsc::UnboundedReceiver<()>,
    stop: tokio::sync::oneshot::Sender<()>,
    server: tokio::task::JoinHandle<()>,
    clients: Vec<UnixStream>,
}

async fn in_flight(calls: usize) -> InFlight {
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
    let (dropped, drops) = tokio::sync::mpsc::unbounded_channel();
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
                    effects: nucleus_spec::EffectTable::unclassified(),
                },
            )]),
            caller,
            egress: serving_tests::test_egress_arc(),
            streams: serving_tests::test_streams(),
            peer: super::peer::PeerRule::VmmForwarded,
        },
        async {
            let _ = stopped.await;
        },
    ));
    let mut clients = Vec::new();
    for i in 0..calls {
        let frame = serde_json::json!({"operation":"WebFetch", "target":"model-api", "justification":"test", "idempotency_key":format!("call-{i}"), "path":"/call", "body":[1,2,3]}).to_string();
        let signed = nucleus_cred_protocol::frame::sign(b"test-capability", &frame);
        let mut client = UnixStream::connect(&path).await.unwrap();
        client
            .write_all(format!("{signed}\n").as_bytes())
            .await
            .unwrap();
        clients.push(client);
    }
    for _ in 0..calls {
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(3), enters.recv())
                .await
                .unwrap(),
            Some(())
        );
    }
    assert_eq!(active.load(Ordering::SeqCst), calls);
    InFlight {
        dir,
        policy,
        active,
        drops,
        stop,
        server,
        clients,
    }
}

async fn saturated(revoke_directly: bool) {
    let InFlight {
        dir,
        policy,
        active,
        mut drops,
        stop,
        server,
        clients,
    } = in_flight(MAX_CONCURRENT_CONNECTIONS).await;
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
                crate::upstreams::CallCharge::free(),
                false
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

/// A connection cancelled by revocation must not hold the revocation watch while
/// it drops its in-flight effect.
///
/// Dropping the effect records it as interrupted under the pod's policy lock
/// (`Pending::drop`), and every revoke writes the watch while holding that lock.
/// So a connection that read-locks the watch and then waits for the policy lock,
/// while a second revoke holds the policy lock and waits to write the watch, is a
/// lock-order cycle on two blocking locks: both threads park in a futex, and so
/// does every later caller of the pod's policy. Teardown revokes more than once
/// (`cleanup_identity`, then `BrokerListener::shutdown`, then its `Drop`). The Mac
/// node froze this way on 2026-10-30 for 8 h 44 min: last log line the workload
/// API bridge shutting down, the in-flight call's outcome never written, all eight
/// workers in `futex_do_wait`. gatehouse F-315.
///
/// The interleaving is forced, not raced: this thread holds the policy lock from
/// the first revoke to the second, which is where a second revoke that won the
/// lock race stands.
#[test]
fn a_connection_revoked_mid_call_drops_its_call_without_holding_the_revocation_watch() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let InFlight {
        dir: _dir,
        policy,
        active: _,
        mut drops,
        stop,
        server,
        clients: _clients,
    } = runtime.block_on(in_flight(1));

    let (done, finished) = std::sync::mpsc::channel();
    let revoker = Arc::clone(&policy);
    std::thread::spawn(move || {
        let state = revoker.lock().unwrap();
        state.revoke_held();
        // The connection sees the revocation and drops its upstream call, then
        // its outcome observer, which asks for the policy lock held here. Not
        // awaited unboundedly: were the observer dropped first, it would park
        // on this lock before the call's drop was reported.
        let seen = std::time::Instant::now();
        while drops.try_recv().is_err() && seen.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(200));
        state.revoke_held();
        drop(state);
        let _ = done.send(());
    });
    if finished.recv_timeout(Duration::from_secs(10)).is_err() {
        // Two threads are parked for good; do not wait for them on the way out.
        runtime.shutdown_background();
        panic!(
            "deadlock: a revoke holding the pod's policy lock waited to write the \
             revocation watch while the revoked connection held the watch's read \
             lock and waited for the policy lock"
        );
    }

    // The node is still serving the pod's policy, and teardown still completes.
    runtime.block_on(async {
        let probe = Arc::clone(&policy);
        tokio::time::timeout(
            Duration::from_secs(3),
            tokio::spawn(async move { PodPolicy::available(&probe) }),
        )
        .await
        .expect("the runtime must keep answering after a revocation")
        .unwrap()
        .expect_err("a revoked policy is unavailable");
        stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .expect("the broker must shut down after revocation")
            .unwrap();
    });
    runtime.shutdown_timeout(Duration::from_secs(1));
}
