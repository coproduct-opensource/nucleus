use super::*;
use std::time::Duration;

fn meter(dir: &std::path::Path) -> Arc<crate::egress_meter::EgressMeter> {
    crate::egress_meter::EgressMeter::new(
        portcullis::EgressCeiling::new(
            1_000,
            portcullis::EgressPace::PerWindow {
                bytes: 100,
                window_secs: std::num::NonZeroU32::new(1).unwrap(),
            },
        ),
        dir.to_path_buf(),
        "paced-perform".into(),
    )
}

#[tokio::test]
async fn ordinary_perform_crosses_windows_and_replay_sends_nothing() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let received = Arc::new(Mutex::new(Vec::new()));
    let sink = received.clone();
    let app = axum::Router::new().route(
        "/v1/messages",
        axum::routing::post(move |body: axum::body::Bytes| async move {
            sink.lock().unwrap().push(body.to_vec());
            "ordinary response"
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let mut spec = upstream().spec().clone();
    spec.upstream = format!("http://{address}/v1");
    let upstreams = [RegistryEntry::env(spec)];
    let (policy, credentials, identity, ledger) = (
        PermissionLattice::permissive(),
        store(),
        who(),
        IdempotencyLedger::new(),
    );
    let dir = tempfile::tempdir().unwrap();
    let meter = meter(dir.path());
    let context = PerformContext {
        egress: &meter,
        ..ctx(&policy, &credentials, &upstreams, &ledger, &identity)
    };
    let mut req = request();
    req.body = vec![b'x'; 250];
    let caller = crate::broker_transport::http_caller(reqwest::Client::new());
    let started = std::time::Instant::now();
    let reply = handle_perform(&req, &context, NOW, |call| caller(call)).await;
    assert!(reply.granted, "{}", reply.reason);
    assert_eq!(reply.body, b"ordinary response");
    assert!(started.elapsed() >= Duration::from_secs(2));
    assert_eq!(*received.lock().unwrap(), vec![req.body.clone()]);
    assert_eq!(meter.counted(), upload_bytes(&req));
    let repeated = handle_perform(&req, &context, NOW + 3, |_| async {
        panic!("a completed retry must not dispatch")
    })
    .await;
    assert_eq!(reply, repeated);
    assert_eq!(meter.counted(), upload_bytes(&req));
    server.abort();
}

#[tokio::test]
async fn cancelled_perform_retains_full_charge_after_body_handoff() {
    let (policy, credentials, identity, ledger) = (
        PermissionLattice::permissive(),
        store(),
        who(),
        IdempotencyLedger::new(),
    );
    let upstreams = [upstream()];
    let dir = tempfile::tempdir().unwrap();
    let meter = meter(dir.path());
    let context = PerformContext {
        egress: &meter,
        ..ctx(&policy, &credentials, &upstreams, &ledger, &identity)
    };
    let mut req = request();
    req.body = vec![b'x'; 250];
    let (sent, received) = tokio::sync::oneshot::channel();
    let mut serving = Box::pin(handle_perform(&req, &context, NOW, |mut call| async move {
        let chunk = call.body.recv().await.unwrap().unwrap();
        assert!(!chunk.is_empty() && chunk.len() <= 100);
        sent.send(()).unwrap();
        std::future::pending::<()>().await;
        drop(call);
        Err("unreachable".into())
    }));
    tokio::select! {
        _ = &mut serving => panic!("the request should still be running"),
        result = received => result.unwrap(),
    }
    drop(serving);
    assert_eq!(meter.counted(), upload_bytes(&req));
    assert_eq!(
        ledger.len(),
        1,
        "an ambiguous cancelled call retains its retry key"
    );
}

#[tokio::test]
async fn upstream_deadline_settles_an_ambiguous_result_without_retrying() {
    let (policy, credentials, identity, ledger) = (
        PermissionLattice::permissive(),
        store(),
        who(),
        IdempotencyLedger::new(),
    );
    let upstreams = [upstream()];
    let dir = tempfile::tempdir().unwrap();
    let meter = meter(dir.path());
    let context = PerformContext {
        egress: &meter,
        ..ctx(&policy, &credentials, &upstreams, &ledger, &identity)
    };
    let req = request();
    let called = AtomicUsize::new(0);
    let reply = perform_until(
        &req,
        &context,
        NOW,
        tokio::time::Instant::now() + Duration::from_millis(20),
        |call| async {
            called.fetch_add(1, Ordering::SeqCst);
            let _ = call.body.collect_bytes().await;
            std::future::pending::<Result<UpstreamResponse, String>>().await
        },
    )
    .await;
    assert_eq!(called.load(Ordering::SeqCst), 1);
    assert!(!reply.granted);
    assert_eq!(reply.reason, "upstream call failed");
    assert_eq!(meter.counted(), upload_bytes(&req));
    let repeated = handle_perform(&req, &context, NOW + 1, |_| async {
        panic!("a timed-out upstream is not automatically retried")
    })
    .await;
    assert_eq!(reply, repeated);
}
