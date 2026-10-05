use super::*;
use crate::host_decide::effects::Operator;

fn operator() -> Operator {
    Operator::authenticate("operator", "operator").unwrap()
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
async fn pending(pod: &Pod) -> uuid::Uuid {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Some(approval) = pod
                .host_policy
                .lock()
                .unwrap()
                .list_effect_approvals(operator(), now())
                .first()
            {
                return approval.id;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a pending host approval")
}
fn gated(base: &str) -> Pod {
    let mut pod = Pod::new(base, 1 << 30, StreamLimits::DEFAULT);
    pod.policy
        .obligations
        .insert(portcullis::Operation::WebFetch);
    pod.host_policy = crate::host_decide::test_policy(pod.policy.clone());
    pod
}

#[tokio::test]
async fn original_stream_waits_for_operator_and_resumes_exactly_once() {
    for (guest_required, grant) in [(false, true), (false, false), (true, true), (true, false)] {
        let (base, seen) = upstream().await;
        let pod = if guest_required {
            Pod::new(&base, 1 << 30, StreamLimits::DEFAULT)
        } else {
            gated(&base)
        };
        let mut request = open("model-api", "paused");
        request.approval_wait_seconds = 10;
        request.require_approval = guest_required;
        let body = mebibyte();
        let control = async {
            let id = pending(&pod).await;
            assert!(seen.lock().unwrap().is_empty());
            tokio::time::sleep(Duration::from_millis(20)).await;
            let mut policy = pod.host_policy.lock().unwrap();
            let review = policy.effect_review(operator(), id, now()).unwrap();
            assert_eq!(review.request.require_approval, guest_required);
            let mut changed = review.request.clone();
            changed.require_approval = !guest_required;
            assert_ne!(changed.digest().unwrap(), review.request.digest().unwrap());
            use base64::Engine as _;
            assert_eq!(
                base64::engine::general_purpose::STANDARD
                    .decode(review.body_base64)
                    .unwrap(),
                body
            );
            policy
                .settle_effect_approval(operator(), id, grant, now())
                .unwrap();
        };
        let (heard, ()) = tokio::join!(drive(&pod, &request, &body), control);
        assert_eq!(heard.head.granted, grant, "{}", heard.head.reason);
        let calls = seen.lock().unwrap();
        assert_eq!(calls.len(), usize::from(grant));
        if grant {
            assert!(calls[0].complete);
            assert_eq!(calls[0].body_len, body.len());
            assert_eq!(
                calls[0].body_sha256,
                <[u8; 32]>::from(Sha256::digest(&body))
            );
        }
        if !grant {
            assert!(heard.head.reason.contains("operator refused"));
        }
    }
}

#[tokio::test]
async fn operator_can_grant_after_credential_authorization_expires() {
    let (base, seen) = upstream().await;
    let pod = gated(&base);
    let mut request = open("model-api", "slow-operator");
    request.approval_wait_seconds = 120;
    let control = async {
        let id = pending(&pod).await;
        // Cross the credential PDP witness lifetime, not the operator grant's
        // lifetime. The stream must recheck policy before fetching credentials.
        tokio::time::sleep(Duration::from_secs(
            nucleus_cred_broker::APPROVAL_TTL_SECS + 1,
        ))
        .await;
        assert!(seen.lock().unwrap().is_empty());
        pod.host_policy
            .lock()
            .unwrap()
            .settle_effect_approval(operator(), id, true, now())
            .unwrap();
    };
    let (heard, ()) = tokio::join!(drive(&pod, &request, b"reviewed payload"), control);
    assert!(heard.head.granted, "{}", heard.head.reason);
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn approval_wait_times_out_without_dispatch_or_erasing_the_review() {
    let (base, seen) = upstream().await;
    let pod = gated(&base);
    let mut request = open("model-api", "timeout");
    request.approval_wait_seconds = 1;
    let heard = tokio::time::timeout(Duration::from_secs(5), drive(&pod, &request, b"pending"))
        .await
        .unwrap();
    assert!(!heard.head.granted);
    assert!(heard.head.reason.contains("wait timed out"));
    assert!(seen.lock().unwrap().is_empty());
    let id = pending(&pod).await;
    assert!(
        pod.host_policy
            .lock()
            .unwrap()
            .effect_review(operator(), id, now())
            .is_ok()
    );
}

#[tokio::test]
async fn broker_disconnect_and_revocation_cancel_pending_streams_without_dispatch() {
    for revoke in [false, true] {
        let (base, seen) = upstream().await;
        let pod = gated(&base);
        let mut request = open("model-api", "disconnect");
        request.approval_wait_seconds = 120;
        let line = format!(
            "{}\n",
            nucleus_cred_protocol::frame::sign(KEY, &serde_json::to_string(&request).unwrap())
        );
        let (mut guest, host) = tokio::io::duplex(16 * 1024);
        let serving = pod.serving();
        let serve = serve_connection_with_timeout(host, &serving, Duration::from_secs(10));
        let guest = async {
            guest.write_all(line.as_bytes()).await.unwrap();
            write_chunks(&mut guest, b"pending").await.unwrap();
            write_end(&mut guest).await.unwrap();
            pending(&pod).await;
            if revoke {
                crate::host_decide::PodPolicy::revoke(&pod.host_policy);
                // Revocation may close the connection or send a refusal before
                // the outer connection task observes the same signal.
                let mut reader = BufReader::new(&mut guest);
                if let Ok(line) = read_line(&mut reader, MAX_STREAM_LINE_BYTES).await {
                    let head: StreamHead = serde_json::from_str(&line).unwrap();
                    assert!(!head.granted);
                }
            }
            drop(guest);
        };
        tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(serve, guest);
        })
        .await
        .unwrap();
        assert!(seen.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn wait_option_preserves_non_approval_refusal_reasons() {
    let (base, seen) = upstream().await;
    let mut pod = Pod::new(&base, 1 << 30, StreamLimits::DEFAULT);
    pod.policy.budget.max_cost_usd = rust_decimal::Decimal::ZERO;
    pod.host_policy = crate::host_decide::test_policy(pod.policy.clone());
    let mut request = open("model-api", "exhausted");
    request.approval_wait_seconds = 120;
    let heard = drive(&pod, &request, b"budget exhausted").await;
    assert!(!heard.head.granted);
    assert!(
        heard.head.reason.contains("budget_exhausted"),
        "{}",
        heard.head.reason
    );
    assert!(seen.lock().unwrap().is_empty());
}
