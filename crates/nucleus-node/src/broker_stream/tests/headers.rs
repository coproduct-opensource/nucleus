//! The operator's fixed and secret request headers (#3213), over the REAL
//! serving path against a fake upstream that requires a version header and
//! records every header that reached it.
use super::*;

/// What the fake upstream saw of one request.
#[derive(Debug, Clone)]
struct Hit {
    version: Option<String>,
    authorization: Option<String>,
    binding: Option<String>,
    accept: Option<String>,
}

type Hits = Arc<Mutex<Vec<Hit>>>;

const VERSION: &str = "2026-01-01";

/// A fake upstream that answers 200 only to a request carrying
/// `x-api-version: 2026-01-01`, and 400 to anything else, as an API that
/// pins its request format by header does.
async fn versioned() -> (String, Hits) {
    let hits: Hits = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&hits);
    let app = axum::Router::new().fallback(move |request: axum::extract::Request| {
        let log = Arc::clone(&log);
        async move {
            let header = |name: &str| {
                request
                    .headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
            };
            let hit = Hit {
                version: header("x-api-version"),
                authorization: header("authorization"),
                binding: header("x-account-binding"),
                accept: header("accept"),
            };
            let status = if hit.version.as_deref() == Some(VERSION) {
                200
            } else {
                400
            };
            log.lock().unwrap().push(hit);
            axum::response::Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(axum::body::Body::from("{}"))
                .unwrap()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    (format!("http://{addr}/"), hits)
}

/// The upstream as the operator declared it. The allowlist lists the fixed
/// and the secret name too, unvalidated (the loader would refuse it), so the
/// per-call check is shown to hold on its own.
fn entry(base: &str, fixed: &[(&str, &str)]) -> RegistryEntry {
    RegistryEntry::env(nucleus_spec::CredentialedEgressSpec {
        name: "model-api".into(),
        upstream: base.to_string(),
        credential_env: "LLM_API_TOKEN".into(),
        header: "authorization".into(),
        value_prefix: "Bearer ".into(),
    })
    .with_request_headers(&["accept", "x-api-version", "x-account-binding"])
    .with_header_policy(fixed, &["x-account-binding"])
}

fn pod(base: &str, fixed: &[(&str, &str)], policy: PermissionLattice) -> Pod {
    let mut pod = Pod::new(base, 1 << 30, StreamLimits::DEFAULT);
    pod.upstreams = vec![entry(base, fixed)];
    pod.host_policy = crate::host_decide::test_policy(policy.clone());
    pod.policy = policy;
    pod
}

/// A call whose guest proposes its own version, a secret name and an
/// allowed header.
fn proposing(nonce: &str) -> StreamRequest {
    let mut req = open("model-api", nonce);
    req.headers = BTreeMap::from([
        ("accept".into(), "application/json".into()),
        ("x-api-version".into(), "1999-01-01".into()),
        ("x-account-binding".into(), "guest-chosen".into()),
    ]);
    req
}

/// **The fixed header reaches the upstream, and the guest cannot choose
/// it.** The upstream that requires the version answers 200 because the
/// host added it; the guest's own version and its secret-named header were
/// dropped though the allowlist listed both; the credential is the host's;
/// and the record names the forwarded headers, never a value.
///
/// A-19 pair: [`without_the_fixed_header_the_upstream_refuses`].
#[tokio::test]
async fn a_fixed_header_reaches_the_upstream_and_a_guest_cannot_choose_it() {
    let (base, hits) = versioned().await;
    let pod = pod(
        &base,
        &[("x-api-version", VERSION)],
        PermissionLattice::permissive(),
    );
    let heard = drive(&pod, &proposing("fixed"), b"{}").await;
    assert!(heard.head.granted, "{:?}", heard.head);
    assert_eq!(heard.head.status, 200);
    let hits = hits.lock().unwrap().clone();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].version.as_deref(), Some(VERSION));
    assert_eq!(hits[0].binding, None, "a secret name was guest-supplied");
    assert_eq!(hits[0].accept.as_deref(), Some("application/json"));
    assert_eq!(
        hits[0].authorization.as_deref(),
        Some(&*format!("Bearer {TOKEN}"))
    );
    let audit = pod.audit().replace("\\\"", "\"");
    assert!(
        audit.contains("\"headers_forwarded\":[\"accept\",\"x-api-version\"]"),
        "{audit}"
    );
    for value in [TOKEN, VERSION, "1999-01-01", "guest-chosen"] {
        assert!(!audit.contains(value), "the record carries {value:?}");
    }
}

/// The pair: the same upstream, the same guest, and no fixed header in the
/// registry. The guest's own version is still dropped (the per-call check
/// does not depend on the fixed header existing for the secret name), so
/// the upstream refuses the call.
#[tokio::test]
async fn without_the_fixed_header_the_upstream_refuses() {
    let (base, hits) = versioned().await;
    let mut unfixed = pod(&base, &[], PermissionLattice::permissive());
    // Without a fixed version, the guest's proposal would be an ordinary
    // listed header; unlist it so the call carries no version at all.
    unfixed.upstreams = vec![entry(&base, &[]).with_request_headers(&["accept"])];
    let heard = drive(&unfixed, &proposing("unfixed"), b"{}").await;
    assert!(heard.head.granted, "{:?}", heard.head);
    assert_eq!(heard.head.status, 400);
    let hits = hits.lock().unwrap().clone();
    assert_eq!(hits[0].version, None);
    assert_eq!(hits[0].binding, None);
}

/// **An approval binds the fixed header, and the review shows it without the
/// credential.** The operator reviews the call with the fixed version in it;
/// nothing in the review is the credential's value.
#[tokio::test]
async fn the_review_shows_the_fixed_header_and_never_the_credential() {
    let (base, hits) = versioned().await;
    let mut gated = PermissionLattice::permissive();
    gated.obligations.insert(portcullis::Operation::WebFetch);
    let pod = pod(&base, &[("x-api-version", VERSION)], gated);
    let refused = drive(&pod, &proposing("ask"), b"{}").await;
    assert!(refused.head.reason.starts_with("host approval required:"));
    assert!(hits.lock().unwrap().is_empty());
    let review = {
        let operator =
            || crate::host_decide::effects::Operator::authenticate("operator", "operator").unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut policy = pod.host_policy.lock().unwrap();
        let pending = policy.list_effect_approvals(operator(), now);
        assert_eq!(pending.len(), 1, "{pending:?}");
        policy
            .effect_review(operator(), pending[0].id, now)
            .unwrap()
    };
    assert_eq!(review.request.request_headers["x-api-version"], VERSION);
    assert!(
        !review
            .request
            .request_headers
            .contains_key("x-account-binding")
    );
    let shown = format!("{review:?}");
    assert!(!shown.contains(TOKEN), "the review carries the credential");
}
