//! Forge API writes through host-performed egress (#3229), over the REAL
//! serving path against a fake forge that is a real HTTP server. The
//! operator's registry declares `POST /repos/*/*/pulls` as `create_pr` and the
//! upstream as a forge, so opening a pull request is decided as what it is,
//! and a write the registry does not classify is refused. The fake records
//! every request that reached it, so each refusal is also shown to have sent
//! nothing.
use super::*;
use nucleus_cred_protocol::EgressMethod;
use nucleus_spec::{DeclaredEffect, EffectTable, EgressOperation, UpstreamKind};

/// What the fake forge saw of one request.
#[derive(Debug, Clone)]
struct Hit {
    method: String,
    path: String,
    authorization: Option<String>,
    body: Vec<u8>,
}

type Hits = Arc<Mutex<Vec<Hit>>>;

/// A fake forge: every request is recorded, and answered 201 as if it had
/// been created.
async fn forge() -> (String, Hits) {
    let hits: Hits = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&hits);
    let app = axum::Router::new().fallback(move |request: axum::extract::Request| {
        let log = Arc::clone(&log);
        async move {
            let (parts, body) = request.into_parts();
            let body = axum::body::to_bytes(body, 1 << 20)
                .await
                .unwrap_or_default();
            log.lock().unwrap().push(Hit {
                method: parts.method.to_string(),
                path: parts.uri.path().to_string(),
                authorization: parts
                    .headers
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string),
                body: body.to_vec(),
            });
            axum::response::Response::builder()
                .status(201)
                .header("content-type", "application/json")
                .body(axum::body::Body::from("{\"number\":1}"))
                .unwrap()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    (format!("http://{addr}/"), hits)
}

/// The operator's table for the forge: opening a pull request is
/// `create_pr`, and the upstream is a forge.
fn forge_effects() -> EffectTable {
    EffectTable::from_parts(
        Some(UpstreamKind::Forge),
        vec![DeclaredEffect {
            method: EgressMethod::Post,
            path: "/repos/*/*/pulls".into(),
            operation: EgressOperation::CreatePr,
        }],
    )
    .expect("a valid table")
}

/// A pod that declared the forge as `forge-api` with `effects`, under
/// `policy`.
fn declared(base: &str, effects: EffectTable, policy: PermissionLattice) -> Pod {
    let mut pod = Pod::holding(base, 1 << 30, StreamLimits::DEFAULT, &["forge-api"]);
    pod.upstreams = vec![
        RegistryEntry::env(nucleus_spec::CredentialedEgressSpec {
            name: "forge-api".into(),
            upstream: base.to_string(),
            credential_env: "FORGE_API_TOKEN".into(),
            header: "authorization".into(),
            value_prefix: "Bearer ".into(),
            effects,
        })
        .with_request_headers(&["accept"]),
    ];
    pod.host_policy = crate::host_decide::test_policy(policy.clone());
    pod.policy = policy;
    pod
}

/// A stream open for `method path`, labelled by the shared classifier over
/// `effects` exactly as the guest's tool-proxy labels it.
fn forge_open(
    effects: &EffectTable,
    method: EgressMethod,
    path: &str,
    nonce: &str,
) -> StreamRequest {
    let mut req = open("forge-api", nonce);
    req.method = method;
    req.path = path.into();
    req.operation = nucleus_cred_protocol::egress::operation_for(effects, method, path, None)
        .expect("a classified call")
        .label()
        .into();
    req.headers = BTreeMap::from([("accept".into(), "application/json".into())]);
    req
}

fn open_pr(nonce: &str) -> StreamRequest {
    forge_open(
        &forge_effects(),
        EgressMethod::Post,
        "repos/org/repo/pulls",
        nonce,
    )
}

const PR_BODY: &[u8] = b"{\"title\":\"fix\",\"head\":\"fix\",\"base\":\"main\"}";

fn without_create_pr() -> PermissionLattice {
    let mut policy = PermissionLattice::permissive();
    policy.capabilities.create_pr = portcullis::CapabilityLevel::Never;
    policy
}

fn operator() -> crate::host_decide::effects::Operator {
    crate::host_decide::effects::Operator::authenticate("operator", "operator").unwrap()
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Grant the pod's one pending host approval, returning its review.
fn grant_pending(pod: &Pod) -> nucleus_spec::host_effect_approval::ApprovalReview {
    let mut policy = pod.host_policy.lock().unwrap();
    let pending: Vec<_> = policy
        .list_effect_approvals(operator(), now())
        .into_iter()
        .filter(|a| a.status == crate::host_decide::effects::ApprovalStatus::Pending)
        .collect();
    assert_eq!(pending.len(), 1, "{pending:?}");
    let review = policy
        .effect_review(operator(), pending[0].id, now())
        .unwrap();
    policy
        .settle_effect_approval(operator(), pending[0].id, true, now())
        .unwrap();
    review
}

/// **(a) Under `create_pr: never`, opening a pull request is refused by the
/// PDP before any byte leaves.** The call is labelled `CreatePr` by the
/// operator's table and refused "not permitted"; the forge saw nothing.
///
/// A-19: the control below is the same request, the same profile, and the
/// same forge with NO effect table (the upstream as it was before #3229): it
/// is decided as a fetch and reaches the forge. Neutralising the declared
/// effect (an `EffectTable::declared` that never matches) makes the first
/// half fail the same way.
#[tokio::test]
async fn a_pull_request_is_refused_by_the_pdp_under_a_profile_without_it() {
    let (base, hits) = forge().await;
    let pod = declared(&base, forge_effects(), without_create_pr());
    let req = open_pr("pr-never");
    let heard = drive(&pod, &req, PR_BODY).await;
    assert!(
        !heard.head.granted,
        "a pull request was opened: {:?}",
        heard.head
    );
    assert_eq!(heard.head.reason, "not permitted");
    assert!(
        hits.lock().unwrap().is_empty(),
        "a refused write reached the forge"
    );
    assert_eq!(req.operation, "CreatePr");
    let audit = pod.audit().replace("\\\"", "\"");
    assert!(audit.contains("\"operation\":\"CreatePr\""), "{audit}");

    // The control, and the hole #3229 closes: without the operator's
    // classification the identical request is a plain fetch, and goes.
    let unclassified = declared(&base, EffectTable::unclassified(), without_create_pr());
    let mut as_fetch = forge_open(
        &EffectTable::unclassified(),
        EgressMethod::Post,
        "repos/org/repo/pulls",
        "pr-as-fetch",
    );
    assert_eq!(as_fetch.operation, "WebFetch");
    as_fetch.nonce = "pr-as-fetch".into();
    let went = drive(&unclassified, &as_fetch, PR_BODY).await;
    assert!(went.head.granted, "{:?}", went.head);
    assert_eq!(hits.lock().unwrap().len(), 1);
}

/// **(b) Under a profile that allows it, opening a pull request needs the
/// operator's approval, and then reaches the forge with the host's
/// credential.** The review names the operation and the exact request; the
/// approved call carries the injected credential, never the guest's; the
/// record names the operation; the credential never reaches the guest.
#[tokio::test]
async fn an_allowed_pull_request_is_approved_then_sent_with_the_hosts_credential() {
    let (base, hits) = forge().await;
    let pod = declared(&base, forge_effects(), PermissionLattice::permissive());
    let asked = drive(&pod, &open_pr("pr-ask"), PR_BODY).await;
    assert!(
        asked.head.reason.starts_with("host approval required:"),
        "opening a pull request did not ask the operator: {:?}",
        asked.head
    );
    assert!(hits.lock().unwrap().is_empty());
    let review = grant_pending(&pod);
    assert_eq!(review.request.operation, "CreatePr");
    assert_eq!(review.request.method, "POST");
    assert!(review.request.url.ends_with("/repos/org/repo/pulls"));

    let sent = drive(&pod, &open_pr("pr-approved"), PR_BODY).await;
    assert!(sent.head.granted, "{:?}", sent.head);
    assert_eq!(sent.head.status, 201);
    assert!(
        !sent.raw.contains(TOKEN),
        "the credential reached the guest"
    );
    let hits = hits.lock().unwrap().clone();
    assert_eq!(hits.len(), 1);
    assert_eq!(
        (hits[0].method.as_str(), hits[0].path.as_str()),
        ("POST", "/repos/org/repo/pulls")
    );
    assert_eq!(
        hits[0].authorization.as_deref(),
        Some(&*format!("Bearer {TOKEN}"))
    );
    assert_eq!(hits[0].body, PR_BODY);
    let audit = pod.audit().replace("\\\"", "\"");
    assert!(audit.contains("\"operation\":\"CreatePr\""), "{audit}");
    assert!(!audit.contains(TOKEN));
}

/// **(c) A write to a forge that the registry does not classify is refused,
/// whatever it is labelled; a pull request labelled as a fetch is refused;
/// a read is not.** None of the refused calls reaches the forge.
///
/// The `WebFetch`-labelled frames are exactly what a guest that predates
/// effect tables (2.4.0 and earlier) sends for these calls: it labels by
/// the push classifier alone. The host classifies by the REGISTRY's table,
/// which no frame carries, so such a guest cannot bypass it by not knowing
/// the table.
#[tokio::test]
async fn an_unclassified_or_mislabelled_forge_write_is_refused() {
    let (base, hits) = forge().await;
    let pod = declared(&base, forge_effects(), PermissionLattice::permissive());
    let mut refused = Vec::new();
    for (n, label) in ["WebFetch", "CreatePr", "GitPush"].into_iter().enumerate() {
        let mut issue = open("forge-api", &format!("issue-{n}"));
        issue.path = "repos/org/repo/issues".into();
        issue.operation = label.into();
        refused.push(issue);
    }
    let mut pr_as_fetch = open_pr("pr-as-fetch");
    pr_as_fetch.operation = "WebFetch".into();
    refused.push(pr_as_fetch);
    let mut spelled = open_pr("pr-spelled");
    spelled.path = "repos/org/repo/pull%73".into();
    spelled.operation = "WebFetch".into();
    refused.push(spelled);
    for req in &refused {
        let heard = drive(&pod, req, PR_BODY).await;
        assert!(
            !heard.head.granted,
            "{req:?} was performed: {:?}",
            heard.head
        );
        assert_eq!(heard.head.reason, "not permitted", "{req:?}");
    }
    assert!(
        hits.lock().unwrap().is_empty(),
        "a refused write reached the forge"
    );

    // The control: a read of the same forge is a fetch, and goes.
    let read = forge_open(
        &forge_effects(),
        EgressMethod::Get,
        "repos/org/repo",
        "read",
    );
    assert_eq!(read.operation, "WebFetch");
    let heard = drive(&pod, &read, b"").await;
    assert!(heard.head.granted, "{:?}", heard.head);
    assert_eq!(hits.lock().unwrap()[0].method, "GET");
}

/// **(e) The approval is bound to the request digest: method, path, query,
/// headers and body.** An operator approves one pull request; the same call
/// to another repository, with a query, with another proposed header, or with
/// another body cannot spend it, and the original can.
#[tokio::test]
async fn a_pull_request_approval_binds_the_exact_request() {
    let (base, hits) = forge().await;
    let pod = declared(&base, forge_effects(), PermissionLattice::permissive());
    let asked = drive(&pod, &open_pr("ask"), PR_BODY).await;
    assert!(asked.head.reason.starts_with("host approval required:"));
    grant_pending(&pod);

    let other_repo = forge_open(
        &forge_effects(),
        EgressMethod::Post,
        "repos/org/other/pulls",
        "other-repo",
    );
    let mut with_query = open_pr("with-query");
    with_query.query = Some("draft=1".into());
    let mut other_header = open_pr("other-header");
    other_header.headers = BTreeMap::from([("accept".into(), "text/plain".into())]);
    for changed in [&other_repo, &with_query, &other_header] {
        let heard = drive(&pod, changed, PR_BODY).await;
        assert!(!heard.head.granted, "{changed:?} spent the approval");
    }
    let other_body = drive(&pod, &open_pr("other-body"), b"{\"title\":\"other\"}").await;
    assert!(!other_body.head.granted, "another body spent the approval");
    assert!(hits.lock().unwrap().is_empty());

    let granted = drive(&pod, &open_pr("approved"), PR_BODY).await;
    assert!(granted.head.granted, "{:?}", granted.head);
    assert_eq!(hits.lock().unwrap().len(), 1);
}
