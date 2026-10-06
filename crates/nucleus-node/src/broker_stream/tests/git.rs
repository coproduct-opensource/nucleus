//! Smart-HTTP version control through host-performed egress (#3210), over the
//! REAL serving path against a fake smart-HTTP remote that is a real HTTP
//! server. The remote answers `info/refs` and the two pack services with
//! canned pkt-lines; it records what reached it, so every refusal below is
//! also shown to have sent nothing.
use super::*;
use nucleus_cred_protocol::EgressMethod;

mod declassify;
mod human_paced;

/// What the fake remote saw of one request.
#[derive(Debug, Clone)]
struct Hit {
    method: String,
    path: String,
    query: Option<String>,
    authorization: Option<String>,
    git_protocol: Option<String>,
    accept: Option<String>,
    unlisted: bool,
    body_len: usize,
}

type Hits = Arc<Mutex<Vec<Hit>>>;

const ADVERTISEMENT: &[u8] = b"001e# service=git-upload-pack\n0000";
const RESULT: &[u8] = b"000eunpack ok\n0000";

/// A fake smart-HTTP remote: `GET …/info/refs?service=S` answers an
/// advertisement typed for `S`, `POST …/S` answers a result typed for `S`, and
/// anything else is a 404. A host that performed the wrong method would get
/// the 404, not the advertisement.
async fn remote() -> (String, Hits) {
    remote_requiring(None).await
}

/// [`remote`], answering 401 to any request whose `authorization` is not
/// exactly `required` (when set) — as a smart-HTTP endpoint that takes only
/// Basic auth answers a bearer token.
async fn remote_requiring(required: Option<&'static str>) -> (String, Hits) {
    let hits: Hits = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&hits);
    let app = axum::Router::new().fallback(move |request: axum::extract::Request| {
        let log = Arc::clone(&log);
        async move {
            let (parts, body) = request.into_parts();
            let body = axum::body::to_bytes(body, 1 << 20)
                .await
                .unwrap_or_default();
            let header = |name: &str| {
                parts
                    .headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
            };
            let path = parts.uri.path().to_string();
            let query = parts.uri.query().map(str::to_string);
            log.lock().unwrap().push(Hit {
                method: parts.method.to_string(),
                path: path.clone(),
                query: query.clone(),
                authorization: header("authorization"),
                git_protocol: header("git-protocol"),
                accept: header("accept"),
                unlisted: parts.headers.contains_key("x-unlisted"),
                body_len: body.len(),
            });
            let service = query
                .as_deref()
                .and_then(|q| q.strip_prefix("service="))
                .unwrap_or_default()
                .to_string();
            let authorized = required.is_none_or(|r| header("authorization").as_deref() == Some(r));
            let (status, content_type, reply) = match parts.method.as_str() {
                _ if !authorized => (
                    401,
                    "text/plain".to_string(),
                    &b"authentication required"[..],
                ),
                "GET" if path.ends_with("/info/refs") => (
                    200,
                    format!("application/x-{service}-advertisement"),
                    ADVERTISEMENT,
                ),
                "POST" if path.ends_with("pack") => {
                    let service = path.rsplit('/').next().unwrap_or_default();
                    (200, format!("application/x-{service}-result"), RESULT)
                }
                _ => (404, "text/plain".to_string(), &b"no such route"[..]),
            };
            axum::response::Response::builder()
                .status(status)
                .header("content-type", content_type)
                .body(axum::body::Body::from(reply))
                .unwrap()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    (format!("http://{addr}/"), hits)
}

/// A pod that declared the remote as `git-remote`, whose operator allows the
/// guest to propose `accept` and `git-protocol`, under `policy`.
fn declared(base: &str, policy: PermissionLattice) -> Pod {
    let mut pod = Pod::holding(base, 1 << 30, StreamLimits::DEFAULT, &["git-remote"]);
    pod.upstreams = vec![
        RegistryEntry::env(nucleus_spec::CredentialedEgressSpec {
            name: "git-remote".into(),
            upstream: base.to_string(),
            credential_env: "GIT_REMOTE_TOKEN".into(),
            header: "authorization".into(),
            value_prefix: "Basic ".into(),
            effects: nucleus_spec::EffectTable::unclassified(),
        })
        .with_request_headers(&["accept", "git-protocol"]),
    ];
    pod.host_policy = crate::host_decide::test_policy(policy.clone());
    pod.policy = policy;
    pod
}

/// A stream open for `method path?query`, labelled by the shared classifier
/// exactly as the guest's tool-proxy labels it.
fn git_open(method: EgressMethod, path: &str, query: Option<&str>, nonce: &str) -> StreamRequest {
    let mut req = open("git-remote", nonce);
    req.method = method;
    req.path = path.into();
    req.query = query.map(str::to_string);
    req.operation = nucleus_cred_protocol::egress::operation_for(
        &nucleus_spec::EffectTable::unclassified(),
        method,
        path,
        query,
    )
    .expect("an api upstream classifies every call")
    .label()
    .into();
    req.content_type = "application/x-git-upload-pack-request".into();
    req
}

fn advertise(service: &str, nonce: &str) -> StreamRequest {
    let query = format!("service={service}");
    git_open(
        EgressMethod::Get,
        "org/repo.git/info/refs",
        Some(&query),
        nonce,
    )
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
    let pending = policy.list_effect_approvals(operator(), now());
    let pending: Vec<_> = pending
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

fn without_push() -> PermissionLattice {
    let mut policy = PermissionLattice::permissive();
    policy.capabilities.git_push = portcullis::CapabilityLevel::Never;
    policy
}

/// **(a) + (b): a GET with a query goes end to end with the host's
/// credential.** The ref advertisement is a GET (the remote would 404 a POST),
/// its query reaches the remote verbatim, the operator-listed protocol headers
/// are forwarded and an unlisted one is not, the credential is injected by the
/// host and never reaches the guest, and the call's record names the method,
/// path and parameter NAMES without the query's value.
#[tokio::test]
async fn a_ref_advertisement_is_a_get_with_its_query_and_the_hosts_credential() {
    let (base, hits) = remote().await;
    let pod = declared(&base, PermissionLattice::permissive());
    let mut req = advertise("git-upload-pack", "advertise");
    req.headers = BTreeMap::from([
        ("git-protocol".into(), "version=2".into()),
        ("accept".into(), "*/*".into()),
        ("x-unlisted".into(), "1".into()),
    ]);
    let heard = drive(&pod, &req, b"").await;
    assert!(heard.head.granted, "{:?}", heard.head);
    assert_eq!(heard.head.status, 200);
    assert_eq!(
        heard.head.content_type,
        "application/x-git-upload-pack-advertisement"
    );
    assert_eq!(heard.body, ADVERTISEMENT);
    assert!(
        !heard.raw.contains(TOKEN),
        "the credential reached the guest"
    );

    let hits = hits.lock().unwrap().clone();
    assert_eq!(hits.len(), 1);
    let hit = &hits[0];
    assert_eq!(hit.method, "GET");
    assert_eq!(hit.path, "/org/repo.git/info/refs");
    assert_eq!(hit.query.as_deref(), Some("service=git-upload-pack"));
    assert_eq!(
        hit.authorization.as_deref(),
        Some(&*format!("Basic {TOKEN}"))
    );
    assert_eq!(hit.git_protocol.as_deref(), Some("version=2"));
    assert_eq!(hit.accept.as_deref(), Some("*/*"));
    assert!(
        !hit.unlisted,
        "a header the operator did not list was forwarded"
    );
    assert_eq!(hit.body_len, 0);

    // The detail is a JSON string inside the lifecycle record: unescape it.
    let audit = pod.audit().replace("\\\"", "\"");
    for recorded in [
        "\"method\":\"GET\"",
        "\"path\":\"org/repo.git/info/refs\"",
        "\"query_parameters\":[\"service\"]",
        "\"headers_forwarded\":[\"accept\",\"git-protocol\"]",
    ] {
        assert!(audit.contains(recorded), "{recorded} missing from {audit}");
    }
    assert!(
        !audit.contains("git-upload-pack"),
        "the record copied the query's value: {audit}"
    );
    assert!(!audit.contains(TOKEN));
}

/// **(d): a push under a profile without push is refused by the PDP before any
/// byte leaves**; a fetch under the same profile is not, and neither is the
/// push's bodiless ref advertisement, which is a read of the same refs (#3266);
/// and the same push under a profile WITH push is performed, so the refusal is
/// about `git_push` and nothing else.
///
/// A-19: making `operation_for` call every request a `WebFetch` reds this
/// test (the push is then decided under the read capability and performed).
#[tokio::test]
async fn a_push_is_refused_by_the_pdp_under_a_profile_without_push() {
    let (base, hits) = remote().await;
    let pod = declared(&base, without_push());
    let mut send = git_open(
        EgressMethod::Post,
        "org/repo.git/git-receive-pack",
        None,
        "push",
    );
    send.content_type = "application/x-git-receive-pack-request".into();
    let pack = drive(&pod, &send, b"0000PACK").await;
    assert!(!pack.head.granted, "a push was performed: {:?}", pack.head);
    assert_eq!(pack.head.reason, "not permitted");
    assert!(
        hits.lock().unwrap().is_empty(),
        "a refused push reached the remote"
    );

    // The control: a fetch is a read, and this profile reads; so is the
    // push's advertisement, which carries nothing up and answers the refs.
    for (service, nonce) in [("git-upload-pack", "fetch"), ("git-receive-pack", "adv")] {
        let read = drive(&pod, &advertise(service, nonce), b"").await;
        assert!(read.head.granted, "{service}: {:?}", read.head);
    }
    assert_eq!(hits.lock().unwrap().len(), 2);

    // The control: with push granted, the identical push goes through.
    let (base, hits) = remote().await;
    let pod = declared(&base, PermissionLattice::permissive());
    // A push is an exfiltration vector, so the host kernel still asks the
    // operator: the refusal is now an approval request, not "not permitted".
    send.nonce = "push-allowed".into();
    let asked = drive(&pod, &send, b"0000PACK").await;
    assert!(
        asked.head.reason.starts_with("host approval required:"),
        "{:?}",
        asked.head
    );
    grant_pending(&pod);
    send.nonce = "push-approved".into();
    let pushed = drive(&pod, &send, b"0000PACK").await;
    assert!(pushed.head.granted, "{:?}", pushed.head);
    assert_eq!(pushed.body, RESULT);
    let hits = hits.lock().unwrap().clone();
    assert_eq!((hits[0].method.as_str(), hits[0].body_len), ("POST", 8));
}

/// The pack of a push: the request that carries the session's data up.
fn receive_pack(nonce: &str) -> StreamRequest {
    let mut send = git_open(
        EgressMethod::Post,
        "org/repo.git/git-receive-pack",
        None,
        nonce,
    );
    send.content_type = "application/x-git-receive-pack-request".into();
    send
}

/// The safe-pr-fixer profile has no push, so a push from it is refused.
#[tokio::test]
async fn the_safe_pr_fixer_profile_cannot_push() {
    let (base, hits) = remote().await;
    let pod = declared(&base, PermissionLattice::safe_pr_fixer());
    let heard = drive(&pod, &receive_pack("fixer"), b"0000PACK").await;
    assert!(!heard.head.granted, "{:?}", heard.head);
    assert!(hits.lock().unwrap().is_empty());
}

/// A push the guest LABELS as a fetch is refused even where push is allowed:
/// the host recomputes the label from the method, path and query, and a
/// mislabelled call is not decided under the weaker capability. Both ways a
/// body can name the push service: in the path, and in the query of a POST.
#[tokio::test]
async fn a_push_labelled_as_a_fetch_is_refused() {
    let (base, hits) = remote().await;
    let pod = declared(&base, PermissionLattice::permissive());
    for mut req in [
        git_open(
            EgressMethod::Post,
            "org/repo.git/git%2Dreceive-pack",
            None,
            "label-send",
        ),
        git_open(
            EgressMethod::Post,
            "org/repo.git/info/refs",
            Some("service=git-receive-pack"),
            "label-query",
        ),
    ] {
        assert_eq!(req.operation, "GitPush");
        req.operation = "WebFetch".into();
        let heard = drive(&pod, &req, b"0000PACK").await;
        assert!(!heard.head.granted, "{:?}", heard.head);
    }
    assert!(hits.lock().unwrap().is_empty());
}

/// **(c): a credential-looking query parameter is refused before upstream
/// I/O**, as is a query smuggled into the path; the clean query is the
/// control.
#[tokio::test]
async fn a_credential_looking_query_is_refused_before_upstream_io() {
    let (base, hits) = remote().await;
    let pod = declared(&base, PermissionLattice::permissive());
    for (n, query) in [
        "service=git-upload-pack&access_token=abc",
        "token=abc",
        "service=git-upload-pack&private-token=abc",
    ]
    .into_iter()
    .enumerate()
    {
        let req = git_open(
            EgressMethod::Get,
            "org/repo.git/info/refs",
            Some(query),
            &format!("cred-{n}"),
        );
        let heard = drive(&pod, &req, b"").await;
        assert!(!heard.head.granted, "{query}: {:?}", heard.head);
    }
    let smuggled = git_open(
        EgressMethod::Get,
        "org/repo.git/info/refs?access_token=abc",
        None,
        "smuggled",
    );
    assert!(!drive(&pod, &smuggled, b"").await.head.granted);
    assert!(hits.lock().unwrap().is_empty());
    assert!(
        drive(&pod, &advertise("git-upload-pack", "clean"), b"")
            .await
            .head
            .granted
    );
}

/// A GET that uploaded a body is refused by name, and nothing is sent. This
/// is what makes the push's advertisement a read (#3266): decided as a fetch,
/// it still cannot carry a pack, or any other byte of the session, up.
#[tokio::test]
async fn a_get_with_a_body_is_refused() {
    let (base, hits) = remote().await;
    let pod = declared(&base, PermissionLattice::permissive());
    for (service, body) in [
        ("git-upload-pack", &b"x"[..]),
        ("git-receive-pack", &b"0000PACK"[..]),
    ] {
        let heard = drive(&pod, &advertise(service, service), body).await;
        assert!(!heard.head.granted);
        assert_eq!(heard.head.reason, "a GET carries no request body");
    }
    assert!(hits.lock().unwrap().is_empty());
}

/// **The method, the query and the forwarded headers are bound into the
/// approval.** An operator approves one GET advertisement; the same path as a
/// POST, with another query, or with another protocol header cannot spend it,
/// and the original can, once.
///
/// A-19: leaving the method out of the stream's effect description (so it is
/// always the perform path's POST) lets the POST spend the GET's approval.
#[tokio::test]
async fn an_approval_for_a_get_cannot_be_spent_as_a_post_or_another_query() {
    let (base, hits) = remote().await;
    let mut gated = PermissionLattice::permissive();
    gated.obligations.insert(portcullis::Operation::WebFetch);
    let pod = declared(&base, gated);
    let approved = || {
        let mut req = advertise("git-upload-pack", "ask");
        req.headers = BTreeMap::from([("git-protocol".into(), "version=2".into())]);
        req
    };
    let refused = drive(&pod, &approved(), b"").await;
    assert!(refused.head.reason.starts_with("host approval required:"));
    let review = grant_pending(&pod);
    assert_eq!(review.request.method, "GET");
    assert!(
        review
            .request
            .url
            .ends_with("info/refs?service=git-upload-pack")
    );
    assert_eq!(review.request.request_headers["git-protocol"], "version=2");
    let mut as_post = approved();
    as_post.nonce = "as-post".into();
    as_post.method = EgressMethod::Post;
    let mut other_query = approved();
    other_query.nonce = "other-query".into();
    other_query.query = Some("service=git-upload-pack&page=2".into());
    let mut other_header = approved();
    other_header.nonce = "other-header".into();
    other_header.headers = BTreeMap::from([("git-protocol".into(), "version=1".into())]);
    for changed in [&as_post, &other_query, &other_header] {
        let heard = drive(&pod, changed, b"").await;
        assert!(!heard.head.granted, "{changed:?} spent the approval");
    }
    assert!(hits.lock().unwrap().is_empty());
    let mut original = approved();
    original.nonce = "approved".into();
    let granted = drive(&pod, &original, b"").await;
    assert!(granted.head.granted, "{:?}", granted.head);
    assert_eq!(hits.lock().unwrap()[0].method, "GET");
}

/// **(e) A 2.3.x guest's open is refused, never read as a POST.** The change
/// is breaking by the owner's decision: an open without a method (exactly what
/// the 2.3.0 tool-proxy writes) is refused before any upstream I/O, and the
/// pin (`GUEST_RELEASE` 2.4.0 or later, `GuestCapability::EgressMethodAndQuery`) is
/// what keeps the CLI from installing that guest against this node. A frame
/// that names a method but is otherwise malformed is refused the same way.
#[tokio::test]
async fn a_2_3_guest_open_without_a_method_is_refused_not_read_as_a_post() {
    let (base, hits) = remote().await;
    let pod = declared(&base, PermissionLattice::permissive());
    let released_2_3 = serde_json::json!({
        "require_approval": false,
        "operation": "WebFetch",
        "target": "git-remote",
        "justification": "credentialed egress",
        "nonce": "released-2-3",
        "path": "org/repo.git/git-upload-pack",
        "content_type": "application/x-git-upload-pack-request",
    });
    assert_eq!(
        refusal_for(&pod, &released_2_3.to_string()).await,
        "malformed request"
    );
    let mut unknown = serde_json::to_value(advertise("git-upload-pack", "unknown")).unwrap();
    unknown["method"] = "PUT".into();
    assert_eq!(
        refusal_for(&pod, &unknown.to_string()).await,
        "malformed request"
    );
    assert!(hits.lock().unwrap().is_empty());
}

/// Send `payload` as a signed open frame with an empty body, and return the
/// refusal the host answers with.
async fn refusal_for(pod: &Pod, payload: &str) -> String {
    let line = format!("{}\n", nucleus_cred_protocol::frame::sign(KEY, payload));
    let (client, server) = tokio::io::duplex(64 * 1024);
    let serving = pod.serving();
    let serve = serve_connection_with_timeout(server, &serving, Duration::from_secs(10));
    let (r, mut w) = tokio::io::split(client);
    let talk = async move {
        w.write_all(line.as_bytes()).await.unwrap();
        let _ = write_end(&mut w).await;
        let mut r = BufReader::new(r);
        read_line(&mut r, MAX_STREAM_LINE_BYTES).await.unwrap()
    };
    let ((), head) = tokio::join!(serve, talk);
    let head: StreamHead = serde_json::from_str(&head).unwrap();
    assert!(!head.granted);
    head.reason
}

/// The pod identity the federated fixture mints for.
const FEDERATED_POD: &str = "spiffe://nodes.example.invalid/ns/pods/sa/git-pod";

/// `Basic base64("token-user:minted-token-1")`, written out rather than
/// recomputed with the code under test.
const BASIC_MINTED: &str = "Basic dG9rZW4tdXNlcjptaW50ZWQtdG9rZW4tMQ==";

/// A token endpoint that answers every exchange with `minted-token-1`.
async fn token_endpoint() -> wiremock::MockServer {
    use wiremock::matchers::{method, path};
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .respond_with(
            wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "minted-token-1",
                "token_type": "Bearer",
                "expires_in": 3600,
            })),
        )
        .mount(&server)
        .await;
    server
}

/// A pod holding no credential at all, whose `git-remote` is a FEDERATED
/// registry entry with `encoding` (TOML lines) for its header value, loaded
/// through the operator registry's own parser.
fn federated(base: &str, tokens: &str, encoding: &str) -> Pod {
    let mut pod = Pod::holding(base, 1 << 30, StreamLimits::DEFAULT, &[]);
    let registry = crate::upstreams::UpstreamRegistry::from_toml_str(&format!(
        r#"
[[upstream]]
name = "git-remote"
call_charge_micro_usd = 0
base_url = "{base}"
header = "authorization"
request_headers = ["accept", "git-protocol"]
{encoding}

[upstream.credential.federated]
token_endpoint = "{tokens}/oauth/token"
grant = "token-exchange"
encoding = "form"
audience = "https://auth.forge.example.invalid"
"#
    ))
    .expect("the fixture registry loads");
    pod.upstreams = registry.resolve(registry.entries());
    let der = nucleus_federation::EcdsaP256Signer::generate_pkcs8().expect("keygen");
    let signer = nucleus_federation::EcdsaP256Signer::from_pkcs8(&der).expect("loads");
    let source = crate::federated_credential::FederatedSource::new(
        Arc::new(signer),
        "https://federation.example.invalid",
        nucleus_federation::default_client().expect("client"),
    )
    .expect("an https issuer");
    let subject = crate::federated_credential::FederationSubject::new(
        nucleus_federation::AssertionSubject::new(
            FEDERATED_POD,
            "tenant-a.example.invalid",
            "spiffe://tenant-a.example.invalid/ns/ci/sa/release",
            "ab".repeat(32),
        )
        .expect("a valid subject"),
        now() + 86_400,
    );
    pod.credentials = PodCredentials::new(
        nucleus_cred_broker::CredentialStore::new(),
        Some((Arc::new(source), subject)),
    );
    pod.identity = PodIdentity::observed_by_host(FEDERATED_POD);
    pod
}

/// Drive `req`, granting the operator approval a push asks for and driving
/// it again under a fresh nonce.
async fn drive_approved(pod: &Pod, req: &StreamRequest, body: &[u8]) -> Heard {
    let heard = drive(pod, req, body).await;
    if !heard.head.reason.starts_with("host approval required:") {
        return heard;
    }
    grant_pending(pod);
    let mut again = req.clone();
    again.nonce = format!("{}-approved", req.nonce);
    drive(pod, &again, body).await
}

/// `ls-remote` then `push`, as git sends them over smart HTTP: the two ref
/// advertisements and the two pack exchanges. The fetch pair shares a
/// federated pod; each push request gets a fresh one, because once a pod has
/// observed an upstream response its host kernel refuses a push as a flow
/// (`flow_refused`), which is a separate property from the one under test.
/// Returns what the guest heard of each request, and every pod's record.
async fn ls_remote_and_push(base: &str, tokens: &str, encoding: &str) -> (Vec<Heard>, String) {
    let mut upload = git_open(
        EgressMethod::Post,
        "org/repo.git/git-upload-pack",
        None,
        "upload",
    );
    upload.headers = BTreeMap::from([("git-protocol".into(), "version=2".into())]);
    let mut receive = git_open(
        EgressMethod::Post,
        "org/repo.git/git-receive-pack",
        None,
        "receive",
    );
    receive.content_type = "application/x-git-receive-pack-request".into();
    let mut heard = Vec::new();
    let mut audit = String::new();
    for pods in [
        vec![
            (advertise("git-upload-pack", "ls-adv"), &b""[..]),
            (upload, &b"0014command=ls-refs\n0000"[..]),
        ],
        vec![(advertise("git-receive-pack", "push-adv"), &b""[..])],
        vec![(receive, &b"0000PACK"[..])],
    ] {
        let pod = federated(base, tokens, encoding);
        for (req, body) in pods {
            heard.push(drive_approved(&pod, &req, body).await);
        }
        audit.push_str(&pod.audit());
    }
    (heard, audit)
}

/// **#3252: a smart-HTTP remote that takes only Basic auth accepts the
/// host-minted token for `ls-remote` and `push`.** The pod holds no
/// credential; the host mints one per exchange (ADR 0010) and builds
/// `Basic base64("token-user:" + token)` at injection, on the streamed path.
/// All four requests reach the remote with it and are answered, and neither
/// the guest nor the call record sees the token, its encoding or the
/// username.
///
/// A-19: the same entry as `raw` with `value_prefix = "Basic "` (the only
/// way to write it before #3252) sends `Basic minted-token-1`, and the
/// remote refuses all four.
#[tokio::test]
async fn a_basic_only_remote_accepts_the_minted_token_for_ls_remote_and_push() {
    let tokens = token_endpoint().await;
    let (base, hits) = remote_requiring(Some(BASIC_MINTED)).await;
    let (heard, audit) = ls_remote_and_push(
        &base,
        &tokens.uri(),
        r#"value_encoding = { basic = { username = "token-user" } }"#,
    )
    .await;
    assert_eq!(heard.len(), 4);
    for (n, h) in heard.iter().enumerate() {
        assert!(h.head.granted, "request {n}: {:?}", h.head);
        assert_eq!(h.head.status, 200, "request {n}: {:?}", h.head);
        for secret in ["minted-token-1", BASIC_MINTED, "dG9rZW4tdXNlcjpt"] {
            assert!(!h.raw.contains(secret), "{secret:?} reached the guest");
        }
    }
    assert_eq!(heard[1].body, RESULT);
    assert_eq!(heard[3].body, RESULT);
    let hits = hits.lock().unwrap().clone();
    let seen: Vec<_> = hits
        .iter()
        .map(|h| {
            (
                h.method.as_str(),
                h.path.as_str(),
                h.authorization.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            ("GET", "/org/repo.git/info/refs", Some(BASIC_MINTED)),
            ("POST", "/org/repo.git/git-upload-pack", Some(BASIC_MINTED)),
            ("GET", "/org/repo.git/info/refs", Some(BASIC_MINTED)),
            ("POST", "/org/repo.git/git-receive-pack", Some(BASIC_MINTED)),
        ]
    );
    assert!(
        audit.contains("egress_stream_call"),
        "no call was recorded: {audit}"
    );
    for secret in ["minted-token-1", BASIC_MINTED, "token-user"] {
        assert!(!audit.contains(secret), "{secret:?} reached the record");
    }

    // A-19: raw, prefixed the only way the registry could express it before.
    let (base, hits) = remote_requiring(Some(BASIC_MINTED)).await;
    let (heard, _) = ls_remote_and_push(&base, &tokens.uri(), r#"value_prefix = "Basic ""#).await;
    assert_eq!(heard.len(), 4);
    for h in heard {
        assert!(!h.head.granted, "a raw token was accepted: {:?}", h.head);
    }
    let hits = hits.lock().unwrap().clone();
    assert_eq!(hits.len(), 4, "{hits:?}");
    assert!(
        hits.iter()
            .all(|h| h.authorization.as_deref() == Some("Basic minted-token-1")),
        "{hits:?}"
    );
}
