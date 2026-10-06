//! A plain `git push` from a pod, approved by a human who takes minutes
//! (#3266).
//!
//! ```text
//! git (the real client) --HTTP--> door --signed stream open--> host serving
//!   path (this node's, unchanged) --HTTP--> fake smart-HTTP remote
//! ```
//!
//! The door does what the guest's tool-proxy does with a workload's request:
//! it labels the call with the shared classifier and opens a stream to the
//! host with a bounded approval wait, so a held request answers the client
//! with a refusal once the wait runs out. The host is the real serving path,
//! with this pod's clock moved forward so the operator can take seven minutes
//! without the test taking them.
//!
//! Before #3266 this push could not finish. The ref advertisement was a push
//! too, held under its own approval; each retry of the push asked for the
//! advertisement again; and a pending approval lived five minutes from the
//! hold, so the operator's id expired while the workload retried.
use super::declassify::{model_call, pod_at, records};
use super::*;

/// One pkt-line: four hex digits of length (including themselves), then the
/// payload.
fn pkt(payload: &str) -> String {
    format!("{:04x}{payload}", payload.len() + 4)
}

/// A remote a real client can push to: an empty repository's receive-pack
/// advertisement, and a successful report for whatever pack arrives. It never
/// records the push, so a second identical push is byte-for-byte the first.
async fn pushable_remote() -> (String, Hits) {
    let hits: Hits = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&hits);
    let app = axum::Router::new().fallback(move |request: axum::extract::Request| {
        let log = Arc::clone(&log);
        async move {
            let (parts, body) = request.into_parts();
            let body = axum::body::to_bytes(body, 16 << 20)
                .await
                .unwrap_or_default();
            let header = |name: &str| {
                parts
                    .headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
            };
            let query = parts.uri.query().map(str::to_string);
            log.lock().unwrap().push(Hit {
                method: parts.method.to_string(),
                path: parts.uri.path().to_string(),
                query: query.clone(),
                authorization: header("authorization"),
                git_protocol: header("git-protocol"),
                accept: header("accept"),
                unlisted: false,
                body_len: body.len(),
            });
            let (content_type, reply) = match (parts.method.as_str(), query.as_deref()) {
                ("GET", Some("service=git-receive-pack")) => (
                    "application/x-git-receive-pack-advertisement",
                    format!(
                        "{}0000{}0000",
                        pkt("# service=git-receive-pack\n"),
                        pkt(&format!(
                            "{} capabilities^{{}}\0report-status delete-refs\n",
                            "0".repeat(40)
                        )),
                    ),
                ),
                ("POST", None) if parts.uri.path().ends_with("/git-receive-pack") => (
                    "application/x-git-receive-pack-result",
                    format!("{}{}0000", pkt("unpack ok\n"), pkt("ok refs/heads/main\n")),
                ),
                _ => {
                    return axum::response::Response::builder()
                        .status(404)
                        .body(axum::body::Body::from("no such route"))
                        .unwrap();
                }
            };
            axum::response::Response::builder()
                .status(200)
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

/// The door: each request the client makes becomes one stream open to the
/// host, labelled by the shared classifier, waiting at most a second for an
/// approval. Answers what the host relayed, or 403 with the host's reason.
async fn door(pod: Arc<Pod>) -> String {
    let app = axum::Router::new().fallback(move |request: axum::extract::Request| {
        let pod = Arc::clone(&pod);
        async move {
            let (parts, body) = request.into_parts();
            let body = axum::body::to_bytes(body, 16 << 20).await.unwrap();
            let method = EgressMethod::from_http(parts.method.as_str()).unwrap();
            let path = parts.uri.path().trim_start_matches('/');
            let mut req = git_open(
                method,
                path,
                parts.uri.query(),
                &uuid::Uuid::new_v4().to_string(),
            );
            req.approval_wait_seconds = 1;
            let header = |name: &str| {
                parts
                    .headers
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(str::to_string)
            };
            req.content_type = header("content-type").unwrap_or_else(|| "application/json".into());
            req.headers = ["accept", "git-protocol"]
                .into_iter()
                .filter_map(|name| Some((name.to_string(), header(name)?)))
                .collect();
            let heard = drive(&pod, &req, &body).await;
            if !heard.head.granted {
                return axum::response::Response::builder()
                    .status(403)
                    .body(axum::body::Body::from(heard.head.reason))
                    .unwrap();
            }
            axum::response::Response::builder()
                .status(heard.head.status)
                .header("content-type", heard.head.content_type)
                .body(axum::body::Body::from(heard.body))
                .unwrap()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await });
    format!("http://{addr}")
}

/// Run the real `git` in `dir` with nothing from this process's environment
/// but `PATH`, and return whether it succeeded and what it said.
async fn git(dir: &std::path::Path, args: &[&str]) -> (bool, String) {
    let home = dir.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let output = tokio::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin")
        .env("HOME", &home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .kill_on_drop(true)
        .output()
        .await
        .expect("this test runs the real git client, which must be on PATH");
    (
        output.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

fn pending(pod: &Pod) -> Vec<crate::host_decide::effects::ApprovalView> {
    pod.host_policy
        .lock()
        .unwrap()
        .list_effect_approvals(operator(), pod.streams.now_unix())
        .into_iter()
        .filter(|a| a.status == crate::host_decide::effects::ApprovalStatus::Pending)
        .collect()
}

/// Move this pod's clock to `seconds` after the hold.
fn at(pod: &Pod, seconds: u64) {
    pod.streams
        .skew
        .store(seconds, std::sync::atomic::Ordering::SeqCst);
}

/// **The acceptance (#3266).** In one pod, after a model call, the real git
/// client pushes. The ref advertisement is a read and is not held; the pack
/// is, as a declassification, and the push fails when the held request's
/// wait runs out. The workload retries at three minutes: the same pending
/// approval, the same id. The operator grants it at seven minutes; the next
/// `git push`, a plain retry, completes; the very same push again is held
/// afresh under a new id, so the approval released exactly one pack. The
/// pack's signed record names the approval; the advertisements' records are
/// reads that declassify nothing.
///
/// A-19, each driven red on this test: the pre-#3266 timing (pending approvals
/// living 300 s from the hold) leaves the operator nothing to grant at seven
/// minutes; classifying the advertisement as a push again holds the GET, so
/// the push never reaches its pack and the one pending approval is the
/// advertisement's.
#[tokio::test]
async fn a_plain_git_push_completes_after_one_approval_granted_minutes_later() {
    let (base, hits) = pushable_remote().await;
    let pod = Arc::new(pod_at(&base, PermissionLattice::permissive()).await);
    model_call(&pod).await;
    let origin = door(Arc::clone(&pod)).await;
    let work = tempfile::tempdir().unwrap();
    let dir = work.path();
    let (ok, said) = git(dir, &["-c", "init.defaultBranch=main", "init", "-q", "."]).await;
    assert!(ok, "{said}");
    let (ok, said) = git(
        dir,
        &[
            "-c",
            "user.name=agent",
            "-c",
            "user.email=agent@example.invalid",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "change",
        ],
    )
    .await;
    assert!(ok, "{said}");
    let remote = format!("{origin}/org/repo.git");
    let push = || async { git(dir, &["push", remote.as_str(), "HEAD:refs/heads/main"]).await };
    let methods = || -> Vec<String> {
        hits.lock()
            .unwrap()
            .iter()
            .map(|h| h.method.clone())
            .collect()
    };

    // The hold: the advertisement left, the pack did not.
    let (ok, said) = push().await;
    assert!(!ok, "a push left without an approval: {said}");
    assert_eq!(methods(), ["GET"], "{said}");
    let held = pending(&pod);
    assert_eq!(held.len(), 1, "{held:?}");
    assert_eq!(held[0].operation, "git_push");
    assert!(
        held[0].subject.ends_with("/org/repo.git/git-receive-pack"),
        "{}",
        held[0].subject
    );
    assert!(matches!(
        held[0].category,
        crate::host_decide::effects::ApprovalCategory::Declassification { .. }
    ));
    let id = held[0].id;

    // The workload retries before anyone looks: one pending entry, one id.
    at(&pod, 3 * 60);
    let (ok, _) = push().await;
    assert!(!ok);
    let held = pending(&pod);
    assert_eq!(held.len(), 1, "{held:?}");
    assert_eq!(held[0].id, id, "a retry churned the approval id");

    // The operator, seven minutes after the hold, reviews and grants it.
    at(&pod, 7 * 60);
    let held = pending(&pod);
    assert_eq!(
        held.iter().map(|a| a.id).collect::<Vec<_>>(),
        [id],
        "the operator found nothing to grant"
    );
    {
        let now = pod.streams.now_unix();
        let mut policy = pod.host_policy.lock().unwrap();
        let review = policy.effect_review(operator(), id, now).unwrap();
        assert_eq!(review.request.method, "POST");
        policy
            .settle_effect_approval(operator(), id, true, now)
            .unwrap();
    }

    // A plain retry of the push, after the grant: it completes.
    at(&pod, 7 * 60 + 30);
    let (ok, said) = push().await;
    assert!(ok, "the approved push did not complete: {said}");
    assert_eq!(methods(), ["GET", "GET", "GET", "POST"]);
    let pack = hits.lock().unwrap().last().unwrap().body_len;
    assert!(pack > 0, "the pack was empty");

    // The same push again: the approval is spent, so it is held afresh.
    let (ok, _) = push().await;
    assert!(!ok, "one approval released two packs");
    assert_eq!(methods(), ["GET", "GET", "GET", "POST", "GET"]);
    let held = pending(&pod);
    assert_eq!(held.len(), 1, "{held:?}");
    assert_ne!(held[0].id, id, "a spent approval was asked for again");

    // The receipts: the model call and the four advertisements are reads;
    // the one pack names the approval that declassified it.
    let records = records(&pod);
    let pushes: Vec<_> = records
        .iter()
        .filter(|r| r.authorization.operation == "git_push")
        .collect();
    assert_eq!(pushes.len(), 1);
    let declassified = pushes[0]
        .authorization
        .declassification
        .as_ref()
        .expect("the released pack names its declassification");
    assert_eq!(declassified.approval_id, id);
    let reads: Vec<_> = records
        .iter()
        .filter(|r| r.authorization.operation == "web_fetch")
        .collect();
    assert_eq!(reads.len(), 5, "model call and four advertisements");
    assert!(
        reads
            .iter()
            .all(|r| r.authorization.declassification.is_none())
    );
}
