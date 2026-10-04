use super::*;
use crate::node::{NodeArgs, NodeCommand, create_client};
use nucleus_identity::{CaClient, CsrOptions, Identity, SelfSignedCa, TlsServerConfig};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Fixture {
    client: HttpClient,
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
    server: tokio::task::JoinHandle<()>,
}

async fn fixture(approvals: Vec<ApprovalView>, redirect: bool, post_status: u16) -> Fixture {
    fixture_with_review(approvals, redirect, post_status, None).await
}
async fn fixture_with_review(
    approvals: Vec<ApprovalView>,
    redirect: bool,
    post_status: u16,
    review: Option<ApprovalReview>,
) -> Fixture {
    let ca = SelfSignedCa::new("approval-test.local").unwrap();
    async fn mint(ca: &SelfSignedCa, account: &str) -> nucleus_identity::WorkloadCertificate {
        let id = Identity::new("approval-test.local", "system", account);
        let csr = CsrOptions::new(id.to_spiffe_uri()).generate().unwrap();
        ca.sign_csr(
            csr.csr(),
            csr.private_key(),
            &id,
            std::time::Duration::from_secs(3600),
        )
        .await
        .unwrap()
    }
    let server_cert = mint(&ca, "node").await;
    let cli = mint(&ca, "cli").await;
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
    let roots = dir.path().join("roots.pem");
    std::fs::write(&cert, cli.chain_pem()).unwrap();
    std::fs::write(&key, cli.private_key_pem()).unwrap();
    std::fs::write(
        &roots,
        ca.trust_bundle()
            .roots()
            .iter()
            .map(|c| c.to_pem())
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("https://{}", listener.local_addr().unwrap());
    let client = create_client(&NodeArgs {
        url: url.clone(),
        secrets_file: None,
        auth_secret: None,
        actor: "operator".into(),
        tls_cert: Some(cert),
        tls_key: Some(key),
        trust_bundle: Some(roots),
        command: NodeCommand::Health,
    })
    .unwrap();
    let acceptor = TlsServerConfig::new(server_cert, ca.trust_bundle().clone())
        .build_acceptor()
        .unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = requests.clone();
    let server = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut bytes = [0; 4096];
                let n = stream.read(&mut bytes).await.unwrap();
                assert!(n > 0 && request.len() < 65_536);
                request.extend_from_slice(&bytes[..n]);
                if let Some(end) = request.windows(4).position(|b| b == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&request[..end]);
                    let length = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .map(|s| s.parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
            }
            let request = String::from_utf8(request).unwrap();
            let get = request.starts_with("GET ");
            let redirected = redirect && !request.starts_with("GET /unexpected ");
            let requested_review = review.as_ref().filter(|r| {
                request
                    .split_whitespace()
                    .nth(1)
                    .is_some_and(|p| p.ends_with(&r.approval.id.to_string()))
            });
            seen.lock().unwrap().push(request);
            let (status, body) = if get && redirected {
                (302, String::new())
            } else if get {
                (
                    200,
                    match requested_review {
                        Some(r) => serde_json::to_string(r).unwrap(),
                        None => serde_json::to_string(&approvals).unwrap(),
                    },
                )
            } else {
                (post_status, String::new())
            };
            let response = format!(
                "HTTP/1.1 {status} Test\r\nconnection: close\r\nlocation: /unexpected\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
        }
    });
    Fixture {
        client,
        url,
        requests,
        server,
    }
}

fn approval() -> ApprovalView {
    ApprovalView {
        id: Uuid::new_v4(),
        operation: "git_commit".into(),
        subject: "https://upstream.invalid/commit".into(),
        effect_sha256: "ab".repeat(32),
        call_charge_micro_usd: 1234,
        expires_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300,
        status: ApprovalStatus::Pending,
    }
}

#[tokio::test]
async fn mtls_review_grant_and_refuse_use_exact_pod_and_approval_routes() {
    for grant in [true, false] {
        let approval = approval();
        let f = fixture(vec![approval.clone()], false, 204).await;
        let pod = Uuid::new_v4();
        let listed = run(&f.client, &f.url, pod, &Command::List).await.unwrap();
        assert!(listed.contains("1234") && listed.contains(&approval.effect_sha256));
        let command = if grant {
            Command::Grant {
                approval_id: approval.id,
                effect_sha256: approval.effect_sha256.clone(),
            }
        } else {
            Command::Refuse {
                approval_id: approval.id,
            }
        };
        run(&f.client, &f.url, pod, &command).await.unwrap();
        let requests = f.requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 3);
        assert!(requests[0].starts_with(&format!("GET /v1/pods/{pod}/effect-approvals HTTP/1.1")));
        assert!(requests[2].starts_with(&format!(
            "POST /v1/pods/{pod}/effect-approvals/{} HTTP/1.1",
            approval.id
        )));
        assert!(requests[2].ends_with(if grant { "\"grant\"" } else { "\"refuse\"" }));
        f.server.abort();
        let _ = f.server.await;
    }
}

#[tokio::test]
async fn stale_expired_ambiguous_and_mismatched_reviews_never_post() {
    for case in 0..5 {
        let mut approval = approval();
        let mut digest = approval.effect_sha256.clone();
        if case == 0 {
            digest = "cd".repeat(32);
        }
        if case == 1 {
            approval.status = ApprovalStatus::Spent;
        }
        if case == 2 {
            approval.expires_unix = 1;
        }
        let mut entries = vec![approval.clone()];
        if case == 3 {
            entries.push(approval.clone());
        }
        if case == 4 {
            entries.clear();
        }
        let f = fixture(entries, false, 204).await;
        assert!(
            run(
                &f.client,
                &f.url,
                Uuid::new_v4(),
                &Command::Grant {
                    approval_id: approval.id,
                    effect_sha256: digest
                }
            )
            .await
            .is_err()
        );
        assert_eq!(f.requests.lock().unwrap().len(), 1);
        f.server.abort();
        let _ = f.server.await;
    }
}

#[tokio::test]
async fn redirects_and_server_refusals_do_not_report_success() {
    for redirect in [true, false] {
        let approval = approval();
        let f = fixture(vec![approval.clone()], redirect, 403).await;
        assert!(
            run(
                &f.client,
                &f.url,
                Uuid::new_v4(),
                &Command::Grant {
                    approval_id: approval.id,
                    effect_sha256: approval.effect_sha256
                }
            )
            .await
            .is_err()
        );
        assert_eq!(
            f.requests.lock().unwrap().len(),
            if redirect { 1 } else { 2 }
        );
        f.server.abort();
        let _ = f.server.await;
    }
}

#[test]
fn grant_requires_a_valid_explicit_digest_and_uuid() {
    use clap::Parser;
    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        node: NodeArgs,
    }
    let pod = Uuid::new_v4().to_string();
    let id = Uuid::new_v4().to_string();
    let args = ["nucleus", "effect-approvals", &pod, "grant", &id];
    assert!(Cli::try_parse_from(args).is_err());
    assert!(Cli::try_parse_from(args.into_iter().chain(["--effect-sha256", "bad"])).is_err());
    assert!(
        Cli::try_parse_from(
            args.into_iter()
                .chain(["--effect-sha256", &"ab".repeat(32)])
        )
        .is_ok()
    );
    assert!(Cli::try_parse_from(["nucleus", "effect-approvals", "../escape", "list"]).is_err());
}

#[tokio::test]
async fn hmac_client_cannot_settle_host_approvals() {
    let client = HttpClient::Plain(ureq::Agent::new_with_defaults());
    assert!(
        run(
            &client,
            "https://127.0.0.1:1",
            Uuid::new_v4(),
            &Command::List
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("mTLS")
    );
}

fn review_fixture() -> ApprovalReview {
    use nucleus_spec::host_effect_approval::EffectRequest;
    use sha2::{Digest, Sha256};
    let body = b"{\"action\":\"commit\"}\x1b";
    let mut approval = approval();
    let request = EffectRequest {
        operation: "GitCommit".into(),
        upstream: "api".into(),
        url: approval.subject.clone(),
        method: "POST".into(),
        credential_header: "authorization".into(),
        content_type: "application/json".into(),
        body_sha256: Sha256::digest(body).into(),
        body_bytes: body.len() as u64,
        call_charge_micro_usd: Some(approval.call_charge_micro_usd),
    };
    approval.effect_sha256 = hex::encode(request.digest().unwrap());
    ApprovalReview {
        approval,
        request,
        body_base64: base64::engine::general_purpose::STANDARD.encode(body),
    }
}

#[tokio::test]
async fn mtls_review_verifies_and_safely_renders_the_exact_payload() {
    let review = review_fixture();
    let approval = review.approval.clone();
    let f = fixture_with_review(vec![approval.clone()], false, 204, Some(review)).await;
    let output = run(
        &f.client,
        &f.url,
        Uuid::new_v4(),
        &Command::Review {
            approval_id: approval.id,
        },
    )
    .await
    .unwrap();
    assert!(output.contains("body_utf8") && output.contains("commit"));
    assert!(!output.contains('\x1b'));
    assert!(output.contains("\\u001b"));
    assert_eq!(f.requests.lock().unwrap().len(), 2);
    f.server.abort();
    let _ = f.server.await;
}

#[test]
fn review_rejects_payload_destination_tariff_and_approval_substitution() {
    let review = review_fixture();
    let expected = review.approval.clone();
    for case in 0..5 {
        let mut changed = review.clone();
        match case {
            0 => {
                changed.body_base64 =
                    base64::engine::general_purpose::STANDARD.encode(b"different body")
            }
            1 => changed.request.url.push_str("/other"),
            2 => changed.request.call_charge_micro_usd = Some(0),
            3 => changed.approval.id = Uuid::new_v4(),
            4 => changed.request.body_bytes += 1,
            _ => unreachable!(),
        }
        assert!(render_review(changed, &expected).is_err());
    }
}
