use super::*;
use crate::audit_sink::credentials::{MAX_CREDENTIAL_TTL, admit, fake};
use tokio::net::UnixListener;

async fn serve(
    response: Vec<u8>,
) -> (
    tempfile::TempDir,
    PathBuf,
    tokio::task::JoinHandle<serde_json::Value>,
) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mint.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = BufReader::new(stream);
        let mut request = String::new();
        stream.read_line(&mut request).await.unwrap();
        stream.get_mut().write_all(&response).await.unwrap();
        serde_json::from_str(&request).unwrap()
    });
    (dir, path, task)
}

fn response(expires_at: u64) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&serde_json::json!({
        "status": "granted", "access_key_id": "scoped-id", "secret_access_key": "scoped-secret",
        "session_token": "scoped-token", "expires_at_unix": expires_at,
    }))
    .unwrap();
    bytes.push(b'\n');
    bytes
}

#[tokio::test]
async fn admitted_scope_and_lifetime_reach_service_and_grant_reaches_uploader() {
    let expiry = (SystemTime::now() + MAX_CREDENTIAL_TTL)
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (_dir, path, service) = serve(response(expiry)).await;
    let minter = connect_config(&path).unwrap();
    let grant = admit(Some(fake::target()), Some(&minter))
        .unwrap()
        .unwrap()
        .mint(MAX_CREDENTIAL_TTL)
        .await
        .unwrap();
    let request = service.await.unwrap();
    assert_eq!(
        request,
        serde_json::json!({
            "schema": "nucleus.audit-mint.v1", "ttl_seconds": MAX_CREDENTIAL_TTL.as_secs(),
            "scope": {"endpoint": null, "region": null, "bucket": "operator-audit", "prefix": "nucleus/team-a"},
        })
    );
    let env = grant.proxy_env();
    assert!(env.contains(&("AWS_ACCESS_KEY_ID", "scoped-id")));
    assert!(env.contains(&("AWS_SECRET_ACCESS_KEY", "scoped-secret")));
    assert!(env.contains(&("AWS_SESSION_TOKEN", "scoped-token")));
}

#[tokio::test]
async fn provider_refusal_and_invalid_replies_do_not_create_grants() {
    for reply in [
        b"{\"status\":\"refused\"}\n".to_vec(),
        b"secret-in-invalid-json\n".to_vec(),
        b"{\"status\":\"refused\"}".to_vec(),
        vec![b'x'; RESPONSE_LIMIT as usize + 1],
        response(1),
    ] {
        let (_dir, path, service) = serve(reply).await;
        let minter = connect_config(&path).unwrap();
        let error = admit(Some(fake::target()), Some(&minter))
            .unwrap()
            .unwrap()
            .mint(MAX_CREDENTIAL_TTL)
            .await
            .unwrap_err();
        assert!(!error.to_string().contains("secret-in-invalid-json"));
        service.await.unwrap();
    }
}

#[tokio::test]
async fn absent_service_is_a_mint_failure() {
    let dir = tempfile::tempdir().unwrap();
    let minter = connect_config(&dir.path().join("absent.sock")).unwrap();
    let error = admit(Some(fake::target()), Some(&minter))
        .unwrap()
        .unwrap()
        .mint(MAX_CREDENTIAL_TTL)
        .await
        .unwrap_err();
    assert!(matches!(
        error,
        crate::audit_sink::credentials::AuditGrantRefused::MintFailed { .. }
    ));
    assert!(connect_config(Path::new("relative.sock")).is_err());
}

#[tokio::test]
async fn stalled_service_times_out_and_connection_closes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mint.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let service = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = BufReader::new(stream);
        let mut request = String::new();
        stream.read_line(&mut request).await.unwrap();
        let mut remaining = Vec::new();
        stream.read_to_end(&mut remaining).await.unwrap();
        assert!(remaining.is_empty());
    });
    let minter = connect_config(&path).unwrap();
    let error = admit(Some(fake::target()), Some(&minter))
        .unwrap()
        .unwrap()
        .mint(MAX_CREDENTIAL_TTL)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("timed out"));
    tokio::time::timeout(Duration::from_secs(2), service)
        .await
        .unwrap()
        .unwrap();
}
