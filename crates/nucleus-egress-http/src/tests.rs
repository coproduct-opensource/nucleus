use super::*;
use axum::body::{Bytes, to_bytes};
use std::sync::{Arc, Mutex};
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;

struct Fixture {
    _dir: tempfile::TempDir,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    url: String,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
async fn serve(backend: Router) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("door.sock");
    let door = tokio::net::UnixListener::bind(&path).unwrap();
    let unix = tokio::spawn(async move {
        axum::serve(door, backend).await.unwrap();
    });
    let adapter = Adapter::new(
        &format!("unix://{}", path.display()),
        "model-api".into(),
        Duration::from_secs(5),
    )
    .unwrap();
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", tcp.local_addr().unwrap());
    let http = tokio::spawn(async move {
        axum::serve(tcp, router(adapter)).await.unwrap();
    });
    Fixture {
        _dir: dir,
        tasks: vec![unix, http],
        url,
    }
}
#[expect(
    clippy::disallowed_types,
    reason = "test client drives only the local adapter fixture"
)]
fn client() -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

#[test]
fn configuration_and_paths_cannot_select_another_transport_or_door_route() {
    for address in [
        "0.0.0.0:8080",
        "192.0.2.1:8080",
        "[::]:8080",
        "localhost:8080",
    ] {
        assert!(address.parse::<Loopback>().is_err(), "{address}");
    }
    assert!("127.0.0.1:0".parse::<Loopback>().is_ok());
    for door in ["https://outside.invalid", "unix://relative", "unix:///"] {
        assert!(Adapter::new(door, "api".into(), Duration::from_secs(1)).is_err());
    }
    for upstream in ["", ".", "..", "a/b", "a%2fb", "a?b", "a\\b"] {
        assert!(
            Adapter::new(
                "unix:///tmp/door.sock",
                upstream.into(),
                Duration::from_secs(1)
            )
            .is_err()
        );
    }
    let adapter = Adapter::new(
        "unix:///tmp/door.sock",
        "api".into(),
        Duration::from_secs(1),
    )
    .unwrap();
    for path in [
        "/",
        "//read",
        "/v1/../read",
        "/v1/%2e%2e/read",
        "/v1%2fread",
        "/v1/run?q=x",
        "http://outside.invalid/run",
    ] {
        assert!(
            adapter.destination(&path.parse().unwrap()).is_err(),
            "{path}"
        );
    }
    assert_eq!(
        adapter
            .destination(&"/v1/chat/completions".parse().unwrap())
            .unwrap(),
        "http://workload-door/v1/egress/api/v1/chat/completions"
    );
}

#[tokio::test]
async fn large_upload_and_incremental_response_cross_the_real_unix_door_without_credentials() {
    let seen = Arc::new(Mutex::new(None));
    let capture = seen.clone();
    let (release, wait) = oneshot::channel::<()>();
    let wait = Arc::new(Mutex::new(Some(wait)));
    let backend = Router::new().fallback(move |request: Request| {
        let capture = capture.clone();
        let wait = wait.lock().unwrap().take().unwrap();
        async move {
            let (parts, body) = request.into_parts();
            let body = to_bytes(body, 3 * 1024 * 1024).await.unwrap();
            *capture.lock().unwrap() = Some((parts.uri.to_string(), parts.headers, body));
            let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(1);
            tokio::spawn(async move {
                tx.send(Ok(Bytes::from_static(b"data: first\n\n")))
                    .await
                    .unwrap();
                wait.await.unwrap();
                tx.send(Ok(Bytes::from_static(b"data: last\n\n")))
                    .await
                    .unwrap();
            });
            Response::builder()
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(Body::from_stream(ReceiverStream::new(rx)))
                .unwrap()
        }
    });
    let fixture = serve(backend).await;
    let body = vec![b'x'; 2 * 1024 * 1024];
    let mut response = client()
        .post(format!("{}/v1/chat/completions", fixture.url))
        .header(header::AUTHORIZATION, "Bearer must-not-forward")
        .header(header::COOKIE, "secret=must-not-forward")
        .header("x-nucleus-actor", "operator")
        .header("x-nucleus-approval-wait-seconds", "90")
        .header(header::CONTENT_TYPE, "application/json")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/event-stream"
    );
    assert_eq!(response.chunk().await.unwrap().unwrap(), "data: first\n\n");
    release.send(()).unwrap();
    assert_eq!(response.bytes().await.unwrap(), "data: last\n\n");
    let seen = seen.lock().unwrap();
    let (path, headers, received) = seen.as_ref().unwrap();
    assert_eq!(path, "/v1/egress/model-api/v1/chat/completions");
    assert_eq!(received, &body);
    assert_eq!(headers[header::CONTENT_TYPE], "application/json");
    assert_eq!(headers["x-nucleus-approval-wait-seconds"], "90");
    for name in ["authorization", "cookie", "x-nucleus-actor"] {
        assert!(!headers.contains_key(name));
    }
}

#[tokio::test]
async fn refusals_and_redirects_are_returned_without_following_or_contacting_another_route() {
    for status in [
        StatusCode::FORBIDDEN,
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::TEMPORARY_REDIRECT,
        StatusCode::SEE_OTHER,
    ] {
        let calls = Arc::new(Mutex::new(0));
        let count = calls.clone();
        let fixture = serve(Router::new().fallback(move || {
            *count.lock().unwrap() += 1;
            async move {
                (
                    status,
                    [
                        (header::LOCATION, "http://outside.invalid/escape"),
                        (header::RETRY_AFTER, "3"),
                    ],
                    "refused",
                )
            }
        }))
        .await;
        let response = client()
            .post(format!("{}/invoke", fixture.url))
            .body("payload")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()[header::RETRY_AFTER], "3");
        assert!(!response.headers().contains_key(header::LOCATION));
        assert_eq!(response.text().await.unwrap(), "refused");
        assert_eq!(*calls.lock().unwrap(), 1);
        let get = client()
            .get(format!("{}/invoke", fixture.url))
            .send()
            .await
            .unwrap();
        assert_eq!(get.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(*calls.lock().unwrap(), 1);
    }
}

#[tokio::test]
async fn a_missing_door_fails_closed_without_tcp_fallback() {
    use tower::ServiceExt as _;
    let dir = tempfile::tempdir().unwrap();
    let adapter = Adapter::new(
        &format!("unix://{}", dir.path().join("absent").display()),
        "api".into(),
        Duration::from_secs(1),
    )
    .unwrap();
    let response = router(adapter)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/invoke")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn dropping_the_http_response_closes_the_unix_response_stream() {
    let (closed, done) = oneshot::channel();
    let closed = Arc::new(Mutex::new(Some(closed)));
    let fixture = serve(Router::new().fallback(move || {
        let closed = closed.lock().unwrap().take().unwrap();
        async move {
            let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(1);
            tokio::spawn(async move {
                tx.send(Ok(Bytes::from_static(b"first"))).await.unwrap();
                tx.closed().await;
                let _ = closed.send(());
            });
            Body::from_stream(ReceiverStream::new(rx))
        }
    }))
    .await;
    let mut response = client()
        .post(format!("{}/invoke", fixture.url))
        .send()
        .await
        .unwrap();
    assert_eq!(response.chunk().await.unwrap().unwrap(), "first");
    drop(response);
    tokio::time::timeout(Duration::from_secs(2), done)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn disconnect_while_waiting_for_headers_cancels_the_unix_request() {
    struct Cancelled(Option<oneshot::Sender<()>>);
    impl Drop for Cancelled {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }
    let (entered, admitted) = oneshot::channel();
    let (closed, cancelled) = oneshot::channel();
    let signals = Arc::new(Mutex::new(Some((entered, closed))));
    let fixture = serve(Router::new().fallback(move |request: Request| {
        let (entered, closed) = signals.lock().unwrap().take().unwrap();
        async move {
            let _guard = Cancelled(Some(closed));
            to_bytes(request.into_body(), 1024).await.unwrap();
            let _ = entered.send(());
            std::future::pending::<Response>().await
        }
    }))
    .await;
    let url = format!("{}/invoke", fixture.url);
    let request = tokio::spawn(async move { client().post(url).body("pending").send().await });
    tokio::time::timeout(Duration::from_secs(2), admitted)
        .await
        .unwrap()
        .unwrap();
    request.abort();
    tokio::time::timeout(Duration::from_secs(2), cancelled)
        .await
        .unwrap()
        .unwrap();
}
