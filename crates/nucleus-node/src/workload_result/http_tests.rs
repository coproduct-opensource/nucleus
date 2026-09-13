use super::*;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;

async fn probe(status: StatusCode, body: &str) -> Result<WorkloadResult, ApiError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let body = body.to_owned();
    let app = axum::Router::new().route(
        "/v1/workload/result",
        get(move || async move { (status, body) }),
    );
    let server = tokio::spawn(async move { axum::serve(listener, app).await });
    let result = fetch(&reqwest::Client::new(), &format!("http://{address}")).await;
    server.abort();
    result
}

#[tokio::test]
async fn upstream_unavailability_remains_retryable_without_becoming_an_observation() {
    for status in [
        StatusCode::INTERNAL_SERVER_ERROR,
        StatusCode::SERVICE_UNAVAILABLE,
    ] {
        let error = probe(status, "unavailable").await.unwrap_err();
        assert_eq!(
            error.into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
    assert!(matches!(
        probe(StatusCode::OK, r#"{"state":"running"}"#)
            .await
            .unwrap(),
        WorkloadResult::Running
    ));
}

#[tokio::test]
async fn invalid_and_refused_observations_are_not_transient() {
    for status in [
        StatusCode::BAD_REQUEST,
        StatusCode::UNAUTHORIZED,
        StatusCode::FORBIDDEN,
    ] {
        let error = probe(status, "refused").await.unwrap_err();
        assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
    }
    for body in ["invalid".to_owned(), "x".repeat(16 * 1024 + 1)] {
        let error = probe(StatusCode::OK, &body).await.unwrap_err();
        assert_eq!(error.into_response().status(), StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn supervisor_transport_timeout_is_reported_as_unavailable() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    // A live listener that never accepts keeps TCP connected but supplies no
    // HTTP response. Exercise the production ten-second observation deadline.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let error = fetch(&reqwest::Client::new(), &format!("http://{address}"))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("timed out"), "{error}");
    assert_eq!(
        error.into_response().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}
