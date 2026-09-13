use super::*;
use http_body_util::BodyExt;

fn complete(out: Capture, err: Capture) -> Observation {
    Observation {
        result: WorkloadResult::Exited {
            exit_code: Some(23),
            stdout_sha256: out.sha256.clone(),
            stderr_sha256: err.sha256.clone(),
            launch_hash: "a".repeat(64),
            environment: nucleus_spec::workload_result::EnvironmentIdentity::of(&Default::default()),
            program: ProgramBinding::Unavailable {
                reason: "fixture".into(),
            },
            isolation: WorkloadIsolation::Unconfined,
        },
        logs: Some((out, err)),
    }
}

#[tokio::test]
async fn retained_streams_are_exact_raw_bytes_and_readers_cannot_rewrite_them() {
    let bytes: Vec<u8> = (0..=255).cycle().take(16_385).collect();
    let (writer, reader) = channel();
    assert_eq!(
        stdout(Extension(reader.clone())).await.unwrap_err(),
        StatusCode::CONFLICT
    );
    writer.0.send_replace(complete(
        drain(&bytes[..]).await.unwrap(),
        drain(&b"err\0\xff"[..]).await.unwrap(),
    ));
    for _ in 0..2 {
        let response = stdout(Extension(reader.clone())).await.unwrap();
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/octet-stream"
        );
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "private, no-store"
        );
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .as_ref(),
            bytes
        );
    }
    assert_eq!(
        stderr(Extension(reader))
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .as_ref(),
        b"err\0\xff"
    );
}

#[tokio::test]
async fn overflow_drains_and_hashes_every_byte_but_never_returns_a_prefix() {
    let bytes = b"longer than the capture limit";
    let captured = drain_bounded(&bytes[..], 8).await.unwrap();
    assert_eq!(captured.sha256, hex::encode(Sha256::digest(bytes)));
    assert!(captured.bytes.is_none());
    let (writer, reader) = channel();
    writer
        .0
        .send_replace(complete(captured, drain(&b""[..]).await.unwrap()));
    assert_eq!(
        stdout(Extension(reader.clone())).await.unwrap_err(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert!(
        stderr(Extension(reader))
            .await
            .unwrap()
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .is_empty()
    );
    let exact = drain_bounded(&b"12345678"[..], 8).await.unwrap();
    assert_eq!(exact.bytes.as_deref(), Some(b"12345678".as_slice()));
}
