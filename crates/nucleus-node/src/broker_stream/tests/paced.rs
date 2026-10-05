use super::*;

#[tokio::test]
async fn ordinary_http_upload_spans_rate_windows_with_identical_payload() {
    let (base, seen) = upstream().await;
    let mut pod = Pod::new(&base, 1_000, StreamLimits::DEFAULT);
    pod.egress = crate::egress_meter::EgressMeter::new(
        portcullis::EgressCeiling::new(
            1_000,
            portcullis::EgressPace::PerWindow {
                bytes: 100,
                window_secs: std::num::NonZeroU32::new(1).unwrap(),
            },
        ),
        pod.dir.path().to_path_buf(),
        "paced-http".into(),
    );
    let request = open("model-api", "paced-normal");
    let body = vec![b'x'; 250];
    let start = std::time::Instant::now();
    let heard = drive(&pod, &request, &body).await;
    assert!(heard.head.granted, "{}", heard.head.reason);
    assert!(heard.end.unwrap().complete);
    assert!(start.elapsed() >= Duration::from_secs(2));
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].complete);
    assert_eq!(seen[0].body_len, body.len());
    assert_eq!(seen[0].body_sha256, <[u8; 32]>::from(Sha256::digest(&body)));
    assert_eq!(
        pod.egress.counted(),
        (body.len() + request.path.len() + request.content_type.len()) as u64
    );
}

#[tokio::test]
async fn cancelling_paced_body_keeps_charge_and_closes_staging_channel() {
    let dir = tempfile::tempdir().unwrap();
    let meter = crate::egress_meter::EgressMeter::new(
        portcullis::EgressCeiling::new(
            1_000,
            portcullis::EgressPace::PerWindow {
                bytes: 100,
                window_secs: std::num::NonZeroU32::new(60).unwrap(),
            },
        ),
        dir.path().to_path_buf(),
        "paced-cancel".into(),
    );
    let charge = meter.reserve_upload(250).await.unwrap();
    let (sender, receiver) = mpsc::channel(1);
    sender.send(Ok(vec![b'x'; 250])).await.unwrap();
    let mut body = upload::UploadBody::new(receiver, charge, 100);
    assert_eq!(body.recv().await.unwrap().unwrap().len(), 100);
    assert!(
        tokio::time::timeout(Duration::from_millis(20), body.recv())
            .await
            .is_err()
    );
    drop(body);
    assert!(sender.is_closed());
    assert_eq!(meter.counted(), 250);
    // The upload slot is settled; its total and pace remain charged.
    assert!(matches!(
        meter.admit(1, 100).await,
        Err(portcullis::EgressRefusal::RateExceeded { .. })
    ));
    meter
        .admit(750, 160)
        .await
        .err()
        .expect("one window still bounds new sends");
}
