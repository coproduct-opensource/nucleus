//! Exercise exporter initialization in the same Tokio context as proxy startup.
#[test]
fn http_runtime_child() {
    if std::env::var_os("NUCLEUS_TEST_OTLP_CHILD").is_none() {
        return;
    }
    // Match main's crypto initialization before telemetry startup.
    let _ = rustls::crypto::ring::default_provider().install_default();
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let guard = super::init_memory_metrics().unwrap().unwrap();
        guard.0.force_flush().unwrap();
    });
}

#[test]
// The test runner must isolate exporter environment/global state in a child;
// this launches only the same test executable, not a workload shell effect.
#[allow(clippy::disallowed_methods)]
fn http_metrics_reach_signal_path_from_tokio_startup() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        process::Command,
        time::{Duration, Instant},
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let receiver = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error.to_string()),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        loop {
            let mut chunk = [0_u8; 4096];
            let count = stream.read(&mut chunk).map_err(|e| e.to_string())?;
            if count == 0 || request.len() + count > 512 * 1024 {
                return Err("invalid HTTP body".into());
            }
            request.extend_from_slice(&chunk[..count]);
            if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = std::str::from_utf8(&request[..end]).unwrap().to_lowercase();
                let length: usize = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                if request.len() >= end + 4 + length {
                    break;
                }
            }
        }
        stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/x-protobuf\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        Ok(request)
    });
    let mut child = Command::new(std::env::current_exe().unwrap());
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("OTEL_") {
            child.env_remove(key);
        }
    }
    let output = child
        .args([
            "--exact",
            "telemetry::tests::http_runtime_child",
            "--nocapture",
        ])
        .env("NUCLEUS_TEST_OTLP_CHILD", "1")
        .env(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            format!("http://{address}/base"),
        )
        .env("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
        .env("OTEL_EXPORTER_OTLP_TIMEOUT", "1000")
        .output()
        .unwrap();
    let request = receiver.join().unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let request = request.unwrap();
    assert!(request.starts_with(b"POST /base/v1/metrics HTTP/1.1\r\n"));
    assert!(
        request
            .windows(b"nucleus.resource.observation.success".len())
            .any(|w| w == b"nucleus.resource.observation.success")
    );
}
