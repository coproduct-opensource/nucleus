//! A stub Firecracker API server: a real Unix socket speaking real HTTP/1.1,
//! so the transport in `firecracker_api` can be driven without a VMM.
//!
//! The only test that exercised the success path before this was
//! `it_configures_and_is_refused_by_a_real_firecracker`, which self-skips when
//! `firecracker` is not on PATH — so on any machine without the VMM, the
//! coverage runner included, `send` was never executed at all.
//!
//! Hand-rolled rather than hyper's server: this crate takes hyper with
//! `["client", "http1"]` only, and a test fixture is not a reason to widen a
//! production dependency. HTTP/1.1 with a known Content-Length is small enough
//! to answer honestly in a few lines.

/// What the stub was asked for, so a test can assert the client's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Seen {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) body: String,
}

pub(crate) struct StubVmm {
    pub(crate) sock: std::path::PathBuf,
    seen: std::sync::Arc<tokio::sync::Mutex<Vec<Seen>>>,
    _dir: tempfile::TempDir,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for StubVmm {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl StubVmm {
    /// `replies` is consumed in order; once exhausted every further request
    /// gets `204`, which is what Firecracker answers a successful PUT with.
    pub(crate) async fn start(replies: Vec<(u16, &'static str)>) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dir = tempfile::tempdir().expect("tempdir");
        let sock = dir.path().join("fc.socket");
        let listener = tokio::net::UnixListener::bind(&sock).expect("bind");
        let seen = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));

        let seen_for_task = seen.clone();
        let task = tokio::spawn(async move {
            let mut replies = replies.into_iter();
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                // Read headers, then exactly Content-Length bytes of body.
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                let head_end = loop {
                    let Ok(n) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        break None;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break Some(i + 4);
                    }
                };
                let Some(head_end) = head_end else { continue };
                let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
                let len: usize = head
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse().ok())?
                    })
                    .unwrap_or(0);
                while buf.len() < head_end + len {
                    let Ok(n) = stream.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }

                let mut request_line = head.lines().next().unwrap_or_default().split(' ');
                seen_for_task.lock().await.push(Seen {
                    method: request_line.next().unwrap_or_default().to_string(),
                    path: request_line.next().unwrap_or_default().to_string(),
                    body: String::from_utf8_lossy(&buf[head_end..]).into_owned(),
                });

                let (status, body) = replies.next().unwrap_or((204, ""));
                let response = format!(
                    "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
            }
        });

        Self {
            sock,
            seen,
            _dir: dir,
            task,
        }
    }

    pub(crate) async fn seen(&self) -> Vec<Seen> {
        self.seen.lock().await.clone()
    }
}

/// A configuration built the way production builds one, so `configure`
/// drives the real lowering rather than a hand-made request list.
#[cfg(target_os = "linux")]
pub(crate) fn sample_config() -> crate::firecracker_config::FirecrackerConfig {
    let spec: nucleus_spec::PodSpec =
        serde_json::from_str(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{}}"#)
            .expect("a minimal PodSpec deserializes");
    // Deserialized rather than hand-constructed so the spec's own defaults
    // apply — a literal would have to be edited every time a field is added.
    let image: nucleus_spec::ImageSpec = serde_json::from_str(
        r#"{"kernel_path":"/var/lib/nucleus/vmlinux",
            "rootfs_path":"/var/lib/nucleus/rootfs.ext4"}"#,
    )
    .expect("a minimal ImageSpec deserializes");
    crate::firecracker_config::FirecrackerConfig::from_spec(
        &spec,
        std::path::Path::new("/tmp/pod.log"),
        std::path::Path::new("/tmp/vsock.sock"),
        &image,
        None,
        "",
        None,
        None,
    )
}
