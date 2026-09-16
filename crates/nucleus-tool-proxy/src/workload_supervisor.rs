//! Own the workload until it exits and both output pipes have reached EOF.
//! The only writer is the task that owns the child; the HTTP route receives a
//! read-only handle. A guest-written exit report never enters this state.

use axum::body::Bytes;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use nucleus_spec::workload_result::{ProgramBinding, WorkloadIsolation, WorkloadResult};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::watch;

use crate::{ApiError, workload};

#[derive(Clone)]
pub(crate) struct Reader(watch::Receiver<Observation>);
pub(crate) struct Writer(watch::Sender<Observation>);

struct Observation {
    result: WorkloadResult,
    logs: Option<(Capture, Capture)>,
}

struct Capture {
    sha256: String,
    /// None means retention overflow, never an empty or truncated stream.
    bytes: Option<Bytes>,
}

pub(crate) fn channel() -> (Writer, Reader) {
    let (writer, reader) = watch::channel(Observation {
        result: WorkloadResult::NotConfigured,
        logs: None,
    });
    (Writer(writer), Reader(reader))
}

pub(crate) async fn result(Extension(reader): Extension<Reader>) -> Json<WorkloadResult> {
    Json(reader.0.borrow().result.clone())
}

pub(crate) async fn stdout(Extension(reader): Extension<Reader>) -> Result<Response, StatusCode> {
    log(&reader, false)
}

pub(crate) async fn stderr(Extension(reader): Extension<Reader>) -> Result<Response, StatusCode> {
    log(&reader, true)
}

fn log(reader: &Reader, stderr: bool) -> Result<Response, StatusCode> {
    let observed = reader.0.borrow();
    let (out, err) = observed.logs.as_ref().ok_or(StatusCode::CONFLICT)?;
    let captured = if stderr { err } else { out };
    let bytes = captured
        .bytes
        .as_ref()
        .ok_or(StatusCode::PAYLOAD_TOO_LARGE)?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CACHE_CONTROL, "private, no-store"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
        bytes.clone(),
    )
        .into_response())
}

/// Runs once when the workload has exited, BEFORE that exit is published, so a
/// published exit implies the hook finished. Used to write the exit report at the
/// moment nothing further is mediated (`exit_report::on_workload_exit`).
pub(crate) type ExitHook =
    Box<dyn FnOnce() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send>;

/// Dropping the server's guard cancels observation and drops the child whose
/// admitted spawn set `kill_on_drop`. A detached observer would outlive a pod.
pub(crate) struct Supervisor(tokio::task::JoinHandle<()>);

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub(crate) fn start(
    spec: &nucleus_spec::PodSpec,
    bound: workload::BoundProxy,
    auth_secret: &str,
    writer: Writer,
    on_exit: Option<ExitHook>,
) -> Result<Option<Supervisor>, ApiError> {
    let program = match nucleus_spec::identity::program_digest(spec) {
        Ok(digest) => ProgramBinding::Bound { digest },
        Err(error) => ProgramBinding::Unavailable {
            reason: error.to_string(),
        },
    };
    let Some((child, launch)) = workload::start_if_configured(spec, bound, auth_secret)? else {
        crate::console_line("[workload] no workload configured in pod spec");
        return Ok(None);
    };
    crate::console_line(&format!("[workload] started (pid={:?})", child.id()));
    let isolation = if launch.hardened && launch.uid_boundary == "distinct" {
        WorkloadIsolation::UidIsolated
    } else {
        WorkloadIsolation::Unconfined
    };
    writer.0.send_replace(Observation {
        result: WorkloadResult::Running,
        logs: None,
    });
    Ok(Some(Supervisor(tokio::spawn(async move {
        let observed = match observe(child).await {
            Ok((exit_code, stdout, stderr)) => Observation {
                result: WorkloadResult::Exited {
                    exit_code,
                    stdout_sha256: stdout.sha256.clone(),
                    stderr_sha256: stderr.sha256.clone(),
                    launch_hash: launch.hash,
                    environment: launch.environment,
                    program,
                    isolation,
                },
                logs: Some((stdout, stderr)),
            },
            Err(error) => Observation {
                result: WorkloadResult::Unavailable {
                    reason: error.to_string(),
                },
                logs: None,
            },
        };
        // The hook (the exit report) runs BEFORE the exit is published. A caller
        // that sees `Exited` may end the pod at once — the node ends a microVM by
        // killing it — and a report still being written then is lost. Measured:
        // one run in five produced no receipt while the order was the other way.
        if let Some(hook) = on_exit {
            hook().await;
        }
        writer.0.send_replace(observed);
    }))))
}

async fn observe(
    mut child: tokio::process::Child,
) -> std::io::Result<(Option<i32>, Capture, Capture)> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("workload stdout was not captured"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("workload stderr was not captured"))?;
    // Poll all three together: waiting before draining deadlocks a child that
    // fills a pipe. No successful observation exists until both hashes finish.
    let (status, stdout, stderr) = tokio::join!(child.wait(), drain(stdout), drain(stderr));
    Ok((status?.code(), stdout?, stderr?))
}

async fn drain(stream: impl AsyncRead + Unpin) -> std::io::Result<Capture> {
    drain_bounded(stream, nucleus_spec::workload_result::MAX_LOG_BYTES).await
}

async fn drain_bounded(
    mut stream: impl AsyncRead + Unpin,
    limit: usize,
) -> std::io::Result<Capture> {
    let mut hash = Sha256::new();
    let mut retained = Some(Vec::new());
    let mut buffer = [0u8; 8192];
    let mut line = Vec::new();
    let mut emit = |bytes: &[u8]| {
        crate::console_line(&format!("[workload] {}", String::from_utf8_lossy(bytes)));
    };
    loop {
        let size = stream.read(&mut buffer).await?;
        if size == 0 {
            break;
        }
        let bytes = &buffer[..size];
        hash.update(bytes);
        if let Some(output) = &mut retained {
            if output.len().saturating_add(bytes.len()) <= limit {
                output.extend_from_slice(bytes);
            } else {
                retained = None;
            }
        }
        render(bytes, &mut line, &mut emit);
    }
    if !line.is_empty() {
        emit(&line);
    }
    Ok(Capture {
        sha256: hex::encode(hash.finalize()),
        bytes: retained.map(Bytes::from),
    })
}

/// Keep ordinary console lines intact across pipe reads: boot probes inspect
/// their sentinels. Bound oversized lines without changing the raw-byte hash.
fn render(bytes: &[u8], line: &mut Vec<u8>, emit: &mut impl FnMut(&[u8])) {
    for byte in bytes {
        if *byte == b'\n' {
            emit(line);
            line.clear();
        } else {
            line.push(*byte);
            if line.len() == 8192 {
                emit(line);
                line.clear();
            }
        }
    }
}

#[cfg(test)]
mod log_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    #[expect(
        clippy::disallowed_methods,
        reason = "#1216: controlled test child exercises wait and pipe observation; production uses the admitted spawn"
    )]
    fn command(program: &str) -> tokio::process::Command {
        tokio::process::Command::new(program)
    }

    #[tokio::test]
    async fn the_observation_uses_the_real_exit_and_both_raw_streams() {
        let child = command("sh")
            .args(["-c", "printf out; printf err >&2; exit 23"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn shell");
        let (code, out, err) = observe(child).await.expect("complete observation");
        assert_eq!(code, Some(23));
        assert_eq!(out.sha256, hex::encode(Sha256::digest(b"out")));
        assert_eq!(err.sha256, hex::encode(Sha256::digest(b"err")));
        assert_eq!(out.bytes.as_deref(), Some(b"out".as_slice()));
        assert_eq!(err.bytes.as_deref(), Some(b"err".as_slice()));
    }

    #[tokio::test]
    async fn a_signal_is_not_a_successful_exit() {
        let child = command("sh")
            .args(["-c", "kill -TERM $$"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn shell");
        assert_eq!(observe(child).await.expect("observed signal").0, None);
    }

    #[tokio::test]
    async fn a_missing_pipe_is_not_an_empty_successful_log() {
        let child = command("true")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn true");
        assert!(observe(child).await.is_err());
    }

    #[tokio::test]
    async fn initial_state_cannot_claim_a_workload_ran() {
        let (_writer, reader) = channel();
        assert_eq!(
            result(Extension(reader)).await.0,
            WorkloadResult::NotConfigured
        );
    }

    #[tokio::test]
    async fn output_hashes_cover_invalid_utf8_and_multiple_buffer_reads() {
        let bytes: Vec<u8> = (0..=255).cycle().take(16_385).collect();
        assert_eq!(
            drain(bytes.as_slice())
                .await
                .expect("read raw output")
                .sha256,
            hex::encode(Sha256::digest(&bytes))
        );
    }

    #[test]
    fn console_sentinels_survive_split_reads_and_long_lines_are_bounded() {
        let mut line = Vec::new();
        let mut emitted = Vec::new();
        let mut emit = |bytes: &[u8]| emitted.push(bytes.to_vec());
        render(b"PROBE PA", &mut line, &mut emit);
        render(b"SS\n", &mut line, &mut emit);
        render(&vec![b'x'; 20_000], &mut line, &mut emit);
        assert_eq!(
            emitted.first().map(Vec::as_slice),
            Some(b"PROBE PASS".as_slice())
        );
        assert!(emitted.iter().all(|chunk| chunk.len() <= 8192));
        assert!(line.len() < 8192);
    }
}
