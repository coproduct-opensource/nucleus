//! Own the workload until it exits and both output pipes have reached EOF.
//! The only writer is the task that owns the child; the HTTP route receives a
//! read-only handle. A guest-written exit report never enters this state.

use axum::{Extension, Json};
use nucleus_spec::workload_result::{ProgramBinding, WorkloadIsolation, WorkloadResult};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::sync::watch;

use crate::{ApiError, workload};

#[derive(Clone)]
pub(crate) struct Reader(watch::Receiver<WorkloadResult>);
pub(crate) struct Writer(watch::Sender<WorkloadResult>);

pub(crate) fn channel() -> (Writer, Reader) {
    let (writer, reader) = watch::channel(WorkloadResult::NotConfigured);
    (Writer(writer), Reader(reader))
}

pub(crate) async fn result(Extension(reader): Extension<Reader>) -> Json<WorkloadResult> {
    Json(reader.0.borrow().clone())
}

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
    writer.0.send_replace(WorkloadResult::Running);
    Ok(Some(Supervisor(tokio::spawn(async move {
        let observed = match observe(child).await {
            Ok((exit_code, stdout_sha256, stderr_sha256)) => WorkloadResult::Exited {
                exit_code,
                stdout_sha256,
                stderr_sha256,
                launch_hash: launch.hash,
                program,
                isolation,
            },
            Err(error) => WorkloadResult::Unavailable {
                reason: error.to_string(),
            },
        };
        writer.0.send_replace(observed);
    }))))
}

async fn observe(
    mut child: tokio::process::Child,
) -> std::io::Result<(Option<i32>, String, String)> {
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

async fn drain(mut stream: impl AsyncRead + Unpin) -> std::io::Result<String> {
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let size = stream.read(&mut buffer).await?;
        if size == 0 {
            break;
        }
        let bytes = &buffer[..size];
        hash.update(bytes);
        // Console rendering may be lossy; the attested hash is over raw bytes.
        // Fixed-size chunks bound memory even for a stream with no newlines.
        crate::console_line(&format!("[workload] {}", String::from_utf8_lossy(bytes)));
    }
    Ok(hex::encode(hash.finalize()))
}

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
        assert_eq!(out, hex::encode(Sha256::digest(b"out")));
        assert_eq!(err, hex::encode(Sha256::digest(b"err")));
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
            drain(bytes.as_slice()).await.expect("read raw output"),
            hex::encode(Sha256::digest(&bytes))
        );
    }
}
