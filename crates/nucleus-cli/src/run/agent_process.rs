//! An interruptible agent wait that returns to the caller's pod teardown path.
use std::future::Future;
use std::io;
use std::process::{Command, ExitStatus, Output, Stdio};

use anyhow::{Context, Result, anyhow};
use tokio::io::AsyncReadExt;

pub(super) async fn output(command: Command) -> Result<Output> {
    output_until(command, tokio::signal::ctrl_c()).await
}

enum Completion {
    Exited(io::Result<ExitStatus>),
    Interrupted(io::Result<()>),
}

async fn output_until(
    command: Command,
    interrupt: impl Future<Output = io::Result<()>>,
) -> Result<Output> {
    let mut command = tokio::process::Command::from(command);
    let mut child = command
        .kill_on_drop(true)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning agent process")?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("missing agent stdout pipe"))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("missing agent stderr pipe"))?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let completion = tokio::select! {
        result = async {
            let (status, _, _) = tokio::try_join!(
                child.wait(),
                stdout.read_to_end(&mut out),
                stderr.read_to_end(&mut err),
            )?;
            Ok(status)
        } => Completion::Exited(result),
        signal = interrupt => Completion::Interrupted(signal),
    };
    let error = match completion {
        Completion::Exited(Ok(status)) => {
            return Ok(Output {
                status,
                stdout: out,
                stderr: err,
            });
        }
        Completion::Exited(Err(error)) => anyhow!(error).context("collecting agent output"),
        Completion::Interrupted(Ok(())) => anyhow!("agent interrupted; stopping the run"),
        Completion::Interrupted(Err(error)) => anyhow!(error).context("waiting for interruption"),
    };
    // Await kill's reap before returning to pod cleanup. This owns only the
    // immediate agent child, not arbitrary detached descendants it may create.
    child
        .kill()
        .await
        .with_context(|| format!("{error:#}; stopping agent process"))?;
    Err(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ordinary_exit_preserves_output_and_failed_exit_status() {
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "printf 'ordinary output'; printf 'diagnostic' >&2; exit 7",
        ]);
        let output = output_until(command, std::future::pending()).await.unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert_eq!(output.stdout, b"ordinary output");
        assert_eq!(output.stderr, b"diagnostic");
    }

    #[tokio::test]
    async fn interruption_stops_and_reaps_the_agent() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "echo $$ > \"$1\"; exec sleep 60", "agent"]);
        command.arg(&pid_file);
        let interrupt = async {
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while !pid_file.exists() {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            Ok(())
        };
        let error = output_until(command, interrupt).await.unwrap_err();
        assert!(error.to_string().contains("interrupted"));
        let pid = std::fs::read_to_string(pid_file).unwrap();
        let status = Command::new("/bin/kill")
            .args(["-0", pid.trim()])
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(
            !status.success(),
            "agent still exists after interruption returned"
        );
    }
}
