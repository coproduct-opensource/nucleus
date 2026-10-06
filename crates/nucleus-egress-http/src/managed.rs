//! The adapter and its direct workload share one lifetime. The pod supervisor
//! owns containment and descendant cleanup; this helper runs at workload UID.
use std::ffi::OsString;
use std::future::{Future, IntoFuture};
use std::process::{ExitCode, ExitStatus};

use axum::Router;

type Error = Box<dyn std::error::Error>;

/// Register handlers before launching a child, so an immediate stop is observed.
pub(super) fn shutdown() -> std::io::Result<impl Future<Output = u8>> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    Ok(async move {
        tokio::select! {
            _ = interrupt.recv() => 130,
            _ = terminate.recv() => 143,
        }
    })
}

fn exit_code(status: ExitStatus) -> ExitCode {
    use std::os::unix::process::ExitStatusExt;
    let code = status
        .code()
        .or_else(|| status.signal().and_then(|s| s.checked_add(128)));
    ExitCode::from(code.and_then(|c| u8::try_from(c).ok()).unwrap_or(1))
}

/// Serve every `(listener, app)` pair, and run `command` (if any) with `env`
/// added to what it inherits, until the command exits, a server stops, or a
/// stop signal arrives.
///
/// The listeners are bound before this is called, so the command's first
/// request finds them listening.
#[expect(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "unprivileged adapter launches its declared workload inside existing pod containment"
)]
pub(super) async fn run<L>(
    servers: Vec<(L, Router)>,
    env: Vec<(String, String)>,
    command: Vec<OsString>,
    stop: impl Future<Output = u8>,
) -> Result<ExitCode, Error>
where
    L: axum::serve::Listener,
    L::Addr: std::fmt::Debug,
{
    let mut serving = tokio::task::JoinSet::new();
    for (listener, app) in servers {
        serving.spawn(axum::serve(listener, app).into_future());
    }
    tokio::pin!(stop);
    let Some((program, arguments)) = command.split_first() else {
        return tokio::select! {
            ended = serving.join_next() => {
                ended.ok_or("no upstream to serve")???;
                Ok(ExitCode::SUCCESS)
            },
            code = &mut stop => Ok(ExitCode::from(code)),
        };
    };
    // This executable itself is the admitted workload, not the privileged
    // proxy. Inherit its already-filtered environment and captured stdio.
    let mut child = tokio::process::Command::new(program)
        .args(arguments)
        .envs(env)
        .kill_on_drop(true)
        .spawn()?;
    tokio::select! {
        status = child.wait() => Ok(exit_code(status?)),
        ended = serving.join_next() => {
            child.kill().await?;
            ended.ok_or("no upstream to serve")???;
            Err("HTTP adapter stopped while the workload was running".into())
        },
        code = &mut stop => {
            child.kill().await?;
            Ok(ExitCode::from(code))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn workload_gets_its_env_and_its_exit_status_is_preserved() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let command = vec![
            "/bin/sh".into(),
            "-c".into(),
            format!("test \"$NUCLEUS_EGRESS_HTTP_URL\" = http://{address} && exit 7").into(),
        ];
        let env = vec![(
            "NUCLEUS_EGRESS_HTTP_URL".to_string(),
            format!("http://{address}"),
        )];
        let code = run(
            vec![(listener, Router::new())],
            env,
            command,
            std::future::pending(),
        )
        .await
        .unwrap();
        assert_eq!(code, ExitCode::from(7));
        // Listener lifetime is checked across actual adapter process exit by
        // the integration test. Parallel unit-test subprocesses can temporarily
        // inherit unrelated descriptors between fork and exec.
    }

    #[tokio::test]
    async fn stopping_adapter_kills_and_reaps_direct_workload() {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("pid");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let command = vec![
            "/bin/sh".into(),
            "-c".into(),
            // Write then rename: `>` creates the file before echo fills it,
            // and the poll below would read an empty pid.
            "echo $$ > \"$1.tmp\"; mv \"$1.tmp\" \"$1\"; exec sleep 30".into(),
            "fixture".into(),
            pid_file.as_os_str().into(),
        ];
        let stop = async {
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while !pid_file.exists() {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            143
        };
        let code = run(vec![(listener, Router::new())], Vec::new(), command, stop)
            .await
            .unwrap();
        assert_eq!(code, ExitCode::from(143));
        let pid: i32 = std::fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let error = nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid), None).unwrap_err();
        assert_eq!(error, nix::errno::Errno::ECHILD);
    }
}
