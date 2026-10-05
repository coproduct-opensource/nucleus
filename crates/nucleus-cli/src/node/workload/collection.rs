//! Bounded observation before collecting evidence. Completion is not success.
use std::future::Future;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use nucleus_spec::workload_result::WorkloadResult;

use super::{HttpClient, REQUEST_TIMEOUT};

pub(super) async fn wait(client: &HttpClient, url: &reqwest::Url, within: Duration) -> Result<()> {
    until_exited(within, || async {
        let (status, bytes) = client
            .send(
                reqwest::Method::GET,
                url.as_str(),
                &[],
                &[],
                REQUEST_TIMEOUT,
            )
            .await?;
        if status != 200 {
            let detail = serde_json::to_string(&super::super::node_error_detail(&bytes))?;
            bail!("workload observation failed (HTTP {status}): {detail}");
        }
        serde_json::from_slice(&bytes).context("invalid workload result")
    })
    .await
}

async fn until_exited<F, Fut>(within: Duration, mut observe: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<WorkloadResult>>,
{
    tokio::time::timeout(within, async {
        loop {
            match observe().await? {
                WorkloadResult::Exited { .. } => return Ok(()),
                WorkloadResult::Running => tokio::time::sleep(Duration::from_secs(1)).await,
                WorkloadResult::NotConfigured => {
                    bail!("pod has no supervised workload; no execution receipt can be collected")
                }
                WorkloadResult::Unavailable { reason } => {
                    bail!("workload observation unavailable: {reason}")
                }
            }
        }
    })
    .await
    .context("timed out waiting for workload completion; pod was not cancelled")?
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_spec::workload_result::{EnvironmentIdentity, ProgramBinding, WorkloadIsolation};

    fn exited(code: Option<i32>) -> WorkloadResult {
        WorkloadResult::Exited {
            exit_code: code,
            stdout_sha256: String::new(),
            stderr_sha256: String::new(),
            launch_hash: String::new(),
            environment: EnvironmentIdentity::of(&Default::default()),
            program: ProgramBinding::Unavailable {
                reason: "fixture".into(),
            },
            isolation: WorkloadIsolation::Unconfined,
        }
    }

    #[tokio::test]
    async fn collects_evidence_for_normal_failed_and_signalled_exits() {
        for code in [Some(0), Some(23), None] {
            until_exited(Duration::from_secs(1), || {
                std::future::ready(Ok(exited(code)))
            })
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn running_workload_is_observed_until_exit() {
        let mut observations = 0;
        until_exited(Duration::from_secs(3), || {
            observations += 1;
            std::future::ready(Ok(if observations == 1 {
                WorkloadResult::Running
            } else {
                exited(Some(0))
            }))
        })
        .await
        .unwrap();
        assert_eq!(observations, 2);
    }

    #[tokio::test]
    async fn missing_or_failed_observation_is_not_retried_as_running() {
        for (result, expected) in [
            (Ok(WorkloadResult::NotConfigured), "no supervised workload"),
            (
                Ok(WorkloadResult::Unavailable {
                    reason: "pipe failed".into(),
                }),
                "pipe failed",
            ),
            (Err(anyhow::anyhow!("HTTP 503")), "HTTP 503"),
        ] {
            let mut result = Some(result);
            let error = until_exited(Duration::from_secs(1), || {
                std::future::ready(result.take().expect("terminal observation retried"))
            })
            .await
            .unwrap_err();
            assert!(error.to_string().contains(expected), "{error:#}");
        }
    }

    #[tokio::test]
    async fn deadline_bounds_poll_delay_and_unresponsive_request() {
        let duration = Duration::from_millis(10);
        let running = until_exited(duration, || std::future::ready(Ok(WorkloadResult::Running)))
            .await
            .unwrap_err();
        let stalled = until_exited(duration, std::future::pending::<Result<WorkloadResult>>)
            .await
            .unwrap_err();
        for error in [running, stalled] {
            assert!(error.to_string().contains("timed out"));
            assert!(error.to_string().contains("pod was not cancelled"));
        }
    }
}
