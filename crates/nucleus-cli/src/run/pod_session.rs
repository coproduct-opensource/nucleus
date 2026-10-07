//! Teardown after a run, including agent startup and output failures.
use anyhow::{Context, Result, anyhow, bail};
use uuid::Uuid;

use super::ResolvedConfig;

pub(super) async fn cancel(config: &ResolvedConfig, pod: Uuid) -> Result<()> {
    let url = format!(
        "{}/v1/pods/{pod}/cancel",
        config.node_url.trim_end_matches('/')
    );
    let response = config
        .node_mtls_client
        .post(&url)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .context("sending pod cancellation")?;
    let status = response.status();
    if !status.is_success() {
        bail!("pod cancellation returned HTTP {status}");
    }
    Ok(())
}

pub(super) fn finish(result: Result<()>, cleanup: Result<()>, pod: Uuid) -> Result<()> {
    match (result, cleanup) {
        (result, Ok(())) => result,
        (Ok(()), Err(error)) => {
            Err(error.context(format!("run finished but pod {pod} cleanup failed")))
        }
        (Err(run), Err(cleanup)) => Err(anyhow!(
            "run failed: {run:#}; pod {pod} cleanup also failed: {cleanup:#}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_and_cleanup_outcomes_are_preserved() {
        let pod = Uuid::nil();
        assert!(finish(Ok(()), Ok(()), pod).is_ok());
        assert_eq!(
            finish(Err(anyhow!("agent exited")), Ok(()), pod)
                .unwrap_err()
                .to_string(),
            "agent exited"
        );
        let cleanup = finish(Ok(()), Err(anyhow!("node unavailable")), pod).unwrap_err();
        assert!(format!("{cleanup:#}").contains("node unavailable"));
        let both = finish(
            Err(anyhow!("agent exited")),
            Err(anyhow!("node unavailable")),
            pod,
        )
        .unwrap_err();
        assert!(both.to_string().contains("agent exited"));
        assert!(both.to_string().contains("node unavailable"));
        assert!(both.to_string().contains(&pod.to_string()));
    }
}
