//! A bound on every wait teardown makes before it kills a pod's VMM.
//!
//! A pod's capacity reservation is released only after its VMM has exited, and the
//! VMM is killed last, after identity services drain (`firecracker_lifecycle.rs`).
//! So a teardown wait that never ends holds the node's capacity. Measured
//! 2026-10-13 on a stage node: a cancel issued while a Vertex call was in flight
//! did not return, the pod's VMM was still running 23 minutes later, and every
//! later launch was refused for capacity. The wait was a join on a listener
//! task: none of these joins had a bound.
use std::time::Duration;
use tokio::task::JoinHandle;

/// Await `task` for at most `bound`. Past it, abort the task and return without
/// awaiting it again: an aborted task stops at its next await, and a task stuck in
/// a synchronous call would hold this wait as long as the unbounded join did.
/// Returns whether the task finished inside the bound.
pub(crate) async fn join<T>(what: &str, task: &mut JoinHandle<T>, bound: Duration) -> bool {
    if tokio::time::timeout(bound, &mut *task).await.is_ok() {
        return true;
    }
    task.abort();
    tracing::warn!(
        what,
        bound_ms = u64::try_from(bound.as_millis()).unwrap_or(u64::MAX),
        "teardown wait passed its bound; task aborted and not awaited"
    );
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_finished_task_is_joined() {
        let mut task = tokio::spawn(async {});
        assert!(join("done", &mut task, Duration::from_secs(1)).await);
    }

    #[tokio::test]
    async fn a_task_that_never_ends_is_aborted_at_the_bound() {
        let mut task = tokio::spawn(std::future::pending::<()>());
        let started = std::time::Instant::now();
        assert!(!join("pending", &mut task, Duration::from_millis(50)).await);
        assert!(started.elapsed() < Duration::from_secs(1));
        let error = task.await.unwrap_err();
        assert!(error.is_cancelled());
    }
}
