//! Reporting the pool's own census, so "why does a pool of sixteen deliver two" is answerable.
//!
//! **This exists because the log is not a history.** `ci/fly-runner/README.md` says the manager's
//! log shows every start, warm-up and retirement, and it does — but `fly logs` is a TAIL. It
//! keeps the recent past and nothing older, its lines carry no timestamp of their own (the
//! envelope supplies one), and its per-machine lines say what the manager DID rather than what
//! the pool WAS. The plan that led here was going to parse that log. It would have produced a
//! brittle reader of a format nobody versions, over a window that may already be gone.
//!
//! The manager already reads the whole machine list every pass, to plan over it. Carrying that
//! observation out as rows costs one clone and is exact: the census is taken from the same
//! snapshot the pass planned over, so the numbers and the decisions they explain line up.
//!
//! **A sample, not a transition log, and the difference is stated rather than blurred.** One row
//! per managed machine per poll interval. A machine that started and stopped between two passes
//! leaves no trace, so these rows under-count churn and are honest about occupancy — which is the
//! quantity that was actually wanted. The shape is OpenTelemetry's `cicd.worker.count` by
//! `cicd.worker.state`, which has no queue-time metric to go with it; that gap is the subject.
//!
//! Reporting is OFF unless `GATEHOUSE_URL` and `GATEHOUSE_TOKEN` are both set, and a failure to
//! report is logged and never fatal. A manager that stops launching runners because a metrics
//! endpoint is down has turned an observability feature into an outage.

use crate::api::Transport;
use crate::reconcile::Worker;

/// Where the census goes, if anywhere.
pub struct Reporter {
    url: String,
    token: String,
    tenant: String,
}

impl Reporter {
    /// From the environment, or `None` when it is not configured — which is the default and is
    /// not an error.
    pub fn from_env() -> Option<Reporter> {
        let url = std::env::var("GATEHOUSE_URL").ok()?;
        let token = std::env::var("GATEHOUSE_TOKEN").ok()?;
        if url.is_empty() || token.is_empty() {
            return None;
        }
        Some(Reporter {
            url: url.trim_end_matches('/').to_string(),
            token,
            tenant: std::env::var("GATEHOUSE_TENANT").unwrap_or_else(|_| "nucleus".into()),
        })
    }

    /// The body one pass posts. Separated from the call so the encoding is testable without a
    /// transport, which is the only part of this that can be wrong in a way anybody notices.
    pub fn body(workers: &[Worker], now_secs: u64) -> String {
        let at = now_secs.saturating_mul(1_000_000);
        let events: Vec<serde_json::Value> = workers
            .iter()
            .map(|w| {
                serde_json::json!({
                    "pool": w.pool, "machine": w.machine, "state": w.state, "at_micros": at
                })
            })
            .collect();
        serde_json::json!({ "worker_events": events }).to_string()
    }

    /// Post one pass's census. `Err` is a reason to log, never a reason to stop reconciling.
    pub fn report(
        &self,
        transport: &dyn Transport,
        workers: &[Worker],
        now_secs: u64,
    ) -> Result<usize, String> {
        if workers.is_empty() {
            // An empty pool is a real observation and the route refuses an empty body, so there
            // is nothing to send and nothing wrong. Saying "0" here rather than posting keeps the
            // route's "an empty body is a caller bug" rule true from this side.
            return Ok(0);
        }
        let body = Self::body(workers, now_secs);
        let response = transport.call(
            "POST",
            &format!("{}/v1/{}/ci-facts", self.url, self.tenant),
            &self.token,
            None,
            Some(&body),
        )?;
        if response.status != 200 {
            return Err(format!(
                "gatehouse answered {} to a census of {} machine(s)",
                response.status,
                workers.len()
            ));
        }
        Ok(workers.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(pool: &str, machine: &str, state: &str) -> Worker {
        Worker {
            pool: pool.into(),
            machine: machine.into(),
            state: state.into(),
        }
    }

    /// Seconds in, micros out. Every clock in gatehouse's store is micros, and a factor of a
    /// million is the kind of wrong that looks like a plausible number.
    #[test]
    fn the_census_is_stamped_in_microseconds() {
        let body = Reporter::body(&[w("p", "m1", "started")], 1_789_034_400);
        assert!(body.contains("\"at_micros\":1789034400000000"), "{body}");
    }

    /// **Fly's own state strings, unmapped.** Renaming `started` to `busy` here would put this
    /// manager's vocabulary between a reader and the API that decides, and the whole question is
    /// why a pool whose machines the substrate calls `started` is not running jobs.
    #[test]
    fn the_state_is_the_substrates_word_for_it() {
        let body = Reporter::body(
            &[w("build", "m1", "started"), w("build", "m2", "stopped")],
            1,
        );
        assert!(body.contains("\"state\":\"started\""), "{body}");
        assert!(body.contains("\"state\":\"stopped\""), "{body}");
    }

    /// Not configured is the default and is not an error: a manager that refuses to reconcile
    /// because a metrics endpoint is unset has turned observability into an outage.
    #[test]
    fn an_empty_census_posts_nothing_and_is_not_a_failure() {
        struct Never;
        impl Transport for Never {
            fn call(
                &self,
                _: &'static str,
                _: &str,
                _: &str,
                _: Option<&str>,
                _: Option<&str>,
            ) -> Result<crate::api::Response, String> {
                panic!("an empty census must not reach the transport")
            }
        }
        let r = Reporter {
            url: "https://example.invalid".into(),
            token: "t".into(),
            tenant: "nucleus".into(),
        };
        assert_eq!(r.report(&Never, &[], 1), Ok(0));
    }
}
