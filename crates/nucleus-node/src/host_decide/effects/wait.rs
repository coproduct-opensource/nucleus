//! A bounded pause on the original staged request, never permission to retry an
//! ambiguous upstream effect. No lock is held while the operator reviews it.
use super::{ApprovalStatus, PodPolicy};
use crate::host_decide::SharedPodPolicy;
use nucleus_decision_protocol::ArgsDigest;

pub(crate) enum WaitOutcome {
    NoPendingApproval,
    Granted,
}

pub(crate) async fn for_effect(
    policy: &SharedPodPolicy,
    digest: ArgsDigest,
    now: u64,
    requested_seconds: u64,
) -> Result<WaitOutcome, String> {
    let (id, expires, mut changed) = {
        let mut state = policy.lock().map_err(|_| "host policy unavailable")?;
        state.ensure_live().map_err(|_| "host policy revoked")?;
        state.approvals.prune(now);
        let Some(approval) = state.approvals.entries.values().find(|a| {
            a.digest == digest
                && matches!(
                    a.view.status,
                    ApprovalStatus::Pending | ApprovalStatus::Granted
                )
        }) else {
            return Ok(WaitOutcome::NoPendingApproval);
        };
        if approval.review.is_none() {
            return Err("host approval review unavailable".into());
        }
        (
            approval.view.id,
            approval.view.expires_unix,
            state.approvals.changed.subscribe(),
        )
    };
    let mut revoked = PodPolicy::revocation(policy).map_err(|_| "host policy revoked")?;
    let seconds = requested_seconds
        .min(nucleus_cred_protocol::stream::MAX_APPROVAL_WAIT_SECONDS)
        .min(expires.saturating_sub(now));
    let started = tokio::time::Instant::now();
    let deadline = started + std::time::Duration::from_secs(seconds);
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(
                "host approval wait timed out; review remains available until expiry".into(),
            );
        }
        let current = now.saturating_add(started.elapsed().as_secs());
        {
            let mut state = policy.lock().map_err(|_| "host policy unavailable")?;
            state.ensure_live().map_err(|_| "host policy revoked")?;
            state.approvals.prune(current);
            let approval = state
                .approvals
                .entries
                .get(&id)
                .ok_or("host approval expired")?;
            match approval.view.status {
                ApprovalStatus::Granted => return Ok(WaitOutcome::Granted),
                ApprovalStatus::Refused => return Err("host operator refused the effect".into()),
                ApprovalStatus::Spent => return Err("host approval already consumed".into()),
                ApprovalStatus::Pending => {}
            }
        }
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => return Err("host approval wait timed out; review remains available until expiry".into()),
            result = changed.changed() => { result.map_err(|_| "host approval service unavailable")?; }
            _ = revoked.changed() => return Err("host policy revoked".into()),
        }
    }
}
