//! Retained review data is bounded independently of the number of approvals.
use super::{ApprovalStatus, Operator, PodPolicy};
use base64::Engine as _;
use nucleus_decision_protocol::ArgsDigest;
use nucleus_spec::host_effect_approval::{ApprovalReview, EffectRequest};

pub(crate) const MAX_REVIEW_BYTES: u64 = 64 * 1024 * 1024;
pub(super) struct Payload {
    request: EffectRequest,
    body: Vec<u8>,
}

impl PodPolicy {
    pub(crate) fn review_requested(&mut self, digest: ArgsDigest, now: u64) -> bool {
        self.approvals.prune(now);
        self.approvals.entries.values().any(|a| {
            a.digest == digest
                && a.review.is_none()
                && matches!(
                    a.view.status,
                    ApprovalStatus::Pending | ApprovalStatus::Granted
                )
        })
    }

    pub(crate) fn attach_review(
        &mut self,
        digest: ArgsDigest,
        request: EffectRequest,
        body: &[u8],
        now: u64,
    ) -> Result<(), String> {
        self.ensure_live()
            .map_err(|_| "host policy revoked or unavailable")?;
        self.approvals.prune(now);
        let retained: u64 = self
            .approvals
            .entries
            .values()
            .filter_map(|a| a.review.as_ref())
            .map(|r| r.body.len() as u64)
            .sum();
        let approval = self
            .approvals
            .entries
            .values_mut()
            .find(|a| {
                a.digest == digest
                    && matches!(
                        a.view.status,
                        ApprovalStatus::Pending | ApprovalStatus::Granted
                    )
            })
            .ok_or("approval no longer available for review")?;
        if approval.review.is_some() {
            return Ok(());
        }
        let valid = request.matches_body(body)
            && request.digest().map_err(|e| e.to_string())? == *digest.as_bytes();
        if !valid || body.len() as u64 > MAX_REVIEW_BYTES.saturating_sub(retained) {
            approval.view.status = ApprovalStatus::Refused;
            return Err(
                "host approval review unavailable: invalid binding or retained payload limit"
                    .into(),
            );
        }
        approval.review = Some(Payload {
            request,
            body: body.to_vec(),
        });
        Ok(())
    }

    pub(crate) fn refuse_missing_review(&mut self, digest: ArgsDigest) {
        for approval in self
            .approvals
            .entries
            .values_mut()
            .filter(|a| a.digest == digest && a.review.is_none())
        {
            approval.view.status = ApprovalStatus::Refused;
        }
    }

    pub(crate) fn effect_review(
        &mut self,
        _operator: Operator,
        id: uuid::Uuid,
        now: u64,
    ) -> Result<ApprovalReview, &'static str> {
        self.ensure_live()
            .map_err(|_| "host policy revoked or unavailable")?;
        self.approvals.prune(now);
        let approval = self
            .approvals
            .entries
            .get(&id)
            .ok_or("unknown or expired approval")?;
        let payload = approval
            .review
            .as_ref()
            .ok_or("request payload unavailable for this approval")?;
        Ok(ApprovalReview {
            approval: approval.view.clone(),
            request: payload.request.clone(),
            body_base64: base64::engine::general_purpose::STANDARD.encode(&payload.body),
        })
    }
}

#[cfg(test)]
mod tests;
