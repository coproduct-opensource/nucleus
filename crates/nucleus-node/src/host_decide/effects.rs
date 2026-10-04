//! Host-owned, action-bound approvals for broker effects.
use std::collections::HashMap;

use nucleus_decision_protocol::{ArgsDigest, Outcome};
use portcullis::Operation;
use portcullis::kernel::{DecisionToken, Verdict};
use uuid::Uuid;

use super::PodPolicy;
pub(crate) mod review;
pub(crate) mod wait;

const MAX_APPROVALS: usize = 1024;
const APPROVAL_TTL: u64 = 300;

/// Only the authenticated operator route can construct this authority.
pub(crate) struct Operator {
    _identity: String,
}

impl Operator {
    pub(crate) fn authenticate(identity: &str, root: &str) -> Result<Self, &'static str> {
        if identity != root {
            return Err("only the configured operator may approve host effects");
        }
        Ok(Self {
            _identity: identity.to_string(),
        })
    }
}

pub(crate) use nucleus_spec::host_effect_approval::{ApprovalStatus, ApprovalView};

struct Approval {
    review: Option<review::Payload>,
    digest: ArgsDigest,
    view: ApprovalView,
}

#[derive(Clone, Copy)]
enum Phase {
    Preflight,
    Commit,
}

struct EffectCheck {
    phase: Phase,
    charge: crate::upstreams::CallCharge,
}

pub(super) struct Approvals {
    entries: HashMap<Uuid, Approval>,
    changed: tokio::sync::watch::Sender<()>,
}

impl Approvals {
    pub(super) fn new() -> Self {
        Self {
            entries: HashMap::new(),
            changed: tokio::sync::watch::channel(()).0,
        }
    }

    fn prune(&mut self, now: u64) {
        self.entries.retain(|_, a| now < a.view.expires_unix);
    }

    pub(crate) fn list(&mut self, _operator: Operator, now: u64) -> Vec<ApprovalView> {
        self.prune(now);
        let mut entries: Vec<_> = self.entries.values().map(|a| a.view.clone()).collect();
        entries.sort_by_key(|a| a.id);
        entries
    }

    pub(crate) fn settle(
        &mut self,
        _operator: Operator,
        id: Uuid,
        grant: bool,
        now: u64,
    ) -> Result<(), &'static str> {
        self.prune(now);
        let a = self
            .entries
            .get_mut(&id)
            .ok_or("unknown or expired approval")?;
        if a.view.status != ApprovalStatus::Pending {
            return Err("approval already decided");
        }
        a.view.status = if grant {
            ApprovalStatus::Granted
        } else {
            ApprovalStatus::Refused
        };
        self.changed.send_replace(());
        Ok(())
    }

    fn check_or_request(
        &mut self,
        digest: ArgsDigest,
        op: Operation,
        subject: &str,
        now: u64,
        check: EffectCheck,
    ) -> Result<(), String> {
        let EffectCheck { phase, charge } = check;
        self.prune(now);
        if let Some(a) = self
            .entries
            .values_mut()
            .find(|a| a.digest == digest && a.view.status == ApprovalStatus::Granted)
        {
            if matches!(phase, Phase::Commit) {
                a.view.status = ApprovalStatus::Spent;
            }
            return Ok(());
        }
        if let Some(a) = self
            .entries
            .values()
            .find(|a| a.digest == digest && a.view.status == ApprovalStatus::Pending)
        {
            return Err(format!("host approval required: {}", a.view.id));
        }
        if self.entries.len() >= MAX_APPROVALS {
            return Err("too many host approvals".into());
        }
        let id = Uuid::new_v4();
        let expires_unix = now
            .checked_add(APPROVAL_TTL)
            .ok_or("approval clock overflow")?;
        self.entries.insert(
            id,
            Approval {
                review: None,
                digest,
                view: ApprovalView {
                    id,
                    operation: portcullis::grant_usage::operation_name(op).into(),
                    subject: subject.to_string(),
                    effect_sha256: hex::encode(digest.as_bytes()),
                    call_charge_micro_usd: charge.micro_usd(),
                    expires_unix,
                    status: ApprovalStatus::Pending,
                },
            },
        );
        Err(format!("host approval required: {id}"))
    }
}

/// An affine witness required to construct a host upstream call.
#[derive(Debug)]
#[must_use]
pub(crate) struct EffectPermit {
    _decisions: Vec<DecisionToken>,
    _effect: ArgsDigest,
    _record: super::evidence::Recorded,
}

#[derive(Debug)]
#[must_use]
pub(crate) struct ExecutingEffect {
    _decisions: Vec<DecisionToken>,
    _effect: ArgsDigest,
}

impl EffectPermit {
    pub(crate) fn observe(
        self,
        policy: super::SharedPodPolicy,
        now: u64,
    ) -> (ExecutingEffect, super::evidence::outcomes::Pending) {
        let Self {
            _decisions,
            _effect,
            _record,
        } = self;
        (
            ExecutingEffect {
                _decisions,
                _effect,
            },
            _record.observe(policy, now),
        )
    }
}

impl PodPolicy {
    pub(crate) fn list_effect_approvals(
        &mut self,
        operator: Operator,
        now: u64,
    ) -> Vec<ApprovalView> {
        self.approvals.list(operator, now)
    }
    pub(crate) fn settle_effect_approval(
        &mut self,
        operator: Operator,
        id: Uuid,
        grant: bool,
        now: u64,
    ) -> Result<(), &'static str> {
        self.ensure_live()
            .map_err(|_| "host policy revoked or unavailable")?;
        self.approvals.settle(operator, id, grant, now)
    }

    /// Check before credential retrieval, without spending an approval.
    pub(crate) fn preflight_effect(
        &mut self,
        digest: ArgsDigest,
        op: Operation,
        subject: &str,
        now: u64,
        charge: crate::upstreams::CallCharge,
    ) -> Result<(), String> {
        self.check_effect(
            digest,
            op,
            subject,
            now,
            EffectCheck {
                phase: Phase::Preflight,
                charge,
            },
        )
        .map(|_| ())
    }

    /// Decide the real HTTP effect, then any additional requested operation.
    /// Both are host decisions over the current shared state; the guest cannot
    /// label a network request as a file read to avoid the network capability.
    pub(crate) fn authorize_effect(
        &mut self,
        digest: ArgsDigest,
        op: Operation,
        subject: &str,
        now: u64,
        charge: crate::upstreams::CallCharge,
    ) -> Result<EffectPermit, String> {
        let tokens = self.check_effect(
            digest,
            op,
            subject,
            now,
            EffectCheck {
                phase: Phase::Commit,
                charge,
            },
        )?;
        let record = self.budget.commit(charge.usd(), || {
            self.evidence.commit(digest, op, subject, now, charge)
        })?;
        Ok(EffectPermit {
            _decisions: tokens,
            _effect: digest,
            _record: record,
        })
    }

    fn check_effect(
        &mut self,
        digest: ArgsDigest,
        op: Operation,
        subject: &str,
        now: u64,
        check: EffectCheck,
    ) -> Result<Vec<DecisionToken>, String> {
        let EffectCheck { phase, charge } = check;
        self.ensure_live()
            .map_err(|_| "host policy revoked or unavailable")?;
        self.evidence.available()?;
        if charge.usd() > self.budget.available()? {
            return Err("host budget exhausted for operator call charge".into());
        }
        let mut tokens = Vec::new();
        let mut approval_ops = Vec::new();
        for operation in [
            Some(Operation::WebFetch),
            (op != Operation::WebFetch).then_some(op),
        ]
        .into_iter()
        .flatten()
        {
            let (decision, token) = self.decide(operation, subject);
            match decision.verdict {
                Verdict::Allow => {
                    tokens.push(token.ok_or("host allowed without a decision token")?)
                }
                Verdict::RequiresApproval => approval_ops.push(operation),
                Verdict::Deny(_) => {
                    let outcome = nucleus_decision_protocol::kernel::outcome_of(&decision.verdict);
                    let Outcome::Denied { reason } = outcome else {
                        return Err("host policy refused".into());
                    };
                    return Err(format!("host policy refused: {}", super::deny_code(reason)));
                }
            }
        }
        if !approval_ops.is_empty() {
            self.approvals.check_or_request(
                digest,
                op,
                subject,
                now,
                EffectCheck { phase, charge },
            )?;
            for operation in approval_ops
                .into_iter()
                .filter(|_| matches!(phase, Phase::Commit))
            {
                tokens.push(
                    self.kernel
                        .issue_approved_token(operation, "action-bound host operator approval"),
                );
            }
        }
        Ok(tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis::{CapabilityLevel, PermissionLattice};

    const NOW: u64 = 1000;
    const SUBJECT: &str = "https://upstream.invalid/v1/commit";
    fn operator() -> Operator {
        Operator::authenticate("spiffe://test/operator", "spiffe://test/operator").unwrap()
    }
    fn gated() -> super::super::SharedPodPolicy {
        let mut policy = PermissionLattice::permissive();
        policy.obligations.insert(Operation::GitCommit);
        super::super::test_policy(policy)
    }
    fn request_and_grant(policy: &mut PodPolicy, digest: ArgsDigest) -> Uuid {
        assert!(
            policy
                .preflight_effect(
                    digest,
                    Operation::GitCommit,
                    SUBJECT,
                    NOW,
                    crate::upstreams::CallCharge::free()
                )
                .is_err()
        );
        let pending = policy.list_effect_approvals(operator(), NOW);
        let id = pending
            .iter()
            .find(|a| a.effect_sha256 == hex::encode(digest.as_bytes()))
            .unwrap()
            .id;
        policy
            .settle_effect_approval(operator(), id, true, NOW)
            .unwrap();
        id
    }

    #[test]
    fn revocation_overrides_an_approved_preflight_and_cannot_be_reapproved() {
        let policy = gated();
        let digest = ArgsDigest::new([19; 32]);
        let id = {
            let mut state = policy.lock().unwrap();
            let id = request_and_grant(&mut state, digest);
            state
                .preflight_effect(
                    digest,
                    Operation::GitCommit,
                    SUBJECT,
                    NOW,
                    crate::upstreams::CallCharge::free(),
                )
                .unwrap();
            id
        };
        PodPolicy::revoke(&policy);
        PodPolicy::revoke(&policy);
        assert!(PodPolicy::available(&policy).is_err());
        assert!(PodPolicy::observe_response(&policy, NOW).is_err());
        let mut state = policy.lock().unwrap();
        assert!(
            state
                .authorize_effect(
                    digest,
                    Operation::GitCommit,
                    SUBJECT,
                    NOW,
                    crate::upstreams::CallCharge::free()
                )
                .unwrap_err()
                .contains("revoked")
        );
        assert!(
            state
                .settle_effect_approval(operator(), id, true, NOW)
                .is_err()
        );
    }

    #[test]
    fn preflight_does_not_spend_but_commit_is_one_shot_and_action_bound() {
        let shared = gated();
        let mut policy = shared.lock().unwrap();
        let digest = ArgsDigest::new([1; 32]);
        let id = request_and_grant(&mut policy, digest);
        for _ in 0..2 {
            policy
                .preflight_effect(
                    digest,
                    Operation::GitCommit,
                    SUBJECT,
                    NOW,
                    crate::upstreams::CallCharge::free(),
                )
                .unwrap();
        }
        assert!(
            policy
                .authorize_effect(
                    ArgsDigest::new([2; 32]),
                    Operation::GitCommit,
                    SUBJECT,
                    NOW,
                    crate::upstreams::CallCharge::free()
                )
                .is_err()
        );
        let _permit = policy
            .authorize_effect(
                digest,
                Operation::GitCommit,
                SUBJECT,
                NOW,
                crate::upstreams::CallCharge::free(),
            )
            .unwrap();
        assert!(
            policy
                .authorize_effect(
                    digest,
                    Operation::GitCommit,
                    SUBJECT,
                    NOW,
                    crate::upstreams::CallCharge::free()
                )
                .is_err()
        );
        assert_eq!(
            policy
                .list_effect_approvals(operator(), NOW)
                .iter()
                .find(|a| a.id == id)
                .unwrap()
                .status,
            ApprovalStatus::Spent
        );
        assert!(
            policy
                .settle_effect_approval(operator(), id, true, NOW)
                .is_err()
        );
    }

    #[test]
    fn expired_refused_and_other_pod_approvals_cannot_execute() {
        let shared = gated();
        let mut policy = shared.lock().unwrap();
        let digest = ArgsDigest::new([1; 32]);
        let id = request_and_grant(&mut policy, digest);
        let other = gated();
        assert!(
            other
                .lock()
                .unwrap()
                .settle_effect_approval(operator(), id, true, NOW)
                .is_err()
        );
        assert!(
            policy
                .authorize_effect(
                    digest,
                    Operation::GitCommit,
                    SUBJECT,
                    NOW + APPROVAL_TTL,
                    crate::upstreams::CallCharge::free()
                )
                .is_err()
        );
        let pending = policy.list_effect_approvals(operator(), NOW + APPROVAL_TTL);
        policy
            .settle_effect_approval(operator(), pending[0].id, false, NOW + APPROVAL_TTL)
            .unwrap();
        assert!(
            policy
                .authorize_effect(
                    digest,
                    Operation::GitCommit,
                    SUBJECT,
                    NOW + APPROVAL_TTL,
                    crate::upstreams::CallCharge::free()
                )
                .is_err()
        );
        assert!(Operator::authenticate("spiffe://test/guest", "spiffe://test/operator").is_err());
        assert!(
            Operator::authenticate("spiffe://test/operator/child", "spiffe://test/operator")
                .is_err()
        );
    }

    #[test]
    fn commit_rechecks_budget_after_successful_preflight() {
        let shared = gated();
        let mut policy = shared.lock().unwrap();
        let digest = ArgsDigest::new([1; 32]);
        let id = request_and_grant(&mut policy, digest);
        policy
            .preflight_effect(
                digest,
                Operation::GitCommit,
                SUBJECT,
                NOW,
                crate::upstreams::CallCharge::free(),
            )
            .unwrap();
        let remaining = policy.budget.available().unwrap();
        policy.budget.commit(remaining, || Ok(())).unwrap();
        assert!(
            policy
                .authorize_effect(
                    digest,
                    Operation::GitCommit,
                    SUBJECT,
                    NOW,
                    crate::upstreams::CallCharge::free()
                )
                .unwrap_err()
                .contains("budget_exhausted")
        );
        assert_eq!(
            policy
                .list_effect_approvals(operator(), NOW)
                .iter()
                .find(|a| a.id == id)
                .unwrap()
                .status,
            ApprovalStatus::Granted
        );
    }

    #[test]
    fn file_label_cannot_bypass_the_actual_network_capability() {
        let mut lattice = PermissionLattice::permissive();
        lattice.capabilities.web_fetch = CapabilityLevel::Never;
        let shared = super::super::test_policy(lattice);
        assert!(
            shared
                .lock()
                .unwrap()
                .authorize_effect(
                    ArgsDigest::new([1; 32]),
                    Operation::ReadFiles,
                    SUBJECT,
                    NOW,
                    crate::upstreams::CallCharge::free()
                )
                .is_err()
        );
    }

    #[test]
    fn concurrent_preflights_share_exactly_one_commit() {
        let shared = gated();
        let digest = ArgsDigest::new([1; 32]);
        request_and_grant(&mut shared.lock().unwrap(), digest);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let shared = shared.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    shared
                        .lock()
                        .unwrap()
                        .preflight_effect(
                            digest,
                            Operation::GitCommit,
                            SUBJECT,
                            NOW,
                            crate::upstreams::CallCharge::free(),
                        )
                        .unwrap();
                    barrier.wait();
                    shared
                        .lock()
                        .unwrap()
                        .authorize_effect(
                            digest,
                            Operation::GitCommit,
                            SUBJECT,
                            NOW,
                            crate::upstreams::CallCharge::free(),
                        )
                        .is_ok()
                })
            })
            .collect();
        assert_eq!(
            workers
                .into_iter()
                .map(|worker| usize::from(worker.join().unwrap()))
                .sum::<usize>(),
            1
        );
    }
}
