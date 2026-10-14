//! Effects that run only with a verified owner decision cited (`docs/permissions.md`,
//! "Decisions").
//!
//! A spec lists capabilities in `requires_decision` (`nucleus_spec::decision_gate`). The first
//! sink wired is credentialed egress: a pull request opened (`create_pr:<upstream>`) or a push
//! (`git_push:<upstream>`) through a named upstream, as the shared classifier labels the call.
//! A call exercising a listed capability must cite a decision id in [`DECISION_HEADER`]. The
//! effect runs only when [`require_core`] finds that decision verified against the operator's
//! trust roots, unexpired, not superseded, covering the capability and every path the effect
//! writes, and, for a one-shot decision, spent, by value, in this pod's ledger. The signed audit
//! log records the decision id beside the effect before the effect runs.
//!
//! Every refusal is by name: no id, an id with no bundle, a bundle that does not verify (forged,
//! tampered, another tenant, expired, not yet valid), a decision superseded or already spent, a
//! capability outside its scope, and an effect whose write set this proxy cannot read
//! ([`nucleus_signed_decision::Coverage::CannotTell`], a push today). A label never satisfies
//! the gate: a workspace file, a brief or a memory record that says the owner decided has no
//! path in here.
//!
//! # What is not enforced yet
//!
//! Single use is per pod. Supersession covers the bundles this pod was given. No log inclusion
//! proof is checked, and nothing revokes a decision fleet-wide before its window closes.

use std::collections::BTreeSet;

use nucleus_signed_decision::{Action, DecisionLedger, OwnerDecisionId, WriteSet};
use nucleus_spec::decision_gate::{DecisionCapability, DecisionGatedEffect};
use nucleus_spec::tool_proxy_audit::AuditEvent;

use crate::ApiError;
use crate::owner_decision::DecisionDesk;

/// The request header a gated call cites its decision in. `x-nucleus-*` is never forwarded to
/// an upstream (`workload_egress::guest_may_propose_header`).
pub(crate) const DECISION_HEADER: &str = "x-nucleus-decision";

/// The proof that an owner decision covered one effect. Minted only by [`require_core`], after
/// the ledger cited or spent the decision; carried to the audit record by value.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "a covered effect must be recorded before it runs"]
pub(crate) struct Covered {
    capability: String,
    decision: OwnerDecisionId,
    use_: Use,
}

/// How the decision was used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Use {
    /// A standing decision, cited and re-checked.
    Cited,
    /// A one-shot decision, spent in this ledger and now refused to any later call.
    Spent,
}

impl Covered {
    /// The decision that covered the effect. The audit record carries it in production.
    #[cfg(test)]
    pub(crate) const fn decision(&self) -> OwnerDecisionId {
        self.decision
    }

    /// How it was used.
    #[cfg(test)]
    pub(crate) const fn used(&self) -> Use {
        self.use_
    }

    /// The signed audit record that names the decision beside the effect: the effect's receipt.
    pub(crate) fn into_event(self, now: u64) -> AuditEvent {
        let how = match self.use_ {
            Use::Cited => "cited",
            Use::Spent => "spent",
        };
        AuditEvent {
            timestamp_unix: now,
            actor: None,
            event: "owner_decision".to_string(),
            subject: self.capability,
            result: format!("{how} {}", self.decision),
            spiffe_id: None,
            policy_rule: Some("requires_decision".to_string()),
        }
    }
}

/// What an effect writes, as the decision's scope is checked against it. Exhaustive: a gated
/// effect states whether this proxy can say.
fn writes(effect: DecisionGatedEffect) -> WriteSet<'static> {
    match effect {
        // A pack's paths are not read here, so no scope can be shown to cover them.
        DecisionGatedEffect::GitPush => WriteSet::Unknown,
        // Opening a pull request writes no repository path; what it proposes was pushed.
        DecisionGatedEffect::CreatePr => WriteSet::Known(&[]),
    }
}

fn refuse(capability: &DecisionCapability, why: impl std::fmt::Display) -> ApiError {
    ApiError::IfcDenied(format!("{capability} requires an owner decision: {why}"))
}

/// Decide whether `capability` may run, citing `cited`. `Ok(None)`: the spec does not require
/// a decision for it. `Ok(Some(_))`: a decision covered it, and a one-shot one is spent.
///
/// # Errors
/// Every refusal names the capability and the reason.
pub(crate) fn require_core(
    desk: Option<&DecisionDesk>,
    ledger: &mut DecisionLedger,
    capability: &DecisionCapability,
    cited: Option<&str>,
    now: u64,
) -> Result<Option<Covered>, ApiError> {
    let Some(desk) = desk.filter(|d| d.requires(capability)) else {
        return Ok(None);
    };
    let cited = cited.ok_or_else(|| {
        refuse(
            capability,
            format_args!("none was cited; name one in the {DECISION_HEADER} header"),
        )
    })?;
    let id = OwnerDecisionId::from_hex(cited.trim())
        .map_err(|_| refuse(capability, "the cited id is not 64 lowercase hex"))?;
    // Every bundle the pod holds, so a decision that supersedes the cited one is seen first.
    desk.hold_all(ledger, now)?;
    if ledger.get(id).is_none() {
        let decision = desk
            .load(id, now)
            .map_err(|why| refuse(capability, format_args!("decision {id} refused: {why}")))?;
        ledger
            .hold(decision)
            .map_err(|e| refuse(capability, format_args!("decision {id} refused: {e}")))?;
    }
    let name = capability.to_string();
    let action = Action {
        capability: &name,
        writes: writes(capability.effect()),
    };
    let single_use = ledger.get(id).is_some_and(|d| d.record().single_use);
    let use_ = if single_use {
        let spent = ledger
            .spend(id, &action, now)
            .map_err(|e| refuse(capability, e))?;
        debug_assert_eq!(spent.decision(), id);
        Use::Spent
    } else {
        ledger
            .cite(id, &action, now)
            .map_err(|e| refuse(capability, e))?;
        Use::Cited
    };
    Ok(Some(Covered {
        capability: name,
        decision: id,
        use_,
    }))
}

/// Check a spec's requirements against the decision material, at startup. A spec that requires
/// a decision on a pod with no trust roots, or names an upstream it does not declare, refuses to
/// start by name; an armed gate prints `decision_gate::ARMED_PREFIX` for the node.
///
/// # Errors
/// The requirement could not be enforced.
pub(crate) fn arm(
    desk: Option<DecisionDesk>,
    spec: &nucleus_spec::PodSpecInner,
) -> Result<Option<DecisionDesk>, ApiError> {
    let required = &spec.requires_decision;
    if required.is_empty() {
        return Ok(desk);
    }
    let names = nucleus_spec::decision_gate::armed_line(required);
    let Some(desk) = desk else {
        return Err(ApiError::Spec(format!(
            "the spec requires owner decisions ({names}) and this pod has no decision trust \
             roots, so none could be verified"
        )));
    };
    for cap in required {
        if !spec
            .credentialed_egress
            .iter()
            .any(|u| u.name == cap.upstream())
        {
            return Err(ApiError::Spec(format!(
                "requires_decision {cap} names upstream {:?}, which the spec does not declare",
                cap.upstream()
            )));
        }
    }
    let desk = desk.requiring(required.iter().cloned().collect());
    eprintln!("{names}");
    Ok(Some(desk))
}

/// A sub-pod keeps every requirement its parent holds for an upstream the child still has, so
/// delegation cannot shed one (ADR 0006 C4.2). Run after the child's upstreams are clamped.
pub(crate) fn inherit(spec: &mut nucleus_spec::PodSpec, parent: Option<&DecisionDesk>) {
    let Some(parent) = parent else {
        return;
    };
    let mut held: BTreeSet<DecisionCapability> =
        spec.spec.requires_decision.iter().cloned().collect();
    for cap in parent.required() {
        if spec
            .spec
            .credentialed_egress
            .iter()
            .any(|u| u.name == cap.upstream())
        {
            held.insert(cap.clone());
        }
    }
    spec.spec.requires_decision = held.into_iter().collect();
}

#[cfg(test)]
#[path = "decision_gate_tests.rs"]
mod tests;
