//! #3446: an approval that clears a hold is spent, once, by the effect it
//! cleared, whichever gate held it.
//!
//! The reference monitor peeks a grant when it releases a held operation, and
//! the grant used to be spent only by the sandbox's approver, which asks only
//! when the operation carries a static obligation. A hold the sandbox does not
//! share (the dynamic exposure gate, a policy rule) was released by the grant
//! and nothing ever spent it, so it authorized the same act again on every
//! retry until it expired.
//!
//! These are HISTORY tests over the real pieces a handler composes: the
//! monitor (`mediation::decide_and_record`) against a real `Kernel`, a real
//! `ApprovalRegistry` holding signed grants, and a real `nucleus::Sandbox`
//! writing into a temporary directory with the approver the proxy installs.
//! Each one grants, performs (or refuses) the effect, and then decides the
//! identical act again.

use super::*;
use crate::mediation::{Admitted, MediationEnv, decide_and_record};
use nucleus::Sandbox;
use nucleus_ifc_kernel::discharge::test_helpers::bundle_for_subject;
use portcullis::flow_graph::FlowGraph;
use portcullis::kernel::Kernel;
use portcullis::verdict_sink::{SinkError, VerdictSink};
use portcullis::{CapabilityLevel, PermissionLattice};
use portcullis_core::SinkClass;
use portcullis_core::policy_rules::{
    AdmissibilityRule, LabelPredicate, PolicyRuleSet, RuleVerdict,
};
use portcullis_effects::authority::Authority;
use std::sync::Arc;

const NOTES: &str = "notes.txt";

struct NoopSink;
impl VerdictSink for NoopSink {
    fn record(&self, _: VerdictContext) -> Result<(), SinkError> {
        Ok(())
    }
    fn preflight(&self, _: Operation) -> Result<(), SinkError> {
        Ok(())
    }
}

/// A signed grant of `count` uses of `key`, through the real verifier.
fn grant(registry: &ApprovalRegistry, key: &str, count: usize) {
    let body = approve_body(key, count, None, "n-3446");
    registry.approve(mint(&approver(), &body).expect("a signed grant mints"));
}

/// The monitor, as `http_kernel_decide` drives it, against `registry`.
fn decide(
    kernel: &mut Kernel,
    registry: &ApprovalRegistry,
    operation: Operation,
    subject: &str,
) -> Result<Admitted, ApiError> {
    decide_and_record(
        MediationEnv {
            sink: &NoopSink,
            actor: ActorIdentity::Unknown,
            transport: "http",
            grants: registry,
            shadow: &crate::host_decide::HostDecide::Off,
        },
        kernel,
        &FlowGraph::new(),
        operation,
        subject,
    )
    .map_err(|d| d.error)
}

/// The name the monitor holds `operation` on `subject` for, or a panic naming
/// what it did instead.
fn held_for(
    kernel: &mut Kernel,
    registry: &ApprovalRegistry,
    operation: Operation,
    subject: &str,
) -> String {
    match decide(kernel, registry, operation, subject) {
        Err(ApiError::Nucleus(nucleus::NucleusError::ApprovalRequired { operation })) => operation,
        Ok(_) => panic!("{operation:?} {subject} was admitted, not held"),
        Err(other) => panic!("{operation:?} {subject} was refused, not held: {other:?}"),
    }
}

/// Every capability on, normalized as the proxy's policy is, so the kernel
/// and the sandbox agree on the permissions a token was decided under.
fn policy() -> PermissionLattice {
    PermissionLattice::permissive().normalize()
}

/// A sandbox in a fresh directory, with the approver the proxy installs.
fn new_sandbox(
    policy: &PermissionLattice,
    registry: &Arc<ApprovalRegistry>,
) -> (tempfile::TempDir, Sandbox) {
    let dir = tempfile::tempdir().expect("tempdir");
    let sandbox = Sandbox::new(policy, dir.path())
        .expect("sandbox")
        .with_approver(Arc::new(effect_approver(Arc::clone(registry))));
    (dir, sandbox)
}

/// `write_file`'s composition after the monitor: the sandbox's own ask, the
/// one spend, the write.
fn write(
    sandbox: &Sandbox,
    registry: &ApprovalRegistry,
    admitted: Admitted,
    path: &str,
) -> Result<(), String> {
    let operation = sandbox.write_operation_for(path);
    let asks = sandbox.write_consent(path).map_err(|e| e.to_string())?;
    let consented = admit_effect(registry, admitted, asks, |key| {
        sandbox.request_approval(key)
    })
    .map_err(|e| format!("{e:?}"))?;
    let authority = Authority::new(bundle_for_subject(
        operation,
        SinkClass::WorkspaceWrite,
        path,
    ));
    match consented.approval {
        Some(approval) => {
            sandbox.write_approved(path, b"approved", consented.token, &approval, authority)
        }
        None => sandbox.write(path, b"approved", consented.token, authority),
    }
    .map_err(|e| e.to_string())
}

/// Private data, then untrusted content: the exposure every exfil leg after
/// it completes.
fn expose(kernel: &mut Kernel, registry: &ApprovalRegistry) {
    for (operation, subject) in [
        (Operation::ReadFiles, "docs/design.md"),
        (Operation::WebFetch, "https://untrusted.example/x"),
    ] {
        assert!(
            decide(kernel, registry, operation, subject).is_ok(),
            "precondition: {operation:?} is admitted"
        );
    }
}

/// THE defect. The exposure gate holds a write the policy does not obligate,
/// so the sandbox never asks. One grant clears the hold, the write lands, and
/// the identical write is held again: the grant was spent by the write.
#[test]
fn an_exposure_gate_grant_is_spent_by_the_write_it_cleared() {
    let policy = policy();
    assert!(
        !policy.requires_approval(Operation::WriteFiles),
        "precondition: no static obligation, so the sandbox does not ask"
    );
    let registry = Arc::new(ApprovalRegistry::default());
    let (dir, sandbox) = new_sandbox(&policy, &registry);
    let mut kernel = Kernel::new(policy);
    expose(&mut kernel, &registry);

    let key = held_for(&mut kernel, &registry, Operation::WriteFiles, NOTES);
    assert_eq!(key, nucleus::approval_key(Operation::WriteFiles, NOTES));
    grant(&registry, &key, 1);

    let admitted = decide(&mut kernel, &registry, Operation::WriteFiles, NOTES)
        .expect("the grant clears the exposure-gate hold");
    write(&sandbox, &registry, admitted, NOTES).expect("the approved write lands");
    assert_eq!(
        std::fs::read(dir.path().join(NOTES)).expect("written"),
        b"approved"
    );

    assert!(
        !registry.is_granted(&key),
        "the write did not spend the grant that cleared its hold"
    );
    assert_eq!(
        held_for(&mut kernel, &registry, Operation::WriteFiles, NOTES),
        key,
        "one grant bought a second write: it replays until it expires"
    );
}

/// The same history with a policy rule holding the write (kernel step 3d).
#[test]
fn a_policy_rule_grant_is_spent_by_the_write_it_cleared() {
    let policy = policy();
    let registry = Arc::new(ApprovalRegistry::default());
    let (_dir, sandbox) = new_sandbox(&policy, &registry);
    let mut kernel = Kernel::new(policy);
    let mut rules = PolicyRuleSet::new();
    rules.push(AdmissibilityRule {
        name: "writes are held for a person".to_string(),
        source_predicate: LabelPredicate::any(),
        artifact_predicate: LabelPredicate::any(),
        sink_class: SinkClass::WorkspaceWrite,
        verdict: RuleVerdict::RequiresApproval,
    });
    kernel.set_policy_rules(rules);

    let key = held_for(&mut kernel, &registry, Operation::WriteFiles, NOTES);
    grant(&registry, &key, 1);
    let admitted = decide(&mut kernel, &registry, Operation::WriteFiles, NOTES)
        .expect("the grant clears the policy-rule hold");
    write(&sandbox, &registry, admitted, NOTES).expect("the approved write lands");

    assert!(
        !registry.is_granted(&key),
        "the write did not spend the grant that cleared its hold"
    );
    assert_eq!(
        held_for(&mut kernel, &registry, Operation::WriteFiles, NOTES),
        key,
        "one grant bought a second write: it replays until it expires"
    );
}

/// Refusals spend nothing (#3443, kept): an admission a handler drops on a
/// later refusal, and a sandbox that refuses the write, both leave the grant
/// live. Then the write that does happen spends it, once.
#[test]
fn a_refusal_after_the_grant_leaves_it_unspent() {
    let policy = policy();
    let registry = Arc::new(ApprovalRegistry::default());
    let (_dir, sandbox) = new_sandbox(&policy, &registry);
    let mut refusing = policy.clone();
    refusing.capabilities.write_files = CapabilityLevel::Never;
    let (_refusing_dir, refusing_sandbox) = new_sandbox(&refusing, &registry);
    let mut kernel = Kernel::new(policy);
    expose(&mut kernel, &registry);
    let key = held_for(&mut kernel, &registry, Operation::WriteFiles, NOTES);
    grant(&registry, &key, 1);

    // A handler that refuses after the monitor (a discharge, a URL check)
    // returns early and drops the admission.
    let dropped = decide(&mut kernel, &registry, Operation::WriteFiles, NOTES).expect("cleared");
    drop(dropped);
    assert!(
        registry.is_granted(&key),
        "a dropped admission spent the grant"
    );

    // The effect's own gate refuses before the spend.
    let refused = decide(&mut kernel, &registry, Operation::WriteFiles, NOTES).expect("cleared");
    assert!(
        write(&refusing_sandbox, &registry, refused, NOTES).is_err(),
        "precondition: this sandbox refuses the write"
    );
    assert!(registry.is_granted(&key), "a refused write spent the grant");

    let admitted = decide(&mut kernel, &registry, Operation::WriteFiles, NOTES).expect("cleared");
    write(&sandbox, &registry, admitted, NOTES).expect("the approved write lands");
    assert!(!registry.is_granted(&key), "and the write spent it");
}

/// One decision, one spend: when the monitor and the sandbox both ask (a
/// static obligation), they ask for the same name, and one write spends one
/// use of it, not one per gate.
#[test]
fn one_write_spends_one_approval_when_both_gates_ask() {
    let mut policy = policy();
    policy.obligations.insert(Operation::WriteFiles);
    let registry = Arc::new(ApprovalRegistry::default());
    let (dir, sandbox) = new_sandbox(&policy, &registry);
    let mut kernel = Kernel::new(policy);

    let key = held_for(&mut kernel, &registry, Operation::WriteFiles, NOTES);
    grant(&registry, &key, 2);

    let first = decide(&mut kernel, &registry, Operation::WriteFiles, NOTES).expect("cleared");
    write(&sandbox, &registry, first, NOTES).expect("the first write lands");
    assert!(
        registry.is_granted(&key),
        "one write spent both uses: the monitor and the sandbox each spent one"
    );

    // Remove it, so the next write is a create again and asks the same name.
    std::fs::remove_file(dir.path().join(NOTES)).expect("remove");
    let second = decide(&mut kernel, &registry, Operation::WriteFiles, NOTES).expect("cleared");
    write(&sandbox, &registry, second, NOTES).expect("the second write lands");
    assert!(!registry.is_granted(&key), "two writes spent two uses");
    assert_eq!(
        held_for(&mut kernel, &registry, Operation::WriteFiles, NOTES),
        key,
        "and nothing is left"
    );
}
