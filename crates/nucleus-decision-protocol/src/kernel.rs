//! What both ends of the shadow channel compute from a portcullis kernel (P8).
//!
//! Three facts cross the decision channel that are derived from kernel state
//! rather than read off the wire, and each is written here ONCE, for the guest
//! and the host both to call (ADR 0007 G-1):
//!
//! * [`outcome_of`]: which wire [`Outcome`] a kernel verdict is. The guest maps
//!   its own decision with it before reporting it in a `Shadow` frame, and the
//!   host maps its verdict with it before comparing. Two mappings would make
//!   "disagree" mean "the two mappings differ" as often as "the two kernels do".
//! * [`taint_report`] and [`HostTaint`]: what the guest tells the host about its
//!   flow graph, and what the host makes of it. D2 says the host computes the
//!   taint and the guest can only raise it; the raise is the protocol's
//!   [`LabelRaise`], and these two are the only producer and consumer of one.
//!   `host_taint_answers_as_the_graph_it_was_told_about` is the property that
//!   makes them a pair.
//! * [`args_digest`]: the call digest a `Decide` carries.
//!
//! Behind the `kernel` feature so the codec itself stays dependency-free.

use nucleus_ifc_kernel::{
    AuthorityLevel, ConfLevel, Freshness, IFCLabel, IntegLevel, Operation, ProvenanceSet,
};
use portcullis::SafetyCheck;
use portcullis::exposure_core::EgressAggregates;
use portcullis::flow_graph::FlowGraph;
use portcullis::kernel::{DenyReason as KernelDeny, Verdict as KernelVerdict};
use sha2::{Digest, Sha256};

use crate::codec::op_wire;
use crate::frame::{ArgsDigest, DenyReason, LabelRaise, Outcome, Subject};

/// The wire outcome of a kernel verdict. The one mapping both ends use.
pub fn outcome_of(verdict: &KernelVerdict) -> Outcome {
    match verdict {
        KernelVerdict::Allow => Outcome::Allowed,
        KernelVerdict::RequiresApproval => Outcome::ApprovalRequired,
        KernelVerdict::Deny(reason) => Outcome::Denied {
            reason: deny_class(reason),
        },
    }
}

/// The wire's closed vocabulary is coarser than the kernel's: it names which
/// kind of rule refused, not the rule. Exhaustive, so a new kernel refusal is a
/// build error here until someone decides which kind it is (ADR 0007 E-2).
fn deny_class(reason: &KernelDeny) -> DenyReason {
    match reason {
        // The session's information flow forbids it.
        KernelDeny::FlowViolation { .. }
        | KernelDeny::IfcUnsafe { .. }
        | KernelDeny::InvalidDeclassification { .. }
        | KernelDeny::DeclassificationReplayed { .. } => DenyReason::FlowRefused,
        KernelDeny::BudgetExhausted { .. } => DenyReason::BudgetExhausted,
        // Everything else is the pod's authority not reaching this call.
        KernelDeny::InsufficientCapability
        | KernelDeny::TimeExpired { .. }
        | KernelDeny::PathBlocked { .. }
        | KernelDeny::CommandBlocked { .. }
        | KernelDeny::IsolationInsufficient { .. }
        | KernelDeny::IsolationGated { .. }
        | KernelDeny::EgressBlocked { .. }
        | KernelDeny::DlcAdmissionDenied { .. }
        | KernelDeny::PolicyDenied { .. }
        | KernelDeny::EnterpriseBlocked { .. }
        | KernelDeny::DelegationDenied { .. }
        | KernelDeny::SinkScopeDenied { .. }
        | KernelDeny::ActionTermRejected { .. }
        | KernelDeny::CedarDenied { .. } => DenyReason::NotGranted,
    }
}

/// The least restrictive freshness: the label's freshness never gates a
/// decision the egress verdict makes, so a report claims none.
const NO_FRESHNESS: Freshness = Freshness {
    observed_at: u64::MAX,
    ttl_secs: 0,
};

/// What the guest's flow graph says, as a raise the host can fold in.
///
/// Carries exactly the three session aggregates the kernel's egress gate reads
/// (`EgressAggregates`): adversarial integrity, the confidentiality ceiling, and
/// the derivation ceiling. Every other dimension is at the bottom of the
/// lattice, so the raise adds nothing the graph did not say.
///
/// A POISONED graph is a graph whose taint the guest cannot vouch for — an
/// observation was dropped — so it reports [`IFCLabel::top`], the most a raise
/// can say. That is not the graph's answer (a poisoned graph denies every
/// operation, reads included, and no label can say that), but it is the nearest
/// raise, and the gap shows up as recorded disagreements rather than silence.
pub fn taint_report(graph: &FlowGraph) -> LabelRaise {
    if graph.is_poisoned() {
        return LabelRaise::new(IFCLabel::top());
    }
    let integrity = if graph.is_tainted() {
        IntegLevel::Adversarial
    } else {
        IntegLevel::Trusted
    };
    // A full literal: a field added to IFCLabel is a build error here.
    LabelRaise::new(IFCLabel {
        confidentiality: graph.session_conf_ceiling(),
        integrity,
        provenance: ProvenanceSet::EMPTY,
        freshness: NO_FRESHNESS,
        authority: AuthorityLevel::Directive,
        derivation: graph.session_taint_ceiling(),
    })
}

/// The host's taint for one pod, shared across decision channels (decision D2).
///
/// One label, starting at the bottom before observations. The host raises it
/// before delivering broker responses, independently of guest reports; guest
/// reports can raise it further. Every update uses [`HostTaint::raise`], the
/// lattice join. There is no setter and no way to lower it.
///
/// The kernel reads it through [`EgressAggregates`], the same trait it reads a
/// `FlowGraph` through, so the host's verdict comes out of the same gate the
/// guest's does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostTaint {
    label: IFCLabel,
}

impl HostTaint {
    /// A channel the host has delivered nothing on and heard nothing about.
    pub fn clean() -> Self {
        Self {
            label: IFCLabel::bottom(),
        }
    }

    /// Fold a guest report in. Never lowers: the result is the join.
    pub fn raise(&mut self, report: LabelRaise) {
        self.label = report.raise(self.label);
    }

    /// The label the host holds.
    pub fn label(&self) -> IFCLabel {
        self.label
    }
}

impl EgressAggregates for HostTaint {
    /// Never: every label the host holds arrived as a whole frame or was
    /// refused, so its state is never unprovable.
    fn is_poisoned(&self) -> bool {
        false
    }

    fn is_tainted(&self) -> bool {
        self.label.integrity == IntegLevel::Adversarial
    }

    fn session_exfiltration_check(&self, sink_max_conf: ConfLevel) -> SafetyCheck {
        if self.label.confidentiality > sink_max_conf {
            SafetyCheck::ConfidentialityViolation {
                data_conf: self.label.confidentiality,
                sink_max_conf,
            }
        } else {
            SafetyCheck::Safe
        }
    }
}

/// Domain separation for [`args_digest`].
const ARGS_DOMAIN: &[u8] = b"nucleus-decision-args-v1\0";

/// The digest a `Decide` carries for a call.
///
/// What the guest's decision points hold today is the operation and its
/// subject, so that is what is bound. P9, which moves the deciding, widens the
/// preimage to the call's full arguments; the domain string's version moves
/// with it so the two digests cannot be confused.
pub fn args_digest(op: Operation, subject: &Subject) -> ArgsDigest {
    let mut h = Sha256::new();
    h.update(ARGS_DOMAIN);
    h.update([op_wire(op)]);
    h.update(subject.as_str().as_bytes());
    ArgsDigest::new(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis::flow::NodeKind;
    use portcullis::kernel::Kernel;
    use portcullis::{ActionTerm, PermissionLattice};
    use proptest::prelude::*;

    const KINDS: [NodeKind; 8] = [
        NodeKind::UserPrompt,
        NodeKind::ToolResponse,
        NodeKind::WebContent,
        NodeKind::McpToolResult,
        NodeKind::FileRead,
        NodeKind::Secret,
        NodeKind::ModelPlan,
        NodeKind::EnvVar,
    ];

    const CAPS: [ConfLevel; 3] = [ConfLevel::Public, ConfLevel::Internal, ConfLevel::Secret];

    fn graph_of(kinds: &[NodeKind]) -> FlowGraph {
        let mut g = FlowGraph::new();
        for k in kinds {
            g.insert_observation(*k, &[], 1)
                .expect("parent-less observe");
        }
        g
    }

    fn host_told(g: &FlowGraph) -> HostTaint {
        let mut t = HostTaint::clean();
        t.raise(taint_report(g));
        t
    }

    proptest! {
        /// THE pairing property: a host told about a graph answers every
        /// question the egress gate asks exactly as the graph does.
        #[test]
        fn host_taint_answers_as_the_graph_it_was_told_about(
            picks in prop::collection::vec(0usize..KINDS.len(), 0..8),
        ) {
            let kinds: Vec<NodeKind> = picks.iter().map(|i| KINDS[*i]).collect();
            let g = graph_of(&kinds);
            let t = host_told(&g);
            prop_assert_eq!(t.is_poisoned(), g.is_poisoned());
            prop_assert_eq!(t.is_tainted(), g.is_tainted());
            for cap in CAPS {
                prop_assert_eq!(
                    t.session_exfiltration_check(cap),
                    g.session_exfiltration_check(cap)
                );
            }
            for op in Operation::ALL {
                prop_assert_eq!(t.effective_is_tainted(op), g.effective_is_tainted(op));
                for cap in CAPS {
                    prop_assert_eq!(
                        t.effective_exfiltration_check(op, cap),
                        g.effective_exfiltration_check(op, cap)
                    );
                }
            }
        }

        /// And so the kernel, reading either, decides the same.
        #[test]
        fn a_kernel_decides_the_same_over_either(
            picks in prop::collection::vec(0usize..KINDS.len(), 0..6),
        ) {
            let kinds: Vec<NodeKind> = picks.iter().map(|i| KINDS[*i]).collect();
            let g = graph_of(&kinds);
            let t = host_told(&g);
            for op in Operation::ALL {
                let term = || ActionTerm::from_operation(op, "subject");
                let mut a = Kernel::new(PermissionLattice::permissive());
                let mut b = Kernel::new(PermissionLattice::permissive());
                let (da, _) = a.decide_term_with_flow(term(), Some(&g));
                let (db, _) = b.decide_term_with_flow(term(), Some(&t));
                prop_assert_eq!(outcome_of(&da.verdict), outcome_of(&db.verdict), "{:?}", op);
                // And the effect decider — the one with an approval exit — too.
                let ea = a.decide_effect_with_flow(term(), Some(&g));
                let eb = b.decide_effect_with_flow(term(), Some(&t));
                prop_assert_eq!(outcome_of(&ea.decision.verdict), outcome_of(&eb.decision.verdict));
                prop_assert_eq!(ea.hold, eb.hold, "{:?}", op);
            }
        }

        /// A later report never lowers what an earlier one raised.
        #[test]
        fn reports_only_raise(
            first in prop::collection::vec(0usize..KINDS.len(), 0..6),
            second in prop::collection::vec(0usize..KINDS.len(), 0..6),
        ) {
            let a: Vec<NodeKind> = first.iter().map(|i| KINDS[*i]).collect();
            let b: Vec<NodeKind> = second.iter().map(|i| KINDS[*i]).collect();
            let mut t = host_told(&graph_of(&a));
            let before = t.label();
            t.raise(taint_report(&graph_of(&b)));
            // `before ⊑ after`: joining the earlier label in changes nothing.
            prop_assert_eq!(t.label(), before.join(t.label()));
        }
    }

    /// Web content is the case the whole of D2 is about: once the guest has
    /// read it, the host refuses outbound actions too.
    #[test]
    fn web_content_taints_the_host() {
        let t = host_told(&graph_of(&[NodeKind::WebContent]));
        assert!(t.is_tainted());
        assert!(!HostTaint::clean().is_tainted());
    }

    /// A poisoned graph is reported as the top of the lattice, never as clean.
    #[test]
    fn a_poisoned_graph_raises_to_the_top() {
        let mut g = FlowGraph::new();
        g.poison();
        let t = host_told(&g);
        assert_eq!(t.label(), IFCLabel::bottom().join(IFCLabel::top()));
        assert!(t.is_tainted());
        assert!(
            t.session_exfiltration_check(ConfLevel::Internal)
                .is_denied()
        );
    }

    /// #3255's agreement table, like #3218's profile agreement: the guest over
    /// its own flow graph and the host over the taint it was told about hold,
    /// refuse or allow a push alike, for every `git_push` level. A guest that
    /// refuses where the host holds (or the reverse) fails here.
    #[test]
    fn guest_and_host_hold_a_tainted_push_alike() {
        use portcullis::CapabilityLevel;
        let refused = Outcome::Denied {
            reason: DenyReason::FlowRefused,
        };
        let not_granted = Outcome::Denied {
            reason: DenyReason::NotGranted,
        };
        let asked = Outcome::ApprovalRequired;
        let web: &[NodeKind] = &[NodeKind::WebContent];
        let secret: &[NodeKind] = &[NodeKind::WebContent, NodeKind::Secret];
        // (session, git_push, outcome, held for its taint). A clean push under
        // this profile already asks the operator (a push is an exfiltration
        // vector); a tainted one is asked the same question, and the approval
        // that answers it is then a declassification.
        let table: [(&[NodeKind], CapabilityLevel, Outcome, bool); 9] = [
            (&[], CapabilityLevel::Never, not_granted, false),
            (&[], CapabilityLevel::LowRisk, asked, false),
            (&[], CapabilityLevel::Always, asked, false),
            (web, CapabilityLevel::Never, refused, false),
            (web, CapabilityLevel::LowRisk, asked, true),
            (web, CapabilityLevel::Always, asked, true),
            // A secret-bearing session is never held, whatever the profile.
            (secret, CapabilityLevel::Never, refused, false),
            (secret, CapabilityLevel::LowRisk, refused, false),
            (secret, CapabilityLevel::Always, refused, false),
        ];
        for (kinds, level, expected, taint_hold) in table {
            let g = graph_of(kinds);
            let t = host_told(&g);
            let mut policy = PermissionLattice::permissive();
            policy.capabilities.git_push = level;
            let term = || ActionTerm::from_operation(Operation::GitPush, "https://forge.invalid/r");
            let guest = Kernel::new(policy.clone()).decide_effect_with_flow(term(), Some(&g));
            let host = Kernel::new(policy.clone()).decide_effect_with_flow(term(), Some(&t));
            let case = format!("{kinds:?} at {level:?}");
            assert_eq!(
                outcome_of(&guest.decision.verdict),
                expected,
                "guest: {case}"
            );
            assert_eq!(outcome_of(&host.decision.verdict), expected, "host: {case}");
            assert_eq!(guest.hold.is_some(), taint_hold, "{case}");
            assert_eq!(guest.hold, host.hold, "{case}");
            if taint_hold {
                // The exit is new: the abort-only decider refuses the same push.
                let (before, _) = Kernel::new(policy).decide_term_with_flow(term(), Some(&g));
                assert_eq!(outcome_of(&before.verdict), refused, "{case}");
            }
        }
    }

    #[test]
    fn kernel_verdicts_map_onto_the_wire() {
        assert_eq!(outcome_of(&KernelVerdict::Allow), Outcome::Allowed);
        assert_eq!(
            outcome_of(&KernelVerdict::RequiresApproval),
            Outcome::ApprovalRequired
        );
        assert_eq!(
            outcome_of(&KernelVerdict::Deny(KernelDeny::InsufficientCapability)),
            Outcome::Denied {
                reason: DenyReason::NotGranted
            }
        );
        assert_eq!(
            outcome_of(&KernelVerdict::Deny(KernelDeny::IfcUnsafe {
                detail: "x".into()
            })),
            Outcome::Denied {
                reason: DenyReason::FlowRefused
            }
        );
    }

    #[test]
    fn the_digest_binds_operation_and_subject() {
        let s = Subject::new("src/main.rs").unwrap();
        let t = Subject::new("src/lib.rs").unwrap();
        let d = args_digest(Operation::ReadFiles, &s);
        assert_eq!(d, args_digest(Operation::ReadFiles, &s));
        assert_ne!(d, args_digest(Operation::WriteFiles, &s));
        assert_ne!(d, args_digest(Operation::ReadFiles, &t));
    }
}
