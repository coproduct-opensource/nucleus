//! Authority from the control chain (#3459): the half of [`FlowGraph`]'s
//! verdict that decides which parents may instruct an action.
//!
//! An action's parents play one of two roles, and the caller names which in
//! [`ActionParents`]:
//!
//! - **control** parents are the instruction sources — who told the agent to
//!   act. Only a [`NodeKind::UserPrompt`], or a [`NodeKind::ModelPlan`] rooted
//!   in one, confers authority (see [`FlowGraph::insert_action`] for the exact
//!   rule). Anything else named as control confers `NoAuthority`.
//! - **data** parents are what the action consumed: tool responses, file
//!   reads, web content, memory reads.
//!
//! The action's **authority** is the meet of what its control parents confer,
//! and an action with no control parent has `NoAuthority` — absence never
//! grants (ADR 0007 A/B). Every other dimension — confidentiality,
//! integrity, provenance, freshness, derivation — is judged on the full join
//! over ALL parents, control and data, exactly as before, and the stored node
//! label is that full join, authority included.
//!
//! Data cannot raise authority, and context cannot lower it: a data parent
//! with `Informational` or `Suggestive` authority (a file read, a tool
//! response) informs the action without capping it. Two kinds of data still
//! cap it, exactly as before the split: content with `NoAuthority` (web
//! content, an upstream tool result, a secret — `check_flow` rule 2,
//! "NoAuthority data cannot steer privileged actions"), and anything
//! `Adversarial`.

use portcullis_core::flow::{check_flow, FlowNode, FlowVerdict, NodeId, NodeKind};
use portcullis_core::{AuthorityLevel, IFCLabel, IntegLevel};

use super::{DeclassScope, FlowGraph};

/// The causal parents of an action, split by the role each plays (#3459).
///
/// The split is the caller's statement of fact, made at the call site with
/// named fields rather than inferred from position or node kind:
///
/// ```
/// use portcullis::flow_graph::{ActionParents, FlowGraph};
/// use portcullis_core::flow::{FlowVerdict, NodeKind};
/// use portcullis_core::Operation;
///
/// let mut g = FlowGraph::new();
/// let prompt = g.insert_observation(NodeKind::UserPrompt, &[], 0).unwrap();
/// let file = g.insert_observation(NodeKind::FileRead, &[], 0).unwrap();
/// let write = g
///     .insert_action(
///         Operation::WriteFiles,
///         ActionParents { control: &[prompt], data: &[file] },
///         0,
///     )
///     .unwrap();
/// assert_eq!(write.verdict, FlowVerdict::Allow);
/// ```
///
/// Both slices are causal parents: they are validated together, counted
/// together against [`MAX_PARENTS`](portcullis_core::flow::MAX_PARENTS), and joined together into the action's
/// label. Only `control` decides authority.
#[derive(Debug, Clone, Copy)]
pub struct ActionParents<'a> {
    /// Instruction sources: who told the agent to take this action. A
    /// [`NodeKind::UserPrompt`], or a [`NodeKind::ModelPlan`] rooted in one;
    /// any other node named here confers `NoAuthority`.
    pub control: &'a [NodeId],
    /// What the action consumed: tool responses, file reads, web content,
    /// memory reads, earlier actions. Joined into every label dimension, and
    /// never a source of authority.
    pub data: &'a [NodeId],
}

impl ActionParents<'_> {
    /// Every parent, control first: the order the node records them in.
    pub(super) fn all(&self) -> Vec<NodeId> {
        let mut all = Vec::with_capacity(self.control.len() + self.data.len());
        all.extend_from_slice(self.control);
        all.extend_from_slice(self.data);
        all
    }
}

impl FlowGraph {
    /// The single verdict computation: [`check_flow`] over the node's
    /// effective label (the released view where `scope` admits the node's
    /// operation, the strict label otherwise), with an action's authority
    /// replaced by [`judged_authority`] of what its control chain conferred.
    ///
    /// Returns the verdict and the authority it was judged by.
    pub(super) fn judge(
        node: &FlowNode,
        scope: Option<&DeclassScope>,
        chain: AuthorityLevel,
        now: u64,
    ) -> (FlowVerdict, AuthorityLevel) {
        use portcullis_core::extracted::declassify::mask_admits;
        use portcullis_core::extracted::mediation::med_of;
        let mut shadow = *node;
        let Some(op) = node.operation else {
            // Not an action: check_flow reads no authority for it.
            return (check_flow(&shadow, now), shadow.label.authority);
        };
        if let Some(s) = scope {
            if mask_admits(s.sink_mask, med_of(op)) {
                shadow.label = s.released_label;
            }
        }
        shadow.label.authority = judged_authority(shadow.label, chain);
        (check_flow(&shadow, now), shadow.label.authority)
    }

    /// The authority a node confers when an action names it as a CONTROL
    /// parent (#3459).
    ///
    /// - `UserPrompt`: its label's authority.
    /// - `ModelPlan`: what its own control chain conferred when it was
    ///   observed (`control_authority`); `NoAuthority` if it was not rooted in
    ///   a `UserPrompt` chain.
    /// - every other kind: `NoAuthority`. A file, a tool response, web content
    ///   or an earlier action named as control instructs nothing.
    ///
    /// Exhaustive on purpose (ADR 0007 E-2): a new kind must decide here.
    pub(super) fn conferred_authority(&self, id: NodeId) -> AuthorityLevel {
        let Some(node) = self.get(id) else {
            return AuthorityLevel::NoAuthority;
        };
        match node.kind {
            NodeKind::UserPrompt => node.label.authority,
            NodeKind::ModelPlan => self
                .control_authority
                .get(&id)
                .copied()
                .unwrap_or(AuthorityLevel::NoAuthority),
            NodeKind::ToolResponse
            | NodeKind::WebContent
            | NodeKind::McpToolResult
            | NodeKind::McpToolDescription
            | NodeKind::SponsoredOffer
            | NodeKind::MemoryRead
            | NodeKind::MemoryWrite
            | NodeKind::FileRead
            | NodeKind::EnvVar
            | NodeKind::Secret
            | NodeKind::OutboundAction
            | NodeKind::Summarization
            | NodeKind::Retry
            | NodeKind::HTTPResponse
            | NodeKind::DatabaseRow
            | NodeKind::GitBlob
            | NodeKind::CachedDatum
            | NodeKind::DeterministicBind
            | NodeKind::ImageContent
            | NodeKind::AudioContent
            | NodeKind::PDFContent
            | NodeKind::Custom(_) => AuthorityLevel::NoAuthority,
        }
    }

    /// Whether `id` can confer authority as a control parent: a `UserPrompt`,
    /// or a `ModelPlan` that was rooted when observed.
    pub(super) fn is_instruction_source(&self, id: NodeId) -> bool {
        self.get(id).is_some_and(|n| match n.kind {
            NodeKind::UserPrompt => true,
            NodeKind::ModelPlan => self.control_authority.contains_key(&id),
            _ => false,
        })
    }

    /// The meet of what `control` confers, capped by the new node's
    /// intrinsic authority. No control parent is `NoAuthority`: absence never
    /// grants.
    pub(super) fn chain_authority(
        &self,
        control: &[NodeId],
        intrinsic: AuthorityLevel,
    ) -> AuthorityLevel {
        control
            .iter()
            .map(|&id| self.conferred_authority(id))
            .min()
            .map_or(AuthorityLevel::NoAuthority, |a| a.min(intrinsic))
    }

    /// The authority a newly observed `ModelPlan` will confer as a control
    /// parent, or `None` when it is not rooted in a `UserPrompt` chain.
    ///
    /// An observation takes one untyped parent slice, so a plan's control
    /// parents are the ones that are instruction sources themselves (a
    /// `UserPrompt`, or a rooted plan) and the rest are data. The plan then
    /// confers what an action with those parents would be judged by:
    /// [`judged_authority`] of their chain over the plan's full-join label.
    pub(super) fn rooted_plan_authority(
        &self,
        parents: &[NodeId],
        label: IFCLabel,
        intrinsic: AuthorityLevel,
    ) -> Option<AuthorityLevel> {
        let control: Vec<NodeId> = parents
            .iter()
            .copied()
            .filter(|&p| self.is_instruction_source(p))
            .collect();
        if control.is_empty() {
            return None;
        }
        Some(judged_authority(
            label,
            self.chain_authority(&control, intrinsic),
        ))
    }
}

/// The authority an action is judged by, given the (full-join) label being
/// judged and what its control chain conferred (#3459).
///
/// The chain, capped by the label's own authority in exactly two cases:
///
/// - the label's authority is `NoAuthority`: some parent is content that may
///   not steer a privileged action at all (web content, an upstream tool
///   result, a secret). That is `check_flow` rule 2 as documented, and naming
///   the content as data rather than control does not get around it;
/// - the label's integrity is `Adversarial`: adversarial content is judged
///   exactly as it was before the control/data split.
///
/// Otherwise the data parents' authority is `Informational` or `Suggestive` —
/// context, which by those levels' own definitions informs but does not
/// direct — and the action's authority is its control chain's.
pub(super) fn judged_authority(label: IFCLabel, chain: AuthorityLevel) -> AuthorityLevel {
    let adversarial = match label.integrity {
        IntegLevel::Adversarial => true,
        IntegLevel::Untrusted | IntegLevel::Trusted => false,
    };
    let may_not_steer = match label.authority {
        AuthorityLevel::NoAuthority => true,
        AuthorityLevel::Informational | AuthorityLevel::Suggestive | AuthorityLevel::Directive => {
            false
        }
    };
    if adversarial || may_not_steer {
        chain.min(label.authority)
    } else {
        chain
    }
}
