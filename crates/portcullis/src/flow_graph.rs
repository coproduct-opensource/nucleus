//! Runtime causal DAG for precise information flow tracking.
//!
//! Eliminates the over-tainting problem: instead of a flat session-level
//! label accumulator (where reading web content blocks ALL subsequent writes),
//! the DAG tracks actual causal dependencies. An action that depends only on
//! local files is unaffected by web content read elsewhere in the session.

use std::collections::{BTreeSet, VecDeque};

use portcullis_core::flow::{
    check_flow, intrinsic_label, propagate_label, FlowNode, FlowVerdict, NodeId, NodeKind,
    QuarantineVerdict, TrustAncestryResult, MAX_PARENTS,
};
use portcullis_core::receipt::{build_receipt, FlowReceipt, MAX_RECEIPT_ANCESTORS};
use portcullis_core::{IFCLabel, Operation};

/// Errors during graph operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowGraphError {
    /// A referenced parent node does not exist in the graph.
    ParentNotFound(
        /// The missing node ID.
        NodeId,
    ),
    /// More than MAX_PARENTS (8) parents provided.
    TooManyParents {
        /// Number of parents provided.
        provided: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Parent ID 0 (sentinel) is not a valid parent reference.
    SentinelParent,
    /// The flow graph has not been enabled via `enable_flow_graph()`.
    GraphNotEnabled,
    /// A referenced parent was a denied action — denied actions did not
    /// execute and cannot be causal ancestors.
    DeniedParent(
        /// The denied node ID.
        NodeId,
    ),
    /// A referenced parent is quarantined — quarantined artifacts cannot
    /// be used as causal inputs without explicit release.
    QuarantinedParent(
        /// The quarantined node ID.
        NodeId,
    ),
}

impl std::fmt::Display for FlowGraphError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FlowGraphError::ParentNotFound(id) => write!(f, "parent node {id} not found"),
            FlowGraphError::TooManyParents { provided, max } => {
                write!(f, "too many parents: {provided} > {max}")
            }
            FlowGraphError::SentinelParent => write!(f, "sentinel (0) is not a valid parent"),
            FlowGraphError::GraphNotEnabled => write!(f, "flow graph not enabled"),
            FlowGraphError::DeniedParent(id) => {
                write!(f, "parent {id} was denied — cannot be a causal ancestor")
            }
            FlowGraphError::QuarantinedParent(id) => {
                write!(
                    f,
                    "parent {id} is quarantined — release quarantine before use"
                )
            }
        }
    }
}

impl std::error::Error for FlowGraphError {}

/// Result of inserting an action node (atomic check-and-insert).
#[derive(Debug, Clone)]
pub struct FlowDecision {
    /// The flow verdict (Allow or Deny with reason).
    pub verdict: FlowVerdict,
    /// The NodeId assigned to this action in the graph.
    pub node_id: NodeId,
    /// The propagated label for this action.
    pub label: IFCLabel,
}

const MAX_DENIED_NODES: usize = 1024;
const MAX_QUARANTINED_NODES: usize = 4096;

/// Append-only causal DAG for information flow tracking.
///
/// Nodes are indexed by sequential `NodeId` (u64). Index 0 is the sentinel
/// (no parent). Real nodes start at 1.
///
/// Denied action nodes are tracked but cannot be referenced as parents —
/// a denied action did not execute, so it has no causal effect.
/// The denied set is capped at [`MAX_DENIED_NODES`] with oldest-first eviction.
///
/// Quarantined nodes are artifacts marked as untrusted at the individual
/// node level (not session-wide). Quarantine propagates through the DAG:
/// any node whose causal ancestry includes a quarantined node is itself
/// considered quarantined. Actions with quarantined ancestors are blocked
/// until the quarantine is explicitly released.
pub struct FlowGraph {
    nodes: Vec<Option<FlowNode>>,
    next_id: u64,
    /// Node IDs of denied actions — cannot be used as parents.
    /// Capped at MAX_DENIED_NODES to prevent unbounded growth in
    /// long-running sessions.
    denied: BTreeSet<NodeId>,
    /// Node IDs of explicitly quarantined artifacts.
    /// Descendants inherit quarantine status via causal ancestry traversal.
    /// Capped at [`MAX_QUARANTINED_NODES`] with oldest-first eviction.
    quarantined: BTreeSet<NodeId>,
}

impl FlowGraph {
    /// Create an empty graph. Index 0 is reserved as sentinel.
    pub fn new() -> Self {
        Self {
            nodes: vec![None], // index 0 = sentinel
            next_id: 1,
            denied: BTreeSet::new(),
            quarantined: BTreeSet::new(),
        }
    }

    /// Number of real nodes (excludes sentinel).
    pub fn len(&self) -> usize {
        self.nodes.iter().filter(|n| n.is_some()).count()
    }

    /// Whether the graph has no real nodes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Look up a node by ID. O(1).
    pub fn get(&self, id: NodeId) -> Option<&FlowNode> {
        self.nodes.get(id as usize)?.as_ref()
    }

    /// Apply a label modification to an existing node (for declassification).
    ///
    /// Only modifies the label — does not change the node's kind, parents,
    /// or operation. Returns the previous label for audit.
    pub fn modify_label(&mut self, id: NodeId, new_label: IFCLabel) -> Option<IFCLabel> {
        let node = self.nodes.get_mut(id as usize)?.as_mut()?;
        let old = node.label;
        node.label = new_label;
        Some(old)
    }

    /// Compute the propagated label for a set of causal parents.
    ///
    /// This is the label that an action node WOULD have if it were inserted
    /// with these parents — without actually inserting anything into the graph.
    /// Use this for querying what the kernel's decision would be based on
    /// exact causal ancestry, rather than a session-wide taint accumulator.
    ///
    /// Returns the intrinsic `OutboundAction` label joined with parent labels.
    /// With no parents, returns the base OutboundAction label (no taint).
    pub fn causal_label(&self, parents: &[NodeId], now: u64) -> Result<IFCLabel, FlowGraphError> {
        self.validate_parents(parents)?;
        let parent_labels = self.gather_labels(parents);
        Ok(propagate_label(
            &parent_labels,
            intrinsic_label(NodeKind::OutboundAction, now),
        ))
    }

    /// Insert a data-source observation. NOT flow-checked.
    ///
    /// If any parent is quarantined (directly or via ancestry), the new
    /// observation node automatically inherits quarantine status (#639).
    pub fn insert_observation(
        &mut self,
        kind: NodeKind,
        parents: &[NodeId],
        now: u64,
    ) -> Result<NodeId, FlowGraphError> {
        self.validate_parents(parents)?;

        // Check if any parent is quarantined (directly or transitively)
        let any_parent_quarantined = parents.iter().any(|&pid| self.is_quarantined(pid));

        let label = propagate_label(&self.gather_labels(parents), intrinsic_label(kind, now));
        let id = self.alloc_node(kind, label, parents, None);

        // Propagate quarantine to the new observation node
        if any_parent_quarantined {
            self.quarantined.insert(id);
        }

        Ok(id)
    }

    /// Atomic check-and-insert for action nodes.
    ///
    /// If any parent is quarantined (directly or via ancestry), the new
    /// action node automatically inherits quarantine status (#639).
    pub fn insert_action(
        &mut self,
        operation: Operation,
        parents: &[NodeId],
        now: u64,
    ) -> Result<FlowDecision, FlowGraphError> {
        self.validate_parents(parents)?;

        // Check if any parent is quarantined (directly or transitively)
        let any_parent_quarantined = parents.iter().any(|&pid| self.is_quarantined(pid));

        let label = propagate_label(
            &self.gather_labels(parents),
            intrinsic_label(NodeKind::OutboundAction, now),
        );
        let node = self.build_node(NodeKind::OutboundAction, label, parents, Some(operation));
        let verdict = check_flow(&node, now);
        let id = self.next_id;
        self.nodes.push(Some(node));
        self.next_id += 1;

        // Propagate quarantine to the new action node
        if any_parent_quarantined {
            self.quarantined.insert(id);
        }

        // Denied actions are inscribed for receipt/audit but cannot be parents
        if matches!(verdict, FlowVerdict::Deny(_)) {
            self.denied.insert(id);
            // GC: cap the denied set to prevent unbounded growth.
            // SECURITY (#480): When evicting, tombstone the node in the nodes
            // Vec so it can't be referenced as a parent. Without this, evicted
            // denied nodes become referenceable, bypassing the denied-parent check.
            while self.denied.len() > MAX_DENIED_NODES {
                if let Some(&oldest) = self.denied.iter().next() {
                    self.denied.remove(&oldest);
                    // Tombstone: remove the node so get(oldest) returns None,
                    // which causes validate_parents to return ParentNotFound.
                    if let Some(slot) = self.nodes.get_mut(oldest as usize) {
                        *slot = None;
                    }
                }
            }
        }
        Ok(FlowDecision {
            verdict,
            node_id: id,
            label,
        })
    }

    /// Transitive ancestors via BFS, capped at MAX_RECEIPT_ANCESTORS.
    pub fn ancestors(&self, id: NodeId) -> Vec<&FlowNode> {
        let mut result = Vec::new();
        let mut queue = VecDeque::new();
        let mut visited = vec![false; self.nodes.len()];

        if let Some(node) = self.get(id) {
            for i in 0..node.parent_count as usize {
                let pid = node.parents[i];
                if pid > 0 && (pid as usize) < self.nodes.len() && !visited[pid as usize] {
                    queue.push_back(pid);
                    visited[pid as usize] = true;
                }
            }
        }

        while let Some(nid) = queue.pop_front() {
            if result.len() >= MAX_RECEIPT_ANCESTORS {
                break;
            }
            // Defense-in-depth: skip denied nodes during ancestor traversal.
            // The denied-set check in validate_parents should prevent denied
            // nodes from being reachable, but this is belt-and-suspenders.
            if self.denied.contains(&nid) {
                continue;
            }
            if let Some(node) = self.get(nid) {
                result.push(node);
                for i in 0..node.parent_count as usize {
                    let pid = node.parents[i];
                    if pid > 0 && (pid as usize) < self.nodes.len() && !visited[pid as usize] {
                        queue.push_back(pid);
                        visited[pid as usize] = true;
                    }
                }
            }
        }

        result
    }

    /// Build a receipt from the causal chain of a node.
    pub fn build_receipt_for(&self, id: NodeId, now: u64) -> Option<FlowReceipt> {
        let node = self.get(id)?;
        let ancestors = self.ancestors(id);
        let ancestor_refs: Vec<&FlowNode> = ancestors.to_vec();
        let verdict = check_flow(node, now);
        Some(build_receipt(node, &ancestor_refs, verdict, now))
    }

    fn validate_parents(&self, parents: &[NodeId]) -> Result<(), FlowGraphError> {
        if parents.len() > MAX_PARENTS {
            return Err(FlowGraphError::TooManyParents {
                provided: parents.len(),
                max: MAX_PARENTS,
            });
        }
        for &pid in parents {
            if pid == 0 {
                return Err(FlowGraphError::SentinelParent);
            }
            if self.get(pid).is_none() {
                return Err(FlowGraphError::ParentNotFound(pid));
            }
            if self.denied.contains(&pid) {
                return Err(FlowGraphError::DeniedParent(pid));
            }
        }
        Ok(())
    }

    fn gather_labels(&self, parents: &[NodeId]) -> Vec<IFCLabel> {
        parents
            .iter()
            .filter_map(|&pid| self.get(pid).map(|n| n.label))
            .collect()
    }

    fn build_node(
        &self,
        kind: NodeKind,
        label: IFCLabel,
        parents: &[NodeId],
        operation: Option<Operation>,
    ) -> FlowNode {
        let mut parent_array = [0u64; MAX_PARENTS];
        for (i, &pid) in parents.iter().take(MAX_PARENTS).enumerate() {
            parent_array[i] = pid;
        }
        FlowNode {
            id: self.next_id,
            kind,
            label,
            parent_count: parents.len().min(MAX_PARENTS) as u8,
            parents: parent_array,
            operation,
            sink_class: None,
        }
    }

    fn alloc_node(
        &mut self,
        kind: NodeKind,
        label: IFCLabel,
        parents: &[NodeId],
        operation: Option<Operation>,
    ) -> NodeId {
        let node = self.build_node(kind, label, parents, operation);
        let id = self.next_id;
        self.nodes.push(Some(node));
        self.next_id += 1;
        id
    }

    /// Apply a scoped declassification token to a specific node.
    ///
    /// Validates that:
    /// 1. The target node exists in the graph
    /// 2. The token has not expired
    /// 3. The underlying rule's precondition matches the node's label
    ///
    /// On success, modifies the node's label and returns the old/new labels.
    /// The caller is responsible for recording this in the receipt chain.
    pub fn apply_token(
        &mut self,
        token: &portcullis_core::declassify::DeclassificationToken,
        now: u64,
    ) -> portcullis_core::declassify::TokenApplyResult {
        use portcullis_core::declassify::TokenApplyResult;

        // Check expiry
        if token.is_expired(now) {
            return TokenApplyResult::Expired {
                valid_until: token.valid_until,
                now,
            };
        }

        // Check node exists
        let node = match self.get(token.target_node_id) {
            Some(n) => n,
            None => return TokenApplyResult::NodeNotFound,
        };

        // Apply the underlying rule
        let result = token.rule.apply(node.label);
        if !result.applied {
            return TokenApplyResult::PreconditionUnmet;
        }

        // Modify the node's label
        self.modify_label(token.target_node_id, result.label);
        TokenApplyResult::Applied {
            original_label: result.original,
            new_label: result.label,
        }
    }

    // ── Trusted ancestry check (#515) ────────────────────────────────

    /// Check whether a node has trusted ancestry — all causal ancestors
    /// have integrity >= `Untrusted` (i.e., not `Adversarial`).
    ///
    /// This is the compartment-aware provenance check required when
    /// transitioning to Execute or Breakglass. The spec mandates that
    /// data "may reach privileged sinks in execute only from trusted
    /// ancestry or explicit declassification."
    ///
    /// The check walks the full causal DAG (BFS), including the node
    /// itself, and collects any nodes with `Adversarial` integrity.
    /// Denied nodes are skipped (they did not execute). Declassified
    /// nodes that have been raised to `Untrusted` or above pass the
    /// check — this is how web content can legitimately reach Execute
    /// after explicit operator review.
    ///
    /// Returns [`TrustAncestryResult::Trusted`] if the chain is clean,
    /// or [`TrustAncestryResult::Untrusted`] with the tainted node IDs.
    pub fn check_trusted_ancestry(&self, node_id: NodeId) -> Option<TrustAncestryResult> {
        use portcullis_core::IntegLevel;

        let node = self.get(node_id)?;

        let mut tainted = Vec::new();

        // Check the node itself
        if node.label.integrity < IntegLevel::Untrusted {
            tainted.push(node_id);
        }

        // BFS over ancestors
        let mut queue = VecDeque::new();
        let mut visited = vec![false; self.nodes.len()];
        visited[node_id as usize] = true;

        // Seed the queue with direct parents
        for i in 0..node.parent_count as usize {
            let pid = node.parents[i];
            if pid > 0 && (pid as usize) < self.nodes.len() && !visited[pid as usize] {
                queue.push_back(pid);
                visited[pid as usize] = true;
            }
        }

        while let Some(nid) = queue.pop_front() {
            // Skip denied nodes — they did not execute and cannot
            // contribute causal data.
            if self.denied.contains(&nid) {
                continue;
            }

            if let Some(ancestor) = self.get(nid) {
                if ancestor.label.integrity < IntegLevel::Untrusted {
                    tainted.push(nid);
                }

                // Continue BFS through this ancestor's parents
                for i in 0..ancestor.parent_count as usize {
                    let pid = ancestor.parents[i];
                    if pid > 0 && (pid as usize) < self.nodes.len() && !visited[pid as usize] {
                        queue.push_back(pid);
                        visited[pid as usize] = true;
                    }
                }
            }
        }

        if tainted.is_empty() {
            Some(TrustAncestryResult::Trusted)
        } else {
            Some(TrustAncestryResult::Untrusted {
                tainted_ancestors: tainted,
            })
        }
    }

    // ── Artifact-granular quarantine (#639) ─────────────────────────

    /// Mark a specific node as quarantined.
    ///
    /// Quarantine is artifact-scoped: only this node and its causal
    /// descendants are affected. Sibling branches in the DAG remain clean.
    /// Returns `true` if the node exists and was newly quarantined,
    /// `false` if already quarantined or the node does not exist.
    pub fn quarantine(&mut self, node_id: NodeId) -> bool {
        if self.get(node_id).is_none() {
            return false;
        }
        let inserted = self.quarantined.insert(node_id);
        // GC: cap the quarantined set to prevent unbounded growth.
        while self.quarantined.len() > MAX_QUARANTINED_NODES {
            if let Some(&oldest) = self.quarantined.iter().next() {
                self.quarantined.remove(&oldest);
            }
        }
        inserted
    }

    /// Release quarantine from a specific node.
    ///
    /// Only removes the explicit quarantine mark — does not affect
    /// ancestors that may also be quarantined. Returns `true` if the
    /// node was quarantined and is now released.
    pub fn release_quarantine(&mut self, node_id: NodeId) -> bool {
        self.quarantined.remove(&node_id)
    }

    /// Check whether a node is quarantined (directly or via ancestry).
    ///
    /// A node is considered quarantined if:
    /// 1. It is explicitly in the quarantined set, OR
    /// 2. Any of its transitive ancestors is in the quarantined set.
    ///
    /// This is O(ancestors) — bounded by `MAX_RECEIPT_ANCESTORS`.
    pub fn is_quarantined(&self, node_id: NodeId) -> bool {
        if self.quarantined.contains(&node_id) {
            return true;
        }
        // Walk ancestors looking for any quarantined node
        !self.quarantined_ancestors(node_id).is_empty()
    }

    /// Returns the specific quarantined node IDs in the causal ancestry
    /// of `node_id` (including `node_id` itself if directly quarantined).
    ///
    /// Useful for audit trails and error messages: "blocked because
    /// ancestor X (web content from issue #42) is quarantined."
    pub fn quarantined_ancestors(&self, node_id: NodeId) -> Vec<NodeId> {
        let mut result = Vec::new();
        if self.quarantined.contains(&node_id) {
            result.push(node_id);
        }

        let mut queue = VecDeque::new();
        let mut visited = vec![false; self.nodes.len()];

        if let Some(node) = self.get(node_id) {
            for i in 0..node.parent_count as usize {
                let pid = node.parents[i];
                if pid > 0 && (pid as usize) < self.nodes.len() && !visited[pid as usize] {
                    queue.push_back(pid);
                    visited[pid as usize] = true;
                }
            }
        }

        while let Some(nid) = queue.pop_front() {
            if self.quarantined.contains(&nid) {
                result.push(nid);
            }
            if let Some(node) = self.get(nid) {
                for i in 0..node.parent_count as usize {
                    let pid = node.parents[i];
                    if pid > 0 && (pid as usize) < self.nodes.len() && !visited[pid as usize] {
                        queue.push_back(pid);
                        visited[pid as usize] = true;
                    }
                }
            }
        }

        result
    }

    /// Quarantine-aware flow check: combines IFC label checking with
    /// artifact-granular quarantine.
    ///
    /// Returns [`QuarantineVerdict::Quarantined`] if any causal ancestor
    /// is quarantined, regardless of whether the IFC label would allow
    /// the action. Returns [`QuarantineVerdict::Clean`] with the normal
    /// flow verdict otherwise.
    pub fn check_flow_with_quarantine(
        &self,
        node_id: NodeId,
        now: u64,
    ) -> Option<QuarantineVerdict> {
        let node = self.get(node_id)?;
        let underlying = check_flow(node, now);
        let qa = self.quarantined_ancestors(node_id);
        if qa.is_empty() {
            Some(QuarantineVerdict::Clean(underlying))
        } else {
            Some(QuarantineVerdict::Quarantined {
                quarantined_ancestors: qa,
                underlying_verdict: underlying,
            })
        }
    }
}

impl Default for FlowGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use portcullis_core::flow::FlowDenyReason;
    use portcullis_core::*;

    #[test]
    fn empty_graph() {
        let g = FlowGraph::new();
        assert!(g.is_empty());
        assert!(g.get(0).is_none());
        assert!(g.get(1).is_none());
    }

    #[test]
    fn sequential_ids() {
        let mut g = FlowGraph::new();
        let now = 1000;
        assert_eq!(
            g.insert_observation(NodeKind::UserPrompt, &[], now)
                .unwrap(),
            1
        );
        assert_eq!(
            g.insert_observation(NodeKind::FileRead, &[], now).unwrap(),
            2
        );
        assert_eq!(
            g.insert_observation(NodeKind::WebContent, &[], now)
                .unwrap(),
            3
        );
        assert_eq!(g.len(), 3);
    }

    #[test]
    fn observation_propagates_labels() {
        let mut g = FlowGraph::new();
        let now = 1000;
        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        let user = g
            .insert_observation(NodeKind::UserPrompt, &[], now)
            .unwrap();
        let plan = g
            .insert_observation(NodeKind::ModelPlan, &[web, user], now)
            .unwrap();
        let n = g.get(plan).unwrap();
        assert_eq!(n.label.integrity, IntegLevel::Adversarial);
        assert_eq!(n.label.authority, AuthorityLevel::NoAuthority);
    }

    #[test]
    fn action_denied_with_web_parent() {
        let mut g = FlowGraph::new();
        let now = 1000;
        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        let r = g.insert_action(Operation::WriteFiles, &[web], now).unwrap();
        assert_eq!(
            r.verdict,
            FlowVerdict::Deny(FlowDenyReason::AuthorityEscalation)
        );
    }

    #[test]
    fn action_allowed_with_clean_parents() {
        let mut g = FlowGraph::new();
        let now = 1000;
        let user = g
            .insert_observation(NodeKind::UserPrompt, &[], now)
            .unwrap();
        let file = g
            .insert_observation(NodeKind::FileRead, &[user], now)
            .unwrap();
        let r = g
            .insert_action(Operation::WriteFiles, &[file], now)
            .unwrap();
        assert_eq!(r.verdict, FlowVerdict::Allow);
    }

    #[test]
    fn parent_not_found() {
        let mut g = FlowGraph::new();
        assert_eq!(
            g.insert_observation(NodeKind::FileRead, &[999], 1000),
            Err(FlowGraphError::ParentNotFound(999))
        );
    }

    #[test]
    fn too_many_parents() {
        let mut g = FlowGraph::new();
        let parents: Vec<NodeId> = (1..=9).collect();
        assert_eq!(
            g.insert_observation(NodeKind::ModelPlan, &parents, 1000),
            Err(FlowGraphError::TooManyParents {
                provided: 9,
                max: 8
            })
        );
    }

    #[test]
    fn ancestors_traversal() {
        let mut g = FlowGraph::new();
        let now = 1000;
        let a = g
            .insert_observation(NodeKind::UserPrompt, &[], now)
            .unwrap();
        let b = g.insert_observation(NodeKind::FileRead, &[a], now).unwrap();
        let c = g
            .insert_observation(NodeKind::ModelPlan, &[b], now)
            .unwrap();
        let d = g.insert_action(Operation::WriteFiles, &[c], now).unwrap();
        assert_eq!(g.ancestors(d.node_id).len(), 3);
    }

    #[test]
    fn receipt_from_denied_action() {
        let mut g = FlowGraph::new();
        let now = 1000;
        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        let r = g.insert_action(Operation::CreatePr, &[web], now).unwrap();
        assert!(matches!(r.verdict, FlowVerdict::Deny(_)));
        let receipt = g.build_receipt_for(r.node_id, now).unwrap();
        assert!(receipt.display_chain().contains("BLOCKED"));
    }

    #[test]
    fn sentinel_parent_rejected() {
        let mut g = FlowGraph::new();
        assert_eq!(
            g.insert_observation(NodeKind::FileRead, &[0], 1000),
            Err(FlowGraphError::SentinelParent)
        );
    }

    #[test]
    fn denied_action_cannot_be_parent() {
        let mut g = FlowGraph::new();
        let now = 1000;
        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        // This write is denied (web taint)
        let denied = g.insert_action(Operation::WriteFiles, &[web], now).unwrap();
        assert!(matches!(denied.verdict, FlowVerdict::Deny(_)));
        // Trying to reference the denied node as a parent should fail
        assert_eq!(
            g.insert_observation(NodeKind::FileRead, &[denied.node_id], now),
            Err(FlowGraphError::DeniedParent(denied.node_id))
        );
    }

    #[test]
    fn sentinel_parent_rejected_in_action() {
        let mut g = FlowGraph::new();
        assert!(matches!(
            g.insert_action(Operation::WriteFiles, &[0], 1000),
            Err(FlowGraphError::SentinelParent)
        ));
    }

    // THE KEY TEST
    #[test]
    fn independent_branches_no_overtaint() {
        let mut g = FlowGraph::new();
        let now = 1000;

        // Task A: web content (adversarial)
        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        // Task B: local file (trusted) — NO dependency on web
        let file = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();

        // Task B write: depends ONLY on file — ALLOWED
        let b = g
            .insert_action(Operation::WriteFiles, &[file], now)
            .unwrap();
        assert_eq!(
            b.verdict,
            FlowVerdict::Allow,
            "No web taint — should be allowed"
        );

        // Task A write: depends on web — DENIED
        let a = g.insert_action(Operation::WriteFiles, &[web], now).unwrap();
        assert!(
            matches!(a.verdict, FlowVerdict::Deny(_)),
            "Web taint — should be denied"
        );
    }

    /// #372: Same operation can be denied then allowed (denied set uses IDs, not ops)
    #[test]
    fn denied_then_allowed_same_operation() {
        let mut g = FlowGraph::new();
        let now = 1000;

        // Web content → write denied
        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        let denied = g.insert_action(Operation::WriteFiles, &[web], now).unwrap();
        assert!(matches!(denied.verdict, FlowVerdict::Deny(_)));

        // Clean source → same operation (WriteFiles) allowed
        let clean = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
        let allowed = g
            .insert_action(Operation::WriteFiles, &[clean], now)
            .unwrap();
        assert!(
            matches!(allowed.verdict, FlowVerdict::Allow),
            "WriteFiles with clean parents should be allowed even after a prior denial"
        );
    }

    /// #370: ancestors() skips denied nodes
    #[test]
    fn ancestors_skip_denied_nodes() {
        let mut g = FlowGraph::new();
        let now = 1000;

        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        let denied = g.insert_action(Operation::WriteFiles, &[web], now).unwrap();
        assert!(matches!(denied.verdict, FlowVerdict::Deny(_)));

        // The denied node's own ancestors should work (for its receipt)
        // but we can verify that if somehow reached, denied nodes are skipped
        let ancestors = g.ancestors(denied.node_id);
        // Should include web (the parent) but not the denied node itself
        for a in &ancestors {
            assert_ne!(
                a.id, denied.node_id,
                "denied node should not appear in its own ancestors"
            );
        }
    }

    /// #368: FlowGraphError has Display
    #[test]
    fn error_display_messages() {
        let e = FlowGraphError::SentinelParent;
        assert!(e.to_string().contains("sentinel"));

        let e = FlowGraphError::DeniedParent(42);
        assert!(e.to_string().contains("42"));
        assert!(e.to_string().contains("denied"));

        let e = FlowGraphError::ParentNotFound(99);
        assert!(e.to_string().contains("99"));
    }

    // ── causal_label() tests (#653) ────────────────────────────────────

    #[test]
    fn causal_label_no_parents_is_clean() {
        let g = FlowGraph::new();
        let now = 1000;
        // No parents → base OutboundAction label (trusted, no taint)
        let label = g.causal_label(&[], now).unwrap();
        assert_eq!(label.integrity, portcullis_core::IntegLevel::Trusted);
    }

    #[test]
    fn causal_label_from_web_is_tainted() {
        let mut g = FlowGraph::new();
        let now = 1000;
        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        let label = g.causal_label(&[web], now).unwrap();
        assert_eq!(
            label.integrity,
            portcullis_core::IntegLevel::Adversarial,
            "causal label from web content should be adversarial"
        );
    }

    #[test]
    fn causal_label_independent_branches_not_tainted() {
        let mut g = FlowGraph::new();
        let now = 1000;

        // Branch A: web content (adversarial)
        let _web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();

        // Branch B: local file read (trusted) — independent of web
        let file = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();

        // causal_label for an action depending ONLY on the file read
        let label = g.causal_label(&[file], now).unwrap();
        assert_eq!(
            label.integrity,
            portcullis_core::IntegLevel::Trusted,
            "action depending only on file read should NOT be tainted by unrelated web content"
        );
    }

    #[test]
    fn causal_label_mixed_parents_takes_worst() {
        let mut g = FlowGraph::new();
        let now = 1000;

        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        let file = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();

        // Action depending on BOTH web and file → takes the worst (adversarial)
        let label = g.causal_label(&[web, file], now).unwrap();
        assert_eq!(
            label.integrity,
            portcullis_core::IntegLevel::Adversarial,
            "mixed parents should propagate the worst label"
        );
    }

    #[test]
    fn causal_label_matches_insert_action_label() {
        let mut g = FlowGraph::new();
        let now = 1000;

        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();

        // Query the causal label
        let queried = g.causal_label(&[web], now).unwrap();

        // Actually insert the action
        let decision = g.insert_action(Operation::WriteFiles, &[web], now).unwrap();
        let inserted = g.get(decision.node_id).unwrap().label;

        assert_eq!(
            queried, inserted,
            "causal_label query must match the label of an actually inserted action"
        );
    }

    #[test]
    fn causal_label_invalid_parent_returns_error() {
        let g = FlowGraph::new();
        let result = g.causal_label(&[999], 1000);
        assert!(result.is_err());
    }

    // ── DeclassificationToken integration tests ──────────────────────

    #[test]
    fn apply_token_raises_integrity() {
        use portcullis_core::declassify::*;

        let mut g = FlowGraph::new();
        let now = 1000;

        // Insert web content (adversarial integrity)
        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        let web_label = g.get(web).unwrap().label;
        assert_eq!(
            web_label.integrity,
            portcullis_core::IntegLevel::Adversarial
        );

        // Create a token to raise integrity for this specific node
        let token = DeclassificationToken::new(
            web,
            DeclassificationRule {
                action: DeclassifyAction::RaiseIntegrity {
                    from: portcullis_core::IntegLevel::Adversarial,
                    to: portcullis_core::IntegLevel::Untrusted,
                },
                justification: "Validated search results",
            },
            vec![Operation::WriteFiles, Operation::GitCommit],
            now + 3600,
            "Curated API output".to_string(),
        );

        let result = g.apply_token(&token, now);
        match result {
            TokenApplyResult::Applied {
                original_label,
                new_label,
            } => {
                assert_eq!(
                    original_label.integrity,
                    portcullis_core::IntegLevel::Adversarial
                );
                assert_eq!(new_label.integrity, portcullis_core::IntegLevel::Untrusted);
            }
            other => panic!("Expected Applied, got {other:?}"),
        }

        // Verify the node's label was actually modified in the graph
        assert_eq!(
            g.get(web).unwrap().label.integrity,
            portcullis_core::IntegLevel::Untrusted
        );
    }

    #[test]
    fn apply_token_expired() {
        use portcullis_core::declassify::*;

        let mut g = FlowGraph::new();
        let now = 1000;
        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();

        let token = DeclassificationToken::new(
            web,
            DeclassificationRule {
                action: DeclassifyAction::RaiseIntegrity {
                    from: portcullis_core::IntegLevel::Adversarial,
                    to: portcullis_core::IntegLevel::Untrusted,
                },
                justification: "test",
            },
            vec![Operation::WriteFiles],
            999, // expired before now=1000
            "expired token".to_string(),
        );

        let result = g.apply_token(&token, now);
        assert!(matches!(result, TokenApplyResult::Expired { .. }));

        // Label should be unchanged
        assert_eq!(
            g.get(web).unwrap().label.integrity,
            portcullis_core::IntegLevel::Adversarial
        );
    }

    #[test]
    fn apply_token_node_not_found() {
        use portcullis_core::declassify::*;

        let mut g = FlowGraph::new();
        let token = DeclassificationToken::new(
            999, // nonexistent
            DeclassificationRule {
                action: DeclassifyAction::RaiseIntegrity {
                    from: portcullis_core::IntegLevel::Adversarial,
                    to: portcullis_core::IntegLevel::Untrusted,
                },
                justification: "test",
            },
            vec![],
            u64::MAX,
            "ghost node".to_string(),
        );

        assert!(matches!(
            g.apply_token(&token, 1000),
            TokenApplyResult::NodeNotFound
        ));
    }

    #[test]
    fn apply_token_precondition_unmet() {
        use portcullis_core::declassify::*;

        let mut g = FlowGraph::new();
        let now = 1000;

        // FileRead has Trusted integrity — rule expects Adversarial
        let file = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();

        let token = DeclassificationToken::new(
            file,
            DeclassificationRule {
                action: DeclassifyAction::RaiseIntegrity {
                    from: portcullis_core::IntegLevel::Adversarial,
                    to: portcullis_core::IntegLevel::Untrusted,
                },
                justification: "test",
            },
            vec![Operation::WriteFiles],
            u64::MAX,
            "wrong precondition".to_string(),
        );

        assert!(matches!(
            g.apply_token(&token, now),
            TokenApplyResult::PreconditionUnmet
        ));
    }

    // ── Artifact-granular quarantine tests (#639) ───────────────────

    #[test]
    fn quarantine_nonexistent_node_returns_false() {
        let mut g = FlowGraph::new();
        assert!(!g.quarantine(999));
    }

    #[test]
    fn quarantine_and_check_direct() {
        let mut g = FlowGraph::new();
        let now = 1000;
        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        assert!(!g.is_quarantined(web));
        assert!(g.quarantine(web));
        assert!(g.is_quarantined(web));
    }

    #[test]
    fn quarantine_idempotent() {
        let mut g = FlowGraph::new();
        let now = 1000;
        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        assert!(g.quarantine(web)); // first time: true (newly inserted)
        assert!(!g.quarantine(web)); // second time: false (already present)
        assert!(g.is_quarantined(web));
    }

    #[test]
    fn quarantine_propagates_to_descendants() {
        let mut g = FlowGraph::new();
        let now = 1000;

        // Web content → model plan → action chain
        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        let plan = g
            .insert_observation(NodeKind::ModelPlan, &[web], now)
            .unwrap();
        let summary = g
            .insert_observation(NodeKind::Summarization, &[plan], now)
            .unwrap();

        // Quarantine the web content node
        g.quarantine(web);

        // All descendants should be quarantined via ancestry
        assert!(g.is_quarantined(plan), "child of quarantined node");
        assert!(g.is_quarantined(summary), "grandchild of quarantined node");
    }

    #[test]
    fn quarantine_independent_branch_not_affected() {
        let mut g = FlowGraph::new();
        let now = 1000;

        // Branch A: web content (will be quarantined)
        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        let web_plan = g
            .insert_observation(NodeKind::ModelPlan, &[web], now)
            .unwrap();

        // Branch B: local file (independent, clean)
        let file = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
        let file_plan = g
            .insert_observation(NodeKind::ModelPlan, &[file], now)
            .unwrap();

        // Quarantine web content
        g.quarantine(web);

        // Branch A is quarantined
        assert!(g.is_quarantined(web));
        assert!(g.is_quarantined(web_plan));

        // Branch B is NOT quarantined
        assert!(!g.is_quarantined(file), "independent file not quarantined");
        assert!(
            !g.is_quarantined(file_plan),
            "independent file plan not quarantined"
        );
    }

    #[test]
    fn quarantined_ancestors_returns_specific_nodes() {
        let mut g = FlowGraph::new();
        let now = 1000;

        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        let plan = g
            .insert_observation(NodeKind::ModelPlan, &[web], now)
            .unwrap();
        let summary = g
            .insert_observation(NodeKind::Summarization, &[plan], now)
            .unwrap();

        g.quarantine(web);

        let qa = g.quarantined_ancestors(summary);
        assert_eq!(
            qa,
            vec![web],
            "should identify the exact quarantined ancestor"
        );
    }

    #[test]
    fn quarantined_ancestors_multiple() {
        let mut g = FlowGraph::new();
        let now = 1000;

        let web1 = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        let web2 = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        let merged = g
            .insert_observation(NodeKind::ModelPlan, &[web1, web2], now)
            .unwrap();

        g.quarantine(web1);
        g.quarantine(web2);

        let mut qa = g.quarantined_ancestors(merged);
        qa.sort();
        assert_eq!(qa, vec![web1, web2]);
    }

    #[test]
    fn insert_action_inherits_quarantine_from_parent() {
        let mut g = FlowGraph::new();
        let now = 1000;

        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        g.quarantine(web);

        // Insert an action with the quarantined parent
        let decision = g.insert_action(Operation::WriteFiles, &[web], now).unwrap();

        // The action node should be quarantined
        assert!(
            g.is_quarantined(decision.node_id),
            "action with quarantined parent should inherit quarantine"
        );
    }

    #[test]
    fn insert_observation_inherits_quarantine_from_parent() {
        let mut g = FlowGraph::new();
        let now = 1000;

        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        g.quarantine(web);

        // Insert observation with quarantined parent
        let plan = g
            .insert_observation(NodeKind::ModelPlan, &[web], now)
            .unwrap();

        assert!(
            g.is_quarantined(plan),
            "observation with quarantined parent should inherit quarantine"
        );
    }

    #[test]
    fn insert_action_clean_parents_not_quarantined() {
        let mut g = FlowGraph::new();
        let now = 1000;

        let file = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
        let decision = g
            .insert_action(Operation::WriteFiles, &[file], now)
            .unwrap();

        assert!(
            !g.is_quarantined(decision.node_id),
            "action with clean parents should not be quarantined"
        );
    }

    #[test]
    fn release_quarantine() {
        let mut g = FlowGraph::new();
        let now = 1000;

        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        g.quarantine(web);
        assert!(g.is_quarantined(web));

        assert!(g.release_quarantine(web));
        assert!(!g.is_quarantined(web));

        // Double release returns false
        assert!(!g.release_quarantine(web));
    }

    #[test]
    fn release_quarantine_stops_propagation() {
        let mut g = FlowGraph::new();
        let now = 1000;

        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        let plan = g
            .insert_observation(NodeKind::ModelPlan, &[web], now)
            .unwrap();

        g.quarantine(web);
        assert!(g.is_quarantined(plan));

        // Release the quarantine on web
        g.release_quarantine(web);

        // plan should no longer be quarantined (the ancestor is released)
        assert!(
            !g.is_quarantined(plan),
            "after releasing ancestor quarantine, descendant should be clean"
        );
    }

    #[test]
    fn check_flow_with_quarantine_clean() {
        let mut g = FlowGraph::new();
        let now = 1000;

        let user = g
            .insert_observation(NodeKind::UserPrompt, &[], now)
            .unwrap();
        let decision = g
            .insert_action(Operation::WriteFiles, &[user], now)
            .unwrap();

        let qv = g.check_flow_with_quarantine(decision.node_id, now).unwrap();
        assert_eq!(
            qv,
            QuarantineVerdict::Clean(FlowVerdict::Allow),
            "clean node should get Clean verdict"
        );
    }

    #[test]
    fn check_flow_with_quarantine_blocked() {
        let mut g = FlowGraph::new();
        let now = 1000;

        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        g.quarantine(web);

        // Even though this action is also denied by IFC (web taint),
        // the quarantine verdict takes precedence
        let decision = g.insert_action(Operation::WriteFiles, &[web], now).unwrap();
        let qv = g.check_flow_with_quarantine(decision.node_id, now).unwrap();

        match qv {
            QuarantineVerdict::Quarantined {
                quarantined_ancestors,
                underlying_verdict,
            } => {
                // The action itself is quarantined (inherited from web parent)
                assert!(
                    quarantined_ancestors.contains(&decision.node_id)
                        || quarantined_ancestors.contains(&web),
                    "should identify quarantined ancestor(s)"
                );
                // The underlying IFC verdict should also be Deny
                assert!(
                    matches!(underlying_verdict, FlowVerdict::Deny(_)),
                    "underlying verdict should also be deny for web-tainted action"
                );
            }
            other => panic!("Expected Quarantined, got {other:?}"),
        }
    }

    /// THE KEY QUARANTINE TEST: malicious issue quarantined, unrelated code clean
    #[test]
    fn quarantine_scenario_malicious_issue_vs_clean_code() {
        let mut g = FlowGraph::new();
        let now = 1000;

        // Agent reads malicious GitHub issue (web content)
        let malicious_issue = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();

        // Agent produces a summary from the malicious issue
        let summary = g
            .insert_observation(NodeKind::Summarization, &[malicious_issue], now)
            .unwrap();

        // Agent also reads local code (independent branch)
        let local_code = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();

        // Agent edits code based ONLY on local code (no dependency on issue)
        let code_edit = g
            .insert_action(Operation::WriteFiles, &[local_code], now)
            .unwrap();

        // Quarantine the malicious issue
        g.quarantine(malicious_issue);

        // Summary (from malicious issue) is quarantined
        assert!(
            g.is_quarantined(summary),
            "summary derived from quarantined issue should be quarantined"
        );

        // Code edit (independent branch) is NOT quarantined
        assert!(
            !g.is_quarantined(code_edit.node_id),
            "code edit from clean local code should NOT be quarantined"
        );

        // Summary cannot reach GitPush (quarantine check)
        let summary_action = g
            .insert_action(Operation::GitPush, &[summary], now)
            .unwrap();
        let qv = g
            .check_flow_with_quarantine(summary_action.node_id, now)
            .unwrap();
        assert!(
            matches!(qv, QuarantineVerdict::Quarantined { .. }),
            "action from quarantined summary should be blocked"
        );

        // Code edit CAN reach GitPush (no quarantine)
        // (It may still be denied by IFC rules, but no quarantine)
        let code_push = g
            .insert_action(Operation::GitPush, &[local_code], now)
            .unwrap();
        let qv2 = g
            .check_flow_with_quarantine(code_push.node_id, now)
            .unwrap();
        assert!(
            matches!(qv2, QuarantineVerdict::Clean(_)),
            "action from clean code should not be quarantined"
        );
    }

    #[test]
    fn error_display_quarantined_parent() {
        let e = FlowGraphError::QuarantinedParent(7);
        assert!(e.to_string().contains("7"));
        assert!(e.to_string().contains("quarantined"));
    }

    // ── Trusted ancestry check tests (#515) ────────────────────────

    #[test]
    fn trusted_ancestry_file_reads_only() {
        let mut g = FlowGraph::new();
        let now = 1000;

        let user = g
            .insert_observation(NodeKind::UserPrompt, &[], now)
            .unwrap();
        let file = g
            .insert_observation(NodeKind::FileRead, &[user], now)
            .unwrap();
        let plan = g
            .insert_observation(NodeKind::ModelPlan, &[file], now)
            .unwrap();

        assert_eq!(
            g.check_trusted_ancestry(plan),
            Some(TrustAncestryResult::Trusted),
            "chain of user prompt → file read → model plan should be trusted"
        );
    }

    #[test]
    fn trusted_ancestry_web_ancestor_untrusted() {
        let mut g = FlowGraph::new();
        let now = 1000;

        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        let plan = g
            .insert_observation(NodeKind::ModelPlan, &[web], now)
            .unwrap();

        match g.check_trusted_ancestry(plan) {
            Some(TrustAncestryResult::Untrusted { tainted_ancestors }) => {
                // The web node (Adversarial integrity) should be flagged.
                // The plan node inherits Adversarial via propagation, so both are tainted.
                assert!(
                    tainted_ancestors.contains(&web),
                    "web content node should be in tainted ancestors"
                );
                assert!(
                    tainted_ancestors.contains(&plan),
                    "plan node (inherits Adversarial from web) should be tainted"
                );
            }
            other => panic!("Expected Untrusted, got {other:?}"),
        }
    }

    #[test]
    fn trusted_ancestry_declassified_web_content_trusted() {
        use portcullis_core::declassify::*;

        let mut g = FlowGraph::new();
        let now = 1000;

        // Web content starts as Adversarial
        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        assert_eq!(
            g.get(web).unwrap().label.integrity,
            portcullis_core::IntegLevel::Adversarial
        );

        // Declassify: raise integrity from Adversarial to Untrusted
        let token = DeclassificationToken::new(
            web,
            DeclassificationRule {
                action: DeclassifyAction::RaiseIntegrity {
                    from: portcullis_core::IntegLevel::Adversarial,
                    to: portcullis_core::IntegLevel::Untrusted,
                },
                justification: "Operator reviewed search results",
            },
            vec![Operation::WriteFiles],
            now + 3600,
            "Curated search output".to_string(),
        );
        let result = g.apply_token(&token, now);
        assert!(matches!(result, TokenApplyResult::Applied { .. }));

        // Insert a plan node depending on the declassified web content
        let plan = g
            .insert_observation(NodeKind::ModelPlan, &[web], now)
            .unwrap();

        // The plan inherits Untrusted (from declassified web) — which is
        // >= Untrusted, so the ancestry check should pass.
        assert_eq!(
            g.check_trusted_ancestry(plan),
            Some(TrustAncestryResult::Trusted),
            "declassified web content (Untrusted) should pass trusted ancestry check"
        );
    }

    #[test]
    fn trusted_ancestry_nonexistent_node_returns_none() {
        let g = FlowGraph::new();
        assert_eq!(g.check_trusted_ancestry(999), None);
    }

    #[test]
    fn trusted_ancestry_root_node_no_parents() {
        let mut g = FlowGraph::new();
        let now = 1000;

        // A file read with no parents — Trusted integrity
        let file = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
        assert_eq!(
            g.check_trusted_ancestry(file),
            Some(TrustAncestryResult::Trusted),
        );

        // A web content with no parents — Adversarial integrity
        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        match g.check_trusted_ancestry(web) {
            Some(TrustAncestryResult::Untrusted { tainted_ancestors }) => {
                assert_eq!(tainted_ancestors, vec![web]);
            }
            other => panic!("Expected Untrusted, got {other:?}"),
        }
    }

    #[test]
    fn trusted_ancestry_independent_branch_not_affected() {
        let mut g = FlowGraph::new();
        let now = 1000;

        // Branch A: web content (adversarial)
        let _web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();

        // Branch B: clean file chain (independent)
        let user = g
            .insert_observation(NodeKind::UserPrompt, &[], now)
            .unwrap();
        let file = g
            .insert_observation(NodeKind::FileRead, &[user], now)
            .unwrap();

        // Branch B should be trusted — web content in branch A is irrelevant
        assert_eq!(
            g.check_trusted_ancestry(file),
            Some(TrustAncestryResult::Trusted),
            "independent branch should not be tainted by unrelated web content"
        );
    }

    #[test]
    fn trusted_ancestry_mixed_parents_one_tainted() {
        let mut g = FlowGraph::new();
        let now = 1000;

        let file = g.insert_observation(NodeKind::FileRead, &[], now).unwrap();
        let web = g
            .insert_observation(NodeKind::WebContent, &[], now)
            .unwrap();
        let merged = g
            .insert_observation(NodeKind::ModelPlan, &[file, web], now)
            .unwrap();

        match g.check_trusted_ancestry(merged) {
            Some(TrustAncestryResult::Untrusted { tainted_ancestors }) => {
                assert!(
                    tainted_ancestors.contains(&web),
                    "web ancestor should be in tainted list"
                );
            }
            other => panic!("Expected Untrusted, got {other:?}"),
        }
    }
}
