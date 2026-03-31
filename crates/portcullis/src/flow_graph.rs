//! Runtime causal DAG for precise information flow tracking.
//!
//! Eliminates the over-tainting problem: instead of a flat session-level
//! label accumulator (where reading web content blocks ALL subsequent writes),
//! the DAG tracks actual causal dependencies. An action that depends only on
//! local files is unaffected by web content read elsewhere in the session.

use std::collections::VecDeque;

use portcullis_core::flow::{
    check_flow, intrinsic_label, propagate_label, FlowNode, FlowVerdict, NodeId, NodeKind,
    MAX_PARENTS,
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

/// Append-only causal DAG for information flow tracking.
///
/// Nodes are indexed by sequential `NodeId` (u64). Index 0 is the sentinel
/// (no parent). Real nodes start at 1.
///
/// Denied action nodes are tracked but cannot be referenced as parents —
/// a denied action did not execute, so it has no causal effect.
/// The denied set is capped at [`MAX_DENIED_NODES`] with oldest-first eviction.
pub struct FlowGraph {
    nodes: Vec<Option<FlowNode>>,
    next_id: u64,
    /// Node IDs of denied actions — cannot be used as parents.
    /// Capped at MAX_DENIED_NODES to prevent unbounded growth in
    /// long-running sessions.
    denied: std::collections::BTreeSet<NodeId>,
}

impl FlowGraph {
    /// Create an empty graph. Index 0 is reserved as sentinel.
    pub fn new() -> Self {
        Self {
            nodes: vec![None], // index 0 = sentinel
            next_id: 1,
            denied: std::collections::BTreeSet::new(),
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

    /// Insert a data-source observation. NOT flow-checked.
    pub fn insert_observation(
        &mut self,
        kind: NodeKind,
        parents: &[NodeId],
        now: u64,
    ) -> Result<NodeId, FlowGraphError> {
        self.validate_parents(parents)?;
        let label = propagate_label(&self.gather_labels(parents), intrinsic_label(kind, now));
        let id = self.alloc_node(kind, label, parents, None);
        Ok(id)
    }

    /// Atomic check-and-insert for action nodes.
    pub fn insert_action(
        &mut self,
        operation: Operation,
        parents: &[NodeId],
        now: u64,
    ) -> Result<FlowDecision, FlowGraphError> {
        self.validate_parents(parents)?;
        let label = propagate_label(
            &self.gather_labels(parents),
            intrinsic_label(NodeKind::OutboundAction, now),
        );
        let node = self.build_node(NodeKind::OutboundAction, label, parents, Some(operation));
        let verdict = check_flow(&node, now);
        let id = self.next_id;
        self.nodes.push(Some(node));
        self.next_id += 1;
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
}
