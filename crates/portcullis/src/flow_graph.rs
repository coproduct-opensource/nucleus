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
}

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

/// Append-only causal DAG for information flow tracking.
///
/// Nodes are indexed by sequential `NodeId` (u64). Index 0 is the sentinel
/// (no parent). Real nodes start at 1.
pub struct FlowGraph {
    nodes: Vec<Option<FlowNode>>,
    next_id: u64,
}

impl FlowGraph {
    /// Create an empty graph. Index 0 is reserved as sentinel.
    pub fn new() -> Self {
        Self {
            nodes: vec![None], // index 0 = sentinel
            next_id: 1,
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
            if pid > 0 && self.get(pid).is_none() {
                return Err(FlowGraphError::ParentNotFound(pid));
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
}
