//! Runtime causal DAG for precise information flow tracking.
//!
//! Eliminates the over-tainting problem: instead of a flat session-level
//! label accumulator (where reading web content blocks ALL subsequent writes),
//! the DAG tracks actual causal dependencies. An action that depends only on
//! local files is unaffected by web content read elsewhere in the session.

use std::collections::{BTreeSet, HashMap, VecDeque};

use tracing::warn;

use portcullis_core::effect::EffectKind;
use portcullis_core::flow::{
    check_flow, intrinsic_label, propagate_label, FlowNode, FlowVerdict, NodeId, NodeKind,
    QuarantineVerdict, TrustAncestryResult, MAX_PARENTS,
};
use portcullis_core::receipt::{
    build_receipt, FlowReceipt, TombstonedAncestor, MAX_RECEIPT_ANCESTORS,
};
use portcullis_core::{default_sink_class, IFCLabel, Operation, SinkClass};

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
    /// A DeterministicBind node has a parent with AIDerived/Mixed derivation.
    /// This would break the deterministic data path invariant (#922).
    DeterministicBindTainted(
        /// The tainted parent node ID.
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
            FlowGraphError::DeniedParent(id) => {
                write!(f, "parent {id} was denied — cannot be a causal ancestor")
            }
            FlowGraphError::QuarantinedParent(id) => {
                write!(
                    f,
                    "parent {id} is quarantined — release quarantine before use"
                )
            }
            FlowGraphError::DeterministicBindTainted(id) => {
                write!(
                    f,
                    "parent {id} has AI-derived taint — DeterministicBind requires clean ancestry"
                )
            }
        }
    }
}

impl std::error::Error for FlowGraphError {}

/// Errors specific to quarantine operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuarantineError {
    /// Attempted to release a node that is not quarantined.
    NotQuarantined(NodeId),
}

impl std::fmt::Display for QuarantineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QuarantineError::NotQuarantined(id) => {
                write!(f, "node {id} is not quarantined — cannot release")
            }
        }
    }
}

impl std::error::Error for QuarantineError {}

/// Audit record of a quarantine release.
///
/// Every successful quarantine release produces one of these records,
/// capturing who released it, why, and when. This provides an audit
/// trail for a security-critical operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantineRelease {
    /// The node that was released from quarantine.
    pub node_id: NodeId,
    /// The principal (identity) that authorized the release.
    pub released_by: String,
    /// Human-readable justification for the release.
    pub reason: String,
    /// Timestamp (epoch seconds) when the release occurred.
    pub released_at: u64,
}

// ═══════════════════════════════════════════════════════════════════════════
// Field-level lineage (DPI §13, #711)
// ═══════════════════════════════════════════════════════════════════════════

/// A reference to a specific field on a specific node.
///
/// This is the atomic unit of field-level provenance: "field X on node Y".
/// Used in [`FieldLineage`] to express which source fields contributed to
/// an output field.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FieldRef {
    /// The node that contains this field.
    pub node_id: NodeId,
    /// The field name within that node's structured output.
    pub field_name: String,
}

/// Field-level lineage record for a single output field.
///
/// Captures the fine-grained provenance of one field in a node's structured
/// output: which source fields contributed, what kind of effect produced it,
/// and what derivation class it carries. This enables mixed rows where some
/// fields are deterministic (price from a database) and others are AI-derived
/// (summary from an LLM), each with their own label — rather than tainting
/// the entire row as `Mixed`.
///
/// The field's effective IFC label is the join of all source field labels,
/// refined by the `derivation` override. This is strictly more precise than
/// node-level labeling: `field_label <= node_label` (monotonicity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldLineage {
    /// The name of the output field this lineage describes.
    pub field_name: String,
    /// The source fields that contributed to this output field.
    /// Each entry is a `(node_id, field_name)` pair identifying an input field.
    pub source_fields: Vec<FieldRef>,
    /// The effect kind that produced this field (e.g., PureTransform, LLMGenerate).
    pub effect_kind: EffectKind,
    /// The derivation class of this specific field. This may differ from the
    /// node-level derivation: a node that produces both deterministic and
    /// AI-derived fields will have `Mixed` at the node level, but individual
    /// fields can be `Deterministic` or `AIDerived`.
    pub derivation: portcullis_core::DerivationClass,
}

/// Errors from field lineage operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldLineageError {
    /// The target node does not exist in the graph.
    NodeNotFound(NodeId),
    /// A source field references a node that does not exist.
    SourceNodeNotFound {
        /// The field lineage entry that has the bad reference.
        field_name: String,
        /// The missing source node ID.
        source_node_id: NodeId,
    },
}

impl std::fmt::Display for FieldLineageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FieldLineageError::NodeNotFound(id) => write!(f, "node {id} not found"),
            FieldLineageError::SourceNodeNotFound {
                field_name,
                source_node_id,
            } => write!(
                f,
                "field '{field_name}' references source node {source_node_id} which does not exist"
            ),
        }
    }
}

impl std::error::Error for FieldLineageError {}

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

/// Maximum number of slots in the nodes Vec before compaction.
///
/// When this limit is reached, old non-essential nodes are tombstoned
/// (set to `None`) to cap memory. The sentinel (index 0), denied nodes,
/// quarantined nodes, and the most recent `MAX_GRAPH_NODES / 2` nodes
/// are preserved.
const MAX_GRAPH_NODES: usize = 10_000;

/// Warn when the graph reaches this fraction of MAX_GRAPH_NODES.
const GRAPH_WARN_THRESHOLD: usize = MAX_GRAPH_NODES * 8 / 10; // 80%

/// Maximum number of entries in the compaction audit log.
/// Oldest entries are evicted when this cap is reached.
const MAX_COMPACTION_LOG: usize = 1000;

/// Maximum number of entries in the quarantine-release audit log.
/// Oldest entries are evicted when this cap is reached.
const MAX_QUARANTINE_RELEASES: usize = 1000;

/// Record of a node that was tombstoned during compaction.
///
/// When `maybe_compact()` removes old nodes to cap memory, it preserves
/// the node's IFC label as a compaction record. The label captures the
/// join of all ancestry — so even though individual ancestor nodes are
/// gone, the taint information is preserved. This prevents "compaction
/// laundering" where an attacker could exploit memory management to
/// silently erase tainted ancestry from audit trails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionRecord {
    /// The ID of the node that was compacted (tombstoned).
    pub compacted_node_id: NodeId,
    /// The IFC label of the node at the time of compaction.
    /// This label is the join of all the node's causal ancestors,
    /// preserving taint even though ancestors are gone.
    pub preserved_label: IFCLabel,
    /// Number of direct parents the node had before compaction.
    pub original_parent_count: u8,
    /// Timestamp (logical) when compaction occurred.
    pub compacted_at: u64,
}

/// Result of an ancestor traversal, including information about
/// tombstoned nodes encountered during the walk.
///
/// When compaction has occurred, some ancestor slots will be `None`.
/// Instead of silently skipping them (which erases the audit trail),
/// we report the compaction records so callers know the chain is
/// incomplete and can see the preserved labels.
#[derive(Debug, Clone)]
pub struct AncestryResult<'a> {
    /// Live ancestor nodes found during BFS traversal.
    pub ancestors: Vec<&'a FlowNode>,
    /// Compaction records for tombstoned nodes encountered during traversal.
    /// Non-empty means the causal chain is incomplete — some ancestors
    /// were compacted. The preserved labels still carry their taint.
    pub tombstoned: Vec<CompactionRecord>,
}

impl<'a> AncestryResult<'a> {
    /// Whether the ancestry chain is complete (no tombstoned nodes).
    pub fn is_complete(&self) -> bool {
        self.tombstoned.is_empty()
    }

    /// Total number of tombstoned ancestors encountered.
    pub fn tombstoned_count(&self) -> usize {
        self.tombstoned.len()
    }
}

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
    /// Audit log of compacted nodes, preserving their labels.
    /// Prevents "compaction laundering" — the taint information survives
    /// even when the node itself is tombstoned for memory management.
    compaction_log: Vec<CompactionRecord>,
    /// Audit log of quarantine releases. Every successful call to
    /// `release_quarantine()` appends a record here, capturing the
    /// principal, reason, and timestamp.
    quarantine_releases: Vec<QuarantineRelease>,
    /// Field-level lineage annotations, keyed by node ID.
    ///
    /// Stored separately from `FlowNode` (which is `Copy` in portcullis-core)
    /// because field lineage uses heap-allocated strings and vectors.
    /// Most nodes have no field lineage — only nodes that produce structured
    /// output (rows, records) need this annotation.
    field_lineage: HashMap<NodeId, Vec<FieldLineage>>,
    /// Frozen node IDs whose labels cannot be modified (#947).
    /// Prevents retroactive taint laundering — once a node is frozen,
    /// its label is immutable. The only legitimate label change path
    /// is `modify_label_with_token()` which requires a signed
    /// `DeclassificationToken`.
    frozen: BTreeSet<NodeId>,
}

impl FlowGraph {
    /// Create an empty graph. Index 0 is reserved as sentinel.
    pub fn new() -> Self {
        Self {
            nodes: vec![None], // index 0 = sentinel
            next_id: 1,
            denied: BTreeSet::new(),
            quarantined: BTreeSet::new(),
            compaction_log: Vec::new(),
            quarantine_releases: Vec::new(),
            field_lineage: HashMap::new(),
            frozen: BTreeSet::new(),
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

    /// Total number of slots in the backing Vec (including tombstones
    /// and the sentinel). This reflects actual memory usage, unlike
    /// `len()` which counts only live nodes.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Look up a node by ID. O(1).
    pub fn get(&self, id: NodeId) -> Option<&FlowNode> {
        self.nodes.get(id as usize)?.as_ref()
    }

    /// Apply a label modification to an existing node (for declassification).
    ///
    /// Only modifies the label — does not change the node's kind, parents,
    /// or operation. Returns the previous label for audit.
    ///
    /// **Fails if the node is frozen** (#947). Frozen nodes require
    /// `modify_label_forced()` with explicit justification (e.g., a signed
    /// `DeclassificationToken` verified by the caller).
    pub fn modify_label(&mut self, id: NodeId, new_label: IFCLabel) -> Option<IFCLabel> {
        if self.frozen.contains(&id) {
            return None;
        }
        let node = self.nodes.get_mut(id as usize)?.as_mut()?;
        let old = node.label;
        node.label = new_label;
        Some(old)
    }

    /// Force a label modification on a frozen node (#947).
    ///
    /// The caller is responsible for verifying authorization (e.g.,
    /// checking a signed `DeclassificationToken`). This bypass exists
    /// because legitimate declassification must still be possible —
    /// but it's a separate, auditable code path.
    pub fn modify_label_forced(&mut self, id: NodeId, new_label: IFCLabel) -> Option<IFCLabel> {
        let node = self.nodes.get_mut(id as usize)?.as_mut()?;
        let old = node.label;
        node.label = new_label;
        Some(old)
    }

    /// Freeze all currently existing nodes (#947).
    ///
    /// After this call, `modify_label()` will return `None` for any
    /// existing node. Only `modify_label_forced()` can change them.
    /// New nodes inserted after freeze are NOT frozen — they get
    /// frozen on the next call to `freeze_all()`.
    pub fn freeze_all(&mut self) {
        for id in 1..self.next_id {
            if self.nodes.get(id as usize).is_some_and(|n| n.is_some()) {
                self.frozen.insert(id);
            }
        }
    }

    /// Number of frozen nodes.
    pub fn frozen_count(&self) -> usize {
        self.frozen.len()
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

        // DeterministicBind nodes require all parents to have Deterministic derivation.
        // This prevents AI-derived taint from entering the deterministic data path (#922).
        if kind == NodeKind::DeterministicBind {
            for &pid in parents {
                if let Some(node) = self.get(pid) {
                    if !matches!(
                        node.label.derivation,
                        portcullis_core::DerivationClass::Deterministic
                    ) {
                        return Err(FlowGraphError::DeterministicBindTainted(pid));
                    }
                }
            }
        }

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
        self.insert_action_with_effect(operation, parents, now, None)
    }

    /// Like [`insert_action`](Self::insert_action) but attaches an [`EffectKind`] (#775).
    pub fn insert_action_with_effect(
        &mut self,
        operation: Operation,
        parents: &[NodeId],
        now: u64,
        effect_kind: Option<EffectKind>,
    ) -> Result<FlowDecision, FlowGraphError> {
        self.validate_parents(parents)?;

        // Check if any parent is quarantined (directly or transitively)
        let any_parent_quarantined = parents.iter().any(|&pid| self.is_quarantined(pid));

        let label = propagate_label(
            &self.gather_labels(parents),
            intrinsic_label(NodeKind::OutboundAction, now),
        );
        let sink_class = Some(default_sink_class(operation));
        let node = self.build_node_with_effect(
            NodeKind::OutboundAction,
            label,
            parents,
            Some(operation),
            sink_class,
            effect_kind,
        );
        let verdict = check_flow(&node, now);
        self.maybe_compact();
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
    ///
    /// Returns an [`AncestryResult`] containing both the live ancestor nodes
    /// and any compaction records for tombstoned nodes encountered during
    /// traversal. If `tombstoned` is non-empty, the causal chain is
    /// incomplete — callers should treat the ancestry as truncated and
    /// include the compaction records in audit output.
    pub fn ancestors(&self, id: NodeId) -> AncestryResult<'_> {
        let mut result = Vec::new();
        let mut tombstoned = Vec::new();
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
            } else {
                // Node was tombstoned — look up its compaction record.
                // This is the key fix for #782: instead of silently dropping
                // the ancestor, we include the compaction record so the
                // audit trail shows that compaction occurred and what label
                // (taint) the compacted node carried.
                //
                // If the compaction record was evicted (log capped at
                // MAX_COMPACTION_LOG, #836), synthesize a minimal record
                // so ancestor traversal still reports the gap.
                if let Some(record) = self
                    .compaction_log
                    .iter()
                    .find(|r| r.compacted_node_id == nid)
                {
                    tombstoned.push(record.clone());
                } else {
                    // Record evicted from capped log — synthesize a
                    // placeholder so callers know a gap exists.
                    tombstoned.push(CompactionRecord {
                        compacted_node_id: nid,
                        preserved_label: IFCLabel::default(),
                        original_parent_count: 0,
                        compacted_at: 0,
                    });
                }
            }
        }

        AncestryResult {
            ancestors: result,
            tombstoned,
        }
    }

    /// Transitive ancestors via BFS (flat list, without compaction info).
    ///
    /// This is a convenience wrapper that returns only the live nodes,
    /// matching the pre-#782 API shape. Prefer [`ancestors()`] for
    /// audit-sensitive paths.
    pub fn ancestors_flat(&self, id: NodeId) -> Vec<&FlowNode> {
        self.ancestors(id).ancestors
    }

    /// Build a receipt from the causal chain of a node.
    ///
    /// If compaction has occurred and some ancestors are tombstoned,
    /// the receipt's `tombstoned_ancestors` field will be populated
    /// with the count and preserved labels, ensuring the audit trail
    /// records that the chain is incomplete.
    pub fn build_receipt_for(&self, id: NodeId, now: u64) -> Option<FlowReceipt> {
        let node = self.get(id)?;
        let ancestry = self.ancestors(id);
        let ancestor_refs: Vec<&FlowNode> = ancestry.ancestors.to_vec();
        let verdict = check_flow(node, now);
        let mut receipt = build_receipt(node, &ancestor_refs, verdict, now);

        if !ancestry.tombstoned.is_empty() {
            let tombstoned_labels: Vec<_> = ancestry
                .tombstoned
                .iter()
                .map(|r| TombstonedAncestor {
                    compacted_node_id: r.compacted_node_id,
                    preserved_label: r.preserved_label,
                })
                .collect();
            receipt.set_tombstoned_ancestors(tombstoned_labels);
        }

        Some(receipt)
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
        sink_class: Option<SinkClass>,
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
            sink_class,
            effect_kind: None,
        }
    }

    fn build_node_with_effect(
        &self,
        kind: NodeKind,
        label: IFCLabel,
        parents: &[NodeId],
        operation: Option<Operation>,
        sink_class: Option<SinkClass>,
        effect_kind: Option<EffectKind>,
    ) -> FlowNode {
        let mut node = self.build_node(kind, label, parents, operation, sink_class);
        node.effect_kind = effect_kind;
        node
    }

    fn alloc_node(
        &mut self,
        kind: NodeKind,
        label: IFCLabel,
        parents: &[NodeId],
        operation: Option<Operation>,
    ) -> NodeId {
        self.maybe_compact();
        let node = self.build_node(kind, label, parents, operation, None);
        let id = self.next_id;
        self.nodes.push(Some(node));
        self.next_id += 1;
        id
    }

    /// Compact the nodes Vec when it reaches `MAX_GRAPH_NODES`.
    ///
    /// Preserves:
    /// - Index 0 (sentinel)
    /// - All denied nodes (in `self.denied`)
    /// - All quarantined nodes (in `self.quarantined`)
    /// - The most recent `MAX_GRAPH_NODES / 2` nodes
    ///
    /// Everything else is tombstoned (`None`). The Vec is not
    /// reallocated — node IDs remain stable — but memory for the
    /// `FlowNode` payloads is freed.
    fn maybe_compact(&mut self) {
        let count = self.nodes.len();

        if count == GRAPH_WARN_THRESHOLD {
            warn!(
                nodes = count,
                max = MAX_GRAPH_NODES,
                "FlowGraph approaching node limit ({}/{})",
                count,
                MAX_GRAPH_NODES,
            );
        }

        if count < MAX_GRAPH_NODES {
            return;
        }

        warn!(
            nodes = count,
            max = MAX_GRAPH_NODES,
            "FlowGraph reached node limit, compacting"
        );

        // Keep the most recent half of slots (by index).
        let keep_from = count - MAX_GRAPH_NODES / 2;

        for i in 1..keep_from {
            let id = i as u64;
            // Preserve denied and quarantined nodes — they carry
            // security-critical state.
            if self.denied.contains(&id) || self.quarantined.contains(&id) {
                continue;
            }
            if let Some(node) = &self.nodes[i] {
                // Record the compaction BEFORE tombstoning (#782).
                // The node's label captures the join of all its ancestry,
                // so even though individual ancestor nodes may also be
                // tombstoned, the taint is preserved in the label.
                self.compaction_log.push(CompactionRecord {
                    compacted_node_id: node.id,
                    preserved_label: node.label,
                    original_parent_count: node.parent_count,
                    compacted_at: self.next_id, // logical timestamp
                });
                self.nodes[i] = None;
            }
        }

        // Cap compaction_log — evict oldest entries (#836).
        if self.compaction_log.len() > MAX_COMPACTION_LOG {
            let excess = self.compaction_log.len() - MAX_COMPACTION_LOG;
            self.compaction_log.drain(..excess);
        }

        // Cap quarantine_releases — evict oldest entries (#836).
        if self.quarantine_releases.len() > MAX_QUARANTINE_RELEASES {
            let excess = self.quarantine_releases.len() - MAX_QUARANTINE_RELEASES;
            self.quarantine_releases.drain(..excess);
        }

        // Remove field_lineage entries for tombstoned nodes (#836).
        self.field_lineage.retain(|nid, _| {
            let idx = *nid as usize;
            idx < self.nodes.len() && self.nodes[idx].is_some()
        });
    }

    /// Read-only access to the compaction audit log.
    ///
    /// Each entry records a node that was tombstoned during compaction,
    /// preserving its IFC label (which captures the join of all ancestry).
    /// Auditors can use this to verify that no taint was silently erased.
    pub fn compaction_log(&self) -> &[CompactionRecord] {
        &self.compaction_log
    }

    /// Apply a scoped declassification token to a specific node **without
    /// signature verification**.
    ///
    /// # Security Warning
    ///
    /// This method does **not** verify the token's Ed25519 signature.
    /// In production, use [`apply_token_verified()`](Self::apply_token_verified)
    /// which cryptographically verifies the signature against trusted keys
    /// before applying the declassification.
    ///
    /// This unverified method is retained for backward compatibility and
    /// testing scenarios where signature infrastructure is not available.
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

    /// Apply a declassification token with Ed25519 signature verification.
    ///
    /// Unlike `apply_token()`, this method **requires** a valid signature
    /// verified against at least one of the provided trusted public keys.
    /// Unsigned or tampered tokens are rejected with `InvalidSignature`.
    ///
    /// This is the recommended method for production use. The unverified
    /// `apply_token()` should only be used in tests.
    ///
    /// # Arguments
    ///
    /// * `token` — The declassification token to apply.
    /// * `trusted_keys` — Ed25519 public keys (32 bytes each) that may
    ///   have signed this token. Supports key rotation by accepting
    ///   multiple keys.
    /// * `now` — Current unix timestamp for expiry checking.
    #[cfg(feature = "crypto")]
    pub fn apply_token_verified(
        &mut self,
        token: &portcullis_core::declassify::DeclassificationToken,
        trusted_keys: &[&[u8]],
        now: u64,
    ) -> portcullis_core::declassify::TokenApplyResult {
        use portcullis_core::declassify::TokenApplyResult;

        // Verify signature FIRST — before any other checks
        if crate::token_sign::verify_token_any_key(token, trusted_keys).is_err() {
            return TokenApplyResult::InvalidSignature;
        }

        // Delegate to the existing apply logic
        self.apply_token(token, now)
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

    /// Release quarantine from a specific node with authorization.
    ///
    /// Requires a principal identity and justification reason. The release
    /// is recorded in the audit trail (`quarantine_releases`).
    ///
    /// Only removes the explicit quarantine mark — does not affect
    /// ancestors that may also be quarantined.
    ///
    /// Returns `Ok(QuarantineRelease)` with the audit record on success,
    /// or `Err(QuarantineError::NotQuarantined)` if the node was not
    /// quarantined.
    pub fn release_quarantine(
        &mut self,
        node_id: NodeId,
        principal: &str,
        reason: &str,
        now: u64,
    ) -> Result<QuarantineRelease, QuarantineError> {
        if !self.quarantined.remove(&node_id) {
            return Err(QuarantineError::NotQuarantined(node_id));
        }
        let record = QuarantineRelease {
            node_id,
            released_by: principal.to_string(),
            reason: reason.to_string(),
            released_at: now,
        };
        self.quarantine_releases.push(record.clone());
        Ok(record)
    }

    /// Returns the audit log of quarantine releases.
    pub fn quarantine_releases(&self) -> &[QuarantineRelease] {
        &self.quarantine_releases
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

    // ── Field-level lineage (DPI §13, #711) ────────────────────────────

    /// Annotate a node with field-level provenance after creation.
    ///
    /// This is the primary entry point for setting field lineage on a node
    /// that produces structured output (e.g., a row with named fields).
    /// Each [`FieldLineage`] entry describes one output field: its name,
    /// which source fields contributed to it, and its derivation class.
    ///
    /// Validates that:
    /// 1. The target node exists in the graph
    /// 2. All source field references point to existing nodes
    ///
    /// Overwrites any previous field lineage for this node.
    pub fn set_field_lineage(
        &mut self,
        node_id: NodeId,
        fields: Vec<FieldLineage>,
    ) -> Result<(), FieldLineageError> {
        if self.get(node_id).is_none() {
            return Err(FieldLineageError::NodeNotFound(node_id));
        }
        // Validate all source node references exist
        for fl in &fields {
            for src in &fl.source_fields {
                if self.get(src.node_id).is_none() {
                    return Err(FieldLineageError::SourceNodeNotFound {
                        field_name: fl.field_name.clone(),
                        source_node_id: src.node_id,
                    });
                }
            }
        }
        self.field_lineage.insert(node_id, fields);
        Ok(())
    }

    /// Get the field lineage annotations for a node, if any.
    pub fn get_field_lineage(&self, node_id: NodeId) -> Option<&[FieldLineage]> {
        self.field_lineage.get(&node_id).map(|v| v.as_slice())
    }

    /// Trace a specific field's source nodes through the lineage chain.
    ///
    /// Returns the transitive closure of source node IDs for the named
    /// field on the given node. If the source fields themselves have field
    /// lineage, this recurses to find the ultimate sources.
    ///
    /// Returns an empty Vec if the node has no field lineage or the field
    /// is not found.
    pub fn field_ancestry(&self, node_id: NodeId, field_name: &str) -> Vec<NodeId> {
        let mut result = BTreeSet::new();
        let mut queue: VecDeque<(NodeId, String)> = VecDeque::new();
        queue.push_back((node_id, field_name.to_string()));

        while let Some((nid, fname)) = queue.pop_front() {
            if let Some(lineage_entries) = self.field_lineage.get(&nid) {
                if let Some(entry) = lineage_entries.iter().find(|fl| fl.field_name == fname) {
                    for src in &entry.source_fields {
                        if result.insert(src.node_id) {
                            // Recurse: if the source node also has field lineage
                            // for this source field, follow it
                            queue.push_back((src.node_id, src.field_name.clone()));
                        }
                    }
                }
            }
        }

        result.into_iter().collect()
    }

    /// Compute the IFC label for a specific field on a node.
    ///
    /// The field's label is the join of its source fields' node labels,
    /// with the derivation class overridden by the field lineage entry's
    /// `derivation` value. This is strictly more precise than the node-level
    /// label: a deterministic field on a Mixed node will have a Deterministic
    /// field label.
    ///
    /// Returns `None` if the node has no field lineage or the field is not
    /// found. In that case, callers should fall back to the node-level label.
    pub fn field_label(&self, node_id: NodeId, field_name: &str) -> Option<IFCLabel> {
        let lineage_entries = self.field_lineage.get(&node_id)?;
        let entry = lineage_entries
            .iter()
            .find(|fl| fl.field_name == field_name)?;

        if entry.source_fields.is_empty() {
            // No sources — use the node's own label with the field's derivation
            let node = self.get(node_id)?;
            let mut label = node.label;
            label.derivation = entry.derivation;
            return Some(label);
        }

        // Join the labels of all source nodes
        let mut label: Option<IFCLabel> = None;
        for src in &entry.source_fields {
            if let Some(src_node) = self.get(src.node_id) {
                // If the source node has field lineage for this source field,
                // use the field-specific label; otherwise use the node label
                let src_label = self
                    .field_label(src.node_id, &src.field_name)
                    .unwrap_or(src_node.label);
                label = Some(match label {
                    Some(existing) => existing.join(src_label),
                    None => src_label,
                });
            }
        }

        // Override the derivation class with the field-specific value
        label.map(|mut l| {
            l.derivation = entry.derivation;
            l
        })
    }
}

impl Default for FlowGraph {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "flow_graph_tests.rs"]
mod tests;
