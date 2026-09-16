//! A command walk over [`FlowGraph`]'s causal structure, held to a model.
//!
//! Random sequences of observations, actions, quarantines and releases — with
//! parents drawn from existing nodes, the sentinel `0`, and ids that do not exist —
//! are applied to a real `FlowGraph` and to a model of a few dozen lines. After
//! every step, for every node, the graph must agree with the model on:
//!
//! - **the label law**: a node's label is its kind's intrinsic label joined with
//!   every parent's label (and `causal_label` answers the same for a hypothetical
//!   action);
//! - **parent validation**, in the graph's own order: too many parents, then per
//!   parent the sentinel, a missing node, a denied action;
//! - **ids and size**: ids are allocated densely from 1 and `len` counts them;
//! - **ancestry**: `ancestors` is the transitive parent set, excluding the node;
//! - **quarantine**: `quarantine` is true only when it newly quarantines an
//!   existing node; `is_quarantined` is "explicitly quarantined, or any ancestor
//!   is"; a node inserted under a quarantined parent is quarantined itself and
//!   STAYS so when that ancestor is released; `quarantined_ancestors` is the
//!   quarantined subset of the node and its ancestors; `quarantine` of a missing
//!   node is refused; releasing a node that is not explicitly quarantined fails;
//!   every release is logged with who, why and when.
//!
//! What is NOT modelled, and stays in `flow_graph_tests.rs`: the flow VERDICT
//! policy (whether an action is denied is taken from the graph, and only its
//! consequence — a denied action cannot be a parent — is checked), declass scopes
//! and tokens, compaction, field lineage, freezing, content hashes and receipts.
//! Walks stay far below the compaction threshold, so no node is tombstoned.

use std::collections::BTreeSet;

use proptest::prelude::*;

use super::*;
use portcullis_core::flow::{intrinsic_label, FlowVerdict, MAX_PARENTS};

const NOW: u64 = 1_000;

const KINDS: [NodeKind; 5] = [
    NodeKind::UserPrompt,
    NodeKind::WebContent,
    NodeKind::FileRead,
    NodeKind::ToolResponse,
    NodeKind::ModelPlan,
];

const OPS: [Operation; 5] = [
    Operation::ReadFiles,
    Operation::WriteFiles,
    Operation::WebFetch,
    Operation::GitPush,
    Operation::RunBash,
];

/// A parent (or target) as drawn by the walk, resolved against the current size.
#[derive(Debug, Clone, Copy)]
enum Pick {
    /// The `i`-th existing node, modulo how many exist.
    Existing(usize),
    Sentinel,
    Missing,
}

#[derive(Debug, Clone)]
enum Cmd {
    Observe(usize, Vec<Pick>),
    Act(usize, Vec<Pick>),
    Quarantine(Pick),
    Release(Pick),
}

fn pick() -> impl Strategy<Value = Pick> {
    prop_oneof![
        8 => any::<usize>().prop_map(Pick::Existing),
        1 => Just(Pick::Sentinel),
        1 => Just(Pick::Missing),
    ]
}

fn cmd() -> impl Strategy<Value = Cmd> {
    // Usually 0..=3 parents; sometimes one more than the graph allows.
    let parents = prop_oneof![
        12 => proptest::collection::vec(pick(), 0..=3),
        1 => proptest::collection::vec(pick(), MAX_PARENTS + 1..=MAX_PARENTS + 1),
    ];
    prop_oneof![
        4 => (0..KINDS.len(), parents.clone()).prop_map(|(k, p)| Cmd::Observe(k, p)),
        3 => (0..OPS.len(), parents).prop_map(|(o, p)| Cmd::Act(o, p)),
        2 => pick().prop_map(Cmd::Quarantine),
        2 => pick().prop_map(Cmd::Release),
    ]
}

#[derive(Default)]
struct Model {
    /// Index `i` is node id `i + 1`.
    parents: Vec<Vec<NodeId>>,
    labels: Vec<IFCLabel>,
    denied: BTreeSet<NodeId>,
    quarantined: BTreeSet<NodeId>,
    /// Every release, in order: (node, when). Who and why are fixed per walk.
    releases: Vec<(NodeId, u64)>,
}

/// What the walk saw happen, so a run that exercised nothing can be told apart.
#[derive(Debug, Default)]
struct Seen {
    inherited_quarantine: usize,
    quarantine_outlived_release: usize,
    denied_parent_refused: usize,
    labels_joined: usize,
}

impl Model {
    fn len(&self) -> NodeId {
        self.parents.len() as NodeId
    }

    fn resolve(&self, p: Pick) -> NodeId {
        match p {
            Pick::Existing(i) if self.len() > 0 => (i as NodeId % self.len()) + 1,
            Pick::Existing(_) | Pick::Missing => self.len() + 100,
            Pick::Sentinel => 0,
        }
    }

    fn exists(&self, id: NodeId) -> bool {
        id >= 1 && id <= self.len()
    }

    fn ancestors(&self, id: NodeId) -> BTreeSet<NodeId> {
        let mut out = BTreeSet::new();
        let mut stack: Vec<NodeId> = self.parents[(id - 1) as usize].clone();
        while let Some(p) = stack.pop() {
            if out.insert(p) {
                stack.extend(self.parents[(p - 1) as usize].iter().copied());
            }
        }
        out
    }

    fn is_quarantined(&self, id: NodeId) -> bool {
        self.quarantined.contains(&id) || !self.ancestors(id).is_disjoint(&self.quarantined)
    }

    /// The error inserting with these parents must produce, if any.
    fn insert_error(&self, parents: &[NodeId]) -> Option<FlowGraphError> {
        if parents.len() > MAX_PARENTS {
            return Some(FlowGraphError::TooManyParents {
                provided: parents.len(),
                max: MAX_PARENTS,
            });
        }
        parents.iter().find_map(|&p| {
            if p == 0 {
                Some(FlowGraphError::SentinelParent)
            } else if !self.exists(p) {
                Some(FlowGraphError::ParentNotFound(p))
            } else if self.denied.contains(&p) {
                Some(FlowGraphError::DeniedParent(p))
            } else {
                None
            }
        })
    }

    fn joined(&self, intrinsic: IFCLabel, parents: &[NodeId]) -> IFCLabel {
        parents
            .iter()
            .fold(intrinsic, |acc, p| acc.join(self.labels[(*p - 1) as usize]))
    }

    fn add(&mut self, parents: Vec<NodeId>, label: IFCLabel) -> NodeId {
        let inherit = parents.iter().any(|p| self.is_quarantined(*p));
        self.parents.push(parents);
        self.labels.push(label);
        let id = self.len();
        if inherit {
            self.quarantined.insert(id);
        }
        id
    }
}

fn run(cmds: &[Cmd]) -> Result<Seen, TestCaseError> {
    let mut g = FlowGraph::new();
    let mut m = Model::default();
    let mut seen = Seen::default();
    let mut released: BTreeSet<NodeId> = BTreeSet::new();

    for (step, c) in cmds.iter().enumerate() {
        match c {
            Cmd::Observe(k, picks) | Cmd::Act(k, picks) => {
                let parents: Vec<NodeId> = picks.iter().map(|p| m.resolve(*p)).collect();
                let expected_err = m.insert_error(&parents);
                if matches!(expected_err, Some(FlowGraphError::DeniedParent(_))) {
                    seen.denied_parent_refused += 1;
                }
                let (kind, got) = match c {
                    Cmd::Observe(..) => (
                        KINDS[*k],
                        g.insert_observation(KINDS[*k], &parents, NOW)
                            .map(|id| (id, None)),
                    ),
                    _ => (
                        NodeKind::OutboundAction,
                        g.insert_action(OPS[*k], &parents, NOW)
                            .map(|d| (d.node_id, Some(d.verdict))),
                    ),
                };
                // `causal_label` validates exactly as an insert does.
                let causal = g.causal_label(&parents, NOW);
                match (expected_err, got) {
                    (Some(want), Err(e)) => {
                        prop_assert_eq!(&e, &want, "step {}: {:?}", step, c);
                        prop_assert_eq!(causal, Err(want), "step {}: causal_label", step);
                    }
                    (None, Ok((id, verdict))) => {
                        prop_assert_eq!(id, m.len() + 1, "step {}: ids are dense", step);
                        let label = m.joined(intrinsic_label(kind, NOW), &parents);
                        let action_label =
                            m.joined(intrinsic_label(NodeKind::OutboundAction, NOW), &parents);
                        prop_assert_eq!(causal, Ok(action_label), "step {}: causal_label", step);
                        if !parents.is_empty() {
                            seen.labels_joined += 1;
                        }
                        if parents.iter().any(|p| m.is_quarantined(*p)) {
                            seen.inherited_quarantine += 1;
                        }
                        let new = m.add(parents.clone(), label);
                        if matches!(verdict, Some(FlowVerdict::Deny(_))) {
                            m.denied.insert(new);
                        }
                    }
                    (want, got) => {
                        return Err(TestCaseError::fail(format!(
                            "step {step}: {c:?} with parents {parents:?}: model {want:?}, graph {got:?}"
                        )));
                    }
                }
            }
            Cmd::Quarantine(p) => {
                let id = m.resolve(*p);
                // True only when this call quarantined it: a missing node, or one
                // already explicitly quarantined, is false.
                let newly = m.exists(id) && m.quarantined.insert(id);
                prop_assert_eq!(g.quarantine(id), newly, "step {}: quarantine({})", step, id);
            }
            Cmd::Release(p) => {
                let id = m.resolve(*p);
                let got = g.release_quarantine(id, "walker", "walk release", NOW + step as u64);
                if m.quarantined.remove(&id) {
                    let rec = got.map_err(|e| {
                        TestCaseError::fail(format!("step {step}: release({id}) refused: {e}"))
                    })?;
                    prop_assert_eq!(
                        (
                            rec.node_id,
                            rec.released_by.as_str(),
                            rec.reason.as_str(),
                            rec.released_at
                        ),
                        (id, "walker", "walk release", NOW + step as u64)
                    );
                    m.releases.push((id, NOW + step as u64));
                    released.insert(id);
                } else {
                    prop_assert_eq!(
                        got,
                        Err(QuarantineError::NotQuarantined(id)),
                        "step {}",
                        step
                    );
                }
            }
        }

        // The whole observable structure, after every step.
        prop_assert_eq!(g.len(), m.len() as usize, "step {}: len", step);
        let log: Vec<(NodeId, u64)> = g
            .quarantine_releases()
            .iter()
            .map(|r| (r.node_id, r.released_at))
            .collect();
        prop_assert_eq!(
            &log,
            &m.releases,
            "step {}: the release log, in order",
            step
        );
        prop_assert!(
            g.quarantine_releases()
                .iter()
                .all(|r| r.released_by == "walker" && r.reason == "walk release"),
            "step {}: every release records who and why",
            step
        );
        for id in 1..=m.len() {
            let node = g
                .get(id)
                .ok_or_else(|| TestCaseError::fail(format!("node {id} missing")))?;
            prop_assert_eq!(
                node.label,
                m.labels[(id - 1) as usize],
                "step {}: label of {}",
                step,
                id
            );
            let q = m.is_quarantined(id);
            prop_assert_eq!(
                g.is_quarantined(id),
                q,
                "step {}: is_quarantined({})",
                step,
                id
            );
            if q && released
                .iter()
                .any(|r| m.ancestors(id).contains(r) || *r == id)
            {
                seen.quarantine_outlived_release += 1;
            }
            let mut want: BTreeSet<NodeId> = m.ancestors(id);
            let ancestors: BTreeSet<NodeId> =
                g.ancestors(id).ancestors.iter().map(|n| n.id).collect();
            prop_assert_eq!(&ancestors, &want, "step {}: ancestors({})", step, id);
            want.insert(id);
            let qa: BTreeSet<NodeId> = g.quarantined_ancestors(id).into_iter().collect();
            let want_qa: BTreeSet<NodeId> = want.intersection(&m.quarantined).copied().collect();
            prop_assert_eq!(qa, want_qa, "step {}: quarantined_ancestors({})", step, id);
        }
    }
    Ok(seen)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn the_flow_graph_holds_to_its_model(cmds in proptest::collection::vec(cmd(), 1..40)) {
        run(&cmds)?;
    }
}

/// Non-vacuity: one fixed walk that must exercise the laws the random walk checks —
/// a label joined from parents, quarantine inherited and outliving its ancestor's
/// release, and a denied action refused as a parent.
#[test]
fn a_fixed_walk_exercises_every_law() {
    use Cmd::*;
    use Pick::*;
    let cmds = vec![
        Observe(1, vec![]),                         // 1: web content (adversarial)
        Act(1, vec![Existing(0)]),                  // 2: write steered by web -> denied
        Observe(0, vec![]),                         // 3: user prompt
        Observe(4, vec![Existing(0), Existing(2)]), // 4: plan from web + user
        Quarantine(Existing(2)),                    // quarantine 3 (the prompt)
        Observe(2, vec![Existing(2)]),              // 5: inherits quarantine from 3
        Release(Existing(2)),                       // release 3: 5 stays quarantined
        Observe(2, vec![Existing(1)]),              // refused: parent 2 is a denied action
        Quarantine(Missing),
        Release(Existing(0)), // 1 was never quarantined
    ];
    let seen = run(&cmds).expect("the fixed walk holds to the model");
    assert!(seen.labels_joined > 0, "{seen:?}");
    assert!(seen.inherited_quarantine > 0, "{seen:?}");
    assert!(seen.quarantine_outlived_release > 0, "{seen:?}");
    assert!(seen.denied_parent_refused > 0, "{seen:?}");
}
