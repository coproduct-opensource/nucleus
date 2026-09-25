//! The Pod carrier of the command walk — `docs/design/command-walk.md`.
//!
//! Random sequences of create, list, get, logs and cancel, issued by the
//! operator or by pods, are run against a real `NodeState` with real registered
//! pods (the `handler_tests` fixture: each pod is a `/bin/sleep` child behind the
//! local driver). Beside it runs a model of the lineage and each pod's state.
//! Every step is checked against the model:
//!
//! - **Lineage is recorded from the proved caller.** A pod that creates a pod is
//!   its parent, whatever the parent header claims. Only an unidentified caller
//!   (the operator) may name a parent by header.
//! - **Scoping, in every read and in cancel.** A pod reaches itself and its
//!   direct children, and nothing else. That includes a grandchild:
//!   `caller_may_manage` is deliberately non-transitive, and the walk generates
//!   three-deep lineage so the deliberate choice stays deliberate. The operator
//!   reaches everything.
//! - **Refused looks like absent.** A pod may not manage the target, or the
//!   target does not exist; either way the answer is `NotFound`. Answering
//!   differently would let a caller probe which pod ids exist.
//! - **A refused cancel changes nothing.** The target keeps running.
//! - **A3, cancel is absorbing, and reads survive it.** A cancelled pod stays
//!   listed and fetchable, and its logs stay readable. Cancelling it again is
//!   answered the same as the first time.
//!
//! # What this does not reach
//!
//! Pods are registered through the fixture, not `create_pod_internal`. The
//! parent a create would record goes through the real `resolve_parent_pod_id`,
//! but `PodAuthority` admission and the driver spawn are out of the walk. The
//! cascade-cancel in the reaper loop is not run.

use std::collections::BTreeSet;

use axum::Extension;
use axum::extract::{Path as AxumPath, State};
use proptest::prelude::*;
use uuid::Uuid;

use crate::PodState;

use super::handler_tests::{register, state};
use super::*;

/// Who issues a step. A pod caller is an index into the pods created so far,
/// resolved modulo their count when the step runs.
#[derive(Debug, Clone, Copy)]
enum Caller {
    Operator,
    Pod(usize),
}

/// What a step names as its target.
#[derive(Debug, Clone, Copy)]
enum Target {
    Existing(usize),
    /// An id no pod has — the case refusal must be indistinguishable from.
    Unknown,
}

#[derive(Debug, Clone, Copy)]
enum Op {
    /// `header` names a pod as the claimed parent, the way the parent header does.
    Create {
        caller: Caller,
        header: Option<usize>,
    },
    List {
        caller: Caller,
    },
    Get {
        caller: Caller,
        target: Target,
    },
    Logs {
        caller: Caller,
        target: Target,
    },
    Cancel {
        caller: Caller,
        target: Target,
    },
}

#[derive(Debug, Clone)]
struct ModelPod {
    id: Uuid,
    parent: Option<Uuid>,
    cancelled: bool,
}

/// The reference state. Creation order is index order.
#[derive(Debug, Default)]
struct Model {
    pods: Vec<ModelPod>,
}

impl Model {
    fn caller_id(&self, c: Caller) -> Option<Uuid> {
        match c {
            Caller::Operator => None,
            Caller::Pod(i) => self.pods.get(i % self.pods.len().max(1)).map(|p| p.id),
        }
    }

    fn target_id(&self, t: Target, unknown: Uuid) -> Uuid {
        match t {
            Target::Existing(i) if !self.pods.is_empty() => self.pods[i % self.pods.len()].id,
            Target::Existing(_) | Target::Unknown => unknown,
        }
    }

    fn pod(&self, id: Uuid) -> Option<&ModelPod> {
        self.pods.iter().find(|p| p.id == id)
    }

    /// The model's own statement of the management rule — written from the
    /// design, not read from `caller_may_manage`, so the walk checks the rule
    /// rather than restating it.
    fn may_manage(&self, caller: Option<Uuid>, target: Uuid) -> bool {
        match (caller, self.pod(target)) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(c), Some(t)) => t.id == c || t.parent == Some(c),
        }
    }

    fn visible_to(&self, caller: Option<Uuid>) -> BTreeSet<Uuid> {
        self.pods
            .iter()
            .filter(|p| self.may_manage(caller, p.id))
            .map(|p| p.id)
            .collect()
    }

    /// The lineage depth of the deepest pod: 1 for a root.
    fn depth(&self) -> usize {
        self.pods
            .iter()
            .map(|p| {
                let mut d = 1;
                let mut cur = p.parent;
                while let Some(parent) = cur.and_then(|id| self.pod(id)) {
                    d += 1;
                    cur = parent.parent;
                }
                d
            })
            .max()
            .unwrap_or(0)
    }
}

fn caller() -> impl Strategy<Value = Caller> {
    prop_oneof![
        1 => Just(Caller::Operator),
        3 => (0usize..8).prop_map(Caller::Pod),
    ]
}

fn target() -> impl Strategy<Value = Target> {
    prop_oneof![
        6 => (0usize..8).prop_map(Target::Existing),
        1 => Just(Target::Unknown),
    ]
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        // Creates are weighted up: lineage depth 3 is reached only by three
        // nested creates, which a uniform draw rarely strings together.
        4 => (caller(), proptest::option::of(0usize..8))
            .prop_map(|(caller, header)| Op::Create { caller, header }),
        2 => caller().prop_map(|caller| Op::List { caller }),
        2 => (caller(), target()).prop_map(|(caller, target)| Op::Get { caller, target }),
        1 => (caller(), target()).prop_map(|(caller, target)| Op::Logs { caller, target }),
        3 => (caller(), target()).prop_map(|(caller, target)| Op::Cancel { caller, target }),
    ]
}

/// Most pods one walk registers: each is a live `sleep` process.
const MAX_PODS: usize = 7;

/// Run one walk; `Err` names the first step where node and model disagree.
async fn walk(ops: &[Op]) -> Result<Stats, String> {
    let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let st = state(&dir);
    let mut model = Model::default();
    let mut stats = Stats::default();
    let unknown = Uuid::new_v4();

    // Every walk starts from one root, so a pod caller always resolves.
    let root = register(&st, None).await;
    model.pods.push(ModelPod {
        id: root,
        parent: None,
        cancelled: false,
    });

    let result = async {
        for (step, op) in ops.iter().enumerate() {
            let at = |what: String| format!("step {step} {op:?}: {what}");
            match *op {
                Op::Create { caller, header } => {
                    if model.pods.len() >= MAX_PODS {
                        continue;
                    }
                    let caller_id = model.caller_id(caller);
                    let header_text =
                        header.map(|h| model.pods[h % model.pods.len()].id.to_string());
                    let parent = resolve_parent_pod_id(caller_id, header_text.as_deref());
                    let want = match caller_id {
                        Some(c) => Some(c),
                        None => header_text.as_deref().and_then(|h| Uuid::parse_str(h).ok()),
                    };
                    if parent != want {
                        return Err(at(format!(
                            "recorded parent {parent:?}, model says {want:?}"
                        )));
                    }
                    if caller_id.is_some()
                        && header_text.is_some()
                        && header_text != caller_id.map(|c| c.to_string())
                    {
                        stats.spoofed_headers_ignored += 1;
                    }
                    let id = register(&st, parent).await;
                    model.pods.push(ModelPod {
                        id,
                        parent,
                        cancelled: false,
                    });
                    stats.depth = stats.depth.max(model.depth());
                }
                Op::List { caller } => {
                    let caller_id = model.caller_id(caller);
                    let infos = collect_pod_infos(&st, caller_id).await;
                    let got: BTreeSet<Uuid> = infos.iter().map(|i| i.id).collect();
                    let want = model.visible_to(caller_id);
                    if got != want {
                        return Err(at(format!("listed {got:?}, model says {want:?}")));
                    }
                    for info in &infos {
                        let m = model
                            .pod(info.id)
                            .ok_or_else(|| at("listed an unknown pod".into()))?;
                        if info.parent_pod_id != m.parent {
                            return Err(at(format!(
                                "{} reports parent {:?}, model {:?}",
                                info.id, info.parent_pod_id, m.parent
                            )));
                        }
                        let running = matches!(info.state, PodState::Running);
                        if running == m.cancelled {
                            return Err(at(format!(
                                "{} state {:?}, model cancelled={}",
                                info.id, info.state, m.cancelled
                            )));
                        }
                    }
                }
                Op::Get { caller, target } => {
                    let caller_id = model.caller_id(caller);
                    let id = model.target_id(target, unknown);
                    let got = get_pod_for_caller(&st, id, caller_id).await;
                    check_scoped(&model, caller_id, id, got.map(|p| p.id), &mut stats)
                        .map_err(at)?;
                }
                Op::Logs { caller, target } => {
                    let caller_id = model.caller_id(caller);
                    let id = model.target_id(target, unknown);
                    let got =
                        pod_logs(State(st.clone()), Extension(caller_id.into()), AxumPath(id))
                            .await;
                    check_scoped(&model, caller_id, id, got.map(|_| id), &mut stats).map_err(at)?;
                }
                Op::Cancel { caller, target } => {
                    let caller_id = model.caller_id(caller);
                    let id = model.target_id(target, unknown);
                    let already = model.pod(id).is_some_and(|p| p.cancelled);
                    let got =
                        cancel_pod(State(st.clone()), Extension(caller_id.into()), AxumPath(id))
                            .await;
                    let allowed = model.may_manage(caller_id, id);
                    check_scoped(&model, caller_id, id, got.map(|_| id), &mut stats).map_err(at)?;
                    if allowed {
                        if already {
                            stats.repeat_cancels += 1;
                        }
                        if let Some(p) = model.pods.iter_mut().find(|p| p.id == id) {
                            p.cancelled = true;
                        }
                    }
                    // A refused cancel changes nothing — checked on the node,
                    // not assumed from the reply.
                    if let Some(m) = model.pod(id) {
                        let handle = get_pod(&st, id)
                            .await
                            .map_err(|e| at(format!("pod vanished: {e}")))?;
                        let running = matches!(handle.status().await, PodState::Running);
                        if running == m.cancelled {
                            return Err(at(format!(
                                "after cancel, {id} running={running}, model cancelled={}",
                                m.cancelled
                            )));
                        }
                    }
                }
            }
        }
        Ok(())
    }
    .await;

    for (_, h) in st.pods.lock().await.iter() {
        let _ = h.cancel().await;
    }
    result.map(|()| stats)
}

/// A scoped read or cancel: allowed ⇔ the model says so, and every refusal is
/// `NotFound`, identical for "not yours" and "does not exist".
fn check_scoped(
    model: &Model,
    caller: Option<Uuid>,
    id: Uuid,
    got: Result<Uuid, ApiError>,
    stats: &mut Stats,
) -> Result<(), String> {
    let allowed = model.may_manage(caller, id);
    match (allowed, got) {
        (true, Ok(found)) if found == id => Ok(()),
        (false, Err(ApiError::NotFound)) => {
            if model.pod(id).is_some() {
                stats.refused_existing += 1;
                if let (Some(c), Some(t)) = (caller, model.pod(id))
                    && let Some(parent) = t.parent.and_then(|p| model.pod(p))
                    && parent.parent == Some(c)
                {
                    stats.grandparent_refusals += 1;
                }
            }
            Ok(())
        }
        (allowed, got) => Err(format!("allowed={allowed} but node answered {got:?}")),
    }
}

/// What a walk reached, so non-vacuity can be asserted rather than hoped for.
#[derive(Debug, Default, Clone, Copy)]
struct Stats {
    depth: usize,
    refused_existing: usize,
    grandparent_refusals: usize,
    repeat_cancels: usize,
    spoofed_headers_ignored: usize,
}

/// The commutation census over the pod API.
mod census;

mod cross;

proptest! {
    // Each case builds a NodeState and up to MAX_PODS live processes.
    #![proptest_config(ProptestConfig::with_cases(48))]

    #[test]
    fn the_pod_api_agrees_with_its_model(ops in proptest::collection::vec(op(), 1..40)) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        if let Err(disagreement) = runtime.block_on(walk(&ops)) {
            prop_assert!(false, "{}", disagreement);
        }
    }
}

/// Non-vacuity: a scripted walk reaches every case the laws are about — a
/// three-deep lineage, a grandparent refused, a refusal of an existing pod, a
/// repeated cancel, and a parent header a pod tried to spoof.
#[tokio::test]
async fn the_walk_reaches_every_case_it_asserts() {
    let script = [
        // root(0) -> a(1) -> b(2): pods create their own children.
        Op::Create {
            caller: Caller::Pod(0),
            header: None,
        },
        Op::Create {
            caller: Caller::Pod(1),
            header: None,
        },
        // A pod names someone else as parent by header; the proved caller wins.
        Op::Create {
            caller: Caller::Pod(2),
            header: Some(0),
        },
        // The root is b's grandparent: refused, and b keeps running.
        Op::Cancel {
            caller: Caller::Pod(0),
            target: Target::Existing(2),
        },
        Op::Get {
            caller: Caller::Pod(0),
            target: Target::Existing(2),
        },
        // Not-yours and does-not-exist answer alike.
        Op::Get {
            caller: Caller::Pod(1),
            target: Target::Unknown,
        },
        // Cancel, cancel again, and read what was cancelled.
        Op::Cancel {
            caller: Caller::Operator,
            target: Target::Existing(3),
        },
        Op::Cancel {
            caller: Caller::Operator,
            target: Target::Existing(3),
        },
        Op::List {
            caller: Caller::Pod(2),
        },
        Op::Logs {
            caller: Caller::Pod(2),
            target: Target::Existing(3),
        },
        Op::List {
            caller: Caller::Operator,
        },
    ];
    let stats = walk(&script)
        .await
        .expect("the scripted walk agrees with the model");
    assert!(stats.depth >= 3, "{stats:?}");
    assert!(stats.grandparent_refusals >= 2, "{stats:?}");
    assert!(stats.refused_existing >= 2, "{stats:?}");
    assert!(stats.repeat_cancels >= 1, "{stats:?}");
    assert!(stats.spoofed_headers_ignored >= 1, "{stats:?}");
}
