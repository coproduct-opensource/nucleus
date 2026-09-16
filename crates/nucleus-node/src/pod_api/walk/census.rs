//! Which pod-API commands commute — the commutation census for the Pod carrier.
//!
//! The guest surface's census (`workload_api_vsock/walk/census.rs`) found its
//! sequencing laws by measuring which squares of the command cube are filled.
//! This does the same over the pod API, where the laws are lineage and cancel:
//! a face `(a, b)` is FILLED when `a ; b` and `b ; a` look the same to the host
//! from every starting state, and HOLLOW otherwise.
//!
//! # The universe
//!
//! Every run starts from three real registered pods — root `R`, its child `C`,
//! and `C`'s child `G` — in every combination of cancelled and running (8
//! states). The alphabet names roles, not ids:
//!
//! - cancels by the operator (of `G`), by a parent (`R` of `C`, `C` of `G`), and by
//!   a GRANDPARENT (`R` of `G`) — which must be refused, since management is
//!   deliberately not transitive;
//! - gets of `G` by `R` (refused) and by `C`;
//! - listings as the operator, `R` and `C`;
//! - creates by the operator and by `R`.
//!
//! Created pods are recorded by their parent, not their id, which differs between
//! the two orders of a pair and is not something the host concludes.
//!
//! # The declaration is derived from the design's rules
//!
//! [`declared_hollow`] computes the laws from two rules the design states: who may
//! manage whom (itself and its direct children; the operator, everything), and
//! who sees what in a listing (the same). A face is hollow exactly when one letter
//! changes something the other observes. It is written from the rules, not read
//! from `caller_may_manage`, so the census checks the rules rather than restating
//! the code. The expected count is 10 of 55, with only the creates non-idempotent:
//! A3 (cancel is absorbing — idempotent, and invisible to a get) and the refused
//! grandparent cancel commuting with everything are consequences, not entries.
//!
//! # What this does not reach
//!
//! Pods are registered through the fixture, not `create_pod_internal`; the reaper's
//! cascade-cancel is not run; `logs` is not in the alphabet (its scoping is the
//! get's); squares only, no three-way cubes.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Role {
    Operator,
    R,
    C,
    G,
}

/// One axis of the cube.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Letter {
    Cancel(Role, Role),
    Get(Role, Role),
    List(Role),
    Create(Role),
}

const LETTERS: [Letter; 11] = [
    Letter::Cancel(Role::Operator, Role::G),
    Letter::Cancel(Role::R, Role::C),
    Letter::Cancel(Role::R, Role::G),
    Letter::Cancel(Role::C, Role::G),
    Letter::Get(Role::R, Role::G),
    Letter::Get(Role::C, Role::G),
    Letter::List(Role::Operator),
    Letter::List(Role::R),
    Letter::List(Role::C),
    Letter::Create(Role::Operator),
    Letter::Create(Role::R),
];

/// The three pods of a run, by role.
struct Universe {
    r: Uuid,
    c: Uuid,
    g: Uuid,
}

impl Universe {
    fn id(&self, role: Role) -> Option<Uuid> {
        match role {
            Role::Operator => None,
            Role::R => Some(self.r),
            Role::C => Some(self.c),
            Role::G => Some(self.g),
        }
    }

    /// A pod's label: its role, or `new(parent)` for one created during the run.
    fn label(&self, id: Uuid, parent: Option<Uuid>) -> String {
        let role_of = |x: Uuid| {
            [(self.r, "R"), (self.c, "C"), (self.g, "G")]
                .iter()
                .find(|(i, _)| *i == x)
                .map(|(_, n)| (*n).to_string())
        };
        role_of(id).unwrap_or_else(|| {
            format!(
                "new(parent={})",
                parent
                    .map(|p| role_of(p).unwrap_or_else(|| "new".into()))
                    .unwrap_or_else(|| "none".into())
            )
        })
    }
}

/// What the host told the caller, in role terms.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Seen {
    Cancelled,
    Found(String),
    NotFound,
    Listed(Vec<(String, bool)>),
    Created,
    Other(String),
}

/// The registry, in role terms: `(label, parent label, running)`, sorted.
type Record = Vec<(String, String, bool)>;

async fn snapshot(st: &NodeState, u: &Universe) -> Record {
    let mut out: Record = collect_pod_infos(st, None)
        .await
        .iter()
        .map(|i| {
            let parent = i
                .parent_pod_id
                .map(|p| u.label(p, None))
                .unwrap_or_else(|| "none".into());
            (
                u.label(i.id, i.parent_pod_id),
                parent,
                matches!(i.state, PodState::Running),
            )
        })
        .collect();
    out.sort();
    out
}

/// Run `letters` from the universe with `cancelled` roles already cancelled.
async fn run(cancelled: &[Role], letters: &[Letter]) -> (Vec<Seen>, Record) {
    let dir = tempfile::tempdir().expect("tempdir");
    let st = state(&dir);
    let r = register(&st, None).await;
    let c = register(&st, Some(r)).await;
    let g = register(&st, Some(c)).await;
    let u = Universe { r, c, g };
    for role in cancelled {
        if let Some(id) = u.id(*role) {
            let _ = cancel_pod(State(st.clone()), Extension(None), AxumPath(id)).await;
        }
    }

    let mut seen = Vec::with_capacity(letters.len());
    for letter in letters {
        let s = match *letter {
            Letter::Cancel(caller, target) => {
                let id = u.id(target).expect("a pod");
                match cancel_pod(State(st.clone()), Extension(u.id(caller)), AxumPath(id)).await {
                    Ok(_) => Seen::Cancelled,
                    Err(ApiError::NotFound) => Seen::NotFound,
                    Err(e) => Seen::Other(e.to_string()),
                }
            }
            Letter::Get(caller, target) => {
                let id = u.id(target).expect("a pod");
                match get_pod_for_caller(&st, id, u.id(caller)).await {
                    Ok(p) => Seen::Found(u.label(p.id, p.parent_pod_id)),
                    Err(ApiError::NotFound) => Seen::NotFound,
                    Err(e) => Seen::Other(e.to_string()),
                }
            }
            Letter::List(caller) => {
                let mut listed: Vec<(String, bool)> = collect_pod_infos(&st, u.id(caller))
                    .await
                    .iter()
                    .map(|i| {
                        (
                            u.label(i.id, i.parent_pod_id),
                            matches!(i.state, PodState::Running),
                        )
                    })
                    .collect();
                listed.sort();
                Seen::Listed(listed)
            }
            Letter::Create(caller) => {
                let parent = resolve_parent_pod_id(u.id(caller), None);
                let _ = register(&st, parent).await;
                Seen::Created
            }
        };
        seen.push(s);
    }
    let record = snapshot(&st, &u).await;
    for (_, h) in st.pods.lock().await.iter() {
        let _ = h.cancel().await;
    }
    (seen, record)
}

/// The design's two rules, at role level.
fn may_manage(caller: Role, target: Role) -> bool {
    match (caller, target) {
        (Role::Operator, _) => true,
        (c, t) if c == t => true,
        (Role::R, Role::C) | (Role::C, Role::G) => true,
        (Role::R | Role::C | Role::G, _) => false,
    }
}

/// Who a listing by `viewer` shows a pod whose own role is `pod` (or a new pod
/// whose parent is `parent`).
fn sees(viewer: Role, pod: Option<Role>, parent: Option<Role>) -> bool {
    match (viewer, pod) {
        (Role::Operator, _) => true,
        (v, Some(p)) => may_manage(v, p),
        (v, None) => parent == Some(v),
    }
}

/// The hollow faces the rules imply: one letter changes what the other observes.
fn declared_hollow() -> BTreeSet<(Letter, Letter)> {
    // What a letter can change: a pod's running state, or the set of pods.
    let changes = |l: Letter| -> Option<(Option<Role>, Option<Role>)> {
        match l {
            Letter::Cancel(caller, target) if may_manage(caller, target) => {
                Some((Some(target), None))
            }
            Letter::Create(caller) => Some((
                None,
                if caller == Role::Operator {
                    None
                } else {
                    Some(caller)
                },
            )),
            Letter::Cancel(..) | Letter::Get(..) | Letter::List(_) => None,
        }
    };
    // Only listings observe state (a get's reply does not depend on it; a cancel's
    // and a create's replies depend only on the caller and target).
    let observed_by = |observer: Letter, change: (Option<Role>, Option<Role>)| match observer {
        Letter::List(viewer) => sees(viewer, change.0, change.1),
        Letter::Cancel(..) | Letter::Get(..) | Letter::Create(_) => false,
    };
    let mut out = BTreeSet::new();
    for (i, &a) in LETTERS.iter().enumerate() {
        for &b in &LETTERS[i + 1..] {
            let hollow = changes(a).is_some_and(|c| observed_by(b, c))
                || changes(b).is_some_and(|c| observed_by(a, c));
            if hollow {
                out.insert((a, b));
            }
        }
    }
    out
}

/// A letter is not idempotent when doing it twice leaves a different registry:
/// only a create does. A3 is that a cancel is not in this set.
fn declared_not_idempotent() -> BTreeSet<Letter> {
    LETTERS
        .iter()
        .copied()
        .filter(|l| matches!(l, Letter::Create(_)))
        .collect()
}

#[tokio::test]
async fn the_pod_api_commutes_exactly_where_the_rules_say() {
    let roles = [Role::R, Role::C, Role::G];
    let starts: Vec<Vec<Role>> = (0..8u8)
        .map(|mask| {
            roles
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, r)| *r)
                .collect()
        })
        .collect();

    let mut hollow: BTreeMap<(Letter, Letter), String> = BTreeMap::new();
    let mut not_idempotent: BTreeMap<Letter, String> = BTreeMap::new();
    let mut checks = 0usize;
    for start in &starts {
        for (i, &a) in LETTERS.iter().enumerate() {
            let (once_seen, once) = run(start, &[a]).await;
            let (twice_seen, twice) = run(start, &[a, a]).await;
            if (once != twice || once_seen[0] != twice_seen[1]) && !not_idempotent.contains_key(&a)
            {
                not_idempotent.insert(
                    a,
                    format!("from cancelled {start:?}: once {once:?}, twice {twice:?}"),
                );
            }
            for &b in &LETTERS[i + 1..] {
                let (ab_seen, ab) = run(start, &[a, b]).await;
                let (ba_seen, ba) = run(start, &[b, a]).await;
                checks += 1;
                let why = if ab_seen[0] != ba_seen[1] {
                    Some(format!(
                        "{a:?} answered {:?} first, {:?} second",
                        ab_seen[0], ba_seen[1]
                    ))
                } else if ab_seen[1] != ba_seen[0] {
                    Some(format!(
                        "{b:?} answered {:?} first, {:?} second",
                        ba_seen[0], ab_seen[1]
                    ))
                } else if ab != ba {
                    Some(format!("registries differ: {ab:?} vs {ba:?}"))
                } else {
                    None
                };
                if let Some(why) = why {
                    hollow
                        .entry((a, b))
                        .or_insert_with(|| format!("from cancelled {start:?}: {why}"));
                }
            }
        }
    }

    let faces = LETTERS.len() * (LETTERS.len() - 1) / 2;
    eprintln!(
        "pod census: {} letters, {faces} faces, {checks} checks from {} states; hollow {}",
        LETTERS.len(),
        starts.len(),
        hollow.len()
    );
    for ((a, b), why) in &hollow {
        eprintln!("  hollow  {a:?} ; {b:?}  —  {why}");
    }
    for (a, why) in &not_idempotent {
        eprintln!("  not idempotent  {a:?}  —  {why}");
    }

    // Non-vacuity: the laws the census exists to find are among the measured ones.
    assert!(
        hollow.contains_key(&(Letter::Cancel(Role::R, Role::C), Letter::List(Role::R))),
        "a parent's cancel is not visible to its own listing: the census saw nothing"
    );
    assert!(
        !LETTERS.iter().any(
            |&b| hollow.contains_key(&(Letter::Cancel(Role::R, Role::G), b))
                || hollow.contains_key(&(b, Letter::Cancel(Role::R, Role::G)))
        ),
        "a grandparent's cancel changed something someone could see: management became transitive"
    );

    let measured: BTreeSet<(Letter, Letter)> = hollow.keys().copied().collect();
    let declared = declared_hollow();
    let undeclared: Vec<_> = measured.difference(&declared).collect();
    let stale: Vec<_> = declared.difference(&measured).collect();
    assert!(
        undeclared.is_empty() && stale.is_empty(),
        "hollow faces the rules do not imply: {undeclared:?}; implied faces that filled: {stale:?}"
    );
    let measured: BTreeSet<Letter> = not_idempotent.keys().copied().collect();
    assert_eq!(
        measured,
        declared_not_idempotent(),
        "idempotence differs from the rules"
    );
}
