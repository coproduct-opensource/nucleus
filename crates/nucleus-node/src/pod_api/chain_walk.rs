//! The delegation-chain walk: random chains of pods creating pods, run through
//! the node's real admission, against a model of the tree and its ledgers.
//!
//! [`walk`](super::walk) registers its pods through the fixture and says so:
//! "`PodAuthority` admission and the driver spawn are out of the walk. The
//! cascade-cancel in the reaper loop is not run." Those are where the node's
//! recent fixes were, and every one was a bug in a SEQUENCE rather than in a
//! call: a create dropped mid-boot that never handed its reservation back
//! (#3032), a lockdown attributed to the name its caller wrote (#3081), a CI
//! identity that reached every pod (#3088). This walk is for that layer.
//!
//! Each step goes through the handler a request reaches. Creates, cancels,
//! listings and lockdowns go through the gRPC `NodeService`, with the
//! interceptor's verified peer in the request extensions, or through the HTTP
//! handlers behind the same three calls `auth_middleware` makes. A create runs
//! all of `create_pod_internal`: admission, the local driver's spawn (a
//! stand-in tool proxy that never announces), the reservation's commit, its
//! release when the spawn fails, and its drop when the client goes away. The
//! reaper is run as steps of its own. Nothing about the authority is faked.
//!
//! Beside it runs a model written from the design, not read from the code: a
//! tree of pods with each one's lineage, budget, depth and phase, and a ledger
//! for every pod and every external chain. After every step:
//!
//! - **Admission.** A create is admitted iff the model says so: the root minter
//!   always; an external caller within its chain's budget and fan-out; a pod
//!   that still holds a certificate, within its budget, fan-out and depth.
//! - **Attenuation.** Every certificate verifies under the node's root key and
//!   names the pod it was issued to. A pod's effective authority is at most
//!   what it asked for and at most its parent's, and its chain extends its
//!   parent's chain, block for block, at every depth. The spec the driver
//!   launched carries the certificate's lattice, not the request.
//! - **Budget conservation.** Every ledger the authority holds equals the
//!   model's, coordinate by coordinate: its ceiling, what retired children
//!   consumed, what live children hold, how many there are. A create that
//!   never ran releases its reservation exactly once.
//! - **Upstreams.** A credentialed upstream is admitted iff the operator's
//!   registry holds it, field for field, and — for a pod caller — the calling
//!   pod was admitted it too: a child's upstreams are a subset of its
//!   parent's, checked against what the AUTHORITY holds for both, not against
//!   the model. A request beyond either ceiling is refused whole. The spec the
//!   driver launched carries exactly the admitted set.
//! - **A restart changes nothing.** The node can restart between any two
//!   steps: a fresh authority over the same state directory, restored from
//!   disk. Every ledger must come back exactly as the model kept it, including
//!   what retired children consumed, which no live child records.
//! - **Revocation reaches the subtree.** A pod that has stopped, or has a
//!   stopped pod above it, can create nothing from that moment, before any
//!   reaper pass. Once the reaper has run to a fixpoint, every pod below a
//!   stopped pod is stopped, no stopped pod holds a certificate, and none of
//!   them can create anything.
//! - **Scope.** A pod lists and cancels only itself and its direct children; an
//!   identity the policy grants node-wide reach reaches every pod; a refusal is
//!   `NotFound` and leaves the target running. Cancelling twice answers alike.
//! - **Attribution.** A lockdown is broadcast and audited under the verified
//!   peer, with the caller's own `operator_id` only as a quoted claim beside
//!   it, and only an operator or orchestrator may issue one.
//! - **A lockdown covers the subtree.** A pod's lockdown is audited in, and
//!   delivered to, the pod and every pod below it, and none of them can create
//!   anything while it holds; a watcher that connects later is told it. Lifting
//!   it reaches only the pods no other lockdown still covers.
//!
//! # Running it
//!
//! In the `test` gate it runs [`DEFAULT_CASES`] cases from a FIXED seed, so a
//! red is reproducible and a green is the same green every time. To soak:
//!
//! ```text
//! NUCLEUS_CHAIN_WALK_CASES=5000 NUCLEUS_CHAIN_WALK_SEED=random \
//!   cargo test -p nucleus-node --all-features chain_walk -- --nocapture
//! ```
//!
//! A failure prints the seed and the SHRUNK sequence as Rust. Paste it into
//! [`CORPUS`], which replays every entry on every run.
//!
//! # Where the model states the rule and the node does not follow it
//!
//! [`Rules`] names each place, with the issue that tracks it, and the walk
//! runs as shipped. The `#[ignore]`d tests at the bottom run the documented
//! rule instead, and fail on main until the fix lands. Then the flag goes, and
//! the rule is checked on every run.

use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;

use axum::Extension;
use axum::extract::{Path as AxumPath, State};
use portcullis::certificate::{LatticeCertificate, verify_certificate};
use portcullis::token::AttenuationToken;
use portcullis::{CapabilityLevel, PermissionLattice};
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestError, TestRng, TestRunner};
use ring::signature::{Ed25519KeyPair, KeyPair};
use uuid::Uuid;

use super::handler_tests::state;
use super::*;
use crate::pod_authority::{AuthorityArgs, LedgerView, Parent, PodAuthority};
use crate::proto;
use crate::proto::node_service_server::NodeService;
use crate::{NodeState, PodState};

/// Cases per run in the `test` gate. `NUCLEUS_CHAIN_WALK_CASES` overrides it.
const DEFAULT_CASES: u32 = 64;
/// The seed the gate runs. `NUCLEUS_CHAIN_WALK_SEED` overrides it: a number,
/// or `random`.
const DEFAULT_SEED: u64 = 0x6e75_636c_6575_7301;

const STRANGER: &str = "spiffe://nucleus.local/ns/elsewhere/sa/x";
/// The external callers: two orchestrators and two CI identities, each holding
/// a delegation chain rooted at an anchor the node trusts, with this budget.
const EXTERNAL: [(&str, u32); 4] = [
    ("spiffe://nucleus.local/ns/default/sa/orch-0", 6),
    ("spiffe://nucleus.local/ns/default/sa/orch-1", 3),
    ("spiffe://nucleus.local/ns/github/sa/ci-0", 5),
    ("spiffe://nucleus.local/ns/github/sa/ci-1", 2),
];
/// The fan-out cap the authority is built with.
const FAN_OUT: usize = 4;
/// `portcullis::certificate::DEFAULT_MAX_CHAIN_DEPTH`, written down rather
/// than imported: the model states the rule.
const MAX_DEPTH: usize = 10;
/// Most pods one case registers: each is a live process.
const MAX_PODS: usize = 24;
const MICRO: u64 = 1_000_000;
const REASON: &str = "chain walk";

// ── The steps ────────────────────────────────────────────────────────────────

/// A pod, named by position: resolved modulo the pods registered so far, so a
/// shrunk sequence stays meaningful.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PodRef {
    Nth(u8),
    /// The most recently registered pod: how a walk builds depth.
    Newest,
}

/// Who issues a step, as the node authenticates it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Who {
    /// The root minter, which the policy also names as the operator.
    Operator,
    /// `EXTERNAL[0..2]`: orchestrators, node-wide by policy.
    Orch(u8),
    /// `EXTERNAL[2..4]`: CI identities.
    Ci(u8),
    Pod(PodRef),
    /// An identity in the trust domain that the policy grants nothing.
    Stranger,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Via {
    Grpc,
    Http,
}

/// How a create's spawn ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Boot {
    Runs,
    /// The tool proxy cannot be executed: the spawn's `Err` arm.
    SpawnFails,
    /// The client goes away while the pod boots: the create's future is
    /// dropped after admission, before the spawn returns (#3032).
    ClientGone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Pod(PodRef),
    /// An id no pod has.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    All,
    Pod(Target),
    /// The empty label selector, which every pod matches.
    Label,
}

/// What a lockdown request writes in its own `operator_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Claim {
    Empty,
    SomeoneElse,
    /// The operator's identity, claimed by whoever sends it.
    TheOperator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    Create {
        who: Who,
        via: Via,
        /// A pod caller also sends its caller token.
        token: bool,
        budget: u8,
        /// Three capability levels, base 3.
        caps: u8,
        boot: Boot,
        /// The unauthenticated parent header.
        header: Option<PodRef>,
        /// The credentialed upstreams the spec asks for, one bit per
        /// [`upstream`]: two the registry holds, two it does not.
        ups: u8,
    },
    Cancel {
        who: Who,
        via: Via,
        token: bool,
        target: Target,
    },
    List {
        who: Who,
        via: Via,
        token: bool,
    },
    Lockdown {
        who: Who,
        scope: Scope,
        claim: Claim,
        restore: bool,
    },
    /// One pass of the reaper.
    Reap,
    /// The node restarts: a fresh authority, restored from its state directory.
    Restart,
}

/// One case: the root pod's budget, then the steps.
#[derive(Debug, Clone)]
struct Case {
    root_budget: u8,
    ops: Vec<Op>,
}

impl Case {
    /// This case as a [`CORPUS`] entry, in Rust.
    fn literal(&self) -> String {
        let pod = |r: PodRef| match r {
            PodRef::Nth(n) => format!("PodRef::Nth({n})"),
            PodRef::Newest => "PodRef::Newest".to_string(),
        };
        let who = |w: Who| match w {
            Who::Pod(r) => format!("Who::Pod({})", pod(r)),
            other => format!("Who::{other:?}"),
        };
        let target = |t: Target| match t {
            Target::Pod(r) => format!("Target::Pod({})", pod(r)),
            Target::Unknown => "Target::Unknown".to_string(),
        };
        let mut out = format!("(\"<name the bug>\", {}, &[\n", self.root_budget);
        for op in &self.ops {
            let line = match *op {
                Op::Create {
                    who: w,
                    via,
                    token,
                    budget,
                    caps,
                    boot,
                    header,
                    ups,
                } => format!(
                    "Op::Create {{ who: {}, via: Via::{via:?}, token: {token}, budget: {budget}, \
                     caps: {caps}, boot: Boot::{boot:?}, header: {}, ups: {ups:#06b} }}",
                    who(w),
                    header.map_or("None".to_string(), |h| format!("Some({})", pod(h)))
                ),
                Op::Cancel {
                    who: w,
                    via,
                    token,
                    target: t,
                } => format!(
                    "Op::Cancel {{ who: {}, via: Via::{via:?}, token: {token}, target: {} }}",
                    who(w),
                    target(t)
                ),
                Op::List { who: w, via, token } => format!(
                    "Op::List {{ who: {}, via: Via::{via:?}, token: {token} }}",
                    who(w)
                ),
                Op::Lockdown {
                    who: w,
                    scope,
                    claim,
                    restore,
                } => format!(
                    "Op::Lockdown {{ who: {}, scope: {}, claim: Claim::{claim:?}, restore: {restore} }}",
                    who(w),
                    match scope {
                        Scope::Pod(t) => format!("Scope::Pod({})", target(t)),
                        other => format!("Scope::{other:?}"),
                    }
                ),
                Op::Reap => "Op::Reap".to_string(),
                Op::Restart => "Op::Restart".to_string(),
            };
            out.push_str(&format!("    {line},\n"));
        }
        out.push_str("]),");
        out
    }
}

fn pod_ref() -> impl Strategy<Value = PodRef> {
    // The root and the newest pod are named often: one is how a parent meets
    // its fan-out cap, the other how a chain gets deep.
    prop_oneof![
        2 => Just(PodRef::Newest),
        2 => Just(PodRef::Nth(0)),
        2 => (0u8..4).prop_map(PodRef::Nth),
    ]
}

fn who() -> impl Strategy<Value = Who> {
    prop_oneof![
        1 => Just(Who::Operator),
        1 => (0u8..2).prop_map(Who::Orch),
        1 => (0u8..2).prop_map(Who::Ci),
        6 => pod_ref().prop_map(Who::Pod),
        1 => Just(Who::Stranger),
    ]
}

fn via() -> impl Strategy<Value = Via> {
    prop_oneof![Just(Via::Grpc), Just(Via::Http)]
}

fn target() -> impl Strategy<Value = Target> {
    prop_oneof![6 => pod_ref().prop_map(Target::Pod), 1 => Just(Target::Unknown)]
}

fn op() -> impl Strategy<Value = Op> {
    let create = (
        who(),
        via(),
        any::<bool>(),
        // Mostly small, so a parent's fan-out cap is reached before its budget.
        prop_oneof![3 => Just(0u8), 3 => Just(1u8), 2 => 2u8..=4],
        0u8..27,
        prop_oneof![6 => Just(Boot::Runs), 1 => Just(Boot::SpawnFails), 1 => Just(Boot::ClientGone)],
        proptest::option::weighted(0.2, pod_ref()),
        // Mostly none, so the budget and fan-out refusals stay reachable; then
        // the registry's own entries, which a pod caller holds only if its
        // parent does; then anything, the registry's absentees included.
        prop_oneof![5 => Just(0u8), 3 => 1u8..=REGISTERED, 1 => 0u8..16],
    )
        .prop_map(|(who, via, token, budget, caps, boot, header, ups)| Op::Create {
            who,
            via,
            token,
            budget,
            caps,
            boot,
            header,
            ups,
        });
    let cancel =
        (who(), via(), any::<bool>(), target()).prop_map(|(who, via, token, target)| Op::Cancel {
            who,
            via,
            token,
            target,
        });
    let list =
        (who(), via(), any::<bool>()).prop_map(|(who, via, token)| Op::List { who, via, token });
    let scope = prop_oneof![
        Just(Scope::All),
        target().prop_map(Scope::Pod),
        Just(Scope::Label)
    ];
    let claim = prop_oneof![
        Just(Claim::Empty),
        Just(Claim::SomeoneElse),
        Just(Claim::TheOperator)
    ];
    let lockdown = (who(), scope, claim, any::<bool>()).prop_map(|(who, scope, claim, restore)| {
        Op::Lockdown {
            who,
            scope,
            claim,
            restore,
        }
    });
    prop_oneof![
        8 => create,
        3 => cancel,
        1 => list,
        1 => lockdown,
        2 => Just(Op::Reap),
        1 => Just(Op::Restart),
    ]
}

fn case() -> impl Strategy<Value = Case> {
    (0u8..=12, proptest::collection::vec(op(), 1..40))
        .prop_map(|(root_budget, ops)| Case { root_budget, ops })
}

// ── Where the model and the node part ways on purpose ────────────────────────

/// A rule the model states, and the node does not yet follow. Each flag names
/// the issue; the walk runs [`Rules::AS_SHIPPED`], and the ignored tests at
/// the bottom run the documented rule.
#[derive(Debug, Clone, Copy)]
struct Rules {
    /// A create that never ran hands its reservation back: `Reservation`'s own
    /// doc says so. On main the release folds the whole allocation into the
    /// parent's consumption, as for a pod that ran, so the slot comes back and
    /// the budget does not (#3105).
    unrun_refunds: bool,
}

impl Rules {
    const AS_SHIPPED: Self = Self {
        unrun_refunds: false,
    };
}

// ── The model ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Running,
    /// Stopped; the reaper has not seen it yet, so it still holds authority.
    Exited,
    /// The reaper released its authority.
    Reaped,
}

/// Where a pod's budget and authority came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Root,
    Pod(usize),
    External(usize),
}

#[derive(Debug, Clone)]
struct MPod {
    id: Uuid,
    /// The lineage the registry records: management and cascade follow it.
    reg_parent: Option<usize>,
    source: Source,
    creator: Who,
    budget: u64,
    depth: usize,
    phase: Phase,
    ledger: LedgerView,
    /// Read from the node at creation, for checking the pod's children.
    effective: PermissionLattice,
    cert: LatticeCertificate,
    /// The upstreams it was admitted, as [`Op::Create`]'s bits.
    ups: u8,
}

#[derive(Debug)]
struct Model {
    pods: Vec<MPod>,
    external: Vec<LedgerView>,
    /// Pods under a pod-scoped lockdown, each covering its subtree.
    locked: BTreeSet<usize>,
    /// A node-wide lockdown is in force.
    locked_all: bool,
    rules: Rules,
}

fn fresh_ledger(max: u64) -> LedgerView {
    LedgerView {
        max,
        consumed: 0,
        allocated: 0,
        live: 0,
    }
}

impl Model {
    fn new(rules: Rules) -> Self {
        Self {
            pods: Vec::new(),
            external: EXTERNAL
                .iter()
                .map(|(_, b)| fresh_ledger(u64::from(*b) * MICRO))
                .collect(),
            locked: BTreeSet::new(),
            locked_all: false,
            rules,
        }
    }

    /// Pod `i`, then each pod above it in the registry.
    fn lineage(&self, i: usize) -> Vec<usize> {
        let mut out = vec![i];
        while let Some(up) = out.last().and_then(|&a| self.pods[a].reg_parent) {
            out.push(up);
        }
        out
    }

    /// Is pod `i` under a lockdown: node-wide, or of it or a pod above it?
    fn covered(&self, i: usize) -> bool {
        self.locked_all || self.lineage(i).iter().any(|a| self.locked.contains(a))
    }

    /// Has pod `i`, or a pod above it, stopped?
    fn stopped_above(&self, i: usize) -> bool {
        self.lineage(i)
            .iter()
            .any(|&a| self.pods[a].phase != Phase::Running)
    }

    fn resolve(&self, r: PodRef) -> usize {
        match r {
            PodRef::Nth(n) => usize::from(n) % self.pods.len(),
            PodRef::Newest => self.pods.len() - 1,
        }
    }

    fn ledger(&self, s: Source) -> Option<&LedgerView> {
        match s {
            Source::Root => None,
            Source::Pod(i) => Some(&self.pods[i].ledger),
            Source::External(k) => Some(&self.external[k]),
        }
    }

    fn ledger_mut(&mut self, s: Source) -> Option<&mut LedgerView> {
        match s {
            Source::Root => None,
            Source::Pod(i) => Some(&mut self.pods[i].ledger),
            Source::External(k) => Some(&mut self.external[k]),
        }
    }

    /// Would admission issue `who` a child of `budget` micro-USD, and from
    /// which source, at what depth — upstreams aside?
    fn admits(&self, who: Who, budget: u64) -> Option<(Source, usize)> {
        let (source, depth) = match who {
            Who::Stranger => return None,
            Who::Operator => return Some((Source::Root, 1)),
            Who::Orch(k) => (Source::External(usize::from(k)), 1),
            Who::Ci(k) => (Source::External(2 + usize::from(k)), 1),
            Who::Pod(r) => {
                let i = self.resolve(r);
                let p = &self.pods[i];
                // A pod whose authority the reaper released holds no certificate;
                // a pod under lockdown, or stopped, or below one that stopped,
                // may not use the one it holds.
                if self.covered(i) || self.stopped_above(i) || p.depth + 1 > MAX_DEPTH {
                    return None;
                }
                (Source::Pod(i), p.depth + 1)
            }
        };
        let l = self.ledger(source)?;
        let available = l.max - l.consumed - l.allocated;
        (l.live < FAN_OUT && budget <= available).then_some((source, depth))
    }

    /// The upstreams a child of `source` may be admitted: the registry's, and
    /// for a pod caller only those its own pod was admitted. An external
    /// caller's ceiling is the registry until caller bindings carry their own.
    fn upstream_ceiling(&self, source: Source) -> u8 {
        match source {
            Source::Root | Source::External(_) => REGISTERED,
            Source::Pod(i) => self.pods[i].ups & REGISTERED,
        }
    }

    fn allocate(&mut self, source: Source, budget: u64) {
        if let Some(l) = self.ledger_mut(source) {
            l.allocated += budget;
            l.live += 1;
        }
    }

    /// A child's allocation retired: folded into its source's consumption,
    /// whole (no child reports what it spent), unless `refund`.
    fn retire(&mut self, source: Source, budget: u64, refund: bool) {
        // A source the reaper already released is gone, ledger and all.
        if let Source::Pod(i) = source
            && self.pods[i].phase == Phase::Reaped
        {
            return;
        }
        if let Some(l) = self.ledger_mut(source) {
            l.allocated -= budget;
            l.live -= 1;
            if !refund {
                l.consumed += budget;
            }
        }
    }

    /// May `who` manage pod `j`?
    fn reaches(&self, who: Who, j: usize) -> bool {
        match who {
            Who::Operator | Who::Orch(_) => true,
            // A CI identity reaches only the pods it created (#3088).
            Who::Ci(_) => self.pods[j].creator == who,
            Who::Pod(r) => {
                let i = self.resolve(r);
                j == i || self.pods[j].reg_parent == Some(i)
            }
            Who::Stranger => false,
        }
    }

    fn may_lock_down(who: Who) -> bool {
        matches!(who, Who::Operator | Who::Orch(_))
    }

    /// One reaper pass, as `reap_once` is specified: release every stopped pod
    /// not yet released, then stop every running child of a stopped pod.
    fn reap(&mut self) -> usize {
        let stopped: Vec<usize> = (0..self.pods.len())
            .filter(|&i| self.pods[i].phase != Phase::Running)
            .collect();
        for &i in &stopped {
            if self.pods[i].phase == Phase::Exited {
                let (source, budget) = (self.pods[i].source, self.pods[i].budget);
                self.retire(source, budget, false);
                self.pods[i].phase = Phase::Reaped;
            }
        }
        let mut cascaded = 0;
        for j in 0..self.pods.len() {
            if self.pods[j].phase == Phase::Running
                && self.pods[j]
                    .reg_parent
                    .is_some_and(|p| stopped.contains(&p))
            {
                self.pods[j].phase = Phase::Exited;
                cascaded += 1;
            }
        }
        cascaded
    }
}

// ── The node under test ──────────────────────────────────────────────────────

struct Node {
    st: NodeState,
    /// The same node with a tool proxy that cannot be executed.
    failing: NodeState,
    /// Per `EXTERNAL` entry: its delegation header and its chain's fingerprint.
    chains: Vec<(String, [u8; 32])>,
    ext_lattices: Vec<PermissionLattice>,
    operator: String,
    /// What the authority was built with, to build it again on a restart.
    args: AuthorityArgs,
    _bin: tempfile::TempDir,
}

fn lattice(budget_micro: u64) -> PermissionLattice {
    let mut l = PermissionLattice::permissive();
    l.budget.max_cost_usd =
        rust_decimal::Decimal::new(i64::try_from(budget_micro).expect("small"), 6);
    l
}

fn requested(budget: u8, caps: u8) -> PermissionLattice {
    let level = |d: u8| match d % 3 {
        0 => CapabilityLevel::Never,
        1 => CapabilityLevel::LowRisk,
        _ => CapabilityLevel::Always,
    };
    let mut l = lattice(u64::from(budget) * MICRO);
    l.capabilities.git_push = level(caps);
    l.capabilities.run_bash = level(caps / 3);
    l.capabilities.web_fetch = level(caps / 9);
    l
}

/// The operator registry the walk's node starts with: [`upstream`]'s first two.
const REGISTRY: &str = r#"
[[upstream]]
name = "model-api"
base_url = "https://model-api.invalid/v1"
header = "authorization"
value_prefix = "Bearer "
credential.env.var = "EXAMPLE_MODEL_API_TOKEN"

[[upstream]]
name = "search-api"
base_url = "https://search-api.invalid"
header = "x-api-key"
credential.env.var = "EXAMPLE_SEARCH_API_TOKEN"
"#;

/// The bits of [`Op::Create`]'s `ups` that name registry entries.
const REGISTERED: u8 = 0b0011;

/// One requestable upstream per bit. The first two are the registry's entries
/// exactly. The third is the first with its base URL moved, so it differs in
/// one field; the fourth is an entry the registry lacks, naming a node
/// variable nobody registered.
fn upstream(bit: u8) -> nucleus_spec::CredentialedEgressSpec {
    let entry = |name: &str, upstream: &str, var: &str, header: &str, prefix: &str| {
        nucleus_spec::CredentialedEgressSpec {
            name: name.into(),
            upstream: upstream.into(),
            credential_env: var.into(),
            header: header.into(),
            value_prefix: prefix.into(),
        }
    };
    match bit {
        0 => entry(
            "model-api",
            "https://model-api.invalid/v1",
            "EXAMPLE_MODEL_API_TOKEN",
            "authorization",
            "Bearer ",
        ),
        1 => entry(
            "search-api",
            "https://search-api.invalid",
            "EXAMPLE_SEARCH_API_TOKEN",
            "x-api-key",
            "",
        ),
        2 => entry(
            "model-api",
            "https://elsewhere.invalid/v1",
            "EXAMPLE_MODEL_API_TOKEN",
            "authorization",
            "Bearer ",
        ),
        _ => entry(
            "unregistered",
            "https://elsewhere.invalid",
            "NUCLEUS_NODE_PROXY_AUTH_SECRET",
            "authorization",
            "",
        ),
    }
}

/// The upstreams `ups` names, in bit order.
fn upstreams(ups: u8) -> Vec<nucleus_spec::CredentialedEgressSpec> {
    (0..4)
        .filter(|b| ups & (1 << b) != 0)
        .map(upstream)
        .collect()
}

fn spec_yaml(work: &std::path::Path, policy: PermissionLattice, ups: u8) -> String {
    let mut spec: nucleus_spec::PodSpec =
        serde_json::from_str(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{}}"#)
            .expect("minimal spec");
    spec.spec.work_dir = work.to_path_buf();
    spec.spec.timeout_seconds = 600;
    spec.spec.credentialed_egress = upstreams(ups);
    spec.spec.policy = nucleus_spec::PolicySpec::Inline {
        lattice: Box::new(policy),
    };
    serde_yaml::to_string(&spec).expect("spec serializes")
}

fn key() -> Ed25519KeyPair {
    let doc = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).expect("pkcs8");
    Ed25519KeyPair::from_pkcs8(doc.as_ref()).expect("key")
}

fn node(dir: &tempfile::TempDir) -> Node {
    let mut st = state(dir);
    let rng = ring::rand::SystemRandom::new();
    let ext_root = key();
    let registry = dir.path().join("upstreams.toml");
    std::fs::write(&registry, REGISTRY).expect("registry");
    let args = AuthorityArgs {
        root_minter_spiffe_id: None,
        cert_trust_anchors: vec![hex::encode(ext_root.public_key().as_ref())],
        max_children_per_pod: FAN_OUT,
        upstreams: Some(registry),
        federation_issuer: None,
    };
    let authority =
        PodAuthority::new(&args, "nucleus.local", &st.state_dir).expect("authority builds");
    let operator = authority.root_minter().to_string();
    st.authority = Arc::new(authority);
    st.authz_policy = st.authz_policy.clone().with_operator_identity(&operator);

    let expiry = chrono::Utc::now() + chrono::Duration::hours(1);
    let mut chains = Vec::new();
    let mut ext_lattices = Vec::new();
    for (spiffe, budget) in EXTERNAL {
        let (root, holder) = LatticeCertificate::mint(
            lattice(100 * MICRO),
            "spiffe://elsewhere.example/human/alice".into(),
            expiry,
            &ext_root,
            &rng,
        );
        let leaf_lattice = lattice(u64::from(budget) * MICRO);
        let (leaf, _) = root
            .delegate(&leaf_lattice, spiffe.into(), expiry, &holder, &rng)
            .expect("the external chain delegates");
        let token = AttenuationToken::seal(leaf, ext_root.public_key().as_ref().to_vec());
        chains.push((token.to_base64().expect("token"), token.fingerprint()));
        ext_lattices.push(leaf_lattice);
    }

    // The stand-in tool proxy: runs, never announces. Beside the test binary,
    // because a temp dir may be mounted noexec (see the handler_tests fixture).
    let exe = std::env::current_exe().expect("the test binary's path");
    let bin = tempfile::Builder::new()
        .prefix("chain-walk")
        .tempdir_in(exe.parent().expect("the test binary's directory"))
        .expect("a temp dir beside the test binary");
    let proxy = bin.path().join("never-announces.sh");
    std::fs::write(&proxy, "#!/bin/sh\nexec sleep 120\n").expect("script");
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&proxy, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    }
    st.tool_proxy_path = proxy;
    let mut failing = st.clone();
    failing.tool_proxy_path = bin.path().join("absent");
    std::fs::create_dir_all(st.state_dir.join("w")).expect("work dir");
    Node {
        st,
        failing,
        chains,
        ext_lattices,
        operator,
        args,
        _bin: bin,
    }
}

impl Node {
    fn peer(&self, model: &Model, who: Who) -> String {
        match who {
            Who::Operator => self.operator.clone(),
            Who::Orch(k) => EXTERNAL[usize::from(k)].0.to_string(),
            Who::Ci(k) => EXTERNAL[2 + usize::from(k)].0.to_string(),
            Who::Pod(r) => self
                .st
                .authority
                .pod_spiffe_id(model.pods[model.resolve(r)].id),
            Who::Stranger => STRANGER.to_string(),
        }
    }

    fn chain(&self, who: Who) -> Option<&str> {
        match who {
            Who::Orch(k) => Some(&self.chains[usize::from(k)].0),
            Who::Ci(k) => Some(&self.chains[2 + usize::from(k)].0),
            _ => None,
        }
    }

    /// The caller token a pod caller sends, when it sends one.
    fn token(&self, model: &Model, who: Who, token: bool) -> Option<(Uuid, String)> {
        let Who::Pod(r) = who else { return None };
        let id = model.pods[model.resolve(r)].id;
        token.then(|| {
            (
                id,
                crate::pod_caller_identity::derive_token(self.st.caller_secret.as_ref(), id),
            )
        })
    }

    fn grpc<T>(&self, model: &Model, who: Who, token: bool, msg: T) -> tonic::Request<T> {
        let mut r = tonic::Request::new(msg);
        r.extensions_mut()
            .insert(crate::auth::AuthContext::from_spiffe(self.peer(model, who)));
        let md = r.metadata_mut();
        if let Some((id, t)) = self.token(model, who, token) {
            md.insert(
                nucleus_client::HEADER_POD_ID,
                id.to_string().parse().expect("ascii"),
            );
            md.insert(nucleus_client::HEADER_POD_TOKEN, t.parse().expect("ascii"));
        }
        if let Some(chain) = self.chain(who) {
            md.insert(
                crate::pod_authority::HEADER_DELEGATION_CERT,
                chain.parse().expect("ascii"),
            );
        }
        r
    }

    /// What `auth_middleware` does before a handler runs: the route's
    /// authorization for the verified peer, and the headers the caller sends.
    /// The caller's scope is resolved at each call site, by
    /// `auth::resolve_http_caller`, so its type is the resolver's own.
    fn http(
        &self,
        model: &Model,
        who: Who,
        token: bool,
        path: &str,
        method: axum::http::Method,
    ) -> Result<(crate::auth::AuthContext, axum::http::HeaderMap), String> {
        use nucleus_identity::mtls::{ClientCertInfo, MtlsConnectInfo};
        let mut extensions = axum::http::Extensions::new();
        extensions.insert(axum::extract::ConnectInfo(MtlsConnectInfo {
            peer_addr: "127.0.0.1:0".parse().expect("addr"),
            client_cert: Some(ClientCertInfo {
                cert_der: vec![],
                spiffe_id: Some(self.peer(model, who)),
            }),
        }));
        let ctx = crate::auth::spiffe_context_for_request(
            &self.st.authz_policy,
            &method,
            path,
            &extensions,
        )
        .map_err(|e| e.to_string())?;
        let mut headers = axum::http::HeaderMap::new();
        if let Some((id, t)) = self.token(model, who, token) {
            headers.insert(
                nucleus_client::HEADER_POD_ID,
                id.to_string().parse().expect("ascii"),
            );
            headers.insert(nucleus_client::HEADER_POD_TOKEN, t.parse().expect("ascii"));
        }
        if let Some(chain) = self.chain(who) {
            headers.insert(
                crate::pod_authority::HEADER_DELEGATION_CERT,
                chain.parse().expect("ascii"),
            );
        }
        Ok((ctx, headers))
    }
}

// ── One case ─────────────────────────────────────────────────────────────────

/// What a case reached, so the walk can show it was not vacuous.
#[derive(Debug, Default, Clone, Copy)]
struct Stats {
    depth: usize,
    admitted: usize,
    external_admitted: usize,
    refused_budget: usize,
    refused_fan_out: usize,
    refused_depth: usize,
    refused_released: usize,
    /// Refused only for an upstream the registry lacks.
    refused_unregistered: usize,
    /// Refused only for a registered upstream the calling pod lacks.
    refused_beyond_parent: usize,
    /// Pods admitted an upstream by a pod caller.
    admitted_upstreams_from_a_pod: usize,
    spawn_failed: usize,
    client_gone: usize,
    cascaded: usize,
    scope_refused: usize,
    repeat_cancels: usize,
    attributed_claims: usize,
    lockdowns_refused: usize,
    /// Creates refused because a lockdown covers the caller.
    refused_locked: usize,
    /// Creates refused because the caller or a pod above it stopped, before
    /// the reaper released anything.
    refused_stopped: usize,
    /// Pods a lockdown reached because a pod above them was its target.
    locked_below: usize,
    /// Restarts with a retired child's consumption in some ledger.
    restarts_with_consumption: usize,
}

impl Stats {
    fn add(&mut self, o: &Self) {
        self.depth = self.depth.max(o.depth);
        self.admitted += o.admitted;
        self.external_admitted += o.external_admitted;
        self.refused_budget += o.refused_budget;
        self.refused_fan_out += o.refused_fan_out;
        self.refused_depth += o.refused_depth;
        self.refused_released += o.refused_released;
        self.refused_unregistered += o.refused_unregistered;
        self.refused_beyond_parent += o.refused_beyond_parent;
        self.admitted_upstreams_from_a_pod += o.admitted_upstreams_from_a_pod;
        self.spawn_failed += o.spawn_failed;
        self.client_gone += o.client_gone;
        self.cascaded += o.cascaded;
        self.scope_refused += o.scope_refused;
        self.repeat_cancels += o.repeat_cancels;
        self.attributed_claims += o.attributed_claims;
        self.lockdowns_refused += o.lockdowns_refused;
        self.refused_locked += o.refused_locked;
        self.refused_stopped += o.refused_stopped;
        self.locked_below += o.locked_below;
        self.restarts_with_consumption += o.restarts_with_consumption;
    }
}

/// How a create ended, as the caller sees it. The strings are the node's own
/// words, carried into a disagreement's message.
#[derive(Debug)]
enum Created {
    Pod(Uuid),
    Refused(String),
    SpawnFailed(String),
    Dropped,
}

impl std::fmt::Display for Created {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pod(id) => write!(f, "created {id}"),
            Self::Refused(why) => write!(f, "refused ({why})"),
            Self::SpawnFailed(why) => write!(f, "spawn failed ({why})"),
            Self::Dropped => write!(f, "dropped mid-boot"),
        }
    }
}

/// What admission issued, in the model's terms: a create's half of
/// [`Walk::register`]'s comparison.
struct Issued<'a> {
    who: Who,
    source: Source,
    depth: usize,
    micro: u64,
    header: Option<PodRef>,
    asked: &'a PermissionLattice,
    ups: u8,
}

struct Walk {
    node: Node,
    model: Model,
    stats: Stats,
    reaped: HashSet<Uuid>,
    heard: tokio::sync::broadcast::Receiver<proto::LockdownCommand>,
    unknown: Uuid,
}

/// Run one case; `Err` names the first step where node and model disagree.
async fn run_case(case: &Case, rules: Rules) -> Result<Stats, String> {
    let dir = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let node = node(&dir);
    let heard = node.st.lockdown_tx.subscribe();
    let mut w = Walk {
        node,
        model: Model::new(rules),
        stats: Stats::default(),
        reaped: HashSet::new(),
        heard,
        unknown: Uuid::new_v4(),
    };
    let result = w.drive(case).await;
    let pods: Vec<_> = w.node.st.pods.lock().await.values().cloned().collect();
    for p in pods {
        let _ = p.cancel().await;
    }
    result.map(|()| w.stats)
}

impl Walk {
    async fn drive(&mut self, case: &Case) -> Result<(), String> {
        // Every case starts from one root, so a pod caller always resolves.
        let root = Op::Create {
            who: Who::Operator,
            via: Via::Grpc,
            token: false,
            budget: case.root_budget,
            caps: 26,
            boot: Boot::Runs,
            header: None,
            ups: REGISTERED,
        };
        self.step(&root)
            .await
            .map_err(|e| format!("root create: {e}"))?;
        for (n, op) in case.ops.iter().enumerate() {
            self.step(op)
                .await
                .map_err(|e| format!("step {n} {op:?}: {e}"))?;
            self.check()
                .await
                .map_err(|e| format!("after step {n} {op:?}: {e}"))?;
        }
        self.quiesce()
            .await
            .map_err(|e| format!("at quiescence: {e}"))
    }

    async fn step(&mut self, op: &Op) -> Result<(), String> {
        match *op {
            Op::Create { .. } => {
                if self.model.pods.len() >= MAX_PODS {
                    return Ok(());
                }
                self.create(op).await
            }
            Op::Cancel {
                who,
                via,
                token,
                target,
            } => self.cancel(who, via, token, target).await,
            Op::List { who, via, token } => self.list(who, via, token).await,
            Op::Lockdown {
                who,
                scope,
                claim,
                restore,
            } => self.lockdown(who, scope, claim, restore).await,
            Op::Reap => {
                crate::reap_once(&self.node.st, &mut self.reaped).await;
                self.stats.cascaded += self.model.reap();
                Ok(())
            }
            Op::Restart => self.restart().await,
        }
    }

    /// A fresh authority over the same state directory, restored from disk,
    /// in place of the old one. The model does not change: nothing a restart
    /// does may show in any ledger.
    async fn restart(&mut self) -> Result<(), String> {
        let fresh = PodAuthority::new(&self.node.args, "nucleus.local", &self.node.st.state_dir)
            .map_err(|e| format!("the authority does not rebuild: {e}"))?;
        fresh.restore_from_disk().await;
        let fresh = Arc::new(fresh);
        self.node.st.authority = Arc::clone(&fresh);
        self.node.failing.authority = fresh;
        let consumed = self
            .model
            .pods
            .iter()
            .filter(|p| p.phase != Phase::Reaped)
            .map(|p| p.ledger)
            .chain(self.model.external.iter().copied())
            .any(|l| l.consumed > 0);
        if consumed {
            self.stats.restarts_with_consumption += 1;
        }
        Ok(())
    }

    async fn create(&mut self, op: &Op) -> Result<(), String> {
        let Op::Create {
            who,
            via,
            token,
            budget,
            caps,
            boot,
            header,
            ups,
        } = *op
        else {
            return Err("not a create".into());
        };
        let micro = u64::from(budget) * MICRO;
        let authorised = self.model.admits(who, micro);
        let ceiling = authorised.map(|(source, _)| self.model.upstream_ceiling(source));
        let want = authorised.filter(|_| ceiling.is_some_and(|c| ups & !c == 0));
        let header_id = header.map(|h| self.model.pods[self.model.resolve(h)].id);
        let asked = requested(budget, caps);
        let yaml = spec_yaml(&self.node.st.state_dir.join("w"), asked.clone(), ups);
        let st = match boot {
            Boot::SpawnFails => self.node.failing.clone(),
            _ => self.node.st.clone(),
        };
        let held_before = self.node.st.authority.held().await.pods.len();

        let fut = self.issue_create(&st, who, via, token, header_id, yaml);
        let got = if boot == Boot::ClientGone {
            // Dropped once admission has run and the spawn is waiting for its
            // proxy (3 s, on a paused clock): the client went away mid-boot.
            match tokio::time::timeout(std::time::Duration::from_secs(1), fut).await {
                Ok(done) => done,
                Err(_) => Created::Dropped,
            }
        } else {
            fut.await
        };

        let Some((source, depth)) = want else {
            let Created::Refused(_) = got else {
                return Err(format!("the model refuses this create; the node: {got}"));
            };
            match ceiling {
                Some(_) if ups & !REGISTERED != 0 => self.stats.refused_unregistered += 1,
                Some(_) => self.stats.refused_beyond_parent += 1,
                None => self.count_refusal(who, micro),
            }
            return Ok(());
        };
        match (boot, got) {
            (Boot::Runs, Created::Pod(id)) => {
                let issued = Issued {
                    who,
                    source,
                    depth,
                    micro,
                    header,
                    asked: &asked,
                    ups,
                };
                self.register(id, issued).await
            }
            (Boot::SpawnFails, Created::SpawnFailed(_)) => {
                self.stats.spawn_failed += 1;
                self.model.allocate(source, micro);
                self.model
                    .retire(source, micro, self.model.rules.unrun_refunds);
                Ok(())
            }
            (Boot::ClientGone, Created::Dropped) => {
                self.stats.client_gone += 1;
                self.model.allocate(source, micro);
                self.model
                    .retire(source, micro, self.model.rules.unrun_refunds);
                // The release runs on a task of its own: give it the chance a
                // live node would, then hold the node to the model.
                self.settle(held_before).await;
                Ok(())
            }
            (_, got) => Err(format!(
                "the model admits this create from {source:?} at depth {depth}; the node: {got}"
            )),
        }
    }

    /// Wait (bounded, on the paused clock) for the authority to hold `n` pods.
    async fn settle(&self, n: usize) {
        for _ in 0..500 {
            if self.node.st.authority.held().await.pods.len() <= n {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    }

    fn count_refusal(&mut self, who: Who, micro: u64) {
        let ledger = match who {
            Who::Pod(r) => {
                let i = self.model.resolve(r);
                let p = &self.model.pods[i];
                if p.phase == Phase::Reaped {
                    self.stats.refused_released += 1;
                    return;
                }
                if self.model.covered(i) {
                    self.stats.refused_locked += 1;
                    return;
                }
                if self.model.stopped_above(i) {
                    self.stats.refused_stopped += 1;
                    return;
                }
                if p.depth + 1 > MAX_DEPTH {
                    self.stats.refused_depth += 1;
                    return;
                }
                p.ledger
            }
            Who::Orch(k) => self.model.external[usize::from(k)],
            Who::Ci(k) => self.model.external[2 + usize::from(k)],
            Who::Operator | Who::Stranger => return,
        };
        if ledger.live >= FAN_OUT {
            self.stats.refused_fan_out += 1;
        } else if micro > ledger.max - ledger.consumed - ledger.allocated {
            self.stats.refused_budget += 1;
        }
    }

    async fn issue_create(
        &self,
        st: &NodeState,
        who: Who,
        via: Via,
        token: bool,
        header: Option<Uuid>,
        yaml: String,
    ) -> Created {
        let model = &self.model;
        match via {
            Via::Grpc => {
                let mut r = self
                    .node
                    .grpc(model, who, token, proto::CreatePodRequest { yaml });
                if let Some(h) = header {
                    r.metadata_mut().insert(
                        "x-nucleus-parent-pod-id",
                        h.to_string().parse().expect("ascii"),
                    );
                }
                let svc = crate::GrpcService { state: st.clone() };
                match svc.create_pod(r).await {
                    Ok(resp) => match Uuid::parse_str(&resp.into_inner().id) {
                        Ok(id) => Created::Pod(id),
                        Err(e) => Created::SpawnFailed(format!("unparseable id: {e}")),
                    },
                    Err(s) if s.code() == tonic::Code::PermissionDenied => {
                        Created::Refused(s.message().to_string())
                    }
                    Err(s) => Created::SpawnFailed(format!("{:?}: {}", s.code(), s.message())),
                }
            }
            Via::Http => {
                let (ctx, mut headers) =
                    match self
                        .node
                        .http(model, who, token, "/v1/pods", axum::http::Method::POST)
                    {
                        Ok(x) => x,
                        Err(e) => return Created::Refused(e),
                    };
                let caller = match crate::auth::resolve_http_caller(st, &ctx, &headers) {
                    Ok(c) => c,
                    Err(e) => return Created::Refused(e.to_string()),
                };
                if let Some(h) = header {
                    headers.insert(
                        "x-nucleus-parent-pod-id",
                        h.to_string().parse().expect("ascii"),
                    );
                }
                let body = axum::body::Bytes::from(yaml);
                match crate::create_pod(
                    State(st.clone()),
                    Extension(caller),
                    Extension(ctx),
                    headers,
                    body,
                )
                .await
                {
                    Ok(resp) => Created::Pod(resp.0.id),
                    Err(e @ (ApiError::Authority(_) | ApiError::Authorization(_))) => {
                        Created::Refused(e.to_string())
                    }
                    Err(e) => Created::SpawnFailed(e.to_string()),
                }
            }
        }
    }

    /// A pod the node created: hold its certificate to the model's chain, then
    /// add it to the model.
    async fn register(&mut self, id: Uuid, issued: Issued<'_>) -> Result<(), String> {
        let Issued {
            who,
            source,
            depth,
            micro,
            header,
            asked,
            ups,
        } = issued;
        let held = self.node.st.authority.held().await;
        let h = held
            .pods
            .get(&id)
            .ok_or("the node created a pod its authority holds nothing for")?;
        let cert = h.cert.clone();
        let effective = cert.effective_permissions().clone();
        let me = self.node.st.authority.pod_spiffe_id(id);
        let root_key = hex::decode(self.node.st.authority.root_pubkey_hex()).expect("hex");

        verify_certificate(&cert, &root_key, chrono::Utc::now(), MAX_DEPTH)
            .map_err(|e| format!("the certificate does not verify under the node's root: {e}"))?;
        if cert.leaf_identity() != me {
            return Err(format!(
                "certificate names {}, not {me}",
                cert.leaf_identity()
            ));
        }
        if cert.chain_depth() != depth {
            return Err(format!(
                "certificate depth {}, model {depth}",
                cert.chain_depth()
            ));
        }
        if !effective.leq(asked) {
            return Err("effective authority exceeds what the pod asked for".into());
        }
        let last = cert
            .delegation_blocks()
            .last()
            .ok_or("a pod certificate with no delegation block")?;
        if last.to_identity != me {
            return Err(format!("last block delegates to {}", last.to_identity));
        }
        let want_parent = match source {
            Source::Root => {
                if cert.root_identity() != self.node.operator
                    || cert.authority().provenance.is_some()
                {
                    return Err("a root pod's chain is not rooted at the root minter".into());
                }
                Parent::Root
            }
            Source::External(k) => {
                let (_, fp) = self.node.chains[k];
                if cert.root_identity() != EXTERNAL[k].0
                    || cert.authority().provenance != Some(fp)
                    || !effective.leq(&self.node.ext_lattices[k])
                {
                    return Err(
                        "an external caller's pod is not re-rooted at its verified chain".into(),
                    );
                }
                self.stats.external_admitted += 1;
                Parent::External(fp)
            }
            Source::Pod(p) => {
                let parent = &self.model.pods[p];
                if !effective.leq(&parent.effective) {
                    return Err(format!(
                        "pod at depth {depth} holds more authority than its parent"
                    ));
                }
                let theirs = parent.cert.delegation_blocks();
                let ours = cert.delegation_blocks();
                let extends = ours.len() == theirs.len() + 1
                    && cert.authority().signature == parent.cert.authority().signature
                    && ours
                        .iter()
                        .zip(theirs)
                        .all(|(a, b)| a.signature == b.signature);
                if !extends {
                    return Err("the certificate does not extend its parent's chain".into());
                }
                let parent_id = self.node.st.authority.pod_spiffe_id(parent.id);
                if last.from_identity != parent_id {
                    return Err(format!(
                        "delegated by {}, not the calling pod {parent_id}",
                        last.from_identity
                    ));
                }
                Parent::Pod(parent.id)
            }
        };
        if h.parent != want_parent {
            return Err(format!(
                "budget parent {:?}, model {want_parent:?}",
                h.parent
            ));
        }
        // The spec the driver launched carries what was issued, not the request.
        let handle = get_pod(&self.node.st, id)
            .await
            .map_err(|_| "the node created a pod it does not list".to_string())?;
        let launched = handle
            .spec
            .spec
            .resolve_policy()
            .map_err(|e| format!("launched policy: {e}"))?;
        if serde_json::to_value(&launched).ok() != serde_json::to_value(&effective).ok() {
            return Err("the launched spec's policy is not the certificate's lattice".into());
        }
        // And the upstreams admission granted, which the model says are all
        // that were asked for: a request beyond a ceiling is refused whole.
        if handle.spec.spec.credentialed_egress != upstreams(ups) {
            return Err(format!(
                "the launched spec carries upstreams {:?}, admitted {ups:#06b}",
                handle
                    .spec
                    .spec
                    .credentialed_egress
                    .iter()
                    .map(|u| (&u.name, &u.upstream))
                    .collect::<Vec<_>>()
            ));
        }
        if h.upstreams != upstreams(ups) {
            return Err(format!(
                "the authority recorded different upstreams than it launched ({ups:#06b})"
            ));
        }
        if matches!(source, Source::Pod(_)) && ups != 0 {
            self.stats.admitted_upstreams_from_a_pod += 1;
        }

        let reg_parent = match who {
            Who::Pod(r) => Some(self.model.resolve(r)),
            _ => header.map(|h| self.model.resolve(h)),
        };
        self.model.allocate(source, micro);
        self.model.pods.push(MPod {
            id,
            reg_parent,
            source,
            creator: who,
            budget: micro,
            depth,
            phase: Phase::Running,
            ledger: fresh_ledger(micro),
            effective,
            cert,
            ups,
        });
        self.stats.admitted += 1;
        self.stats.depth = self.stats.depth.max(depth);
        Ok(())
    }

    fn target_id(&self, t: Target) -> Uuid {
        match t {
            Target::Pod(r) => self.model.pods[self.model.resolve(r)].id,
            Target::Unknown => self.unknown,
        }
    }

    fn index_of(&self, id: Uuid) -> Option<usize> {
        self.model.pods.iter().position(|p| p.id == id)
    }

    async fn cancel(
        &mut self,
        who: Who,
        via: Via,
        token: bool,
        target: Target,
    ) -> Result<(), String> {
        let id = self.target_id(target);
        let j = self.index_of(id);
        let allowed = who != Who::Stranger && j.is_some_and(|j| self.model.reaches(who, j));
        // Ok(()) cancelled; Err(true) "not found"; Err(false) refused outright.
        let got: Result<(), bool> = match via {
            Via::Grpc => {
                let r =
                    self.node
                        .grpc(&self.model, who, token, proto::PodId { id: id.to_string() });
                let svc = crate::GrpcService {
                    state: self.node.st.clone(),
                };
                match svc.cancel_pod(r).await {
                    Ok(_) => Ok(()),
                    Err(s) => Err(s.code() == tonic::Code::NotFound),
                }
            }
            Via::Http => {
                let path = format!("/v1/pods/{id}/cancel");
                match self
                    .node
                    .http(&self.model, who, token, &path, axum::http::Method::POST)
                {
                    Err(_) => Err(false),
                    Ok((ctx, headers)) => {
                        match crate::auth::resolve_http_caller(&self.node.st, &ctx, &headers) {
                            Err(_) => Err(false),
                            Ok(caller) => match cancel_pod(
                                State(self.node.st.clone()),
                                Extension(caller),
                                AxumPath(id),
                            )
                            .await
                            {
                                Ok(_) => Ok(()),
                                Err(ApiError::NotFound) => Err(true),
                                Err(_) => Err(false),
                            },
                        }
                    }
                }
            }
        };
        match (allowed, got) {
            (true, Ok(())) => {
                let j = j.expect("allowed implies a pod");
                if self.model.pods[j].phase == Phase::Running {
                    self.model.pods[j].phase = Phase::Exited;
                } else {
                    self.stats.repeat_cancels += 1;
                }
                Ok(())
            }
            // Refused looks like absent, to a caller the node knows; an
            // identity it grants nothing is refused before any lookup.
            (false, Err(not_found)) if not_found == (who != Who::Stranger) => {
                if j.is_some() {
                    self.stats.scope_refused += 1;
                }
                Ok(())
            }
            (allowed, got) => Err(format!(
                "model allows={allowed}; the node answered {got:?} (Err(true) is NotFound)"
            )),
        }
    }

    async fn list(&mut self, who: Who, via: Via, token: bool) -> Result<(), String> {
        let got: Option<BTreeSet<Uuid>> = match via {
            Via::Grpc => {
                let r = self.node.grpc(&self.model, who, token, proto::Empty {});
                let svc = crate::GrpcService {
                    state: self.node.st.clone(),
                };
                svc.list_pods(r).await.ok().map(|resp| {
                    resp.into_inner()
                        .pods
                        .into_iter()
                        .filter_map(|p| Uuid::parse_str(&p.id).ok())
                        .collect()
                })
            }
            Via::Http => {
                match self
                    .node
                    .http(&self.model, who, token, "/v1/pods", axum::http::Method::GET)
                {
                    Err(_) => None,
                    Ok((ctx, headers)) => {
                        match crate::auth::resolve_http_caller(&self.node.st, &ctx, &headers) {
                            Err(_) => None,
                            Ok(caller) => list_pods(State(self.node.st.clone()), Extension(caller))
                                .await
                                .ok()
                                .map(|j| j.0.into_iter().map(|i| i.id).collect()),
                        }
                    }
                }
            }
        };
        let want: Option<BTreeSet<Uuid>> = (who != Who::Stranger).then(|| {
            (0..self.model.pods.len())
                .filter(|&j| self.model.reaches(who, j))
                .map(|j| self.model.pods[j].id)
                .collect()
        });
        if got != want {
            return Err(format!("listed {got:?}, model says {want:?}"));
        }
        Ok(())
    }

    async fn lockdown(
        &mut self,
        who: Who,
        scope: Scope,
        claim: Claim,
        restore: bool,
    ) -> Result<(), String> {
        let claimed = match claim {
            Claim::Empty => String::new(),
            Claim::SomeoneElse => "someone-else".to_string(),
            Claim::TheOperator => self.node.operator.clone(),
        };
        let wire = match scope {
            Scope::All => None,
            Scope::Pod(t) => Some(proto::lockdown_request::Scope::PodId(
                self.target_id(t).to_string(),
            )),
            Scope::Label => Some(proto::lockdown_request::Scope::LabelSelector(String::new())),
        };
        let r = self.node.grpc(
            &self.model,
            who,
            false,
            proto::LockdownRequest {
                scope: wire,
                reason: REASON.to_string(),
                operator_id: claimed.clone(),
                restore,
            },
        );
        let svc = crate::GrpcService {
            state: self.node.st.clone(),
        };
        let got = svc.lockdown(r).await;
        let heard = self.heard.try_recv();

        if !Model::may_lock_down(who) {
            if got.is_ok() || heard.is_ok() {
                return Err(format!(
                    "a caller the policy does not let lock down did: {got:?}, broadcast {heard:?}"
                ));
            }
            self.stats.lockdowns_refused += 1;
            return Ok(());
        }
        let resp = got.map_err(|s| format!("refused: {s}"))?.into_inner();
        let cmd = heard.map_err(|e| format!("nothing broadcast: {e}"))?;

        let verified = self.node.peer(&self.model, who);
        let operator = if claimed.is_empty() {
            verified.clone()
        } else {
            self.stats.attributed_claims += 1;
            format!("{verified} (claims {claimed:?})")
        };
        if cmd.operator_id != operator {
            return Err(format!(
                "broadcast attributes the lockdown to {:?}; the verified peer is {verified:?}",
                cmd.operator_id
            ));
        }
        if cmd.active == restore {
            return Err("broadcast in the wrong direction".into());
        }
        let target = match scope {
            Scope::Pod(Target::Pod(r)) => Some(self.model.resolve(r)),
            _ => None,
        };
        match (scope, target) {
            (Scope::All, _) if restore => {
                self.model.locked_all = false;
                self.model.locked.clear();
            }
            (Scope::All, _) => self.model.locked_all = true,
            (_, Some(j)) if restore => {
                self.model.locked.remove(&j);
            }
            (_, Some(j)) => {
                self.model.locked.insert(j);
            }
            _ => {}
        }
        let below = |j: usize| target.is_some_and(|t| self.model.lineage(j).contains(&t));
        let affected: Vec<usize> = (0..self.model.pods.len())
            .filter(|&j| match scope {
                Scope::All | Scope::Label => true,
                Scope::Pod(_) => below(j),
            })
            .collect();
        if resp.affected_pods as usize != affected.len() {
            return Err(format!(
                "affected {}, model {}",
                resp.affected_pods,
                affected.len()
            ));
        }
        // What each pod's watcher is sent, now and if it connects later.
        for j in 0..self.model.pods.len() {
            let id = self.model.pods[j].id;
            let sent = crate::lockdown::delivery(&self.node.st, &cmd, Some(id)).await;
            let reached = match scope {
                Scope::All | Scope::Label => true,
                Scope::Pod(_) => below(j),
            };
            let want = reached && !(restore && self.model.covered(j));
            match sent {
                Some(c) if want => {
                    let addressed = match scope {
                        Scope::Pod(_) => c.scope == format!("pod:{id}"),
                        _ => c.scope == cmd.scope,
                    };
                    if !addressed || c.active == restore || c.operator_id != operator {
                        return Err(format!("pod {j} is sent {c:?}"));
                    }
                    if target.is_some_and(|t| t != j) && !restore {
                        self.stats.locked_below += 1;
                    }
                }
                None if !want => {}
                sent => {
                    return Err(format!(
                        "pod {j} is sent {sent:?}; the model says it is {}sent this lockdown",
                        if want { "" } else { "not " }
                    ));
                }
            }
            let later = crate::lockdown::in_force(&self.node.st, Some(id)).await;
            if later.as_ref().is_some_and(|c| !c.active) || later.is_some() != self.model.covered(j)
            {
                return Err(format!(
                    "a watcher pod {j} connects now is told {later:?}; the model says it is {}under lockdown",
                    if self.model.covered(j) { "" } else { "not " }
                ));
            }
        }
        for &j in &affected {
            let id = self.model.pods[j].id;
            let log = self
                .node
                .st
                .state_dir
                .join("pods")
                .join(id.to_string())
                .join("lifecycle.log");
            let text = std::fs::read_to_string(&log).unwrap_or_default();
            let entry: serde_json::Value = text
                .lines()
                .last()
                .and_then(|l| serde_json::from_str(l).ok())
                .ok_or_else(|| format!("no lifecycle entry for {id}"))?;
            let event = if restore {
                "lockdown_restored"
            } else {
                "lockdown_applied"
            };
            let detail = format!("reason={REASON}, operator={operator}");
            if entry["event"] != event || entry["result"] != detail.as_str() {
                return Err(format!(
                    "{id}'s audit records {entry}; the verified attribution is {detail:?}"
                ));
            }
        }
        Ok(())
    }

    /// Hold the node to the model: the authority's pods, their budget parents
    /// and every ledger; the registry's pods, their lineage and their state.
    async fn check(&self) -> Result<(), String> {
        let held = self.node.st.authority.held().await;
        let want: BTreeSet<Uuid> = self
            .model
            .pods
            .iter()
            .filter(|p| p.phase != Phase::Reaped)
            .map(|p| p.id)
            .collect();
        let have: BTreeSet<Uuid> = held.pods.keys().copied().collect();
        if have != want {
            let extra = have.difference(&want).count();
            let missing = want.difference(&have).count();
            return Err(format!(
                "the authority holds {extra} certificate(s) the model has none for, \
                 and lacks {missing} it has"
            ));
        }
        for (j, p) in self.model.pods.iter().enumerate() {
            if let Some(h) = held.pods.get(&p.id) {
                if h.ledger != p.ledger {
                    return Err(format!(
                        "pod {j}'s ledger is {:?}, model {:?}",
                        h.ledger, p.ledger
                    ));
                }
                if h.ledger.allocated + h.ledger.consumed > h.ledger.max {
                    return Err(format!("pod {j}'s ledger over-commits: {:?}", h.ledger));
                }
                if h.upstreams != upstreams(p.ups) {
                    return Err(format!(
                        "pod {j}'s upstreams are not those it was admitted ({:#06b})",
                        p.ups
                    ));
                }
            }
        }
        // A child's upstreams are within its parent's, read from what the
        // authority holds for both rather than from the model: the invariant
        // admission exists to keep, at every depth and across restarts.
        for (id, h) in &held.pods {
            if let Parent::Pod(parent) = h.parent
                && let Some(p) = held.pods.get(&parent)
                && let Some(beyond) = h.upstreams.iter().find(|u| !u.admitted_by(&p.upstreams))
            {
                return Err(format!(
                    "{id} holds upstream `{}`, which its parent {parent} does not",
                    beyond.name
                ));
            }
        }
        for (k, want) in self.model.external.iter().enumerate() {
            let (_, fp) = self.node.chains[k];
            let have = held
                .external
                .get(&fp)
                .copied()
                .unwrap_or(fresh_ledger(want.max));
            if have != *want {
                return Err(format!(
                    "external chain {k}'s ledger is {have:?}, model {want:?}"
                ));
            }
        }

        let pods = self.node.st.pods.lock().await.clone();
        if pods.len() != self.model.pods.len() {
            return Err(format!(
                "the registry holds {} pods, model {}",
                pods.len(),
                self.model.pods.len()
            ));
        }
        for p in &self.model.pods {
            let h = pods.get(&p.id).ok_or("a model pod is not registered")?;
            let parent = p.reg_parent.map(|i| self.model.pods[i].id);
            if h.parent_pod_id != parent {
                return Err(format!(
                    "{} records parent {:?}, model {parent:?}",
                    p.id, h.parent_pod_id
                ));
            }
            let running = matches!(h.status().await, PodState::Running);
            if running != (p.phase == Phase::Running) {
                return Err(format!("{} running={running}, model {:?}", p.id, p.phase));
            }
        }
        Ok(())
    }

    /// Run the reaper to a fixpoint, then: nothing below a stopped pod runs,
    /// nothing stopped holds authority, and nothing stopped can create.
    async fn quiesce(&mut self) -> Result<(), String> {
        for _ in 0..=MAX_DEPTH + 2 {
            crate::reap_once(&self.node.st, &mut self.reaped).await;
            self.stats.cascaded += self.model.reap();
        }
        self.check().await?;
        for (j, p) in self.model.pods.iter().enumerate() {
            let mut up = p.reg_parent;
            while let Some(a) = up {
                if self.model.pods[a].phase != Phase::Running && p.phase == Phase::Running {
                    return Err(format!("pod {j} still runs below stopped pod {a}"));
                }
                up = self.model.pods[a].reg_parent;
            }
            if p.phase == Phase::Exited {
                return Err(format!("pod {j} stopped and still holds authority"));
            }
        }
        let held_before = self.node.st.authority.held().await;
        for j in 0..self.model.pods.len() {
            if self.model.pods[j].phase != Phase::Reaped {
                continue;
            }
            let who = Who::Pod(PodRef::Nth(u8::try_from(j).expect("fewer than 256 pods")));
            let yaml = spec_yaml(&self.node.st.state_dir.join("w"), requested(0, 0), 0);
            let got = self
                .issue_create(&self.node.st.clone(), who, Via::Grpc, false, None, yaml)
                .await;
            if !matches!(got, Created::Refused(_)) {
                return Err(format!("released pod {j} could still create: {got}"));
            }
        }
        let held_after = self.node.st.authority.held().await;
        if held_before.pods.len() != held_after.pods.len() {
            return Err("a refused create changed what the authority holds".into());
        }
        Ok(())
    }
}

// ── Running it ───────────────────────────────────────────────────────────────

fn runtime() -> tokio::runtime::Runtime {
    // Paused: a booting pod waits 3 s for its proxy's announcement, and the
    // walk lets the clock jump rather than sleep through it.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("runtime")
}

fn seed() -> u64 {
    match std::env::var("NUCLEUS_CHAIN_WALK_SEED").ok().as_deref() {
        None | Some("") => DEFAULT_SEED,
        Some("random") => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch");
            u64::try_from(now.as_nanos() & u128::from(u64::MAX)).expect("masked")
        }
        Some(s) => s
            .trim_start_matches("0x")
            .parse::<u64>()
            .or_else(|_| u64::from_str_radix(s.trim_start_matches("0x"), 16))
            .expect("NUCLEUS_CHAIN_WALK_SEED is a number or `random`"),
    }
}

/// Replay [`CORPUS`], then run the walk; on a disagreement, the seed and the
/// shrunk case.
fn explore(rules: Rules) -> Stats {
    replay(rules);
    let cases = std::env::var("NUCLEUS_CHAIN_WALK_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_CASES);
    let seed = seed();
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    let config = Config {
        cases,
        failure_persistence: None,
        max_shrink_iters: 4096,
        ..Config::default()
    };
    let mut runner =
        TestRunner::new_with_rng(config, TestRng::from_seed(RngAlgorithm::ChaCha, &bytes));
    let total = std::sync::Mutex::new(Stats::default());
    let result = runner.run(&case(), |case| {
        let stats = runtime()
            .block_on(run_case(&case, rules))
            .map_err(TestCaseError::fail)?;
        total.lock().expect("stats").add(&stats);
        Ok(())
    });
    match result {
        Ok(()) => total.into_inner().expect("stats"),
        Err(TestError::Fail(why, case)) => panic!(
            "the node and the model disagree (seed {seed:#x}, {cases} cases).\n\
             {why}\n\nShrunk case, for CORPUS:\n{}",
            case.literal()
        ),
        Err(TestError::Abort(why)) => panic!("aborted (seed {seed:#x}): {why}"),
    }
}

/// The node agrees with the model on every random case. Its stats also show
/// the run reached what it checks: a run that never refused a budget or
/// cascaded a cancel proved nothing about either.
#[test]
fn random_delegation_chains_agree_with_the_model() {
    let stats = explore(Rules::AS_SHIPPED);
    eprintln!("chain walk reached: {stats:?}");
    // Three, not deeper: a chain stops growing the moment any pod above its
    // newest stops, which a random walk does often. The depth bound itself is
    // `a_chain_is_refused_one_hop_past_the_depth_bound`'s.
    assert!(stats.depth >= 3, "{stats:?}");
    for (what, n) in [
        ("admitted", stats.admitted),
        ("external admissions", stats.external_admitted),
        ("budget refusals", stats.refused_budget),
        ("fan-out refusals", stats.refused_fan_out),
        ("refusals of a released pod", stats.refused_released),
        (
            "refusals of an unregistered upstream",
            stats.refused_unregistered,
        ),
        (
            "refusals of an upstream beyond the parent's",
            stats.refused_beyond_parent,
        ),
        (
            "upstreams admitted to a pod caller's child",
            stats.admitted_upstreams_from_a_pod,
        ),
        ("failed spawns", stats.spawn_failed),
        ("dropped creates", stats.client_gone),
        ("cascaded cancels", stats.cascaded),
        ("scope refusals", stats.scope_refused),
        ("repeated cancels", stats.repeat_cancels),
        ("attributed claims", stats.attributed_claims),
        ("refused lockdowns", stats.lockdowns_refused),
        ("refusals under lockdown", stats.refused_locked),
        ("refusals below a stopped pod", stats.refused_stopped),
        ("restarts with consumption", stats.restarts_with_consumption),
    ] {
        assert!(n > 0, "the walk never reached {what}: {stats:?}");
    }
}

/// Depth is the one refusal a random walk rarely strings together: ten nested
/// creates. This one does, and goes one further.
#[test]
fn a_chain_is_refused_one_hop_past_the_depth_bound() {
    let mut ops = vec![
        Op::Create {
            who: Who::Pod(PodRef::Newest),
            via: Via::Grpc,
            token: false,
            budget: 0,
            caps: 0,
            boot: Boot::Runs,
            header: None,
            ups: 0,
        };
        MAX_DEPTH
    ];
    ops.push(Op::Cancel {
        who: Who::Operator,
        via: Via::Grpc,
        token: false,
        target: Target::Pod(PodRef::Nth(0)),
    });
    let stats = runtime()
        .block_on(run_case(
            &Case {
                root_budget: 0,
                ops,
            },
            Rules::AS_SHIPPED,
        ))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stats.depth, MAX_DEPTH, "{stats:?}");
    assert_eq!(stats.refused_depth, 1, "{stats:?}");
    assert!(stats.cascaded >= MAX_DEPTH - 1, "{stats:?}");
}

/// A lockdown of a chain's root reaches every pod down the chain, and none of
/// them can create while it holds. Deterministic, because a random walk only
/// sometimes locks a pod that already has descendants.
#[test]
fn a_lockdown_of_a_chains_root_reaches_the_whole_chain() {
    let create = Op::Create {
        who: Who::Pod(PodRef::Newest),
        via: Via::Grpc,
        token: false,
        budget: 0,
        caps: 0,
        boot: Boot::Runs,
        header: None,
        ups: 0,
    };
    let mut ops = vec![create; 4];
    ops.push(Op::Lockdown {
        who: Who::Operator,
        scope: Scope::Pod(Target::Pod(PodRef::Nth(0))),
        claim: Claim::Empty,
        restore: false,
    });
    ops.push(create);
    let stats = runtime()
        .block_on(run_case(
            &Case {
                root_budget: 0,
                ops,
            },
            Rules::AS_SHIPPED,
        ))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stats.locked_below, 4, "{stats:?}");
    assert_eq!(stats.refused_locked, 1, "{stats:?}");
}

/// The upstream corpus entry reaches every case it is there for: a pod caller
/// refused an upstream its parent lacks (before and after a restart), refused
/// one the registry lacks or holds differently, the same for the root minter
/// and external callers, and a grandchild admitted what its chain holds.
#[test]
fn a_child_is_never_admitted_an_upstream_its_parent_lacks() {
    let (_, root_budget, ops) = CORPUS
        .iter()
        .find(|(name, ..)| name.starts_with("a child holds no upstream"))
        .expect("the upstream corpus entry");
    let stats = runtime()
        .block_on(run_case(
            &Case {
                root_budget: *root_budget,
                ops: ops.to_vec(),
            },
            Rules::AS_SHIPPED,
        ))
        .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(stats.refused_beyond_parent, 3, "{stats:?}");
    assert_eq!(stats.refused_unregistered, 5, "{stats:?}");
    assert_eq!(stats.admitted_upstreams_from_a_pod, 3, "{stats:?}");
}

// ── The regression corpus ────────────────────────────────────────────────────

/// Shrunk cases that found a bug, replayed before every walk under that
/// walk's [`Rules`]. Each is named for the bug it found; the PR that added it
/// shows the perturbation it was found under. The `#3105` entry checks
/// nothing as shipped and is the first thing its documented rule trips on.
#[rustfmt::skip]
const CORPUS: &[(&str, u8, &[Op])] = &[
    ("#3032: a create dropped mid-boot keeps no certificate", 0, &[
        Op::Create { who: Who::Operator, via: Via::Grpc, token: false, budget: 0, caps: 0, boot: Boot::ClientGone, header: None, ups: 0 },
    ]),
    ("#3032: a pod's create dropped mid-boot hands its slot back", 1, &[
        Op::Create { who: Who::Pod(PodRef::Newest), via: Via::Grpc, token: false, budget: 1, caps: 0, boot: Boot::ClientGone, header: None, ups: 0 },
        Op::Create { who: Who::Pod(PodRef::Nth(0)), via: Via::Http, token: true, budget: 0, caps: 0, boot: Boot::Runs, header: None, ups: 0 },
    ]),
    ("#3093: a committed reservation is not released while its pod runs", 0, &[
        Op::Create { who: Who::Operator, via: Via::Grpc, token: false, budget: 0, caps: 0, boot: Boot::Runs, header: None, ups: 0 },
    ]),
    ("#3081: a lockdown is attributed to the verified peer, not its claim", 0, &[
        Op::Lockdown { who: Who::Operator, scope: Scope::All, claim: Claim::SomeoneElse, restore: false },
    ]),
    ("#3088: a CI identity does not reach a pod it did not create", 0, &[
        Op::List { who: Who::Ci(0), via: Via::Grpc, token: false },
    ]),
    ("#3088: a CI identity reaches the pod it created", 0, &[
        Op::Create { who: Who::Ci(0), via: Via::Grpc, token: false, budget: 0, caps: 0, boot: Boot::Runs, header: None, ups: 0 },
        Op::List { who: Who::Ci(0), via: Via::Grpc, token: false },
    ]),
    ("#3105: a failed spawn hands its reservation back", 1, &[
        Op::Create { who: Who::Orch(0), via: Via::Grpc, token: false, budget: 1, caps: 0, boot: Boot::SpawnFails, header: None, ups: 0 },
    ]),
    ("a pod's lockdown reaches the pods below it", 0, &[
        Op::Create { who: Who::Pod(PodRef::Newest), via: Via::Grpc, token: false, budget: 0, caps: 0, boot: Boot::Runs, header: None, ups: 0 },
        Op::Lockdown { who: Who::Operator, scope: Scope::Pod(Target::Pod(PodRef::Nth(0))), claim: Claim::Empty, restore: false },
    ]),
    ("a pod below a locked pod creates nothing", 0, &[
        Op::Create { who: Who::Pod(PodRef::Newest), via: Via::Grpc, token: false, budget: 0, caps: 0, boot: Boot::Runs, header: None, ups: 0 },
        Op::Lockdown { who: Who::Orch(0), scope: Scope::Pod(Target::Pod(PodRef::Nth(0))), claim: Claim::Empty, restore: false },
        Op::Create { who: Who::Pod(PodRef::Newest), via: Via::Http, token: true, budget: 0, caps: 0, boot: Boot::Runs, header: None, ups: 0 },
    ]),
    ("lifting a pod's lockdown leaves the one above it in force", 0, &[
        Op::Create { who: Who::Pod(PodRef::Newest), via: Via::Grpc, token: false, budget: 0, caps: 0, boot: Boot::Runs, header: None, ups: 0 },
        Op::Lockdown { who: Who::Operator, scope: Scope::Pod(Target::Pod(PodRef::Nth(0))), claim: Claim::Empty, restore: false },
        Op::Lockdown { who: Who::Operator, scope: Scope::Pod(Target::Pod(PodRef::Newest)), claim: Claim::Empty, restore: false },
        Op::Lockdown { who: Who::Operator, scope: Scope::Pod(Target::Pod(PodRef::Newest)), claim: Claim::Empty, restore: true },
        Op::Create { who: Who::Pod(PodRef::Newest), via: Via::Grpc, token: false, budget: 0, caps: 0, boot: Boot::Runs, header: None, ups: 0 },
    ]),
    ("a watcher that connects under a lockdown is told it", 0, &[
        Op::Lockdown { who: Who::Operator, scope: Scope::All, claim: Claim::Empty, restore: false },
    ]),
    ("a pod below a stopped pod creates nothing", 0, &[
        Op::Cancel { who: Who::Operator, via: Via::Grpc, token: false, target: Target::Pod(PodRef::Newest) },
        Op::Create { who: Who::Operator, via: Via::Grpc, token: false, budget: 1, caps: 0, boot: Boot::Runs, header: Some(PodRef::Newest), ups: 0 },
        Op::Create { who: Who::Pod(PodRef::Nth(1)), via: Via::Grpc, token: false, budget: 0, caps: 0, boot: Boot::Runs, header: None, ups: 0 },
    ]),
    ("an external chain's ledger is restored on restart", 0, &[
        Op::Create { who: Who::Orch(0), via: Via::Grpc, token: false, budget: 0, caps: 0, boot: Boot::Runs, header: None, ups: 0 },
        Op::Restart,
    ]),
    ("a child holds no upstream its parent lacks, before and after a restart", 1, &[
        Op::Create { who: Who::Pod(PodRef::Nth(0)), via: Via::Grpc, token: false, budget: 0, caps: 0, boot: Boot::Runs, header: None, ups: 0b0001 },
        Op::Create { who: Who::Pod(PodRef::Newest), via: Via::Grpc, token: false, budget: 0, caps: 0, boot: Boot::Runs, header: None, ups: 0b0010 },
        Op::Create { who: Who::Pod(PodRef::Newest), via: Via::Http, token: true, budget: 0, caps: 0, boot: Boot::Runs, header: None, ups: 0b0011 },
        Op::Create { who: Who::Pod(PodRef::Newest), via: Via::Http, token: true, budget: 0, caps: 0, boot: Boot::Runs, header: None, ups: 0b0001 },
        Op::Restart,
        Op::Create { who: Who::Pod(PodRef::Nth(1)), via: Via::Grpc, token: false, budget: 0, caps: 0, boot: Boot::Runs, header: None, ups: 0b0010 },
        Op::Create { who: Who::Pod(PodRef::Newest), via: Via::Grpc, token: false, budget: 0, caps: 0, boot: Boot::Runs, header: None, ups: 0b0001 },
        Op::Create { who: Who::Pod(PodRef::Nth(0)), via: Via::Grpc, token: false, budget: 0, caps: 0, boot: Boot::Runs, header: None, ups: 0b0100 },
        Op::Create { who: Who::Pod(PodRef::Nth(0)), via: Via::Http, token: true, budget: 0, caps: 0, boot: Boot::Runs, header: None, ups: 0b1000 },
        Op::Create { who: Who::Orch(0), via: Via::Grpc, token: false, budget: 0, caps: 0, boot: Boot::Runs, header: None, ups: 0b1001 },
        Op::Create { who: Who::Ci(0), via: Via::Http, token: false, budget: 0, caps: 0, boot: Boot::Runs, header: None, ups: 0b0100 },
        Op::Create { who: Who::Operator, via: Via::Grpc, token: false, budget: 0, caps: 0, boot: Boot::Runs, header: None, ups: 0b1000 },
        Op::Create { who: Who::Orch(1), via: Via::Http, token: false, budget: 0, caps: 0, boot: Boot::Runs, header: None, ups: 0b0011 },
    ]),
    ("what a retired child consumed is restored on restart", 1, &[
        Op::Create { who: Who::Pod(PodRef::Newest), via: Via::Grpc, token: false, budget: 1, caps: 0, boot: Boot::Runs, header: None, ups: 0 },
        Op::Cancel { who: Who::Operator, via: Via::Grpc, token: false, target: Target::Pod(PodRef::Newest) },
        Op::Reap,
        Op::Restart,
    ]),
];

fn replay(rules: Rules) {
    for (name, root_budget, ops) in CORPUS {
        let case = Case {
            root_budget: *root_budget,
            ops: ops.to_vec(),
        };
        if let Err(e) = runtime().block_on(run_case(&case, rules)) {
            panic!("corpus entry `{name}`: {e}");
        }
    }
}

#[test]
fn the_corpus_agrees_with_the_model() {
    replay(Rules::AS_SHIPPED);
}

// ── The documented rules, red on main ────────────────────────────────────────

/// #3105: a create that never ran hands its whole reservation back.
#[test]
#[ignore = "red on main until #3105: an unrun create's reservation is folded into consumption"]
fn as_documented_a_create_that_never_ran_refunds_its_reservation() {
    explore(Rules {
        unrun_refunds: true,
    });
}
