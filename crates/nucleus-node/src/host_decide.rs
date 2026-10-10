//! The host's decision service, in SHADOW mode (#2702, L-1, step P8).
//!
//! Today every decision about a tool call is taken in the guest, by the
//! tool-proxy's kernel. The programme moves it to the host. This module is the
//! first step that runs on a live pod: for each decision the guest takes, the
//! guest ALSO asks the host, over its own vsock port
//! ([`nucleus_decision_protocol::DECISION_VSOCK_PORT`]), in the P7 frames. The
//! host answers from a kernel it built itself, from the certificate it issued
//! the pod (`pod_authority`), and then compares its answer with the one the
//! guest reports it enforced.
//!
//! **Nothing the host says here is enforced.** The guest still acts on its own
//! kernel; the host's verdict is a measurement. What this step produces is the
//! evidence P9 needs before it can make the host authoritative: a count of
//! agreements and disagreements over real traffic, and a record of every
//! disagreement naming both outcomes and the operation.
//!
//! # Pod policy, channel protocol
//!
//! A connection is one channel, and a channel is the host's view of one guest
//! kernel session (the HTTP transport's kernel and the MCP transport's are two
//! sessions, so two channels). The pod shares across every channel:
//!
//! * a [`Kernel`] built from the pod's certificate — the same constructor the
//!   guest uses (`Kernel::from_certificate`), so the two start equal;
//! * a [`HostTaint`] — owner decision D2: the host's own label, which a guest
//!   `Observe` can only raise (it is the lattice join, and no frame lowers it).
//!
//! Observation and decision serialize under one pod policy lock; a poisoned
//! lock closes the channel. Reconnecting cannot reset this history. Each
//! channel separately holds:
//!
//! * a [`SeqGate`] — the host numbers the frames, the guest only echoes;
//! * a [`DecisionLedger`] under an epoch no earlier channel on this node used
//!   ([`EpochSource`]), so an id from a closed channel is `ForeignEpoch` on the
//!   one that replaced it rather than a live number on a ledger that also
//!   started from zero.
//!
//! # The exchange
//!
//! `Decide` → the host decides and answers with a `Verdict` carrying a fresh id.
//! `Shadow` (the guest's own outcome for that `Decide`) → the host compares
//! ([`Agreement::of`], the one decider), records, retires the id it issued —
//! nothing in shadow mode will ever act on it, and leaving it live would grow the
//! ledger toward `MAX_LIVE` — and answers `Compared`. The guest counts from the
//! host's `Agreement`, so the two tallies cannot disagree about one exchange.
//!
//! # What can make an honest pair disagree
//!
//! Listed so a disagreement is read as data, not noise:
//!
//! * a human approval grant (`issue_approved_token` moves the guest's exposure);
//! * declassification keys provisioned into the guest kernel (DLC admission no
//!   longer: the host's kernel reads the pod's admitted DLC through the same
//!   `DlcAdmission::provision` the guest's does);
//! * per-node declassification scopes in the guest's graph (the host's taint is
//!   one label, so it is never less restrictive than the graph);
//! * a poisoned guest graph, which the guest reports as the top label but which
//!   also denies reads;
//! * another channel or a replacement guest with less history than the host:
//!   the host retains the pod's cumulative observations and kernel state.

// The listener is started from `spawn_firecracker_pod`, which is linux-only; a
// macOS build compiles none of its callers.
#![cfg_attr(all(not(test), not(target_os = "linux")), allow(dead_code))]

pub(crate) mod effects;
pub(crate) mod evidence;
pub(crate) mod starting_label;

pub(crate) use starting_label::{StartingLabel, Untrusted};

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nucleus_decision_protocol::host::{
    DecisionLedger, LedgerError, Redemption, SeqError, SeqGate, Spent,
};
use nucleus_decision_protocol::kernel::{HostTaint, args_digest, outcome_of};
use nucleus_decision_protocol::{
    Agreement, ApprovalId, DecisionId, DenyReason, EncodeError, FrameError, GuestFrame, HostFrame,
    LEN_PREFIX, Outcome, Seq, Subject, Verdict, body_len,
};
use nucleus_spec::host_decide_telemetry::{LatencyHistogram, OutcomePair};
use portcullis::kernel::{Kernel, Verdict as KernelVerdict};
use portcullis::{ActionTerm, Operation};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

/// How long the host waits for the rest of a frame once its length has arrived.
/// A channel may idle between frames for as long as its session lives; it may
/// not stall halfway through one.
const FRAME_DEADLINE: Duration = Duration::from_secs(5);

/// The most channels one pod may hold open at once. A guest has one per kernel
/// session; past this it is opening them to cost the host, and is refused.
const MAX_CHANNELS_PER_POD: usize = 8;

/// The most disagreements kept in memory per pod. Every one is also written to
/// the pod's record file; this bound is only on what the node holds.
const KEPT_DISAGREEMENTS: usize = 64;

/// The file in the pod directory that disagreements are appended to.
pub(crate) use nucleus_spec::host_decide_telemetry::DISAGREEMENT_LOG;

// ── epochs ──────────────────────────────────────────────────────────────────

/// Hands every decision channel on this node an epoch no earlier channel used.
///
/// A counter, so uniqueness within one node process is by construction: each
/// epoch is handed out once and the counter refuses to wrap. Seeded from the OS
/// RNG with the top bit clear, so a restarted node starts somewhere else in a
/// 2^63 space instead of back at an epoch a surviving guest may still hold ids
/// for, and 2^63 channels of headroom remain before the counter refuses.
#[derive(Debug)]
pub(crate) struct EpochSource {
    next: AtomicU64,
}

/// The node handed out every epoch it had. Refused rather than wrapped onto one
/// an earlier channel used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EpochsExhausted;

impl EpochSource {
    /// A source seeded from the OS RNG.
    pub fn seeded() -> Self {
        use rand_core::RngCore;
        Self::starting_at(rand_core::OsRng.next_u64() >> 1)
    }

    /// A source whose first epoch is `first`.
    pub fn starting_at(first: u64) -> Self {
        Self {
            next: AtomicU64::new(first),
        }
    }

    /// The next unused epoch.
    pub fn next(&self) -> Result<u64, EpochsExhausted> {
        self.next
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_add(1))
            .map_err(|_| EpochsExhausted)
    }
}

// ── the record ──────────────────────────────────────────────────────────────

/// One compared exchange: the operation, both outcomes, and what the host
/// found. Written for every disagreement; counted for every exchange.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct Comparison {
    pub pod: Uuid,
    /// The epoch of the channel it was decided on.
    pub epoch: u64,
    /// The number of the `Decide` frame.
    pub decided: u64,
    pub operation: &'static str,
    pub subject: String,
    /// What the guest's kernel decided, and enforced.
    pub guest: String,
    /// What the host's kernel decided.
    pub host: String,
    /// The host kernel's own refusal code, finer than the wire's vocabulary.
    pub host_detail: &'static str,
    /// The decision id the host retired for it, when it issued one.
    pub retired_decision: Option<u64>,
    pub agreement: AgreementCode,
}

/// [`Agreement`] as the record spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AgreementCode {
    Agree,
    Disagree,
}

impl From<Agreement> for AgreementCode {
    fn from(a: Agreement) -> Self {
        match a {
            Agreement::Agree => AgreementCode::Agree,
            Agreement::Disagree => AgreementCode::Disagree,
        }
    }
}

/// An outcome as the record spells it. Never `Debug`: a record an auditor
/// queries must not change spelling when a variant gains a field.
pub(crate) fn outcome_code(o: Outcome) -> String {
    match o {
        Outcome::Allowed => "allowed".to_string(),
        Outcome::ApprovalRequired => "approval_required".to_string(),
        Outcome::Denied { reason } => format!("denied:{}", deny_code(reason)),
    }
}

fn deny_code(r: DenyReason) -> &'static str {
    match r {
        DenyReason::NotGranted => "not_granted",
        DenyReason::FlowRefused => "flow_refused",
        DenyReason::BudgetExhausted => "budget_exhausted",
        DenyReason::ApprovalRefused => "approval_refused",
        DenyReason::ApprovalExpired => "approval_expired",
        DenyReason::ApprovalUnknown => "approval_unknown",
        DenyReason::NotRegistered => "not_registered",
        DenyReason::RouteRefused => "route_refused",
    }
}

fn kernel_detail(v: &KernelVerdict) -> &'static str {
    match v {
        KernelVerdict::Allow => "allow",
        KernelVerdict::RequiresApproval => "requires_approval",
        KernelVerdict::Deny(reason) => portcullis::gate_class::deny_code(reason),
    }
}

/// One pod's shadow counters, and the disagreements behind them.
///
/// Every compared exchange is counted once, by operation and outcome pair;
/// agreement and disagreement are derived from those pairs, never counted
/// beside them (ADR 0007 G-1). `faults` counts channels the host closed because
/// the guest broke the protocol; `unreported` counts `Decide`s the host answered
/// whose `Shadow` report never came. A guest that never reached the host is
/// counted by the GUEST, as `HostUnavailable` — the host cannot count what it
/// never received.
#[derive(Debug, Default)]
pub(crate) struct ShadowTally {
    pairs: std::sync::Mutex<BTreeMap<PairKey, u64>>,
    faults: AtomicU64,
    unreported: AtomicU64,
    service: std::sync::Mutex<LatencyHistogram>,
    disagreements: std::sync::Mutex<VecDeque<Comparison>>,
}

/// An operation and the two outcomes it was decided with, as the record
/// spells them.
type PairKey = (&'static str, String, String);

/// A point-in-time read of a [`ShadowTally`]'s counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TallySnapshot {
    pub agree: u64,
    pub disagree: u64,
    pub faults: u64,
    pub unreported: u64,
}

/// Everything a pod's shadow service measured, read once at teardown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TeardownReport {
    pub tally: TallySnapshot,
    pub pairs: Vec<OutcomePair>,
    pub service: LatencyHistogram,
}

fn locked<T>(m: &std::sync::Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A counter is still a counter after a panic elsewhere; never lose it.
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl ShadowTally {
    pub fn snapshot(&self) -> TallySnapshot {
        let (mut agree, mut disagree) = (0u64, 0u64);
        for ((_, guest, host), n) in locked(&self.pairs).iter() {
            let slot = if guest == host {
                &mut agree
            } else {
                &mut disagree
            };
            *slot = slot.saturating_add(*n);
        }
        TallySnapshot {
            agree,
            disagree,
            faults: self.faults.load(Ordering::SeqCst),
            unreported: self.unreported.load(Ordering::SeqCst),
        }
    }

    /// The counts, the pairs behind them and the service times.
    pub fn report(&self) -> TeardownReport {
        let pairs = locked(&self.pairs)
            .iter()
            .map(|((operation, guest, host), count)| OutcomePair {
                operation: (*operation).to_string(),
                guest: guest.clone(),
                host: host.clone(),
                count: *count,
            })
            .collect();
        TeardownReport {
            tally: self.snapshot(),
            pairs,
            service: locked(&self.service).clone(),
        }
    }

    /// The most recent disagreements, oldest first.
    #[cfg(test)]
    pub fn disagreements(&self) -> Vec<Comparison> {
        locked(&self.disagreements).iter().cloned().collect()
    }

    fn count(&self, c: &Comparison) {
        {
            let mut pairs = locked(&self.pairs);
            let slot = pairs
                .entry((c.operation, c.guest.clone(), c.host.clone()))
                .or_insert(0);
            *slot = slot.saturating_add(1);
        }
        match c.agreement {
            AgreementCode::Agree => {}
            AgreementCode::Disagree => {
                let mut kept = locked(&self.disagreements);
                if kept.len() >= KEPT_DISAGREEMENTS {
                    kept.pop_front();
                }
                kept.push_back(c.clone());
            }
        }
    }

    fn fault(&self) {
        self.faults.fetch_add(1, Ordering::SeqCst);
    }

    fn unreported(&self) {
        self.unreported.fetch_add(1, Ordering::SeqCst);
    }

    fn served(&self, elapsed: Duration) {
        locked(&self.service).record(elapsed);
    }
}

// ── one channel ─────────────────────────────────────────────────────────────

/// The right a host verdict carried, held until the guest's `Shadow` report
/// arrives and then retired.
#[derive(Debug)]
enum Right {
    Decision(DecisionId),
    Approval(ApprovalId),
    Nothing,
}

/// A `Decide` the host answered and is waiting for the guest's report on.
#[derive(Debug)]
struct Pending {
    seq: Seq,
    op: Operation,
    subject: Subject,
    host: Outcome,
    host_detail: &'static str,
    right: Right,
}

/// Why the host closed a channel: protocol faults, bounds, or unavailable policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChannelError {
    /// Shared pod policy was revoked or cannot be trusted after a panic.
    PolicyUnavailable,
    /// The frame's number was not the one the host expected.
    Sequence(SeqError),
    /// The bytes were not a frame.
    Frame(FrameError),
    /// The ledger refused (bounds, or an id it did not issue).
    Ledger(LedgerError),
    /// The host could not encode its own answer.
    Encode(EncodeError),
    /// A `Decide` whose digest is not the digest of its operation and subject.
    DigestMismatch,
    /// A second `Decide` before the first was reported on.
    Unreported { pending: Seq },
    /// A `Shadow` report for a `Decide` the host is not waiting on.
    NotPending { decided: Seq },
    /// An approval the host refused came back still pending.
    ApprovalUnsettled,
    /// The guest stalled halfway through a frame.
    Stalled,
    /// The connection failed mid-frame.
    Io(std::io::ErrorKind),
}

impl From<SeqError> for ChannelError {
    fn from(e: SeqError) -> Self {
        ChannelError::Sequence(e)
    }
}
impl From<FrameError> for ChannelError {
    fn from(e: FrameError) -> Self {
        ChannelError::Frame(e)
    }
}
impl From<LedgerError> for ChannelError {
    fn from(e: LedgerError) -> Self {
        ChannelError::Ledger(e)
    }
}
impl From<EncodeError> for ChannelError {
    fn from(e: EncodeError) -> Self {
        ChannelError::Encode(e)
    }
}

/// What one guest frame produced: the bytes to send back, and the comparison
/// when the frame was a `Shadow` report.
#[derive(Debug)]
pub(crate) struct Step {
    pub reply: Vec<u8>,
    pub compared: Option<Comparison>,
}

/// Policy history belongs to the pod, not to a guest-selected connection.
/// Access is serialized with observation and decision in one critical section.
pub(crate) struct PodPolicy {
    kernel: Kernel,
    budget: crate::pod_authority::budget::SharedBudget,
    taint: HostTaint,
    approvals: effects::Approvals,
    evidence: evidence::Evidence,
    revoked: tokio::sync::watch::Sender<bool>,
}

/// One policy history shared by the decision and credential listeners.
pub(crate) type SharedPodPolicy = Arc<Mutex<PodPolicy>>;

/// Restoring a certificate does not restore observations or spent runtime budget.
pub(crate) enum PolicyHistory {
    Fresh,
    Live(SharedPodPolicy),
    UnavailableAfterRestart,
}

impl PodPolicy {
    fn ensure_live(&self) -> Result<(), ChannelError> {
        if *self.revoked.borrow() {
            Err(ChannelError::PolicyUnavailable)
        } else {
            Ok(())
        }
    }

    pub(crate) fn revoke(policy: &SharedPodPolicy) {
        let state = policy
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.revoked.send_replace(true);
    }

    pub(crate) fn revocation(
        policy: &SharedPodPolicy,
    ) -> Result<tokio::sync::watch::Receiver<bool>, ChannelError> {
        let state = policy.lock().map_err(|_| ChannelError::PolicyUnavailable)?;
        state.ensure_live()?;
        Ok(state.revoked.subscribe())
    }

    pub(crate) fn available(policy: &SharedPodPolicy) -> Result<(), ChannelError> {
        policy
            .lock()
            .map_err(|_| ChannelError::PolicyUnavailable)?
            .ensure_live()
    }

    #[cfg(test)]
    pub(crate) fn new(kernel: Kernel, evidence: evidence::Evidence) -> SharedPodPolicy {
        let budget = crate::pod_authority::budget::SharedBudget::memory(
            portcullis::BudgetLedger::for_parent(&kernel.effective().budget),
        );
        Self::with_budget(
            kernel,
            evidence,
            budget,
            effects::ApprovalTiming::HUMAN,
            HostTaint::clean(),
        )
    }

    pub(crate) fn with_budget(
        kernel: Kernel,
        evidence: evidence::Evidence,
        budget: crate::pod_authority::budget::SharedBudget,
        approval_timing: effects::ApprovalTiming,
        // Where the label starts: `StartingLabel::taint`, the join of what the
        // host put into the cell (ADR 0014 §3). Only `observe_response`, an
        // `Observe` and a verified declassification move it afterwards.
        taint: HostTaint,
    ) -> SharedPodPolicy {
        Arc::new(Mutex::new(Self {
            kernel,
            budget,
            taint,
            approvals: effects::Approvals::new(approval_timing),
            evidence,
            revoked: tokio::sync::watch::channel(false).0,
        }))
    }

    /// Record host-delivered external content before making it visible to the
    /// guest. A guest report is not needed and cannot undo this observation.
    pub(crate) fn observe_response(policy: &SharedPodPolicy, now: u64) -> Result<(), ChannelError> {
        let mut policy = policy.lock().map_err(|_| ChannelError::PolicyUnavailable)?;
        policy.ensure_live()?;
        policy
            .taint
            .raise(nucleus_decision_protocol::LabelRaise::new(
                nucleus_decision_protocol::IFCLabel::web_content(now),
            ));
        Ok(())
    }

    pub(crate) fn decide(
        &mut self,
        op: Operation,
        subject: &str,
    ) -> (
        portcullis::kernel::Decision,
        Option<portcullis::kernel::DecisionToken>,
    ) {
        // A taint hold matters only to an effect an approval can release
        // (`effects`); a shadowed decision compares the verdict alone.
        let portcullis::kernel::EffectDecision {
            decision,
            token,
            hold: _,
        } = self.decide_effect(op, subject);
        (decision, token)
    }

    /// Every host decision, shadowed or enforced, comes out of
    /// `decide_effect_with_flow` — the entry the guest's broker submission
    /// calls too (#3255). It decides every operation but a push or a pull
    /// request exactly as `decide_term_with_flow`, which the guest's tool
    /// calls use, so the shadow channel compares like with like.
    pub(crate) fn decide_effect(
        &mut self,
        op: Operation,
        subject: &str,
    ) -> portcullis::kernel::EffectDecision {
        // The kernel's budget is a derived projection, never an independent
        // spending counter. Missing budget state projects to exhausted.
        let max = self.kernel.effective().budget.max_cost_usd;
        let available = self
            .budget
            .available()
            .unwrap_or(rust_decimal::Decimal::ZERO)
            .min(max);
        self.kernel.refund(self.kernel.consumed_usd());
        let _ = self.kernel.charge(max - available);
        self.kernel
            .decide_effect_with_flow(ActionTerm::from_operation(op, subject), Some(&self.taint))
    }
}

#[cfg(test)]
pub(crate) fn test_policy(policy: portcullis::PermissionLattice) -> SharedPodPolicy {
    PodPolicy::new(Kernel::new(policy), evidence::Evidence::memory())
}

/// One decision channel's host state. See the module docs.
pub(crate) struct Channel {
    pod: Uuid,
    gate: SeqGate,
    ledger: DecisionLedger,
    policy: SharedPodPolicy,
    pending: Option<Pending>,
}

impl std::fmt::Debug for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Channel")
            .field("pod", &self.pod)
            .field("epoch", &self.ledger.epoch())
            .finish_non_exhaustive()
    }
}

impl Channel {
    /// Isolated policy state for unit tests; production opens from PodDecide.
    #[cfg(test)]
    pub fn open(pod: Uuid, kernel: Kernel, epoch: u64) -> Self {
        Self::with_policy(
            pod,
            PodPolicy::new(kernel, evidence::Evidence::memory()),
            epoch,
        )
    }

    fn with_policy(pod: Uuid, policy: SharedPodPolicy, epoch: u64) -> Self {
        Self {
            pod,
            gate: SeqGate::new(),
            ledger: DecisionLedger::new(epoch),
            policy,
            pending: None,
        }
    }

    /// The epoch this channel's ids carry.
    #[cfg(test)]
    pub fn epoch(&self) -> u64 {
        self.ledger.epoch()
    }

    /// The host's shared pod taint, snapshotted for tests.
    #[cfg(test)]
    pub fn taint(&self) -> HostTaint {
        self.policy.lock().expect("healthy policy").taint.clone()
    }

    /// Spend a decision id against this channel's ledger. By value: the
    /// ledger forgets a spent id, so a second presentation — a copy decoded
    /// from the same bytes — is `Retired`, and an id from another channel is
    /// `ForeignEpoch`.
    pub fn spend(
        &mut self,
        id: DecisionId,
        digest: nucleus_decision_protocol::ArgsDigest,
    ) -> Result<Spent, LedgerError> {
        self.ledger.consume(id, digest)
    }

    /// Answer one guest frame.
    pub fn step(&mut self, frame: GuestFrame) -> Result<Step, ChannelError> {
        PodPolicy::available(&self.policy)?;
        self.gate.admit(frame.seq())?;
        match frame {
            GuestFrame::Decide {
                seq,
                op,
                subject,
                args_digest: digest,
            } => self.decide(seq, op, subject, digest),
            GuestFrame::Observe { seq, label_raise } => {
                self.policy
                    .lock()
                    .map_err(|_| ChannelError::PolicyUnavailable)?
                    .taint
                    .raise(label_raise);
                Ok(Step {
                    reply: HostFrame::Observed { seq }.encode()?,
                    compared: None,
                })
            }
            GuestFrame::Redeem { seq, approval_id } => {
                // No host approver exists in shadow mode, and every approval is
                // retired at its `Shadow` report, so this is `ApprovalUnknown`
                // in practice. The other arms answer what the ledger says.
                let verdict = match self.ledger.redeem(approval_id) {
                    Ok(Redemption::Granted(decision_id)) => Verdict::Allowed { decision_id },
                    Ok(Redemption::Refused) => Verdict::Denied {
                        reason: DenyReason::ApprovalRefused,
                    },
                    Ok(Redemption::Pending(approval_id)) => {
                        Verdict::ApprovalRequired { approval_id }
                    }
                    Err(_) => Verdict::Denied {
                        reason: DenyReason::ApprovalUnknown,
                    },
                };
                Ok(Step {
                    reply: HostFrame::Verdict { seq, verdict }.encode()?,
                    compared: None,
                })
            }
            GuestFrame::Shadow {
                seq,
                decided,
                local,
            } => self.compare(seq, decided, local),
        }
    }

    fn decide(
        &mut self,
        seq: Seq,
        op: Operation,
        subject: Subject,
        digest: nucleus_decision_protocol::ArgsDigest,
    ) -> Result<Step, ChannelError> {
        if let Some(p) = &self.pending {
            return Err(ChannelError::Unreported { pending: p.seq });
        }
        if digest != args_digest(op, &subject) {
            return Err(ChannelError::DigestMismatch);
        }
        // The guest's tool calls decide with `decide_term_with_flow` and its
        // broker submissions with `decide_effect_with_flow`; the two differ
        // only for a push or a pull request, which only a broker submission
        // decides, so the host's `decide_effect_with_flow` matches both.
        let (decision, token) = {
            let mut policy = self
                .policy
                .lock()
                .map_err(|_| ChannelError::PolicyUnavailable)?;
            policy.ensure_live()?;
            policy.decide(op, subject.as_str())
        };
        // The host performs nothing in shadow mode; the token authorizes I/O
        // nobody will do.
        drop(token);
        let host = outcome_of(&decision.verdict);
        let host_detail = kernel_detail(&decision.verdict);
        let verdict = match host {
            Outcome::Allowed => Verdict::Allowed {
                decision_id: self.ledger.allow(digest)?,
            },
            Outcome::Denied { reason } => Verdict::Denied { reason },
            Outcome::ApprovalRequired => Verdict::ApprovalRequired {
                approval_id: self.ledger.require_approval(digest)?,
            },
        };
        let frame = HostFrame::Verdict { seq, verdict };
        let reply = frame.encode()?;
        // Encoded from a borrow; the id itself stays with the host until the
        // guest reports, then is retired.
        let right = match frame {
            HostFrame::Verdict {
                seq: _,
                verdict: Verdict::Allowed { decision_id },
            } => Right::Decision(decision_id),
            HostFrame::Verdict {
                seq: _,
                verdict: Verdict::ApprovalRequired { approval_id },
            } => Right::Approval(approval_id),
            HostFrame::Verdict {
                seq: _,
                verdict: Verdict::Denied { reason: _ },
            }
            | HostFrame::Observed { seq: _ }
            | HostFrame::Compared {
                seq: _,
                agreement: _,
            } => Right::Nothing,
        };
        self.pending = Some(Pending {
            seq,
            op,
            subject,
            host,
            host_detail,
            right,
        });
        Ok(Step {
            reply,
            compared: None,
        })
    }

    fn compare(&mut self, seq: Seq, decided: Seq, local: Outcome) -> Result<Step, ChannelError> {
        let p = match self.pending.take() {
            Some(p) if p.seq == decided => p,
            Some(p) => {
                self.pending = Some(p);
                return Err(ChannelError::NotPending { decided });
            }
            None => return Err(ChannelError::NotPending { decided }),
        };
        let Pending {
            seq: decide_seq,
            op,
            subject,
            host,
            host_detail,
            right,
        } = p;
        let agreement = Agreement::of(host, local);
        let retired_decision = self.retire(right, args_digest(op, &subject))?;
        let compared = Comparison {
            pod: self.pod,
            epoch: self.ledger.epoch(),
            decided: decide_seq.get(),
            operation: portcullis::grant_usage::operation_name(op),
            subject: subject.as_str().to_string(),
            guest: outcome_code(local),
            host: outcome_code(host),
            host_detail,
            retired_decision,
            agreement: agreement.into(),
        };
        Ok(Step {
            reply: HostFrame::Compared { seq, agreement }.encode()?,
            compared: Some(compared),
        })
    }

    /// Retire the right a verdict carried. Nothing in shadow mode acts on it,
    /// and an approval has no host approver yet, so it is refused and redeemed
    /// to nothing.
    fn retire(
        &mut self,
        right: Right,
        digest: nucleus_decision_protocol::ArgsDigest,
    ) -> Result<Option<u64>, ChannelError> {
        match right {
            Right::Nothing => Ok(None),
            Right::Decision(id) => Ok(Some(self.spend(id, digest)?.decision())),
            Right::Approval(id) => {
                self.ledger.refuse(id.number())?;
                match self.ledger.redeem(id)? {
                    Redemption::Refused => Ok(None),
                    Redemption::Granted(d) => Ok(Some(self.spend(d, digest)?.decision())),
                    Redemption::Pending(_) => Err(ChannelError::ApprovalUnsettled),
                }
            }
        }
    }
}

// ── serving ─────────────────────────────────────────────────────────────────

/// Read one guest frame. `Ok(None)` is the guest closing between frames.
async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Option<GuestFrame>, ChannelError> {
    let mut prefix = [0u8; LEN_PREFIX];
    match r.read_exact(&mut prefix).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(ChannelError::Io(e.kind())),
    }
    // Bounded before a body byte is buffered.
    let len = body_len(prefix)?;
    let mut body = vec![0u8; len];
    match tokio::time::timeout(FRAME_DEADLINE, r.read_exact(&mut body)).await {
        Ok(Ok(_)) => Ok(Some(GuestFrame::decode_body(&body)?)),
        Ok(Err(e)) => Err(ChannelError::Io(e.kind())),
        Err(_) => Err(ChannelError::Stalled),
    }
}

/// Where one pod's comparisons go.
#[derive(Debug, Clone)]
pub(crate) struct Recorder {
    pub tally: Arc<ShadowTally>,
    /// The append-only file disagreements are written to; `None` keeps them in
    /// memory only (tests).
    pub log: Option<PathBuf>,
}

impl Recorder {
    async fn record(&self, c: Comparison) {
        self.tally.count(&c);
        if c.agreement == AgreementCode::Disagree {
            tracing::warn!(
                pod = %c.pod,
                epoch = c.epoch,
                operation = c.operation,
                subject = %c.subject,
                guest = %c.guest,
                host = %c.host,
                host_detail = c.host_detail,
                "host-decide shadow: the host's verdict differs from the one the guest enforced"
            );
            if let Some(path) = &self.log {
                match serde_json::to_string(&c) {
                    Ok(line) => {
                        if let Err(e) =
                            nucleus_jsonl::append_line_unsynced_async(path.clone(), line).await
                        {
                            tracing::warn!(error = %e, "host-decide disagreement not written");
                        }
                    }
                    Err(e) => tracing::warn!(error = %e, "host-decide disagreement not encoded"),
                }
            }
        }
    }
}

/// A channel being served. Whatever ends the serving — the guest closing, a
/// fault, or the listener's shutdown dropping the task mid-await — a `Decide`
/// the host answered and the guest never reported on is counted as
/// unreported when this is dropped. Counted in `Drop` because a shutdown
/// cancels the serving future and no code after an `.await` would run.
struct Served<'a> {
    channel: Channel,
    tally: &'a ShadowTally,
}

impl Drop for Served<'_> {
    fn drop(&mut self) {
        if self.channel.pending.is_some() {
            self.tally.unreported();
        }
    }
}

/// Serve one channel until the guest closes it or breaks the protocol.
pub(crate) async fn serve_channel<S>(
    stream: S,
    channel: Channel,
    recorder: &Recorder,
) -> Result<(), ChannelError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut r, mut w) = tokio::io::split(stream);
    let mut served = Served {
        channel,
        tally: &recorder.tally,
    };
    loop {
        let frame = match read_frame(&mut r).await {
            Ok(Some(f)) => f,
            Ok(None) => return Ok(()),
            Err(e) => {
                recorder.tally.fault();
                return Err(e);
            }
        };
        // Service time is a `Decide`'s: the one exchange an authoritative
        // guest will wait on (ADR 0014 §8).
        let decide = matches!(
            frame,
            GuestFrame::Decide {
                seq: _,
                op: _,
                subject: _,
                args_digest: _
            }
        );
        let arrived = std::time::Instant::now();
        let step = match served.channel.step(frame) {
            Ok(s) => s,
            Err(e) => {
                recorder.tally.fault();
                return Err(e);
            }
        };
        if let Some(c) = step.compared {
            recorder.record(c).await;
        }
        if let Err(e) = w.write_all(&step.reply).await {
            return Err(ChannelError::Io(e.kind()));
        }
        if decide {
            recorder.tally.served(arrived.elapsed());
        }
    }
}

/// Everything a pod's listener opens channels with.
#[derive(Clone)]
pub(crate) struct PodDecide {
    pub pod: Uuid,
    pub authority: Arc<crate::pod_authority::PodAuthority>,
    policy: SharedPodPolicy,
    pub epochs: Arc<EpochSource>,
    pub recorder: Recorder,
}

impl std::fmt::Debug for PodDecide {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PodDecide")
            .field("pod", &self.pod)
            .field("tally", &self.recorder.tally.snapshot())
            .finish_non_exhaustive()
    }
}

impl PodDecide {
    /// Verify once to initialize the pod's durable-in-memory policy history.
    async fn new(
        pod: Uuid,
        authority: Arc<crate::pod_authority::PodAuthority>,
        epochs: Arc<EpochSource>,
        recorder: Recorder,
    ) -> Result<Self, crate::pod_authority::HostKernelError> {
        let policy = authority.host_policy(pod).await?;
        Ok(Self {
            pod,
            authority,
            epochs,
            recorder,
            policy,
        })
    }

    /// Reverify admission and give the channel fresh protocol bookkeeping.
    /// The resulting kernel is discarded: reopening must not reset policy history.
    async fn open(&self) -> Result<Channel, String> {
        self.authority
            .host_kernel(self.pod)
            .await
            .map_err(|e| e.to_string())?;
        let epoch = self
            .epochs
            .next()
            .map_err(|EpochsExhausted| "the node has no decision epochs left".to_string())?;
        Ok(Channel::with_policy(
            self.pod,
            Arc::clone(&self.policy),
            epoch,
        ))
    }
}

/// Accept channels until `shutdown`. Connection tasks live in a `JoinSet` the
/// serving task owns, so stopping the listener stops every channel too — a
/// listener shutdown that only stopped ACCEPTING is the defect #2930 fixed in
/// the workload API bridge.
pub(crate) async fn serve_pod(
    listener: tokio::net::UnixListener,
    pod: PodDecide,
    shutdown: impl std::future::Future<Output = ()>,
) {
    let mut channels = tokio::task::JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                // Abort every channel AND wait for each to be dropped, so a
                // `Decide` left unreported is counted before the teardown
                // report is read.
                channels.shutdown().await;
                return;
            }
            Some(_) = channels.join_next(), if !channels.is_empty() => {}
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                if channels.len() >= MAX_CHANNELS_PER_POD {
                    pod.recorder.tally.fault();
                    drop(stream);
                    continue;
                }
                let pod = pod.clone();
                channels.spawn(async move {
                    match pod.open().await {
                        Ok(channel) => {
                            if let Err(e) = serve_channel(stream, channel, &pod.recorder).await {
                                tracing::warn!(pod = %pod.pod, error = ?e, "host-decide channel closed by the host");
                            }
                        }
                        Err(e) => {
                            pod.recorder.tally.fault();
                            tracing::warn!(pod = %pod.pod, error = %e, "host-decide channel not opened");
                        }
                    }
                });
            }
        }
    }
}

/// A running decision listener, owned by the pod it serves.
pub(crate) struct DecideListener {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
    socket_path: PathBuf,
    tally: Arc<ShadowTally>,
}

impl std::fmt::Debug for DecideListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecideListener")
            .field("socket_path", &self.socket_path)
            .field("tally", &self.tally.snapshot())
            .finish()
    }
}

impl DecideListener {
    /// Bind the pod's decision socket (Firecracker's guest-initiated path for
    /// the inventory's `VsockListener::DecisionChannel`) and serve it.
    pub fn start(
        uds_path: &Path,
        pod: PodDecide,
        jail_owner: Option<(u32, u32)>,
    ) -> std::io::Result<Self> {
        let (listener, socket_path) = crate::guest_socket::bind_guest_listener(
            uds_path,
            nucleus_ifc_kernel::VsockListener::DecisionChannel,
            jail_owner,
        )?;
        let tally = Arc::clone(&pod.recorder.tally);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(serve_pod(listener, pod, async {
            let _ = rx.await;
        }));
        Ok(Self {
            shutdown: Some(tx),
            task,
            socket_path,
            tally,
        })
    }

    /// Where the guest connects.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// This pod's counters.
    #[cfg(test)]
    pub fn tally(&self) -> Arc<ShadowTally> {
        Arc::clone(&self.tally)
    }

    /// Stop every channel, unlink the socket, and hand back what was measured.
    pub async fn shutdown(mut self) -> TeardownReport {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if tokio::time::timeout(Duration::from_secs(2), &mut self.task)
            .await
            .is_err()
        {
            self.task.abort();
        }
        let _ = tokio::fs::remove_file(&self.socket_path).await;
        self.tally.report()
    }
}

/// Start a pod's shadow decision service.
///
/// `None` when the pod holds no certificate from this node (there is nothing
/// to build the host's kernel from) or the socket cannot be bound. Shadow mode
/// never fails a launch: nothing the guest does depends on this socket yet.
#[cfg(target_os = "linux")]
pub(crate) async fn start_for_pod(
    state: &crate::NodeState,
    pod: Uuid,
    vsock_path: &Path,
    pod_dir: &Path,
    jail_owner: Option<(u32, u32)>,
) -> Option<DecideListener> {
    let decide = match PodDecide::new(
        pod,
        Arc::clone(&state.authority),
        Arc::clone(&state.decision_epochs),
        Recorder {
            tally: Arc::new(ShadowTally::default()),
            log: Some(pod_dir.join(DISAGREEMENT_LOG)),
        },
    )
    .await
    {
        Ok(decide) => decide,
        Err(e) => {
            tracing::info!(pod = %pod, reason = %e, "host-decide shadow not started");
            return None;
        }
    };
    match DecideListener::start(vsock_path, decide, jail_owner) {
        Ok(l) => {
            tracing::info!(pod = %pod, socket = %l.socket_path().display(), "host-decide shadow listening");
            Some(l)
        }
        Err(e) => {
            tracing::warn!(pod = %pod, error = %e, "host-decide shadow socket not created");
            None
        }
    }
}

/// Print a pod's teardown report: the counts as numeric fields, the pairs and
/// service times as JSON in the same line, all read back by
/// `cargo xtask host-decide-agreement` through
/// `nucleus_spec::host_decide_telemetry::HostTeardown` (ADR 0014 S1).
pub(crate) fn log_teardown(pod_dir: &Path, report: TeardownReport) {
    let TeardownReport {
        tally:
            TallySnapshot {
                agree,
                disagree,
                faults,
                unreported,
            },
        pairs,
        service,
    } = report;
    // Plain strings and integers: encoding cannot fail, and if it ever did the
    // reader refuses the line rather than read it as zero.
    let pairs = serde_json::to_string(&pairs).unwrap_or_default();
    let service = serde_json::to_string(&service).unwrap_or_default();
    tracing::info!(
        pod_dir = %pod_dir.display(),
        agree,
        disagree,
        faults,
        unreported,
        pairs = %pairs,
        service = %service,
        "{}",
        nucleus_spec::host_decide_telemetry::TEARDOWN_MESSAGE
    );
}

#[cfg(test)]
#[path = "host_decide_tests.rs"]
mod tests;
