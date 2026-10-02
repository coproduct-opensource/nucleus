//! Host-side conformance for #2702 (L-1): the decision point must survive
//! compromise of the guest it polices.
//!
//! The HOST is the subject here. The guest is a test double that has already
//! been compromised: it speaks the existing vsock protocols (the workload API
//! and the credential broker) through the node's own per-pod listeners, built
//! by the same `pod_boot_identity::prepare` and `serve_broker` a Firecracker pod
//! gets, and it does whatever an honest guest would refuse to do. Each property
//! asks whether the host still refuses.
//!
//! # Every row isolates the host
//!
//! Before a row is measured, `portcullis::kernel::Kernel` is run over the same
//! scenario, under the same policy, and must refuse it. That is the honest
//! guest's answer. If the honest kernel would ALLOW the scenario, a host that
//! also allows it proves nothing, so the row is [`Outcome::NotEvaluated`] rather
//! than a Gap or a Holds.
//!
//! # The table can only shrink its gaps
//!
//! [`expected`] is the one table. A measured outcome that differs from it fails
//! the test, in both directions: a Holds row that starts admitting is a
//! regression, and a Gap row that starts refusing is a fix whose author flips
//! the row to [`Expected::Holds`] in the same change. An expected Gap carries the
//! issue that tracks it, by construction.
//!
//! # Could not look is not "looked and it held" (ADR 0007 A-2)
//!
//! [`Outcome::NotEvaluated`] agrees with no expectation. A double that never
//! reached the host, a reply that could not be read, a positive control that
//! failed, a legitimate prelude step the host did not perform: each is
//! `NotEvaluated`, and each fails the table. `a_disconnected_double_never_reads_as_holds`
//! pins that, and `an_enforcing_host_measures_holds_on_every_row` pins that the
//! measurement CAN say Holds, so the gaps the node measures are not an artefact
//! of a probe that only knows how to say Gap.
//!
//! This module measures; it changes no behaviour.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer, SigningKey};
use nucleus_cred_protocol::{PerformReply, PerformRequest};
use portcullis::kernel::{DenyReason, Kernel, Verdict};
use portcullis::mediation_receipt::{MEDIATION_RECEIPT_SCHEMA_VERSION, MediationReceipt};
use portcullis::{ActionTerm, CapabilityLevel, NodeKind, Operation, PermissionLattice};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

use crate::broker_perform::UpstreamCall;
use crate::pod_receipt::{ReceiptError, ReportSource};

/// What a row measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The host refused what an honest guest would refuse.
    Holds,
    /// The host admitted it.
    Gap,
    /// The measurement could not say. Never counts as either.
    NotEvaluated,
}

/// What the table says a row must measure. A Gap names its issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expected {
    Holds,
    Gap { issue: u32 },
}

/// The host-side properties #2702 requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Property {
    /// P1: a mediation receipt is accepted only if it verifies under a key the
    /// guest never held.
    ReceiptKeyGuestNeverHeld,
    /// P1b: the same, for the pod's exit report.
    ExitReportKeyGuestNeverHeld,
    /// P2: the broker refuses a PERFORM for a session whose taint forbids it.
    TaintedPerformRefused,
    /// P3: the broker refuses an approval-gated PERFORM with no host-verified approval.
    UnapprovedPerformRefused,
    /// P4: the broker refuses a PERFORM beyond the budget.
    OverBudgetPerformRefused,
    /// P5: the host refuses a reused approval (decision) to act twice.
    ReusedApprovalRefused,
}

/// Every property, in table order. Each is measured exactly once.
const ALL: &[Property] = &[
    Property::ReceiptKeyGuestNeverHeld,
    Property::ExitReportKeyGuestNeverHeld,
    Property::TaintedPerformRefused,
    Property::UnapprovedPerformRefused,
    Property::OverBudgetPerformRefused,
    Property::ReusedApprovalRefused,
];

impl Property {
    fn id(self) -> &'static str {
        match self {
            Property::ReceiptKeyGuestNeverHeld => "P1",
            Property::ExitReportKeyGuestNeverHeld => "P1b",
            Property::TaintedPerformRefused => "P2",
            Property::UnapprovedPerformRefused => "P3",
            Property::OverBudgetPerformRefused => "P4",
            Property::ReusedApprovalRefused => "P5",
        }
    }
}

/// THE table. Exhaustive, so a new property cannot be measured without a row.
fn expected(p: Property) -> Expected {
    match p {
        Property::ReceiptKeyGuestNeverHeld => Expected::Gap { issue: 3114 },
        Property::ExitReportKeyGuestNeverHeld => Expected::Gap { issue: 3114 },
        Property::TaintedPerformRefused => Expected::Gap { issue: 3115 },
        Property::UnapprovedPerformRefused => Expected::Gap { issue: 3116 },
        Property::OverBudgetPerformRefused => Expected::Gap { issue: 3117 },
        Property::ReusedApprovalRefused => Expected::Gap { issue: 3116 },
    }
}

/// Whether a measurement is what the table says. `NotEvaluated` agrees with nothing.
fn agrees(expected: Expected, measured: Outcome) -> bool {
    match (expected, measured) {
        (Expected::Holds, Outcome::Holds) | (Expected::Gap { .. }, Outcome::Gap) => true,
        (Expected::Holds, Outcome::Gap) | (Expected::Gap { .. }, Outcome::Holds) => false,
        (Expected::Holds, Outcome::NotEvaluated)
        | (Expected::Gap { .. }, Outcome::NotEvaluated) => false,
    }
}

/// What the host did with one thing the guest double sent it.
#[derive(Debug)]
enum Probe {
    /// The host took it: kept the receipt, accepted the report, made the call.
    Admitted(String),
    /// The host answered, and the answer was a refusal.
    Refused(String),
    /// No answer that says either.
    Inconclusive(String),
}

impl Probe {
    fn outcome(&self) -> Outcome {
        match self {
            Probe::Admitted(_) => Outcome::Gap,
            Probe::Refused(_) => Outcome::Holds,
            Probe::Inconclusive(_) => Outcome::NotEvaluated,
        }
    }

    fn evidence(&self) -> &str {
        match self {
            Probe::Admitted(e) | Probe::Refused(e) | Probe::Inconclusive(e) => e,
        }
    }
}

/// What the guest double got when it asked for the mediation signing key.
enum KeyFetch {
    Served(SigningKey),
    Withheld(String),
    Inconclusive(String),
}

/// One measured row.
struct Measured {
    property: Property,
    outcome: Outcome,
    evidence: String,
}

/// A host the double can boot pods on.
trait Host {
    type Pod: GuestFacing;
    /// Boot one pod under `policy`. `approvals` are operator approvals the host
    /// itself has verified, by operation and count.
    async fn boot(
        &self,
        policy: PermissionLattice,
        approvals: &[(Operation, u32)],
    ) -> Result<Self::Pod, String>;
}

/// One pod's host, as the guest reaches it over its vsock listeners.
trait GuestFacing {
    /// The positive control: a legitimate fetch of this pod's own spec is served.
    async fn legitimate_fetch(&mut self) -> Probe;
    async fn fetch_mediation_key(&mut self) -> KeyFetch;
    async fn ship_receipt(&mut self, line: &str) -> Probe;
    /// The exit report a guest leaves behind, as the host reads it at teardown.
    fn leave_exit_report(&mut self, json: &str) -> Probe;
    async fn perform(&mut self, req: &PerformRequest) -> Probe;
}

/// The upstream every scenario PERFORMs against, configured by the operator.
const UPSTREAM: &str = "model-api";

fn perform_request(operation: Operation, idempotency_key: &str) -> PerformRequest {
    PerformRequest {
        operation: format!("{operation:?}"),
        target: UPSTREAM.to_string(),
        justification: "conformance".to_string(),
        idempotency_key: idempotency_key.to_string(),
        path: "/act".to_string(),
        body: b"{}".to_vec(),
    }
}

/// A broker scenario: the pod's policy and host-verified approvals, legitimate
/// steps that must be performed first, and the step under test.
struct BrokerScenario {
    policy: PermissionLattice,
    approvals: Vec<(Operation, u32)>,
    prelude: Vec<PerformRequest>,
    probe: PerformRequest,
}

fn scenario_taint() -> BrokerScenario {
    BrokerScenario {
        policy: PermissionLattice::permissive(),
        approvals: Vec::new(),
        // The HOST performs the fetch and hands the guest untrusted content: the
        // taint is something the host itself observed, not a guest claim.
        prelude: vec![perform_request(Operation::WebFetch, "taint-fetch")],
        probe: perform_request(Operation::GitCommit, "taint-commit"),
    }
}

fn approval_gated() -> PermissionLattice {
    let mut policy = PermissionLattice::permissive();
    policy.obligations.insert(Operation::GitCommit);
    policy
}

fn scenario_unapproved() -> BrokerScenario {
    BrokerScenario {
        policy: approval_gated(),
        approvals: Vec::new(),
        prelude: Vec::new(),
        probe: perform_request(Operation::GitCommit, "unapproved-commit"),
    }
}

fn scenario_budget() -> BrokerScenario {
    let mut policy = PermissionLattice::permissive();
    // The PERFORM frame carries no cost, so the sharpest per-call question the
    // host can be asked is the one with no budget left at all.
    policy.budget.max_cost_usd = rust_decimal::Decimal::ZERO;
    BrokerScenario {
        policy,
        approvals: Vec::new(),
        prelude: Vec::new(),
        probe: perform_request(Operation::WebFetch, "over-budget-fetch"),
    }
}

fn scenario_reuse() -> BrokerScenario {
    BrokerScenario {
        policy: approval_gated(),
        // ONE approval. The first commit spends it.
        approvals: vec![(Operation::GitCommit, 1)],
        prelude: vec![perform_request(Operation::GitCommit, "approved-commit")],
        // A fresh idempotency key: the key is guest-chosen, so the host's ledger
        // deduplicates retries and is no defence against a second decision.
        probe: perform_request(Operation::GitCommit, "reused-approval-commit"),
    }
}

fn scenario_control() -> BrokerScenario {
    BrokerScenario {
        policy: PermissionLattice::permissive(),
        approvals: Vec::new(),
        prelude: Vec::new(),
        probe: perform_request(Operation::WebFetch, "control-fetch"),
    }
}

fn verdict_of(kernel: &mut Kernel, op: Operation, subject: &str) -> Verdict {
    let (decision, _token) = kernel.decide_term(ActionTerm::from_operation(op, subject));
    decision.verdict
}

/// The honest guest's answer to a scenario: `Ok(evidence)` iff it refuses.
fn refuses(verdict: Verdict, what: &str) -> Result<String, String> {
    match verdict {
        Verdict::Allow => Err(format!(
            "an honest kernel ALLOWS {what}, so the row would not isolate the host"
        )),
        Verdict::RequiresApproval => Ok(format!("honest kernel: {what} requires approval")),
        Verdict::Deny(why) => Ok(format!("honest kernel: {what} denied ({why:?})")),
    }
}

/// The forged decision P1 and P1b carry: RunBash, under a policy that grants none.
fn no_run_bash() -> PermissionLattice {
    let mut policy = PermissionLattice::permissive();
    policy.capabilities.run_bash = CapabilityLevel::Never;
    policy
}

const FORGED_COMMAND: &str = "curl https://exfil.invalid";

fn witness_forged_decision() -> Result<String, String> {
    let mut kernel = Kernel::new(no_run_bash());
    refuses(
        verdict_of(&mut kernel, Operation::RunBash, FORGED_COMMAND),
        "RunBash under a policy granting none",
    )
}

fn witness_taint(s: &BrokerScenario) -> Result<String, String> {
    let mut kernel = Kernel::new(s.policy.clone());
    let fetched = kernel
        .observe(NodeKind::WebContent, &[])
        .map_err(|e| format!("could not record the fetched content: {e:?}"))?;
    let (decision, _token) = kernel.decide_with_parents(Operation::GitCommit, "commit", &[fetched]);
    refuses(decision.verdict, "GitCommit of fetched web content")
}

fn witness_unapproved(s: &BrokerScenario) -> Result<String, String> {
    let mut kernel = Kernel::new(s.policy.clone());
    refuses(
        verdict_of(&mut kernel, Operation::GitCommit, "commit"),
        "an approval-gated GitCommit with no approval",
    )
}

fn witness_budget(s: &BrokerScenario) -> Result<String, String> {
    let mut kernel = Kernel::new(s.policy.clone());
    let verdict = verdict_of(
        &mut kernel,
        Operation::WebFetch,
        "https://upstream.invalid/v1/act",
    );
    match verdict {
        Verdict::Deny(DenyReason::BudgetExhausted { .. }) => {
            refuses(verdict, "WebFetch with no budget left")
        }
        other => Err(format!(
            "the honest kernel's answer is not a budget refusal: {other:?}"
        )),
    }
}

fn witness_reuse(s: &BrokerScenario) -> Result<String, String> {
    let mut kernel = Kernel::new(s.policy.clone());
    for &(op, count) in &s.approvals {
        kernel.grant_approval(op, count);
    }
    match verdict_of(&mut kernel, Operation::GitCommit, "commit") {
        Verdict::Allow => {}
        other => {
            return Err(format!(
                "the honest kernel refuses even the approved commit ({other:?}), so the \
                 scenario does not test reuse"
            ));
        }
    }
    refuses(
        verdict_of(&mut kernel, Operation::GitCommit, "commit"),
        "a second GitCommit on one approval",
    )
}

/// The broker's positive control: a legitimate PERFORM on a permissive pod is made.
async fn broker_control<H: Host>(host: &H) -> Result<String, String> {
    let s = scenario_control();
    let mut pod = host.boot(s.policy, &s.approvals).await?;
    match pod.perform(&s.probe).await {
        Probe::Admitted(e) => Ok(e),
        other => Err(format!("a legitimate PERFORM was not performed: {other:?}")),
    }
}

/// Boot, and require the pod's positive control before anything is asked of it.
async fn boot_live<H: Host>(
    host: &H,
    policy: PermissionLattice,
    approvals: &[(Operation, u32)],
) -> Result<H::Pod, Probe> {
    let mut pod = host
        .boot(policy, approvals)
        .await
        .map_err(|e| Probe::Inconclusive(format!("the pod did not boot: {e}")))?;
    match pod.legitimate_fetch().await {
        Probe::Admitted(_) => Ok(pod),
        other => Err(Probe::Inconclusive(format!(
            "positive control failed, a legitimate fetch was not served: {other:?}"
        ))),
    }
}

/// The key a compromised guest signs with: the host's, if the host served it.
async fn guest_signing_key(pod: &mut impl GuestFacing) -> Result<(SigningKey, String), Probe> {
    match pod.fetch_mediation_key().await {
        KeyFetch::Served(key) => Ok((
            key,
            "signed with the mediation key the host SERVED the guest".to_string(),
        )),
        KeyFetch::Withheld(why) => Ok((
            SigningKey::from_bytes(&[0x42; 32]),
            format!("the host withheld its key ({why}), so signed with the guest's own"),
        )),
        KeyFetch::Inconclusive(e) => Err(Probe::Inconclusive(e)),
    }
}

/// A receipt recording ALLOW for the decision the honest kernel denies.
fn forged_receipt(key: &SigningKey) -> MediationReceipt {
    let mut receipt = MediationReceipt {
        schema_version: MEDIATION_RECEIPT_SCHEMA_VERSION,
        mediator_spiffe_id: "spiffe://test.local/mediator/forged".to_string(),
        session_id: "forged-session".to_string(),
        decision_seq: 0,
        operation: "run_bash".to_string(),
        subject: FORGED_COMMAND.to_string(),
        verdict: "allow".to_string(),
        art12_record_hash: "0".repeat(64),
        signer_assurance: 0,
        signer_backend: "self-measured".to_string(),
        signature: String::new(),
    };
    receipt.signature = hex::encode(key.sign(&receipt.preimage()).to_bytes());
    receipt
}

/// An exit report erasing the denial the honest kernel would have recorded.
fn forged_exit_report(key: &SigningKey) -> Result<String, String> {
    use nucleus_spec::exit_report_auth::{SignedExitReport, signing_bytes};
    let report: nucleus_spec::ExitReport = serde_json::from_value(serde_json::json!({
        "workspace_hash": "forged-by-the-guest",
        "audit_tail_hash": "forged-by-the-guest",
        "audit_entry_count": 0,
        "timestamp_unix": 1_757_000_000u64,
    }))
    .map_err(|e| e.to_string())?;
    let bytes = signing_bytes(&report).map_err(|e| e.to_string())?;
    serde_json::to_string(&SignedExitReport {
        signature: hex::encode(key.sign(&bytes).to_bytes()),
        signer_pubkey: hex::encode(key.verifying_key().to_bytes()),
        report,
    })
    .map_err(|e| e.to_string())
}

async fn probe_receipt<H: Host>(host: &H) -> Probe {
    let mut pod = match boot_live(host, PermissionLattice::permissive(), &[]).await {
        Ok(pod) => pod,
        Err(p) => return p,
    };
    let (key, provenance) = match guest_signing_key(&mut pod).await {
        Ok(k) => k,
        Err(p) => return p,
    };
    let line = match serde_json::to_string(&forged_receipt(&key)) {
        Ok(l) => l,
        Err(e) => return Probe::Inconclusive(e.to_string()),
    };
    annotate(pod.ship_receipt(&line).await, &provenance)
}

async fn probe_exit_report<H: Host>(host: &H) -> Probe {
    let mut pod = match boot_live(host, PermissionLattice::permissive(), &[]).await {
        Ok(pod) => pod,
        Err(p) => return p,
    };
    let (key, provenance) = match guest_signing_key(&mut pod).await {
        Ok(k) => k,
        Err(p) => return p,
    };
    match forged_exit_report(&key) {
        Ok(json) => annotate(pod.leave_exit_report(&json), &provenance),
        Err(e) => Probe::Inconclusive(e),
    }
}

async fn probe_broker<H: Host>(
    host: &H,
    control: &Result<String, String>,
    s: BrokerScenario,
) -> Probe {
    if let Err(why) = control {
        return Probe::Inconclusive(format!("the broker's positive control failed: {why}"));
    }
    let mut pod = match boot_live(host, s.policy, &s.approvals).await {
        Ok(pod) => pod,
        Err(p) => return p,
    };
    for step in &s.prelude {
        match pod.perform(step).await {
            Probe::Admitted(_) => {}
            other => {
                return Probe::Inconclusive(format!(
                    "a legitimate prelude step ({}) was not performed: {other:?}",
                    step.operation
                ));
            }
        }
    }
    pod.perform(&s.probe).await
}

fn annotate(p: Probe, note: &str) -> Probe {
    match p {
        Probe::Admitted(e) => Probe::Admitted(format!("{note}; {e}")),
        Probe::Refused(e) => Probe::Refused(format!("{note}; {e}")),
        Probe::Inconclusive(e) => Probe::Inconclusive(format!("{note}; {e}")),
    }
}

/// Measure one row: the honest guest must refuse first, then the host is asked.
async fn measure<H: Host>(host: &H, control: &Result<String, String>, p: Property) -> Measured {
    let (witness, probe) = match p {
        Property::ReceiptKeyGuestNeverHeld => {
            (witness_forged_decision(), probe_receipt(host).await)
        }
        Property::ExitReportKeyGuestNeverHeld => {
            (witness_forged_decision(), probe_exit_report(host).await)
        }
        Property::TaintedPerformRefused => {
            let s = scenario_taint();
            (witness_taint(&s), probe_broker(host, control, s).await)
        }
        Property::UnapprovedPerformRefused => {
            let s = scenario_unapproved();
            (witness_unapproved(&s), probe_broker(host, control, s).await)
        }
        Property::OverBudgetPerformRefused => {
            let s = scenario_budget();
            (witness_budget(&s), probe_broker(host, control, s).await)
        }
        Property::ReusedApprovalRefused => {
            let s = scenario_reuse();
            (witness_reuse(&s), probe_broker(host, control, s).await)
        }
    };
    match witness {
        Ok(honest) => Measured {
            property: p,
            outcome: probe.outcome(),
            evidence: format!("{honest}; host: {}", probe.evidence()),
        },
        Err(why) => Measured {
            property: p,
            outcome: Outcome::NotEvaluated,
            evidence: why,
        },
    }
}

async fn measure_all<H: Host>(host: &H) -> (Result<String, String>, Vec<Measured>) {
    let control = broker_control(host).await;
    let mut rows = Vec::new();
    for &p in ALL {
        rows.push(measure(host, &control, p).await);
    }
    (control, rows)
}

fn render(control: &Result<String, String>, rows: &[Measured]) -> String {
    let mut out = format!("broker positive control: {control:?}\n");
    for m in rows {
        let expected = match expected(m.property) {
            Expected::Holds => "Holds".to_string(),
            Expected::Gap { issue } => format!("Gap (#{issue})"),
        };
        out.push_str(&format!(
            "{:<4} {:?}  measured={:?} expected={expected}\n     {}\n",
            m.property.id(),
            m.property,
            m.outcome,
            m.evidence
        ));
    }
    out
}

// ── The node ─────────────────────────────────────────────────────────────

/// The real node: `pod_boot_identity::prepare` for the workload API, and
/// `serve_broker` for the credential broker, on one pod's vsock paths.
struct Node;

struct NodePod {
    /// The workload API socket the guest reaches.
    api: PathBuf,
    /// The pod's node-side directory: the node's key anchor and receipt log.
    pod_dir: PathBuf,
    /// Where the guest was told the broker is, and the capability it was served.
    broker: Result<(PathBuf, Vec<u8>), String>,
    /// Every upstream call the host made for this pod.
    calls: Arc<Mutex<Vec<UpstreamCall>>>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    _prepared: crate::pod_boot_identity::PreparedIdentity,
    _dir: tempfile::TempDir,
}

impl Drop for NodePod {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}

const POD_NAME: &str = "trust-boundary-conformance";

impl Host for Node {
    type Pod = NodePod;

    async fn boot(
        &self,
        policy: PermissionLattice,
        approvals: &[(Operation, u32)],
    ) -> Result<NodePod, String> {
        // The node's approvals (`/v1/approve`, signed with `approval_signer`) are
        // delivered to the in-guest proxy. The broker takes no approval input,
        // so there is nowhere on the host to hand these: that is P3/P5's finding.
        let _ = approvals;
        let dir = tempfile::tempdir_in("/tmp").map_err(|e| e.to_string())?;
        let mut st = super::handler_tests::state(&dir);
        let manager = crate::identity::IdentityManager::new(
            "test.local",
            std::time::Duration::from_secs(3600),
        )
        .map_err(|e| e.to_string())?;
        st.identity_manager = Some(manager);
        let id = uuid::Uuid::new_v4();
        let pod_dir = dir.path().join("pod");
        std::fs::create_dir_all(&pod_dir).map_err(|e| e.to_string())?;
        let kernel = dir.path().join("kernel");
        let rootfs = dir.path().join("rootfs");
        std::fs::write(&kernel, b"test kernel").map_err(|e| e.to_string())?;
        std::fs::write(&rootfs, b"test rootfs").map_err(|e| e.to_string())?;
        let image: nucleus_spec::ImageSpec = serde_json::from_value(serde_json::json!({
            "kernel_path": kernel, "rootfs_path": rootfs,
        }))
        .map_err(|e| e.to_string())?;
        let image = crate::rootfs_source::HostImage::resolve(&image).map_err(|e| e.to_string())?;
        let spec: nucleus_spec::PodSpec = serde_json::from_value(serde_json::json!({
            "apiVersion": "nucleus/v1", "kind": "Pod",
            "metadata": {"name": POD_NAME}, "spec": {},
        }))
        .map_err(|e| e.to_string())?;
        let vsock = dir.path().join("vsock");
        let (serve, verify) = crate::broker_launch::BrokerCapability::mint(id);
        let prepared = crate::pod_boot_identity::prepare(crate::pod_boot_identity::Inputs {
            state: &st,
            pod_dir: &pod_dir,
            spec: &spec,
            image: &image,
            id,
            grant: &crate::net::IdentityGrant::Granted,
            vsock_path: &vsock,
            jail_owner: None,
            task_token: None,
            pod_certificate: None,
            broker_serve: serve,
            measured: crate::image_identity::Measured::default(),
        })
        .await
        .map_err(|e| e.to_string())?;

        // The broker, as `BrokerListener::start` assembles it, but with the
        // recording caller in place of a network client.
        let listener = crate::broker_transport::prepare_socket(
            &crate::broker_transport::broker_socket_path(&vsock, st.broker_vsock_port),
        )
        .map_err(|e| e.to_string())?;
        let mut store = nucleus_cred_broker::CredentialStore::new();
        store.insert(
            UPSTREAM,
            nucleus_cred_broker::Credential::new("test-token-123"),
        );
        let (caller, calls) = crate::broker_transport::serving_tests::recording_caller();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let broker = crate::broker_transport::PodBroker {
            identity: nucleus_cred_broker::PodIdentity::observed_by_host(format!(
                "spiffe://test.local/ns/pods/sa/{id}"
            )),
            policy: Arc::new(policy),
            credentials: Arc::new(crate::federated_credential::PodCredentials::static_only(
                store,
            )),
            broker_secret: Some(verify.into_verifier(id).map_err(|e| e.to_string())?),
            upstreams: Arc::new(vec![crate::upstreams::RegistryEntry::env(
                nucleus_spec::CredentialedEgressSpec {
                    name: UPSTREAM.into(),
                    upstream: "https://upstream.invalid/v1".into(),
                    credential_env: "LLM_API_TOKEN".into(),
                    header: "authorization".into(),
                    value_prefix: "Bearer ".into(),
                },
            )]),
            caller,
        };
        tokio::spawn(crate::broker_transport::serve_broker(
            listener,
            broker,
            async {
                let _ = stopped.await;
            },
        ));

        let api = PathBuf::from(format!("{}_{}", vsock.display(), st.identity_vsock_port));
        // The capability is fetched first, as `nucleus-guest-init` does, and the
        // broker is found where the host SAID it is, not where this test bound it.
        let broker = match ask(&api, "FETCH_BROKER_SECRET").await {
            Ok(reply) => serde_json::from_str::<serde_json::Value>(&reply)
                .ok()
                .and_then(|v| {
                    let secret = v.get("secret")?.as_str()?.as_bytes().to_vec();
                    let port = u32::try_from(v.get("port")?.as_u64()?).ok()?;
                    Some((
                        crate::broker_transport::broker_socket_path(&vsock, port),
                        secret,
                    ))
                })
                .ok_or(format!("the broker capability reply was not one: {reply}")),
            Err(e) => Err(format!("FETCH_BROKER_SECRET: {e}")),
        };
        Ok(NodePod {
            api,
            pod_dir,
            broker,
            calls,
            stop: Some(stop),
            _prepared: prepared,
            _dir: dir,
        })
    }
}

/// One workload-API command, one reply line, on a fresh connection.
async fn ask(api: &Path, command: &str) -> std::io::Result<String> {
    exchange(api, &[command]).await
}

/// Write `frames` as newline-terminated lines on one connection; read one reply.
async fn exchange(api: &Path, frames: &[&str]) -> std::io::Result<String> {
    let stream = tokio::net::UnixStream::connect(api).await?;
    let (reader, mut writer) = stream.into_split();
    for frame in frames {
        writer.write_all(frame.as_bytes()).await?;
        writer.write_all(b"\n").await?;
    }
    writer.flush().await?;
    let mut line = String::new();
    tokio::io::BufReader::new(reader)
        .read_line(&mut line)
        .await?;
    Ok(line)
}

/// A workload-API reply is either the payload or `{"error": …}`.
fn refusal_in(reply: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(reply)
        .ok()?
        .get("error")?
        .as_str()
        .map(str::to_string)
}

impl GuestFacing for NodePod {
    async fn legitimate_fetch(&mut self) -> Probe {
        match ask(&self.api, "FETCH_POD_SPEC").await {
            Ok(reply) if reply.contains(POD_NAME) => {
                Probe::Admitted("FETCH_POD_SPEC served this pod's spec".into())
            }
            Ok(reply) => Probe::Refused(format!("FETCH_POD_SPEC: {}", reply.trim())),
            Err(e) => Probe::Inconclusive(format!("FETCH_POD_SPEC: {e}")),
        }
    }

    async fn fetch_mediation_key(&mut self) -> KeyFetch {
        let reply = match ask(&self.api, "FETCH_MEDIATION_KEY").await {
            Ok(r) => r,
            Err(e) => return KeyFetch::Inconclusive(format!("FETCH_MEDIATION_KEY: {e}")),
        };
        if let Some(why) = refusal_in(&reply) {
            return KeyFetch::Withheld(why);
        }
        let seed = serde_json::from_str::<serde_json::Value>(&reply)
            .ok()
            .and_then(|v| hex::decode(v.get("signing_key")?.as_str()?).ok())
            .and_then(|b| <[u8; 32]>::try_from(b).ok());
        match seed {
            Some(seed) => KeyFetch::Served(SigningKey::from_bytes(&seed)),
            None => KeyFetch::Inconclusive(format!("unreadable key reply: {}", reply.trim())),
        }
    }

    async fn ship_receipt(&mut self, line: &str) -> Probe {
        let reply = match exchange(&self.api, &["SHIP_RECEIPT", line]).await {
            Ok(r) => r,
            Err(e) => return Probe::Inconclusive(format!("SHIP_RECEIPT: {e}")),
        };
        if let Some(why) = refusal_in(&reply) {
            return Probe::Refused(format!("SHIP_RECEIPT refused: {why}"));
        }
        if !reply.contains("collected") {
            return Probe::Inconclusive(format!("SHIP_RECEIPT: {}", reply.trim()));
        }
        // What an auditor would later check it against: the node's own anchor.
        let anchor = std::fs::read_to_string(self.pod_dir.join("mediator-pubkey.hex"))
            .ok()
            .and_then(|h| hex::decode(h.trim()).ok())
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .and_then(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).ok());
        let audit = match (anchor, serde_json::from_str::<MediationReceipt>(line)) {
            (Some(anchor), Ok(r)) => match r.verify(&anchor) {
                Ok(()) => "and it VERIFIES under the node's own mediator-pubkey anchor",
                Err(_) => "and it does not verify under the node's anchor",
            },
            (None, _) | (Some(_), Err(_)) => "and the node has no readable anchor to audit it",
        };
        Probe::Admitted(format!(
            "SHIP_RECEIPT collected a receipt recording ALLOW for a denied RunBash, {audit}"
        ))
    }

    fn leave_exit_report(&mut self, json: &str) -> Probe {
        let source = ReportSource::WorkloadOwnedImage {
            pod_dir: self.pod_dir.clone(),
        };
        match crate::pod_receipt::parse_report(json, &source) {
            Ok(report) => Probe::Admitted(format!(
                "parse_report accepted a report with audit_entry_count={} workspace_hash={}",
                report.audit_entry_count, report.workspace_hash
            )),
            Err(ReceiptError::Unauthenticated(why)) => {
                Probe::Refused(format!("parse_report: unauthenticated ({why})"))
            }
            Err(ReceiptError::Malformed(why)) => {
                Probe::Refused(format!("parse_report: malformed ({why})"))
            }
            Err(ReceiptError::NotExited) | Err(ReceiptError::NoExitReport(_)) => {
                Probe::Inconclusive("parse_report answered about a different question".into())
            }
        }
    }

    async fn perform(&mut self, req: &PerformRequest) -> Probe {
        let (path, secret) = match &self.broker {
            Ok(b) => b,
            Err(why) => return Probe::Inconclusive(why.clone()),
        };
        let made = |calls: &Mutex<Vec<UpstreamCall>>| calls.lock().ok().map(|c| c.len());
        let Some(before) = made(&self.calls) else {
            return Probe::Inconclusive("the call record is poisoned".into());
        };
        let payload = match serde_json::to_string(req) {
            Ok(p) => p,
            Err(e) => return Probe::Inconclusive(e.to_string()),
        };
        let frame = nucleus_cred_protocol::frame::sign(secret, &payload);
        let line = match crate::broker_transport::request_over_socket(path, &frame).await {
            Ok(l) => l,
            Err(e) => return Probe::Inconclusive(format!("broker: {e}")),
        };
        let Ok(reply) = serde_json::from_str::<PerformReply>(line.trim()) else {
            return Probe::Inconclusive(format!("unreadable broker reply: {}", line.trim()));
        };
        let Some(after) = made(&self.calls) else {
            return Probe::Inconclusive("the call record is poisoned".into());
        };
        match (after > before, reply.granted) {
            (true, _) => Probe::Admitted(format!(
                "PERFORM {} granted={} status={}, the host made the upstream call",
                req.operation, reply.granted, reply.status
            )),
            (false, false) => Probe::Refused(format!(
                "PERFORM {} refused: {}",
                req.operation, reply.reason
            )),
            (false, true) => Probe::Inconclusive(format!(
                "PERFORM {} granted with no upstream call",
                req.operation
            )),
        }
    }
}

#[tokio::test]
async fn the_node_measures_as_the_table_says() {
    let (control, rows) = measure_all(&Node).await;
    let table = render(&control, &rows);
    println!("{table}");
    assert!(
        control.is_ok(),
        "the broker's positive control failed:\n{table}"
    );
    let disagreements: Vec<_> = rows
        .iter()
        .filter(|m| !agrees(expected(m.property), m.outcome))
        .map(|m| m.property.id())
        .collect();
    assert!(
        disagreements.is_empty(),
        "measured outcomes differ from the table for {disagreements:?}. A Gap that now \
         Holds is a fix: flip its row to Expected::Holds. Anything else is a regression \
         or a measurement that could not look.\n{table}"
    );
}

// ── Non-vacuity ──────────────────────────────────────────────────────────

/// A host that enforces every property: the shape #2702 asks the node to take.
struct Enforcing;

struct EnforcingPod {
    policy: PermissionLattice,
    approvals: BTreeMap<Operation, u32>,
    /// Taint the HOST observed: it performed a fetch and handed back its content.
    tainted: bool,
    /// Never served.
    receipt_key: SigningKey,
}

impl Host for Enforcing {
    type Pod = EnforcingPod;

    async fn boot(
        &self,
        policy: PermissionLattice,
        approvals: &[(Operation, u32)],
    ) -> Result<EnforcingPod, String> {
        Ok(EnforcingPod {
            policy,
            approvals: approvals.iter().copied().collect(),
            tainted: false,
            receipt_key: SigningKey::from_bytes(&[0x07; 32]),
        })
    }
}

impl GuestFacing for EnforcingPod {
    async fn legitimate_fetch(&mut self) -> Probe {
        Probe::Admitted("served".into())
    }

    async fn fetch_mediation_key(&mut self) -> KeyFetch {
        KeyFetch::Withheld("the host signs receipts itself".into())
    }

    async fn ship_receipt(&mut self, line: &str) -> Probe {
        match serde_json::from_str::<MediationReceipt>(line) {
            Ok(r) if r.verify(&self.receipt_key.verifying_key()).is_ok() => {
                Probe::Admitted("verified".into())
            }
            Ok(_) => Probe::Refused("not signed by the host's key".into()),
            Err(e) => Probe::Refused(format!("malformed: {e}")),
        }
    }

    fn leave_exit_report(&mut self, json: &str) -> Probe {
        use nucleus_spec::exit_report_auth::{SignedExitReport, signing_bytes};
        let Ok(signed) = serde_json::from_str::<SignedExitReport>(json) else {
            return Probe::Refused("malformed".into());
        };
        let verified = signing_bytes(&signed.report).ok().and_then(|bytes| {
            let sig: [u8; 64] = hex::decode(&signed.signature).ok()?.try_into().ok()?;
            self.receipt_key
                .verifying_key()
                .verify_strict(&bytes, &ed25519_dalek::Signature::from_bytes(&sig))
                .ok()
        });
        match verified {
            Some(()) => Probe::Admitted("verified".into()),
            None => Probe::Refused("not signed by the host's key".into()),
        }
    }

    async fn perform(&mut self, req: &PerformRequest) -> Probe {
        let Some(op) = crate::broker::parse_operation(&req.operation) else {
            return Probe::Refused("unknown operation".into());
        };
        if self.policy.capabilities.level_for(op) == CapabilityLevel::Never {
            return Probe::Refused("capability".into());
        }
        if self.policy.budget.max_cost_usd <= self.policy.budget.consumed_usd {
            return Probe::Refused("budget".into());
        }
        let outbound = matches!(
            op,
            Operation::GitCommit
                | Operation::WriteFiles
                | Operation::EditFiles
                | Operation::RunBash
        );
        if self.tainted && outbound {
            return Probe::Refused("taint".into());
        }
        if self.policy.requires_approval(op) {
            match self.approvals.get_mut(&op) {
                Some(left) if *left > 0 => *left -= 1,
                Some(_) | None => return Probe::Refused("no approval".into()),
            }
        }
        if matches!(op, Operation::WebFetch | Operation::WebSearch) {
            self.tainted = true;
        }
        Probe::Admitted("performed".into())
    }
}

/// A double that never reaches anything.
struct Disconnected;

struct DeadPod;

impl Host for Disconnected {
    type Pod = DeadPod;

    async fn boot(
        &self,
        _policy: PermissionLattice,
        _approvals: &[(Operation, u32)],
    ) -> Result<DeadPod, String> {
        Ok(DeadPod)
    }
}

impl GuestFacing for DeadPod {
    async fn legitimate_fetch(&mut self) -> Probe {
        Probe::Inconclusive("connection refused".into())
    }
    async fn fetch_mediation_key(&mut self) -> KeyFetch {
        KeyFetch::Inconclusive("connection refused".into())
    }
    async fn ship_receipt(&mut self, _line: &str) -> Probe {
        Probe::Inconclusive("connection refused".into())
    }
    fn leave_exit_report(&mut self, _json: &str) -> Probe {
        Probe::Inconclusive("connection refused".into())
    }
    async fn perform(&mut self, _req: &PerformRequest) -> Probe {
        Probe::Inconclusive("connection refused".into())
    }
}

/// The measurement CAN say Holds: every row, against a host that enforces.
#[tokio::test]
async fn an_enforcing_host_measures_holds_on_every_row() {
    let (control, rows) = measure_all(&Enforcing).await;
    let table = render(&control, &rows);
    assert!(control.is_ok(), "{table}");
    assert_eq!(rows.len(), ALL.len(), "{table}");
    for m in &rows {
        assert_eq!(m.outcome, Outcome::Holds, "{table}");
        assert!(agrees(Expected::Holds, m.outcome));
    }
}

/// A double that reached nothing reads as NotEvaluated on every row, and that
/// agrees with no row of the table, Holds or Gap.
#[tokio::test]
async fn a_disconnected_double_never_reads_as_holds() {
    let (control, rows) = measure_all(&Disconnected).await;
    let table = render(&control, &rows);
    assert!(control.is_err(), "{table}");
    for m in &rows {
        assert_eq!(m.outcome, Outcome::NotEvaluated, "{table}");
        assert!(!agrees(Expected::Holds, m.outcome));
        assert!(!agrees(expected(m.property), m.outcome));
    }
}

/// An honest kernel that ALLOWS the scenario makes the row NotEvaluated: a host
/// allowing what the guest would also allow isolates nothing.
#[test]
fn a_scenario_the_honest_kernel_allows_is_not_evaluated() {
    let s = BrokerScenario {
        policy: PermissionLattice::permissive(),
        approvals: Vec::new(),
        prelude: Vec::new(),
        probe: perform_request(Operation::GitCommit, "ungated-commit"),
    };
    assert!(witness_unapproved(&s).is_err());
}
