//! Execution-receipt reporting to the external trust API.
//!
//! **There is no reputation here any more (#2512).** This module used to look
//! an agent up against the Coproduct Trust API, map a grade to an f64
//! discount, and record the result on the pod. All of that is deleted. What
//! remains is receipt reporting: after a pod exits, the node POSTs a signed
//! execution receipt so the receipt is externally anchored.
//!
//! # What was deleted, and what had already gone
//!
//! #2512 describes `apply_trust_enforcement` as narrowing `spec.spec.policy`
//! before `PodAuthority::admit` — "the last live economics→authority path".
//! **That path was already closed**, by #2438 in commit `0aa77e0a`; the
//! function did not exist when this change was written. What was still here
//! was the OBSERVATIONAL half: an external HTTP lookup that wrote three
//! `trust.coproduct.one/*` labels onto the spec and nothing else. It authorised
//! nothing, and it was a standing invitation to re-wire — a reputation number
//! already on the spec is one edit away from being read by something that
//! matters.
//!
//! (The label names are not spelled here on purpose.
//! `test_trust_gate_has_no_authorization_path` greps this file's production
//! half for them, and a doc comment that quoted them would red the gate. That
//! is the gate working, not a false positive: the cheapest way to keep a
//! deleted path deleted is to make its vocabulary unwritable here.)
//!
//! So this change removes a hazard, not a live vulnerability, and saying which
//! is the difference between a fix and a cleanup wearing a fix's label.
//!
//! # The keys moved out
//!
//! The node's four role-separated signing keys now live in [`crate::keys`].
//! They were never reputation; they were here because this file was where the
//! node's `state_dir` handling accreted, and `pod_authority` reaching into a
//! module named "trust gate" for the certificate root was the clearest sign
//! the boundary was wrong. Moving them is also what made the deletion above
//! possible: the file could not go while it held the certificate anchor.
//!
//! # What this module does NOT do
//!
//! It does not decide, narrow, or influence what any pod may do. Authority is
//! decided once, from the caller's certificate, in
//! `pod_authority::PodAuthority::admit`. `test_trust_gate_has_no_authorization_path`
//! pins that structurally, and is kept even though the reputation path it was
//! written against is gone — it now guards against the path coming back.

use std::path::Path;
use std::sync::Arc;

use crate::keys::{
    generate_signing_key, load_or_create_signing_key, load_or_create_task_issuer_signing_key,
};
use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use hmac::{Hmac, Mac, digest::KeyInit};

use serde::Serialize;
use sha2::Sha256;
use tracing::{debug, info, warn};

/// Configuration for the trust gate.
#[derive(Debug, Clone)]
pub struct TrustGateConfig {
    /// URL of the Coproduct Trust API (e.g., "https://trust.coproduct.one")
    pub trust_api_url: String,
    /// HMAC-SHA256 key for signing X-Nucleus-Signature on receipt POSTs.
    /// Must match TRUST_RECEIPT_SECRET on the trust-service side.
    /// When None, report_receipt() skips signing and the server will reject
    /// requests with 401 unless it is running with insecure bypass enabled.
    pub receipt_secret: Option<Arc<Vec<u8>>>,
    /// Per-executor Ed25519 signing key for receipt authentication.
    /// Each executor gets a unique keypair — the trust-service verifies receipts
    /// against the registered public key, preventing forged attestations even if
    /// the shared HMAC secret is compromised.
    pub executor_signing_key: Arc<SigningKey>,
    /// Executor identity sent as X-Nucleus-Executor-Id on receipt POSTs.
    pub executor_id: String,
    /// Dedicated Ed25519 key that signs live-path **session capability tokens**
    /// ([`SignedTaskRef`](nucleus_provenance_memory::SignedTaskRef)) minted at
    /// pod spawn. Deliberately DISTINCT from `executor_signing_key` (role
    /// separation): the executor key signs executor decisions and is the
    /// executor's receipt identity, so reusing it as the token root issuer
    /// would conflate two trust roles. Only the PUBLIC half is ever injected
    /// into a pod (as `NUCLEUS_TASK_TOKEN_ISSUER`); the private key never leaves
    /// the node.
    pub task_issuer_signing_key: Arc<SigningKey>,
}

impl Default for TrustGateConfig {
    fn default() -> Self {
        Self {
            trust_api_url: String::new(), // Disabled by default
            receipt_secret: None,
            executor_signing_key: Arc::new(generate_signing_key()),
            executor_id: format!("nucleus-executor/{}", uuid_hex()),
            task_issuer_signing_key: Arc::new(generate_signing_key()),
        }
    }
}

/// Generate a short hex UUID for default executor IDs.
fn uuid_hex() -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes(),
    );
    hex::encode(&hasher.finalize()[..8])
}

/// Derive a stable executor id from the persistent public key, so the id no
/// longer changes on every restart (closes #1636). Used only when
/// `TRUST_EXECUTOR_ID` is unset.
fn executor_id_from_key(key: &SigningKey) -> String {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(key.verifying_key().as_bytes());
    format!("nucleus-executor/{}", hex::encode(&h.finalize()[..8]))
}

impl TrustGateConfig {
    /// Create from environment variables, persisting the per-executor signing
    /// key under `state_dir` so the executor's identity survives restarts.
    pub fn from_env(state_dir: &Path) -> Self {
        let receipt_secret = std::env::var("TRUST_RECEIPT_SECRET")
            .ok()
            .and_then(|s| base64::prelude::BASE64_STANDARD.decode(&s).ok())
            .map(Arc::new);

        let executor_signing_key = load_or_create_signing_key(state_dir);
        // Role-separated key that signs live-path session capability tokens.
        let task_issuer_signing_key = load_or_create_task_issuer_signing_key(state_dir);

        // Prefer an explicit id; otherwise derive a stable one from the
        // persistent key (not a fresh uuid per process — #1636).
        let executor_id = std::env::var("TRUST_EXECUTOR_ID")
            .unwrap_or_else(|_| executor_id_from_key(&executor_signing_key));

        Self {
            trust_api_url: std::env::var("TRUST_API_URL").unwrap_or_default(),
            receipt_secret,
            executor_signing_key: Arc::new(executor_signing_key),
            executor_id,
            task_issuer_signing_key: Arc::new(task_issuer_signing_key),
        }
    }

    /// Whether the trust gate is enabled.
    pub fn is_enabled(&self) -> bool {
        !self.trust_api_url.is_empty()
    }
}

/// Execution receipt data to send to the trust API.
#[derive(Debug, Serialize)]
pub struct ReceiptReport {
    /// Agent identity
    pub agent_id: String,
    /// Pod/session ID
    pub session_id: String,
    /// Whether execution succeeded (exit code 0)
    pub success: bool,
    /// Execution cost in USD
    pub cost_usd: f64,
    /// Number of tool calls (audit entries)
    pub tool_call_count: u64,
    /// SHA-256 of workspace at exit (tamper evidence)
    pub workspace_hash: String,
    /// Hash of audit log tail (integrity proof)
    pub audit_tail_hash: String,

    // ── Verified exposure (from McpMediator, not claims) ──────────
    /// Observed exposure legs during execution.
    /// These come from the McpMediator's actual interception of tool calls,
    /// NOT from tool description parsing. This is the ground truth.
    pub observed_exposure_labels: Vec<String>,
    /// Observed risk tier: safe, low, medium, critical.
    pub observed_risk_tier: String,
    /// Whether the uninhabitable state was reached during execution.
    pub uninhabitable_reached: bool,
    /// The host's signature over the pod's Article 12 chain head, when the pod
    /// kept a log. `None` means no Article 12 record-keeping happened, which is
    /// reported rather than left to inference.
    pub art12_attestation: Option<Art12Attestation>,
    /// Decision-stream property violations observed by the tool proxy's
    /// `TraceMonitor` (class labels), plus any dropped past the retention cap.
    ///
    /// Distinct from exposure: exposure says which capability legs the session
    /// exercised, this says whether the mediation invariants held while it did.
    pub monitor_violations: Vec<String>,
    /// Violations observed but not retained. Non-zero means
    /// `monitor_violations` is truncated.
    pub monitor_violations_dropped: u64,

    // ── Cryptographic session identity ─────────────────────────────
    /// SPIFFE ID or pod identity from the sandbox. Sent as `sandbox_identity`
    /// in session-complete; in secure mode the trust-service cross-checks this
    /// against `agent_id` and rejects mismatches with HTTP 400.
    pub sandbox_identity: String,
    /// SHA-256 v1 content hash computed by nucleus-node over the canonical
    /// receipt fields (pod_id, workspace_hash, audit_tail_hash, …).
    /// Must be pre-registered via POST /api/trust/receipts/register before
    /// session-complete in secure mode; without it the handler returns 422
    /// when observed_exposure_labels are present.
    pub v1_content_hash: String,
}

// `Art12Attestation` and `art12_attestation_preimage` live in
// `portcullis::art12_record`, beside `Art12Record`, so this signer and the
// verifier in `nucleus-audit` share ONE definition of the preimage. Two
// renderings that agree today break the first time either side gains a field —
// and they break by rejecting authentic evidence, which is the worst direction.
pub use portcullis::art12_record::{
    ART12_ATTESTATION_KIND, Art12Attestation, art12_attestation_preimage,
};

/// Sign the Article 12 chain head with the executor key.
///
/// # It signs what the HOST observed, not what the pod reported
///
/// `observed` comes from the node's own collected stream. Signing the pod's
/// reported head would mean the executor vouches for a value the pod chose — an
/// honest signature over a possibly dishonest input, which reads exactly like a
/// trustworthy one.
///
/// When the pod also reported a head, both are carried. They can legitimately
/// differ in ONE direction: the pod ships each record before appending it
/// locally, so a pod that dies mid-write leaves the host holding one MORE than
/// the pod kept. The other direction — the pod claiming more records than the
/// host received — means records were made and never witnessed, and that is the
/// finding this field exists to surface rather than reconcile.
///
/// Falls back to the pod-reported head when the host observed nothing, so a
/// deployment without the evidence channel still gets the weaker-but-honest
/// attestation it had before; `pod_reported_head` being equal to `chain_head`
/// is the tell.
///
/// Returns `None` when neither side has a log — an attestation over an empty
/// head would assert record-keeping that did not happen.
#[must_use]
pub fn attest_art12(
    report: &nucleus_spec::ExitReport,
    observed: Option<&crate::art12_collector::ObservedChain>,
    session_id: &str,
    executor_id: &str,
    key: &SigningKey,
) -> Option<Art12Attestation> {
    let (head, records) = match observed {
        Some(o) => (o.head.clone(), o.records),
        None => (report.art12_chain_head.clone(), report.art12_records),
    };
    if head.is_empty() {
        return None;
    }
    let diverged = observed
        .is_some_and(|o| o.head != report.art12_chain_head || o.records != report.art12_records);
    let preimage = art12_attestation_preimage(
        session_id,
        &head,
        records,
        report.art12_dropped,
        executor_id,
    );
    let sig = key.sign(preimage.as_bytes());
    Some(Art12Attestation {
        kind: ART12_ATTESTATION_KIND.to_string(),
        session_id: session_id.to_string(),
        chain_head: head,
        records,
        dropped: report.art12_dropped,
        executor_id: executor_id.to_string(),
        pod_reported_head: diverged.then(|| report.art12_chain_head.clone()),
        pod_records: diverged.then_some(report.art12_records),
        signature: hex::encode(sig.to_bytes()),
    })
}

impl TrustGateConfig {
    /// The shared secret a pod signs Article 12 records with.
    ///
    /// `None` here means no secret was configured, and the collector must then
    /// REFUSE every record rather than accept unauthenticated evidence. Returning
    /// an empty key would make any signature verify against it, which is the
    /// fail-open reading of the same situation.
    #[must_use]
    pub fn art12_secret(&self) -> Option<&[u8]> {
        self.receipt_secret.as_ref().map(|s| s.as_slice())
    }
}

/// Compute the v1 content hash over the canonical receipt fields.
///
/// # Trust model (Trail of Bits finding #4)
///
/// This hash covers CONTENT (what happened), not IDENTITY (who attested). The
/// executor's Ed25519 signature travels separately in the
/// `X-Nucleus-Executor-Sig` header and signs the serialized session-complete
/// body, which includes this hash. Verification is two-phase: the trust service
/// validates the hash was pre-registered, then verifies the signature against
/// the executor's registered public key. See also `AuditEntry::content_hash()`
/// in `portcullis/src/audit.rs`.
///
/// # What must be committed
///
/// **Every observation the trust service acts on.** A field the trust service
/// reads but the hash does not cover can be stripped or rewritten in flight
/// while the hash still validates — which defeats the binding the
/// `SandboxAttested` upgrade path depends on. That is why the exposure labels,
/// the risk tier, and the monitor's findings are all folded in here, and why a
/// new observation field added to `ExitReport` must be added here too.
///
/// Extracted from `main.rs` so the preimage is testable: it was previously
/// inline in a long handler and no test could reach it.
pub(crate) fn compute_v1_content_hash(
    pod_id: &str,
    manifest_hash: &str,
    report: &nucleus_spec::ExitReport,
) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(pod_id.as_bytes());
    hasher.update(report.workspace_hash.as_bytes());
    hasher.update(report.audit_tail_hash.as_bytes());
    hasher.update(report.audit_entry_count.to_le_bytes());
    hasher.update(report.timestamp_unix.to_le_bytes());
    hasher.update(manifest_hash.as_bytes());
    for label in &report.observed_exposure_labels {
        hasher.update(label.as_bytes());
    }
    hasher.update(report.observed_risk_tier.as_bytes());
    for label in &report.monitor_violations {
        hasher.update(label.as_bytes());
    }
    hasher.update(report.monitor_violations_dropped.to_le_bytes());
    // Same reasoning again: an attestation the receipt hash does not cover can
    // be stripped in flight while the hash still validates, and a stripped
    // attestation reads as "this pod kept no Article 12 log".
    hasher.update(report.art12_chain_head.as_bytes());
    hasher.update(report.art12_records.to_le_bytes());
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Compute a continuous session quality score in [0.0, 1.0] from execution signals.
///
/// Replaces the previous binary 0.85/0.3 split, which collapsed the entire
/// reputation system into a success counter and discarded the continuous
/// signals available from the sandbox observation.
///
/// # Inputs
///
/// | Signal | Effect |
/// |--------|--------|
/// | `success = false` | −0.50 base penalty |
/// | `observed_risk_tier` | +0.15 (safe) → −0.20 (critical) |
/// | `uninhabitable_reached` | −0.10 (dangerous combination triggered) |
/// | exposure breadth | −0.02 per label, capped at −0.10 |
pub(crate) fn compute_session_score(report: &ReceiptReport) -> f64 {
    // Base: success maps to a higher starting point.
    let base = if report.success { 0.70 } else { 0.20 };

    // Risk tier: safe executions that stayed in low-risk operations score higher;
    // executions that reached high/critical exposure score lower.
    let risk_adj = match report.observed_risk_tier.as_str() {
        "safe" => 0.15,
        "low" => 0.08,
        "medium" => 0.00,
        "high" => -0.10,
        "critical" => -0.20,
        _ => 0.00,
    };

    // Uninhabitable state reached: the dangerous capability combination
    // (private-data + untrusted-content + exfiltration) was triggered.
    let uninhabitable_penalty = if report.uninhabitable_reached {
        0.10
    } else {
        0.0
    };

    // Exposure breadth: more real-world exposure legs demonstrated = more risk
    // the agent actually exercised during this session.
    let exposure_penalty = (report.observed_exposure_labels.len() as f64 * 0.02).min(0.10);

    (base + risk_adj - uninhabitable_penalty - exposure_penalty).clamp(0.0, 1.0)
}

/// Build the JSON body for `POST /api/trust/session-complete`.
///
/// Extracted so tests can serialize and assert the exact payload without
/// needing to mock HTTP. The body intentionally includes all four fields that
/// trigger the `NameHeuristic → SandboxAttested` upgrade path in the handler:
/// `observed_exposure_labels`, `observed_risk_tier`, `v1_content_hash`, and
/// `sandbox_identity`.
pub(crate) fn build_session_complete_body(report: &ReceiptReport) -> serde_json::Value {
    serde_json::json!({
        "session_id": report.session_id,
        "agent_id": report.agent_id,
        "sandbox_identity": report.sandbox_identity,
        "success": report.success,
        "score": compute_session_score(report),
        // A recorded effect that nothing authorised is an issue by any reading
        // of the word. Deliberately NOT folded into `compute_session_score`:
        // the weight a violation should carry against reputation is a policy
        // question, and inventing one here would be a number nobody chose.
        "had_issues": !report.success
            || report.uninhabitable_reached
            || !report.monitor_violations.is_empty()
            || report.monitor_violations_dropped > 0,
        "hook_event_name": "ExecutionReceipt",
        "observed_exposure_labels": report.observed_exposure_labels,
        "observed_risk_tier": report.observed_risk_tier,
        "monitor_violations": report.monitor_violations,
        "monitor_violations_dropped": report.monitor_violations_dropped,
        // Present iff the pod kept an Article 12 log. The trust service can
        // check this against the executor's registered public key WITHOUT
        // holding the pod's HMAC secret — which is the whole point.
        "art12_attestation": report.art12_attestation,
        "v1_content_hash": report.v1_content_hash,
    })
}

/// Pre-register the `v1_content_hash` with the trust API before sending
/// `session-complete`.
///
/// In secure mode (`receipt_secret` configured), the trust-service handler
/// returns HTTP 422 when `observed_exposure_labels` arrive without a
/// previously-registered `v1_content_hash`. Call this immediately after
/// computing the hash and before spawning `report_receipt()`.
///
/// No-ops when the trust gate is disabled or running in insecure mode.
pub async fn register_receipt_hash(
    config: &TrustGateConfig,
    report: &ReceiptReport,
    http_client: &reqwest::Client,
) {
    // Registration is only required in secure mode; insecure/dev mode accepts
    // exposure labels without a pre-registered hash.
    if !config.is_enabled() || config.receipt_secret.is_none() {
        return;
    }

    let url = format!("{}/api/trust/receipts/register", config.trust_api_url);
    let body = serde_json::json!({
        "v1_content_hash": report.v1_content_hash,
        "session_id": report.session_id,
        "agent_id": report.agent_id,
    });
    let body_bytes = serde_json::to_vec(&body).unwrap_or_default();

    // receipt_secret is Some — we checked above
    let sig = hmac_sha256_hex(config.receipt_secret.as_ref().unwrap(), &body_bytes);

    match http_client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("X-Nucleus-Signature", sig)
        .timeout(std::time::Duration::from_secs(5))
        .body(body_bytes)
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            debug!(
                session = %report.session_id,
                hash = %report.v1_content_hash,
                "Trust gate: receipt hash pre-registered"
            );
        }
        Ok(resp) => {
            warn!(
                status = resp.status().as_u16(),
                session = %report.session_id,
                hash = %report.v1_content_hash,
                "Trust gate: receipt hash pre-registration failed — session-complete with \
                 observed_exposure_labels will be rejected with 422"
            );
        }
        Err(e) => {
            warn!(
                error = %e,
                session = %report.session_id,
                "Trust gate: receipt hash pre-registration request failed"
            );
        }
    }
}

/// Report an execution receipt to the Coproduct Trust API.
///
/// This is the receipt-to-trust bridge: cryptographically attested execution
/// results feed back into reputation scoring. Receipt-backed data is worth
/// more than hook-backed data because it's third-party verified by the sandbox.
///
/// Called from `get_receipt()` after the execution receipt is computed.
/// Runs asynchronously — never blocks receipt delivery.
///
/// In secure mode, call `register_receipt_hash()` first so the handler can
/// validate `v1_content_hash` and allow the `SandboxAttested` upgrade.
pub async fn report_receipt(
    config: &TrustGateConfig,
    report: &ReceiptReport,
    http_client: &reqwest::Client,
) {
    if !config.is_enabled() {
        return;
    }

    let url = format!("{}/api/trust/session-complete", config.trust_api_url);

    let body = build_session_complete_body(report);

    let body_bytes = serde_json::to_vec(&body).unwrap_or_default();

    let mut req = http_client
        .post(&url)
        .header("Content-Type", "application/json")
        .timeout(std::time::Duration::from_secs(5))
        .body(body_bytes.clone());

    if let Some(secret) = &config.receipt_secret {
        let sig = hmac_sha256_hex(secret, &body_bytes);
        req = req.header("X-Nucleus-Signature", sig);
    } else {
        warn!(
            "TRUST_RECEIPT_SECRET not set — sending session-complete without X-Nucleus-Signature; \
             trust-service will reject with 401 unless TRUST_INSECURE_NO_SIGNATURE_VERIFICATION=true"
        );
    }

    // Per-executor Ed25519 signature — allows trust-service to verify which
    // specific executor produced this receipt, not just "someone with the HMAC key".
    let ed25519_sig = config.executor_signing_key.sign(&body_bytes);
    req = req
        .header("X-Nucleus-Executor-Id", &config.executor_id)
        .header(
            "X-Nucleus-Executor-Sig",
            base64::prelude::BASE64_STANDARD.encode(ed25519_sig.to_bytes()),
        );

    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            info!(
                agent = %report.agent_id,
                session = %report.session_id,
                success = report.success,
                cost = report.cost_usd,
                tools = report.tool_call_count,
                "Trust gate: execution receipt reported"
            );
        }
        Ok(resp) => {
            debug!(
                status = resp.status().as_u16(),
                "Trust gate: receipt report returned non-success"
            );
        }
        Err(e) => {
            debug!(error = %e, "Trust gate: receipt report failed (non-blocking)");
        }
    }

    // Also report each tool used via ingest (if we have audit data)
    if report.tool_call_count > 0 {
        let ingest_url = format!("{}/api/trust/ingest", config.trust_api_url);
        let ingest_body = serde_json::json!({
            "hook_event_name": "PostToolUse",
            "session_id": report.session_id,
            "agent_id": report.agent_id,
            "tool_name": "nucleus_execution",
            "tool_response": {
                "success": report.success,
                "source": "execution_receipt",
                "workspace_hash": report.workspace_hash,
                "audit_tail_hash": report.audit_tail_hash,
                "tool_call_count": report.tool_call_count,
                "cost_usd": report.cost_usd,
                // Verified exposure: from actual sandbox observation, not claims
                "verified_exposure": {
                    "observed_labels": report.observed_exposure_labels,
                    "risk_tier": report.observed_risk_tier,
                    "uninhabitable_reached": report.uninhabitable_reached,
                }
            }
        });

        let ingest_bytes = serde_json::to_vec(&ingest_body).unwrap_or_default();

        let mut ingest_req = http_client
            .post(&ingest_url)
            .header("Content-Type", "application/json")
            .timeout(std::time::Duration::from_secs(5))
            .body(ingest_bytes.clone());

        if let Some(secret) = &config.receipt_secret {
            let sig = hmac_sha256_hex(secret, &ingest_bytes);
            ingest_req = ingest_req.header("X-Nucleus-Signature", sig);
        }

        // Per-executor Ed25519 on ingest path too
        let ed25519_sig = config.executor_signing_key.sign(&ingest_bytes);
        ingest_req = ingest_req
            .header("X-Nucleus-Executor-Id", &config.executor_id)
            .header(
                "X-Nucleus-Executor-Sig",
                base64::prelude::BASE64_STANDARD.encode(ed25519_sig.to_bytes()),
            );

        let _ = ingest_req.send().await;
    }
}

/// Compute HMAC-SHA256(secret, data) and return the result as a lowercase hex string.
///
/// This matches the verification logic in trust-service's `verify_nucleus_signature()`,
/// which computes the MAC over the raw body bytes and compares it constant-time.
fn hmac_sha256_hex(secret: &[u8], data: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize()
        .into_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Register this executor's Ed25519 public key with the trust-service.
///
/// Called once at startup (from `main`, before serving) so the trust-service
/// can verify per-executor signatures on subsequent receipt POSTs — those POSTs
/// carry `X-Nucleus-Executor-Sig` but no inline pubkey, so without this
/// enrollment the signatures are unverifiable. The registration request itself
/// is HMAC-authenticated using `receipt_secret`.
pub async fn register_executor_pubkey(config: &TrustGateConfig, http_client: &reqwest::Client) {
    if !config.is_enabled() {
        return;
    }

    let url = format!("{}/api/trust/executors/register", config.trust_api_url);

    let pubkey_b64 = base64::prelude::BASE64_STANDARD
        .encode(config.executor_signing_key.verifying_key().to_bytes());

    let body = serde_json::json!({
        "executor_id": config.executor_id,
        "public_key": pubkey_b64,
        "algorithm": "Ed25519",
    });

    let body_bytes = serde_json::to_vec(&body).unwrap_or_default();

    let mut req = http_client
        .post(&url)
        .header("Content-Type", "application/json")
        .timeout(std::time::Duration::from_secs(5))
        .body(body_bytes.clone());

    // HMAC-authenticate the registration itself
    if let Some(secret) = &config.receipt_secret {
        let sig = hmac_sha256_hex(secret, &body_bytes);
        req = req.header("X-Nucleus-Signature", sig);
    }

    match req.send().await {
        Ok(resp) if resp.status().is_success() => {
            info!(
                executor_id = %config.executor_id,
                "Registered executor public key with trust-service"
            );
        }
        Ok(resp) => {
            warn!(
                executor_id = %config.executor_id,
                status = %resp.status(),
                "Failed to register executor public key"
            );
        }
        Err(e) => {
            warn!(
                executor_id = %config.executor_id,
                error = %e,
                "Failed to register executor public key (network error)"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_exit_report() -> nucleus_spec::ExitReport {
        nucleus_spec::ExitReport {
            workspace_hash: "ws".to_string(),
            audit_tail_hash: "tail".to_string(),
            audit_entry_count: 3,
            timestamp_unix: 1_700_000_000,
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 0,
            cost_usd: 0.0,
            observed_exposure_labels: vec!["PrivateData".to_string()],
            observed_risk_tier: "medium".to_string(),
            uninhabitable_reached: false,
            monitor_violations: vec!["OutcomeWithoutDecision".to_string()],
            monitor_violations_dropped: 2,
            art12_chain_head: "head".to_string(),
            art12_records: 5,
            art12_dropped: 0,
            authority: None,
        }
    }

    /// **The attestation must reach the trust service.** Signing it and then
    /// dropping it on the floor is the defect this whole line of work is about:
    /// a mechanism that exists, a claim about it, and nothing joining the two.
    #[test]
    fn the_attestation_reaches_the_session_complete_body() {
        let key = SigningKey::from_bytes(&[9u8; 32]);
        let mut report = sample_receipt_report();
        assert!(
            build_session_complete_body(&report)["art12_attestation"].is_null(),
            "no log means no attestation, or the assertion below proves nothing"
        );

        report.art12_attestation =
            attest_art12(&sample_exit_report(), None, "sess", "exec-1", &key);
        let body = build_session_complete_body(&report);
        assert_eq!(
            body["art12_attestation"]["chain_head"].as_str(),
            Some("head"),
            "the executor's attestation must travel with the receipt"
        );
        assert!(
            body["art12_attestation"]["signature"]
                .as_str()
                .is_some_and(|s| s.len() == 128),
            "an Ed25519 signature is 64 bytes hex-encoded"
        );
    }

    /// **The attestation binds the head with a key the pod does not hold.**
    /// That is the whole point: an HMAC'd chain proves nothing against a pod
    /// that holds its own signing secret.
    #[test]
    fn an_attestation_verifies_under_the_executor_public_key() {
        use ed25519_dalek::{Signature, Verifier as _};
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let report = sample_exit_report();
        let att = attest_art12(&report, None, "sess", "exec-1", &key).expect("a log was kept");

        let preimage = art12_attestation_preimage(
            "sess",
            &report.art12_chain_head,
            report.art12_records,
            report.art12_dropped,
            "exec-1",
        );
        let bytes: [u8; 64] = hex::decode(&att.signature).unwrap().try_into().unwrap();
        assert!(
            key.verifying_key()
                .verify(preimage.as_bytes(), &Signature::from_bytes(&bytes))
                .is_ok()
        );
    }

    fn observed(head: &str, records: u64) -> crate::art12_collector::ObservedChain {
        crate::art12_collector::ObservedChain {
            head: head.to_string(),
            records,
        }
    }

    /// **The attestation signs what the HOST saw, not what the pod said.**
    /// Signing the pod's value would be an honest signature over a possibly
    /// dishonest input, which reads exactly like a trustworthy one.
    #[test]
    fn the_host_observed_head_is_what_gets_signed() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let mut report = sample_exit_report();
        report.art12_chain_head = "what-the-pod-claimed".into();
        report.art12_records = 5;

        let att = attest_art12(
            &report,
            Some(&observed("what-the-host-received", 5)),
            "sess",
            "exec-1",
            &key,
        )
        .unwrap();
        assert_eq!(att.chain_head, "what-the-host-received");
        assert_eq!(
            att.pod_reported_head.as_deref(),
            Some("what-the-pod-claimed"),
            "the disagreement must be carried, not silently resolved"
        );
    }

    /// Agreement carries no divergence fields — otherwise every ordinary session
    /// would look like a finding and the real ones would be lost in it.
    #[test]
    fn agreement_records_no_divergence() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let report = sample_exit_report();
        let att = attest_art12(
            &report,
            Some(&observed(&report.art12_chain_head, report.art12_records)),
            "sess",
            "exec-1",
            &key,
        )
        .unwrap();
        assert!(att.pod_reported_head.is_none());
        assert!(att.pod_records.is_none());
    }

    /// **The alarming direction.** A pod claiming MORE records than the host
    /// received means decisions were made and never witnessed. The count must
    /// survive into the attestation so a reader can tell which way it went.
    #[test]
    fn a_pod_claiming_more_records_than_the_host_saw_is_visible() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let mut report = sample_exit_report();
        report.art12_records = 99;

        let att = attest_art12(
            &report,
            Some(&observed(&report.art12_chain_head, 3)),
            "sess",
            "exec-1",
            &key,
        )
        .unwrap();
        assert_eq!(att.records, 3, "the host attests what it received");
        assert_eq!(
            att.pod_records,
            Some(99),
            "and what the pod claimed, so the gap is legible"
        );
    }

    /// Without the evidence channel the pod-reported head is still attested —
    /// the weaker-but-honest configuration that existed before. Falling back to
    /// nothing would make deployments without a channel silently unattested.
    #[test]
    fn with_no_host_observation_the_pod_head_is_still_attested() {
        let key = SigningKey::from_bytes(&[5u8; 32]);
        let report = sample_exit_report();
        let att = attest_art12(&report, None, "sess", "exec-1", &key).unwrap();
        assert_eq!(att.chain_head, report.art12_chain_head);
        assert!(
            att.pod_reported_head.is_none(),
            "with nothing to compare against there is no divergence to report"
        );
    }

    /// **A rewritten log cannot keep its attestation.** This is the property the
    /// export exists for: change the history, and the head no longer matches the
    /// one the executor signed.
    #[test]
    fn a_rewritten_chain_head_breaks_the_attestation() {
        use ed25519_dalek::{Signature, Verifier as _};
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let report = sample_exit_report();
        let att = attest_art12(&report, None, "sess", "exec-1", &key).unwrap();

        // The pod rewrites its log after the fact; the head moves.
        let forged = art12_attestation_preimage("sess", "different-head", 5, 0, "exec-1");
        let bytes: [u8; 64] = hex::decode(&att.signature).unwrap().try_into().unwrap();
        assert!(
            key.verifying_key()
                .verify(forged.as_bytes(), &Signature::from_bytes(&bytes))
                .is_err(),
            "a moved chain head must not verify under the original signature"
        );
    }

    /// Every field in the preimage must be bound, or it can be rewritten freely
    /// while the signature still checks.
    #[test]
    fn every_attestation_field_is_bound_by_the_signature() {
        let base = art12_attestation_preimage("sess", "head", 5, 0, "exec-1");
        for (field, other) in [
            (
                "session_id",
                art12_attestation_preimage("other", "head", 5, 0, "exec-1"),
            ),
            (
                "chain_head",
                art12_attestation_preimage("sess", "other", 5, 0, "exec-1"),
            ),
            (
                "records",
                art12_attestation_preimage("sess", "head", 6, 0, "exec-1"),
            ),
            (
                "dropped",
                art12_attestation_preimage("sess", "head", 5, 1, "exec-1"),
            ),
            (
                "executor_id",
                art12_attestation_preimage("sess", "head", 5, 0, "exec-2"),
            ),
        ] {
            assert_ne!(base, other, "{field} is not in the signed preimage");
        }
    }

    /// A session that kept no log must NOT get an attestation — signing an empty
    /// head would assert record-keeping that did not happen.
    #[test]
    fn no_log_means_no_attestation() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let mut report = sample_exit_report();
        report.art12_chain_head = String::new();
        assert!(
            attest_art12(&report, None, "sess", "exec-1", &key).is_none(),
            "an absent log must not produce an attestation that implies one"
        );
    }

    /// **Every observation the trust service acts on must be committed.** A
    /// field it reads but the hash does not cover can be stripped in flight
    /// while the hash still validates, which is precisely the tamper the
    /// content-hash binding exists to prevent.
    ///
    /// Perturbing any field below must change the hash; a field that does not
    /// appear here is one an attacker can rewrite for free.
    #[test]
    fn every_committed_field_changes_the_v1_content_hash() {
        let base = sample_exit_report();
        let baseline = compute_v1_content_hash("pod-1", "manifest", &base);

        let mut mutations: Vec<(&str, nucleus_spec::ExitReport)> = Vec::new();
        let mut m = base.clone();
        m.workspace_hash = "other".into();
        mutations.push(("workspace_hash", m));
        let mut m = base.clone();
        m.audit_tail_hash = "other".into();
        mutations.push(("audit_tail_hash", m));
        let mut m = base.clone();
        m.audit_entry_count = 4;
        mutations.push(("audit_entry_count", m));
        let mut m = base.clone();
        m.timestamp_unix += 1;
        mutations.push(("timestamp_unix", m));
        let mut m = base.clone();
        m.observed_exposure_labels = vec!["ExfilVector".into()];
        mutations.push(("observed_exposure_labels", m));
        let mut m = base.clone();
        m.observed_risk_tier = "safe".into();
        mutations.push(("observed_risk_tier", m));
        // The two added by the trace-monitor wiring. Stripping the violations is
        // the interesting attack: a session that broke its mediation invariants
        // filing a clean receipt.
        let mut m = base.clone();
        m.monitor_violations = Vec::new();
        mutations.push(("monitor_violations", m));
        let mut m = base.clone();
        m.monitor_violations_dropped = 0;
        mutations.push(("monitor_violations_dropped", m));

        for (field, mutated) in mutations {
            assert_ne!(
                compute_v1_content_hash("pod-1", "manifest", &mutated),
                baseline,
                "{field} is not committed into v1_content_hash — it can be tampered with freely"
            );
        }

        // The two arguments are committed too.
        assert_ne!(
            compute_v1_content_hash("pod-2", "manifest", &base),
            baseline
        );
        assert_ne!(compute_v1_content_hash("pod-1", "other", &base), baseline);
    }

    /// Helper to build a minimal ReceiptReport for body-structure tests.
    fn sample_receipt_report() -> ReceiptReport {
        ReceiptReport {
            agent_id: "spiffe://nucleus/test-agent".to_string(),
            session_id: "sess-test-001".to_string(),
            success: true,
            cost_usd: 0.01,
            tool_call_count: 3,
            workspace_hash: "abc123def456".to_string(),
            audit_tail_hash: "fed654cba321".to_string(),
            observed_exposure_labels: vec!["NetworkEgress".to_string(), "WriteFiles".to_string()],
            observed_risk_tier: "medium".to_string(),
            uninhabitable_reached: false,
            monitor_violations: Vec::new(),
            monitor_violations_dropped: 0,
            art12_attestation: None,
            sandbox_identity: "spiffe://nucleus/test-agent".to_string(),
            v1_content_hash: "cafebabe11223344556677889900aabbccddeeff".to_string(),
        }
    }

    /// Verify that `build_session_complete_body()` includes all four fields
    /// required for the `NameHeuristic → SandboxAttested` upgrade path.
    ///
    /// This test directly exercises the body builder used by `report_receipt()`.
    /// Previously the body omitted `observed_exposure_labels`, `observed_risk_tier`,
    /// `v1_content_hash`, and `sandbox_identity`, making the upgrade path dead in
    /// production. Any regression in the body builder will be caught here.
    #[test]
    fn test_session_complete_body_includes_all_upgrade_fields() {
        let report = sample_receipt_report();
        let body = build_session_complete_body(&report);

        // All four fields that trigger the SandboxAttested upgrade must be present.
        assert!(
            body.get("observed_exposure_labels").is_some(),
            "observed_exposure_labels must be present in session-complete body"
        );
        assert!(
            body.get("observed_risk_tier").is_some(),
            "observed_risk_tier must be present in session-complete body"
        );
        assert!(
            body.get("v1_content_hash").is_some(),
            "v1_content_hash must be present in session-complete body — \
             without it the handler returns 422 in secure mode"
        );
        assert!(
            body.get("sandbox_identity").is_some(),
            "sandbox_identity must be present in session-complete body — \
             required for cross-check in secure mode"
        );

        // Values must round-trip correctly.
        let labels = body["observed_exposure_labels"].as_array().unwrap();
        assert_eq!(labels.len(), 2);
        assert!(labels.iter().any(|v| v.as_str() == Some("NetworkEgress")));
        assert!(labels.iter().any(|v| v.as_str() == Some("WriteFiles")));
        assert_eq!(body["observed_risk_tier"].as_str(), Some("medium"));
        assert_eq!(
            body["v1_content_hash"].as_str(),
            Some("cafebabe11223344556677889900aabbccddeeff")
        );
        assert_eq!(
            body["sandbox_identity"].as_str(),
            Some("spiffe://nucleus/test-agent")
        );
        assert_eq!(
            body["agent_id"].as_str(),
            Some("spiffe://nucleus/test-agent")
        );
        assert_eq!(body["session_id"].as_str(), Some("sess-test-001"));
        assert_eq!(body["success"].as_bool(), Some(true));

        // Score: success(0.70) + medium(0.00) - no_uninhabitable(0.00) - 2_labels(0.04) = 0.66
        let score = body["score"].as_f64().unwrap();
        assert!(
            (score - 0.66).abs() < 0.001,
            "expected score ≈ 0.66, got {score}"
        );
        assert_eq!(body["had_issues"].as_bool(), Some(false));
        assert_eq!(body["hook_event_name"].as_str(), Some("ExecutionReceipt"));
    }

    /// Verify that `build_session_complete_body()` correctly sets `had_issues`
    /// when `uninhabitable_reached` is true even on a successful exit.
    #[test]
    fn test_session_complete_body_had_issues_when_uninhabitable_reached() {
        let mut report = sample_receipt_report();
        report.success = true;
        report.uninhabitable_reached = true;

        let body = build_session_complete_body(&report);
        assert_eq!(
            body["had_issues"].as_bool(),
            Some(true),
            "had_issues must be true when uninhabitable_reached is set"
        );
        // Score: success(0.70) + medium(0.00) - uninhabitable(0.10) - 2_labels(0.04) = 0.56
        let score = body["score"].as_f64().unwrap();
        assert!(
            (score - 0.56).abs() < 0.001,
            "expected score ≈ 0.56 with uninhabitable penalty, got {score}"
        );
    }

    /// A monitor violation is a recorded effect that nothing authorised. A
    /// session that produced one did not go cleanly, whatever its exit code —
    /// and without this the exit report's new fields would be written by the
    /// proxy and read by nothing, which is the defect they exist to detect.
    #[test]
    fn test_session_complete_body_had_issues_when_monitor_flagged() {
        let mut report = sample_receipt_report();
        report.success = true;
        report.uninhabitable_reached = false;
        assert_eq!(
            build_session_complete_body(&report)["had_issues"].as_bool(),
            Some(false),
            "the control must be clean, or the assertion below proves nothing"
        );

        report.monitor_violations = vec!["OutcomeWithoutDecision".to_string()];
        let body = build_session_complete_body(&report);
        assert_eq!(
            body["had_issues"].as_bool(),
            Some(true),
            "had_issues must be true when the monitor observed a violation"
        );
        assert_eq!(
            body["monitor_violations"][0].as_str(),
            Some("OutcomeWithoutDecision"),
            "the violation classes must reach the trust service, not just the flag"
        );
    }

    /// Truncation must not read as cleanliness: a session whose violations all
    /// overflowed the retention cap still had issues.
    #[test]
    fn test_dropped_violations_alone_set_had_issues() {
        let mut report = sample_receipt_report();
        report.success = true;
        report.monitor_violations = Vec::new();
        report.monitor_violations_dropped = 7;

        let body = build_session_complete_body(&report);
        assert_eq!(
            body["had_issues"].as_bool(),
            Some(true),
            "an empty-but-truncated violation list must not read as clean"
        );
        assert_eq!(body["monitor_violations_dropped"].as_u64(), Some(7));
    }

    /// Verify failure path: score drops significantly and had_issues is set.
    #[test]
    fn test_session_complete_body_failure_score() {
        let mut report = sample_receipt_report();
        report.success = false;
        report.uninhabitable_reached = false;

        let body = build_session_complete_body(&report);
        // Score: failure(0.20) + medium(0.00) - 0 - 2_labels(0.04) = 0.16
        let score = body["score"].as_f64().unwrap();
        assert!(
            (score - 0.16).abs() < 0.001,
            "expected score ≈ 0.16 for failure path, got {score}"
        );
        assert_eq!(body["had_issues"].as_bool(), Some(true));
    }

    #[test]
    fn test_config_from_env_defaults() {
        let config = TrustGateConfig::default();
        assert!(!config.is_enabled());
    }

    #[test]
    fn test_hmac_sha256_hex_matches_server_expectation() {
        // Verify our signing matches the logic in trust-service verify_nucleus_signature():
        //   mac = HMAC_SHA256(secret, body_bytes)
        //   expected_hex = mac.finalize().into_bytes().map(|b| format!("{:02x}", b)).collect()
        let secret = b"test-receipt-secret";
        let body = b"{\"session_id\":\"abc\",\"success\":true}";

        let sig = hmac_sha256_hex(secret, body);

        // Signature must be 64 lowercase hex chars (32 bytes)
        assert_eq!(sig.len(), 64);
        assert!(
            sig.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );

        // Re-computing with the same inputs must yield the same signature (deterministic)
        let sig2 = hmac_sha256_hex(secret, body);
        assert_eq!(sig, sig2);

        // Different secret → different signature
        let sig_other = hmac_sha256_hex(b"different-secret", body);
        assert_ne!(sig, sig_other);

        // Different body → different signature
        let sig_body = hmac_sha256_hex(secret, b"{\"session_id\":\"xyz\"}");
        assert_ne!(sig, sig_body);
    }

    #[test]
    fn test_config_with_receipt_secret() {
        let secret_bytes = b"my-receipt-secret-32-bytes-long!!";
        let config = TrustGateConfig {
            trust_api_url: "https://trust.example.com".to_string(),
            receipt_secret: Some(Arc::new(secret_bytes.to_vec())),
            ..Default::default()
        };

        assert!(config.is_enabled());
        assert!(config.receipt_secret.is_some());

        // Verify the stored secret is the one we set
        let stored = config.receipt_secret.as_ref().unwrap();
        assert_eq!(stored.as_slice(), secret_bytes);
    }

    #[test]
    fn test_config_default_has_no_receipt_secret() {
        let config = TrustGateConfig::default();
        assert!(config.receipt_secret.is_none());
    }

    /// Simulate what report_receipt() does for the session-complete body and verify
    /// the resulting signature against the same algorithm used by trust-service.
    #[test]
    fn test_report_receipt_signature_is_verifiable() {
        let secret = b"shared-receipt-secret";

        // Build a minimal body for HMAC signing verification.
        // (This is testing the signing algorithm, not the body structure.)
        let body = serde_json::json!({
            "session_id": "sess-001",
            "agent_id": "agent@example.com",
            "success": true,
            "score": 0.66_f64,
            "had_issues": false,
            "hook_event_name": "ExecutionReceipt",
        });
        let body_bytes = serde_json::to_vec(&body).unwrap();
        let signature = hmac_sha256_hex(secret, &body_bytes);

        // Server-side verification (mirrors trust-service verify_nucleus_signature)
        let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
        mac.update(&body_bytes);
        let expected: String = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        assert_eq!(
            signature, expected,
            "Client-side signature must match server-side HMAC-SHA256 over the same body bytes"
        );
    }

    /// Verify compute_session_score produces sensible values across risk tiers.
    #[test]
    fn test_compute_session_score_risk_tiers() {
        let mut report = sample_receipt_report(); // success, medium, 2 labels, no uninhabitable
        report.observed_exposure_labels.clear(); // remove exposure noise for clarity

        // Safe tier: success(0.70) + safe(0.15) = 0.85
        report.observed_risk_tier = "safe".to_string();
        let safe_score = compute_session_score(&report);
        assert!((safe_score - 0.85).abs() < 0.001, "safe: {safe_score}");

        // Medium tier: success(0.70) + medium(0.00) = 0.70
        report.observed_risk_tier = "medium".to_string();
        let medium_score = compute_session_score(&report);
        assert!(
            (medium_score - 0.70).abs() < 0.001,
            "medium: {medium_score}"
        );

        // Critical tier: success(0.70) + critical(-0.20) = 0.50
        report.observed_risk_tier = "critical".to_string();
        let critical_score = compute_session_score(&report);
        assert!(
            (critical_score - 0.50).abs() < 0.001,
            "critical: {critical_score}"
        );

        // Failure + critical: failure(0.20) + critical(-0.20) = 0.00
        report.success = false;
        let fail_critical = compute_session_score(&report);
        assert!(
            fail_critical < 0.01,
            "fail+critical should be near 0: {fail_critical}"
        );
    }

    /// Verify compute_session_score caps the exposure penalty at 0.10.
    #[test]
    fn test_compute_session_score_exposure_cap() {
        let mut report = sample_receipt_report();
        report.success = true;
        report.observed_risk_tier = "medium".to_string();
        report.uninhabitable_reached = false;
        // 10 labels: penalty would be 10 * 0.02 = 0.20, but capped at 0.10
        report.observed_exposure_labels = (0..10).map(|i| format!("Label{i}")).collect();

        // success(0.70) + medium(0.00) - cap(0.10) = 0.60
        let score = compute_session_score(&report);
        assert!((score - 0.60).abs() < 0.001, "exposure cap: {score}");
    }

    /// Verify compute_session_score result is always in [0.0, 1.0].
    #[test]
    fn test_compute_session_score_clamped() {
        let mut report = sample_receipt_report();
        // Worst-case scenario
        report.success = false;
        report.uninhabitable_reached = true;
        report.observed_risk_tier = "critical".to_string();
        report.observed_exposure_labels = (0..20).map(|i| format!("L{i}")).collect();
        assert!(compute_session_score(&report) >= 0.0);

        // Best-case scenario
        let mut best = sample_receipt_report();
        best.success = true;
        best.uninhabitable_reached = false;
        best.observed_risk_tier = "safe".to_string();
        best.observed_exposure_labels.clear();
        assert!(compute_session_score(&best) <= 1.0);
    }

    #[test]
    fn test_from_env_provisions_role_separated_task_issuer_key() {
        let dir = tempfile::tempdir().unwrap();
        let config = TrustGateConfig::from_env(dir.path());
        assert_ne!(
            config.executor_signing_key.verifying_key().as_bytes(),
            config.task_issuer_signing_key.verifying_key().as_bytes(),
            "from_env must provision a task-issuer key distinct from the executor key"
        );
    }

    #[test]
    fn test_executor_id_from_key_is_deterministic_and_keyed() {
        let dir = tempfile::tempdir().unwrap();
        let key = load_or_create_signing_key(dir.path());
        let id1 = executor_id_from_key(&key);
        let id2 = executor_id_from_key(&key);
        assert_eq!(id1, id2, "id must be a deterministic function of the key");
        assert!(id1.starts_with("nucleus-executor/"));
        // A different key yields a different id.
        let other = tempfile::tempdir().unwrap();
        let id_other = executor_id_from_key(&load_or_create_signing_key(other.path()));
        assert_ne!(id1, id_other);
    }
    #[test]
    fn test_trust_gate_has_no_authorization_path() {
        let src = include_str!("trust_gate.rs");
        let production = src
            .split("#[cfg(test)]")
            .next()
            .expect("the module has a test half");
        // The first four predate #2512 and guarded the OBSERVATIONAL gate
        // against regaining an authorization path. The rest are #2512's: the
        // reputation lookup itself is gone, and these names are how it would
        // come back. A pin that only forbids the old enforcement would let the
        // whole lookup return and call itself observational again.
        for needle in [
            "spec.spec.policy =",
            "TrustProfile",
            "require_isolation",
            "TRUST_GATE_ENFORCE",
            "api/trust/discount",
            "api/trust/verify",
            "reputation-score",
            "discount_factor",
            "bracket",
        ] {
            assert!(
                !production.contains(needle),
                "trust_gate.rs must not contain {needle:?} outside its tests"
            );
        }
    }
}
