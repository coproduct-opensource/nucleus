//! Trust Gate — verifies agent attestations against Coproduct Trust API
//! and derives permission scoping from reputation brackets.
//!
//! Injected into `create_pod_internal()` to scope sandbox permissions
//! based on the agent's demonstrated reputation. Agents with higher
//! reputation get broader capabilities; unknown or low-reputation agents
//! get restricted sandboxes.
//!
//! # Flow
//!
//! ```text
//! PodSpec arrives
//!   → extract agent identity from metadata labels
//!   → call POST trust_api_url/api/trust/verify (if attestation JWT present)
//!   → or call POST trust_api_url/api/trust/discount (identity lookup)
//!   → map bracket → bracket_to_profile()
//!   → TrustProfile::enforce() on requested permissions
//!   → log enforcement result
//!   → return scoped PodSpec
//! ```

use std::sync::Arc;

use base64::Engine as _;
use ed25519_dalek::{Signer as _, SigningKey};
use hmac::{digest::KeyInit, Hmac, Mac};
use nucleus_spec::{PodSpec, PolicySpec};
use portcullis::{IsolationLattice, PermissionLattice, TrustProfile};

use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::{debug, info, warn};

/// Configuration for the trust gate.
#[derive(Debug, Clone)]
pub struct TrustGateConfig {
    /// URL of the Coproduct Trust API (e.g., "https://trust.coproduct.one")
    pub trust_api_url: String,
    /// Whether to enforce trust profiles (false = log-only mode)
    pub enforce: bool,
    /// Default bracket for agents without attestations
    pub default_bracket: String,
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
}

impl Default for TrustGateConfig {
    fn default() -> Self {
        Self {
            trust_api_url: String::new(),     // Disabled by default
            enforce: false,                   // Log-only by default
            default_bracket: "C".to_string(), // Adequate — tenant profile
            receipt_secret: None,
            executor_signing_key: Arc::new(SigningKey::generate(&mut rand::rngs::OsRng)),
            executor_id: format!("nucleus-executor/{}", uuid_hex()),
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

impl TrustGateConfig {
    /// Create from environment variables.
    pub fn from_env() -> Self {
        let receipt_secret = std::env::var("TRUST_RECEIPT_SECRET")
            .ok()
            .and_then(|s| base64::prelude::BASE64_STANDARD.decode(&s).ok())
            .map(Arc::new);

        let executor_id = std::env::var("TRUST_EXECUTOR_ID")
            .unwrap_or_else(|_| format!("nucleus-executor/{}", uuid_hex()));

        let executor_signing_key = Arc::new(SigningKey::generate(&mut rand::rngs::OsRng));

        Self {
            trust_api_url: std::env::var("TRUST_API_URL").unwrap_or_default(),
            enforce: std::env::var("TRUST_GATE_ENFORCE")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
            default_bracket: std::env::var("TRUST_DEFAULT_BRACKET")
                .unwrap_or_else(|_| "C".to_string()),
            receipt_secret,
            executor_signing_key,
            executor_id,
        }
    }

    /// Whether the trust gate is enabled.
    pub fn is_enabled(&self) -> bool {
        !self.trust_api_url.is_empty()
    }
}

/// Result of trust verification for a pod.
#[derive(Debug, Clone, Serialize)]
pub struct TrustVerification {
    /// Agent identity used for lookup
    pub agent_identity: String,
    /// Attestation bracket (A-F)
    pub bracket: String,
    /// Trust profile name derived from bracket
    pub profile_name: String,
    /// Whether permissions were actually restricted
    pub was_restricted: bool,
    /// Whether enforcement is active (vs log-only)
    pub enforced: bool,
    /// Continuous reputation score in [0.0, 1.0] when available from the
    /// discount endpoint. Preserves full precision of the discount_factor
    /// rather than double-discretizing through bracket → score bracket mapping.
    /// Falls back to bracket-derived discrete values in apply_trust_enforcement
    /// when None (e.g., when score was derived from an attestation JWT).
    pub continuous_score: Option<f64>,
}

/// Response from the trust API discount endpoint.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct DiscountResponse {
    discount_factor: f64,
    reputation_context: ReputationContext,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ReputationContext {
    execution_score: f64,
    reviewer_score: f64,
    total_completions: u64,
    total_reviews: u64,
}

/// Response from the trust API verify endpoint.
#[derive(Debug, Deserialize)]
struct VerifyResponse {
    verified: bool,
    brackets: Option<Brackets>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Brackets {
    overall: String,
}

/// Verify an agent's trust status and return the appropriate TrustProfile.
///
/// If the trust API is unreachable or returns an error, falls back to
/// the default bracket (never blocks execution due to trust API failure).
pub async fn verify_agent_trust(
    config: &TrustGateConfig,
    spec: &PodSpec,
    http_client: &reqwest::Client,
) -> TrustVerification {
    // Extract agent identity from pod metadata
    let agent_identity = extract_agent_identity(spec);

    // Check for attestation JWT in metadata labels
    let attestation_jwt = spec
        .metadata
        .labels
        .get("trust.coproduct.one/attestation")
        .cloned();

    let mut continuous_score: Option<f64> = None;

    let bracket = if let Some(jwt) = attestation_jwt {
        // Verify the attestation JWT
        match verify_attestation(config, &jwt, http_client).await {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    agent = %agent_identity,
                    error = %e,
                    "Trust gate: attestation verification failed, using default"
                );
                config.default_bracket.clone()
            }
        }
    } else {
        // No attestation — look up by identity. Returns (bracket, continuous_score)
        // so the continuous discount_factor is preserved without double-discretization.
        match lookup_reputation(config, &agent_identity, http_client).await {
            Ok((b, score)) => {
                continuous_score = Some(score);
                b
            }
            Err(e) => {
                debug!(
                    agent = %agent_identity,
                    error = %e,
                    "Trust gate: reputation lookup failed, using default"
                );
                config.default_bracket.clone()
            }
        }
    };

    let profile_name = bracket_to_profile(&bracket).to_string();

    info!(
        agent = %agent_identity,
        bracket = %bracket,
        profile = %profile_name,
        continuous_score = ?continuous_score,
        enforce = config.enforce,
        "Trust gate: agent verified"
    );

    TrustVerification {
        agent_identity,
        bracket,
        profile_name,
        was_restricted: false, // Updated after apply_trust_enforcement() is called
        enforced: config.enforce,
        continuous_score,
    }
}

/// Apply the trust profile to a PodSpec, scoping permissions.
///
/// Computes a `TrustProfile` from the continuous reputation score via
/// `TrustProfile::from_reputation_score()`, then calls `profile.enforce()` to
/// actually restrict the PodSpec's capability lattice before it is submitted to
/// the runtime. In enforce mode the PodSpec policy is replaced with an inline
/// lattice containing the enforced capabilities/isolation/obligations.
/// In log-only mode the restriction is computed and logged but not applied.
pub fn apply_trust_enforcement(verification: &mut TrustVerification, spec: &mut PodSpec) {
    // Use the continuous discount-derived score when available — it preserves
    // the full resolution of the trust API's discount_factor without the
    // lossy double-discretization of discount_factor → bracket → score.
    // Fall back to bracket-derived values for attestation-JWT paths.
    let reputation_score =
        verification
            .continuous_score
            .unwrap_or(match verification.bracket.as_str() {
                "A" => 0.95,
                "B" => 0.82,
                "C" => 0.65,
                "D" => 0.45,
                _ => 0.2,
            });

    // Write metadata labels for downstream observability and auditing.
    spec.metadata.labels.insert(
        "trust.coproduct.one/bracket".to_string(),
        verification.bracket.clone(),
    );
    spec.metadata.labels.insert(
        "trust.coproduct.one/profile".to_string(),
        verification.profile_name.clone(),
    );
    spec.metadata.labels.insert(
        "trust.coproduct.one/enforced".to_string(),
        verification.enforced.to_string(),
    );
    spec.metadata.labels.insert(
        "trust.coproduct.one/reputation-score".to_string(),
        format!("{reputation_score:.4}"),
    );

    // Resolve the PodSpec's requested policy to get the current capability lattice.
    let current_lattice = match spec.spec.resolve_policy() {
        Ok(l) => l,
        Err(e) => {
            warn!(
                agent = %verification.agent_identity,
                error = %e,
                "Trust gate: policy resolution failed, skipping enforcement"
            );
            return;
        }
    };

    // Derive the trust profile from the continuous reputation score.
    // This uses smooth thresholds and transition zones — no discrete cliffs.
    let profile = TrustProfile::from_reputation_score(reputation_score);

    // Use the existing minimum_isolation as the baseline; default to localhost
    // (no pre-existing isolation requirement) so the profile floor can only
    // strengthen, never weaken, the required isolation.
    let current_isolation = current_lattice
        .minimum_isolation
        .unwrap_or_else(IsolationLattice::localhost);

    // Enforce: capabilities ← meet(current, ceiling)
    //          isolation   ← join(current, floor)
    //          obligations ← union(current, mandatory)
    let enforcement = profile.enforce(
        &current_lattice.capabilities,
        &current_isolation,
        &current_lattice.obligations,
    );

    verification.was_restricted = enforcement.was_restricted;

    if enforcement.was_restricted {
        info!(
            agent = %verification.agent_identity,
            profile = %enforcement.profile_name,
            score = reputation_score,
            enforced = verification.enforced,
            "Trust gate: sandbox capabilities restricted by reputation profile"
        );
    }

    // In enforce mode, apply the scoped policy to the PodSpec so the runtime
    // sees the narrowed capabilities before launching the sandbox.
    // In log-only mode we've computed the restriction for audit purposes only.
    if verification.enforced && enforcement.was_restricted {
        let enforced_lattice = PermissionLattice::builder()
            .description(format!(
                "trust-scoped by {} (score={:.4})",
                enforcement.profile_name, reputation_score
            ))
            .capabilities(enforcement.capabilities)
            .obligations(enforcement.obligations)
            .paths(current_lattice.paths.clone())
            .budget(current_lattice.budget.clone())
            .commands(current_lattice.commands.clone())
            .time(current_lattice.time.clone())
            .minimum_isolation(enforcement.isolation)
            .created_by("trust-gate")
            .build();

        spec.spec.policy = PolicySpec::Inline {
            lattice: Box::new(enforced_lattice),
        };
    }
}

/// Map attestation bracket to portcullis trust profile name.
///
/// Used for logging and metadata labels. The actual permission scoping
/// uses `TrustProfile::from_reputation_score()` for continuous lattice
/// autonomy (no discrete brackets in enforcement).
fn bracket_to_profile(bracket: &str) -> &'static str {
    match bracket.to_uppercase().as_str() {
        "A" => "operator",
        "B" | "C" => "tenant",
        "D" => "untrusted",
        _ => "airgapped",
    }
}

/// Map discount factor to a continuous reputation score.
///
/// The trust API's discount_factor is in [0.5, 1.0] where lower = better.
/// We invert to [0.0, 1.0] where higher = better for portcullis scoring.
pub fn discount_to_reputation_score(discount_factor: f64) -> f64 {
    // discount_factor 0.5 → reputation 1.0 (best)
    // discount_factor 1.0 → reputation 0.0 (worst)
    ((1.0 - discount_factor) * 2.0).clamp(0.0, 1.0)
}

/// Extract agent identity from PodSpec metadata.
fn extract_agent_identity(spec: &PodSpec) -> String {
    // Priority: explicit SPIFFE label > agent-id label > namespace/name > "anonymous"
    spec.metadata
        .labels
        .get("spiffe.io/identity")
        .or_else(|| spec.metadata.labels.get("trust.coproduct.one/agent-id"))
        .cloned()
        .unwrap_or_else(|| {
            let ns = spec.metadata.namespace.as_deref().unwrap_or("default");
            let name = spec.metadata.name.as_deref().unwrap_or("anonymous");
            format!("{ns}/{name}")
        })
}

/// Verify an attestation JWT against the trust API.
async fn verify_attestation(
    config: &TrustGateConfig,
    jwt: &str,
    client: &reqwest::Client,
) -> Result<String, String> {
    let url = format!("{}/api/trust/verify", config.trust_api_url);
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "attestation_jwt": jwt,
        }))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| format!("HTTP error: {e}"))?;

    let body: VerifyResponse = resp.json().await.map_err(|e| format!("JSON error: {e}"))?;

    if body.verified {
        Ok(body
            .brackets
            .map(|b| b.overall)
            .unwrap_or_else(|| config.default_bracket.clone()))
    } else {
        Err(body
            .error
            .unwrap_or_else(|| "Verification failed".to_string()))
    }
}

/// Look up reputation by identity (no attestation JWT available).
///
/// Returns `(bracket, continuous_score)` where `continuous_score` is derived
/// directly from `discount_to_reputation_score(discount_factor)` — preserving
/// the full continuous resolution of the trust API's discount_factor without
/// losing precision through a second discretization step.
async fn lookup_reputation(
    config: &TrustGateConfig,
    identity: &str,
    client: &reqwest::Client,
) -> Result<(String, f64), String> {
    let url = format!("{}/api/trust/discount", config.trust_api_url);
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "executor_identity": identity,
        }))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
        .map_err(|e| format!("HTTP error: {e}"))?;

    let body: DiscountResponse = resp.json().await.map_err(|e| format!("JSON error: {e}"))?;

    // Preserve the continuous reputation score directly from the discount_factor.
    // The bracket is used only for logging/labels; enforcement uses the continuous score.
    let continuous_score = discount_to_reputation_score(body.discount_factor);

    // Map discount factor to bracket for backward-compatible labelling.
    // discount_factor is in [0.5, 1.0] — lower = better reputation.
    let bracket = if body.discount_factor <= 0.6 {
        "A" // Exceptional discount = exceptional reputation
    } else if body.discount_factor <= 0.75 {
        "B"
    } else if body.discount_factor <= 0.9 {
        "C"
    } else if body.discount_factor <= 0.98 {
        "D"
    } else {
        "F" // No discount = no reputation
    };

    Ok((bracket.to_string(), continuous_score))
}

// ═══════════════════════════════════════════════════════════════════════════
// RECEIPT BRIDGE — feed execution results back to trust API
// ═══════════════════════════════════════════════════════════════════════════

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
    /// Trust bracket that was applied to this execution
    pub trust_bracket: Option<String>,
    /// Trust profile that scoped the sandbox
    pub trust_profile: Option<String>,
    /// Whether the sandbox was reputation-scoped
    pub attested_execution: bool,

    // ── Verified exposure (from McpMediator, not claims) ──────────
    /// Observed exposure legs during execution.
    /// These come from the McpMediator's actual interception of tool calls,
    /// NOT from tool description parsing. This is the ground truth.
    pub observed_exposure_labels: Vec<String>,
    /// Observed risk tier: safe, low, medium, critical.
    pub observed_risk_tier: String,
    /// Whether the uninhabitable state was reached during execution.
    pub uninhabitable_reached: bool,

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
        "had_issues": !report.success || report.uninhabitable_reached,
        "hook_event_name": "ExecutionReceipt",
        "observed_exposure_labels": report.observed_exposure_labels,
        "observed_risk_tier": report.observed_risk_tier,
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
                bracket = report.trust_bracket.as_deref().unwrap_or("-"),
                attested = report.attested_execution,
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
                "attested": report.attested_execution,
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
/// Called once at startup so the trust-service can verify per-executor
/// signatures on subsequent receipt POSTs. The registration request itself
/// is HMAC-authenticated using `receipt_secret`.
#[allow(dead_code)] // Called at startup when trust gate is enabled
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
            trust_bracket: Some("B".to_string()),
            trust_profile: Some("tenant".to_string()),
            attested_execution: true,
            observed_exposure_labels: vec!["NetworkEgress".to_string(), "WriteFiles".to_string()],
            observed_risk_tier: "medium".to_string(),
            uninhabitable_reached: false,
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
        assert!(!config.enforce);
        assert_eq!(config.default_bracket, "C");
    }

    #[test]
    fn test_discount_to_reputation_score() {
        // Best discount (0.5) → highest reputation (1.0)
        assert!((discount_to_reputation_score(0.5) - 1.0).abs() < 0.01);
        // No discount (1.0) → zero reputation
        assert!((discount_to_reputation_score(1.0) - 0.0).abs() < 0.01);
        // Middle discount (0.75) → middle reputation (0.5)
        assert!((discount_to_reputation_score(0.75) - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_bracket_to_profile_mapping() {
        assert_eq!(bracket_to_profile("A"), "operator");
        assert_eq!(bracket_to_profile("B"), "tenant");
        assert_eq!(bracket_to_profile("C"), "tenant");
        assert_eq!(bracket_to_profile("D"), "untrusted");
        assert_eq!(bracket_to_profile("F"), "airgapped");
        assert_eq!(bracket_to_profile("Z"), "airgapped");
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
        assert!(sig
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));

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
            enforce: true,
            default_bracket: "C".to_string(),
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

    /// Verify apply_trust_enforcement writes all expected metadata labels.
    #[test]
    fn test_apply_trust_enforcement_writes_labels() {
        use nucleus_spec::{PodSpecInner, PolicySpec};
        use std::path::PathBuf;

        let spec_inner = PodSpecInner {
            work_dir: PathBuf::from("/workspace"),
            timeout_seconds: 3600,
            policy: PolicySpec::Profile {
                name: "default".to_string(),
            },
            budget_model: None,
            resources: None,
            network: None,
            image: None,
            vsock: None,
            seccomp: None,
            cgroup: None,
            audit_sink: None,
            credentials: None,
        };
        let mut spec = PodSpec::new(spec_inner);

        let mut verification = TrustVerification {
            agent_identity: "spiffe://nucleus/test".to_string(),
            bracket: "D".to_string(),
            profile_name: "untrusted".to_string(),
            was_restricted: false,
            enforced: false, // log-only — spec must not be modified
            continuous_score: None,
        };

        apply_trust_enforcement(&mut verification, &mut spec);

        assert_eq!(
            spec.metadata
                .labels
                .get("trust.coproduct.one/bracket")
                .map(String::as_str),
            Some("D")
        );
        assert_eq!(
            spec.metadata
                .labels
                .get("trust.coproduct.one/profile")
                .map(String::as_str),
            Some("untrusted")
        );
        assert!(
            spec.metadata
                .labels
                .contains_key("trust.coproduct.one/reputation-score"),
            "reputation-score label must be written"
        );
        assert_eq!(
            spec.metadata
                .labels
                .get("trust.coproduct.one/enforced")
                .map(String::as_str),
            Some("false")
        );
    }

    /// Verify apply_trust_enforcement replaces the PodSpec policy in enforce mode
    /// when the requested capabilities exceed the reputation profile.
    #[test]
    fn test_apply_trust_enforcement_scopes_policy_in_enforce_mode() {
        use nucleus_spec::{PodSpecInner, PolicySpec};
        use std::path::PathBuf;

        // Start with the permissive "local_dev" profile and a low-reputation agent.
        // The agent's score (0.45 for bracket D) should restrict write/bash/push.
        let spec_inner = PodSpecInner {
            work_dir: PathBuf::from("/workspace"),
            timeout_seconds: 3600,
            policy: PolicySpec::Profile {
                name: "local_dev".to_string(),
            },
            budget_model: None,
            resources: None,
            network: None,
            image: None,
            vsock: None,
            seccomp: None,
            cgroup: None,
            audit_sink: None,
            credentials: None,
        };
        let mut spec = PodSpec::new(spec_inner);

        let mut verification = TrustVerification {
            agent_identity: "spiffe://nucleus/low-trust".to_string(),
            bracket: "D".to_string(),
            profile_name: "untrusted".to_string(),
            was_restricted: false,
            enforced: true, // enforce mode — policy must be replaced
            continuous_score: Some(0.45),
        };

        apply_trust_enforcement(&mut verification, &mut spec);

        // was_restricted should be set because local_dev is more permissive than score 0.45 allows
        assert!(
            verification.was_restricted,
            "low-reputation agent against permissive profile must be restricted"
        );

        // The policy should now be an inline lattice
        match &spec.spec.policy {
            PolicySpec::Inline { lattice } => {
                // Score 0.45: write_files threshold is 0.5 → Never
                use portcullis::CapabilityLevel;
                assert_eq!(
                    lattice.capabilities.write_files,
                    CapabilityLevel::Never,
                    "write_files must be blocked at score 0.45"
                );
                // run_bash threshold is 0.6 → Never
                assert_eq!(
                    lattice.capabilities.run_bash,
                    CapabilityLevel::Never,
                    "run_bash must be blocked at score 0.45"
                );
                // read_files is always allowed
                assert_eq!(
                    lattice.capabilities.read_files,
                    CapabilityLevel::Always,
                    "read_files must always be allowed"
                );
            }
            PolicySpec::Profile { name } => {
                panic!("policy was not replaced with inline lattice; still Profile({name:?})");
            }
        }
    }

    /// Verify apply_trust_enforcement does NOT modify the policy in log-only mode.
    #[test]
    fn test_apply_trust_enforcement_log_only_does_not_modify_policy() {
        use nucleus_spec::{PodSpecInner, PolicySpec};
        use std::path::PathBuf;

        let spec_inner = PodSpecInner {
            work_dir: PathBuf::from("/workspace"),
            timeout_seconds: 3600,
            policy: PolicySpec::Profile {
                name: "fix_issue".to_string(),
            },
            budget_model: None,
            resources: None,
            network: None,
            image: None,
            vsock: None,
            seccomp: None,
            cgroup: None,
            audit_sink: None,
            credentials: None,
        };
        let mut spec = PodSpec::new(spec_inner);

        let mut verification = TrustVerification {
            agent_identity: "spiffe://nucleus/test".to_string(),
            bracket: "F".to_string(),
            profile_name: "airgapped".to_string(),
            was_restricted: false,
            enforced: false, // log-only
            continuous_score: Some(0.1),
        };

        apply_trust_enforcement(&mut verification, &mut spec);

        // Policy must remain unchanged in log-only mode
        match &spec.spec.policy {
            PolicySpec::Profile { name } => {
                assert_eq!(
                    name, "fix_issue",
                    "policy profile must not be mutated in log-only mode"
                );
            }
            PolicySpec::Inline { .. } => {
                panic!("policy must not be replaced in log-only mode");
            }
        }
    }

    /// Verify continuous_score from discount lookup bypasses bracket discretization.
    #[test]
    fn test_continuous_score_bypasses_bracket_discretization() {
        // A discount_factor of 0.85 → continuous_score = (1 - 0.85) * 2 = 0.30
        // That's bracket D in the lookup (0.75 < 0.85 ≤ 0.90), which would
        // naively map to score 0.45. The continuous path preserves 0.30.
        let continuous = discount_to_reputation_score(0.85);
        assert!((continuous - 0.30).abs() < 0.01, "continuous: {continuous}");

        // Bracket D hardcoded score would be 0.45 — significantly different.
        // This test documents the precision gain from using the continuous path.
        let bracket_d_score = 0.45_f64;
        assert!(
            (continuous - bracket_d_score).abs() > 0.10,
            "continuous score {continuous} should differ meaningfully from bracket-D score {bracket_d_score}"
        );
    }
}
