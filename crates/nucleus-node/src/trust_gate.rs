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
use hmac::{Hmac, Mac};
use nucleus_spec::{PodSpec, PolicySpec};
use portcullis::isolation::IsolationLattice;
use portcullis::trust::TrustProfile;
use portcullis::PermissionLattice;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::{debug, info, warn};

/// Configuration for the trust gate.
#[derive(Clone)]
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
    /// Executor identity string sent as `X-Nucleus-Executor-Id` on every receipt.
    /// Typically a SPIFFE ID or a stable UUID for this executor instance.
    /// Required: report_receipt() will not sign or send requests without this.
    pub executor_id: String,
    /// Ed25519 signing key for per-executor attestation on receipt submissions.
    /// Generated at startup; the corresponding public key must be registered with
    /// the trust service via register_executor_pubkey() before sending receipts.
    pub executor_signing_key: Arc<SigningKey>,
}

impl std::fmt::Debug for TrustGateConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustGateConfig")
            .field("trust_api_url", &self.trust_api_url)
            .field("enforce", &self.enforce)
            .field("default_bracket", &self.default_bracket)
            .field(
                "receipt_secret",
                &self.receipt_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("executor_id", &self.executor_id)
            .field(
                "executor_pubkey",
                &base64::prelude::BASE64_STANDARD
                    .encode(self.executor_signing_key.verifying_key().to_bytes()),
            )
            .finish()
    }
}

impl Default for TrustGateConfig {
    fn default() -> Self {
        let signing_key = Arc::new(SigningKey::generate(&mut OsRng));
        Self {
            trust_api_url: String::new(),     // Disabled by default
            enforce: false,                   // Log-only by default
            default_bracket: "C".to_string(), // Adequate — tenant profile
            receipt_secret: None,
            executor_id: format!("nucleus-executor/{}", uuid_hex(),),
            executor_signing_key: signing_key,
        }
    }
}

impl TrustGateConfig {
    /// Create from environment variables.
    ///
    /// Generates a fresh Ed25519 keypair at startup. The caller must invoke
    /// `register_executor_pubkey()` once the HTTP client is available to register
    /// the public key with the trust service before sending receipts.
    pub fn from_env() -> Self {
        let receipt_secret = std::env::var("TRUST_RECEIPT_SECRET")
            .ok()
            .and_then(|s| base64::prelude::BASE64_STANDARD.decode(&s).ok())
            .map(Arc::new);

        let executor_id = std::env::var("TRUST_EXECUTOR_ID")
            .unwrap_or_else(|_| format!("nucleus-executor/{}", uuid_hex()));

        let signing_key = Arc::new(SigningKey::generate(&mut OsRng));

        Self {
            trust_api_url: std::env::var("TRUST_API_URL").unwrap_or_default(),
            enforce: std::env::var("TRUST_GATE_ENFORCE")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
            default_bracket: std::env::var("TRUST_DEFAULT_BRACKET")
                .unwrap_or_else(|_| "C".to_string()),
            receipt_secret,
            executor_id,
            executor_signing_key: signing_key,
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
        // No attestation — look up by identity
        match lookup_reputation(config, &agent_identity, http_client).await {
            Ok(b) => b,
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
        enforce = config.enforce,
        "Trust gate: agent verified"
    );

    TrustVerification {
        agent_identity,
        bracket,
        profile_name,
        was_restricted: false, // Updated after enforce() is called
        enforced: config.enforce,
    }
}

/// Apply the trust profile to a PodSpec, scoping permissions.
///
/// In enforce mode, modifies the spec's policy by calling
/// `TrustProfile::enforce()` which performs the actual lattice meet/join
/// on capabilities and isolation. In log-only mode, computes the restriction
/// and updates `verification.was_restricted` without writing back to the spec.
pub fn apply_trust_enforcement(verification: &mut TrustVerification, spec: &mut PodSpec) {
    let reputation_score = bracket_to_reputation_score(&verification.bracket);

    // Build a continuous trust profile from the reputation score.
    // This uses smooth thresholds (no discrete bracket cliffs in enforcement).
    let profile = TrustProfile::from_reputation_score(reputation_score);

    // Resolve the current policy to get the base capability/isolation/obligations.
    // If resolution fails (unknown profile name), fall back to permissive so that
    // enforcement is still applied and the pod is bounded by the trust profile.
    let mut resolved = spec.spec.policy.resolve().unwrap_or_else(|e| {
        warn!(
            bracket = %verification.bracket,
            error = %e,
            "Trust gate: policy resolution failed, applying enforcement to permissive lattice"
        );
        PermissionLattice::permissive()
    });

    // Use the existing minimum_isolation as the current isolation floor, defaulting
    // to localhost (weakest) so that the trust profile's floor is always applied.
    let current_isolation = resolved
        .minimum_isolation
        .unwrap_or_else(IsolationLattice::localhost);

    // Perform actual lattice enforcement:
    //   capabilities = meet(current, profile.ceiling)   — never more permissive
    //   isolation    = join(current, profile.floor)     — never weaker
    //   obligations  = union(current, profile.mandatory) — obligations accumulate
    let result = profile.enforce(
        &resolved.capabilities,
        &current_isolation,
        &resolved.obligations,
    );

    verification.was_restricted = result.was_restricted;

    if verification.enforced {
        // Write the enforcement result back into the spec's policy.
        resolved.capabilities = result.capabilities;
        resolved.obligations = result.obligations;
        resolved.minimum_isolation = Some(result.isolation);
        spec.spec.policy = PolicySpec::Inline {
            lattice: Box::new(resolved),
        };

        info!(
            agent = %verification.agent_identity,
            bracket = %verification.bracket,
            profile = %result.profile_name,
            was_restricted = result.was_restricted,
            reputation_score,
            "Trust gate: enforcement applied to PodSpec"
        );
    } else {
        info!(
            agent = %verification.agent_identity,
            bracket = %verification.bracket,
            profile = %result.profile_name,
            was_restricted = result.was_restricted,
            reputation_score,
            "Trust gate: enforcement computed (log-only mode, spec not modified)"
        );
    }

    // Write metadata labels (always, regardless of enforce mode)
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
        format!("{reputation_score:.2}"),
    );
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

/// Map attestation bracket to a continuous reputation score for lattice enforcement.
///
/// These midpoint values are used as inputs to `TrustProfile::from_reputation_score()`,
/// which applies smooth per-operation thresholds rather than discrete profile steps.
fn bracket_to_reputation_score(bracket: &str) -> f64 {
    match bracket.to_uppercase().as_str() {
        "A" => 0.95,
        "B" => 0.82,
        "C" => 0.65,
        "D" => 0.45,
        _ => 0.2, // F or unknown
    }
}

/// Map discount factor to a continuous reputation score.
///
/// The trust API's discount_factor is in [0.5, 1.0] where lower = better.
/// We invert to [0.0, 1.0] where higher = better for portcullis scoring.
#[allow(dead_code)]
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
async fn lookup_reputation(
    config: &TrustGateConfig,
    identity: &str,
    client: &reqwest::Client,
) -> Result<String, String> {
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

    // Map discount factor to bracket
    // discount_factor is in [0.5, 1.0] — lower = better reputation
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

    Ok(bracket.to_string())
}

/// Generate a short hex token using OS randomness for executor IDs.
fn uuid_hex() -> String {
    let mut buf = [0u8; 16];
    // Use OsRng directly for the UUID bytes
    use rand::RngCore as _;
    OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Sign `body` with the executor's Ed25519 signing key and return the
/// base64-encoded signature (suitable for the `X-Nucleus-Executor-Sig` header).
fn ed25519_sign_body(key: &SigningKey, body: &[u8]) -> String {
    let sig = key.sign(body);
    base64::prelude::BASE64_STANDARD.encode(sig.to_bytes())
}

/// Register this executor's Ed25519 public key with the trust service.
///
/// Must be called once at startup, before any `report_receipt()` calls, so the
/// trust service knows the public key to verify against. Requires a valid
/// `receipt_secret` in the config (for the HMAC authentication on the registration
/// request itself).
#[allow(dead_code)] // Called at startup when trust gate is enabled
pub async fn register_executor_pubkey(config: &TrustGateConfig, http_client: &reqwest::Client) {
    if !config.is_enabled() {
        return;
    }
    let Some(secret) = &config.receipt_secret else {
        warn!(
            executor_id = %config.executor_id,
            "TRUST_RECEIPT_SECRET not set — skipping executor key registration; \
             trust-service will reject all receipts with 401"
        );
        return;
    };

    let pubkey_b64 = base64::prelude::BASE64_STANDARD
        .encode(config.executor_signing_key.verifying_key().to_bytes());
    let body = serde_json::json!({
        "executor_id": config.executor_id,
        "public_key_base64": pubkey_b64,
    });
    let body_bytes = serde_json::to_vec(&body).unwrap_or_default();
    let sig = hmac_sha256_hex(secret, &body_bytes);

    let url = format!("{}/api/executors/register", config.trust_api_url);
    match http_client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("X-Nucleus-Signature", sig)
        .body(body_bytes)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            info!(
                executor_id = %config.executor_id,
                pubkey = %pubkey_b64,
                "Trust gate: executor Ed25519 public key registered with trust service"
            );
        }
        Ok(resp) => {
            warn!(
                executor_id = %config.executor_id,
                status = resp.status().as_u16(),
                "Trust gate: executor key registration returned non-success"
            );
        }
        Err(e) => {
            warn!(
                executor_id = %config.executor_id,
                error = %e,
                "Trust gate: executor key registration failed"
            );
        }
    }
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
    /// SHA-256 content hash from the ExecutionReceipt (v1 scheme).
    /// Commits to pod_id, workspace/audit hashes, manifest, and all
    /// exposure fields so they cannot be swapped post-hoc.
    /// Used to pre-register the receipt with the ledger before calling
    /// session-complete, enabling cryptographic binding verification.
    pub v1_content_hash: String,
}

/// Report an execution receipt to the Coproduct Trust API.
///
/// This is the receipt-to-trust bridge: cryptographically attested execution
/// results feed back into reputation scoring. Receipt-backed data is worth
/// more than hook-backed data because it's third-party verified by the sandbox.
///
/// Called from `get_receipt()` after the execution receipt is computed.
/// Runs asynchronously — never blocks receipt delivery.
pub async fn report_receipt(
    config: &TrustGateConfig,
    report: &ReceiptReport,
    http_client: &reqwest::Client,
) {
    if !config.is_enabled() {
        return;
    }

    // Step 1: Pre-register the receipt hash with the ledger BEFORE calling
    // session-complete.  This is the required protocol:
    //   (a) nucleus-node registers hash → ledger records it as unconsumed
    //   (b) session-complete carries the same hash → ledger consumes it
    // Only after successful consumption does the trust API allow a
    // SandboxAttested tool upgrade.  Without this step the receipt ledger is
    // always empty and the hash-verification path is dead code.
    if !report.v1_content_hash.is_empty() {
        let register_url = format!("{}/api/trust/receipts/register", config.trust_api_url);

        // Compute the exposure hash that the trust service will store and
        // verify at consume time.  Sorted labels + canonical JSON gives a
        // deterministic byte sequence regardless of insertion order.
        let mut sorted_labels = report.observed_exposure_labels.clone();
        sorted_labels.sort();
        let register_body = serde_json::json!({
            "v1_content_hash": report.v1_content_hash,
            "session_id": report.session_id,
            "agent_id": report.agent_id,
            "observed_exposure_labels": sorted_labels,
            "observed_risk_tier": report.observed_risk_tier,
            "uninhabitable_reached": report.uninhabitable_reached,
        });
        let register_bytes = serde_json::to_vec(&register_body).unwrap_or_default();
        let register_sig = ed25519_sign_body(&config.executor_signing_key, &register_bytes);

        let mut reg_req = http_client
            .post(&register_url)
            .header("Content-Type", "application/json")
            .header("X-Nucleus-Executor-Id", &config.executor_id)
            .header("X-Nucleus-Executor-Sig", &register_sig)
            .timeout(std::time::Duration::from_secs(5))
            .body(register_bytes.clone());

        if let Some(secret) = &config.receipt_secret {
            let sig = hmac_sha256_hex(secret, &register_bytes);
            reg_req = reg_req.header("X-Nucleus-Signature", sig);
        }

        match reg_req.send().await {
            Ok(resp) if resp.status().is_success() => {
                debug!(
                    session = %report.session_id,
                    v1_content_hash = %report.v1_content_hash,
                    "Trust gate: receipt pre-registered with ledger"
                );
            }
            Ok(resp) => {
                warn!(
                    session = %report.session_id,
                    status = resp.status().as_u16(),
                    "Trust gate: receipt registration returned non-success"
                );
            }
            Err(e) => {
                warn!(
                    session = %report.session_id,
                    error = %e,
                    "Trust gate: receipt registration failed (non-blocking)"
                );
            }
        }
    }

    let url = format!("{}/api/trust/session-complete", config.trust_api_url);

    // Compute a continuous session score from observed execution metrics.
    // This replaces the binary success/failure with a value that reflects
    // actual quality signals, enabling the trust store's weighted recency
    // computation to work over a real continuous range.
    let score = compute_session_score(report);

    // Include the receipt hash and all exposure fields so the trust service
    // can verify that received labels are cryptographically bound to the
    // specific ExecutionReceipt produced by this sandbox run.
    let mut sorted_labels_sc = report.observed_exposure_labels.clone();
    sorted_labels_sc.sort();
    let body = serde_json::json!({
        "session_id": report.session_id,
        "agent_id": report.agent_id,
        "success": report.success,
        "score": score,
        "had_issues": !report.success || report.uninhabitable_reached,
        "hook_event_name": "ExecutionReceipt",
        "v1_content_hash": report.v1_content_hash,
        "observed_exposure_labels": sorted_labels_sc,
        "observed_risk_tier": report.observed_risk_tier,
        "uninhabitable_reached": report.uninhabitable_reached,
    });

    let body_bytes = serde_json::to_vec(&body).unwrap_or_default();

    let ed25519_sig = ed25519_sign_body(&config.executor_signing_key, &body_bytes);

    let mut req = http_client
        .post(&url)
        .header("Content-Type", "application/json")
        .header("X-Nucleus-Executor-Id", &config.executor_id)
        .header("X-Nucleus-Executor-Sig", &ed25519_sig)
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
        let ingest_ed25519_sig = ed25519_sign_body(&config.executor_signing_key, &ingest_bytes);

        let mut ingest_req = http_client
            .post(&ingest_url)
            .header("Content-Type", "application/json")
            .header("X-Nucleus-Executor-Id", &config.executor_id)
            .header("X-Nucleus-Executor-Sig", &ingest_ed25519_sig)
            .timeout(std::time::Duration::from_secs(5))
            .body(ingest_bytes.clone());

        if let Some(secret) = &config.receipt_secret {
            let sig = hmac_sha256_hex(secret, &ingest_bytes);
            ingest_req = ingest_req.header("X-Nucleus-Signature", sig);
        }

        let _ = ingest_req.send().await;
    }
}

/// Compute a continuous reputation score in [0.0, 1.0] from observed session metrics.
///
/// The score factors in:
/// - Execution success (primary signal)
/// - Observed risk tier from MCP mediator (ground-truth exposure, not claims)
/// - Whether the uninhabitable state was reached (severe penalty)
/// - Tool call count (efficiency signal)
/// - Execution cost (efficiency signal)
///
/// This ensures the trust store receives continuous values that make the
/// weighted-recency reputation computation meaningful, not just two possible values.
fn compute_session_score(report: &ReceiptReport) -> f64 {
    // Base score: success is the primary signal
    let base = if report.success { 0.75 } else { 0.20 };

    // Observed risk tier from the MCP mediator's actual interception —
    // ground truth, not from tool description parsing or claims.
    let risk_adjustment = match report.observed_risk_tier.as_str() {
        "safe" => 0.10,
        "low" => 0.05,
        "medium" => -0.05,
        "critical" => -0.20,
        _ => 0.0,
    };

    // Uninhabitable state is a severe negative signal (exfiltration vector activated)
    let uninhabitable_penalty = if report.uninhabitable_reached {
        -0.25
    } else {
        0.0
    };

    // Tool call count: excessive calls suggest thrashing or poor task decomposition
    let tool_factor = if report.tool_call_count == 0 {
        0.05 // Efficient: completed without tool use (or very simple)
    } else if report.tool_call_count <= 50 {
        0.0 // Normal range
    } else if report.tool_call_count <= 200 {
        -0.05 // Higher than typical — possible thrashing
    } else {
        -0.10 // Excessive — strong signal of a runaway session
    };

    // Cost: very high cost signals either a complex/expensive session or runaway spending
    let cost_factor = if report.cost_usd <= 0.10 {
        0.05 // Low cost, efficient
    } else if report.cost_usd <= 1.00 {
        0.0 // Normal range
    } else if report.cost_usd <= 5.00 {
        -0.05 // High cost
    } else {
        -0.10 // Very high cost
    };

    let total: f64 = base + risk_adjustment + uninhabitable_penalty + tool_factor + cost_factor;
    total.clamp(0.0, 1.0)
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier as _;

    #[test]
    fn test_config_from_env_defaults() {
        let config = TrustGateConfig::default();
        assert!(!config.is_enabled());
        assert!(!config.enforce);
        assert_eq!(config.default_bracket, "C");
    }

    /// Executor config always carries a signing key and a non-empty executor_id.
    #[test]
    fn test_config_default_has_executor_identity() {
        let config = TrustGateConfig::default();
        assert!(!config.executor_id.is_empty(), "executor_id must be set");
        assert!(
            config.executor_id.starts_with("nucleus-executor/"),
            "default executor_id must have expected prefix"
        );
        // Verify the public key is accessible
        let _pubkey = config.executor_signing_key.verifying_key();
    }

    /// report_receipt() injects X-Nucleus-Executor-Id and X-Nucleus-Executor-Sig.
    ///
    /// This test verifies the signing helper used by report_receipt() produces
    /// a signature that can be verified against the executor's public key — the
    /// same verification the trust service performs on every receipt.
    #[test]
    fn test_ed25519_sign_body_is_verifiable() {
        let config = TrustGateConfig::default();
        let body = b"{\"session_id\":\"test-sess\",\"success\":true}";

        // Produce the signature the way report_receipt() does
        let sig_b64 = ed25519_sign_body(&config.executor_signing_key, body);

        // Decode and verify using the public key (mirrors trust-service verification)
        let sig_bytes = base64::prelude::BASE64_STANDARD
            .decode(&sig_b64)
            .expect("signature must be valid base64");
        let sig =
            ed25519_dalek::Signature::from_slice(&sig_bytes).expect("signature must be 64 bytes");
        let pubkey = config.executor_signing_key.verifying_key();
        pubkey
            .verify(body, &sig)
            .expect("Ed25519 signature must verify against the executor's public key");
    }

    /// Different bodies produce different signatures (no trivial signature reuse).
    #[test]
    fn test_ed25519_sign_body_distinct_per_body() {
        let config = TrustGateConfig::default();
        let sig1 = ed25519_sign_body(&config.executor_signing_key, b"body-one");
        let sig2 = ed25519_sign_body(&config.executor_signing_key, b"body-two");
        assert_ne!(
            sig1, sig2,
            "different bodies must produce different signatures"
        );
    }

    /// The executor_id and signing key fields are present in the config that
    /// report_receipt() will use — asserts the outgoing request would carry both headers.
    #[test]
    fn test_config_provides_both_executor_headers() {
        let config = TrustGateConfig {
            trust_api_url: "https://trust.example.com".to_string(),
            enforce: true,
            default_bracket: "C".to_string(),
            receipt_secret: Some(Arc::new(b"test-secret".to_vec())),
            executor_id: "spiffe://test/nucleus-node-123".to_string(),
            executor_signing_key: Arc::new(SigningKey::generate(&mut OsRng)),
        };

        // Simulate what report_receipt() does: build body, produce both header values
        let body = b"{\"session_id\":\"abc\",\"success\":true}";
        let executor_id_header = config.executor_id.clone();
        let executor_sig_header = ed25519_sign_body(&config.executor_signing_key, body);

        // Both header values must be non-empty
        assert!(
            !executor_id_header.is_empty(),
            "X-Nucleus-Executor-Id must be non-empty"
        );
        assert!(
            !executor_sig_header.is_empty(),
            "X-Nucleus-Executor-Sig must be non-empty"
        );

        // The signature must be verifiable
        let sig_bytes = base64::prelude::BASE64_STANDARD
            .decode(&executor_sig_header)
            .unwrap();
        let sig = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        config
            .executor_signing_key
            .verifying_key()
            .verify(body, &sig)
            .expect("executor sig header must verify against executor signing key");
    }

    #[test]
    fn test_apply_trust_enforcement_restricts_low_bracket() {
        use nucleus_spec::{PodSpec, PodSpecInner, PolicySpec};

        // Build a PodSpec with a permissive inline policy
        let lattice = portcullis::PermissionLattice::permissive();
        let spec_inner = PodSpecInner {
            work_dir: std::path::PathBuf::from("/tmp"),
            timeout_seconds: 3600,
            policy: PolicySpec::Inline {
                lattice: Box::new(lattice),
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
            agent_identity: "test-agent".to_string(),
            bracket: "F".to_string(), // Lowest bracket — airgapped profile
            profile_name: "airgapped".to_string(),
            was_restricted: false,
            enforced: true,
        };

        apply_trust_enforcement(&mut verification, &mut spec);

        // Enforcement should have run and flagged restriction
        assert!(
            verification.was_restricted,
            "airgapped bracket should restrict a permissive policy"
        );

        // The policy should now be Inline (written back)
        match &spec.spec.policy {
            PolicySpec::Inline { lattice } => {
                // Airgapped profile blocks git_push and write_files
                assert_eq!(
                    lattice.capabilities.git_push,
                    portcullis::CapabilityLevel::Never,
                    "git_push must be blocked after airgapped enforcement"
                );
                assert_eq!(
                    lattice.capabilities.write_files,
                    portcullis::CapabilityLevel::Never,
                    "write_files must be blocked after airgapped enforcement"
                );
                // Isolation floor must be set (microVM)
                assert!(
                    lattice.minimum_isolation.is_some(),
                    "minimum_isolation must be set after enforcement"
                );
            }
            PolicySpec::Profile { name } => {
                panic!("Expected Inline policy after enforcement, got Profile {name}");
            }
        }

        // Metadata labels must be written
        assert_eq!(
            spec.metadata
                .labels
                .get("trust.coproduct.one/bracket")
                .map(String::as_str),
            Some("F")
        );
        assert_eq!(
            spec.metadata
                .labels
                .get("trust.coproduct.one/enforced")
                .map(String::as_str),
            Some("true")
        );
        assert!(
            spec.metadata
                .labels
                .contains_key("trust.coproduct.one/reputation-score"),
            "reputation-score label must be present"
        );
    }

    #[test]
    fn test_apply_trust_enforcement_log_only_does_not_modify_policy() {
        use nucleus_spec::{PodSpec, PodSpecInner, PolicySpec};

        let lattice = portcullis::PermissionLattice::permissive();
        let spec_inner = PodSpecInner {
            work_dir: std::path::PathBuf::from("/tmp"),
            timeout_seconds: 3600,
            policy: PolicySpec::Inline {
                lattice: Box::new(lattice.clone()),
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
            agent_identity: "test-agent".to_string(),
            bracket: "F".to_string(),
            profile_name: "airgapped".to_string(),
            was_restricted: false,
            enforced: false, // log-only mode
        };

        apply_trust_enforcement(&mut verification, &mut spec);

        // was_restricted should be computed even in log-only mode
        assert!(
            verification.was_restricted,
            "was_restricted must be set even in log-only mode"
        );

        // The policy must NOT have been written back in log-only mode
        match &spec.spec.policy {
            PolicySpec::Inline { lattice: stored } => {
                // The permissive policy should be unchanged (git_push still allowed)
                assert_eq!(
                    stored.capabilities.git_push,
                    portcullis::CapabilityLevel::Always,
                    "log-only mode must not modify the spec's capabilities"
                );
            }
            PolicySpec::Profile { .. } => {
                // Profile is also acceptable (was not changed)
            }
        }
    }

    #[test]
    fn test_compute_session_score_continuous() {
        // Verify the score is continuous across all combinations and stays in [0, 1]
        let tiers = &["safe", "low", "medium", "critical", "unknown"];
        for &tier in tiers {
            for &success in &[true, false] {
                for &uninhabitable in &[true, false] {
                    for &tools in &[0u64, 10, 100, 500] {
                        for &cost in &[0.01_f64, 0.5, 2.0, 10.0] {
                            let report = ReceiptReport {
                                agent_id: "a".to_string(),
                                session_id: "s".to_string(),
                                success,
                                cost_usd: cost,
                                tool_call_count: tools,
                                workspace_hash: String::new(),
                                audit_tail_hash: String::new(),
                                trust_bracket: None,
                                trust_profile: None,
                                attested_execution: false,
                                observed_exposure_labels: vec![],
                                observed_risk_tier: tier.to_string(),
                                uninhabitable_reached: uninhabitable,
                                v1_content_hash: String::new(),
                            };
                            let score = compute_session_score(&report);
                            assert!(
                                (0.0..=1.0).contains(&score),
                                "score {score} out of [0,1] for tier={tier} success={success} \
                                 uninhabitable={uninhabitable} tools={tools} cost={cost}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_compute_session_score_ordering() {
        // A successful safe session scores higher than a failed critical one
        let good = ReceiptReport {
            agent_id: "a".to_string(),
            session_id: "s".to_string(),
            success: true,
            cost_usd: 0.05,
            tool_call_count: 10,
            workspace_hash: String::new(),
            audit_tail_hash: String::new(),
            trust_bracket: None,
            trust_profile: None,
            attested_execution: false,
            observed_exposure_labels: vec![],
            observed_risk_tier: "safe".to_string(),
            uninhabitable_reached: false,
            v1_content_hash: String::new(),
        };
        let bad = ReceiptReport {
            agent_id: "a".to_string(),
            session_id: "s".to_string(),
            success: false,
            cost_usd: 10.0,
            tool_call_count: 500,
            workspace_hash: String::new(),
            audit_tail_hash: String::new(),
            trust_bracket: None,
            trust_profile: None,
            attested_execution: false,
            observed_exposure_labels: vec![],
            observed_risk_tier: "critical".to_string(),
            uninhabitable_reached: true,
            v1_content_hash: String::new(),
        };
        assert!(
            compute_session_score(&good) > compute_session_score(&bad),
            "Good session must score higher than bad session"
        );
        // Scores must differ (not both 0 or both 1)
        assert_ne!(
            compute_session_score(&good),
            compute_session_score(&bad),
            "Scores must be distinct across very different sessions"
        );
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
            executor_id: "spiffe://test/node-1".to_string(),
            executor_signing_key: Arc::new(SigningKey::generate(&mut OsRng)),
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

        // This mirrors the body construction in report_receipt()
        let body = serde_json::json!({
            "session_id": "sess-001",
            "agent_id": "agent@example.com",
            "success": true,
            "score": 0.85_f64,
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
}
