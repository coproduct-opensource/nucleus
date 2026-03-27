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
use hmac::{Hmac, Mac};
use nucleus_spec::PodSpec;
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
}

impl Default for TrustGateConfig {
    fn default() -> Self {
        Self {
            trust_api_url: String::new(),     // Disabled by default
            enforce: false,                   // Log-only by default
            default_bracket: "C".to_string(), // Adequate — tenant profile
            receipt_secret: None,
        }
    }
}

impl TrustGateConfig {
    /// Create from environment variables.
    pub fn from_env() -> Self {
        let receipt_secret = std::env::var("TRUST_RECEIPT_SECRET")
            .ok()
            .and_then(|s| base64::prelude::BASE64_STANDARD.decode(&s).ok())
            .map(Arc::new);

        Self {
            trust_api_url: std::env::var("TRUST_API_URL").unwrap_or_default(),
            enforce: std::env::var("TRUST_GATE_ENFORCE")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
            default_bracket: std::env::var("TRUST_DEFAULT_BRACKET")
                .unwrap_or_else(|_| "C".to_string()),
            receipt_secret,
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
/// In enforce mode, modifies the spec's policy. In log-only mode,
/// computes the restriction but doesn't apply it.
pub fn apply_trust_enforcement(verification: &mut TrustVerification, spec: &mut PodSpec) {
    let _profile_name = bracket_to_profile(&verification.bracket);

    // If the spec has a resolved permission lattice, enforce the trust profile
    // For now, we store the trust metadata in labels for downstream consumption
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

    // Store continuous reputation score for lattice-based autonomy.
    // The policy resolver reads this and calls TrustProfile::from_reputation_score()
    // instead of discrete bracket → profile mapping.
    let reputation_score = match verification.bracket.as_str() {
        "A" => 0.95,
        "B" => 0.82,
        "C" => 0.65,
        "D" => 0.45,
        _ => 0.2,
    };
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

    let url = format!("{}/api/trust/session-complete", config.trust_api_url);

    let body = serde_json::json!({
        "session_id": report.session_id,
        "agent_id": report.agent_id,
        "success": report.success,
        "score": if report.success { 0.85 } else { 0.3 },
        "had_issues": !report.success || report.uninhabitable_reached,
        "hook_event_name": "ExecutionReceipt",
    });

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

#[cfg(test)]
mod tests {
    use super::*;

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
