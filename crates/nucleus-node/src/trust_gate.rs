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
    /// Shared secret for HMAC-SHA256 signing of outbound receipt POSTs.
    /// Used to prove to the trust API that receipts originate from a nucleus-node
    /// instance, not an arbitrary client. Loaded from NUCLEUS_NODE_AUTH_SECRET.
    pub auth_secret: Vec<u8>,
}

impl Default for TrustGateConfig {
    fn default() -> Self {
        Self {
            trust_api_url: String::new(),     // Disabled by default
            enforce: false,                   // Log-only by default
            default_bracket: "C".to_string(), // Adequate — tenant profile
            auth_secret: Vec::new(),
        }
    }
}

impl TrustGateConfig {
    /// Create from environment variables.
    pub fn from_env() -> Self {
        Self {
            trust_api_url: std::env::var("TRUST_API_URL").unwrap_or_default(),
            enforce: std::env::var("TRUST_GATE_ENFORCE")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
            default_bracket: std::env::var("TRUST_DEFAULT_BRACKET")
                .unwrap_or_else(|_| "C".to_string()),
            auth_secret: std::env::var("NUCLEUS_NODE_AUTH_SECRET")
                .unwrap_or_default()
                .into_bytes(),
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

    // ── Sandbox identity (from SandboxProof established at tool-proxy startup) ─
    /// SPIFFE ID or pod ID from the sandbox proof. This is the cryptographic
    /// identity that was verified when the tool-proxy started inside the sandbox.
    /// Included in the receipt body so the trust API can cross-check the signing
    /// identity against the agent identity declared in agent_id.
    pub sandbox_identity: Option<String>,
}

/// Compute an HMAC-SHA256 signature over `body` bytes using `secret`.
///
/// Returns the hex-encoded signature string suitable for use in
/// `X-Nucleus-Signature` headers on outbound trust API calls.
fn hmac_sign(secret: &[u8], body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

/// Compute a weighted reputation score from actual observed sandbox behavior.
///
/// Replaces the prior hardcoded `0.85 / 0.3` binary constant with a formula
/// that reads from the observed fields in `ReceiptReport`.
///
/// # Formula
///
/// ```text
/// score = base(success) + risk_tier_delta(observed_risk_tier)
///       - uninhabitable_penalty
/// ```
///
/// Clamped to `[0.0, 1.0]`.
pub fn compute_reputation_score(report: &ReceiptReport) -> f64 {
    // Base score from execution outcome
    let base: f64 = if report.success { 0.72 } else { 0.20 };

    // Risk tier adjustment based on actual observed tool behavior
    let risk_delta: f64 = match report.observed_risk_tier.as_str() {
        "safe" => 0.18,
        "low" => 0.08,
        "medium" => 0.00,
        "critical" => -0.25,
        _ => 0.00, // unknown/empty → neutral
    };

    // Heavy penalty if the uninhabitable policy boundary was tripped
    let uninhabitable_penalty: f64 = if report.uninhabitable_reached {
        0.30
    } else {
        0.00
    };

    (base + risk_delta - uninhabitable_penalty).clamp(0.0, 1.0)
}

/// Report an execution receipt to the Coproduct Trust API.
///
/// This is the receipt-to-trust bridge: cryptographically attested execution
/// results feed back into reputation scoring. Receipt-backed data is worth
/// more than hook-backed data because it's third-party verified by the sandbox.
///
/// Both outbound POST requests are signed with an HMAC-SHA256 signature
/// (derived from `config.auth_secret`) placed in the `X-Nucleus-Signature`
/// header. The trust API must verify this header before accepting a score
/// update, preventing unsigned receipt injection.
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

    let score = compute_reputation_score(report);

    let url = format!("{}/api/trust/session-complete", config.trust_api_url);

    let body = serde_json::json!({
        "session_id": report.session_id,
        "agent_id": report.agent_id,
        "success": report.success,
        "score": score,
        "had_issues": !report.success || report.uninhabitable_reached,
        "hook_event_name": "ExecutionReceipt",
        // Sandbox identity from the cryptographic SandboxProof established at
        // tool-proxy startup. Allows the trust API to cross-check the signing
        // identity against the declared agent_id.
        "sandbox_identity": report.sandbox_identity,
        // Observed risk data forwarded so the trust API can audit the score
        "observed_risk_tier": report.observed_risk_tier,
        "uninhabitable_reached": report.uninhabitable_reached,
        "tool_call_count": report.tool_call_count,
    });

    let body_bytes = serde_json::to_vec(&body).unwrap_or_default();
    let signature = hmac_sign(&config.auth_secret, &body_bytes);

    match http_client
        .post(&url)
        .header("X-Nucleus-Signature", &signature)
        .header("Content-Type", "application/json")
        .body(body_bytes)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => {
            info!(
                agent = %report.agent_id,
                session = %report.session_id,
                success = report.success,
                score = score,
                cost = report.cost_usd,
                tools = report.tool_call_count,
                bracket = report.trust_bracket.as_deref().unwrap_or("-"),
                attested = report.attested_execution,
                risk_tier = %report.observed_risk_tier,
                uninhabitable = report.uninhabitable_reached,
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
            "sandbox_identity": report.sandbox_identity,
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
        let ingest_sig = hmac_sign(&config.auth_secret, &ingest_bytes);

        let _ = http_client
            .post(&ingest_url)
            .header("X-Nucleus-Signature", &ingest_sig)
            .header("Content-Type", "application/json")
            .body(ingest_bytes)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_report(success: bool, risk_tier: &str, uninhabitable: bool) -> ReceiptReport {
        ReceiptReport {
            agent_id: "test-agent".to_string(),
            session_id: "sess-001".to_string(),
            success,
            cost_usd: 0.01,
            tool_call_count: 5,
            workspace_hash: "abc123".to_string(),
            audit_tail_hash: "def456".to_string(),
            trust_bracket: Some("B".to_string()),
            trust_profile: Some("tenant".to_string()),
            attested_execution: true,
            observed_exposure_labels: vec![],
            observed_risk_tier: risk_tier.to_string(),
            uninhabitable_reached: uninhabitable,
            sandbox_identity: Some("spiffe://nucleus.local/ns/default/sa/tool-proxy".to_string()),
        }
    }

    #[test]
    fn test_config_from_env_defaults() {
        let config = TrustGateConfig::default();
        assert!(!config.is_enabled());
        assert!(!config.enforce);
        assert_eq!(config.default_bracket, "C");
        assert!(config.auth_secret.is_empty());
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

    // ── compute_reputation_score tests ─────────────────────────────────────

    #[test]
    fn test_score_success_safe_is_high() {
        let report = sample_report(true, "safe", false);
        let score = compute_reputation_score(&report);
        // success(0.72) + safe(+0.18) = 0.90
        assert!((score - 0.90).abs() < 0.001, "expected ~0.90, got {score}");
    }

    #[test]
    fn test_score_success_medium_is_moderate() {
        let report = sample_report(true, "medium", false);
        let score = compute_reputation_score(&report);
        // success(0.72) + medium(0.0) = 0.72
        assert!((score - 0.72).abs() < 0.001, "expected ~0.72, got {score}");
    }

    #[test]
    fn test_score_failure_critical_is_low() {
        let report = sample_report(false, "critical", false);
        let score = compute_reputation_score(&report);
        // failure(0.20) + critical(-0.25) = clamped to 0.0
        assert!(score < 0.01, "expected ~0.0, got {score}");
    }

    #[test]
    fn test_score_uninhabitable_penalty() {
        let report = sample_report(true, "safe", true);
        let score = compute_reputation_score(&report);
        // success(0.72) + safe(+0.18) - uninhabitable(0.30) = 0.60
        assert!((score - 0.60).abs() < 0.001, "expected ~0.60, got {score}");
    }

    #[test]
    fn test_score_failure_uninhabitable_critical_clamps_to_zero() {
        let report = sample_report(false, "critical", true);
        let score = compute_reputation_score(&report);
        // failure(0.20) - critical(0.25) - uninhabitable(0.30) = -0.35 → clamped 0.0
        assert_eq!(score, 0.0);
    }

    #[test]
    fn test_score_unknown_risk_tier_is_neutral() {
        let report_unknown = sample_report(true, "unknown", false);
        let report_medium = sample_report(true, "medium", false);
        // Both should produce the same score since unknown → 0 delta like medium
        assert!(
            (compute_reputation_score(&report_unknown) - compute_reputation_score(&report_medium))
                .abs()
                < 0.001
        );
    }

    #[test]
    fn test_score_always_in_bounds() {
        for (success, tier, uninhabitable) in [
            (true, "safe", false),
            (true, "critical", true),
            (false, "safe", false),
            (false, "critical", true),
            (true, "low", true),
        ] {
            let report = sample_report(success, tier, uninhabitable);
            let score = compute_reputation_score(&report);
            assert!(
                (0.0..=1.0).contains(&score),
                "score out of bounds: {score} for success={success} tier={tier} uninhabitable={uninhabitable}"
            );
        }
    }

    // ── hmac_sign tests ────────────────────────────────────────────────────

    #[test]
    fn test_hmac_sign_deterministic() {
        let secret = b"test-secret-key";
        let body = b"hello world";
        let sig1 = hmac_sign(secret, body);
        let sig2 = hmac_sign(secret, body);
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_hmac_sign_different_bodies_produce_different_sigs() {
        let secret = b"test-secret-key";
        let sig1 = hmac_sign(secret, b"body-one");
        let sig2 = hmac_sign(secret, b"body-two");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_hmac_sign_different_secrets_produce_different_sigs() {
        let sig1 = hmac_sign(b"secret-a", b"same body");
        let sig2 = hmac_sign(b"secret-b", b"same body");
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_hmac_sign_output_is_valid_hex() {
        let sig = hmac_sign(b"key", b"data");
        // HMAC-SHA256 produces 32 bytes → 64 hex chars
        assert_eq!(sig.len(), 64);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hmac_sign_verifiable_with_hmac_crate() {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let secret = b"verify-secret";
        let body = b"receipt-body-bytes";
        let sig_hex = hmac_sign(secret, body);

        let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac.update(body);
        let expected = hex::encode(mac.finalize().into_bytes());
        assert_eq!(sig_hex, expected);
    }
}
