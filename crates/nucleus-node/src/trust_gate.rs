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

use std::path::Path;
use std::sync::Arc;

use base64::Engine as _;
use ed25519_dalek::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _};
use ed25519_dalek::{Signer as _, SigningKey};
use hmac::{digest::KeyInit, Hmac, Mac};
use nucleus_spec::{PodSpec, PolicySpec};
use portcullis::enforcement::{require_isolation, BackendCapability};
use portcullis::{IsolationLattice, PermissionLattice, TrustProfile};

use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tracing::{debug, error, info, warn};

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
            trust_api_url: String::new(),     // Disabled by default
            enforce: false,                   // Log-only by default
            default_bracket: "C".to_string(), // Adequate — tenant profile
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

/// Filename (under `state_dir`) holding the persisted executor signing key.
const EXECUTOR_KEY_FILE: &str = "executor_signing_key.der";

/// Filename (under `state_dir`) holding the persisted **task-issuer** signing
/// key — the root that signs live-path session capability tokens. DISTINCT from
/// [`EXECUTOR_KEY_FILE`] so the two trust roles never share a key.
const TASK_ISSUER_KEY_FILE: &str = "task_issuer_signing_key.der";

/// Filename (under `state_dir`) holding the persisted **approval** signing
/// key — the key whose signatures the guest tool-proxy accepts on
/// `/v1/approve`, verified against the PUBLIC half delivered as
/// `nucleus.approval_pubkeys`. DISTINCT from the other two role keys: the
/// approval authority must not double as the executor's receipt identity or
/// the task-token root.
const APPROVAL_SIGNING_KEY_FILE: &str = "approval_signing_key.der";

/// Generate a fresh Ed25519 signing key from the OS CSPRNG.
///
/// Samples 32 raw bytes via `rand_core 0.6`'s `fill_bytes` and feeds
/// `SigningKey::from_bytes` — equivalent to `SigningKey::generate(&mut rng)` but
/// avoids the cross-version `CryptoRng`/`rand_core` trait-identity mismatch that
/// breaks `generate` when multiple rand_core majors coexist (dalek 3 tracks a
/// newer rand_core than the 0.6 we depend on). Mirrors the pattern in
/// `nucleus-verifier-service::signing::VerifierSigner::random`.
fn generate_signing_key() -> SigningKey {
    use rand_core::RngCore as _;
    let mut seed = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

/// Load the per-executor Ed25519 signing key from `state_dir`, creating and
/// persisting a fresh one on first run.
///
/// Without persistence, every node restart mints a brand-new identity, which
/// silently invalidates any prior `register_executor_pubkey` enrollment — the
/// threat-model claim that registration survives an HMAC compromise is only
/// true if the executor's signing key is stable across restarts (#1630).
///
/// The key is stored as PKCS#8 DER (same encoding as
/// [`nucleus_lineage::LocalIssuer`]) with `0o400` permissions on Unix. A
/// missing file is created; a present-but-unreadable file is logged and
/// replaced rather than crashing the node (fail-open on *availability*, not on
/// identity — a corrupt key was never a valid enrollment anyway).
pub fn load_or_create_signing_key(state_dir: &Path) -> SigningKey {
    load_or_create_key_file(state_dir, EXECUTOR_KEY_FILE, "executor signing key")
}

/// Load the dedicated **task-issuer** Ed25519 signing key from `state_dir`,
/// creating and persisting a fresh one on first run.
///
/// Uses the identical persistence discipline as
/// [`load_or_create_signing_key`] (PKCS#8 DER, `0o400`, fail-open on
/// availability) but a DISTINCT file ([`TASK_ISSUER_KEY_FILE`]). This is the
/// root that signs live-path session capability tokens; keeping it separate
/// from the executor key enforces role separation — a compromise or rotation
/// of one identity does not implicate the other, and the executor key (which
/// is also the executor's receipt identity) never doubles as a token root.
pub fn load_or_create_task_issuer_signing_key(state_dir: &Path) -> SigningKey {
    load_or_create_key_file(state_dir, TASK_ISSUER_KEY_FILE, "task issuer signing key")
}

/// Load the dedicated **approval** Ed25519 signing key from `state_dir`,
/// creating and persisting a fresh one on first run.
///
/// Same persistence discipline as the other role keys, and persistence
/// matters MORE here: a running pod verifies approvals against the public key
/// it booted with, so a node that minted a fresh key on every restart could
/// no longer approve anything for pods launched before the restart.
pub fn load_or_create_approval_signing_key(state_dir: &Path) -> SigningKey {
    load_or_create_key_file(state_dir, APPROVAL_SIGNING_KEY_FILE, "approval signing key")
}

/// Shared implementation for the persisted per-node Ed25519 keys. `filename` is
/// the basename under `state_dir`; `label` is used only in log lines.
fn load_or_create_key_file(state_dir: &Path, filename: &str, label: &str) -> SigningKey {
    let path = state_dir.join(filename);

    if path.exists() {
        match std::fs::read(&path) {
            Ok(bytes) => match SigningKey::from_pkcs8_der(&bytes) {
                Ok(key) => {
                    debug!(path = %path.display(), "loaded persisted {label}");
                    return key;
                }
                Err(e) => warn!(
                    path = %path.display(),
                    error = %e,
                    "{label} file is unreadable; regenerating"
                ),
            },
            Err(e) => warn!(
                path = %path.display(),
                error = %e,
                "failed to read {label} file; regenerating"
            ),
        }
    }

    let key = generate_signing_key();
    match key.to_pkcs8_der() {
        Ok(der) => {
            if let Err(e) = write_key_file(&path, der.as_bytes()) {
                warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to persist {label}; identity will not survive restart"
                );
            } else {
                info!(path = %path.display(), "generated and persisted new {label}");
            }
        }
        Err(e) => warn!(error = %e, "failed to PKCS#8-encode {label}; not persisting"),
    }
    key
}

/// Write `bytes` to `path`, restricting permissions to owner-read-only (`0o400`)
/// on Unix so the private key is not world/group readable.
fn write_key_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))?;
    }
    Ok(())
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
            enforce: std::env::var("TRUST_GATE_ENFORCE")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
            default_bracket: std::env::var("TRUST_DEFAULT_BRACKET")
                .unwrap_or_else(|_| "C".to_string()),
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
#[tracing::instrument(skip_all, fields(boot.stage = "trust_gate.verify"))]
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

    // ── Backend-enforceability gate ──────────────────────────────────────
    // The trust profile chose a REQUIRED isolation posture (join of the pod's
    // current isolation with the profile floor). Clamp it to what THIS node's
    // backend can actually enforce: on Firecracker this is the full lattice (a
    // no-op); on a host that can't enforce a level (e.g. Apple VZ exposes no
    // host-side egress allowlist) the posture is strengthened UP — never
    // weakened — and the gap is recorded. The sandbox is then configured from
    // the ENFORCED posture, so a pod never runs believing it has a guarantee
    // the platform doesn't actually deliver.
    let backend = isolation_backend();
    let isolation = match require_isolation(enforcement.isolation, backend) {
        Ok(enforced) => {
            spec.metadata.labels.insert(
                "isolation.coproduct.one/requested".to_string(),
                enforced.requested.to_string(),
            );
            spec.metadata.labels.insert(
                "isolation.coproduct.one/enforced".to_string(),
                enforced.enforced.to_string(),
            );
            spec.metadata.labels.insert(
                "isolation.coproduct.one/backend".to_string(),
                backend.name.to_string(),
            );
            if enforced.was_strengthened() {
                warn!(
                    agent = %verification.agent_identity,
                    backend = backend.name,
                    requested = %enforced.requested,
                    enforced = %enforced.enforced,
                    "Trust gate: isolation strengthened to the backend-enforceable posture"
                );
            }
            enforced.enforced
        }
        Err(err) => {
            // Unreachable for the built-in backends (their top level is always
            // enforceable), but a misconfigured custom backend could reach here.
            // Fail safe: keep the strongest posture available — the requested
            // one — and surface the error rather than silently under-enforcing.
            error!(
                agent = %verification.agent_identity,
                backend = backend.name,
                error = %err,
                "Trust gate: required isolation is unenforceable on this backend"
            );
            enforcement.isolation
        }
    };
    let isolation_strengthened = isolation != enforcement.isolation;

    // In enforce mode, apply the scoped policy to the PodSpec so the runtime
    // sees the narrowed capabilities + the backend-enforceable isolation before
    // launching the sandbox. Rewrite whenever the profile restricted the pod OR
    // the backend clamp strengthened the isolation posture.
    // In log-only mode we've computed the restriction for audit purposes only.
    if verification.enforced && (enforcement.was_restricted || isolation_strengthened) {
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
            .minimum_isolation(isolation)
            .created_by("trust-gate")
            .build();

        spec.spec.policy = PolicySpec::Inline {
            lattice: Box::new(enforced_lattice),
        };
    }
}

/// The isolation backend this node enforces with. Defaults to Firecracker
/// (Linux/KVM — the full lattice); set `NUCLEUS_ISOLATION_BACKEND=apple-vz` on a
/// macOS `Virtualization.framework` host so the trust gate clamps un-enforceable
/// levels (no host egress allowlist, no namespaces tier) UP to what VZ delivers.
fn isolation_backend() -> &'static BackendCapability {
    match std::env::var("NUCLEUS_ISOLATION_BACKEND").as_deref() {
        Ok("apple-vz") => &BackendCapability::APPLE_VZ,
        _ => &BackendCapability::FIRECRACKER,
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
    art12_attestation_preimage, Art12Attestation, ART12_ATTESTATION_KIND,
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
        assert!(key
            .verifying_key()
            .verify(preimage.as_bytes(), &Signature::from_bytes(&bytes))
            .is_ok());
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
            trust_bracket: Some("B".to_string()),
            trust_profile: Some("tenant".to_string()),
            attested_execution: true,
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
        assert!(!config.enforce);
        assert_eq!(config.default_bracket, "C");
    }

    // ── Executor signing-key persistence (#1630) ──────────────────────────

    #[test]
    fn test_signing_key_persists_across_calls() {
        // The core property: a "restart" (a second load from the same
        // state_dir) must yield the SAME executor identity.
        let dir = tempfile::tempdir().unwrap();
        let k1 = load_or_create_signing_key(dir.path());
        let k2 = load_or_create_signing_key(dir.path());
        assert_eq!(
            k1.verifying_key().as_bytes(),
            k2.verifying_key().as_bytes(),
            "executor signing key must be stable across restarts"
        );
        assert!(dir.path().join(EXECUTOR_KEY_FILE).exists());
    }

    /// Role separation: the task-issuer key must be a DIFFERENT key from the
    /// executor key in the same state_dir (distinct files), yet each must be
    /// stable across restarts. Reusing the executor key as the token root would
    /// conflate the executor identity with the capability-token issuer.
    #[test]
    fn test_task_issuer_key_is_distinct_from_executor_and_persists() {
        let dir = tempfile::tempdir().unwrap();

        let exec = load_or_create_signing_key(dir.path());
        let issuer = load_or_create_task_issuer_signing_key(dir.path());
        assert_ne!(
            exec.verifying_key().as_bytes(),
            issuer.verifying_key().as_bytes(),
            "task-issuer key must not equal the executor key (role separation)"
        );

        // Distinct files on disk.
        assert!(dir.path().join(EXECUTOR_KEY_FILE).exists());
        assert!(dir.path().join(TASK_ISSUER_KEY_FILE).exists());

        // Stable across a "restart" (second load from the same dir).
        let issuer2 = load_or_create_task_issuer_signing_key(dir.path());
        assert_eq!(
            issuer.verifying_key().as_bytes(),
            issuer2.verifying_key().as_bytes(),
            "task-issuer key must be stable across restarts"
        );
    }

    /// `from_env` provisions BOTH keys and they are role-separated.
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
    fn test_signing_key_distinct_per_state_dir() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let ka = load_or_create_signing_key(a.path());
        let kb = load_or_create_signing_key(b.path());
        assert_ne!(
            ka.verifying_key().as_bytes(),
            kb.verifying_key().as_bytes(),
            "separate state dirs must have independent identities"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_persisted_key_is_owner_read_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().unwrap();
        load_or_create_signing_key(dir.path());
        let mode = std::fs::metadata(dir.path().join(EXECUTOR_KEY_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o400, "private key must be mode 0400");
    }

    #[test]
    fn test_corrupt_key_file_regenerates_without_panic() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(EXECUTOR_KEY_FILE), b"not valid pkcs8 der").unwrap();
        // Must not panic; must produce a usable, persisted key.
        let k = load_or_create_signing_key(dir.path());
        let reloaded = load_or_create_signing_key(dir.path());
        assert_eq!(
            k.verifying_key().as_bytes(),
            reloaded.verifying_key().as_bytes(),
            "after regeneration the new key must itself persist"
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
            credentialed_egress: Vec::new(),
            workload: None,
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

    /// The enforcement gate is wired into the runtime: `apply_trust_enforcement`
    /// clamps the required isolation through the node's backend and records the
    /// requested/enforced/backend posture. On the default Firecracker backend
    /// the full lattice is enforceable, so `enforced == requested`. (Apple-VZ
    /// strengthening is covered by `portcullis::enforcement`'s unit tests.)
    #[test]
    fn test_apply_trust_enforcement_records_backend_isolation() {
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
            credentialed_egress: Vec::new(),
            workload: None,
            vsock: None,
            seccomp: None,
            cgroup: None,
            audit_sink: None,
            credentials: None,
        };
        let mut spec = PodSpec::new(spec_inner);
        let mut verification = TrustVerification {
            agent_identity: "spiffe://nucleus/test".to_string(),
            bracket: "A".to_string(),
            profile_name: "trusted".to_string(),
            was_restricted: false,
            enforced: true,
            continuous_score: None,
        };

        apply_trust_enforcement(&mut verification, &mut spec);

        let backend = spec
            .metadata
            .labels
            .get("isolation.coproduct.one/backend")
            .cloned()
            .expect("backend label must be written");
        let requested = spec
            .metadata
            .labels
            .get("isolation.coproduct.one/requested")
            .cloned();
        let enforced = spec
            .metadata
            .labels
            .get("isolation.coproduct.one/enforced")
            .cloned();
        assert!(
            requested.is_some() && enforced.is_some(),
            "requested/enforced isolation labels must be written"
        );
        // Firecracker (the default, no env override) enforces the full lattice,
        // so the enforced posture is faithful to the requested one.
        if backend == "firecracker" {
            assert_eq!(requested, enforced, "firecracker enforces the full lattice");
        }
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
            credentialed_egress: Vec::new(),
            workload: None,
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
            credentialed_egress: Vec::new(),
            workload: None,
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
