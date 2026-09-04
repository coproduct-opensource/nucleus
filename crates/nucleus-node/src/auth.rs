use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac, digest::KeyInit};
use sha2::Sha256;

/// Context from a successfully authenticated request.
///
/// Move B deleted the HMAC tier this used to also carry
/// (`AuthMethod::Hmac`/`AuthContext::from_hmac`) — mTLS with SPIFFE is the // hmac-allow: historical, describes what Move B deleted
/// only authentication method left, so the `AuthMethod` enum indirection
/// this struct used to wrap is gone too. See `docs/production-delta.md` and
/// the `move-b-delete-hmac` branch history for what this replaced.
#[allow(dead_code)] // actor/timestamp are read in tests only in production builds
#[derive(Clone, Debug)]
pub struct AuthContext {
    /// The actor identifier (the last path segment of the SPIFFE ID).
    pub actor: Option<String>,
    /// Time this context was created.
    pub timestamp: i64,
    /// The SPIFFE ID from the client's certificate.
    /// Format: `spiffe://trust-domain/path`
    pub spiffe_id: String,
}

impl AuthContext {
    /// Creates a new auth context from SPIFFE/mTLS verification.
    pub fn from_spiffe(spiffe_id: String) -> Self {
        // Extract actor from SPIFFE path (last segment)
        let actor = spiffe_id
            .strip_prefix("spiffe://")
            .and_then(|rest| rest.split('/').next_back())
            .map(|s| s.to_string());

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Self {
            actor,
            timestamp,
            spiffe_id,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("no client certificate presented (mTLS is mandatory; there is no HMAC fallback)")]
    NoClientCertificate,
}

/// HMAC-SHA256 verify. NOT part of the CLI/tool-proxy/node auth tier Move B
/// deleted — this is a generic primitive with its own callers that each
/// hold their own, unrelated secret: `signed_proxy.rs` (pod approval
/// signing), `art12_collector.rs` (Article 12 shipper/collector), and
/// `pod_caller_identity.rs` (caller-identity tokens). None of them go
/// through `AuthContext`/mTLS — they stay exactly as they were.
fn verify_signature(secret: &[u8], message: &[u8], signature_hex: &str) -> Result<(), AuthError> {
    let signature = hex::decode(signature_hex).map_err(|_| AuthError::InvalidSignature)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret).map_err(|_| AuthError::InvalidSignature)?;
    mac.update(message);
    mac.verify_slice(&signature)
        .map_err(|_| AuthError::InvalidSignature)
}

/// Public wrapper so the Article 12 collector can authenticate a body without
/// duplicating the HMAC comparison — one implementation, constant-time compare.
pub fn verify_signature_pub(
    secret: &[u8],
    message: &[u8],
    signature_hex: &str,
) -> Result<(), AuthError> {
    verify_signature(secret, message, signature_hex)
}

pub fn sign_message(secret: &[u8], message: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("hmac key");
    mac.update(message);
    let result = mac.finalize().into_bytes();
    hex::encode(result)
}

// ═══════════════════════════════════════════════════════════════════════════
// AUTHORIZATION
// ═══════════════════════════════════════════════════════════════════════════

/// Operations that can be authorized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // PodManagement is used in match arms for grouping
pub enum Operation {
    /// Create a new pod.
    CreatePod,
    /// List existing pods.
    ListPods,
    /// Get details of a specific pod.
    GetPod,
    /// Cancel a running pod.
    CancelPod,
    /// Stream logs from a pod.
    StreamLogs,
    /// Get execution receipt for a pod.
    GetReceipt,
    /// Any pod management operation (used for matching).
    PodManagement,
}

/// Authorization policy for nucleus operations.
///
/// This policy defines what SPIFFE identities are allowed to do.
/// By default, all identities within the trust domain can perform all operations.
#[derive(Clone, Debug)]
pub struct AuthorizationPolicy {
    /// Trust domain that identities must belong to.
    trust_domain: String,
    /// Allowed SPIFFE ID prefixes for orchestrators.
    /// Identities matching these prefixes can perform any operation.
    orchestrator_prefixes: Vec<String>,
    /// Allowed SPIFFE ID prefixes for CI/CD (GitHub OIDC).
    /// These identities can only manage pods with matching labels.
    cicd_prefixes: Vec<String>,
    /// SPIFFE ID prefixes of PODS this node minted (`ns/pods/sa/<uuid>`).
    ///
    /// A pod may perform pod-management operations, and only those; WHAT it
    /// may create is decided by its certificate (`pod_authority`), not by
    /// this prefix. Node-assigned: `pod_authority::pod_spiffe_id` mints this
    /// shape regardless of the spec's own `metadata`, so an agent-authored
    /// sub-pod spec can no longer name itself into an orchestrator prefix.
    pod_prefixes: Vec<String>,
    /// Exact SPIFFE IDs with full access — the certificate root minter.
    operator_identities: Vec<String>,
}

impl Default for AuthorizationPolicy {
    fn default() -> Self {
        Self::new("nucleus.local")
    }
}

#[allow(dead_code)] // Builder methods used in tests and future config
impl AuthorizationPolicy {
    /// Create a new authorization policy for the given trust domain.
    pub fn new(trust_domain: impl Into<String>) -> Self {
        let trust_domain = trust_domain.into();
        Self {
            orchestrator_prefixes: vec![
                format!("spiffe://{}/ns/default/sa/", trust_domain),
                format!("spiffe://{}/ns/workstream-kg/sa/", trust_domain),
            ],
            cicd_prefixes: vec![format!("spiffe://{}/ns/github/sa/", trust_domain)],
            pod_prefixes: vec![format!("spiffe://{}/ns/pods/sa/", trust_domain)],
            operator_identities: Vec::new(),
            trust_domain,
        }
    }

    /// Add an orchestrator prefix.
    pub fn with_orchestrator_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.orchestrator_prefixes.push(prefix.into());
        self
    }

    /// The pod id a SPIFFE ID names, if it has the node-assigned pod shape
    /// (`<pod prefix><uuid>`). Anything else — including an orchestrator or
    /// CI/CD identity — is `None`: those callers are not pods.
    pub fn pod_id_from_spiffe(&self, spiffe_id: &str) -> Option<uuid::Uuid> {
        self.pod_prefixes.iter().find_map(|prefix| {
            spiffe_id
                .strip_prefix(prefix.as_str())
                .and_then(|rest| uuid::Uuid::parse_str(rest).ok())
        })
    }

    /// Add a CI/CD prefix.
    pub fn with_cicd_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.cicd_prefixes.push(prefix.into());
        self
    }

    /// Authorize one EXACT identity as an operator (full access): the
    /// certificate root minter (`pod_authority`), by default the
    /// `ns/system/sa/cli` identity `nucleus setup` provisions. Exact, not a
    /// prefix — `…/sa/cli` must not also admit `…/sa/cli-anything`.
    pub fn with_operator_identity(mut self, spiffe_id: impl Into<String>) -> Self {
        self.operator_identities.push(spiffe_id.into());
        self
    }

    /// Check if an authentication context is authorized to perform an operation.
    ///
    /// # Returns
    ///
    /// `Ok(())` if authorized, `Err(AuthorizationError)` otherwise.
    pub fn authorize(&self, ctx: &AuthContext, op: Operation) -> Result<(), AuthorizationError> {
        self.authorize_spiffe(&ctx.spiffe_id, op)
    }

    /// Check if a SPIFFE ID is authorized to perform an operation.
    fn authorize_spiffe(&self, spiffe_id: &str, op: Operation) -> Result<(), AuthorizationError> {
        // Verify trust domain
        let expected_prefix = format!("spiffe://{}/", self.trust_domain);
        if !spiffe_id.starts_with(&expected_prefix) {
            return Err(AuthorizationError::WrongTrustDomain {
                expected: self.trust_domain.clone(),
                got: spiffe_id.to_string(),
            });
        }

        // The operator (certificate root minter): exact match, full access.
        if self.operator_identities.iter().any(|id| id == spiffe_id) {
            tracing::debug!(spiffe_id = %spiffe_id, operation = ?op, "Authorized operator operation");
            return Ok(());
        }

        // Check if this is an orchestrator identity (full access)
        for prefix in &self.orchestrator_prefixes {
            if spiffe_id.starts_with(prefix) {
                tracing::debug!(
                    spiffe_id = %spiffe_id,
                    operation = ?op,
                    "Authorized orchestrator operation"
                );
                return Ok(());
            }
        }

        // Check if this is a CI/CD identity (limited access)
        for prefix in &self.cicd_prefixes {
            if spiffe_id.starts_with(prefix) {
                // CI/CD identities can only perform pod management operations
                match op {
                    Operation::CreatePod
                    | Operation::GetPod
                    | Operation::CancelPod
                    | Operation::StreamLogs
                    | Operation::ListPods
                    | Operation::GetReceipt
                    | Operation::PodManagement => {
                        tracing::debug!(
                            spiffe_id = %spiffe_id,
                            operation = ?op,
                            "Authorized CI/CD operation"
                        );
                        return Ok(());
                    }
                }
            }
        }

        // A pod this node minted: pod-management operations only. Its
        // certificate decides what those operations may grant (pod_authority).
        for prefix in &self.pod_prefixes {
            if spiffe_id.starts_with(prefix) {
                match op {
                    Operation::CreatePod
                    | Operation::GetPod
                    | Operation::CancelPod
                    | Operation::StreamLogs
                    | Operation::ListPods
                    | Operation::GetReceipt
                    | Operation::PodManagement => {
                        tracing::debug!(
                            spiffe_id = %spiffe_id,
                            operation = ?op,
                            "Authorized pod operation"
                        );
                        return Ok(());
                    }
                }
            }
        }

        // Unknown identity type
        Err(AuthorizationError::NotAuthorized {
            identity: spiffe_id.to_string(),
            operation: format!("{:?}", op),
        })
    }
}

/// Authorization errors.
#[derive(Debug, thiserror::Error)]
pub enum AuthorizationError {
    #[error("no client certificate presented (mTLS is mandatory; there is no HMAC fallback)")]
    NoClientCertificate,

    #[error("identity from wrong trust domain: expected {expected}, got {got}")]
    WrongTrustDomain { expected: String, got: String },

    #[error("identity {identity} is not authorized for operation {operation}")]
    NotAuthorized { identity: String, operation: String },
}

// ═══════════════════════════════════════════════════════════════════════════
// SPIFFE ID EXTRACTION FROM PEER CERTIFICATES
// ═══════════════════════════════════════════════════════════════════════════

/// Extracts the SPIFFE ID from a DER-encoded X.509 certificate.
///
/// The SPIFFE ID is stored in the Subject Alternative Name (SAN) extension
/// as a URI starting with "spiffe://".
pub fn extract_spiffe_id_from_cert(cert_der: &[u8]) -> Option<String> {
    // Delegated to nucleus-identity so this AUTHORIZATION path cannot disagree
    // with any other component about who a peer is. The local copy this
    // replaced returned the FIRST `spiffe://` SAN, so a certificate naming two
    // identities was accepted and resolved by DER encoding order.
    nucleus_identity::spiffe_uri_from_svid(cert_der).ok()
}

/// Extracts SPIFFE ID from a tonic Request's peer certificates.
///
/// This is used for gRPC mTLS authentication. Returns `None` if:
/// - No TLS connection info is available
/// - No peer certificates were provided
/// - The certificate doesn't contain a SPIFFE ID
pub fn extract_spiffe_id_from_request<T>(request: &tonic::Request<T>) -> Option<String> {
    // Use tonic's built-in peer_certs() method which extracts from TlsConnectInfo
    let peer_certs = request.peer_certs()?;

    if peer_certs.is_empty() {
        return None;
    }

    // The first certificate is the end-entity (client) certificate
    let client_cert_der = peer_certs[0].as_ref();
    extract_spiffe_id_from_cert(client_cert_der)
}

/// Authenticate a gRPC request via mTLS.
///
/// Move B: this used to try mTLS first and fall back to HMAC when no client
/// certificate was presented. There is no fallback left — the gRPC listener
/// requires a client certificate unconditionally (`serve_grpc` refuses to
/// start otherwise), so a request with no extractable SPIFFE ID is refused
/// here rather than silently degrading to a weaker check.
pub fn authenticate_grpc_request<T>(request: &tonic::Request<T>) -> Result<AuthContext, AuthError> {
    let spiffe_id =
        extract_spiffe_id_from_request(request).ok_or(AuthError::NoClientCertificate)?;
    tracing::debug!(spiffe_id = %spiffe_id, "authenticated via mTLS with SPIFFE ID");
    Ok(AuthContext::from_spiffe(spiffe_id))
}

/// Extract the AuthContext from a request's extensions.
///
/// This should be called in gRPC handlers after the interceptor has authenticated
/// the request and stored the context.
pub fn get_auth_context<T>(request: &tonic::Request<T>) -> Option<&AuthContext> {
    request.extensions().get::<AuthContext>()
}

// ═══════════════════════════════════════════════════════════════════════════
// HTTP AUTHORIZATION — the SPIFFE branch (Move A step 4)
// ═══════════════════════════════════════════════════════════════════════════

/// Maps an HTTP method + path to the [`Operation`] a SPIFFE-authenticated
/// caller must be authorized for. `None` means no operation matches — the
/// SPIFFE path refuses fail-closed rather than guessing, so a route added to
/// `authenticated_routes` in `main.rs` without a matching entry here is
/// refused for SPIFFE callers rather than silently authorized.
///
/// This crate's HTTP API has exactly four protected routes; matched here by
/// fixed segment shape rather than axum's own routing algebra, which is
/// adequate at this size and not meant to generalize further. Kept in sync
/// with `main.rs`'s `authenticated_routes` table by hand — the two tables
/// must agree, and nothing enforces that but this comment and the tests
/// below, which assert against the literal route strings.
pub fn operation_for_route(method: &axum::http::Method, path: &str) -> Option<Operation> {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match (method, segments.as_slice()) {
        (&axum::http::Method::POST, ["v1", "pods"]) => Some(Operation::CreatePod),
        (&axum::http::Method::GET, ["v1", "pods"]) => Some(Operation::ListPods),
        (&axum::http::Method::GET, ["v1", "pods", _id, "logs"]) => Some(Operation::StreamLogs),
        (&axum::http::Method::POST, ["v1", "pods", _id, "cancel"]) => Some(Operation::CancelPod),
        _ => None,
    }
}

/// Resolves the auth context for an HTTP request from a verified SPIFFE
/// peer.
///
/// `Ok(None)` case is gone (Move B): the HTTP listener requires a client
/// certificate unconditionally (`http_serve::serve` always binds the mTLS
/// listener), so `extract_spiffe_id_from_extensions` finding nothing is now
/// itself an authentication failure rather than a signal to fall through to
/// HMAC.
///
/// `Err` when either no SPIFFE peer was found, or one WAS present but is not
/// authorized — the route has no mapped [`Operation`], or
/// [`AuthorizationPolicy::authorize`] itself refuses (wrong trust domain,
/// unrecognized identity). Routes `policy.authorize` — the SAME policy
/// [`authorize_grpc_operation`] uses — so HTTP and gRPC share one
/// authorization rule instead of two.
pub fn spiffe_context_for_request(
    policy: &AuthorizationPolicy,
    method: &axum::http::Method,
    path: &str,
    extensions: &axum::http::Extensions,
) -> Result<AuthContext, AuthorizationError> {
    let spiffe_id = nucleus_identity::mtls::extract_spiffe_id_from_extensions(extensions)
        .ok_or(AuthorizationError::NoClientCertificate)?;
    let ctx = AuthContext::from_spiffe(spiffe_id.clone());
    let operation = operation_for_route(method, path).ok_or(AuthorizationError::NotAuthorized {
        identity: spiffe_id,
        operation: format!("{method} {path}"),
    })?;
    policy.authorize(&ctx, operation)?;
    Ok(ctx)
}

/// Resolves the auth context for an incoming HTTP request via
/// [`spiffe_context_for_request`]. The one call `auth_middleware` needs —
/// kept here, not inline in `main.rs`, so the ratchet-tracked file doesn't
/// grow for wiring that belongs to this module anyway.
pub fn resolve_http_auth(
    state: &crate::NodeState,
    parts: &axum::http::request::Parts,
) -> Result<AuthContext, crate::ApiError> {
    Ok(spiffe_context_for_request(
        &state.authz_policy,
        &parts.method,
        parts.uri.path(),
        &parts.extensions,
    )?)
}

/// Check authorization for a gRPC operation.
///
/// This is a convenience function that extracts the auth context from the request
/// and checks if the operation is authorized according to the policy.
///
/// # Returns
///
/// * `Ok(())` if authorized
/// * `Err(Status)` with appropriate error message if not authorized
pub fn authorize_grpc_operation<T>(
    request: &tonic::Request<T>,
    policy: &AuthorizationPolicy,
    operation: Operation,
) -> Result<(), tonic::Status> {
    let auth_ctx =
        get_auth_context(request).ok_or_else(|| tonic::Status::internal("missing auth context"))?;

    policy
        .authorize(auth_ctx, operation)
        .map_err(|e| tonic::Status::permission_denied(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_context_from_spiffe() {
        let ctx = AuthContext::from_spiffe(
            "spiffe://nucleus.local/ns/workstream-kg/sa/orchestrator".to_string(),
        );
        assert_eq!(ctx.actor, Some("orchestrator".to_string()));
        assert_eq!(
            ctx.spiffe_id,
            "spiffe://nucleus.local/ns/workstream-kg/sa/orchestrator"
        );
    }

    #[test]
    fn test_authorization_policy_orchestrator_allowed() {
        let policy = AuthorizationPolicy::new("nucleus.local");
        let ctx =
            AuthContext::from_spiffe("spiffe://nucleus.local/ns/default/sa/worker".to_string());

        // Orchestrator should be allowed all operations
        assert!(policy.authorize(&ctx, Operation::CreatePod).is_ok());
        assert!(policy.authorize(&ctx, Operation::ListPods).is_ok());
        assert!(policy.authorize(&ctx, Operation::GetPod).is_ok());
        assert!(policy.authorize(&ctx, Operation::CancelPod).is_ok());
        assert!(policy.authorize(&ctx, Operation::StreamLogs).is_ok());
    }

    #[test]
    fn test_authorization_policy_cicd_allowed() {
        let policy = AuthorizationPolicy::new("nucleus.local");
        let ctx = AuthContext::from_spiffe(
            "spiffe://nucleus.local/ns/github/sa/myorg/myrepo".to_string(),
        );

        // CI/CD should be allowed pod management operations
        assert!(policy.authorize(&ctx, Operation::CreatePod).is_ok());
        assert!(policy.authorize(&ctx, Operation::ListPods).is_ok());
        assert!(policy.authorize(&ctx, Operation::GetPod).is_ok());
        assert!(policy.authorize(&ctx, Operation::CancelPod).is_ok());
        assert!(policy.authorize(&ctx, Operation::StreamLogs).is_ok());
    }

    #[test]
    fn test_authorization_policy_wrong_trust_domain() {
        let policy = AuthorizationPolicy::new("nucleus.local");
        let ctx =
            AuthContext::from_spiffe("spiffe://other.domain/ns/default/sa/worker".to_string());

        let result = policy.authorize(&ctx, Operation::CreatePod);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AuthorizationError::WrongTrustDomain { .. }
        ));
    }

    #[test]
    fn test_authorization_policy_unknown_identity() {
        let policy = AuthorizationPolicy::new("nucleus.local");
        // An identity that doesn't match any known prefix
        let ctx =
            AuthContext::from_spiffe("spiffe://nucleus.local/ns/unknown/sa/worker".to_string());

        let result = policy.authorize(&ctx, Operation::CreatePod);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AuthorizationError::NotAuthorized { .. }
        ));
    }

    #[test]
    fn test_authorization_policy_custom_prefixes() {
        let policy = AuthorizationPolicy::new("nucleus.local")
            .with_orchestrator_prefix("spiffe://nucleus.local/ns/custom/sa/")
            .with_cicd_prefix("spiffe://nucleus.local/ns/jenkins/sa/");

        // Custom orchestrator prefix
        let ctx = AuthContext::from_spiffe(
            "spiffe://nucleus.local/ns/custom/sa/my-orchestrator".to_string(),
        );
        assert!(policy.authorize(&ctx, Operation::CreatePod).is_ok());

        // Custom CI/CD prefix
        let ctx = AuthContext::from_spiffe(
            "spiffe://nucleus.local/ns/jenkins/sa/build-agent".to_string(),
        );
        assert!(policy.authorize(&ctx, Operation::CreatePod).is_ok());
    }

    /// The root minter is authorized as an operator by EXACT identity: the
    /// tier-2 e2e creates pods as `ns/system/sa/cli`, which no prefix class
    /// covers, and a prefix would also admit `…/sa/cli-anything`.
    #[test]
    fn the_operator_identity_is_exact_not_a_prefix() {
        let policy = AuthorizationPolicy::new("nucleus.local")
            .with_operator_identity("spiffe://nucleus.local/ns/system/sa/cli");
        let cli = AuthContext::from_spiffe("spiffe://nucleus.local/ns/system/sa/cli".into());
        assert!(policy.authorize(&cli, Operation::CreatePod).is_ok());
        assert!(policy.authorize(&cli, Operation::CancelPod).is_ok());
        let sibling =
            AuthContext::from_spiffe("spiffe://nucleus.local/ns/system/sa/cli-anything".into());
        assert!(policy.authorize(&sibling, Operation::CreatePod).is_err());
        // Non-vacuity: without the operator entry the same identity is refused.
        let bare = AuthorizationPolicy::new("nucleus.local");
        assert!(bare.authorize(&cli, Operation::CreatePod).is_err());
    }

    /// A pod identity is authorized for pod management and nothing else, and
    /// only the node-assigned `ns/pods/sa/<uuid>` shape parses as a pod.
    #[test]
    fn pod_identities_manage_pods_only_and_parse_to_their_id() {
        let policy = AuthorizationPolicy::new("nucleus.local");
        let id = uuid::Uuid::new_v4();
        let spiffe = format!("spiffe://nucleus.local/ns/pods/sa/{id}");
        let ctx = AuthContext::from_spiffe(spiffe.clone());
        for op in [
            Operation::CreatePod,
            Operation::ListPods,
            Operation::GetPod,
            Operation::CancelPod,
            Operation::StreamLogs,
            Operation::GetReceipt,
            Operation::PodManagement,
        ] {
            assert!(policy.authorize(&ctx, op).is_ok(), "{op:?}");
        }
        assert_eq!(policy.pod_id_from_spiffe(&spiffe), Some(id));

        // The old spec-authored shape is NOT a pod identity and is not an
        // orchestrator either once it stops matching `ns/default/sa/`.
        assert_eq!(
            policy.pod_id_from_spiffe("spiffe://nucleus.local/ns/default/sa/orchestrator-x"),
            None
        );
        assert_eq!(
            policy.pod_id_from_spiffe("spiffe://nucleus.local/ns/pods/sa/not-a-uuid"),
            None
        );
        // A different trust domain never parses, even with the right path.
        assert_eq!(
            policy.pod_id_from_spiffe(&format!("spiffe://evil.local/ns/pods/sa/{id}")),
            None
        );
    }

    // ── HTTP SPIFFE branch (Move A step 4 / Move B) ────────────────────────

    /// Exhaustive against `main.rs`'s `authenticated_routes` table: every
    /// route that table declares must map here, and nothing else should.
    #[test]
    fn operation_for_route_matches_every_declared_route_and_nothing_else() {
        use axum::http::Method;

        assert_eq!(
            operation_for_route(&Method::POST, "/v1/pods"),
            Some(Operation::CreatePod)
        );
        assert_eq!(
            operation_for_route(&Method::GET, "/v1/pods"),
            Some(Operation::ListPods)
        );
        assert_eq!(
            operation_for_route(&Method::GET, "/v1/pods/abc-123/logs"),
            Some(Operation::StreamLogs)
        );
        assert_eq!(
            operation_for_route(&Method::POST, "/v1/pods/abc-123/cancel"),
            Some(Operation::CancelPod)
        );

        // Wrong method on a real route.
        assert_eq!(operation_for_route(&Method::DELETE, "/v1/pods"), None);
        // A route this middleware doesn't protect (see `public_routes`).
        assert_eq!(operation_for_route(&Method::GET, "/v1/health"), None);
        // Unmapped nested path.
        assert_eq!(
            operation_for_route(&Method::GET, "/v1/pods/abc-123/receipt"),
            None
        );
    }

    /// Builds a `ConnectInfo<MtlsConnectInfo>` the way axum's own
    /// `into_make_service_with_connect_info` would, carrying `spiffe_id`.
    /// The pipeline-delivery question itself (does axum actually hand a
    /// handler this exact wrapped type) is covered by
    /// `nucleus_identity::mtls::mtls_extraction_survives_the_real_serving_pipeline`;
    /// this tests the NEW logic layered on top of that primitive.
    fn extensions_with_spiffe_id(spiffe_id: &str) -> axum::http::Extensions {
        use nucleus_identity::mtls::{ClientCertInfo, MtlsConnectInfo};
        let mut extensions = axum::http::Extensions::new();
        extensions.insert(axum::extract::ConnectInfo(MtlsConnectInfo {
            peer_addr: "127.0.0.1:0".parse().unwrap(),
            client_cert: Some(ClientCertInfo {
                cert_der: vec![],
                spiffe_id: Some(spiffe_id.to_string()),
            }),
        }));
        extensions
    }

    /// The refute half of Move B's HTTP change: no client certificate must
    /// now be refused, not silently treated as "try HMAC instead" (there is
    /// no HMAC to try).
    #[test]
    fn spiffe_context_for_request_refuses_a_request_with_no_peer() {
        let policy = AuthorizationPolicy::new("nucleus.local");
        let result = spiffe_context_for_request(
            &policy,
            &axum::http::Method::POST,
            "/v1/pods",
            &axum::http::Extensions::new(),
        );
        assert!(matches!(
            result,
            Err(AuthorizationError::NoClientCertificate)
        ));
    }

    #[test]
    fn spiffe_context_for_request_authorizes_a_real_peer() {
        let policy = AuthorizationPolicy::new("nucleus.local");
        let extensions = extensions_with_spiffe_id("spiffe://nucleus.local/ns/default/sa/orch");

        let ctx =
            spiffe_context_for_request(&policy, &axum::http::Method::POST, "/v1/pods", &extensions)
                .expect("a real SPIFFE peer must be authorized");
        assert_eq!(ctx.spiffe_id, "spiffe://nucleus.local/ns/default/sa/orch");
    }

    #[test]
    fn spiffe_context_for_request_refuses_an_unmapped_route() {
        let policy = AuthorizationPolicy::new("nucleus.local");
        // An orchestrator identity that WOULD be authorized for any mapped
        // operation -- proving the refusal is about the route, not the peer.
        let extensions = extensions_with_spiffe_id("spiffe://nucleus.local/ns/default/sa/orch");

        let err = spiffe_context_for_request(
            &policy,
            &axum::http::Method::DELETE,
            "/v1/pods/abc-123",
            &extensions,
        )
        .expect_err("an unmapped route must be refused, not silently authorized");
        assert!(matches!(err, AuthorizationError::NotAuthorized { .. }));
    }

    #[test]
    fn spiffe_context_for_request_refuses_wrong_trust_domain() {
        let policy = AuthorizationPolicy::new("nucleus.local");
        let extensions = extensions_with_spiffe_id("spiffe://attacker.example/ns/default/sa/x");

        let err =
            spiffe_context_for_request(&policy, &axum::http::Method::POST, "/v1/pods", &extensions)
                .expect_err("a peer from the wrong trust domain must be refused");
        assert!(matches!(err, AuthorizationError::WrongTrustDomain { .. }));
    }

    // ── generic HMAC primitive (unrelated to the CLI/tool-proxy/node tier
    //    Move B deleted — see the doc comment on `verify_signature`) ───────

    #[test]
    fn sign_then_verify_round_trips() {
        let secret = b"s3cret";
        let message = b"hello";
        let sig = sign_message(secret, message);
        assert!(verify_signature_pub(secret, message, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_a_signature_from_a_different_secret() {
        let sig = sign_message(b"secret-a", b"hello");
        assert!(matches!(
            verify_signature_pub(b"secret-b", b"hello", &sig),
            Err(AuthError::InvalidSignature)
        ));
    }

    // `resolve_http_auth` itself is not separately unit-tested: it is a
    // trivial pass-through to `spiffe_context_for_request`, and needs a full
    // `NodeState` to call (no test constructor exists, and building one is
    // disproportionate to what this function adds). The interesting logic —
    // routing, trust domain checks, the fail-closed unmapped-route and
    // no-peer refusals — lives in `spiffe_context_for_request`, tested above.
}
