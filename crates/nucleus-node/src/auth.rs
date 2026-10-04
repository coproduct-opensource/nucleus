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
    /// Take a base snapshot of a running pod.
    ///
    /// Deliberately NOT part of the pod-management group. Snapshotting writes to the node's
    /// shared snapshot store, and a base is offered to every later pod with the same program —
    /// so a pod able to snapshot would be a pod able to author what its neighbours boot from.
    /// That is an operator's authority, not a workload's.
    SnapshotPod,
    /// Issue or lift a lockdown (`NodeService::Lockdown`, either direction).
    ///
    /// Not part of the pod-management group. A lockdown is the operator's break-glass control:
    /// an empty scope reaches every pod on the node, and lifting one is the human action that
    /// ends it. Neither is a workload's to take, for itself or for anyone else — a pod that
    /// needs to stop itself already can, locally, through its own circuit breaker. RECEIVING
    /// lockdown commands (`WatchLockdown`) is a different operation and stays with the pods.
    Lockdown,
    /// Inspect or decide an action-bound host approval; configured operator only.
    ApproveEffect,
    /// Any pod management operation (used for matching).
    PodManagement,
}

/// The label the node stamps on a pod created by a CI/CD identity: that
/// identity's full SPIFFE ID. Node-assigned, like the pod's own SVID: a spec
/// that carries it is refused (`AuthorizationPolicy::stamp_ci_principal`), so
/// the only way a pod comes to bear a CI identity's label is for that identity
/// to have created it.
pub const CI_PRINCIPAL_LABEL: &str = "nucleus.io/ci-principal";

/// WHICH pods an authenticated caller may list, read and manage.
///
/// Three answers, not an `Option<Uuid>`: "no pod" used to mean "every pod",
/// and a CI/CD identity, which is not a pod, fell into that arm although the
/// policy restricts it to the pods it created. Every consumer now matches the
/// kind it was handed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallerScope {
    /// The operator or an orchestrator: every pod on the node.
    NodeWide,
    /// A pod: itself and its direct children (`pod_api::caller_may_manage`).
    Pod(uuid::Uuid),
    /// A CI/CD identity: the pods stamped [`CI_PRINCIPAL_LABEL`] = this ID.
    CiPrincipal(String),
    /// A federated tenant, by trust domain (ADR 0001): exactly the pods whose
    /// certificate is rooted in that trust domain. Anything else is 404.
    Tenant(String),
}

impl CallerScope {
    /// The calling pod, when the caller is one.
    pub fn pod(&self) -> Option<uuid::Uuid> {
        match self {
            CallerScope::Pod(p) => Some(*p),
            CallerScope::NodeWide | CallerScope::CiPrincipal(_) | CallerScope::Tenant(_) => None,
        }
    }
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
    /// These identities can only manage pods with matching labels: the pods
    /// they created, which the node stamps [`CI_PRINCIPAL_LABEL`] = their ID.
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
    /// Trust domains of federated tenants (`[[caller]]` bindings,
    /// `federation_ingress.rs`). An identity in one of these got its SVID from
    /// the federation exchange; it may create pods and manage ITS TENANT'S
    /// pods (`CallerScope::Tenant`), and nothing else.
    federated_trust_domains: std::collections::BTreeSet<String>,
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
            federated_trust_domains: std::collections::BTreeSet::new(),
            trust_domain,
        }
    }

    /// Admit the federated tenants' trust domains (see the field). The node's
    /// own trust domain is never one — `CallerBindings` refuses it at load —
    /// and is ignored here as well, so no configuration can turn the
    /// operator's own identities into tenant-scoped ones.
    pub fn with_federated_trust_domains<'a>(
        mut self,
        domains: impl IntoIterator<Item = &'a str>,
    ) -> Self {
        for td in domains {
            if td != self.trust_domain {
                self.federated_trust_domains.insert(td.to_string());
            }
        }
        self
    }

    /// The federated tenant a SPIFFE ID belongs to, if it belongs to one.
    pub fn federated_tenant<'a>(&self, spiffe_id: &'a str) -> Option<&'a str> {
        crate::federation_ingress::trust_domain_of(spiffe_id)
            .filter(|td| self.federated_trust_domains.contains(*td))
    }

    /// Add an orchestrator prefix.
    pub fn with_orchestrator_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.orchestrator_prefixes.push(prefix.into());
        self
    }

    /// The pod id a SPIFFE ID names, if it has the node-assigned pod shape
    /// (`<pod prefix><uuid>`). Anything else — including an orchestrator or
    /// CI/CD identity — is `None`: those callers are not pods.
    ///
    /// The uuid must be spelled exactly as the node mints it (lowercase,
    /// hyphenated). `Uuid::parse_str` also reads the simple, braced, URN and
    /// uppercase forms, and a pod named by any of those would be a second ID
    /// for the same pod.
    pub fn pod_id_from_spiffe(&self, spiffe_id: &str) -> Option<uuid::Uuid> {
        self.pod_prefixes.iter().find_map(|prefix| {
            let rest = spiffe_id.strip_prefix(prefix.as_str())?;
            let pod = uuid::Uuid::parse_str(rest).ok()?;
            (pod.hyphenated().to_string() == rest).then_some(pod)
        })
    }

    /// Which pods an authenticated caller may list, read and manage. The one
    /// resolver both transports use (`resolve_http_caller`,
    /// `pod_api::grpc_caller`), so HTTP and gRPC cannot disagree about a
    /// caller's reach.
    ///
    /// * `Tenant(td)` — a federated tenant's peer: the pods rooted in its own
    ///   trust domain. Decided FIRST, from the verified peer alone: a caller
    ///   token it presents is a replay ([`Self::proved_pod`]) and changes
    ///   nothing.
    /// * `Pod(pod)` — a pod: the one its caller token proves, else the one its
    ///   own SVID names. A pod peer is its own pod with or without a token.
    /// * `NodeWide` — ONLY an identity this policy positively grants every pod:
    ///   the operator or an orchestrator.
    /// * `CiPrincipal(id)` — a CI/CD identity: the pods it created.
    /// * `Err` — anything else, including an identity under a pod prefix that
    ///   names no pod. No arm is a fallthrough.
    pub fn caller_scope(
        &self,
        caller_token_pod: Option<uuid::Uuid>,
        spiffe_id: &str,
    ) -> Result<CallerScope, AuthorizationError> {
        if !is_canonical_spiffe_id(spiffe_id) {
            return Err(AuthorizationError::NotAuthorized {
                identity: spiffe_id.to_string(),
                operation: "anything: not a canonical SPIFFE ID".to_string(),
            });
        }
        if let Some(td) = self.federated_tenant(spiffe_id) {
            return Ok(CallerScope::Tenant(td.to_string()));
        }
        if let Some(pod) = self.proved_pod(caller_token_pod, spiffe_id) {
            return Ok(CallerScope::Pod(pod));
        }
        let node_wide = self.operator_identities.iter().any(|id| id == spiffe_id)
            || self
                .orchestrator_prefixes
                .iter()
                .any(|prefix| id_under(spiffe_id, prefix));
        if node_wide {
            return Ok(CallerScope::NodeWide);
        }
        if self.is_cicd(spiffe_id) {
            return Ok(CallerScope::CiPrincipal(spiffe_id.to_string()));
        }
        Err(AuthorizationError::NotAuthorized {
            identity: spiffe_id.to_string(),
            operation: "node-wide pod management".to_string(),
        })
    }

    fn is_cicd(&self, spiffe_id: &str) -> bool {
        self.cicd_prefixes
            .iter()
            .any(|prefix| id_under(spiffe_id, prefix))
    }

    /// Record who created a pod, where the CI/CD scope reads it: a pod created
    /// by a CI/CD identity is stamped [`CI_PRINCIPAL_LABEL`] = that identity.
    ///
    /// A spec that already carries the label is refused, whoever sends it. The
    /// label is the node's record, not the creator's claim: accepting it from a
    /// spec would let one CI identity file a pod under another's name, or a pod
    /// hand one of its children to a CI identity.
    pub fn stamp_ci_principal(
        &self,
        creator_spiffe_id: &str,
        spec: &mut nucleus_spec::PodSpec,
    ) -> Result<(), String> {
        if spec.metadata.labels.contains_key(CI_PRINCIPAL_LABEL) {
            return Err(format!(
                "label {CI_PRINCIPAL_LABEL} is assigned by the node; a spec may not set it"
            ));
        }
        if self.is_cicd(creator_spiffe_id) {
            spec.metadata.labels.insert(
                CI_PRINCIPAL_LABEL.to_string(),
                creator_spiffe_id.to_string(),
            );
        }
        Ok(())
    }

    /// Which pod an authenticated caller PROVES it is: the per-pod caller token,
    /// else the peer's own pod SVID -- and never either for a federated tenant.
    ///
    /// The caller token is a bearer secret, not bound to the TLS peer. A tenant
    /// holds no pod's token legitimately (pods reach the node with their own
    /// node-domain SVIDs), so a tenant peer presenting one is a replay: honoured,
    /// it would make the tenant `CallerScope::Pod(victim)` and let it manage the
    /// victim's lineage and mint children under the victim's certificate. The
    /// tenant stays a tenant whatever it carries.
    ///
    /// The one decider for this fact: [`Self::caller_scope`] and
    /// `Admission::from_http` both read it, so the pod that lists and the pod
    /// that creates cannot diverge (ADR 0007 G).
    pub fn proved_pod(
        &self,
        caller_token_pod: Option<uuid::Uuid>,
        spiffe_id: &str,
    ) -> Option<uuid::Uuid> {
        if self.federated_tenant(spiffe_id).is_some() {
            return None;
        }
        caller_token_pod.or_else(|| self.pod_id_from_spiffe(spiffe_id))
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
        // Every decision below reads the ID as a string. Each reading is sound
        // only for the one canonical spelling (`docs/spiffe-taxonomy.md`), so
        // anything else is refused before any of them runs.
        if !is_canonical_spiffe_id(spiffe_id) {
            return Err(AuthorizationError::NotAuthorized {
                identity: spiffe_id.to_string(),
                operation: format!("{op:?}"),
            });
        }
        // A federated tenant: pod management over its own pods — which ones is
        // `CallerScope::Tenant`'s scoping, not this table's. Never a snapshot, for
        // the reason on `Operation::SnapshotPod`, which applies to a tenant
        // outside the node at least as much as to a pod inside it.
        if self.federated_tenant(spiffe_id).is_some() {
            return match op {
                Operation::CreatePod
                | Operation::ListPods
                | Operation::GetPod
                | Operation::CancelPod
                | Operation::StreamLogs
                | Operation::GetReceipt
                | Operation::PodManagement => Ok(()),
                // A lockdown is the operator's control (see the variant), and a
                // tenant is never the operator.
                Operation::SnapshotPod | Operation::Lockdown | Operation::ApproveEffect => {
                    Err(AuthorizationError::NotAuthorized {
                        identity: spiffe_id.to_string(),
                        operation: format!("{op:?}"),
                    })
                }
            };
        }

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

        if op == Operation::ApproveEffect {
            return Err(AuthorizationError::NotAuthorized {
                identity: spiffe_id.to_string(),
                operation: format!("{op:?}"),
            });
        }

        // Check if this is an orchestrator identity (full access)
        for prefix in &self.orchestrator_prefixes {
            if id_under(spiffe_id, prefix) {
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
            if id_under(spiffe_id, prefix) {
                // CI/CD identities can only perform pod management operations
                match op {
                    Operation::CreatePod
                    | Operation::GetPod
                    | Operation::CancelPod
                    | Operation::StreamLogs
                    | Operation::ListPods
                    | Operation::GetReceipt
                    | Operation::SnapshotPod
                    | Operation::PodManagement => {
                        tracing::debug!(
                            spiffe_id = %spiffe_id,
                            operation = ?op,
                            "Authorized CI/CD operation"
                        );
                        return Ok(());
                    }
                    // Falls through to the refusal below: see the variant's doc comment.
                    Operation::Lockdown | Operation::ApproveEffect => {}
                }
            }
        }

        // A pod this node minted: pod-management operations only. Its
        // certificate decides what those operations may grant (pod_authority).
        for prefix in &self.pod_prefixes {
            if id_under(spiffe_id, prefix) {
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
                    // Falls through to the refusal below rather than returning: see the variant's
                    // doc comment. A workload does not get to author what its neighbours boot.
                    Operation::SnapshotPod | Operation::Lockdown | Operation::ApproveEffect => {}
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

/// Is `id` the one canonical spelling of a workload SPIFFE ID
/// (`nucleus_identity::Identity::from_spiffe_uri`, the parser every peer
/// certificate already went through)?
pub(crate) fn is_canonical_spiffe_id(id: &str) -> bool {
    nucleus_identity::Identity::from_spiffe_uri(id).is_ok()
}

/// Is `id` below the grant `prefix`, at a SEGMENT boundary?
///
/// A grant is a path prefix, so it must end where a segment ends. Written with
/// a trailing `/` (as every built-in one is) it is a plain prefix; written
/// without one, `…/ns/ops` would otherwise also grant `…/ns/ops-anything` and,
/// as a bare trust domain, `spiffe://td.example` would grant
/// `spiffe://td.example.evil/…`. Here it grants only itself and what lies
/// below it.
pub(crate) fn id_under(id: &str, prefix: &str) -> bool {
    if prefix.ends_with('/') {
        return id.len() > prefix.len() && id.starts_with(prefix);
    }
    id == prefix
        || id
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
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
/// This crate's HTTP API has exactly six protected routes; matched here by
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
        (&axum::http::Method::GET, ["v1", "pods", _id, "workload-logs", "stdout" | "stderr"]) => {
            Some(Operation::StreamLogs)
        }
        (&axum::http::Method::POST, ["v1", "pods", _id, "cancel"]) => Some(Operation::CancelPod),
        (&axum::http::Method::POST, ["v1", "pods", _id, "snapshot"]) => {
            Some(Operation::SnapshotPod)
        }
        (&axum::http::Method::GET, ["v1", "pods", _id, "receipt"]) => Some(Operation::GetReceipt),
        (
            &axum::http::Method::GET,
            [
                "v1",
                "pods",
                _id,
                "workload-admission" | "workload-result" | "execution-receipt",
            ],
        ) => Some(Operation::GetReceipt),
        (&axum::http::Method::POST, ["v1", "pods", _id, "execution-receipt"]) => {
            Some(Operation::GetReceipt)
        }
        (&axum::http::Method::GET, ["v1", "pods", _id, "effect-approvals"])
        | (&axum::http::Method::GET, ["v1", "pods", _id, "effect-approvals", _])
        | (&axum::http::Method::POST, ["v1", "pods", _id, "effect-approvals", _]) => {
            Some(Operation::ApproveEffect)
        }
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

/// Which pod an HTTP caller acts as, for `auth_middleware`: its caller token
/// (from the headers) and its verified peer, through
/// [`AuthorizationPolicy::caller_scope`] — the resolver gRPC uses too.
pub fn resolve_http_caller(
    state: &crate::NodeState,
    ctx: &AuthContext,
    headers: &axum::http::HeaderMap,
) -> Result<CallerScope, crate::ApiError> {
    let token_pod =
        crate::pod_caller_identity::identify_from_headers(state.caller_secret.as_ref(), headers);
    Ok(state
        .authz_policy
        .caller_scope(token_pod.ok(), &ctx.spiffe_id)?)
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

    // Federated tenants are served over HTTP only. The gRPC pod handlers now
    // resolve their caller through `AuthorizationPolicy::caller_scope`, which does
    // produce `CallerScope::Tenant` -- but the gRPC surface was never
    // reviewed for tenant scoping, so it stays closed to tenants here, the one
    // gate every gRPC handler calls, rather than being opened by accident.
    if policy.federated_tenant(&auth_ctx.spiffe_id).is_some() {
        return Err(tonic::Status::permission_denied(
            "federated callers are served over HTTP only",
        ));
    }

    policy
        .authorize(auth_ctx, operation)
        .map_err(|e| tonic::Status::permission_denied(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `caller_scope` answers unscoped only for an identity the policy names as
    /// node-wide; a pod is its own pod with or without a token; anything else
    /// is refused rather than defaulted.
    #[test]
    fn caller_scope_is_node_wide_only_for_a_named_node_wide_identity() {
        let policy = AuthorizationPolicy::default()
            .with_operator_identity("spiffe://nucleus.local/ns/system/sa/cli");
        let pod = uuid::Uuid::new_v4();
        let other = uuid::Uuid::new_v4();
        let pod_svid = format!("spiffe://nucleus.local/ns/pods/sa/{pod}");

        assert_eq!(
            policy.caller_scope(None, &pod_svid).unwrap(),
            CallerScope::Pod(pod)
        );
        assert_eq!(
            policy.caller_scope(Some(pod), &pod_svid).unwrap(),
            CallerScope::Pod(pod)
        );
        let orch = "spiffe://nucleus.local/ns/default/sa/orchestrator";
        assert_eq!(
            policy.caller_scope(Some(other), orch).unwrap(),
            CallerScope::Pod(other)
        );

        for node_wide in [orch, "spiffe://nucleus.local/ns/system/sa/cli"] {
            assert_eq!(
                policy.caller_scope(None, node_wide).unwrap(),
                CallerScope::NodeWide,
                "{node_wide}"
            );
        }
        // A CI/CD identity is NOT node-wide: it reaches the pods it created.
        let ci = "spiffe://nucleus.local/ns/github/sa/org-repo";
        assert_eq!(
            policy.caller_scope(None, ci).unwrap(),
            CallerScope::CiPrincipal(ci.to_string())
        );
        for unplaced in [
            "spiffe://nucleus.local/ns/pods/sa/not-a-pod",
            "spiffe://nucleus.local/ns/system/sa/cli-other",
            "spiffe://nucleus.local/ns/elsewhere/sa/x",
            "spiffe://other.domain/ns/default/sa/orchestrator",
        ] {
            assert!(policy.caller_scope(None, unplaced).is_err(), "{unplaced}");
        }
    }

    fn bare_spec() -> nucleus_spec::PodSpec {
        serde_json::from_str(r#"{"apiVersion":"nucleus/v1","kind":"Pod","spec":{}}"#)
            .expect("minimal spec")
    }

    /// A pod a CI/CD identity creates carries that identity's label; a pod
    /// anyone else creates carries none.
    #[test]
    fn a_ci_identitys_pod_is_stamped_with_that_identity() {
        let policy = AuthorizationPolicy::default();
        let ci = "spiffe://nucleus.local/ns/github/sa/org-repo";
        let mut spec = bare_spec();
        policy.stamp_ci_principal(ci, &mut spec).unwrap();
        assert_eq!(
            spec.metadata
                .labels
                .get(CI_PRINCIPAL_LABEL)
                .map(String::as_str),
            Some(ci)
        );
        for creator in [
            "spiffe://nucleus.local/ns/default/sa/orchestrator",
            &format!("spiffe://nucleus.local/ns/pods/sa/{}", uuid::Uuid::new_v4()),
        ] {
            let mut spec = bare_spec();
            policy.stamp_ci_principal(creator, &mut spec).unwrap();
            assert!(
                !spec.metadata.labels.contains_key(CI_PRINCIPAL_LABEL),
                "{creator} is not a CI identity"
            );
        }
    }

    /// The label is the node's record: a spec that sets it is refused, from a
    /// CI identity (another's name) and from anyone else alike.
    #[test]
    fn a_spec_may_not_set_the_ci_principal_label() {
        let policy = AuthorizationPolicy::default();
        for creator in [
            "spiffe://nucleus.local/ns/github/sa/org-repo",
            "spiffe://nucleus.local/ns/default/sa/orchestrator",
        ] {
            let mut spec = bare_spec();
            spec.metadata.labels.insert(
                CI_PRINCIPAL_LABEL.to_string(),
                "spiffe://nucleus.local/ns/github/sa/someone-else".to_string(),
            );
            assert!(
                policy.stamp_ci_principal(creator, &mut spec).is_err(),
                "{creator}"
            );
        }
    }

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

    /// A workload may not author what its neighbours boot from.
    ///
    /// Every other pod-management operation is granted to a pod identity, so this asymmetry is
    /// the whole content of the test: snapshotting writes a base into the node's shared store,
    /// and a base is handed to every later pod with the same program. A pod that could publish
    /// one could choose what its co-tenants restore — which is an operator's authority, and is
    /// exactly the escalation `Operation::SnapshotPod` exists as a separate variant to prevent.
    #[test]
    fn a_pod_may_manage_pods_but_may_not_publish_a_base() {
        let policy = AuthorizationPolicy::new("nucleus.local");
        let pod = AuthContext::from_spiffe("spiffe://nucleus.local/ns/pods/sa/abc-123".to_string());

        for allowed in [
            Operation::CreatePod,
            Operation::ListPods,
            Operation::GetPod,
            Operation::CancelPod,
            Operation::StreamLogs,
        ] {
            assert!(
                policy.authorize(&pod, allowed).is_ok(),
                "{allowed:?} is ordinary pod management and stays granted"
            );
        }
        assert!(
            policy.authorize(&pod, Operation::SnapshotPod).is_err(),
            "a pod must not be able to publish a base other pods will boot from"
        );

        // An orchestrator asking for a base is the case this route exists for.
        let cicd = AuthContext::from_spiffe(
            "spiffe://nucleus.local/ns/github/sa/myorg/myrepo".to_string(),
        );
        assert!(policy.authorize(&cicd, Operation::SnapshotPod).is_ok());
    }

    /// Issuing or lifting a lockdown belongs to the operator and the orchestrators, and to no
    /// other identity class — while every pod keeps what it needs to RECEIVE one.
    #[test]
    fn lockdown_is_an_operator_action() {
        let cli = "spiffe://nucleus.local/ns/system/sa/cli";
        let policy = AuthorizationPolicy::new("nucleus.local").with_operator_identity(cli);
        let ctx = |s: &str| AuthContext::from_spiffe(s.to_string());

        for operator in [cli, "spiffe://nucleus.local/ns/default/sa/orchestrator"] {
            assert!(
                policy
                    .authorize(&ctx(operator), Operation::Lockdown)
                    .is_ok(),
                "{operator}"
            );
        }
        let pod = format!("spiffe://nucleus.local/ns/pods/sa/{}", uuid::Uuid::new_v4());
        for other in [
            pod.as_str(),
            "spiffe://nucleus.local/ns/github/sa/myorg/myrepo",
            "spiffe://nucleus.local/ns/system/sa/cli-other",
        ] {
            assert!(
                policy.authorize(&ctx(other), Operation::Lockdown).is_err(),
                "{other}"
            );
        }
        // `WatchLockdown` is authorized as `CancelPod`: a pod must still hear a lockdown.
        assert!(policy.authorize(&ctx(&pod), Operation::CancelPod).is_ok());
    }

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
        assert_eq!(
            operation_for_route(&Method::POST, "/v1/pods/abc-123/snapshot"),
            Some(Operation::SnapshotPod)
        );

        // Wrong method on a real route.
        assert_eq!(operation_for_route(&Method::DELETE, "/v1/pods"), None);
        // A route this middleware doesn't protect (see `public_routes`).
        assert_eq!(operation_for_route(&Method::GET, "/v1/health"), None);
        // The receipt route. This assertion used to say `None`, and it was RIGHT: the route did
        // not exist, so the SDK's `GET /v1/pods/{id}/receipt` 404'd while `Operation::GetReceipt`
        // sat in the enum unused. The test faithfully recorded the gap instead of closing it.
        assert_eq!(
            operation_for_route(&Method::GET, "/v1/pods/abc-123/receipt"),
            Some(Operation::GetReceipt)
        );
        // Unmapped nested path.
        assert_eq!(
            operation_for_route(&Method::GET, "/v1/pods/abc-123/nonesuch"),
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
