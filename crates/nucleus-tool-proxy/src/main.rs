#![allow(clippy::disallowed_types)] // #1216 exempt: pod setup, web client init, spec loading (infrastructure)
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{middleware, Json, Router};
use clap::Parser;
use nucleus::portcullis::escalation::{EscalationError, SpiffeTraceChain, SpiffeTraceLink};
use nucleus::portcullis::kernel::{DecisionToken, Kernel};
use nucleus::portcullis::{CapabilityLevel, NodeKind, Operation, PermissionLattice};
use nucleus::{ApprovalRequest, CallbackApprover, NucleusError, PodRuntime};
use nucleus_permission_market::{PermissionBid, PermissionGrant, PermissionMarket};
use nucleus_spec::PodSpec;
use portcullis::flow_graph::FlowGraph;
use portcullis::verdict_sink::{ActorIdentity, VerdictContext, VerdictOutcome};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tracing::{error, info, warn};

mod art12;
mod art12_shipper;
mod art12_sink;
mod attestation;
mod auth;
mod broker_client;
mod cert_bridge;
mod declassify;
mod dlc_admission;
mod egress;
mod escalate;
mod exit_report;
mod identity_fusion;
mod ingest;
mod lockdown_client;
#[cfg(feature = "mcp")]
mod mcp;
mod mediation;
mod memory;
mod mtls;
mod node_client;
mod pod_mgmt;
mod policy;
mod run_gate;
mod sandbox_proof;
mod session_token;
mod telemetry;
#[allow(dead_code)]
mod unicode_audit;
mod validation;
mod verdict_sink;
mod web_fetch_policy;
mod workload;

use attestation::{AttestationConfig, AttestationVerifier};
use auth::{AuthConfig, AuthError};
use base64::Engine as _;
use mtls::{ClientCertInfo, MtlsConfig, MtlsConnectInfo, MtlsListener};
use nucleus_client::drand::{DrandConfig, DrandFailMode};
use nucleus_identity::approval_bundle::{compute_manifest_hash, ApprovalBundleVerifier};
use policy::PolicyEngine;

#[derive(Parser, Debug)]
#[command(name = "nucleus-tool-proxy")]
#[command(about = "Tool proxy server running inside nucleus pods")]
struct Args {
    /// Pod spec YAML path.
    #[arg(long, env = "NUCLEUS_POD_SPEC")]
    spec: PathBuf,
    /// Listen address for the tool proxy (TCP).
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_LISTEN", default_value = "127.0.0.1:0")]
    listen: String,
    /// Optional path to write the bound address for discovery.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_ANNOUNCE")]
    announce_path: Option<PathBuf>,
    /// Optional vsock CID override.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_VSOCK_CID")]
    vsock_cid: Option<u32>,
    /// Optional vsock port override.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_VSOCK_PORT")]
    vsock_port: Option<u32>,
    /// Shared secret for HMAC request signing.
    /// HMAC key for the shared-secret auth tier.
    ///
    /// Defaults to empty because a host-verified vsock listener does not use it
    /// — see `enforce_hmac_key_quality`, which still refuses an empty key on
    /// every transport that can actually select the HMAC tier.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_AUTH_SECRET", default_value = "")]
    auth_secret: String,
    /// Maximum allowed clock skew (seconds) for signed requests.
    #[arg(
        long,
        env = "NUCLEUS_TOOL_PROXY_AUTH_MAX_SKEW_SECS",
        default_value_t = 30
    )]
    auth_max_skew_secs: u64,
    /// Audit log path.
    #[arg(
        long,
        env = "NUCLEUS_TOOL_PROXY_AUDIT_LOG",
        default_value = "/var/log/nucleus/audit.log"
    )]
    audit_log: PathBuf,
    /// Optional audit log signing secret (defaults to auth secret if omitted).
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_AUDIT_SECRET")]
    audit_secret: Option<String>,
    /// Path for the EU AI Act Article 12 record-keeping log (JSONL, hash-chained).
    ///
    /// Absent means no Article 12 log is kept — the runtime does not pretend to
    /// record-keeping it was not configured for. Present means EVERY kernel
    /// decision is appended before the operation proceeds, and a write failure
    /// latches the log degraded so the next operation is refused.
    ///
    /// MUST NOT be inside the agent's workspace: the log is the runtime's record
    /// about the session, and #2145 is the same mistake made with the exit
    /// report. Startup refuses rather than warns.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_ART12_LOG")]
    art12_log: Option<PathBuf>,
    /// Host URL to stream Article 12 records to as they are produced.
    /// See `art12_shipper` for why this is fail-closed and why it matters.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_ART12_SHIP_URL")]
    art12_ship_url: Option<String>,
    /// Approval authority secret (separate from tool auth). Legacy: superseded
    /// by `--approval-pubkeys` wherever that is set. Empty means "not
    /// provisioned", which is fatal at startup unless pubkeys are.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_APPROVAL_SECRET", default_value = "")]
    approval_secret: String,
    /// Comma-separated 64-char-hex Ed25519 approver PUBLIC keys. When set,
    /// `/v1/approve` accepts ONLY an approver's signature (drand-anchored);
    /// no approval secret exists in the guest to steal. This is how
    /// Firecracker pods are provisioned (`nucleus.approval_pubkeys` — a
    /// verification key is safe on the world-readable cmdline, and it is
    /// per-node config, so it does not block a snapshot base).
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_APPROVAL_PUBKEYS")]
    approval_pubkeys: Option<String>,
    /// Optional webhook URL for remote audit log delivery.
    /// Entries are POSTed as JSON with HMAC signature in X-Nucleus-Signature header.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_AUDIT_WEBHOOK")]
    audit_webhook: Option<String>,
    /// S3 bucket for deletion-resistant audit storage.
    /// Each audit entry is stored as a separate object with `if_none_match("*")`
    /// to enforce append-only semantics. Compatible with AWS S3, MinIO, R2, Tigris.
    #[cfg(feature = "remote-audit")]
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_AUDIT_S3_BUCKET")]
    audit_s3_bucket: Option<String>,
    /// Key prefix for audit objects in S3 (e.g. "audit/pod-name").
    #[cfg(feature = "remote-audit")]
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_AUDIT_S3_PREFIX")]
    audit_s3_prefix: Option<String>,
    /// AWS region for the audit S3 bucket.
    #[cfg(feature = "remote-audit")]
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_AUDIT_S3_REGION")]
    audit_s3_region: Option<String>,
    /// Custom S3 endpoint URL (for MinIO, R2, Tigris, etc.).
    #[cfg(feature = "remote-audit")]
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_AUDIT_S3_ENDPOINT")]
    audit_s3_endpoint: Option<String>,
    /// Timeout in seconds for web fetch requests.
    #[arg(
        long,
        env = "NUCLEUS_TOOL_PROXY_WEB_FETCH_TIMEOUT_SECS",
        default_value_t = 15
    )]
    web_fetch_timeout_secs: u64,
    /// Maximum response body size in bytes for web fetch.
    #[arg(
        long,
        env = "NUCLEUS_TOOL_PROXY_WEB_FETCH_MAX_BYTES",
        default_value_t = 5 * 1024 * 1024
    )]
    web_fetch_max_bytes: usize,
    /// Require attestation for all requests.
    /// When enabled, requests must include valid VM attestation.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_REQUIRE_ATTESTATION")]
    require_attestation: bool,
    /// Comma-separated list of allowed kernel hashes (SHA-256, hex).
    /// If empty, any kernel hash is accepted when attestation is present.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_ALLOWED_KERNEL_HASHES")]
    allowed_kernel_hashes: Option<String>,
    /// Comma-separated list of allowed rootfs hashes (SHA-256, hex).
    /// If empty, any rootfs hash is accepted when attestation is present.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_ALLOWED_ROOTFS_HASHES")]
    allowed_rootfs_hashes: Option<String>,
    /// Comma-separated list of allowed config hashes (SHA-256, hex).
    /// If empty, any config hash is accepted when attestation is present.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_ALLOWED_CONFIG_HASHES")]
    allowed_config_hashes: Option<String>,

    // === Sandbox Proof Configuration ===
    /// Path to identity certificate PEM for sandbox proof (tier 1/2).
    /// Falls back to --tls-cert if not specified.
    #[arg(long, env = "NUCLEUS_IDENTITY_CERT")]
    identity_cert: Option<std::path::PathBuf>,
    /// SPIRE Workload API socket path for sandbox proof (tier 2).
    #[arg(long, env = "NUCLEUS_SPIRE_SOCKET")]
    spire_socket: Option<String>,

    // === mTLS Configuration ===
    /// Enable mTLS mode. Requires --tls-cert and --tls-key and --trust-bundle.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_MTLS")]
    mtls: bool,
    /// Path to server certificate PEM file (for mTLS).
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_TLS_CERT")]
    tls_cert: Option<std::path::PathBuf>,
    /// Path to server private key PEM file (for mTLS).
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_TLS_KEY")]
    tls_key: Option<std::path::PathBuf>,
    /// Path to trust bundle PEM file (for mTLS client verification).
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_TRUST_BUNDLE")]
    trust_bundle: Option<std::path::PathBuf>,
    /// Trust domain for SPIFFE identity verification.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_TRUST_DOMAIN")]
    trust_domain: Option<String>,

    // === Policy Configuration ===
    /// Path to identity-based policy YAML file.
    /// When provided, enables zero-prompt authorization for SPIFFE identities.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_POLICY")]
    policy_file: Option<std::path::PathBuf>,

    /// Enable zero-prompt mode (requires --policy-file).
    /// When enabled, operations matching SPIFFE identity policies are auto-approved.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_ZERO_PROMPT")]
    zero_prompt: bool,

    // === Drand Configuration ===
    /// Enable drand anchoring for approval signatures.
    /// When enabled, approval requests must include a valid drand round number
    /// to prevent pre-computation attacks.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_DRAND_ENABLED", default_value_t = true)]
    drand_enabled: bool,
    /// Drand API endpoint URL.
    #[arg(
        long,
        env = "NUCLEUS_TOOL_PROXY_DRAND_URL",
        default_value = "https://api.drand.sh/public/latest"
    )]
    drand_url: String,
    /// Number of previous drand rounds to accept (tolerance for network latency).
    /// With tolerance=1, both current round N and previous round N-1 are valid.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_DRAND_TOLERANCE", default_value_t = 1)]
    drand_tolerance: u64,
    /// Drand failure mode when beacon is unavailable.
    /// - "strict": Reject requests (fail closed) - recommended for production
    /// - "cached": Use cached round for 60 seconds max
    #[arg(
        long,
        env = "NUCLEUS_TOOL_PROXY_DRAND_FAIL_MODE",
        default_value = "strict"
    )]
    drand_fail_mode: String,

    // === Pod Management Configuration (orchestrator mode) ===
    /// Enable pod management endpoints (for orchestrator pods).
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_ENABLE_POD_MGMT")]
    enable_pod_mgmt: bool,

    /// nucleus-node HTTP endpoint for pod management.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_NODE_URL")]
    node_url: Option<String>,

    /// Auth secret for requests to nucleus-node (HMAC).
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_NODE_AUTH_SECRET")]
    node_auth_secret: Option<String>,

    /// gRPC endpoint of nucleus-node for streaming lockdown commands.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_NODE_GRPC_URL")]
    node_grpc_url: Option<String>,

    /// Delegation ceiling for sub-pod permissions (JSON-serialized PermissionLattice).
    /// Sub-pods cannot exceed this ceiling via delegate_to().
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_DELEGATION_CEILING")]
    delegation_ceiling: Option<String>,

    // === Delegation Certificate Configuration ===
    /// Hex-encoded Ed25519 public key of the root delegation authority.
    /// When set, the tool-proxy accepts `x-nucleus-delegation-cert` headers
    /// and verifies delegation certificates against this root key.
    #[arg(long, env = "NUCLEUS_CERT_ROOT_PUBKEY")]
    cert_root_pubkey: Option<String>,

    // === Live-Path Session Task Token (PR-2, present-not-consumed) ===
    // Host-minted session capability token injected on the SAME host-controlled
    // boot channel that provisions credentials (the pod boot environment set by
    // the node — see nucleus-node's pod launch). NEVER read from an agent-supplied
    // field (`spec_yaml`, tool args). Verified once at startup and held privately
    // in `AppState`; a later PR consumes it to gate RunBash. Fail-closed: absent
    // or invalid ⇒ the later gate DENIES.
    /// Serialized (JSON) host-minted session task token (`SignedTaskRef`).
    #[arg(long, env = "NUCLEUS_TASK_TOKEN")]
    task_token: Option<String>,
    /// Hex-encoded 16-byte expected effective nonce for the session task token.
    /// Host-controlled out-of-band value (never agent-readable) — the token
    /// chain's truncation defense.
    #[arg(long, env = "NUCLEUS_TASK_TOKEN_NONCE")]
    task_token_nonce: Option<String>,
    /// Hex-encoded 32-byte Ed25519 root issuer public key the session task token
    /// is pinned to.
    #[arg(long, env = "NUCLEUS_TASK_TOKEN_ISSUER")]
    task_token_issuer: Option<String>,

    // === Approval Bundle Configuration ===
    /// Require a signed approval bundle at startup.
    /// When set, the tool-proxy refuses to start without a valid JWS bundle
    /// in the NUCLEUS_APPROVAL_BUNDLE environment variable.
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_REQUIRE_APPROVAL_BUNDLE")]
    require_approval_bundle: bool,

    // === MCP Server Mode ===
    /// Run as an MCP (Model Context Protocol) server on stdio instead of HTTP.
    /// Mutually exclusive with the HTTP server.
    #[cfg(feature = "mcp")]
    #[arg(long, env = "NUCLEUS_TOOL_PROXY_MCP")]
    mcp: bool,
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) runtime: Arc<PodRuntime>,
    approvals: Arc<ApprovalRegistry>,
    audit: Arc<AuditLog>,
    /// Where a spent [`Authority`] records that it was exercised.
    ///
    /// Distinct from `audit` above: that is the pod's hash-chained audit surface,
    /// this is the effect-discharge receipt log that
    /// `portcullis_effects::authority::Authority::spend` writes to. `spend`
    /// REFUSES an unwitnessed authority (`SpendError::Unwitnessed`), so without
    /// this field the brokered-egress path would fail on every request — safe,
    /// and inert, which is the failure shape this arc has already produced twice.
    ///
    /// **Limit, and it is the one already recorded for FM-3 rather than a new
    /// one:** `ReceiptLog` is an in-memory `Vec`, so an append cannot fail and
    /// "the effect is refused if the record cannot be written" is still not
    /// expressible. It becomes real when the log gains durable backing. See
    /// `docs/production-delta.md`, "Receipt log resilience (FM-3)".
    receipts: Arc<portcullis_effects::receipt::ReceiptLog>,
    auth: AuthConfig,
    approval_auth: AuthConfig,
    /// Approver PUBLIC keys for signature-based approvals. `Some` makes the
    /// Ed25519 tier the ONLY way into `/v1/approve` (the HMAC approval tier
    /// becomes unreachable — see `auth::select_auth_tier`); `None` keeps the
    /// legacy shared-secret tier for env-provisioned container pods. Holding
    /// only verifying keys, the guest cannot forge what it checks.
    approval_verifier: Option<auth::ApprovalVerifier>,
    /// True when this server was started on a vsock listener that accepts only
    /// the host (`pod_mgmt::peer_is_host`).
    ///
    /// When set, a request's origin is established by the transport — the guest
    /// kernel sets the peer CID and no guest process can forge it — so the HMAC
    /// fallback is not consulted. It is a fact about how the server was bound,
    /// never something a request can claim.
    host_verified_transport: bool,
    approval_nonces: Arc<ApprovalNonceCache>,
    approval_rate_limiter: Arc<ApprovalRateLimiter>,
    pub(crate) web_client: reqwest::Client,
    /// Upstreams reachable with a credential the workload never holds.
    pub(crate) credentialed_egress: Vec<nucleus_spec::CredentialedEgressSpec>,
    /// Effective web_fetch response cap: pod `network.max_response_bytes` else
    /// `--web-fetch-max-bytes`. Resolved once so every read site agrees.
    web_fetch_max_bytes: usize,
    /// Pod `network.mime_allow` override; `None` = built-in `ALLOWED_MIME_PREFIXES`.
    web_fetch_mime_allow: Option<Vec<String>>,
    dns_allow: Vec<String>,
    /// URL pattern allowlist for web_fetch. If non-empty, URLs must match.
    url_allow: Vec<String>,
    attestation_verifier: AttestationVerifier,
    policy_engine: PolicyEngine,
    /// Node client for pod management (orchestrator mode only).
    node_client: Option<Arc<node_client::NodeClient>>,
    /// Delegation ceiling: sub-pod permissions cannot exceed this.
    delegation_ceiling: Option<Arc<PermissionLattice>>,
    /// Credentials loaded from orchestrator environment for injection into sub-pods.
    orchestrator_credentials: std::collections::BTreeMap<String, String>,
    /// Permission market for Lagrangian pricing of capability dimensions.
    permission_market: Arc<Mutex<PermissionMarket>>,
    /// Cryptographic proof that this process is inside a managed sandbox.
    sandbox_proof: sandbox_proof::SandboxProof,
    /// Root authority Ed25519 public key for delegation certificate verification.
    cert_root_pubkey: Option<Arc<Vec<u8>>>,
    /// Session exposure guard for exit report (set when MCP server starts).
    exposure_guard: Arc<std::sync::RwLock<Option<Arc<portcullis::GradedExposureGuard>>>>,
    /// File-based lockdown flag. Set by the signal file watcher.
    file_lockdown: Arc<std::sync::atomic::AtomicBool>,
    /// gRPC stream-based lockdown flag. Set by the lockdown streaming client.
    stream_lockdown: Arc<std::sync::atomic::AtomicBool>,
    /// SHA-256 checksum of the permission lattice for telemetry correlation.
    /// Kept for future audit-log integration in VerdictSink (PR 3).
    #[allow(dead_code)]
    policy_checksum: String,
    /// Session ID (policy UUID) for telemetry grouping.
    /// Kept for future audit-log integration in VerdictSink (PR 3).
    #[allow(dead_code)]
    session_id: String,
    /// Shared verdict sink for lockdown + telemetry convergence (HTTP + MCP).
    ///
    /// This IS the monitor below — `build_monitored_sink` returns one object
    /// under two handles — so the field cannot hold an unmonitored sink.
    pub(crate) verdict_sink: Arc<dyn portcullis::verdict_sink::VerdictSink>,
    /// The Article 12 record-keeping log, when configured. Held so the host can
    /// see the chain head and whether recording is still happening — a log the
    /// operator cannot observe is one that can stop without anyone noticing.
    pub(crate) art12_log: Option<Arc<crate::art12::Art12Log>>,
    /// Read handle on the runtime monitor wrapping `verdict_sink`, so the
    /// process can report what the decision stream actually did — live at
    /// `/v1/health`, and at shutdown in the exit report.
    pub(crate) trace_monitor: Arc<portcullis::trace_monitor::TraceMonitor>,
    /// Kernel decision engine for complete mediation (HTTP path).
    pub(crate) kernel: Arc<tokio::sync::Mutex<Kernel>>,
    /// Whether DLC-D verified admission was provisioned on this pod's kernels
    /// (NUCLEUS_DLC_* env, possibly via PodSpec labels). Exposed in /v1/health
    /// so a host — or the Tier 2 harness — can distinguish "the gate refused"
    /// from "the gate was never armed".
    pub(crate) dlc_provisioned: bool,
    /// Session-scoped information-flow graph for the lethal-trifecta guard — the
    /// kernel's proven `FlowGraph`, and the SINGLE authoritative graph the egress
    /// verdict reads (Phase 2 retirement: the former `FlowTracker` oracle and its
    /// divergence canary are gone — there is one graph now). Process-wide,
    /// mirroring the shared kernel: the tool-proxy is a per-pod sidecar (one pod =
    /// one session = one process), so a single shared graph has the same semantics
    /// as the single shared kernel. Under any hypothetical multi-session-per-process
    /// hosting it fails *closed* (taint from any actor blocks outbound for all).
    /// Populated only through the server-computed `ingest` chokepoint — never from
    /// client-declared lineage.
    pub(crate) flow_graph: Arc<tokio::sync::Mutex<FlowGraph>>,
    /// Path → the flow node recording the content last written there.
    ///
    /// This is #2135's laundered-path SET, generalised from a boolean into an
    /// EDGE. That version answered "was this path written while tainted?"; this
    /// one answers "which node produced the content at this path?", and the
    /// taint answer falls out of it — a read whose parent is a tainted write
    /// node inherits `Adversarial` through `propagate_label`, so the special
    /// case #2135 hand-coded becomes a consequence of the graph.
    ///
    /// The proxy may only record edges it MEDIATED BOTH ENDS OF. It wrote these
    /// bytes and it read them back, so this edge is established, not declared —
    /// which matters because the agent is the compromised party under the threat
    /// model and cannot be asked to report its own data flow.
    pub(crate) path_provenance: Arc<tokio::sync::Mutex<std::collections::HashMap<String, u64>>>,
    /// Provenance-verified, taint-labeled agent memory (next-bet #1). A write
    /// goes through `verified_admit`; a recall observes the record's own label
    /// into the single authoritative `flow_graph` so the IFC gate governs whether it
    /// may inform an action. Process-wide, same per-pod-session rationale as the
    /// shared kernel.
    pub(crate) provenance_memory:
        Arc<tokio::sync::Mutex<nucleus_provenance_memory::ProvenanceMemorySet>>,
    /// Deterministic transforms used to recompute-verify `Deterministic` memory
    /// records. Empty by default ⇒ deterministic records fail closed (`Invalid`).
    pub(crate) memory_transforms: Arc<nucleus_provenance_memory::TransformRegistry>,
    /// Trusted Ed25519 verifying keys (32-byte) that may cosign a memory
    /// declassification. From `NUCLEUS_DECLASSIFY_TRUSTED_KEYS`; empty ⇒ every
    /// declassify fails closed (no quorum possible).
    pub(crate) declassify_trusted_keys: Arc<Vec<[u8; 32]>>,
    /// k-of-n threshold for memory declassification. From
    /// `NUCLEUS_DECLASSIFY_THRESHOLD` (default 1); with empty trusted keys this
    /// is unsatisfiable, so declassification is fail-closed until configured.
    pub(crate) declassify_threshold: usize,
    /// Host-minted session capability token, verified once at startup (PR-2,
    /// present-not-consumed). Private to the tool-proxy session — NOT
    /// agent-reachable. Fail-closed: `Missing`/`Invalid` MUST cause the later
    /// RunBash-gating PR to DENY. Consumed by that later PR, hence unused today.
    #[allow(dead_code)]
    pub(crate) session_task_token: session_token::SessionTaskToken,
}

/// OR-semantics: locked if EITHER signal file OR gRPC stream says locked.
/// This prevents a race condition where one path could undo the other.
fn is_locked(state: &AppState) -> bool {
    state
        .file_lockdown
        .load(std::sync::atomic::Ordering::Acquire)
        || state
            .stream_lockdown
            .load(std::sync::atomic::Ordering::Acquire)
}

/// Convert the runtime's `portcullis::CapabilityLattice` into the
/// `portcullis_core` / `nucleus_ifc_kernel` lattice that
/// [`portcullis_effects::production_effects_concrete`] expects — the lattice the
/// sealed net effect's `PolicyEnforced` gate reads (B5). Both carry the identical
/// 13 named dimensions over the same `CapabilityLevel`, so this is a straight
/// field-for-field copy; the `portcullis` lattice's extension dimensions have no
/// `portcullis_core` counterpart and are dropped (net-irrelevant). Mirrors
/// nucleus core's `command::core_capabilities`.
pub(crate) fn core_capabilities(
    caps: &portcullis::CapabilityLattice,
) -> nucleus_ifc_kernel::CapabilityLattice {
    nucleus_ifc_kernel::CapabilityLattice {
        read_files: caps.read_files,
        write_files: caps.write_files,
        edit_files: caps.edit_files,
        run_bash: caps.run_bash,
        glob_search: caps.glob_search,
        grep_search: caps.grep_search,
        web_search: caps.web_search,
        web_fetch: caps.web_fetch,
        git_commit: caps.git_commit,
        git_push: caps.git_push,
        create_pr: caps.create_pr,
        manage_pods: caps.manage_pods,
        spawn_agent: caps.spawn_agent,
    }
}

/// Extract an ActorIdentity from the auth context for verdict recording.
/// Refuse a world-known HMAC key — but only on transports that can select the
/// HMAC tier.
///
/// An EMPTY `auth_secret` satisfies "present" while being a key anyone can
/// compute: an attacker signs with `HMAC(∅, msg)` and every signed request and
/// sandbox token becomes forgeable. That has always been fail-closed here.
///
/// What changed is that on a **host-verified vsock listener** the HMAC tier is
/// unreachable — `auth::select_auth_tier` returns `HostVsock`, and the peer's
/// identity comes from a CID the guest kernel sets and no guest process can
/// forge. On that transport the key is not weak, it is *unused*, and demanding
/// one would force a secret onto the kernel command line for nothing. That
/// command line is world-readable inside the guest, which is the exposure this
/// whole change exists to remove.
///
/// So: still fail closed wherever the key can be reached, and stay silent only
/// where it provably cannot be.
fn enforce_hmac_key_quality(auth_secret: &str, host_verified_transport: bool) {
    if host_verified_transport {
        if !auth_secret.trim().is_empty() {
            warn!(
                "an HMAC auth secret was supplied but this server is bound to a host-verified \
                 vsock listener, where the HMAC tier is unreachable — the secret is unused"
            );
        }
        return;
    }
    if auth_secret.trim().is_empty() {
        error!(
            "NUCLEUS_TOOL_PROXY_AUTH_SECRET is empty — refusing to start: an empty HMAC key is \
             world-known and makes sandbox tokens and request auth forgeable (fail-closed)"
        );
        std::process::exit(1);
    }
    if auth_secret.len() < nucleus_client::MIN_AUTH_SECRET_LEN {
        warn!(
            secret_len = auth_secret.len(),
            min = nucleus_client::MIN_AUTH_SECRET_LEN,
            "NUCLEUS_TOOL_PROXY_AUTH_SECRET is shorter than the recommended minimum — weak HMAC key"
        );
    }
}

pub(crate) fn actor_from_auth(auth: Option<&auth::AuthContext>) -> ActorIdentity {
    if let Some(ctx) = auth {
        if let Some(ref spiffe_id) = ctx.spiffe_id {
            ActorIdentity::Authenticated {
                spiffe_id: spiffe_id.clone(),
            }
        } else {
            ActorIdentity::Unknown
        }
    } else {
        ActorIdentity::Unknown
    }
}

#[derive(Default)]
struct ApprovalRegistry {
    approvals: Mutex<HashMap<String, ApprovalEntry>>,
}

#[derive(Default)]
struct ApprovalNonceCache {
    entries: Mutex<HashMap<String, u64>>,
}

impl ApprovalNonceCache {
    fn check_and_insert(&self, nonce: &str, expires_at_unix: u64, now: u64) -> bool {
        let mut guard = self.entries.lock().unwrap();
        guard.retain(|_, exp| *exp > now);
        if guard.contains_key(nonce) {
            return false;
        }
        guard.insert(nonce.to_string(), expires_at_unix);
        true
    }
}

/// Simple token bucket rate limiter for the approval endpoint.
/// Prevents DoS attacks by limiting approval requests per second.
struct ApprovalRateLimiter {
    /// Maximum tokens (burst capacity)
    max_tokens: u32,
    /// Tokens added per second
    refill_rate: u32,
    /// Current token count and last refill timestamp
    state: Mutex<(u32, u64)>,
}

impl ApprovalRateLimiter {
    fn new(max_tokens: u32, refill_rate: u32) -> Self {
        Self {
            max_tokens,
            refill_rate,
            state: Mutex::new((max_tokens, now_unix())),
        }
    }

    /// Try to consume a token. Returns true if allowed, false if rate limited.
    fn try_acquire(&self) -> bool {
        let mut guard = self.state.lock().unwrap();
        let (tokens, last_refill) = &mut *guard;
        let now = now_unix();

        // Refill tokens based on elapsed time
        let elapsed = now.saturating_sub(*last_refill);
        if elapsed > 0 {
            let refill = (elapsed as u32).saturating_mul(self.refill_rate);
            *tokens = (*tokens).saturating_add(refill).min(self.max_tokens);
            *last_refill = now;
        }

        // Try to consume a token
        if *tokens > 0 {
            *tokens -= 1;
            true
        } else {
            false
        }
    }
}

impl Default for ApprovalRateLimiter {
    fn default() -> Self {
        // Allow 10 approvals per second with burst of 20
        Self::new(20, 10)
    }
}

#[derive(Clone, Copy)]
struct ApprovalEntry {
    count: usize,
    expires_at_unix: Option<u64>,
}

impl ApprovalRegistry {
    fn approve(&self, operation: &str, count: usize, expires_at_unix: Option<u64>) {
        let mut guard = self.approvals.lock().unwrap();
        let entry = guard.entry(operation.to_string()).or_insert(ApprovalEntry {
            count: 0,
            expires_at_unix,
        });
        entry.count += count;
        entry.expires_at_unix = merge_expiry(entry.expires_at_unix, expires_at_unix);
    }

    fn consume(&self, operation: &str) -> bool {
        let mut guard = self.approvals.lock().unwrap();
        if let Some(entry) = guard.get_mut(operation) {
            if is_expired(entry.expires_at_unix) {
                guard.remove(operation);
                return false;
            }
            if entry.count > 0 {
                entry.count -= 1;
                if entry.count == 0 {
                    guard.remove(operation);
                }
                return true;
            }
        }
        false
    }
}

fn merge_expiry(existing: Option<u64>, incoming: Option<u64>) -> Option<u64> {
    match (existing, incoming) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn is_expired(expires_at_unix: Option<u64>) -> bool {
    match expires_at_unix {
        Some(ts) => ts <= now_unix(),
        None => false,
    }
}

/// Simple URL glob matcher for `url_allow` patterns.
///
/// - `*` matches any sequence of characters except `/`
/// - `**` matches any sequence of characters including `/`
/// - All other characters match literally.
pub(crate) fn url_glob_match(pattern: &str, url: &str) -> bool {
    url_glob_match_inner(pattern.as_bytes(), url.as_bytes())
}

fn url_glob_match_inner(pattern: &[u8], text: &[u8]) -> bool {
    if pattern.is_empty() {
        return text.is_empty();
    }
    if pattern.len() >= 2 && pattern[0] == b'*' && pattern[1] == b'*' {
        // `**` — match any number of chars (including `/`)
        let rest = &pattern[2..];
        for i in 0..=text.len() {
            if url_glob_match_inner(rest, &text[i..]) {
                return true;
            }
        }
        return false;
    }
    if pattern[0] == b'*' {
        // `*` — match any number of non-`/` chars
        let rest = &pattern[1..];
        for i in 0..=text.len() {
            if i > 0 && text[i - 1] == b'/' {
                break;
            }
            if url_glob_match_inner(rest, &text[i..]) {
                return true;
            }
        }
        return false;
    }
    if text.is_empty() {
        return false;
    }
    if pattern[0] == text[0] {
        return url_glob_match_inner(&pattern[1..], &text[1..]);
    }
    false
}

/// Load and verify a signed approval bundle from the NUCLEUS_APPROVAL_BUNDLE env var.
///
/// If present and valid, populates the ApprovalRegistry with the approved operations.
/// If `require` is true, the function returns an error when the env var is missing.
fn load_approval_bundle(
    spec_contents: &str,
    approvals: &ApprovalRegistry,
    require: bool,
) -> Result<(), ApiError> {
    let jws = match std::env::var("NUCLEUS_APPROVAL_BUNDLE") {
        Ok(val) if !val.is_empty() => val,
        _ => {
            if require {
                return Err(ApiError::Spec(
                    "--require-approval-bundle is set but NUCLEUS_APPROVAL_BUNDLE is not set"
                        .to_string(),
                ));
            }
            return Ok(());
        }
    };

    let trusted_keys = parse_approval_trusted_keys();
    verify_and_load_approval_bundle(&jws, spec_contents, approvals, &trusted_keys)
}

/// Parse the pinned trusted approver keys from `NUCLEUS_APPROVAL_TRUSTED_KEYS`
/// (a JSON array of JWKs). Unset / empty / parse-error ⇒ empty set ⇒ approval
/// bundles are refused fail-closed. Mirrors the `NUCLEUS_DECLASSIFY_TRUSTED_KEYS`
/// pinned-trust-anchor pattern.
fn parse_approval_trusted_keys() -> Vec<nucleus_identity::did::JsonWebKey> {
    match std::env::var("NUCLEUS_APPROVAL_TRUSTED_KEYS") {
        Ok(val) if !val.trim().is_empty() => {
            match serde_json::from_str::<Vec<nucleus_identity::did::JsonWebKey>>(&val) {
                Ok(keys) => keys,
                Err(e) => {
                    warn!(
                        error = %e,
                        "NUCLEUS_APPROVAL_TRUSTED_KEYS is set but is not a valid JSON array of \
                         JWKs — treating as empty (approval bundles will be refused fail-closed)"
                    );
                    Vec::new()
                }
            }
        }
        _ => Vec::new(),
    }
}

/// Verify a JWS approval bundle against a PINNED set of trusted approver keys and
/// populate the ApprovalRegistry.
///
/// SECURITY: the bundle is verified against `trusted_keys` (the pinned approver
/// trust anchors), NOT against the key embedded in the JWS header. Trusting the
/// header's own JWK would be vacuous — an attacker could sign a bundle with their
/// own key, embed that key in the header, and self-verify, bypassing the
/// human-in-the-loop approval gate. Fail-closed: if no trusted approver key is
/// configured, the bundle is refused.
fn verify_and_load_approval_bundle(
    jws: &str,
    spec_contents: &str,
    approvals: &ApprovalRegistry,
    trusted_keys: &[nucleus_identity::did::JsonWebKey],
) -> Result<(), ApiError> {
    let manifest_hash = compute_manifest_hash(spec_contents.as_bytes());

    // Fail-closed: never self-trust the bundle's embedded key. Without a pinned
    // trusted approver key there is no authority to check against, so refuse.
    if trusted_keys.is_empty() {
        return Err(ApiError::Spec(
            "no trusted approver keys configured (set NUCLEUS_APPROVAL_TRUSTED_KEYS) — refusing \
             to load an approval bundle fail-closed (the embedded JWS key is never self-trusted)"
                .to_string(),
        ));
    }

    let verifier = ApprovalBundleVerifier::new();
    // Verify against each PINNED trusted approver key; accept the first that the
    // bundle validly matches (correct key + valid signature + manifest binding).
    // A bundle signed by any non-trusted key is rejected.
    let claims = trusted_keys
        .iter()
        .find_map(|tk| verifier.verify(jws, tk, &manifest_hash).ok())
        .ok_or_else(|| {
            ApiError::Spec(
                "approval bundle signer is not a trusted approver key (or the signature / \
                 manifest binding is invalid)"
                    .to_string(),
            )
        })?;

    // Populate the ApprovalRegistry with the approved operations
    let count = claims.max_uses.map(|n| n as usize).unwrap_or(usize::MAX);
    let expiry = Some(claims.exp as u64);
    for op in &claims.approved_operations {
        approvals.approve(op, count, expiry);
        info!(
            operation = %op,
            count = count,
            expires_at = claims.exp,
            event = "approval_bundle_loaded",
            "pre-approved operation from signed bundle"
        );
    }

    info!(
        issuer = %claims.iss,
        jti = %claims.jti,
        operations = ?claims.approved_operations,
        manifest_hash = %claims.manifest_hash,
        event = "approval_bundle_verified",
        "signed approval bundle verified and loaded"
    );

    Ok(())
}

#[derive(Debug, Deserialize)]
struct ReadRequest {
    path: String,
}

#[derive(Debug, Serialize)]
struct ReadResponse {
    contents: String,
}

#[derive(Debug, Deserialize)]
struct WriteRequest {
    path: String,
    contents: String,
}

#[derive(Debug, Serialize)]
struct WriteResponse {
    ok: bool,
}

/// Run command request using secure array-based format.
///
/// The array form prevents shell injection by executing commands directly
/// without shell interpretation. Each array element is passed as a separate
/// argument to the process.
#[derive(Debug, Deserialize)]
struct RunRequest {
    /// Command as array, e.g. ["ls", "-la", "/tmp"]
    args: Vec<String>,
    /// Optional input to pass to command stdin
    #[serde(default)]
    stdin: Option<String>,
    /// Optional working directory (relative to sandbox)
    #[serde(default)]
    directory: Option<String>,
    /// Optional timeout in seconds (clamped to policy limit)
    #[serde(default)]
    #[allow(dead_code)] // Reserved for future timeout implementation
    timeout_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
struct RunResponse {
    status: i32,
    success: bool,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Deserialize)]
struct ApproveRequest {
    operation: String,
    #[serde(default = "default_approve_count")]
    count: usize,
    #[serde(default)]
    expires_at_unix: Option<u64>,
    #[serde(default)]
    nonce: Option<String>,
}

fn default_approve_count() -> usize {
    1
}

const MAX_APPROVAL_TTL_SECS: u64 = 300;

#[derive(Debug, Serialize)]
struct ApproveResponse {
    ok: bool,
}

#[derive(Debug, Deserialize)]
struct WebFetchRequest {
    url: String,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    headers: Option<HashMap<String, String>>,
    #[serde(default)]
    body: Option<String>,
}

#[derive(Debug, Serialize)]
struct WebFetchResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    truncated: Option<bool>,
}

/// Glob pattern search request.
#[derive(Debug, Deserialize)]
struct GlobRequest {
    /// Glob pattern to match (e.g., "**/*.rs", "src/*.json")
    pattern: String,
    /// Optional directory to search in (relative to sandbox root)
    #[serde(default)]
    directory: Option<String>,
    /// Maximum number of results to return
    #[serde(default)]
    max_results: Option<usize>,
}

/// Glob search response.
#[derive(Debug, Serialize)]
struct GlobResponse {
    /// Matching file paths (relative to sandbox)
    matches: Vec<String>,
    /// True if results were truncated due to max_results
    #[serde(skip_serializing_if = "Option::is_none")]
    truncated: Option<bool>,
}

/// Grep (content search) request.
#[derive(Debug, Deserialize)]
struct GrepRequest {
    /// Regex pattern to search for
    pattern: String,
    /// Optional file path to search in (relative to sandbox)
    #[serde(default)]
    path: Option<String>,
    /// Optional glob pattern to filter files
    #[serde(default, rename = "glob")]
    file_glob: Option<String>,
    /// Number of context lines before/after match
    #[serde(default)]
    context_lines: Option<usize>,
    /// Maximum number of matches to return
    #[serde(default)]
    max_matches: Option<usize>,
    /// Case-insensitive search
    #[serde(default)]
    case_insensitive: Option<bool>,
}

/// A single grep match result.
#[derive(Debug, Serialize)]
struct GrepMatch {
    /// File path (relative to sandbox)
    file: String,
    /// Line number (1-indexed)
    line: usize,
    /// Matching line content
    content: String,
    /// Optional context lines before
    #[serde(skip_serializing_if = "Option::is_none")]
    context_before: Option<Vec<String>>,
    /// Optional context lines after
    #[serde(skip_serializing_if = "Option::is_none")]
    context_after: Option<Vec<String>>,
}

/// Grep search response.
#[derive(Debug, Serialize)]
struct GrepResponse {
    /// Matching results
    matches: Vec<GrepMatch>,
    /// True if results were truncated due to max_matches
    #[serde(skip_serializing_if = "Option::is_none")]
    truncated: Option<bool>,
}

/// Web search request.
#[derive(Debug, Deserialize)]
struct WebSearchRequest {
    /// Search query
    query: String,
    /// Maximum number of results
    #[serde(default)]
    max_results: Option<usize>,
}

/// A single web search result.
#[derive(Debug, Serialize)]
struct WebSearchResult {
    /// Result title
    title: String,
    /// Result URL
    url: String,
    /// Result snippet/description
    #[serde(skip_serializing_if = "Option::is_none")]
    snippet: Option<String>,
}

/// Web search response.
#[derive(Debug, Serialize)]
struct WebSearchResponse {
    /// Search results
    results: Vec<WebSearchResult>,
}

/// Request to escalate permissions for an agent.
#[derive(Debug, Deserialize)]
pub(crate) struct EscalateRequest {
    /// The requesting agent's SPIFFE trace chain (serialized).
    requestor_chain: SerializedTraceChain,
    /// The approver's SPIFFE trace chain (serialized).
    ///
    /// SECURITY: The approver MUST submit their full chain for proper verification.
    /// The server validates that:
    /// 1. The chain's leaf identity matches the mTLS authenticated identity
    /// 2. The chain is valid (non-expired, monotonically decreasing permissions)
    /// 3. The chain has no overlap with the requestor's chain (anti-self-escalation)
    approver_chain: SerializedTraceChain,
    /// Requested permission preset (e.g., "fix_issue", "permissive").
    requested_preset: String,
    /// Justification for the escalation.
    reason: String,
    /// TTL in seconds for the escalated permissions.
    ttl_seconds: u64,
    /// Unique nonce to prevent replay attacks.
    ///
    /// SECURITY: Required. Each escalation request must have a unique nonce.
    /// The server rejects requests with previously-seen nonces within the
    /// drand tolerance window (~60 seconds).
    nonce: String,
}

/// Serialized trace chain for transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializedTraceChain {
    /// Chain ID.
    id: String,
    /// Links in the chain.
    links: Vec<SerializedTraceLink>,
}

/// Serialized trace link for transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SerializedTraceLink {
    /// Link ID.
    id: String,
    /// SPIFFE ID.
    spiffe_id: String,
    /// Permission preset name (for reconstruction).
    preset: String,
    /// Drand round when created.
    drand_round: u64,
    /// Creation timestamp (Unix seconds).
    created_at: u64,
    /// Expiry timestamp (Unix seconds), if any.
    expires_at: Option<u64>,
    /// Reason for this link.
    reason: String,
}

/// Response from an escalation request.
#[derive(Debug, Serialize)]
pub(crate) struct EscalateResponse {
    /// Whether the escalation was granted.
    granted: bool,
    /// The grant ID (if granted).
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_id: Option<String>,
    /// Granted permission preset (if granted).
    #[serde(skip_serializing_if = "Option::is_none")]
    granted_preset: Option<String>,
    /// Expiry timestamp (Unix seconds).
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    /// Drand round of the grant.
    #[serde(skip_serializing_if = "Option::is_none")]
    drand_round: Option<u64>,
    /// Error message (if denied).
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    operation: Option<String>,
    /// Payment metadata for 402 responses (vendor-agnostic).
    #[serde(skip_serializing_if = "Option::is_none")]
    payment: Option<nucleus_spec::PaymentRequiredInfo>,
}

#[derive(Debug, thiserror::Error)]
enum ApiError {
    #[error("spec error: {0}")]
    Spec(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serde error: {0}")]
    Serde(#[from] serde_yaml::Error),
    #[error("nucleus error: {0}")]
    Nucleus(#[from] NucleusError),
    #[error("auth error: {0}")]
    Auth(#[from] AuthError),
    #[error("request body error: {0}")]
    Body(String),
    #[error("rate limited: too many approval requests")]
    RateLimited,
    #[error("web fetch error: {0}")]
    WebFetch(String),
    #[error("url not in dns_allow list: {0}")]
    DnsNotAllowed(String),
    #[error("attestation verification failed: {0}")]
    AttestationFailed(String),
    #[error("escalation error: {0}")]
    Escalation(String),
    /// The permission kernel refused, for a reason that is not a capability
    /// level. Carries the kernel's own reason rather than flattening every
    /// refusal into "capability is Never".
    #[error("kernel denied: {0}")]
    KernelDenied(String),
    #[error("validation error: {0}")]
    Validation(#[from] validation::ValidationError),
    #[error("permission bid denied: insufficient value")]
    PermissionDenied(#[allow(unused)] nucleus_spec::PaymentRequiredInfo),
    /// Operation denied by the information-flow control monitor: the session has
    /// ingested adversarial (untrusted/web) content and this is an outbound
    /// action that could exfiltrate or act on it (the lethal-trifecta guard,
    /// #1633). Wired into the HTTP path so it has parity with the MCP server.
    #[error("ifc denied: {0}")]
    IfcDenied(String),
    /// A governor declassification token was rejected (bad/absent signature,
    /// no trusted keys, expired, precondition unmet, or node not found).
    #[error("declassification denied: {0}")]
    Declassification(String),
    /// A governor declassification token was well-formed and signed but cannot
    /// take effect because its one-shot authority is spent or the node is
    /// already declassified. Distinct from a rejection so a governor can tell
    /// "already done" from "refused".
    #[error("declassification conflict: {0}")]
    DeclassificationConflict(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, kind, operation, payment) = match &self {
            ApiError::Nucleus(NucleusError::ApprovalRequired { operation }) => (
                StatusCode::FORBIDDEN,
                "approval_required",
                Some(operation.clone()),
                None,
            ),
            ApiError::Nucleus(NucleusError::BudgetExhausted {
                requested,
                remaining,
            }) => {
                let payment_info = nucleus_spec::PaymentRequiredInfo {
                    amount_usd: *requested,
                    reason: format!(
                        "budget exhausted: requested ${requested:.4}, remaining ${remaining:.4}"
                    ),
                    kind: nucleus_spec::PaymentRequiredKind::BudgetExhausted {
                        requested: *requested,
                        remaining: *remaining,
                    },
                    recipient: std::env::var("NUCLEUS_PAYMENT_RECIPIENT").ok(),
                    resource: None,
                };
                (
                    StatusCode::PAYMENT_REQUIRED,
                    "budget_exhausted",
                    None,
                    Some(payment_info),
                )
            }
            ApiError::Nucleus(NucleusError::CommandDenied { .. }) => {
                (StatusCode::FORBIDDEN, "command_denied", None, None)
            }
            // An authority earned for a different action was presented. FORBIDDEN
            // rather than 400: the request was well-formed, the authority was not
            // valid for it.
            ApiError::Nucleus(NucleusError::ScopeMismatch { .. }) => {
                (StatusCode::FORBIDDEN, "scope_mismatch", None, None)
            }
            ApiError::Nucleus(NucleusError::PathDenied { .. }) => {
                (StatusCode::FORBIDDEN, "path_denied", None, None)
            }
            ApiError::Nucleus(NucleusError::SandboxEscape { .. }) => {
                (StatusCode::FORBIDDEN, "sandbox_escape", None, None)
            }
            ApiError::KernelDenied(_) => (StatusCode::FORBIDDEN, "kernel_denied", None, None),
            ApiError::Nucleus(NucleusError::Io(_)) => {
                (StatusCode::INTERNAL_SERVER_ERROR, "io_error", None, None)
            }
            ApiError::Nucleus(NucleusError::TimeViolation { .. }) => {
                (StatusCode::REQUEST_TIMEOUT, "time_violation", None, None)
            }
            ApiError::Nucleus(NucleusError::StateBlocked { .. }) => {
                (StatusCode::FORBIDDEN, "uninhabitable_blocked", None, None)
            }
            ApiError::Nucleus(NucleusError::InsufficientCapability { .. }) => {
                (StatusCode::FORBIDDEN, "insufficient_capability", None, None)
            }
            ApiError::Nucleus(NucleusError::IsolationNotConfigured)
            | ApiError::Nucleus(NucleusError::IsolationInsufficient { .. })
            | ApiError::Nucleus(NucleusError::HardeningUnavailable { .. }) => {
                (StatusCode::FORBIDDEN, "isolation_denied", None, None)
            }
            ApiError::Nucleus(NucleusError::ProvenanceUnverified { .. }) => {
                (StatusCode::FORBIDDEN, "provenance_unverified", None, None)
            }
            ApiError::Nucleus(NucleusError::InvalidApproval { operation }) => (
                StatusCode::FORBIDDEN,
                "invalid_approval",
                Some(operation.clone()),
                None,
            ),
            ApiError::Nucleus(NucleusError::InvalidCharge { .. }) => {
                (StatusCode::BAD_REQUEST, "invalid_charge", None, None)
            }
            ApiError::Spec(_) => (StatusCode::BAD_REQUEST, "spec_error", None, None),
            ApiError::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, "io_error", None, None),
            ApiError::Serde(_) => (StatusCode::BAD_REQUEST, "serde_error", None, None),
            ApiError::Auth(_) => (StatusCode::UNAUTHORIZED, "auth_error", None, None),
            ApiError::Body(_) => (StatusCode::BAD_REQUEST, "body_error", None, None),
            ApiError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited", None, None),
            ApiError::WebFetch(_) => (StatusCode::BAD_GATEWAY, "web_fetch_error", None, None),
            ApiError::DnsNotAllowed(_) => (StatusCode::FORBIDDEN, "dns_not_allowed", None, None),
            ApiError::AttestationFailed(_) => {
                (StatusCode::FORBIDDEN, "attestation_failed", None, None)
            }
            ApiError::Escalation(_) => (StatusCode::FORBIDDEN, "escalation_denied", None, None),
            ApiError::Validation(_) => (StatusCode::BAD_REQUEST, "validation_error", None, None),
            ApiError::PermissionDenied(ref info) => (
                StatusCode::PAYMENT_REQUIRED,
                "permission_denied",
                None,
                Some(info.clone()),
            ),
            ApiError::IfcDenied(_) => (StatusCode::FORBIDDEN, "ifc_denied", None, None),
            ApiError::Declassification(_) => {
                (StatusCode::FORBIDDEN, "declassification_denied", None, None)
            }
            ApiError::DeclassificationConflict(_) => (
                StatusCode::CONFLICT,
                "declassification_conflict",
                None,
                None,
            ),
        };

        // Sanitize error message to prevent information disclosure
        let sanitized_error = validation::sanitize_error_message(&self.to_string(), None);

        let body = Json(ErrorBody {
            error: sanitized_error,
            kind: kind.to_string(),
            operation,
            payment,
        });
        (status, body).into_response()
    }
}

/// Write one line to the guest console log (`firecracker.log`), the sink
/// `nucleus verify` reads back, so workload output (e.g. an in-guest probe's
/// verdict) surfaces on the host. This process's inherited stdio does NOT reach
/// that log post-`exec`, so try, in order of reliability: `/dev/kmsg` (injects
/// into the kernel log ring, which the serial console always carries — the same
/// path the `[    0.28] ...` kernel lines take), then `/dev/console`, then
/// stderr as a last resort (host-side unit tests have no console device).
/// Opened per call — workloads here are few-line probes, and a fresh open avoids
/// sharing a handle across tokio tasks.
///
/// The whole line goes down in ONE `write(2)`: every write to `/dev/kmsg` is a
/// separate log record, and the run-4 boot showed `writeln!`'s per-fragment
/// writes splitting a single message across three records. A sentinel the host
/// greps for must arrive as one record.
fn console_line(msg: &str) {
    use std::io::Write;
    let line = format!("{msg}\n");
    for dev in ["/dev/kmsg", "/dev/console"] {
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(dev) {
            if f.write_all(line.as_bytes()).is_ok() {
                return;
            }
        }
    }
    eprint!("{line}");
}

/// Start the pod's workload (if configured) and drain its piped stdout/stderr
/// to the guest console log, line-attributed as `[workload] ...`.
///
/// Called on BOTH serve paths — vsock and TCP — and it must stay that way. In a
/// real guest the proxy serves over VSOCK and `main` RETURNS from that branch;
/// run 4 of the phase-2b boot gate found the spawn sitting below that early
/// return, on the TCP-only path, so the in-guest workload never started at all:
/// the console channels were proven live at 0.9s by the startup diagnostics,
/// verify's checks were served over vsock, and yet not even the `[workload]`
/// start line appeared — the code was simply unreachable in the guest.
///
/// Draining BOTH streams also keeps a chatty workload from blocking on a full
/// pipe nobody reads. The returned child must be held for the pod's lifetime
/// (`kill_on_drop`).
fn start_and_drain_workload(
    spec: &nucleus_spec::PodSpec,
    bound: workload::BoundProxy,
    auth_secret: &str,
) -> Result<Option<(tokio::process::Child, workload::LaunchReceipt)>, ApiError> {
    let mut started = workload::start_if_configured(spec, bound, auth_secret)?;
    match started.as_mut() {
        Some((child, _receipt)) => {
            console_line(&format!("[workload] started (pid={:?})", child.id()));
            if let Some(out) = child.stdout.take() {
                tokio::spawn(async move {
                    let mut lines = BufReader::new(out).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        console_line(&format!("[workload] {line}"));
                    }
                });
            }
            if let Some(err) = child.stderr.take() {
                tokio::spawn(async move {
                    let mut lines = BufReader::new(err).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        console_line(&format!("[workload] {line}"));
                    }
                });
            }
        }
        // Not an error: most pods run no workload. Logged so a boot that expected
        // one (the probe pod) can tell "no workload configured" — a spec/POD_SPEC
        // problem — apart from "workload ran but produced nothing".
        None => console_line("[workload] no workload configured in pod spec"),
    }
    Ok(started)
}

#[tokio::main]
async fn main() -> Result<(), ApiError> {
    // Install rustls crypto provider before any TLS connections (web_fetch, etc.).
    let _ = rustls::crypto::ring::default_provider().install_default();

    {
        use tracing_subscriber::prelude::*;

        #[cfg(feature = "otel")]
        let otel_layer = telemetry::init_otel_layer();
        #[cfg(not(feature = "otel"))]
        let otel_layer: Option<tracing_subscriber::layer::Identity> = None;

        tracing_subscriber::registry()
            .with(otel_layer)
            .with(
                tracing_subscriber::fmt::layer()
                    .json()
                    .with_filter(tracing_subscriber::EnvFilter::from_default_env()),
            )
            .init();
    }

    let args = Args::parse();

    // === Auth-secret sanity (fail-closed on a world-known key) ===
    // `auth_secret` is a required arg, but an EMPTY string satisfies "present"
    // while being a world-known HMAC key — an empty key makes sandbox tokens and
    // signed requests trivially forgeable (an attacker computes HMAC(∅, msg)).
    // Refuse to start rather than authenticate against it. Legit deployments
    // always provide a real secret, so this never affects them.
    // `.trim().is_empty()` (matching nucleus-node) also rejects a whitespace-only
    // secret, which is effectively unset.
    // MOVED, not removed — see `enforce_hmac_key_quality` below. The check needs
    // to know whether this server will be bound to a host-verified vsock
    // listener, and that is only known once the spec is loaded. Refusing an
    // empty key here would make the secretless vsock path impossible; refusing
    // it nowhere would fail open on the transports that still need HMAC.
    // The node-auth secret defaults to `auth_secret` when unset, but an explicitly
    // provided EMPTY `--node-auth-secret` would be a world-known key for node
    // requests — refuse it too (fail-closed).
    if let Some(ref node_secret) = args.node_auth_secret {
        if node_secret.trim().is_empty() {
            error!(
                "NUCLEUS_TOOL_PROXY_NODE_AUTH_SECRET is empty — refusing to start: an empty HMAC \
                 key makes node request auth forgeable (fail-closed). Unset it to inherit \
                 the main auth secret instead."
            );
            std::process::exit(1);
        }
    }

    // === Sandbox Proof Gate ===
    // Refuse to start unless we can cryptographically prove we're in a managed sandbox.
    let sandbox_proof_config = sandbox_proof::SandboxProofConfig {
        identity_cert_path: args.identity_cert.clone().or_else(|| args.tls_cert.clone()),
        spire_socket: args
            .spire_socket
            .clone()
            .or_else(|| std::env::var("SPIFFE_ENDPOINT_SOCKET").ok()),
        sandbox_token: std::env::var("NUCLEUS_SANDBOX_TOKEN").ok(),
        auth_secret: args.auth_secret.as_bytes().to_vec(),
    };
    let sandbox_proof = match sandbox_proof::verify_sandbox(&sandbox_proof_config).await {
        Ok(proof) => {
            info!(
                "sandbox proof verified: tier={} label={}",
                proof.tier(),
                proof.tier_label()
            );
            proof
        }
        Err(e) => {
            eprintln!("FATAL: {e}");
            std::process::exit(78); // EX_CONFIG
        }
    };

    let spec_contents = tokio::fs::read_to_string(&args.spec).await?;
    let spec: PodSpec =
        serde_yaml::from_str(&spec_contents).map_err(|e| ApiError::Spec(e.to_string()))?;

    let runtime = pod_mgmt::build_runtime(&spec)?;
    let approvals = Arc::new(ApprovalRegistry::default());

    // Load signed approval bundle if present
    if let Err(e) = load_approval_bundle(&spec_contents, &approvals, args.require_approval_bundle) {
        eprintln!("FATAL: {e}");
        std::process::exit(78);
    }

    let approver = CallbackApprover::new({
        let approvals = approvals.clone();
        move |request: &ApprovalRequest| approvals.consume(request.operation())
    });
    let runtime = runtime.with_approver(Arc::new(approver))?;

    let auth = AuthConfig::new(
        args.auth_secret.as_bytes(),
        Duration::from_secs(args.auth_max_skew_secs),
    );

    // Build drand config for approval signatures
    let drand_config = if args.drand_enabled {
        let fail_mode = match args.drand_fail_mode.to_lowercase().as_str() {
            "cached" => DrandFailMode::Cached,
            _ => DrandFailMode::Strict, // "degraded" is no longer supported, defaults to strict
        };
        Some(DrandConfig {
            enabled: true,
            api_url: args.drand_url.clone(),
            round_tolerance: args.drand_tolerance,
            cache_ttl: Duration::from_secs(25),
            fail_mode,
            chain_hash: None, // Verification happens on signer side
            public_key: None,
        })
    } else {
        None
    };

    let approval_auth = {
        let config = AuthConfig::new(
            args.approval_secret.as_bytes(),
            Duration::from_secs(args.auth_max_skew_secs),
        );
        if let Some(ref drand) = drand_config {
            config.with_drand(drand.clone())
        } else {
            config
        }
    };

    // Signature-based approvals: approver PUBLIC keys, drand-anchored. A
    // malformed key list is fatal HERE, not skipped — silently verifying
    // against fewer keys than configured surfaces as unexplained refusals far
    // from the cause. And a pod with NEITHER pubkeys nor a secret has an
    // approval endpoint nobody can authenticate to; that is a provisioning
    // error, and startup is where it should stop.
    let approval_verifier = match args.approval_pubkeys.as_deref() {
        Some(raw) if !raw.trim().is_empty() => {
            match auth::ApprovalVerifier::from_hex_list(
                raw,
                Duration::from_secs(args.auth_max_skew_secs),
                drand_config.clone(),
            ) {
                Ok(v) => {
                    eprintln!(
                        "approvals are signature-based: {} approver key(s), no shared secret \
                         in this guest",
                        v.key_count()
                    );
                    Some(v)
                }
                Err(e) => {
                    eprintln!("FATAL: NUCLEUS_TOOL_PROXY_APPROVAL_PUBKEYS: {e}");
                    std::process::exit(78);
                }
            }
        }
        _ => {
            if args.approval_secret.trim().is_empty() {
                eprintln!(
                    "FATAL: no approval authority is provisioned — set \
                     NUCLEUS_TOOL_PROXY_APPROVAL_PUBKEYS (signature-based) or \
                     NUCLEUS_TOOL_PROXY_APPROVAL_SECRET (legacy shared secret)"
                );
                std::process::exit(78);
            }
            None
        }
    };

    let audit = build_audit_log(&args, &auth).await?;

    // Resolve all web_fetch enforcement inputs (DNS/URL allowlists + per-pod
    // MIME and response-cap overrides) BEFORE building the client, so its
    // redirect policy can re-check every hop against the allowlists.
    let web_fetch_cfg = web_fetch_policy::resolve_web_fetch_config(
        spec.spec.network.as_ref(),
        args.web_fetch_max_bytes,
    );
    let dns_allow = web_fetch_cfg.dns_allow;
    let url_allow = web_fetch_cfg.url_allow;
    let web_fetch_mime_allow = web_fetch_cfg.mime_allow;
    let web_fetch_max_bytes = web_fetch_cfg.max_bytes;

    // Client re-checks every redirect hop against the allowlists (see
    // `web_fetch_policy::build_web_fetch_client`) — closes the SSRF/exfil hop.
    let web_client = web_fetch_policy::build_web_fetch_client(
        Duration::from_secs(args.web_fetch_timeout_secs),
        dns_allow.clone(),
        url_allow.clone(),
    )
    .map_err(|e| ApiError::Spec(format!("failed to build HTTP client: {e}")))?;

    // Build attestation verifier
    let attestation_config = {
        let mut config = if args.require_attestation {
            AttestationConfig::required()
        } else {
            AttestationConfig::default()
        };
        if let Some(ref hashes) = args.allowed_kernel_hashes {
            config = config.with_kernel_hashes(hashes);
        }
        if let Some(ref hashes) = args.allowed_rootfs_hashes {
            config = config.with_rootfs_hashes(hashes);
        }
        if let Some(ref hashes) = args.allowed_config_hashes {
            config = config.with_config_hashes(hashes);
        }
        config
    };
    let attestation_verifier = AttestationVerifier::new(attestation_config);

    // Build policy engine for identity-based authorization
    let policy_engine = if let Some(policy_path) = &args.policy_file {
        if !args.zero_prompt {
            warn!(
                "policy file specified but --zero-prompt not enabled; policy will not be enforced"
            );
        }
        let policy_config = policy::load_policy_file(policy_path).await.map_err(|e| {
            ApiError::Spec(format!(
                "failed to load policy file {}: {}",
                policy_path.display(),
                e
            ))
        })?;
        info!(
            "loaded policy file with {} rules (zero_prompt={})",
            policy_config.policies.len(),
            args.zero_prompt
        );
        if args.zero_prompt {
            PolicyEngine::from_config(&policy_config)
        } else {
            PolicyEngine::disabled()
        }
    } else {
        if args.zero_prompt {
            return Err(ApiError::Spec(
                "--zero-prompt requires --policy-file".to_string(),
            ));
        }
        PolicyEngine::disabled()
    };

    if args.zero_prompt && !args.mtls {
        return Err(ApiError::Spec(
            "--zero-prompt requires --mtls for identity-based authorization".to_string(),
        ));
    }

    if args.require_attestation
        && args.allowed_kernel_hashes.is_none()
        && args.allowed_rootfs_hashes.is_none()
    {
        warn!(
            "attestation required but no kernel/rootfs hash whitelist configured; \
             any attested VM will be accepted"
        );
    }

    // Build node client for pod management (orchestrator mode)
    let node_client = if args.enable_pod_mgmt {
        let node_url = args.node_url.as_deref().unwrap_or("http://127.0.0.1:3000");
        let node_secret = args
            .node_auth_secret
            .clone()
            .unwrap_or_else(|| args.auth_secret.clone());
        info!("pod management enabled (node_url={})", node_url);
        Some(Arc::new(node_client::NodeClient::new(
            node_url.to_string(),
            node_secret,
        )))
    } else {
        None
    };

    // Parse delegation ceiling for orchestrator mode
    let delegation_ceiling = if let Some(ref ceiling_json) = args.delegation_ceiling {
        let lattice: PermissionLattice = serde_json::from_str(ceiling_json)
            .map_err(|e| ApiError::Spec(format!("invalid delegation ceiling JSON: {e}")))?;
        Some(Arc::new(lattice))
    } else {
        None
    };

    // Load orchestrator credentials from environment for sub-pod injection
    let orchestrator_credentials = {
        let mut creds = std::collections::BTreeMap::new();
        for key in ["LLM_API_TOKEN", "GITHUB_TOKEN"] {
            if let Ok(val) = std::env::var(key) {
                creds.insert(key.to_string(), val);
            }
        }
        creds
    };

    let policy_checksum = runtime.policy().checksum();
    let session_id = runtime.policy().id.to_string();

    // Pre-create shared state for lockdown + exposure so VerdictSink can share them.
    let file_lockdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stream_lockdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let exposure_guard: Arc<std::sync::RwLock<Option<Arc<portcullis::GradedExposureGuard>>>> =
        Arc::new(std::sync::RwLock::new(None));

    // DLC-D verified admission: provisioned from NUCLEUS_DLC_* env (inert when
    // unset). The SAME provisioning is applied to both transports' kernels, and
    // the sink stamps every allowed verdict's span with the admission state.
    // Article 12 record-keeping (opt-in). Opened BEFORE the sink chain, because
    // the chain takes it by value and there must be no window in which decisions
    // are made against a chain that is missing it.
    let art12_log = match args.art12_log.as_ref() {
        Some(path) => Some(
            art12_sink::open_log(
                path,
                args.audit_secret.as_deref(),
                &spec.spec.work_dir,
                &session_id,
            )
            .map_err(ApiError::Spec)?,
        ),
        None => None,
    };
    if let Some(path) = args.art12_log.as_ref() {
        info!(path = %path.display(), "Article 12 record-keeping log opened");
    }

    // The Article 12 evidence channel. Absent means records live only in the
    // pod, so the host can attest only a head the pod REPORTED.
    let art12_shipper = art12_shipper::Art12Shipper::from_args(
        args.art12_ship_url.as_ref(),
        args.audit_secret.as_deref(),
        &session_id,
    );

    // Both fail-closed: a credential the workload can read, or an upstream it can
    // reach directly, each turn credentialed egress into a comment.
    workload::reject_credential_readable_workload(
        spec.spec.workload.as_ref(),
        &spec.spec.credentialed_egress,
    )
    .map_err(ApiError::Spec)?;
    // See `egress::reject_bypassable_upstreams` for why this is fail-closed.
    egress::reject_bypassable_upstreams(&spec.spec.credentialed_egress, &dns_allow)
        .map_err(ApiError::Spec)?;

    // Credentialed egress goes through the host broker and nowhere else, so a
    // pod configured for it without a capability can never succeed. Refuse here
    // rather than at the first request, where it would look like a transient
    // upstream error minutes into a run.
    egress::reject_egress_without_a_broker(
        &spec.spec.credentialed_egress,
        std::env::var("NUCLEUS_TOOL_PROXY_BROKER_SECRET").is_ok_and(|v| !v.is_empty()),
    )
    .map_err(ApiError::Spec)?;

    let dlc_admission = dlc_admission::provision_from_env();
    let dlc_provisioned = dlc_admission.is_some();

    // Runtime verification over the decision stream (#2141). The sink comes back
    // already monitored — `build_monitored_sink` is the only constructor
    // reachable from here — so there is no unmonitored chain to fall back to.
    let (verdict_sink, trace_monitor) = verdict_sink::build_monitored_sink(
        file_lockdown.clone(),
        stream_lockdown.clone(),
        runtime.policy().capabilities.clone(),
        exposure_guard.clone(),
        policy_checksum.clone(),
        session_id.clone(),
        dlc_provisioned,
        art12_log.clone(),
        art12_shipper.clone(),
    );

    if dlc_provisioned {
        tracing::info!("DLC-D verified admission provisioned from NUCLEUS_DLC_* env");
    }
    let kernel = Arc::new(tokio::sync::Mutex::new({
        let mut k = Kernel::new(runtime.policy().clone());
        if let Some(admission) = dlc_admission {
            k.set_dlc_admission(admission);
        }
        // Provision the governor's declassification-token keys. This is the ONE
        // place the trusted-key set is written, and it comes from the
        // node-controlled env — never from a request handler — which is what
        // keeps declassification robust (the workload cannot enroll its own
        // key). Absent/empty ⇒ every token is refused fail-closed.
        let governor_keys = declassify::governor_keys_from_env(
            std::env::var("NUCLEUS_DECLASSIFY_TRUSTED_KEYS")
                .ok()
                .as_deref(),
        );
        if !governor_keys.is_empty() {
            tracing::info!(
                count = governor_keys.len(),
                "declassification governor keys provisioned from NUCLEUS_DECLASSIFY_TRUSTED_KEYS"
            );
            k.set_trusted_keys(governor_keys);
        }
        k
    }));

    // The single authoritative information-flow graph the egress verdict reads.
    let flow_graph = Arc::new(tokio::sync::Mutex::new(FlowGraph::new()));

    // Provenance-memory state (next-bet #1). Trusted declassify keys + threshold
    // come from env; absent ⇒ empty/1 ⇒ declassification is fail-closed.
    let provenance_memory = Arc::new(tokio::sync::Mutex::new(
        nucleus_provenance_memory::ProvenanceMemorySet::new(),
    ));
    let memory_transforms = Arc::new(nucleus_provenance_memory::TransformRegistry::new());
    let declassify_trusted_keys = Arc::new(memory::parse_trusted_keys_env(
        std::env::var("NUCLEUS_DECLASSIFY_TRUSTED_KEYS")
            .ok()
            .as_deref(),
    ));
    let declassify_threshold = std::env::var("NUCLEUS_DECLASSIFY_THRESHOLD")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(1);

    // Live-path session task token (PR-2, present-not-consumed). Read the
    // host-injected token/nonce/issuer off the boot channel and verify ONCE.
    // Fail-closed: an unreadable clock, an absent token, or a verification
    // failure all yield a non-`Verified` state so the later RunBash-gating PR
    // denies. `now` is derived from the wall clock here (production) but passed
    // explicitly into the pure resolver (tests supply a fixed `now`).
    let session_task_token = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => session_token::resolve_session_task_token(
            args.task_token.as_deref(),
            args.task_token_nonce.as_deref(),
            args.task_token_issuer.as_deref(),
            elapsed.as_secs(),
        ),
        // Clock before the epoch ⇒ cannot evaluate freshness ⇒ fail closed.
        Err(_) => session_token::SessionTaskToken::Invalid,
    };
    info!(
        "live-path session task token: {}",
        session_task_token.state_label()
    );

    // Resolved BEFORE the state is built: `host_verified_transport` must
    // describe how this server will actually be bound, not be patched in later.
    // A request can never influence it.
    let vsock_binding = pod_mgmt::resolve_vsock(&args, &spec)?;

    // === Auth-secret sanity, transport-aware (fail-closed where it matters) ===
    enforce_hmac_key_quality(&args.auth_secret, vsock_binding.is_some());

    let receipts = Arc::new(portcullis_effects::receipt::ReceiptLog::new());
    let state = AppState {
        receipts: Arc::clone(&receipts),
        path_provenance: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        dlc_provisioned,
        runtime: Arc::new(runtime),
        approvals,
        audit,
        auth,
        approval_auth,
        approval_verifier,
        host_verified_transport: vsock_binding.is_some(),
        approval_nonces: Arc::new(ApprovalNonceCache::default()),
        approval_rate_limiter: Arc::new(ApprovalRateLimiter::default()),
        web_client,
        web_fetch_max_bytes,
        web_fetch_mime_allow,
        dns_allow,
        url_allow,
        attestation_verifier,
        policy_engine,
        node_client,
        delegation_ceiling,
        orchestrator_credentials,
        permission_market: Arc::new(Mutex::new(PermissionMarket::new())),
        sandbox_proof,
        cert_root_pubkey: args
            .cert_root_pubkey
            .as_deref()
            .and_then(|hex_str| hex::decode(hex_str).ok())
            .map(Arc::new),
        exposure_guard,
        file_lockdown,
        stream_lockdown,
        policy_checksum,
        session_id,
        credentialed_egress: spec.spec.credentialed_egress.clone(),
        verdict_sink,
        art12_log,
        trace_monitor,
        kernel,
        flow_graph,
        provenance_memory,
        memory_transforms,
        declassify_trusted_keys,
        declassify_threshold,
        session_task_token,
    };

    if let Err(err) = emit_boot_report(&state).await {
        warn!("failed to emit boot report: {err}");
    }

    // Lockdown signal watcher: polls the signal file every 500ms.
    // Verifies HMAC before acting — prevents privilege escalation via
    // world-writable signal file (red team finding).
    {
        let lockdown_flag = state.file_lockdown.clone();
        tokio::spawn(async move {
            // Same path logic as the CLI
            let signal_path = dirs::runtime_dir()
                .or_else(dirs::data_local_dir)
                .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
                .join("nucleus")
                .join("lockdown.json");

            // Fail-closed lockdown: on ANY verification failure (bad HMAC, parse
            // error, read error), preserve the current lockdown state rather than
            // defaulting to unlocked. Only a verified signal can change the state.
            loop {
                let current = lockdown_flag.load(std::sync::atomic::Ordering::Acquire);
                let should_lock = if signal_path.exists() {
                    match tokio::fs::read_to_string(&signal_path).await {
                        Ok(content) => parse_and_verify_lockdown_signal(&content, current),
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "Failed to read lockdown signal file — preserving current state"
                            );
                            current // fail-closed: preserve current state
                        }
                    }
                } else {
                    false // no file = no lockdown (file must exist to lock)
                };

                if should_lock != current {
                    lockdown_flag.store(should_lock, std::sync::atomic::Ordering::Release);
                    if should_lock {
                        tracing::warn!(
                            "LOCKDOWN ACTIVATED via verified signal file \
                             — meet(current, read_only) applied, forensic reads still allowed"
                        );
                    } else {
                        tracing::info!("Lockdown lifted via verified signal file");
                    }
                }

                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        });
    }

    // Streaming lockdown watcher: connects to nucleus-node gRPC and receives
    // LockdownCommand messages with sub-second latency.
    if let Some(ref grpc_url) = args.node_grpc_url {
        let stream_flag = state.stream_lockdown.clone();
        let auth_secret = args
            .node_auth_secret
            .clone()
            .unwrap_or_else(|| args.auth_secret.clone());
        let config = lockdown_client::LockdownWatcherConfig {
            node_grpc_url: grpc_url.clone(),
            auth_secret,
            proxy_id: format!(
                "{}:{}",
                whoami::hostname().unwrap_or_else(|_| "unknown".into()),
                std::process::id()
            ),
            pod_id: std::env::var("NUCLEUS_POD_ID").ok(),
        };
        tokio::spawn(async move {
            lockdown_client::run_lockdown_watcher(config, stream_flag).await;
        });
    }

    // MCP server mode: serve Model Context Protocol over stdio instead of HTTP.
    #[cfg(feature = "mcp")]
    if args.mcp {
        return mcp::run_mcp_server(Arc::new(state)).await;
    }

    let mut app = Router::new()
        .route(
            "/v1/egress/{name}/{*path}",
            post(egress::credentialed_egress),
        )
        .route("/v1/health", get(health))
        .route("/v1/read", post(read_file))
        .route("/v1/write", post(write_file))
        .route("/v1/run", post(run_command))
        .route("/v1/web_fetch", post(web_fetch))
        .route("/v1/glob", post(glob_search))
        .route("/v1/grep", post(grep_search))
        .route("/v1/web_search", post(web_search))
        .route("/v1/memory/write", post(memory_write))
        .route("/v1/memory/recall", post(memory_recall))
        .route("/v1/approve", post(approve_operation))
        .route("/v1/escalate", post(escalate::escalate_permissions))
        // Governor declassification: signature-gated, one-shot, sink-scoped.
        // Safe on the workload-facing surface because the Ed25519 signature —
        // not the transport — is the authority (see declassify.rs).
        .route("/v1/declassify", post(declassify::apply_declassification));

    // Conditionally add pod management routes for orchestrator mode
    if state.node_client.is_some() {
        app = app
            .route("/v1/pod/create", post(pod_mgmt::create_sub_pod))
            .route("/v1/pod/list", post(pod_mgmt::list_sub_pods))
            .route("/v1/pod/status", post(pod_mgmt::get_pod_status))
            .route("/v1/pod/logs", post(pod_mgmt::get_pod_logs))
            .route("/v1/pod/cancel", post(pod_mgmt::cancel_sub_pod));
    }

    // Keep references for the exit report after shutdown
    let exit_audit = state.audit.clone();
    let exit_work_dir = spec.spec.work_dir.clone();
    let exit_exposure = state.exposure_guard.clone();
    let exit_monitor = state.trace_monitor.clone();
    let exit_art12 = state.art12_log.clone();

    let app = app
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state, auth_middleware))
        // OUTERMOST layer (last `.layer()` wins — it receives the request first,
        // wrapping every inner layer and handler). A stray panic anywhere inside
        // — e.g. a poisoned enforcement lock's `.expect()` — is caught here and
        // converted to a fail-closed HTTP 500 DENY, never a reset/allow, so the
        // proxy can neither crash nor fail-open. See `fail_closed_panic_response`.
        .layer(tower_http::catch_panic::CatchPanicLayer::custom(
            fail_closed_panic_response,
        ));

    if let Some(vsock) = vsock_binding {
        // THE GUEST PATH. In a booted microVM the proxy serves over vsock and
        // `main` returns right here — everything below this block is host/TCP
        // only. The workload therefore starts on this path (between bind and
        // serve, so its proxy URL names a socket that exists); before run 4's
        // diagnosis it started only below, and an in-guest pod's workload never
        // ran at all.
        let bound = pod_mgmt::bind_vsock(vsock, args.announce_path).await?;
        let _workload = start_and_drain_workload(
            &spec,
            workload::BoundProxy::Vsock {
                cid: bound.cid(),
                port: bound.port(),
            },
            &args.auth_secret,
        )?;
        pod_mgmt::serve_vsock(app, bound).await?;
        write_exit_report(
            &exit_audit,
            &exit_work_dir,
            &exit_exposure,
            &exit_monitor,
            exit_art12.as_ref(),
        )
        .await;
        return Ok(());
    }

    let listener = TcpListener::bind(&args.listen).await?;
    let addr = listener.local_addr()?;

    if let Some(path) = args.announce_path.as_ref() {
        tokio::fs::write(path, addr.to_string()).await?;
    }

    // Started here and not earlier; `workload::start_if_configured` explains why.
    // `start_and_drain_workload` explains why the same call also sits on the
    // vsock branch above — this line alone is unreachable in a real guest.
    let _workload =
        start_and_drain_workload(&spec, workload::BoundProxy::Tcp(addr), &args.auth_secret)?;

    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        info!("shutdown signal received, writing exit report");
    };

    // Check if mTLS is enabled
    if args.mtls {
        let mtls_config = build_mtls_config(&args).await?;
        let mtls_listener = MtlsListener::new(listener, &mtls_config)
            .map_err(|e| ApiError::Spec(format!("failed to create mTLS listener: {}", e)))?;

        info!(
            "nucleus-tool-proxy listening on {} (mTLS enabled, trust_domain={})",
            addr,
            args.trust_domain.as_deref().unwrap_or("not set")
        );

        // Use into_make_service_with_connect_info to inject MtlsConnectInfo
        axum::serve(
            mtls_listener,
            app.into_make_service_with_connect_info::<MtlsConnectInfo>(),
        )
        .with_graceful_shutdown(shutdown)
        .await?;
    } else {
        info!("nucleus-tool-proxy listening on {}", addr);
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown)
            .await?;
    }

    // Flush batched OTLP spans before exit — the batch exporter would otherwise
    // drop everything still pending at teardown. See `telemetry::shutdown_otel`.
    #[cfg(feature = "otel")]
    telemetry::shutdown_otel();

    write_exit_report(
        &exit_audit,
        &exit_work_dir,
        &exit_exposure,
        &exit_monitor,
        exit_art12.as_ref(),
    )
    .await;

    Ok(())
}

/// Fail-closed panic handler for [`tower_http::catch_panic::CatchPanicLayer`].
///
/// Any panic that unwinds through the router — a poisoned enforcement lock's
/// `.expect()`, an `unwrap()` on unexpected input, an arithmetic overflow — is
/// converted into an HTTP 500 DENY. It NEVER resets the connection and NEVER
/// returns success/allow: the request is refused, fail-closed. This is the
/// process-level backstop that keeps a stray panic from either crashing the
/// proxy or letting a request through unchecked.
fn fail_closed_panic_response(err: Box<dyn std::any::Any + Send + 'static>) -> Response {
    let detail = if let Some(s) = err.downcast_ref::<String>() {
        s.as_str()
    } else if let Some(s) = err.downcast_ref::<&str>() {
        s
    } else {
        "unknown panic"
    };
    warn!(
        panic = %detail,
        "request handler panicked; failing CLOSED with HTTP 500 DENY"
    );
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "denied: internal enforcement error (fail-closed)",
    )
        .into_response()
}

/// Write the exit report on shutdown (including verified exposure data).
async fn write_exit_report(
    audit: &AuditLog,
    work_dir_path: &Path,
    exposure_guard: &std::sync::RwLock<Option<Arc<portcullis::GradedExposureGuard>>>,
    monitor: &portcullis::trace_monitor::TraceMonitor,
    art12_log: Option<&Arc<crate::art12::Art12Log>>,
) {
    let workspace_hash = match exit_report::hash_workspace(work_dir_path).await {
        Ok(h) => h,
        Err(e) => {
            warn!("failed to hash workspace for exit report: {e}");
            return;
        }
    };

    let (tail_hash, count) = audit.tail_hash_and_count();
    let mut report =
        exit_report::build_exit_report(workspace_hash, tail_hash, count, None, monitor);
    if !report.monitor_violations.is_empty() || report.monitor_violations_dropped > 0 {
        warn!(
            violations = ?report.monitor_violations,
            dropped = report.monitor_violations_dropped,
            "exit report: decision-stream properties were violated during this session"
        );
    }

    exit_report::apply_exposure(&mut report, exposure_guard);
    exit_report::apply_art12(&mut report, art12_log);

    let report_path = work_dir_path.join(".nucleus-exit-report.json");
    match serde_json::to_string_pretty(&report) {
        Ok(json) => {
            if let Err(e) = tokio::fs::write(&report_path, json).await {
                warn!(
                    "failed to write exit report to {}: {e}",
                    report_path.display()
                );
            } else {
                info!(
                    path = %report_path.display(),
                    entries = count,
                    event = "exit_report_written",
                    "exit report written"
                );
            }
        }
        Err(e) => warn!("failed to serialize exit report: {e}"),
    }
}

/// Builds mTLS configuration from CLI arguments.
async fn build_mtls_config(args: &Args) -> Result<MtlsConfig, ApiError> {
    use nucleus_identity::{TrustBundle, WorkloadCertificate};

    let cert_path = args
        .tls_cert
        .as_ref()
        .ok_or_else(|| ApiError::Spec("--tls-cert required when --mtls is enabled".to_string()))?;

    let key_path = args
        .tls_key
        .as_ref()
        .ok_or_else(|| ApiError::Spec("--tls-key required when --mtls is enabled".to_string()))?;

    let bundle_path = args.trust_bundle.as_ref().ok_or_else(|| {
        ApiError::Spec("--trust-bundle required when --mtls is enabled".to_string())
    })?;

    // Read certificate and key
    let cert_pem = tokio::fs::read_to_string(cert_path)
        .await
        .map_err(|e| ApiError::Spec(format!("failed to read TLS cert: {}", e)))?;

    let key_pem = tokio::fs::read_to_string(key_path)
        .await
        .map_err(|e| ApiError::Spec(format!("failed to read TLS key: {}", e)))?;

    let bundle_pem = tokio::fs::read_to_string(bundle_path)
        .await
        .map_err(|e| ApiError::Spec(format!("failed to read trust bundle: {}", e)))?;

    // Parse certificate and trust bundle
    let server_cert = WorkloadCertificate::from_pem(&cert_pem, &key_pem)
        .map_err(|e| ApiError::Spec(format!("failed to parse server certificate: {}", e)))?;

    let trust_bundle = TrustBundle::from_pem(&bundle_pem)
        .map_err(|e| ApiError::Spec(format!("failed to parse trust bundle: {}", e)))?;

    Ok(MtlsConfig::new(server_cert, trust_bundle))
}

const MAX_AUTH_BODY_BYTES: usize = 10 * 1024 * 1024;
const APPROVE_PATH: &str = "/v1/approve";
const HEALTH_PATH: &str = "/v1/health";

/// Check whether a request path maps to a read-only operation that is allowed
/// during lockdown.  This implements `meet(current, read_only)` semantics:
/// operations that would be permitted under `PermissionLattice::read_only()`
/// (i.e., `read_files`, `glob_search`, `grep_search` all at `Always`) pass
/// through, while every mutating operation is blocked.
fn is_allowed_during_lockdown(path: &str) -> bool {
    matches!(path, "/v1/read" | "/v1/glob" | "/v1/grep" | "/v1/health")
}

const HEADER_ATTESTATION: &str = "x-nucleus-attestation";
const HEADER_PERMISSION_BID: &str = "x-nucleus-permission-bid";
const HEADER_DELEGATION_CERT: &str = "x-nucleus-delegation-cert";

async fn auth_middleware(
    State(state): State<AppState>,
    request: axum::http::Request<Body>,
    next: middleware::Next,
) -> Result<Response, ApiError> {
    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, MAX_AUTH_BODY_BYTES)
        .await
        .map_err(|e| ApiError::Body(e.to_string()))?;

    // Skip attestation check for health endpoint
    if parts.uri.path() == HEALTH_PATH {
        let req = axum::http::Request::from_parts(parts, Body::from(bytes));
        return Ok(next.run(req).await);
    }

    // Emergency lockdown check — apply meet(current, read_only) semantics.
    // OR-semantics: locked if EITHER signal file OR gRPC stream says locked.
    // Read-only operations (read, glob, grep) continue working during lockdown
    // to enable forensic investigation. All mutating operations are blocked.
    if is_locked(&state) && !is_allowed_during_lockdown(parts.uri.path()) {
        return Err(ApiError::Body(
            "LOCKDOWN ACTIVE: mutating operations are blocked (read/glob/grep still allowed). \
             Use `nucleus lockdown --restore` to lift the lockdown."
                .to_string(),
        ));
    }

    // Verify attestation if required
    if state.attestation_verifier.is_required() {
        // Try to get client certificate from mTLS connection first
        // Check both direct ClientCertInfo and MtlsConnectInfo
        let client_cert_der = parts
            .extensions
            .get::<MtlsConnectInfo>()
            .and_then(|info| info.client_cert.as_ref())
            .or_else(|| parts.extensions.get::<ClientCertInfo>())
            .map(|cert| cert.der());

        let attestation_result = if let Some(cert_der) = client_cert_der {
            // mTLS mode: extract attestation from client certificate
            let spiffe_id = parts
                .extensions
                .get::<MtlsConnectInfo>()
                .and_then(|info| info.client_cert.as_ref())
                .and_then(|cert| cert.spiffe_id.clone());
            tracing::info!(
                spiffe_id = ?spiffe_id,
                path = %parts.uri.path(),
                method = %parts.method,
                event = "attestation_verify_mtls",
                "verifying attestation from client certificate"
            );
            state.attestation_verifier.verify_certificate(cert_der)
        } else if let Some(att_header) = parts.headers.get(HEADER_ATTESTATION) {
            // Fallback: attestation passed via header (base64-encoded DER)
            // This is less secure as headers can be spoofed
            tracing::warn!(
                path = %parts.uri.path(),
                method = %parts.method,
                event = "attestation_verify_header",
                "attestation via header (not mTLS) - consider enabling mTLS for production"
            );
            let att_value = att_header.to_str().map_err(|_| {
                ApiError::AttestationFailed("invalid attestation header encoding".to_string())
            })?;
            state.attestation_verifier.verify_header(att_value)
        } else {
            // No attestation provided
            attestation::AttestationResult {
                attestation_present: false,
                attestation: None,
                matches_requirements: false,
                rejection_reason: Some("attestation required but not provided (enable mTLS or send x-nucleus-attestation header)".to_string()),
            }
        };

        if !attestation_result.matches_requirements {
            let reason = attestation_result
                .rejection_reason
                .unwrap_or_else(|| "unknown attestation failure".to_string());
            return Err(ApiError::AttestationFailed(reason));
        }

        // Log successful attestation verification
        if let Some(ref info) = attestation_result.attestation {
            tracing::debug!(
                kernel_hash = %&info.kernel_hash[..16],
                rootfs_hash = %&info.rootfs_hash[..16],
                "attestation verified"
            );
        }
    }

    // Determine authentication context (unified flow — no early returns).
    // SPIFFE mTLS is most secure, then HMAC+drand for approvals, then HMAC.
    // Precedence is decided by `auth::select_auth_tier`, which is unit-tested;
    // this match only performs the chosen tier. Keeping the order in one
    // testable place is deliberate — an invisible reordering here would make
    // the transport tier dead and silently reinstate the readable-key HMAC.
    debug_assert_eq!(
        auth::select_auth_tier(
            auth::extract_spiffe_id_from_extensions(&parts.extensions).is_some(),
            parts.uri.path() == APPROVE_PATH,
            state.approval_verifier.is_some(),
            state.host_verified_transport,
        ),
        if auth::extract_spiffe_id_from_extensions(&parts.extensions).is_some() {
            auth::AuthTier::SpiffeMtls
        } else if parts.uri.path() == APPROVE_PATH && state.approval_verifier.is_some() {
            auth::AuthTier::ApprovalEd25519Drand
        } else if parts.uri.path() == APPROVE_PATH {
            auth::AuthTier::ApprovalHmacDrand
        } else if state.host_verified_transport {
            auth::AuthTier::HostVsock
        } else {
            auth::AuthTier::Hmac
        },
        "the inline chain has diverged from select_auth_tier"
    );
    let mut context =
        if let Some(spiffe_id) = auth::extract_spiffe_id_from_extensions(&parts.extensions) {
            tracing::info!(
                spiffe_id = %spiffe_id,
                path = %parts.uri.path(),
                method = %parts.method,
                event = "auth_spiffe_mtls",
                "request authenticated via SPIFFE mTLS"
            );
            auth::verify_spiffe_mtls(&spiffe_id)
        } else if parts.uri.path() == APPROVE_PATH {
            // Signature tier FIRST, and exclusively: when approver public keys
            // are configured, the shared-secret HMAC must not remain an
            // alternative way in — any residual copy of the old secret would
            // still forge approvals and the keys would have removed nothing.
            let ctx = if let Some(ref verifier) = state.approval_verifier {
                auth::verify_http_with_ed25519_drand(&parts.headers, &bytes, verifier)?
            } else {
                auth::verify_http_with_drand(&parts.headers, &bytes, &state.approval_auth)?
            };
            if ctx.drand_round.is_some() {
                tracing::info!(
                    drand_round = ctx.drand_round,
                    auth_method = ?ctx.auth_method,
                    "approval request verified with drand anchoring"
                );
            }
            ctx
        } else if state.host_verified_transport {
            // The listener already dropped every non-host peer, so this request
            // provably came from the host. No shared secret is involved, which
            // is the point: the HMAC key it replaces was readable by the agent
            // from /proc/cmdline.
            auth::verify_host_vsock()
        } else {
            auth::verify_http(&parts.headers, &bytes, &state.auth)?
        };

    // Extract client cert DER for Layer 3 (fused identity fingerprint extraction).
    let client_cert_der: Option<Vec<u8>> = parts
        .extensions
        .get::<MtlsConnectInfo>()
        .and_then(|info| info.client_cert.as_ref())
        .map(|cert| cert.cert_der.clone())
        .or_else(|| {
            parts
                .extensions
                .get::<ClientCertInfo>()
                .map(|cert| cert.cert_der.clone())
        });

    // Evaluate delegation certificate for ALL auth methods (not just HMAC).
    // This fixes the security gap where mTLS requests couldn't use delegation certs.
    // Identity binding: when mTLS is active, leaf_identity must match SPIFFE ID.
    let (permission_grant, certified_perms) = if let Some((grant, certified, fused)) =
        evaluate_delegation_cert_with_identity(
            &parts.headers,
            &state,
            context.spiffe_id.as_deref(),
            client_cert_der.as_deref(),
        ) {
        if let Some(ref fi) = fused {
            if fi.fingerprint_verified {
                context.identity_binding = auth::IdentityBinding::Fused {
                    permission_fingerprint: fi.permission_fingerprint,
                };
            } else {
                context.identity_binding = auth::IdentityBinding::DelegationVerified {
                    leaf_identity: certified.verified.leaf_identity.clone(),
                };
            }
        } else {
            context.identity_binding = auth::IdentityBinding::DelegationVerified {
                leaf_identity: certified.verified.leaf_identity.clone(),
            };
        }
        (Some(grant), Some(certified))
    } else {
        (evaluate_permission_bid(&parts.headers, &state), None)
    };

    // If the bid was fully denied (no dimensions granted), return 402 with pricing
    if let Some(ref grant) = permission_grant {
        if !grant.denied.is_empty() && grant.granted.is_empty() {
            let total_price: f64 = grant.denied.iter().map(|d| d.price).sum();
            let denied_dims = grant
                .denied
                .iter()
                .map(|d| nucleus_spec::DeniedDimensionInfo {
                    dimension: d.dimension.label().to_string(),
                    price_usd: d.price,
                })
                .collect();
            let reason = grant
                .denied
                .iter()
                .map(|d| format!("{} λ={:.2}", d.dimension.label(), d.price))
                .collect::<Vec<_>>()
                .join(", ");
            let payment_info = nucleus_spec::PaymentRequiredInfo {
                amount_usd: total_price,
                reason,
                kind: nucleus_spec::PaymentRequiredKind::PermissionDenied {
                    denied_dimensions: denied_dims,
                },
                recipient: std::env::var("NUCLEUS_PAYMENT_RECIPIENT").ok(),
                resource: Some(parts.uri.path().to_string()),
            };
            return Err(ApiError::PermissionDenied(payment_info));
        }
    }

    let mut req = axum::http::Request::from_parts(parts, Body::from(bytes));
    req.extensions_mut().insert(context);
    if let Some(grant) = permission_grant {
        req.extensions_mut().insert(grant);
    }
    if let Some(certified) = certified_perms {
        req.extensions_mut().insert(certified);
    }
    Ok(next.run(req).await)
}

/// Parse and evaluate a permission bid from request headers.
///
/// Returns `Some(PermissionGrant)` if a valid bid was present, `None` otherwise.
/// Invalid bid JSON is silently ignored (logged at warn level).
fn evaluate_permission_bid(headers: &HeaderMap, state: &AppState) -> Option<PermissionGrant> {
    let bid_header = headers.get(HEADER_PERMISSION_BID)?;
    let bid_str = bid_header.to_str().ok()?;
    let bid: PermissionBid = match serde_json::from_str(bid_str) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "invalid permission bid header");
            return None;
        }
    };

    let market = state.permission_market.lock().unwrap();
    let grant = market.evaluate_bid(&bid);

    tracing::info!(
        skill_id = %bid.skill_id,
        granted = grant.granted.len(),
        denied = grant.denied.len(),
        total_cost = grant.total_cost,
        event = "permission_bid_evaluated",
        "permission market evaluated bid"
    );

    Some(grant)
}

/// Verified delegation certificate permissions, inserted into request extensions.
/// Downstream handlers read these to enforce the intersection of
/// certificate attestation and market pricing.
#[derive(Clone)]
#[allow(dead_code)] // Fields consumed by downstream handlers
pub(crate) struct CertifiedPermissions {
    pub(crate) verified: portcullis::certificate::VerifiedPermissions,
    pub(crate) effective: PermissionLattice,
}

/// Parse, verify, and evaluate a delegation certificate from request headers,
/// enforcing identity binding when an authenticated SPIFFE ID is present.
///
/// Flow:
/// 1. Decode base64 certificate from `x-nucleus-delegation-cert`
/// 2. Verify Ed25519 chain against root public key
/// 3. **Identity binding**: if `authenticated_spiffe_id` is Some, reject if
///    `verified.leaf_identity != spiffe_id` (prevents privilege escalation)
/// 4. Convert `VerifiedPermissions` → `PermissionBid` via α
/// 5. Evaluate bid against market → `PermissionGrant`
/// 6. Intersect grant with certificate → effective `PermissionLattice`
fn evaluate_delegation_cert_with_identity(
    headers: &HeaderMap,
    state: &AppState,
    authenticated_spiffe_id: Option<&str>,
    client_cert_der: Option<&[u8]>,
) -> Option<(
    PermissionGrant,
    CertifiedPermissions,
    Option<identity_fusion::FusedIdentity>,
)> {
    let cert_header = headers.get(HEADER_DELEGATION_CERT)?;
    let cert_b64 = cert_header.to_str().ok()?;

    let root_pubkey = state.cert_root_pubkey.as_ref()?;

    let cert_bytes = match base64::engine::general_purpose::STANDARD.decode(cert_b64) {
        Ok(b) => b,
        Err(e) => {
            warn!(error = %e, "invalid delegation cert base64");
            return None;
        }
    };

    let cert: portcullis::LatticeCertificate = match serde_json::from_slice(&cert_bytes) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "invalid delegation cert JSON");
            return None;
        }
    };

    let verified = match portcullis::verify_certificate(
        &cert,
        root_pubkey,
        chrono::Utc::now(),
        portcullis::certificate::DEFAULT_MAX_CHAIN_DEPTH,
    ) {
        Ok(v) => v,
        Err(e) => {
            warn!(error = %e, "delegation cert verification failed");
            return None;
        }
    };

    // CRITICAL SECURITY CHECK (Layer 1): If we have an authenticated identity (mTLS),
    // verify that the delegation certificate's leaf identity matches.
    // This prevents privilege escalation where agent-A presents agent-B's cert.
    if let Some(spiffe_id) = authenticated_spiffe_id {
        if verified.leaf_identity != spiffe_id {
            tracing::warn!(
                authenticated_id = %spiffe_id,
                cert_leaf_id = %verified.leaf_identity,
                event = "identity_mismatch_rejected",
                "delegation cert leaf_identity does not match authenticated SPIFFE ID"
            );
            return None;
        }
    }

    // Layer 3: Extract fused identity from X.509 permission fingerprint extension.
    let mut fused = client_cert_der.and_then(|der| {
        authenticated_spiffe_id.and_then(|sid| identity_fusion::extract_fused_identity(der, sid))
    });

    let bid = cert_bridge::certificate_to_bid(&verified);

    let market = state.permission_market.lock().unwrap();
    let mut grant = market.evaluate_bid(&bid);

    // Layer 3: If fused identity present, verify fingerprint and elevate trust.
    if let Some(ref mut fi) = fused {
        if identity_fusion::verify_delegation_against_fingerprint(fi, &cert, &verified) {
            grant = identity_fusion::elevate_grant_trust(&grant);
        }
    }

    let effective = cert_bridge::intersect_grant_with_certificate(&grant, &verified);

    tracing::info!(
        leaf_identity = %verified.leaf_identity,
        chain_depth = verified.chain_depth,
        trust_tier = ?bid.trust_tier,
        granted = grant.granted.len(),
        denied = grant.denied.len(),
        total_cost = grant.total_cost,
        identity_verified = authenticated_spiffe_id.is_some(),
        fused_verified = fused.as_ref().is_some_and(|f| f.fingerprint_verified),
        event = "delegation_cert_evaluated",
        "delegation certificate verified and evaluated against market"
    );

    Some((
        grant,
        CertifiedPermissions {
            verified,
            effective,
        },
        fused,
    ))
}

async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "sandbox_proof": {
            "tier": state.sandbox_proof.tier(),
            "label": state.sandbox_proof.tier_label(),
        },
        "dlc_admission": if state.dlc_provisioned { "provisioned" } else { "unprovisioned" },
        // Counts only, never labels or detail. Same reasoning as the DLC field
        // above — a host needs to distinguish "the monitor saw nothing" from
        // "the monitor was never armed" — but this endpoint is reachable from
        // inside the sandbox, so it must not become a channel for reading back
        // which invariant a probe just tripped.
        "trace_monitor": {
            "violations": state.trace_monitor.violations().len(),
            "violations_dropped": state.trace_monitor.violations_dropped(),
        },
        "art12": art12_sink::health_json(state.art12_log.as_ref())
    }))
}

/// Check if a SPIFFE identity has permission for an operation via policy.
/// Returns true if the operation should be auto-approved (zero-prompt).
fn check_identity_policy(
    state: &AppState,
    auth: Option<&auth::AuthContext>,
    operation: &str,
) -> bool {
    // Only check policy for SPIFFE mTLS authenticated requests
    let auth = match auth {
        Some(a) if a.auth_method == auth::AuthMethod::SpiffeMtls => a,
        _ => return false,
    };

    // Get SPIFFE ID
    let spiffe_id = match &auth.spiffe_id {
        Some(id) => id,
        None => return false,
    };

    // Check if policy engine is enabled and has a matching policy
    if !state.policy_engine.is_zero_prompt_enabled() {
        return false;
    }

    // Get permissions for this identity
    let permissions = match state.policy_engine.permissions_for(spiffe_id) {
        Some(p) => p,
        None => return false,
    };

    // Check capabilities based on operation type
    // This is a simplified check - a full implementation would parse the operation
    // and check specific capabilities and path patterns
    let requires_approval = match operation.split_whitespace().next() {
        Some("read") => {
            permissions.capabilities.read_files == CapabilityLevel::Never
                || permissions.requires_approval(Operation::ReadFiles)
        }
        Some("write") => {
            permissions.capabilities.write_files == CapabilityLevel::Never
                || permissions.requires_approval(Operation::WriteFiles)
        }
        Some("run") | Some("execute") => {
            permissions.capabilities.run_bash == CapabilityLevel::Never
                || permissions.requires_approval(Operation::RunBash)
        }
        Some("web_fetch") => {
            permissions.capabilities.web_fetch == CapabilityLevel::Never
                || permissions.requires_approval(Operation::WebFetch)
        }
        _ => true, // Unknown operations require approval
    };

    if !requires_approval {
        tracing::info!(
            spiffe_id = %spiffe_id,
            operation = %operation,
            event = "zero_prompt_authorized",
            "operation authorized via SPIFFE identity policy"
        );
    }

    !requires_approval
}

/// POST `/v1/memory/write` — provenance-verified memory admission (next-bet #1).
/// A write maps to `WriteFiles` (so it is itself subject to the egress gate),
/// then goes through `verified_admit`: a forged label is rejected; an honest
/// web-ingest record is admitted-but-quarantined.
async fn memory_write(
    State(state): State<AppState>,
    _auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<memory::MemoryWriteReq>,
) -> Result<Json<memory::MemoryWriteResp>, ApiError> {
    let _dt = http_kernel_decide(&state, Operation::WriteFiles, "memory://write").await?;
    let mut set = state.provenance_memory.lock().await;
    Ok(Json(memory::memory_write_core(
        &mut set,
        state.memory_transforms.as_ref(),
        req,
    )))
}

/// POST `/v1/memory/recall` — taint-labeled recall gated through the IFC flow
/// tracker (next-bet #1). Recall maps to `ReadFiles` (a read, never an outbound
/// action) so it always runs and injects the recalled record's own label into
/// the session: an un-declassified adversarial record taints the session, so the
/// agent's NEXT privileged tool call is denied by the existing egress gate.
async fn memory_recall(
    State(state): State<AppState>,
    _auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<memory::MemoryRecallReq>,
) -> Result<Json<memory::MemoryRecallResp>, ApiError> {
    let _dt = http_kernel_decide(&state, Operation::ReadFiles, "memory://recall").await?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let set = state.provenance_memory.lock().await;
    // Project the recall's effective label onto the single authoritative graph
    // the egress verdict reads.
    let mut graph = state.flow_graph.lock().await;
    let resp = memory::memory_recall_core(
        &set,
        &mut graph,
        state.declassify_trusted_keys.as_ref(),
        state.declassify_threshold,
        now,
        req,
    )?;
    Ok(Json(resp))
}

/// HTTP enforcement chokepoint: locks the kernel THEN the flow graph (same
/// order as the MCP server) and runs the reference monitor. Both guards are
/// dropped before the caller performs any sandbox/executor I/O.
///
/// The recording is not done here on purpose. `mediation::decide_and_record`
/// owns both halves, so there is no way to obtain a decision on this path
/// without it having been recorded — the hole this increment closes cannot be
/// reopened by a future edit to this function.
async fn http_kernel_decide(
    state: &AppState,
    operation: Operation,
    subject: &str,
) -> Result<DecisionToken, ApiError> {
    let mut kernel = state.kernel.lock().await;
    // The single authoritative FlowGraph is the live verdict source (Phase 2
    // retirement: the FlowTracker oracle is gone). Lock order (kernel, graph)
    // matches ingest.
    let graph = state.flow_graph.lock().await;
    mediation::decide_and_record(
        state.verdict_sink.as_ref(),
        &mut kernel,
        &graph,
        operation,
        subject,
        ActorIdentity::Unknown,
        "http",
    )
}

/// Content-address the *actual ingested bytes* of an agent input (InputsAuthorized
/// brick 3). Recomputes the SHA-256 of the real bytes in hand at the ingest site
/// and wraps the digest in the kernel [`ContentHash`] the FlowGraph node API
/// expects. The hash is NEVER read from an agent-supplied field — it is always
/// recomputed here from the bytes we actually observed.
///
/// [`ContentHash`]: nucleus_ifc_kernel::ContentHash
pub(crate) fn ingest_content_hash(bytes: &[u8]) -> nucleus_ifc_kernel::ContentHash {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest: [u8; 32] = hasher.finalize().into();
    nucleus_ifc_kernel::ContentHash::from_bytes(digest)
}

async fn read_file(
    State(state): State<AppState>,
    _headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<ReadRequest>,
) -> Result<Json<ReadResponse>, ApiError> {
    let sink = &state.verdict_sink;
    let operation = Operation::ReadFiles;
    let auth_ctx = auth.map(|e| e.0);
    let actor = actor_from_auth(auth_ctx.as_ref());

    // Validate inputs before any processing
    if let Err(e) = validation::validate_path(&req.path) {
        if let Err(e) = sink.record(VerdictContext {
            operation,
            subject: req.path.clone(),
            outcome: VerdictOutcome::Deny {
                reason: format!("validation: {e}"),
            },
            actor,
            policy_rule: None,
            extensions: BTreeMap::new(),
        }) {
            warn!(error = %e, "verdict recording failed -- audit gap");
        }
        return Err(ApiError::Validation(e));
    }

    // Kernel mediation + IFC flow consult — obtain DecisionToken for sandbox I/O
    let decision_token = http_kernel_decide(&state, operation, &req.path).await?;

    let path = req.path.clone();
    // Survives the sink record below, which consumes `path`.
    let observed_path = path.clone();

    // Discharge the eight obligations for this read. Reads were previously
    // unmediated on this path: it went from `http_kernel_decide` straight to the
    // sandbox, so a read never cleared the obligations that `FileEffect::read`
    // enforces on the other filesystem path.
    macro_rules! read_authority {
        () => {{
            use nucleus_ifc_kernel::discharge::PreflightResult;
            let verified_scope = state.session_task_token.verified_scope();
            let ceiling = state.runtime.policy().capabilities.read_files;
            let flow = state.flow_graph.lock().await;
            let r = run_gate::preflight_read_fs(verified_scope, ceiling, &path, &flow);
            drop(flow);
            match r {
                PreflightResult::Allowed(b) => portcullis_effects::authority::Authority::new(b),
                PreflightResult::Denied { reason, .. }
                | PreflightResult::RequiresApproval { reason } => {
                    return Err(ApiError::IfcDenied(format!("discharge denied: {reason}")));
                }
            }
        }};
    }
    let first_authority = read_authority!();

    let contents =
        match state
            .runtime
            .sandbox()
            .read_to_string(&path, &decision_token, first_authority)
        {
            Ok(contents) => contents,
            Err(NucleusError::ApprovalRequired { operation: op }) => {
                // Check if policy allows this operation (zero-prompt mode) or if approval was pre-granted
                if check_identity_policy(&state, auth_ctx.as_ref(), &format!("read {}", path))
                    || state.approvals.consume(&op)
                {
                    let approval = state.runtime.sandbox().request_approval(op.clone())?;
                    let approved_dt = {
                        let mut kernel = state.kernel.lock().await;
                        kernel.issue_approved_token(operation, &format!("approved: read {}", path))
                    };
                    // A fresh discharge for the approved retry: one discharge
                    // authorizes one attempt.
                    let retry_authority = read_authority!();
                    state.runtime.sandbox().read_to_string_approved(
                        &path,
                        &approved_dt,
                        &approval,
                        retry_authority,
                    )?
                } else {
                    if let Err(e) = sink.record(VerdictContext {
                        operation,
                        subject: path.clone(),
                        outcome: VerdictOutcome::Deny {
                            reason: "approval_required".to_string(),
                        },
                        actor,
                        policy_rule: None,
                        extensions: BTreeMap::new(),
                    }) {
                        warn!(error = %e, "verdict recording failed -- audit gap");
                    }
                    return Err(ApiError::Nucleus(NucleusError::ApprovalRequired {
                        operation: op,
                    }));
                }
            }
            Err(err) => {
                if let Err(e) = sink.record(VerdictContext {
                    operation,
                    subject: path.clone(),
                    outcome: VerdictOutcome::Error {
                        error: format!("{err:?}"),
                    },
                    actor,
                    policy_rule: None,
                    extensions: BTreeMap::new(),
                }) {
                    warn!(error = %e, "verdict recording failed -- audit gap");
                }
                return Err(ApiError::Nucleus(err));
            }
        };

    if let Err(e) = sink.record(VerdictContext {
        operation,
        subject: path,
        outcome: VerdictOutcome::Allow,
        actor,
        policy_rule: None,
        extensions: BTreeMap::new(),
    }) {
        warn!(error = %e, "verdict recording failed -- audit gap");
    }
    // IFC: a successful file read brings data into the session (#1633).
    // Brick 3: content-address the exact bytes read.
    // A path written during a tainted session re-enters as adversarial, not as a
    // trusted file read — otherwise a round-trip through disk strips the taint.
    // If the proxy wrote this path, the read DERIVES from that write — a real
    // edge, because the proxy mediated both ends. `propagate_label` joins the
    // parent's label in, so a read of a tainted write is adversarial without any
    // special case: #2135 selected a different NodeKind by boolean; the graph now
    // produces the same outcome as a consequence.
    let parents: Vec<u64> = state
        .path_provenance
        .lock()
        .await
        .get(&observed_path)
        .copied()
        .into_iter()
        .collect();
    if !parents.is_empty() {
        warn!(path = %observed_path, parent = parents[0],
              "read derives from a prior write; attaching provenance edge");
    }
    ingest::http_observe_flow_from(&state, NodeKind::FileRead, contents.as_bytes(), &parents).await;
    Ok(Json(ReadResponse { contents }))
}

async fn write_file(
    State(state): State<AppState>,
    _headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<WriteRequest>,
) -> Result<Json<WriteResponse>, ApiError> {
    let sink = &state.verdict_sink;
    let operation = Operation::WriteFiles;
    let auth_ctx = auth.map(|e| e.0);
    let actor = actor_from_auth(auth_ctx.as_ref());

    // Validate inputs before any processing
    if let Err(e) = validation::validate_path(&req.path) {
        if let Err(e) = sink.record(VerdictContext {
            operation,
            subject: req.path.clone(),
            outcome: VerdictOutcome::Deny {
                reason: format!("validation: {e}"),
            },
            actor,
            policy_rule: None,
            extensions: BTreeMap::new(),
        }) {
            warn!(error = %e, "verdict recording failed -- audit gap");
        }
        return Err(ApiError::Validation(e));
    }

    // Kernel mediation + IFC flow consult — obtain DecisionToken for sandbox I/O.
    // WriteFiles is an OutboundAction: denied with IfcUnsafe once the session is
    // tainted by web content (lethal-trifecta guard, #1633).
    let decision_token = http_kernel_decide(&state, operation, &req.path).await?;

    let path = req.path.clone();
    // Survives the sink record below, which consumes `path`.
    let written_path = path.clone();
    let contents = req.contents.clone();

    // ─── Sealed discharge gate (B6, parity with the RunBash executor-proof gate
    // and the B5 net-egress gate). PRECONDITION for the `_proof`-gated
    // `Sandbox::write`: mint the sealed 8-witness `DischargedBundle` via
    // `preflight_fs`. Fail closed — a Missing/Invalid session task token gives
    // `verified_scope == None` ⇒ `InScopeWithTask` denies (no vacuous witness);
    // an out-of-scope op denies. Without the bundle the `_proof`-gated write
    // cannot be typed, so no un-preflighted agent fs write can reach cap-std.
    // The cap-std root confinement inside `Sandbox::write` is retained
    // (dual-stack): this bundle is additive, not a relocation.
    let discharge_bundle = {
        use nucleus_ifc_kernel::discharge::PreflightResult;
        let verified_scope = state.session_task_token.verified_scope();
        let fs_ceiling = state.runtime.policy().capabilities.write_files;
        let flow = state.flow_graph.lock().await;
        let result = run_gate::preflight_fs(
            Operation::WriteFiles,
            verified_scope,
            fs_ceiling,
            &path,
            &flow,
        );
        drop(flow);
        match result {
            PreflightResult::Allowed(bundle) => bundle,
            PreflightResult::Denied { reason, .. }
            | PreflightResult::RequiresApproval { reason } => {
                if let Err(e) = sink.record(VerdictContext {
                    operation,
                    subject: path.clone(),
                    outcome: VerdictOutcome::Deny {
                        reason: format!("discharge denied: {reason}"),
                    },
                    actor,
                    policy_rule: None,
                    extensions: BTreeMap::new(),
                }) {
                    warn!(error = %e, "verdict recording failed -- audit gap");
                }
                return Err(ApiError::IfcDenied(format!("discharge denied: {reason}")));
            }
        }
    };
    let _discharge_note = run_gate::discharge_witness(&discharge_bundle);

    match state.runtime.sandbox().write(
        &path,
        contents.as_bytes(),
        &decision_token,
        portcullis_effects::authority::Authority::new(discharge_bundle),
    ) {
        Ok(()) => {}
        Err(NucleusError::ApprovalRequired { operation: op }) => {
            // Check if policy allows this operation (zero-prompt mode) or if approval was pre-granted
            if check_identity_policy(&state, auth_ctx.as_ref(), &format!("write {}", path))
                || state.approvals.consume(&op)
            {
                let approval = state.runtime.sandbox().request_approval(op.clone())?;
                let approved_dt = {
                    let mut kernel = state.kernel.lock().await;
                    kernel.issue_approved_token(operation, &format!("approved: write {}", path))
                };
                // A fresh discharge for the approved retry: the first attempt
                // spent the authority minted above. One discharge authorizes one
                // attempt, and the approved write is a distinct action that must
                // clear the obligations on its own.
                let retry_bundle = {
                    use nucleus_ifc_kernel::discharge::PreflightResult;
                    let verified_scope = state.session_task_token.verified_scope();
                    let fs_ceiling = state.runtime.policy().capabilities.write_files;
                    let flow = state.flow_graph.lock().await;
                    let r = run_gate::preflight_fs(
                        Operation::WriteFiles,
                        verified_scope,
                        fs_ceiling,
                        &path,
                        &flow,
                    );
                    drop(flow);
                    match r {
                        PreflightResult::Allowed(b) => b,
                        _ => {
                            return Err(ApiError::IfcDenied(
                                "approved write failed re-discharge".to_string(),
                            ))
                        }
                    }
                };
                state.runtime.sandbox().write_approved(
                    &path,
                    contents.as_bytes(),
                    &approved_dt,
                    &approval,
                    portcullis_effects::authority::Authority::new(retry_bundle),
                )?;
            } else {
                if let Err(e) = sink.record(VerdictContext {
                    operation,
                    subject: path.clone(),
                    outcome: VerdictOutcome::Deny {
                        reason: "approval_required".to_string(),
                    },
                    actor,
                    policy_rule: None,
                    extensions: BTreeMap::new(),
                }) {
                    warn!(error = %e, "verdict recording failed -- audit gap");
                }
                return Err(ApiError::Nucleus(NucleusError::ApprovalRequired {
                    operation: op,
                }));
            }
        }
        Err(err) => {
            if let Err(e) = sink.record(VerdictContext {
                operation,
                subject: path.clone(),
                outcome: VerdictOutcome::Error {
                    error: format!("{err:?}"),
                },
                actor,
                policy_rule: None,
                extensions: BTreeMap::new(),
            }) {
                warn!(error = %e, "verdict recording failed -- audit gap");
            }
            return Err(ApiError::Nucleus(err));
        }
    }

    if let Err(e) = sink.record(VerdictContext {
        operation,
        subject: path,
        outcome: VerdictOutcome::Allow,
        actor,
        policy_rule: None,
        extensions: BTreeMap::new(),
    }) {
        warn!(error = %e, "verdict recording failed -- audit gap");
    }
    // If this write succeeded while the session was tainted, the bytes on disk
    // may carry that taint. Record the path so a later read of it is not treated
    // as a trusted file read. Only reachable under grading — see the field docs.
    // Record a node for the content now at this path, so a later read of it has
    // something to derive FROM.
    //
    // Its parent is the latest adversarial node, when there is one. The proxy
    // cannot know which prior nodes influenced what the agent chose to write —
    // that happens inside the agent — so it attaches the conservative edge and
    // over-approximates. Over-approximation is the safe direction: it can only
    // add taint, never clear it.
    // Record a node for the content now at this path, so a later read has
    // something to derive FROM. The provenance parent is attached inside
    // `http_observe_authored`, where it cannot be omitted.
    {
        if let Some(node) =
            ingest::http_observe_authored(&state, NodeKind::FileRead, req.contents.as_bytes()).await
        {
            state
                .path_provenance
                .lock()
                .await
                .insert(written_path.clone(), node);
        }
    }

    Ok(Json(WriteResponse { ok: true }))
}

async fn run_command(
    State(state): State<AppState>,
    _headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<RunRequest>,
) -> Result<Json<RunResponse>, ApiError> {
    let sink = &state.verdict_sink;
    let operation = Operation::RunBash;
    let auth_ctx = auth.map(|e| e.0);
    let actor = actor_from_auth(auth_ctx.as_ref());

    // Build display command for logging/auditing
    let display_command = req.args.join(" ");

    // Validate inputs before any processing
    if let Err(e) = validation::validate_command_args(&req.args) {
        if let Err(e) = sink.record(VerdictContext {
            operation,
            subject: display_command.clone(),
            outcome: VerdictOutcome::Deny {
                reason: format!("validation: {e}"),
            },
            actor,
            policy_rule: None,
            extensions: BTreeMap::new(),
        }) {
            warn!(error = %e, "verdict recording failed -- audit gap");
        }
        return Err(ApiError::Validation(e));
    }
    if let Err(e) = validation::validate_stdin(req.stdin.as_deref()) {
        if let Err(e) = sink.record(VerdictContext {
            operation,
            subject: display_command.clone(),
            outcome: VerdictOutcome::Deny {
                reason: format!("validation: {e}"),
            },
            actor,
            policy_rule: None,
            extensions: BTreeMap::new(),
        }) {
            warn!(error = %e, "verdict recording failed -- audit gap");
        }
        return Err(ApiError::Validation(e));
    }
    if let Some(ref dir) = req.directory {
        if let Err(e) = validation::validate_path(dir) {
            if let Err(e) = sink.record(VerdictContext {
                operation,
                subject: display_command.clone(),
                outcome: VerdictOutcome::Deny {
                    reason: format!("validation: {e}"),
                },
                actor,
                policy_rule: None,
                extensions: BTreeMap::new(),
            }) {
                warn!(error = %e, "verdict recording failed -- audit gap");
            }
            return Err(ApiError::Validation(e));
        }
    }

    // Kernel mediation + IFC flow consult — obtain DecisionToken for executor I/O.
    // RunBash is an OutboundAction: denied with IfcUnsafe once the session is
    // tainted by web content (lethal-trifecta guard, #1633).
    let decision_token = http_kernel_decide(&state, operation, &display_command).await?;

    let executor = state.runtime.executor();

    // Extract optional parameters
    let stdin = req.stdin.as_deref();
    let directory = req.directory.as_deref();

    // ─── Executor-proof gate (PR-2, parity with the MCP RunBash handler) ──────
    // Mint the sealed 8-witness `DischargedBundle` — the type-level precondition
    // that lets `run_args`/`run_args_with_approval` even be typed. Reuses the exact
    // `preflight_runbash` the MCP path uses (no re-mint, no forged bundle). Fail
    // closed on Denied/RequiresApproval: a Missing/Invalid session task token gives
    // `verified_scope == None` ⇒ `InScopeWithTask` denies — never a permissive
    // default. Without a bundle here this HTTP spawn would not compile.
    let discharge_bundle = {
        use nucleus_ifc_kernel::discharge::PreflightResult;
        let verified_scope = state.session_task_token.verified_scope();
        let run_bash_ceiling = state.runtime.policy().capabilities.run_bash;
        let flow = state.flow_graph.lock().await;
        let result =
            run_gate::preflight_runbash(verified_scope, run_bash_ceiling, &display_command, &flow);
        drop(flow);
        match result {
            PreflightResult::Allowed(bundle) => bundle,
            PreflightResult::Denied { reason, .. } => {
                if let Err(e) = sink.record(VerdictContext {
                    operation,
                    subject: display_command.clone(),
                    outcome: VerdictOutcome::Deny {
                        reason: format!("discharge denied: {reason}"),
                    },
                    actor,
                    policy_rule: None,
                    extensions: BTreeMap::new(),
                }) {
                    warn!(error = %e, "verdict recording failed -- audit gap");
                }
                return Err(ApiError::IfcDenied(format!("discharge denied: {reason}")));
            }
            PreflightResult::RequiresApproval { reason } => {
                if let Err(e) = sink.record(VerdictContext {
                    operation,
                    subject: display_command.clone(),
                    outcome: VerdictOutcome::Deny {
                        reason: format!("discharge requires approval: {reason}"),
                    },
                    actor,
                    policy_rule: None,
                    extensions: BTreeMap::new(),
                }) {
                    warn!(error = %e, "verdict recording failed -- audit gap");
                }
                return Err(ApiError::IfcDenied(format!(
                    "discharge requires approval: {reason}"
                )));
            }
        }
    };
    // Durable audit witness of the sealed 8-witness proof (parity with the MCP
    // handler's `discharge_bundle` verdict extension).
    let discharge_note = run_gate::discharge_witness(&discharge_bundle);

    let output = match executor.run_args(
        &req.args,
        stdin,
        directory,
        &decision_token,
        portcullis_effects::authority::Authority::new(discharge_bundle),
    ) {
        Ok(output) => output,
        Err(NucleusError::ApprovalRequired { operation: op }) => {
            // Check if policy allows this operation (zero-prompt mode) or if approval was pre-granted
            if check_identity_policy(
                &state,
                auth_ctx.as_ref(),
                &format!("execute {}", display_command),
            ) || state.approvals.consume(&op)
            {
                let approval = executor.request_approval(&op)?;
                let approved_dt = {
                    let mut kernel = state.kernel.lock().await;
                    kernel.issue_approved_token(
                        operation,
                        &format!("approved: execute {}", display_command),
                    )
                };
                executor.run_args_with_approval(
                    &req.args,
                    stdin,
                    directory,
                    &approved_dt,
                    &approval,
                    // A fresh discharge for the retry. The first attempt spent
                    // the authority minted above — one discharge authorizes one
                    // attempt, and the approved retry is a distinct action that
                    // must clear the obligations on its own.
                    portcullis_effects::authority::Authority::new({
                        use nucleus_ifc_kernel::discharge::PreflightResult;
                        let verified_scope = state.session_task_token.verified_scope();
                        let ceiling = state.runtime.policy().capabilities.run_bash;
                        let flow = state.flow_graph.lock().await;
                        let r = run_gate::preflight_runbash(
                            verified_scope,
                            ceiling,
                            &display_command,
                            &flow,
                        );
                        drop(flow);
                        match r {
                            PreflightResult::Allowed(b) => b,
                            _ => {
                                return Err(ApiError::Body(
                                    "approved retry failed re-discharge".to_string(),
                                ))
                            }
                        }
                    }),
                )?
            } else {
                if let Err(e) = sink.record(VerdictContext {
                    operation,
                    subject: display_command.clone(),
                    outcome: VerdictOutcome::Deny {
                        reason: "approval_required".to_string(),
                    },
                    actor,
                    policy_rule: None,
                    extensions: BTreeMap::new(),
                }) {
                    warn!(error = %e, "verdict recording failed -- audit gap");
                }
                return Err(ApiError::Nucleus(NucleusError::ApprovalRequired {
                    operation: op,
                }));
            }
        }
        Err(err) => {
            if let Err(e) = sink.record(VerdictContext {
                operation,
                subject: display_command.clone(),
                outcome: VerdictOutcome::Error {
                    error: format!("{err:?}"),
                },
                actor,
                policy_rule: None,
                extensions: BTreeMap::from([(
                    "discharge_bundle".to_string(),
                    discharge_note.clone(),
                )]),
            }) {
                warn!(error = %e, "verdict recording failed -- audit gap");
            }
            return Err(ApiError::Nucleus(err));
        }
    };

    if let Err(e) = sink.record(VerdictContext {
        operation,
        subject: display_command,
        outcome: VerdictOutcome::Allow,
        actor,
        policy_rule: None,
        extensions: BTreeMap::from([("discharge_bundle".to_string(), discharge_note)]),
    }) {
        warn!(error = %e, "verdict recording failed -- audit gap");
    }
    ingest::http_observe_command_output(&state, &output.stdout, &output.stderr).await;

    Ok(Json(RunResponse {
        status: output.status.code().unwrap_or(-1),
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }))
}

async fn web_fetch(
    State(state): State<AppState>,
    _headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<WebFetchRequest>,
) -> Result<Json<WebFetchResponse>, ApiError> {
    let sink = &state.verdict_sink;
    let operation = Operation::WebFetch;
    let url_str = req.url.clone();
    let auth_ctx = auth.map(|e| e.0);
    let actor = actor_from_auth(auth_ctx.as_ref());

    // Validate inputs before any processing
    if let Err(e) = validation::validate_url(&req.url) {
        if let Err(e) = sink.record(VerdictContext {
            operation,
            subject: url_str.clone(),
            outcome: VerdictOutcome::Deny {
                reason: format!("validation: {e}"),
            },
            actor,
            policy_rule: None,
            extensions: BTreeMap::new(),
        }) {
            warn!(error = %e, "verdict recording failed -- audit gap");
        }
        return Err(ApiError::Validation(e));
    }

    // Kernel mediation + IFC flow consult. WebFetch is itself a taint source
    // (observed below on success); the consult still runs for capability/exposure.
    let _ = http_kernel_decide(&state, operation, &url_str).await?;

    // Check web_fetch capability
    let policy = state.runtime.policy();
    let level = policy.capabilities.web_fetch;
    if level == CapabilityLevel::Never {
        if let Err(e) = sink.record(VerdictContext {
            operation,
            subject: url_str.clone(),
            outcome: VerdictOutcome::Deny {
                reason: "insufficient_capability".to_string(),
            },
            actor,
            policy_rule: None,
            extensions: BTreeMap::new(),
        }) {
            warn!(error = %e, "verdict recording failed -- audit gap");
        }
        return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
            capability: "web_fetch".into(),
            actual: level,
            required: CapabilityLevel::LowRisk,
        }));
    }

    // Check if uninhabitable_state requires approval for web_fetch
    if policy.requires_approval(Operation::WebFetch) {
        // Check if policy allows this operation (zero-prompt mode)
        let policy_allows =
            check_identity_policy(&state, auth_ctx.as_ref(), &format!("web_fetch {}", url_str));

        if !policy_allows && !state.approvals.consume("web_fetch") {
            if let Err(e) = sink.record(VerdictContext {
                operation,
                subject: url_str.clone(),
                outcome: VerdictOutcome::Deny {
                    reason: "approval_required".to_string(),
                },
                actor,
                policy_rule: None,
                extensions: BTreeMap::new(),
            }) {
                warn!(error = %e, "verdict recording failed -- audit gap");
            }
            return Err(ApiError::Nucleus(NucleusError::ApprovalRequired {
                operation: format!("web_fetch {}", url_str),
            }));
        }
    }

    // Parse and validate URL
    let url =
        url::Url::parse(&url_str).map_err(|e| ApiError::WebFetch(format!("invalid URL: {e}")))?;

    // Check DNS allow list (if configured) — shared with MCP path
    {
        let host = url
            .host_str()
            .ok_or_else(|| ApiError::WebFetch("URL has no host".into()))?;
        let port = url.port_or_known_default().unwrap_or(443);
        web_fetch_policy::check_dns_allowlist(&state.dns_allow, host, port)
            .map_err(ApiError::DnsNotAllowed)?;
    }

    // Check URL allow list (if configured) — shared with MCP path
    web_fetch_policy::check_url_allowlist(&state.url_allow, url.as_str())
        .map_err(ApiError::WebFetch)?;

    // Build the request pieces (method / headers / body) the sealed net effect
    // needs. The raw reqwest send itself now lives in `portcullis-effects`
    // (`NetEffect::fetch`) — this handler no longer performs it.
    let method = req.method.as_deref().unwrap_or("GET").to_uppercase();
    let method = reqwest::Method::from_bytes(method.as_bytes())
        .map_err(|_| ApiError::WebFetch(format!("invalid method: {}", method)))?;
    let headers: Vec<(String, String)> = req.headers.unwrap_or_default().into_iter().collect();
    let body: Option<Vec<u8>> = req.body.map(|b| b.into_bytes());

    // ─── Sealed discharge gate (B5, parity with the RunBash executor-proof gate)
    // PRECONDITION for the sealed `NetEffect::fetch`: mint the sealed 8-witness
    // `DischargedBundle` via `preflight_web`. Fail closed — a Missing/Invalid
    // session task token gives `verified_scope == None` ⇒ `InScopeWithTask`
    // denies (no vacuous witness); an out-of-scope op denies. Without the bundle
    // the sealed fetch cannot be typed, so no un-preflighted agent egress can
    // reach the wire.
    let discharge_bundle = {
        use nucleus_ifc_kernel::discharge::PreflightResult;
        let verified_scope = state.session_task_token.verified_scope();
        let flow = state.flow_graph.lock().await;
        let result = run_gate::preflight_web(operation, verified_scope, level, &url_str, &flow);
        drop(flow);
        match result {
            PreflightResult::Allowed(bundle) => bundle,
            PreflightResult::Denied { reason, .. }
            | PreflightResult::RequiresApproval { reason } => {
                if let Err(e) = sink.record(VerdictContext {
                    operation,
                    subject: url_str.clone(),
                    outcome: VerdictOutcome::Deny {
                        reason: format!("discharge denied: {reason}"),
                    },
                    actor,
                    policy_rule: None,
                    extensions: BTreeMap::new(),
                }) {
                    warn!(error = %e, "verdict recording failed -- audit gap");
                }
                return Err(ApiError::IfcDenied(format!("discharge denied: {reason}")));
            }
        }
    };
    let _discharge_note = run_gate::discharge_witness(&discharge_bundle);

    // Execute the request through the sealed, `_proof`-gated net effect. Passing
    // the bundle is the type-level authorization; `PolicyEnforced` re-checks the
    // `web_fetch` capability inside the sealed home.
    use portcullis_effects::{NetCapability, NetEffect};
    let effects =
        portcullis_effects::production_effects_concrete(core_capabilities(&policy.capabilities));
    let response = effects
        .fetch(
            &state.web_client,
            NetCapability::WebFetch,
            method,
            url,
            &headers,
            body,
            None,
            portcullis_effects::authority::Authority::new(discharge_bundle),
        )
        .await
        .map_err(|e| ApiError::WebFetch(format!("request failed: {e}")))?;

    let status = response.status().as_u16();

    // Verify the final URL after redirects is still in the allowlist.
    // Prevents open-redirect bypass attacks on allowlisted domains.
    let final_url = response.url().clone();
    web_fetch_policy::check_redirect_target(&state.dns_allow, &state.url_allow, &final_url)
        .map_err(|e| ApiError::WebFetch(format!("redirect target blocked: {e}")))?;

    // MIME type gating — shared with MCP path
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    web_fetch_policy::check_mime_type(content_type, state.web_fetch_mime_allow.as_deref())
        .map_err(ApiError::WebFetch)?;

    // Collect response headers + add exposure metadata
    let mut response_headers: HashMap<String, String> = response
        .headers()
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|v| (k.as_str().to_string(), v.to_string()))
        })
        .collect();

    // Exposure provenance: mark all web-fetched content as untrusted.
    // Downstream tool calls can use these headers for exposure tracking.
    response_headers.insert(
        "x-nucleus-exposure".to_string(),
        "UntrustedContent".to_string(),
    );
    if let Some(host) = url::Url::parse(&url_str)
        .ok()
        .and_then(|u| u.host_str().map(|s| s.to_string()))
    {
        response_headers.insert("x-nucleus-source-domain".to_string(), host);
    }

    // Read body with a HARD allocation cap: stream and stop at the limit so a
    // malicious upstream body cannot OOM-kill the enforcement process, which
    // would run the agent unmonitored (fail-open). Audit H-1.
    let (bytes, was_truncated) =
        web_fetch_policy::read_body_capped(response, state.web_fetch_max_bytes)
            .await
            .map_err(|e| ApiError::WebFetch(format!("failed to read response: {e}")))?;
    let body = String::from_utf8_lossy(&bytes).to_string();
    let truncated = if was_truncated { Some(true) } else { None };

    if let Err(e) = sink.record(VerdictContext {
        operation,
        subject: url_str,
        outcome: VerdictOutcome::Allow,
        actor,
        policy_rule: None,
        extensions: BTreeMap::new(),
    }) {
        warn!(error = %e, "verdict recording failed -- audit gap");
    }
    // IFC: web content is an adversarial taint source — taint the session so
    // subsequent outbound actions are denied with IfcUnsafe (lethal trifecta, #1633).
    // Brick 3: content-address the exact fetched body bytes.
    ingest::http_observe_flow(&state, NodeKind::WebContent, &bytes).await;
    Ok(Json(WebFetchResponse {
        status,
        headers: response_headers,
        body,
        truncated,
    }))
}

/// Glob pattern search within the sandbox.
async fn glob_search(
    State(state): State<AppState>,
    _headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<GlobRequest>,
) -> Result<Json<GlobResponse>, ApiError> {
    let sink = &state.verdict_sink;
    let operation = Operation::GlobSearch;
    let auth_ctx = auth.map(|e| e.0);
    let actor = actor_from_auth(auth_ctx.as_ref());

    // Validate inputs before any processing
    validation::validate_pattern(&req.pattern).map_err(ApiError::Validation)?;
    if let Some(ref dir) = req.directory {
        validation::validate_path(dir).map_err(ApiError::Validation)?;
    }

    // Kernel mediation + IFC flow consult. GlobSearch is a FileRead (observed
    // below on success); not an outbound action, so never IFC-denied.
    let _ = http_kernel_decide(&state, operation, &req.pattern).await?;

    // Check glob_search capability
    let policy = state.runtime.policy();
    let level = policy.capabilities.glob_search;
    if level == CapabilityLevel::Never {
        if let Err(e) = sink.record(VerdictContext {
            operation,
            subject: req.pattern.clone(),
            outcome: VerdictOutcome::Deny {
                reason: "insufficient_capability".to_string(),
            },
            actor,
            policy_rule: None,
            extensions: BTreeMap::new(),
        }) {
            warn!(error = %e, "verdict recording failed -- audit gap");
        }
        return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
            capability: "glob_search".into(),
            actual: level,
            required: CapabilityLevel::LowRisk,
        }));
    }

    // Check if uninhabitable_state requires approval
    if policy.requires_approval(Operation::GlobSearch) {
        let policy_allows =
            check_identity_policy(&state, auth_ctx.as_ref(), &format!("glob {}", req.pattern));
        if !policy_allows && !state.approvals.consume("glob_search") {
            if let Err(e) = sink.record(VerdictContext {
                operation,
                subject: req.pattern.clone(),
                outcome: VerdictOutcome::Deny {
                    reason: "approval_required".to_string(),
                },
                actor,
                policy_rule: None,
                extensions: BTreeMap::new(),
            }) {
                warn!(error = %e, "verdict recording failed -- audit gap");
            }
            return Err(ApiError::Nucleus(NucleusError::ApprovalRequired {
                operation: format!("glob {}", req.pattern),
            }));
        }
    }

    // Determine search root
    let sandbox_root = state.runtime.sandbox().root_path();
    let sandbox_canonical = sandbox_root
        .canonicalize()
        .map_err(|e| ApiError::Spec(format!("sandbox root not accessible: {e}")))?;

    let search_root = if let Some(ref dir) = req.directory {
        // Reject absolute paths immediately
        if Path::new(dir).is_absolute() {
            return Err(ApiError::Nucleus(NucleusError::SandboxEscape {
                path: PathBuf::from(dir),
            }));
        }
        let resolved = sandbox_root.join(dir);
        // Canonicalize to resolve symlinks and .. components (path must exist)
        let canonical = resolved.canonicalize().map_err(|_| {
            ApiError::Nucleus(NucleusError::SandboxEscape {
                path: resolved.clone(),
            })
        })?;
        // Security: ensure canonicalized path is within sandbox
        if !canonical.starts_with(&sandbox_canonical) {
            return Err(ApiError::Nucleus(NucleusError::SandboxEscape {
                path: resolved,
            }));
        }
        canonical
    } else {
        sandbox_canonical.clone()
    };

    // Build full glob pattern
    let full_pattern = search_root.join(&req.pattern);
    let pattern_str = full_pattern.to_string_lossy();

    // Perform glob search
    let max_results = req.max_results.unwrap_or(1000);
    let mut matches = Vec::new();
    let mut truncated = false;

    for entry in glob::glob(&pattern_str)
        .map_err(|e| ApiError::Spec(format!("invalid glob pattern: {e}")))?
    {
        match entry {
            Ok(path) => {
                // Security: canonicalize and verify path is within sandbox
                // This prevents symlink-based escapes
                let canonical = match path.canonicalize() {
                    Ok(c) => c,
                    Err(_) => continue, // Skip inaccessible paths
                };
                if !canonical.starts_with(&sandbox_canonical) {
                    continue;
                }
                // Convert to relative path (use canonical sandbox root)
                if let Ok(relative) = canonical.strip_prefix(&sandbox_canonical) {
                    matches.push(relative.to_string_lossy().to_string());
                    if matches.len() >= max_results {
                        truncated = true;
                        break;
                    }
                }
            }
            Err(_) => continue, // Skip inaccessible paths
        }
    }

    if let Err(e) = sink.record(VerdictContext {
        operation,
        subject: req.pattern,
        outcome: VerdictOutcome::Allow,
        actor,
        policy_rule: None,
        extensions: BTreeMap::new(),
    }) {
        warn!(error = %e, "verdict recording failed -- audit gap");
    }
    // IFC: a successful glob brings file data into the session (#1633).
    // Brick 3: content-address the exact match listing ingested.
    let listing = matches.join("\n");
    ingest::http_observe_flow(&state, NodeKind::FileRead, listing.as_bytes()).await;
    Ok(Json(GlobResponse {
        matches,
        truncated: if truncated { Some(true) } else { None },
    }))
}

/// Grep (regex content search) within the sandbox.
async fn grep_search(
    State(state): State<AppState>,
    _headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<GrepRequest>,
) -> Result<Json<GrepResponse>, ApiError> {
    use regex::RegexBuilder;
    use std::io::{BufRead, BufReader};
    use walkdir::WalkDir;

    let sink = &state.verdict_sink;
    let operation = Operation::GrepSearch;
    let auth_ctx = auth.map(|e| e.0);
    let actor = actor_from_auth(auth_ctx.as_ref());

    // Validate inputs before any processing
    validation::validate_pattern(&req.pattern).map_err(ApiError::Validation)?;
    if let Some(ref path) = req.path {
        validation::validate_path(path).map_err(ApiError::Validation)?;
    }
    if let Some(ref glob_pattern) = req.file_glob {
        validation::validate_pattern(glob_pattern).map_err(ApiError::Validation)?;
    }

    // Kernel mediation + IFC flow consult. GrepSearch is a FileRead (observed
    // below on success); not an outbound action, so never IFC-denied.
    let _ = http_kernel_decide(&state, operation, &req.pattern).await?;

    // Check grep_search capability
    let policy = state.runtime.policy();
    let level = policy.capabilities.grep_search;
    if level == CapabilityLevel::Never {
        if let Err(e) = sink.record(VerdictContext {
            operation,
            subject: req.pattern.clone(),
            outcome: VerdictOutcome::Deny {
                reason: "insufficient_capability".to_string(),
            },
            actor,
            policy_rule: None,
            extensions: BTreeMap::new(),
        }) {
            warn!(error = %e, "verdict recording failed -- audit gap");
        }
        return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
            capability: "grep_search".into(),
            actual: level,
            required: CapabilityLevel::LowRisk,
        }));
    }

    // Check if uninhabitable_state requires approval
    if policy.requires_approval(Operation::GrepSearch) {
        let policy_allows =
            check_identity_policy(&state, auth_ctx.as_ref(), &format!("grep {}", req.pattern));
        if !policy_allows && !state.approvals.consume("grep_search") {
            if let Err(e) = sink.record(VerdictContext {
                operation,
                subject: req.pattern.clone(),
                outcome: VerdictOutcome::Deny {
                    reason: "approval_required".to_string(),
                },
                actor,
                policy_rule: None,
                extensions: BTreeMap::new(),
            }) {
                warn!(error = %e, "verdict recording failed -- audit gap");
            }
            return Err(ApiError::Nucleus(NucleusError::ApprovalRequired {
                operation: format!("grep {}", req.pattern),
            }));
        }
    }

    // Build regex
    let regex = RegexBuilder::new(&req.pattern)
        .case_insensitive(req.case_insensitive.unwrap_or(false))
        .build()
        .map_err(|e| ApiError::Spec(format!("invalid regex pattern: {e}")))?;

    let sandbox_root = state.runtime.sandbox().root_path();
    let sandbox_canonical = sandbox_root
        .canonicalize()
        .map_err(|e| ApiError::Spec(format!("sandbox root not accessible: {e}")))?;
    let max_matches = req.max_matches.unwrap_or(100);
    let context_lines = req.context_lines.unwrap_or(0);
    let mut matches = Vec::new();
    let mut truncated = false;

    // Collect files to search
    let files: Vec<std::path::PathBuf> = if let Some(ref path) = req.path {
        // Reject absolute paths immediately
        if Path::new(path).is_absolute() {
            return Err(ApiError::Nucleus(NucleusError::SandboxEscape {
                path: PathBuf::from(path),
            }));
        }
        // Search single file
        let full_path = sandbox_root.join(path);
        // Canonicalize to verify we're within sandbox (handles symlinks and ..)
        let canonical = full_path.canonicalize().map_err(|_| {
            ApiError::Nucleus(NucleusError::SandboxEscape {
                path: full_path.clone(),
            })
        })?;
        if !canonical.starts_with(&sandbox_canonical) {
            return Err(ApiError::Nucleus(NucleusError::SandboxEscape {
                path: full_path,
            }));
        }
        if canonical.is_file() {
            vec![canonical]
        } else {
            vec![]
        }
    } else {
        // Walk directory and optionally filter by glob
        let glob_pattern = req
            .file_glob
            .as_ref()
            .and_then(|g| glob::Pattern::new(g).ok());

        WalkDir::new(&sandbox_canonical)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            // Security: skip symlinks that could point outside sandbox
            .filter(|e| !e.file_type().is_symlink())
            .filter(|e| {
                // Double-check canonical path is within sandbox
                e.path()
                    .canonicalize()
                    .map(|c| c.starts_with(&sandbox_canonical))
                    .unwrap_or(false)
            })
            .filter(|e| {
                if let Some(ref pat) = glob_pattern {
                    pat.matches_path(e.path())
                } else {
                    true
                }
            })
            .map(|e| e.into_path())
            .collect()
    };

    // Search each file
    'outer: for file_path in files {
        let file = match std::fs::File::open(&file_path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let reader = BufReader::new(file);
        let lines: Vec<String> = reader.lines().map_while(Result::ok).collect();

        for (idx, line) in lines.iter().enumerate() {
            if regex.is_match(line) {
                let relative = file_path
                    .strip_prefix(&sandbox_canonical)
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|_| file_path.to_string_lossy().to_string());

                let context_before = if context_lines > 0 {
                    let start = idx.saturating_sub(context_lines);
                    Some(lines[start..idx].to_vec())
                } else {
                    None
                };

                let context_after = if context_lines > 0 {
                    let end = (idx + 1 + context_lines).min(lines.len());
                    Some(lines[idx + 1..end].to_vec())
                } else {
                    None
                };

                matches.push(GrepMatch {
                    file: relative,
                    line: idx + 1, // 1-indexed
                    content: line.clone(),
                    context_before,
                    context_after,
                });

                if matches.len() >= max_matches {
                    truncated = true;
                    break 'outer;
                }
            }
        }
    }

    if let Err(e) = sink.record(VerdictContext {
        operation,
        subject: req.pattern,
        outcome: VerdictOutcome::Allow,
        actor,
        policy_rule: None,
        extensions: BTreeMap::new(),
    }) {
        warn!(error = %e, "verdict recording failed -- audit gap");
    }
    // IFC: a successful grep brings file data into the session (#1633).
    // Brick 3: content-address the exact match set ingested (deterministic
    // serialization of the real matched bytes).
    let match_bytes = serde_json::to_vec(&matches).unwrap_or_default();
    ingest::http_observe_flow(&state, NodeKind::FileRead, &match_bytes).await;
    Ok(Json(GrepResponse {
        matches,
        truncated: if truncated { Some(true) } else { None },
    }))
}

/// Web search using configured backend.
async fn web_search(
    State(state): State<AppState>,
    _headers: HeaderMap,
    auth: Option<axum::Extension<auth::AuthContext>>,
    Json(req): Json<WebSearchRequest>,
) -> Result<Json<WebSearchResponse>, ApiError> {
    let sink = &state.verdict_sink;
    let operation = Operation::WebSearch;
    let auth_ctx = auth.map(|e| e.0);
    let actor = actor_from_auth(auth_ctx.as_ref());

    // Validate inputs before any processing
    validation::validate_query(&req.query).map_err(ApiError::Validation)?;

    // Kernel mediation + IFC flow consult. WebSearch is a taint source
    // (observed below on success); the consult still runs for capability/exposure.
    let _ = http_kernel_decide(&state, operation, &req.query).await?;

    // Check web_search capability
    let policy = state.runtime.policy();
    let level = policy.capabilities.web_search;
    if level == CapabilityLevel::Never {
        if let Err(e) = sink.record(VerdictContext {
            operation,
            subject: req.query.clone(),
            outcome: VerdictOutcome::Deny {
                reason: "insufficient_capability".to_string(),
            },
            actor,
            policy_rule: None,
            extensions: BTreeMap::new(),
        }) {
            warn!(error = %e, "verdict recording failed -- audit gap");
        }
        return Err(ApiError::Nucleus(NucleusError::InsufficientCapability {
            capability: "web_search".into(),
            actual: level,
            required: CapabilityLevel::LowRisk,
        }));
    }

    // Check if uninhabitable_state requires approval
    if policy.requires_approval(Operation::WebSearch) {
        let policy_allows = check_identity_policy(
            &state,
            auth_ctx.as_ref(),
            &format!("web_search {}", req.query),
        );
        if !policy_allows && !state.approvals.consume("web_search") {
            if let Err(e) = sink.record(VerdictContext {
                operation,
                subject: req.query.clone(),
                outcome: VerdictOutcome::Deny {
                    reason: "approval_required".to_string(),
                },
                actor,
                policy_rule: None,
                extensions: BTreeMap::new(),
            }) {
                warn!(error = %e, "verdict recording failed -- audit gap");
            }
            return Err(ApiError::Nucleus(NucleusError::ApprovalRequired {
                operation: format!("web_search {}", req.query),
            }));
        }
    }

    // Web search requires a configured backend URL
    // For now, return an error indicating the backend must be configured
    // A real implementation would read NUCLEUS_WEB_SEARCH_URL from env/config
    let search_url = std::env::var("NUCLEUS_WEB_SEARCH_URL").map_err(|_| {
        ApiError::Spec("web_search requires NUCLEUS_WEB_SEARCH_URL to be configured".to_string())
    })?;

    // Check DNS allow list
    let url = url::Url::parse(&search_url)
        .map_err(|e| ApiError::Spec(format!("invalid search backend URL: {e}")))?;

    if !state.dns_allow.is_empty() {
        let host = url
            .host_str()
            .ok_or_else(|| ApiError::Spec("search URL has no host".into()))?;
        let port = url.port_or_known_default().unwrap_or(443);
        let host_port = format!("{}:{}", host, port);

        let allowed = state.dns_allow.iter().any(|pattern| {
            pattern == &host_port || pattern == host || pattern.starts_with(&format!("{}:", host))
        });

        if !allowed {
            return Err(ApiError::DnsNotAllowed(host_port));
        }
    }

    // Perform search request. Fold the query params into the URL here so the
    // sealed net effect stays a plain method+url+headers+body send; the raw
    // reqwest send itself lives in `portcullis-effects` (`NetEffect::fetch`).
    let max_results = req.max_results.unwrap_or(10);
    let mut fetch_url = url.clone();
    fetch_url
        .query_pairs_mut()
        .append_pair("q", &req.query)
        .append_pair("num", &max_results.to_string());

    // ─── Sealed discharge gate (B5) ─────────────────────────────────────────
    // PRECONDITION for the sealed `NetEffect::fetch`: mint the sealed 8-witness
    // `DischargedBundle` via `preflight_web` (WebSearch/HTTPEgress). Fail closed
    // — Missing/Invalid token ⇒ `verified_scope == None` ⇒ `InScopeWithTask`
    // denies; out-of-scope op denies. No bundle ⇒ no fetch (no wire egress).
    let discharge_bundle = {
        use nucleus_ifc_kernel::discharge::PreflightResult;
        let verified_scope = state.session_task_token.verified_scope();
        let flow = state.flow_graph.lock().await;
        let result = run_gate::preflight_web(operation, verified_scope, level, &req.query, &flow);
        drop(flow);
        match result {
            PreflightResult::Allowed(bundle) => bundle,
            PreflightResult::Denied { reason, .. }
            | PreflightResult::RequiresApproval { reason } => {
                if let Err(e) = sink.record(VerdictContext {
                    operation,
                    subject: req.query.clone(),
                    outcome: VerdictOutcome::Deny {
                        reason: format!("discharge denied: {reason}"),
                    },
                    actor,
                    policy_rule: None,
                    extensions: BTreeMap::new(),
                }) {
                    warn!(error = %e, "verdict recording failed -- audit gap");
                }
                return Err(ApiError::IfcDenied(format!("discharge denied: {reason}")));
            }
        }
    };
    let _discharge_note = run_gate::discharge_witness(&discharge_bundle);

    use portcullis_effects::{NetCapability, NetEffect};
    let effects =
        portcullis_effects::production_effects_concrete(core_capabilities(&policy.capabilities));
    let response = effects
        .fetch(
            &state.web_client,
            NetCapability::WebSearch,
            reqwest::Method::GET,
            fetch_url,
            &[],
            None,
            None,
            portcullis_effects::authority::Authority::new(discharge_bundle),
        )
        .await
        .map_err(|e| ApiError::WebFetch(format!("search request failed: {e}")))?;

    if !response.status().is_success() {
        return Err(ApiError::WebFetch(format!(
            "search backend returned status {}",
            response.status()
        )));
    }

    // Parse response - this is a generic JSON structure
    // Real implementations would adapt to specific search APIs
    let (search_bytes, _truncated) =
        web_fetch_policy::read_body_capped(response, state.web_fetch_max_bytes)
            .await
            .map_err(|e| ApiError::WebFetch(format!("failed to read search response: {e}")))?;
    let body: serde_json::Value = serde_json::from_slice(&search_bytes)
        .map_err(|e| ApiError::WebFetch(format!("failed to parse search response: {e}")))?;

    // Try to extract results from common formats
    let results = if let Some(items) = body.get("results").and_then(|r| r.as_array()) {
        items
            .iter()
            .filter_map(|item| {
                Some(WebSearchResult {
                    title: item.get("title")?.as_str()?.to_string(),
                    url: item.get("url")?.as_str()?.to_string(),
                    snippet: item
                        .get("snippet")
                        .and_then(|s| s.as_str())
                        .map(String::from),
                })
            })
            .take(max_results)
            .collect()
    } else {
        Vec::new()
    };

    if let Err(e) = sink.record(VerdictContext {
        operation,
        subject: req.query,
        outcome: VerdictOutcome::Allow,
        actor,
        policy_rule: None,
        extensions: BTreeMap::new(),
    }) {
        warn!(error = %e, "verdict recording failed -- audit gap");
    }
    // IFC: web search results are an adversarial taint source (#1633).
    // Brick 3: content-address the exact search-backend response bytes.
    ingest::http_observe_flow(&state, NodeKind::WebContent, &search_bytes).await;
    Ok(Json(WebSearchResponse { results }))
}

async fn approve_operation(
    State(state): State<AppState>,
    _headers: HeaderMap,
    Json(req): Json<ApproveRequest>,
) -> Result<Json<ApproveResponse>, ApiError> {
    let sink = &state.verdict_sink;

    // Rate limit approval requests to prevent DoS
    if !state.approval_rate_limiter.try_acquire() {
        return Err(ApiError::RateLimited);
    }

    let now = now_unix();
    let expires_at = resolve_approval_expiry(req.expires_at_unix, now)?;
    let nonce = req
        .nonce
        .as_deref()
        .ok_or_else(|| ApiError::Spec("approval nonce required".to_string()))?;
    let expiry = expires_at.unwrap_or(now + MAX_APPROVAL_TTL_SECS);
    if !state.approval_nonces.check_and_insert(nonce, expiry, now) {
        return Err(ApiError::Spec("approval nonce replayed".to_string()));
    }
    state
        .approvals
        .approve(&req.operation, req.count, expires_at);
    if let Err(e) = sink.record(VerdictContext {
        operation: Operation::ManagePods, // meta-operation: approval grant
        subject: req.operation,
        outcome: VerdictOutcome::Allow,
        actor: ActorIdentity::Unknown,
        policy_rule: None,
        extensions: BTreeMap::new(),
    }) {
        warn!(error = %e, "verdict recording failed -- audit gap");
    }
    Ok(Json(ApproveResponse { ok: true }))
}

/// Deserialize a trace chain from the request format.
///
/// SECURITY: UUIDs are ALWAYS generated server-side. Client-provided IDs are
/// logged for audit purposes but never used. This prevents:
/// - Replay attacks using pre-computed IDs
/// - Collision attacks on chain/link identifiers
/// - ID prediction for future grants
pub(crate) fn deserialize_trace_chain(
    chain: &SerializedTraceChain,
) -> Result<SpiffeTraceChain, ApiError> {
    use chrono::{TimeZone, Utc};

    if chain.links.is_empty() {
        return Err(ApiError::Escalation(
            "trace chain must have at least one link".to_string(),
        ));
    }

    let first_link = &chain.links[0];
    let first_permissions = preset_to_permissions(&first_link.preset);
    let mut trace_chain = SpiffeTraceChain::new_root(
        &first_link.spiffe_id,
        first_permissions,
        first_link.drand_round,
    );

    // SECURITY: Log client-provided ID for audit but NEVER use it
    // Server always generates fresh UUIDs to prevent replay/collision attacks
    // NOTE: Logged at WARN level to ensure visibility in production logs
    if !chain.id.is_empty() {
        tracing::warn!(
            client_provided_chain_id = %chain.id,
            server_chain_id = %trace_chain.id,
            security_event = "client_id_ignored",
            "client provided chain ID ignored - using server-generated ID (potential attack indicator)"
        );
    }

    // Add remaining links
    for link in chain.links.iter().skip(1) {
        let permissions = preset_to_permissions(&link.preset);
        let mut trace_link = SpiffeTraceLink::new(&link.spiffe_id, permissions, link.drand_round)
            .with_reason(&link.reason);

        if let Some(expires_at) = link.expires_at {
            if let Some(dt) = Utc.timestamp_opt(expires_at as i64, 0).single() {
                trace_link = trace_link.with_expiry(dt);
            }
        }

        // SECURITY: Log client-provided ID for audit but NEVER use it
        // NOTE: Logged at WARN level to ensure visibility in production logs
        if !link.id.is_empty() {
            tracing::warn!(
                client_provided_link_id = %link.id,
                server_link_id = %trace_link.id,
                security_event = "client_id_ignored",
                "client provided link ID ignored - using server-generated ID (potential attack indicator)"
            );
        }

        trace_chain.extend(trace_link);
    }

    Ok(trace_chain)
}

/// Convert an EscalationError to a user-friendly string.
pub(crate) fn escalation_error_to_string(e: &EscalationError) -> String {
    match e {
        EscalationError::RequestExpired => "escalation request has expired".to_string(),
        EscalationError::InvalidRequestorChain => "requestor's trace chain is invalid".to_string(),
        EscalationError::InvalidApproverChain => "approver's trace chain is invalid".to_string(),
        EscalationError::ExceedsCeiling { requested, ceiling } => {
            format!(
                "requested '{}' exceeds approver's ceiling '{}'",
                requested, ceiling
            )
        }
        EscalationError::ExceedsPolicyMax => {
            "requested permissions exceed policy maximum".to_string()
        }
        EscalationError::TtlExceedsPolicy { requested, max } => {
            format!(
                "requested TTL ({} seconds) exceeds policy maximum ({} seconds)",
                requested, max
            )
        }
        EscalationError::NoMatchingPolicy => "no matching escalation policy found".to_string(),
        EscalationError::PolicyMismatch { reason } => format!("policy mismatch: {}", reason),
        EscalationError::SelfEscalation => "self-escalation not allowed".to_string(),
        EscalationError::InvalidTtl => "invalid TTL: must be positive".to_string(),
        EscalationError::ChainVerificationFailed { reason } => {
            format!("chain verification failed: {}", reason)
        }
        EscalationError::AttestationRequired { chain_type, status } => {
            format!(
                "attestation required: {} chain has status '{}' but full attestation is mandatory",
                chain_type, status
            )
        }
    }
}

/// Convert a preset name to a PermissionLattice (local helper, mirrors policy.rs).
pub(crate) fn preset_to_permissions(preset: &str) -> PermissionLattice {
    match preset.to_lowercase().as_str() {
        "codegen" => PermissionLattice::codegen(),
        "pr_review" | "pr-review" => PermissionLattice::pr_review(),
        "pr_approve" | "pr-approve" => PermissionLattice::pr_approve(),
        "code_review" | "code-review" => PermissionLattice::code_review(),
        "web_research" | "web-research" | "research" => PermissionLattice::web_research(),
        "restrictive" => PermissionLattice::restrictive(),
        "permissive" => PermissionLattice::permissive(),
        "network_only" | "network-only" => PermissionLattice::network_only(),
        "read_only" | "read-only" => PermissionLattice::read_only(),
        "filesystem_readonly" | "filesystem-readonly" => PermissionLattice::filesystem_readonly(),
        "edit_only" | "edit-only" => PermissionLattice::edit_only(),
        "local_dev" | "local-dev" => PermissionLattice::local_dev(),
        "fix_issue" | "fix-issue" => PermissionLattice::fix_issue(),
        "release" => PermissionLattice::release(),
        "database_client" | "database-client" => PermissionLattice::database_client(),
        "demo" => PermissionLattice::demo(),
        _ => PermissionLattice::restrictive(),
    }
}

fn resolve_approval_expiry(
    expires_at_unix: Option<u64>,
    now: u64,
) -> Result<Option<u64>, ApiError> {
    let requested = expires_at_unix.unwrap_or(now + MAX_APPROVAL_TTL_SECS);
    if requested < now {
        return Err(ApiError::Spec("approval expiry is in the past".to_string()));
    }
    let max_allowed = now + MAX_APPROVAL_TTL_SECS;
    Ok(Some(requested.min(max_allowed)))
}

// Pod management handlers live in pod_mgmt.rs

async fn build_audit_log(args: &Args, auth: &AuthConfig) -> Result<Arc<AuditLog>, ApiError> {
    use nucleus_client::drand::{DrandClient, DrandConfig, DrandFailMode};

    let path = args.audit_log.clone();

    // Ensure parent directory exists (e.g., /var/log/nucleus/ or the pod state dir).
    // Without this, the first write silently fails when the parent is missing.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                ApiError::Spec(format!(
                    "failed to create audit log directory {}: {e}",
                    parent.display()
                ))
            })?;
        }
    }

    let secret = if let Some(secret) = args.audit_secret.as_ref() {
        secret.as_bytes().to_vec()
    } else {
        auth.secret().to_vec()
    };

    let last_hash = load_last_hash(&path).unwrap_or_default();

    // Set up webhook sink if configured
    let webhook = if let Some(url) = args.audit_webhook.as_ref() {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            // Never follow a redirect for audit records — a 3xx to another host
            // would leak the audit stream there.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| ApiError::Spec(format!("failed to build webhook client: {e}")))?;
        info!("audit webhook configured: {}", url);
        Some(WebhookSink {
            url: url.clone(),
            client,
        })
    } else {
        None
    };

    // Set up drand client for cryptographic time anchoring if drand is enabled
    let drand_client = if args.drand_enabled {
        let fail_mode = match args.drand_fail_mode.to_lowercase().as_str() {
            "cached" => DrandFailMode::Cached,
            _ => DrandFailMode::Strict,
        };
        let config = DrandConfig {
            enabled: true,
            api_url: args.drand_url.clone(),
            round_tolerance: args.drand_tolerance,
            cache_ttl: Duration::from_secs(25),
            fail_mode,
            chain_hash: None, // Use default
            public_key: None, // Use default
        };
        info!(
            "drand anchoring enabled for audit logs (url={}, tolerance={})",
            args.drand_url, args.drand_tolerance
        );
        // Exit with the reason rather than panicking. In a microVM this process
        // is PID 1: a panic here kills init and panics the kernel, so the
        // operator sees a reqwest error inside a kernel backtrace instead of the
        // one sentence that tells them what to do.
        //
        // Refusing to start (rather than degrading to `None`) is deliberate: the
        // operator asked for drand anchoring, and a pod that ran without it
        // while reporting success would be a claim outrunning its wiring. The
        // escalation path already refuses when drand is absent; this makes the
        // refusal legible at the moment it is decided.
        match DrandClient::new(config) {
            Ok(c) => Some(Arc::new(c)),
            Err(why) => {
                tracing::error!("{why}");
                eprintln!("FATAL: {why}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    // Set up S3 sink for deletion-resistant audit storage
    #[cfg(feature = "remote-audit")]
    let s3_sink = if let Some(bucket) = args.audit_s3_bucket.as_ref() {
        let region = args.audit_s3_region.as_deref().unwrap_or("us-east-1");
        let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new(region.to_string()));
        if let Some(endpoint) = args.audit_s3_endpoint.as_ref() {
            config_loader = config_loader.endpoint_url(endpoint);
        }
        let sdk_config = config_loader.load().await;
        let s3_client = aws_sdk_s3::Client::new(&sdk_config);
        let prefix = args
            .audit_s3_prefix
            .clone()
            .unwrap_or_else(|| "audit".to_string());
        info!(
            "S3 audit sink configured: bucket={}, prefix={}",
            bucket, prefix
        );
        Some(Arc::new(S3Sink {
            client: s3_client,
            bucket: bucket.clone(),
            prefix,
        }))
    } else {
        None
    };

    Ok(Arc::new(AuditLog {
        path,
        secret,
        last_hash: Mutex::new(last_hash),
        entry_count: std::sync::atomic::AtomicU64::new(0),
        webhook,
        drand_client,
        #[cfg(feature = "remote-audit")]
        s3_sink,
    }))
}

/// Parse and verify a lockdown signal file. Returns the desired lockdown state.
///
/// FAIL-CLOSED: on any verification failure (bad HMAC, malformed JSON, missing
/// fields), returns `current_state` to preserve the existing lockdown. Only a
/// verified, well-formed signal can change the state. This prevents an attacker
/// from unlocking the system by corrupting or forging the signal file.
fn parse_and_verify_lockdown_signal(content: &str, current_state: bool) -> bool {
    let envelope: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => {
            tracing::warn!("Lockdown signal file has invalid JSON — preserving current state");
            return current_state;
        }
    };

    let signal = match envelope.get("signal") {
        Some(s) => s,
        None => {
            tracing::warn!(
                "Lockdown signal file missing 'signal' field — preserving current state"
            );
            return current_state;
        }
    };

    let claimed_hmac = envelope.get("hmac").and_then(|h| h.as_str()).unwrap_or("");

    let body = serde_json::to_string_pretty(signal).unwrap_or_default();

    // HMAC key: hostname:username. This is a tamper-detection mechanism against
    // casual local attacks, not a cryptographic secret. For production fleet
    // lockdown, use the gRPC streaming path with proper HMAC auth.
    let key_material = format!(
        "nucleus-lockdown-{}:{}",
        whoami::hostname().unwrap_or_else(|_| "unknown".to_string()),
        whoami::username().unwrap_or_else(|_| "unknown".to_string()),
    );

    use hmac::{digest::KeyInit, Hmac, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key_material.as_bytes()).expect("hmac");
    mac.update(body.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    if expected != claimed_hmac {
        tracing::warn!(
            "Lockdown signal HMAC mismatch — preserving current state (possible tampering)"
        );
        return current_state; // fail-closed: preserve current state
    }

    // Verified signal — extract desired state
    signal
        .get("restore")
        .and_then(|r| r.as_bool())
        .map(|restore| !restore)
        .unwrap_or(true) // signal without "restore" field = lockdown active
}

async fn emit_boot_report(state: &AppState) -> Result<(), ApiError> {
    // Always emit boot report — this is the first entry in the audit chain.
    // Optional env var adds a custom message; otherwise use a default.
    let message = std::env::var("NUCLEUS_TOOL_PROXY_BOOT_REPORT")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "tool-proxy started".to_string());
    let actor = std::env::var("NUCLEUS_TOOL_PROXY_BOOT_ACTOR").ok();
    let report = format!(
        "{} [sandbox_proof={}]",
        message,
        state.sandbox_proof.tier_label()
    );

    state
        .audit
        .log(AuditEntry {
            timestamp_unix: now_unix(),
            actor,
            event: "boot".to_string(),
            subject: report,
            result: "ok".to_string(),
            prev_hash: String::new(),
            hash: String::new(),
            signature: String::new(),
            drand_round: None, // Will be filled by AuditLog::log
            spiffe_id: None,
            policy_rule: None,
        })
        .await?;

    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct AuditEntry {
    timestamp_unix: u64,
    actor: Option<String>,
    event: String,
    subject: String,
    result: String,
    prev_hash: String,
    hash: String,
    signature: String,
    /// Drand round number for cryptographic time anchoring.
    #[serde(skip_serializing_if = "Option::is_none")]
    drand_round: Option<u64>,
    /// SPIFFE identity of the authenticated requester.
    #[serde(skip_serializing_if = "Option::is_none")]
    spiffe_id: Option<String>,
    /// Policy rule that authorized this operation (if zero-prompt).
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_rule: Option<String>,
}

struct AuditLog {
    path: PathBuf,
    secret: Vec<u8>,
    last_hash: Mutex<String>,
    entry_count: std::sync::atomic::AtomicU64,
    webhook: Option<WebhookSink>,
    /// Optional drand client for cryptographic time anchoring.
    drand_client: Option<Arc<nucleus_client::drand::DrandClient>>,
    /// Optional S3-compatible sink for deletion-resistant audit storage.
    #[cfg(feature = "remote-audit")]
    s3_sink: Option<Arc<S3Sink>>,
}

struct WebhookSink {
    url: String,
    client: reqwest::Client,
}

/// S3-compatible append-only audit sink.
///
/// Each audit entry is stored as a separate S3 object. The `if_none_match("*")`
/// precondition prevents overwriting existing entries. Combined with a bucket
/// policy that denies `s3:DeleteObject`, this provides a deletion-resistant
/// audit trail that a compromised pod cannot erase.
#[cfg(feature = "remote-audit")]
struct S3Sink {
    client: aws_sdk_s3::Client,
    bucket: String,
    prefix: String,
}

#[cfg(feature = "remote-audit")]
impl S3Sink {
    /// Put a single audit line as an S3 object.
    ///
    /// Key format: `{prefix}/{timestamp_unix}-{hash_prefix}.jsonl`
    /// Uses `if_none_match("*")` for append-only semantics: S3 returns 412
    /// if an object with this key already exists.
    async fn put_entry(&self, timestamp_unix: u64, hash: &str, line: &str) {
        let hash_prefix = if hash.len() >= 8 { &hash[..8] } else { hash };
        let key = format!("{}/{}-{}.jsonl", self.prefix, timestamp_unix, hash_prefix);

        let result = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .body(line.as_bytes().to_vec().into())
            .content_type("application/jsonl")
            .if_none_match("*")
            .send() // net-infra: audit S3 append (aws_sdk_s3, operator sink — not agent egress)
            .await;

        if let Err(e) = result {
            tracing::warn!("failed to write audit entry to S3 (key={key}): {e}");
        }
    }
}

impl AuditLog {
    async fn log(&self, mut entry: AuditEntry) -> Result<(), ApiError> {
        // Fetch drand round for cryptographic time anchoring
        if let Some(ref drand) = self.drand_client {
            match drand.current_round().await {
                Ok(round) => {
                    entry.drand_round = Some(round);
                }
                Err(e) => {
                    tracing::warn!("failed to fetch drand round for audit: {e}");
                    // Continue without drand anchoring - don't block audit logging
                }
            }
        }

        let actor = entry.actor.clone().unwrap_or_default();
        let (prev_hash, hash, signature) = {
            let mut last_hash = self.last_hash.lock().unwrap();
            let prev_hash = last_hash.clone();
            // Include drand_round in message if available for stronger binding
            let drand_part = entry
                .drand_round
                .map(|r| format!("|drand:{}", r))
                .unwrap_or_default();
            let message = format!(
                "{}|{}|{}|{}|{}|{}{}",
                entry.timestamp_unix,
                actor,
                entry.event,
                entry.subject,
                entry.result,
                prev_hash,
                drand_part
            );
            let signature = auth::sign_message(&self.secret, message.as_bytes());
            let hash = art12::sha256_hex(&format!("{}|{}", message, signature));
            *last_hash = hash.clone();
            (prev_hash, hash, signature)
        };
        entry.prev_hash = prev_hash;
        entry.signature = signature.clone();
        entry.hash = hash;
        self.entry_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let line = serde_json::to_string(&entry).map_err(|e| ApiError::Spec(e.to_string()))?;

        // Write to local file
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;
        file.write_all(line.as_bytes()).await?;
        file.write_all(b"\n").await?;

        // Send to webhook if configured
        if let Some(webhook) = &self.webhook {
            // Fire and forget - don't block on webhook delivery
            // In production, you'd want retry logic and a buffer
            let url = webhook.url.clone();
            let client = webhook.client.clone();
            let body = line.clone();
            let sig = signature;

            tokio::spawn(async move {
                let result = client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .header("X-Nucleus-Signature", &sig)
                    .body(body)
                    .send() // net-infra: audit webhook (operator-configured URL — not agent egress)
                    .await;

                if let Err(e) = result {
                    tracing::warn!("failed to send audit entry to webhook: {e}");
                }
            });
        }

        // Send to S3 if configured (fire-and-forget, like webhook)
        #[cfg(feature = "remote-audit")]
        if let Some(s3) = &self.s3_sink {
            let s3 = Arc::clone(s3);
            let body = line.clone();
            let ts = entry.timestamp_unix;
            let h = entry.hash.clone();
            tokio::spawn(async move {
                s3.put_entry(ts, &h, &body).await;
            });
        }

        Ok(())
    }

    /// Get the current tail hash and entry count for the exit report.
    fn tail_hash_and_count(&self) -> (String, u64) {
        let hash = self.last_hash.lock().unwrap().clone();
        let count = self.entry_count.load(std::sync::atomic::Ordering::Relaxed);
        (hash, count)
    }
}

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn load_last_hash(path: &Path) -> Option<String> {
    let file = std::fs::File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    if metadata.len() == 0 {
        return None;
    }
    let read_len = metadata.len().min(8192) as usize;
    let mut file = file;
    let start = metadata.len().saturating_sub(read_len as u64);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return None;
    }
    let mut buf = vec![0u8; read_len];
    if file.read_exact(&mut buf).is_err() {
        return None;
    }
    let text = String::from_utf8_lossy(&buf);
    let line = text.lines().rev().find(|line| !line.trim().is_empty())?;
    let entry: AuditEntry = serde_json::from_str(line).ok()?;
    if entry.hash.is_empty() {
        return None;
    }
    Some(entry.hash)
}

#[cfg(test)]
mod read_body_capped_tests {
    //! Regression guard for audit H-1: the tool-proxy must not buffer an entire
    //! attacker-controlled upstream body. `read_body_capped` must stop at the cap
    //! regardless of upstream size. Fails if reverted to whole-body buffering.
    use crate::web_fetch_policy::read_body_capped;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn stops_at_cap_on_oversize_body() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cap = 64 * 1024;
        let server = MockServer::start().await;
        // Upstream body two orders of magnitude larger than the cap.
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'a'; 4 * 1024 * 1024]))
            .mount(&server)
            .await;
        let resp = reqwest::Client::new()
            .get(server.uri())
            .send()
            .await
            .expect("send");
        let (body, truncated) = read_body_capped(resp, cap).await.expect("read");
        assert_eq!(
            body.len(),
            cap,
            "must retain at most the cap, not the 4 MiB body"
        );
        assert!(
            truncated,
            "an oversize upstream body must be flagged truncated"
        );
    }

    #[tokio::test]
    async fn returns_full_small_body_untruncated() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(b"hello".to_vec()))
            .mount(&server)
            .await;
        let resp = reqwest::Client::new()
            .get(server.uri())
            .send()
            .await
            .expect("send");
        let (body, truncated) = read_body_capped(resp, 64 * 1024).await.expect("read");
        assert_eq!(body, b"hello");
        assert!(!truncated);
    }
}

#[cfg(test)]
mod panic_net_tests {
    //! Audit H-3 — router panic net. A stray panic anywhere under the proxy
    //! router (e.g. a poisoned enforcement lock's `.expect()`) must become a
    //! fail-closed HTTP 500, never a connection reset or an allow, and the router
    //! must keep serving afterwards. Exercises the real `fail_closed_panic_response`
    //! handler behind the same OUTERMOST `CatchPanicLayer` wiring as the server.
    use super::fail_closed_panic_response;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;
    use tower_http::catch_panic::CatchPanicLayer;

    async fn panicking_handler() -> &'static str {
        panic!("boom in handler (H-3 test)")
    }

    fn panic_net_router() -> Router {
        Router::new()
            .route("/panic", get(panicking_handler))
            .route("/ok", get(|| async { "ok" }))
            // Same OUTERMOST wiring as the production server.
            .layer(CatchPanicLayer::custom(fail_closed_panic_response))
    }

    #[tokio::test]
    async fn panicking_handler_returns_fail_closed_500_and_keeps_serving() {
        let app = panic_net_router();

        // 1. A panicking handler ⇒ fail-closed 500 (not a reset, not an allow).
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/panic")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router must return a response, not drop the connection");
        assert_eq!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "a panicking handler must fail closed with HTTP 500"
        );

        // 2. The router still serves a subsequent normal request.
        let resp2 = app
            .oneshot(Request::builder().uri("/ok").body(Body::empty()).unwrap())
            .await
            .expect("router must keep serving after a caught panic");
        assert_eq!(resp2.status(), StatusCode::OK);
    }
}

#[cfg(test)]
#[path = "tests_main.rs"]
mod tests;
