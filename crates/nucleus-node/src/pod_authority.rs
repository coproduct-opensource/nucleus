//! Per-pod certificate authority: the node is the sole issuer of pod
//! certificates (#2424, #2425, #2426).
//!
//! # What this closes
//!
//! `POST /v1/pods` used to mint a fresh-root session credential from whatever
//! policy the caller wrote in the spec. Nothing compared that request against
//! anything the caller itself held: a pod holding `manage_pods` could ask for
//! a child with every capability at `Always`, and — because the one narrowing
//! step lived behind an optional operator label the Firecracker driver never
//! even forwarded — got it. Budget was not conserved either: each child was
//! constructed with a fresh `AtomicBudget`, so a fan-out of N children
//! received N× the parent's budget.
//!
//! # The model
//!
//! Every pod holds a [`LatticeCertificate`] chain rooted at this node's
//! persistent root key. The node keeps `(certificate, holder key)` per pod —
//! only the PUBLIC certificate (plus the root public key) is delivered to the
//! guest, same stance as `session_mint`: no signing key enters a pod. A pod's
//! effective policy IS its certificate's effective permissions; the requested
//! spec policy is meet-clamped against the parent's authority and never
//! trusted on its own.
//!
//! [`PodAuthority::admit`] resolves who is asking and derives the child's
//! chain accordingly:
//!
//! 1. **A registered pod** (proved by the per-pod caller token or its own
//!    `ns/pods/sa/<uuid>` SVID): the child's certificate is one hop below the
//!    parent's, minted with the parent's held holder key. Chain depth grows by
//!    one per generation, so `DEFAULT_MAX_CHAIN_DEPTH` bounds recursion for free.
//! 2. **An external caller** (mTLS SPIFFE identity that is not a pod)
//!    presenting `x-nucleus-delegation-cert`: the chain is verified against
//!    the node's trust anchors, its leaf must BE the authenticated identity,
//!    and the node *re-roots* — mints a fresh authority block carrying the
//!    caller's effective permissions and the caller chain's fingerprint as
//!    `provenance` (RFC 8693 `act` semantics) — then delegates one hop to the
//!    pod.
//! 3. **The single bootstrap identity** (`--root-minter-spiffe-id`, default
//!    `spiffe://<td>/ns/system/sa/cli`): may create from a bare inline/profile
//!    policy with no certificate. Someone has to be first. This replaces the
//!    previous "unidentified caller ⇒ allowed".
//! 4. Anything else is refused.
//!
//! # Budget conservation
//!
//! Stateless credentials cannot conserve a counter, so conservation lives
//! here, at the one enforcement point that creates pods: a
//! [`BudgetLedger`] per parent (per external caller chain, for case 2)
//! enforces `Σ live child allocations + consumed ≤ parent max`. A child's
//! allocation is its certificate's `max_cost_usd`; it is released when the
//! reaper sees the child exit. Until a child can report what it actually
//! spent, release folds the WHOLE allocation into the parent's consumption —
//! conservative, documented, and the reason the invariant cannot be violated
//! by a parent that spawns and reaps in a loop.
//!
//! # Credentialed upstreams are admitted here too
//!
//! `credentialed_egress` is not a policy field, so the certificate meet above
//! does not narrow it — and it is the more direct exfiltration primitive of the
//! two, since each entry names a node environment variable and a URL to send it
//! to. Admission clamps it in the same match, by the same case:
//!
//! 1. a pod caller: to what the PARENT was admitted (kept per pod, persisted
//!    with its certificate) AND still in the operator registry, so delegation
//!    can narrow and never invent;
//! 2. an external caller: to the operator registry (`--upstreams`);
//! 3. the root minter: to the operator registry.
//!
//! With no registry configured every requested entry is dropped, for every
//! case. See `upstreams.rs` for why that is fail-closed rather than "trust the
//! root minter".
//!
//! # Persistence
//!
//! `pods/<id>/authority.json` holds the certificate and the holder key
//! (0o400), following the derive-from-`pods/` convention `identity.rs` uses
//! for the VM registry: a restart rebuilds the registry from the directory
//! that already is the record of which pods exist.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use nucleus_spec::{CredentialedEgressSpec, PodSpec};
use portcullis::certificate::{
    DEFAULT_MAX_CHAIN_DEPTH, LatticeCertificate, SinkScope, verify_certificate,
};
use portcullis::token::AttenuationToken;
use portcullis::{BudgetError, BudgetLedger, PermissionLattice};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::federated_credential::{FederatedSource, FederationSubject};
use crate::upstreams::UpstreamRegistry;
use crate::{ApiError, NodeState, keys};

/// Header an external caller presents its own chain in (an
/// [`AttenuationToken`], base64). Same spelling the tool-proxy uses.
pub(crate) const HEADER_DELEGATION_CERT: &str = "x-nucleus-delegation-cert";

/// Env the guest tool-proxy reads its certificate from (base64 [`AttenuationToken`]).
pub(crate) const ENV_POD_CERT: &str = "NUCLEUS_POD_CERT";
/// Env carrying the pinned trust anchor (hex Ed25519 public key). The
/// tool-proxy already reads this name; the token's own embedded key is NOT
/// the trust decision.
pub(crate) const ENV_CERT_ROOT_PUBKEY: &str = "NUCLEUS_CERT_ROOT_PUBKEY";

const AUTHORITY_FILE: &str = "authority.json";

/// Operator knobs, flattened into the node's `Args`.
#[derive(clap::Args, Debug, Clone)]
pub(crate) struct AuthorityArgs {
    /// SPIFFE ID of the ONE identity allowed to create a pod from a bare
    /// (inline / profile) policy with no certificate — the bootstrap case.
    /// Defaults to `spiffe://<trust-domain>/ns/system/sa/cli`, the identity
    /// `nucleus setup` provisions for the operator CLI.
    #[arg(long, env = "NUCLEUS_ROOT_MINTER_SPIFFE_ID")]
    pub root_minter_spiffe_id: Option<String>,
    /// Additional trust anchors (hex Ed25519 public keys) an external
    /// caller's certificate chain may be rooted at. The node's own root key
    /// is always an anchor.
    #[arg(long, env = "NUCLEUS_CERT_TRUST_ANCHORS", value_delimiter = ',')]
    pub cert_trust_anchors: Vec<String>,
    /// Maximum live children per parent pod (fan-out cap).
    #[arg(long, env = "NUCLEUS_MAX_CHILDREN_PER_POD", default_value_t = 8)]
    pub max_children_per_pod: usize,
    /// TOML registry of the credentialed upstreams this node offers
    /// (`[[upstream]]` entries; see `upstreams.rs`). A pod may hold an upstream
    /// only when its spec's entry equals one of these field for field. Unset,
    /// no pod is admitted any credentialed upstream.
    #[arg(long = "upstreams", env = "NUCLEUS_NODE_UPSTREAMS")]
    pub upstreams: Option<PathBuf>,
    /// The `iss` this node signs federated-credential assertions under (an
    /// https URL whose discovery document and JWKS upstreams register; ADR
    /// 0010). Required when the `--upstreams` registry has a `federated` entry:
    /// the node refuses to start without it rather than refuse every call.
    #[arg(long = "federation-issuer", env = "NUCLEUS_FEDERATION_ISSUER")]
    pub federation_issuer: Option<String>,
}

/// Who is asking for a pod, as established by the node — never by the spec.
#[derive(Debug, Clone)]
pub(crate) struct Admission {
    /// The authenticated SPIFFE identity of the caller (mTLS).
    pub caller_spiffe_id: String,
    /// The calling POD, when proved (caller token, or a pod SVID).
    pub caller_pod: Option<Uuid>,
    /// `x-nucleus-delegation-cert`, if presented.
    pub header_cert: Option<String>,
}

/// What the node delivers to a pod at boot: its certificate and the anchor.
#[derive(Debug, Clone)]
pub(crate) struct BootCertificate {
    /// Base64 [`AttenuationToken`].
    pub token_b64: String,
    /// Hex of the node's root public key.
    pub root_pubkey_hex: String,
}

impl Admission {
    /// From an HTTP request: the per-pod caller token (if it proved a pod),
    /// else the mTLS peer's own pod SVID; plus the delegation-cert header.
    pub fn from_http(
        policy: &crate::auth::AuthorizationPolicy,
        caller_token_pod: Option<Uuid>,
        auth_ctx: &crate::auth::AuthContext,
        headers: &axum::http::HeaderMap,
    ) -> Self {
        Self {
            caller_pod: caller_token_pod.or_else(|| policy.pod_id_from_spiffe(&auth_ctx.spiffe_id)),
            header_cert: headers
                .get(HEADER_DELEGATION_CERT)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
            caller_spiffe_id: auth_ctx.spiffe_id.clone(),
        }
    }

    /// From a gRPC request: the interceptor-verified SPIFFE peer (a pod's
    /// own SVID identifies it as a pod) plus the delegation-cert metadata.
    pub fn from_grpc<T>(
        policy: &crate::auth::AuthorizationPolicy,
        auth_ctx: &crate::auth::AuthContext,
        request: &tonic::Request<T>,
    ) -> Self {
        Self {
            caller_pod: policy.pod_id_from_spiffe(&auth_ctx.spiffe_id),
            header_cert: request
                .metadata()
                .get(HEADER_DELEGATION_CERT)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string),
            caller_spiffe_id: auth_ctx.spiffe_id.clone(),
        }
    }
}

/// The outcome of admission: the pod's certificate and its effective policy.
#[derive(Debug)]
pub(crate) struct IssuedAuthority {
    /// The pod's effective permissions — what it will actually run under.
    pub effective: PermissionLattice,
    /// Chain depth of the issued certificate.
    pub chain_depth: usize,
    /// The credentialed upstreams this pod was admitted: the requested entries
    /// that survived the per-case clamp in [`PodAuthority::admit`].
    pub upstreams: Vec<CredentialedEgressSpec>,
}

impl IssuedAuthority {
    /// Replace what the spec REQUESTED with what was ISSUED: the policy with the
    /// certificate's effective lattice, and `credentialed_egress` with the
    /// admitted upstreams.
    ///
    /// One method for both because they are the same act. The policy
    /// replacement had been in `create_pod_internal` since #2424 while the
    /// egress list went through untouched; a single call that does both is what
    /// stops the next spec field of this kind from being replaced in one place
    /// and forgotten in the other.
    pub fn apply_to(self, spec: &mut PodSpec) {
        spec.spec.policy = nucleus_spec::PolicySpec::Inline {
            lattice: Box::new(self.effective),
        };
        spec.spec.credentialed_egress = self.upstreams;
    }
}

struct PodCert {
    cert: LatticeCertificate,
    holder: Ed25519KeyPair,
    holder_pkcs8: Vec<u8>,
    ledger: BudgetLedger,
    parent: Parent,
    /// What this pod was admitted — the ceiling for its own children.
    upstreams: Vec<CredentialedEgressSpec>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Parent {
    /// Minted by the bootstrap identity: no budget parent.
    Root,
    /// One hop below a registered pod.
    Pod(Uuid),
    /// Re-rooted from an external caller's chain, identified by fingerprint.
    External([u8; 32]),
}

#[derive(Serialize, Deserialize)]
struct PersistedAuthority {
    version: u8,
    certificate: LatticeCertificate,
    holder_pkcs8_b64: String,
    parent: Parent,
    /// Absent from files written before upstreams were admitted here, and
    /// defaulting to EMPTY: a pod restored from one confers nothing on its
    /// children, which is the fail-closed reading of "not recorded".
    #[serde(default)]
    upstreams: Vec<CredentialedEgressSpec>,
}

struct Inner {
    pods: HashMap<Uuid, PodCert>,
    /// Ledgers for external callers' chains, keyed by chain fingerprint.
    external: HashMap<[u8; 32], BudgetLedger>,
}

/// Domain separator for pod-receipt signatures.
///
/// Versioned: a change to how the preimage is built is a new signature space,
/// not a silent reinterpretation of the old one.
const RECEIPT_DOMAIN: &[u8] = b"nucleus/pod-receipt/v1\0";

/// Verify a pod-receipt signature against a node's advertised root public key.
///
/// Free function, not a method: a relying party has the public key and the
/// bytes, and must not need a `PodAuthority` — which owns the PRIVATE key — to
/// check a receipt. If verification required the signer, only the signer could
/// verify, which is not a property anyone should accept from an attestation.
// No production caller YET: the node signs, and the thing that verifies is a
// relying party outside it. Stated rather than hidden — the same note
// `snapshot_vmm::load` carries. A verifier nothing calls is still the half of
// the pair that makes the signature checkable, and shipping the signer without
// it would be a signature no one can test against.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn verify_pod_receipt(pubkey_hex: &str, preimage: &[u8], signature_hex: &str) -> bool {
    let (Ok(pubkey), Ok(sig)) = (hex::decode(pubkey_hex), hex::decode(signature_hex)) else {
        return false;
    };
    let mut msg = Vec::with_capacity(RECEIPT_DOMAIN.len() + preimage.len());
    msg.extend_from_slice(RECEIPT_DOMAIN);
    msg.extend_from_slice(preimage);

    // `verify_strict`, NOT `ring::signature::ED25519`.
    //
    // ring's is COFACTORED verification, which accepts signatures that strict
    // verification rejects — small-order and non-canonical points, so one
    // signature can verify under more than one key. The M-3 gate
    // (`scripts/check-verify-strict.sh`) forbids it on a production path, and
    // caught this line. For a receipt the property is not academic: a verdict
    // that verifies under two keys is a verdict attributable to two nodes.
    let Ok(vk_bytes) = <[u8; 32]>::try_from(pubkey.as_slice()) else {
        return false;
    };
    let (Ok(vk), Ok(sig)) = (
        ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes),
        ed25519_dalek::Signature::from_slice(&sig),
    ) else {
        return false;
    };
    vk.verify_strict(&msg, &sig).is_ok()
}

/// The node's certificate authority for pods. See the module docs.
pub(crate) struct PodAuthority {
    trust_domain: String,
    root_minter: String,
    root_key: Ed25519KeyPair,
    root_pubkey: Vec<u8>,
    anchors: Vec<Vec<u8>>,
    max_children: usize,
    state_dir: PathBuf,
    /// The operator's upstream registry; `None` when `--upstreams` is unset.
    registry: Option<std::sync::Arc<UpstreamRegistry>>,
    /// The node's federation issuer; `None` when `--federation-issuer` is unset,
    /// which is refused at start-up if the registry has a federated entry.
    federation: Option<std::sync::Arc<FederatedSource>>,
    inner: tokio::sync::Mutex<Inner>,
}

impl PodAuthority {
    /// Build the authority for this node. The root signing key is persisted
    /// under `state_dir` like the node's other role keys (`trust_gate`).
    ///
    /// # Errors
    /// The `--upstreams` registry is set and does not load. The node refuses to
    /// start rather than run with a ceiling other than the one written. Also a
    /// registry with a `federated` entry and no usable `--federation-issuer`.
    pub fn new(args: &AuthorityArgs, trust_domain: &str, state_dir: &Path) -> Result<Self, String> {
        let dalek = keys::load_or_create_cert_root_signing_key(state_dir);
        // ring's keypair cannot be built from PKCS#8 v2 DER reliably across
        // encoders; seed + public key is the unambiguous form.
        let root_key = Ed25519KeyPair::from_seed_and_public_key(
            &dalek.to_bytes(),
            &dalek.verifying_key().to_bytes(),
        )
        .expect("a freshly generated or persisted Ed25519 seed is a valid seed");
        let root_pubkey = root_key.public_key().as_ref().to_vec();

        let mut anchors = vec![root_pubkey.clone()];
        for hex_key in &args.cert_trust_anchors {
            match hex::decode(hex_key.trim()) {
                Ok(k) if k.len() == 32 => anchors.push(k),
                _ => tracing::warn!(
                    anchor = %hex_key,
                    "ignoring malformed --cert-trust-anchors entry (want 32-byte hex)"
                ),
            }
        }

        let root_minter = args
            .root_minter_spiffe_id
            .clone()
            .unwrap_or_else(|| format!("spiffe://{trust_domain}/ns/system/sa/cli"));

        let registry = match &args.upstreams {
            Some(path) => {
                let reg = UpstreamRegistry::load(path)?;
                tracing::info!(
                    upstreams = reg.entries().len(),
                    path = %path.display(),
                    "loaded the operator upstream registry"
                );
                Some(std::sync::Arc::new(reg))
            }
            None => {
                tracing::info!(
                    "no --upstreams registry: every pod's credentialed_egress is dropped at admission"
                );
                None
            }
        };

        let federation = federation_source(
            args.federation_issuer.as_deref(),
            registry.as_deref(),
            state_dir,
        )?;

        Ok(Self {
            trust_domain: trust_domain.to_string(),
            root_minter,
            root_key,
            root_pubkey,
            anchors,
            max_children: args.max_children_per_pod,
            state_dir: state_dir.to_path_buf(),
            registry,
            federation,
            inner: tokio::sync::Mutex::new(Inner {
                pods: HashMap::new(),
                external: HashMap::new(),
            }),
        })
    }

    /// [`Self::new`] from the node's parsed CLI.
    ///
    /// # Errors
    /// As [`Self::new`].
    pub fn from_args(args: &crate::Args) -> Result<Self, String> {
        Self::new(
            &args.authority,
            &args.identity_trust_domain,
            &args.state_dir,
        )
    }

    /// The operator's upstream registry, for the broker to take its entries
    /// from. `None` when `--upstreams` is unset.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn upstream_registry(&self) -> Option<&UpstreamRegistry> {
        self.registry.as_deref()
    }

    /// The node's federation issuer, for the broker to mint with. `None` when
    /// `--federation-issuer` is unset.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub fn federation_source(&self) -> Option<&std::sync::Arc<FederatedSource>> {
        self.federation.as_ref()
    }

    /// Who a federated assertion for `pod_id` is minted in the name of, read
    /// from the certificate this node issued it.
    ///
    /// * `sub` — `observed`, the identity the pod's broker listener is bound to.
    ///   It must equal the certificate's leaf identity: two host-side records
    ///   of who this pod is that disagree mean one of them is wrong, and an
    ///   assertion is not the place to find out which. `None` (with a warning)
    ///   rather than a guess.
    /// * `nucleus_root` — the identity at the root of the chain: the root
    ///   minter, or the external caller a chain was re-rooted from.
    /// * `nucleus_tenant` — that root identity's trust domain (ADR 0001).
    /// * `nucleus_chain` — the certificate's fingerprint, hex.
    /// * the certificate's `not_after`, past which nothing is minted for it.
    ///
    /// `None` for a pod this node issued no certificate.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub async fn federation_subject(
        &self,
        pod_id: Uuid,
        observed: &nucleus_cred_broker::PodIdentity,
    ) -> Option<FederationSubject> {
        let inner = self.inner.lock().await;
        let cert = &inner.pods.get(&pod_id)?.cert;
        if cert.leaf_identity() != observed.as_str() {
            tracing::warn!(
                pod = %pod_id,
                "the broker's identity for this pod is not its certificate's leaf; no federated                  credential will be minted for it"
            );
            return None;
        }
        let root = cert.root_identity();
        let tenant = root
            .strip_prefix("spiffe://")
            .and_then(|rest| rest.split('/').next())
            .filter(|td| !td.is_empty())?;
        let subject = nucleus_federation::AssertionSubject::new(
            observed.as_str(),
            tenant,
            root,
            hex::encode(cert.fingerprint()),
        )
        .ok()?;
        let not_after = u64::try_from(cert_not_after(cert).timestamp()).unwrap_or(0);
        Some(FederationSubject::new(subject, not_after))
    }

    /// Clamp a requested `credentialed_egress` list to the registry, and — for a
    /// pod caller — to what the parent was admitted as well.
    ///
    /// Both ceilings for a pod caller, not just the parent's: the parent's set
    /// was a subset of the registry when it was admitted, but it may have been
    /// restored from disk onto a node started with a narrower file, and the
    /// operator's current file is the one that should win. No registry is an
    /// empty ceiling.
    fn admit_upstreams(
        &self,
        requested: &[CredentialedEgressSpec],
        parent: Option<&[CredentialedEgressSpec]>,
        child_id: Uuid,
    ) -> Vec<CredentialedEgressSpec> {
        let registry = self
            .registry
            .as_deref()
            .map_or(&[][..], UpstreamRegistry::entries);
        let (mut kept, mut dropped) = CredentialedEgressSpec::clamp(requested.to_vec(), registry);
        if let Some(parent) = parent {
            let (narrowed, beyond_parent) = CredentialedEgressSpec::clamp(kept, parent);
            kept = narrowed;
            dropped.extend(beyond_parent);
        }
        for up in &dropped {
            // By NAME, never by the variable's value — and not by the variable's
            // name either, which is the caller's text and may be a probe.
            tracing::warn!(
                pod = %child_id,
                upstream = %up.name,
                "requested credentialed upstream is not granted (not in the operator registry, \
                 differs from its entry, or not held by the calling pod); dropped at admission"
            );
        }
        kept
    }

    /// The one identity allowed to mint from a bare policy.
    pub fn root_minter(&self) -> &str {
        &self.root_minter
    }

    /// The node-assigned SPIFFE ID of a pod: `spiffe://<td>/ns/pods/sa/<uuid>`.
    ///
    /// Node-assigned, not read from `spec.metadata` — a sub-pod spec is
    /// agent-authored, and letting it pick its own namespace/name let it name
    /// itself into the orchestrator prefix `AuthorizationPolicy` grants full
    /// access to. `AuthorizationPolicy::pod_prefixes` recognises this shape.
    pub fn pod_spiffe_id(&self, pod_id: Uuid) -> String {
        format!("spiffe://{}/ns/pods/sa/{pod_id}", self.trust_domain)
    }

    /// The hex root public key delivered to pods as the pinned anchor.
    /// Sign a pod receipt's preimage with the node's root key.
    ///
    /// # Why this is not `sign(&[u8])`
    ///
    /// The root key also mints `LatticeCertificate`s. A general signing
    /// accessor would be an oracle: anything holding a `&PodAuthority` could
    /// have the node sign bytes of its choosing, and a receipt preimage that
    /// happened to parse as a certificate body would yield a signature valid as
    /// BOTH. The domain tag makes the two languages disjoint, and keeping the
    /// tagging inside this method means no caller can forget it.
    ///
    /// # Why the HOST signs a pod receipt at all
    ///
    /// `MediationReceipt` mints a per-pod key and serves it INTO the guest, which
    /// is right for attesting decisions the in-guest mediator made. It is wrong
    /// for a receipt about what a pod produced: a workload holding the key can
    /// sign any verdict it likes. SLSA Build L3's defining property is that
    /// signing keys are isolated from user-controlled build steps, and this key
    /// never leaves the host — only public halves enter a guest.
    ///
    /// What the signature establishes is therefore narrow and worth stating: the
    /// node, holding this key, observed these bytes. It says nothing about
    /// whether the workload told the truth in them.
    pub fn sign_pod_receipt(&self, preimage: &[u8]) -> String {
        let mut msg = Vec::with_capacity(RECEIPT_DOMAIN.len() + preimage.len());
        msg.extend_from_slice(RECEIPT_DOMAIN);
        msg.extend_from_slice(preimage);
        hex::encode(self.root_key.sign(&msg).as_ref())
    }

    pub fn root_pubkey_hex(&self) -> String {
        hex::encode(&self.root_pubkey)
    }

    /// Admit a pod-creation request: prove the caller's authority, derive the
    /// child's certificate from it, reserve the child's budget against it.
    ///
    /// On `Ok`, the child is registered and its certificate persisted; the
    /// caller MUST call [`Self::release_child`] if the pod then fails to
    /// spawn, or the allocation leaks until the reaper would have run.
    pub async fn admit(
        &self,
        admission: &Admission,
        spec: &PodSpec,
        child_id: Uuid,
    ) -> Result<IssuedAuthority, ApiError> {
        let requested = spec
            .spec
            .resolve_policy()
            .map_err(|e| ApiError::InvalidSpec(format!("policy: {e}")))?;
        let child_identity = self.pod_spiffe_id(child_id);
        let ttl = Duration::seconds(i64::try_from(spec.spec.timeout_seconds).unwrap_or(i64::MAX));
        let now = Utc::now();
        let reason = format!("pod {child_id} created by {}", admission.caller_spiffe_id);

        let child_pkcs8 = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .map_err(|_| ApiError::Authority("holder key generation failed".into()))?;
        let child_key = Ed25519KeyPair::from_pkcs8(child_pkcs8.as_ref())
            .map_err(|_| ApiError::Authority("holder key parse failed".into()))?;

        let mut inner = self.inner.lock().await;

        let (cert, parent, parent_upstreams) = if let Some(parent_id) = admission.caller_pod {
            // ── Case 1: one hop below a registered pod ──────────────────
            let parent = inner.pods.get_mut(&parent_id).ok_or_else(|| {
                ApiError::Authority(format!(
                    "calling pod {parent_id} holds no certificate on this node"
                ))
            })?;
            if parent.ledger.live_children() >= self.max_children {
                return Err(ApiError::Authority(format!(
                    "pod {parent_id} already has {} live children (cap {})",
                    parent.ledger.live_children(),
                    self.max_children
                )));
            }
            parent
                .ledger
                .try_allocate(child_id.as_u128(), requested.budget.max_cost_usd)
                .map_err(ledger_denial)?;
            let not_after = (now + ttl).min(cert_not_after(&parent.cert));
            let cert = parent
                .cert
                .mint_child_with_scope_using_key(
                    &requested,
                    child_identity.clone(),
                    not_after,
                    &reason,
                    SinkScope::unrestricted(),
                    &parent.holder,
                    &child_key,
                )
                .map_err(|e| {
                    // Undo the reservation: nothing was issued.
                    let _ = parent
                        .ledger
                        .release(child_id.as_u128(), rust_decimal::Decimal::ZERO);
                    ApiError::Authority(format!("delegation refused: {e}"))
                })?;
            let ceiling = parent.upstreams.clone();
            (cert, Parent::Pod(parent_id), Some(ceiling))
        } else if let Some(header) = admission.header_cert.as_deref() {
            // ── Case 2: external caller proving its own chain ───────────
            let token = AttenuationToken::from_base64(header.trim())
                .map_err(|e| ApiError::Authority(format!("malformed delegation cert: {e}")))?;
            // The trust decision is against OUR anchors, never the token's
            // own embedded root key (which is self-asserted).
            let verified = self
                .anchors
                .iter()
                .find_map(|anchor| {
                    verify_certificate(token.certificate(), anchor, now, DEFAULT_MAX_CHAIN_DEPTH)
                        .ok()
                })
                .ok_or_else(|| {
                    ApiError::Authority(
                        "delegation cert does not verify against any trust anchor".into(),
                    )
                })?;
            if verified.leaf_identity() != admission.caller_spiffe_id {
                return Err(ApiError::Authority(format!(
                    "delegation cert leaf {} is not the authenticated caller {}",
                    verified.leaf_identity(),
                    admission.caller_spiffe_id
                )));
            }
            let fingerprint = token.fingerprint();
            let ledger = inner
                .external
                .entry(fingerprint)
                .or_insert_with(|| BudgetLedger::for_parent(&verified.effective().budget));
            if ledger.live_children() >= self.max_children {
                return Err(ApiError::Authority(format!(
                    "caller chain already has {} live children (cap {})",
                    ledger.live_children(),
                    self.max_children
                )));
            }
            ledger
                .try_allocate(child_id.as_u128(), requested.budget.max_cost_usd)
                .map_err(ledger_denial)?;
            let not_after = (now + ttl).min(cert_not_after(token.certificate()));
            let bridge = ephemeral_key()?;
            let rerooted = LatticeCertificate::mint_with_holder_key(
                verified.effective().clone(),
                verified.leaf_identity().to_string(),
                not_after,
                Some(fingerprint),
                &self.root_key,
                &bridge,
            );
            let cert = rerooted
                .mint_child_with_scope_using_key(
                    &requested,
                    child_identity.clone(),
                    not_after,
                    &reason,
                    SinkScope::unrestricted(),
                    &bridge,
                    &child_key,
                )
                .map_err(|e| {
                    if let Some(l) = inner.external.get_mut(&fingerprint) {
                        let _ = l.release(child_id.as_u128(), rust_decimal::Decimal::ZERO);
                    }
                    ApiError::Authority(format!("delegation refused: {e}"))
                })?;
            (cert, Parent::External(fingerprint), None)
        } else if admission.caller_spiffe_id == self.root_minter {
            // ── Case 3: the bootstrap identity ──────────────────────────
            let not_after = now + ttl;
            let bridge = ephemeral_key()?;
            let root = LatticeCertificate::mint_with_holder_key(
                requested.clone(),
                self.root_minter.clone(),
                not_after,
                None,
                &self.root_key,
                &bridge,
            );
            let cert = root
                .mint_child_with_scope_using_key(
                    &requested,
                    child_identity.clone(),
                    not_after,
                    &reason,
                    SinkScope::unrestricted(),
                    &bridge,
                    &child_key,
                )
                .map_err(|e| ApiError::Authority(format!("root mint refused: {e}")))?;
            (cert, Parent::Root, None)
        } else {
            // ── Case 4 ──────────────────────────────────────────────────
            return Err(ApiError::Authority(format!(
                "{} presented no certificate and is not the root minter",
                admission.caller_spiffe_id
            )));
        };

        let upstreams = self.admit_upstreams(
            &spec.spec.credentialed_egress,
            parent_upstreams.as_deref(),
            child_id,
        );
        let effective = cert.effective_permissions().clone();
        let chain_depth = cert.chain_depth();
        let entry = PodCert {
            ledger: BudgetLedger::for_parent(&effective.budget),
            cert,
            holder: child_key,
            holder_pkcs8: child_pkcs8.as_ref().to_vec(),
            parent,
            upstreams: upstreams.clone(),
        };
        if let Err(e) = self.persist(child_id, &entry).await {
            tracing::warn!(pod = %child_id, error = %e, "failed to persist pod authority; it will not survive a restart");
        }
        inner.pods.insert(child_id, entry);
        tracing::info!(
            pod = %child_id,
            caller = %admission.caller_spiffe_id,
            parent = ?parent,
            chain_depth,
            budget_usd = %effective.budget.max_cost_usd,
            "pod authority issued"
        );
        Ok(IssuedAuthority {
            effective,
            chain_depth,
            upstreams,
        })
    }

    /// The env pairs a local/container pod receives its certificate in.
    pub async fn boot_env(&self, pod_id: Uuid) -> Vec<(&'static str, String)> {
        match self.boot_certificate(pod_id).await {
            Some(b) => vec![
                (ENV_POD_CERT, b.token_b64),
                (ENV_CERT_ROOT_PUBKEY, b.root_pubkey_hex),
            ],
            None => Vec::new(),
        }
    }

    /// The certificate a Firecracker pod fetches over the workload API.
    pub async fn boot_certificate(&self, pod_id: Uuid) -> Option<BootCertificate> {
        let inner = self.inner.lock().await;
        let entry = inner.pods.get(&pod_id)?;
        let token = AttenuationToken::seal(entry.cert.clone(), self.root_pubkey.clone());
        Some(BootCertificate {
            token_b64: token.to_base64().ok()?,
            root_pubkey_hex: self.root_pubkey_hex(),
        })
    }

    /// The fingerprint of the certificate this node issued to `pod_id`, for
    /// cross-checking the authority a pod's shipped Article 12 records claim
    /// (#2437). `None` when the node issued this pod nothing.
    pub async fn certificate_fingerprint(&self, pod_id: Uuid) -> Option<[u8; 32]> {
        let inner = self.inner.lock().await;
        Some(inner.pods.get(&pod_id)?.cert.fingerprint())
    }

    /// Retire a pod's certificate and return its budget allocation to the
    /// parent's ledger. Until children report actual spend, the whole
    /// allocation is folded into the parent's consumption (no refund).
    pub async fn release_child(&self, pod_id: Uuid) {
        let mut inner = self.inner.lock().await;
        let Some(entry) = inner.pods.remove(&pod_id) else {
            return;
        };
        let consumed = entry.cert.effective_permissions().budget.max_cost_usd;
        let released = match entry.parent {
            Parent::Root => Ok(rust_decimal::Decimal::ZERO),
            Parent::Pod(p) => match inner.pods.get_mut(&p) {
                Some(parent) => parent.ledger.release(pod_id.as_u128(), consumed),
                None => Ok(rust_decimal::Decimal::ZERO),
            },
            Parent::External(fp) => match inner.external.get_mut(&fp) {
                Some(l) => l.release(pod_id.as_u128(), consumed),
                None => Ok(rust_decimal::Decimal::ZERO),
            },
        };
        if let Err(e) = released {
            tracing::debug!(pod = %pod_id, error = %e, "budget release found no live allocation");
        }
        let path = self.authority_path(pod_id);
        let _ = tokio::fs::remove_file(&path).await;
    }

    /// Rebuild the registry from `pods/<id>/authority.json` after a restart.
    /// Parent ledgers are re-derived by re-allocating every live child.
    pub async fn restore_from_disk(&self) -> usize {
        let pods_dir = self.state_dir.join("pods");
        let Ok(mut entries) = tokio::fs::read_dir(&pods_dir).await else {
            return 0;
        };
        let mut loaded: Vec<(Uuid, PodCert)> = Vec::new();
        while let Ok(Some(entry)) = entries.next_entry().await {
            let Some(id) = entry
                .file_name()
                .to_str()
                .and_then(|s| Uuid::parse_str(s).ok())
            else {
                continue;
            };
            let Ok(bytes) = tokio::fs::read(entry.path().join(AUTHORITY_FILE)).await else {
                continue;
            };
            let Ok(persisted) = serde_json::from_slice::<PersistedAuthority>(&bytes) else {
                tracing::warn!(pod = %id, "unreadable authority.json; pod will hold no certificate");
                continue;
            };
            let Ok(holder_pkcs8) = base64_decode(&persisted.holder_pkcs8_b64) else {
                continue;
            };
            let Ok(holder) = Ed25519KeyPair::from_pkcs8(&holder_pkcs8) else {
                continue;
            };
            if holder.public_key().as_ref() != expected_next_key(&persisted.certificate) {
                tracing::warn!(pod = %id, "persisted holder key does not match certificate; skipping");
                continue;
            }
            let ledger =
                BudgetLedger::for_parent(&persisted.certificate.effective_permissions().budget);
            loaded.push((
                id,
                PodCert {
                    cert: persisted.certificate,
                    holder,
                    holder_pkcs8,
                    ledger,
                    parent: persisted.parent,
                    upstreams: persisted.upstreams,
                },
            ));
        }

        let mut inner = self.inner.lock().await;
        let restored = loaded.len();
        let parents: Vec<(Uuid, Parent, rust_decimal::Decimal)> = loaded
            .iter()
            .map(|(id, c)| {
                (
                    *id,
                    c.parent,
                    c.cert.effective_permissions().budget.max_cost_usd,
                )
            })
            .collect();
        for (id, cert) in loaded {
            inner.pods.insert(id, cert);
        }
        for (child, parent, amount) in parents {
            let result = match parent {
                Parent::Root => Ok(()),
                Parent::Pod(p) => match inner.pods.get_mut(&p) {
                    Some(parent) => parent.ledger.try_allocate(child.as_u128(), amount),
                    None => Ok(()),
                },
                Parent::External(fp) => {
                    // The external chain's own budget is not persisted; be
                    // conservative and treat what we restored as its ceiling.
                    inner
                        .external
                        .entry(fp)
                        .or_insert_with(|| {
                            BudgetLedger::for_parent(
                                &portcullis::BudgetLattice::with_cost_limit_decimal(amount),
                            )
                        })
                        .try_allocate(child.as_u128(), amount)
                }
            };
            if let Err(e) = result {
                tracing::warn!(pod = %child, error = %e, "restored child exceeds its parent's ledger");
            }
        }
        restored
    }

    fn authority_path(&self, pod_id: Uuid) -> PathBuf {
        self.state_dir
            .join("pods")
            .join(pod_id.to_string())
            .join(AUTHORITY_FILE)
    }

    async fn persist(&self, pod_id: Uuid, entry: &PodCert) -> std::io::Result<()> {
        let path = self.authority_path(pod_id);
        if let Some(dir) = path.parent() {
            tokio::fs::create_dir_all(dir).await?;
        }
        let persisted = PersistedAuthority {
            version: 1,
            certificate: entry.cert.clone(),
            holder_pkcs8_b64: base64_encode(&entry.holder_pkcs8),
            parent: entry.parent,
            upstreams: entry.upstreams.clone(),
        };
        let bytes = serde_json::to_vec(&persisted).map_err(std::io::Error::other)?;
        tokio::fs::write(&path, bytes).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).await?;
        }
        Ok(())
    }
}

/// The node's federation issuer, if one is configured — and a refusal to
/// start if the registry needs one and it is not.
///
/// Fail-closed at START, not at the first call: a node whose registry has a
/// federated upstream and no issuer would admit pods to that upstream and then
/// refuse every call they made, which reads from inside the guest as an
/// upstream outage.
fn federation_source(
    issuer: Option<&str>,
    registry: Option<&UpstreamRegistry>,
    state_dir: &Path,
) -> Result<Option<std::sync::Arc<FederatedSource>>, String> {
    let needed = registry.is_some_and(UpstreamRegistry::has_federated);
    let Some(issuer) = issuer else {
        if needed {
            return Err("the --upstreams registry has a `federated` credential, but                         --federation-issuer is not set: the node cannot mint assertions for it.                         Set --federation-issuer (NUCLEUS_FEDERATION_ISSUER) to the https URL                         upstreams register as this node's issuer."
                .into());
        }
        return Ok(None);
    };
    // reqwest PANICS building a TLS client with no provider installed (this
    // workspace links it `rustls-no-provider`); `main` installs one first thing,
    // and this makes a caller that did not an error instead of a crash.
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        return Err("--federation-issuer needs a TLS crypto provider installed first".into());
    }
    let signer = keys::load_or_create_jwt_svid_signing_key(state_dir)?;
    let http =
        nucleus_federation::default_client().map_err(|e| format!("federation HTTP client: {e}"))?;
    let source = FederatedSource::new(std::sync::Arc::new(signer), issuer, http)?;
    tracing::info!(issuer = %source.issuer(), "federation issuer configured");
    Ok(Some(std::sync::Arc::new(source)))
}

fn ledger_denial(e: BudgetError) -> ApiError {
    ApiError::Authority(format!("budget conservation: {e}"))
}

fn ephemeral_key() -> Result<Ed25519KeyPair, ApiError> {
    let doc = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .map_err(|_| ApiError::Authority("key generation failed".into()))?;
    Ed25519KeyPair::from_pkcs8(doc.as_ref())
        .map_err(|_| ApiError::Authority("key parse failed".into()))
}

fn cert_not_after(cert: &LatticeCertificate) -> DateTime<Utc> {
    cert.delegation_blocks()
        .last()
        .map(|b| b.not_after)
        .unwrap_or(cert.authority().not_after)
}

fn expected_next_key(cert: &LatticeCertificate) -> &[u8] {
    cert.delegation_blocks()
        .last()
        .map(|b| b.next_key.as_slice())
        .unwrap_or(cert.authority().next_key.as_slice())
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s)
}

/// Mint the live-path session capability token for a pod from its RESOLVED
/// policy. Moved here from `main.rs` untouched: since admission rewrites
/// `spec.spec.policy` to the certificate's effective lattice before any
/// driver runs, this now derives its scope from proven authority rather than
/// from the caller's request.
///
/// Returns `None` (with a warning) if the policy cannot be resolved, the clock
/// is unavailable, or the token cannot be serialized. That is fail-closed: the
/// pod still spawns, but with NO token, so the tool-proxy's startup verify half
/// records `Missing`/`Invalid` and later token-gated operations are denied.
#[cfg_attr(
    not(any(feature = "local-driver", target_os = "linux")),
    allow(dead_code)
)]
pub(crate) async fn mint_task_token_for_spec(
    state: &NodeState,
    spec: &PodSpec,
    id: Uuid,
) -> Option<crate::session_mint::MintedTaskToken> {
    let policy = match spec.spec.resolve_policy() {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                pod = %id,
                error = %e,
                "live-path mint: policy resolution failed; no session token injected (fail-closed at verify)"
            );
            return None;
        }
    };
    let now_unix = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs(),
        Err(_) => {
            tracing::warn!(pod = %id, "live-path mint: clock before epoch; no session token injected");
            return None;
        }
    };
    // TTL = the pod/session lifetime (the spec's own timeout bound, in seconds).
    let ttl_secs = spec.spec.timeout_seconds;
    // The certificate this node issued the pod (#2464) — the token names it
    // (#2486). `None` only for a pod the authority refused to register.
    let authority = state.authority.certificate_fingerprint(id).await;
    match crate::session_mint::mint_session_task_token(
        &id.to_string(),
        &policy,
        ttl_secs,
        now_unix,
        state.trust_gate.task_issuer_signing_key.as_ref(),
        authority,
    ) {
        Ok(minted) => Some(minted),
        Err(e) => {
            tracing::warn!(
                pod = %id,
                error = %e,
                "live-path mint: token serialization failed; no session token injected"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nucleus_spec::{PodSpecInner, PolicySpec};
    use portcullis::CapabilityLevel;
    use rust_decimal::Decimal;

    const TD: &str = "test.local";
    const MINTER: &str = "spiffe://test.local/ns/system/sa/cli";

    fn args() -> AuthorityArgs {
        AuthorityArgs {
            root_minter_spiffe_id: None,
            cert_trust_anchors: Vec::new(),
            max_children_per_pod: 8,
            upstreams: None,
            federation_issuer: None,
        }
    }

    fn authority(dir: &Path, args: AuthorityArgs) -> PodAuthority {
        PodAuthority::new(&args, TD, dir).expect("authority builds")
    }

    fn spec_with(lattice: PermissionLattice) -> PodSpec {
        PodSpec::new(PodSpecInner {
            work_dir: PathBuf::from("/work"),
            timeout_seconds: 600,
            policy: PolicySpec::Inline {
                lattice: Box::new(lattice),
            },
            budget_model: None,
            resources: None,
            network: None,
            credentialed_egress: Vec::new(),
            workload: None,
            image: None,
            vsock: None,
            seccomp: None,
            cgroup: None,
            audit_sink: None,
            credentials: None,
        })
    }

    fn lattice(budget_usd: u32) -> PermissionLattice {
        let mut l = PermissionLattice::permissive();
        l.budget.max_cost_usd = Decimal::from(budget_usd);
        l
    }

    fn by(spiffe: &str) -> Admission {
        Admission {
            caller_spiffe_id: spiffe.into(),
            caller_pod: None,
            header_cert: None,
        }
    }

    fn from_pod(parent: Uuid) -> Admission {
        Admission {
            caller_spiffe_id: format!("spiffe://{TD}/ns/pods/sa/{parent}"),
            caller_pod: Some(parent),
            header_cert: None,
        }
    }

    #[tokio::test]
    async fn the_root_minter_creates_from_a_bare_policy_and_nobody_else_does() {
        let dir = tempfile::tempdir().unwrap();
        let auth = authority(dir.path(), args());
        let pod = Uuid::new_v4();

        let issued = auth
            .admit(&by(MINTER), &spec_with(lattice(5)), pod)
            .await
            .expect("bootstrap identity mints a root");
        assert_eq!(issued.chain_depth, 1);
        assert_eq!(issued.effective.budget.max_cost_usd, Decimal::from(5));
        let boot = auth.boot_certificate(pod).await.expect("registered");
        let token = AttenuationToken::from_base64(&boot.token_b64).unwrap();
        assert_eq!(token.leaf_identity(), auth.pod_spiffe_id(pod));
        assert_eq!(token.root_identity(), MINTER);
        assert!(verify_certificate(token.certificate(), &auth.root_pubkey, Utc::now(), 10).is_ok());

        let stranger = by("spiffe://test.local/ns/default/sa/someone");
        let denied = auth
            .admit(&stranger, &spec_with(lattice(5)), Uuid::new_v4())
            .await;
        assert!(
            matches!(denied, Err(ApiError::Authority(_))),
            "an unidentified non-minter must be refused, got {denied:?}"
        );
        assert!(auth.boot_certificate(Uuid::new_v4()).await.is_none());
    }

    #[tokio::test]
    async fn a_child_is_narrowed_to_its_parent_and_budget_is_conserved() {
        let dir = tempfile::tempdir().unwrap();
        let auth = authority(dir.path(), args());
        let parent = Uuid::new_v4();
        let mut parent_policy = lattice(5);
        parent_policy.capabilities.git_push = CapabilityLevel::Never;
        auth.admit(&by(MINTER), &spec_with(parent_policy.clone()), parent)
            .await
            .unwrap();

        // Child asks for MORE than the parent (git_push Always, $3): capability
        // is meet-clamped, budget is reserved.
        let mut greedy = lattice(3);
        greedy.capabilities.git_push = CapabilityLevel::Always;
        let c1 = Uuid::new_v4();
        let issued = auth
            .admit(&from_pod(parent), &spec_with(greedy.clone()), c1)
            .await
            .unwrap();
        assert_eq!(issued.chain_depth, 2);
        assert_eq!(
            issued.effective.capabilities.git_push,
            CapabilityLevel::Never
        );
        assert!(issued.effective.leq(&parent_policy));

        // Second $3 child: 3 + 3 > 5 — refused. This is the defect: before the
        // ledger, every child got the parent's full budget.
        let c2 = Uuid::new_v4();
        let denied = auth
            .admit(&from_pod(parent), &spec_with(lattice(3)), c2)
            .await;
        assert!(
            matches!(&denied, Err(ApiError::Authority(m)) if m.contains("budget conservation")),
            "got {denied:?}"
        );
        // A $2 child fits exactly.
        auth.admit(&from_pod(parent), &spec_with(lattice(2)), c2)
            .await
            .unwrap();
        // Nothing left.
        assert!(
            auth.admit(&from_pod(parent), &spec_with(lattice(1)), Uuid::new_v4())
                .await
                .is_err()
        );

        // Releasing c1 folds its allocation into the parent's consumption
        // (conservative: no refund), so the parent still cannot over-spawn.
        auth.release_child(c1).await;
        assert!(
            auth.admit(&from_pod(parent), &spec_with(lattice(1)), Uuid::new_v4())
                .await
                .is_err()
        );
        assert!(auth.boot_certificate(c1).await.is_none());
    }

    #[tokio::test]
    async fn a_request_over_the_parent_budget_is_refused_not_clamped() {
        let dir = tempfile::tempdir().unwrap();
        let auth = authority(dir.path(), args());
        let parent = Uuid::new_v4();
        auth.admit(&by(MINTER), &spec_with(lattice(5)), parent)
            .await
            .unwrap();
        let denied = auth
            .admit(&from_pod(parent), &spec_with(lattice(500)), Uuid::new_v4())
            .await;
        assert!(
            matches!(denied, Err(ApiError::Authority(_))),
            "got {denied:?}"
        );
        // And the failed attempt reserved nothing.
        auth.admit(&from_pod(parent), &spec_with(lattice(5)), Uuid::new_v4())
            .await
            .expect("the full budget is still available");
    }

    #[tokio::test]
    async fn fan_out_is_capped_per_parent() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = args();
        a.max_children_per_pod = 2;
        let auth = authority(dir.path(), a);
        let parent = Uuid::new_v4();
        auth.admit(&by(MINTER), &spec_with(lattice(100)), parent)
            .await
            .unwrap();
        auth.admit(&from_pod(parent), &spec_with(lattice(1)), Uuid::new_v4())
            .await
            .unwrap();
        auth.admit(&from_pod(parent), &spec_with(lattice(1)), Uuid::new_v4())
            .await
            .unwrap();
        let third = auth
            .admit(&from_pod(parent), &spec_with(lattice(1)), Uuid::new_v4())
            .await;
        assert!(
            matches!(&third, Err(ApiError::Authority(m)) if m.contains("live children")),
            "got {third:?}"
        );
    }

    #[tokio::test]
    async fn an_unregistered_pod_cannot_spawn() {
        let dir = tempfile::tempdir().unwrap();
        let auth = authority(dir.path(), args());
        let denied = auth
            .admit(
                &from_pod(Uuid::new_v4()),
                &spec_with(lattice(1)),
                Uuid::new_v4(),
            )
            .await;
        assert!(matches!(denied, Err(ApiError::Authority(_))));
    }

    #[tokio::test]
    async fn chain_depth_bounds_recursion() {
        let dir = tempfile::tempdir().unwrap();
        let auth = authority(dir.path(), args());
        let mut current = Uuid::new_v4();
        auth.admit(&by(MINTER), &spec_with(lattice(1_000_000)), current)
            .await
            .unwrap();
        let mut depth = 1;
        loop {
            let next = Uuid::new_v4();
            match auth
                .admit(&from_pod(current), &spec_with(lattice(1)), next)
                .await
            {
                Ok(issued) => {
                    depth = issued.chain_depth;
                    current = next;
                }
                Err(ApiError::Authority(m)) => {
                    assert!(m.contains("depth") && m.contains("exceed"), "{m}");
                    break;
                }
                Err(e) => panic!("unexpected {e:?}"),
            }
            assert!(depth <= DEFAULT_MAX_CHAIN_DEPTH);
        }
        assert_eq!(depth, DEFAULT_MAX_CHAIN_DEPTH);
    }

    /// An external caller: a chain rooted at an operator-registered anchor,
    /// whose leaf is the authenticated identity. Re-rooted with provenance.
    #[tokio::test]
    async fn an_external_chain_is_verified_against_our_anchors_and_bound_to_the_caller() {
        let dir = tempfile::tempdir().unwrap();
        let rng = ring::rand::SystemRandom::new();
        let ext_root = ephemeral_key().unwrap();
        let ext_root_hex = hex::encode(ext_root.public_key().as_ref());

        let mut a = args();
        a.cert_trust_anchors = vec![ext_root_hex];
        let auth = authority(dir.path(), a);

        let caller = "spiffe://other.example/ns/agents/sa/orchestrator";
        // One expiry for both hops: a second `Utc::now()` is already later,
        // and a child may not outlive its parent block.
        let expiry = Utc::now() + Duration::hours(1);
        let (root, holder) = LatticeCertificate::mint(
            lattice(10),
            "spiffe://other.example/human/alice".into(),
            expiry,
            &ext_root,
            &rng,
        );
        let (leaf, _k) = root
            .delegate(&lattice(4), caller.into(), expiry, &holder, &rng)
            .unwrap();
        let token = AttenuationToken::seal(leaf.clone(), ext_root.public_key().as_ref().to_vec());
        let header = token.to_base64().unwrap();

        let pod = Uuid::new_v4();
        let admission = Admission {
            caller_spiffe_id: caller.into(),
            caller_pod: None,
            header_cert: Some(header.clone()),
        };
        let issued = auth
            .admit(&admission, &spec_with(lattice(3)), pod)
            .await
            .unwrap();
        assert_eq!(issued.effective.budget.max_cost_usd, Decimal::from(3));
        let boot = auth.boot_certificate(pod).await.unwrap();
        let minted = AttenuationToken::from_base64(&boot.token_b64).unwrap();
        assert_eq!(
            minted.certificate().authority().provenance,
            Some(token.fingerprint())
        );
        assert_eq!(minted.root_identity(), caller);
        assert!(
            verify_certificate(minted.certificate(), &auth.root_pubkey, Utc::now(), 10).is_ok()
        );

        // The caller's chain carried $4: a second $3 pod is refused.
        let denied = auth
            .admit(&admission, &spec_with(lattice(3)), Uuid::new_v4())
            .await;
        assert!(
            matches!(&denied, Err(ApiError::Authority(m)) if m.contains("budget conservation"))
        );

        // Leaf/caller mismatch: same valid chain, different authenticated identity.
        let impostor = Admission {
            caller_spiffe_id: "spiffe://other.example/ns/agents/sa/impostor".into(),
            caller_pod: None,
            header_cert: Some(header),
        };
        assert!(matches!(
            auth.admit(&impostor, &spec_with(lattice(1)), Uuid::new_v4())
                .await,
            Err(ApiError::Authority(_))
        ));

        // A chain rooted at a key we do NOT trust — even a self-consistent
        // token carrying its own root key — is refused.
        let stranger_root = ephemeral_key().unwrap();
        let (sroot, _) = LatticeCertificate::mint(
            lattice(10),
            caller.into(),
            Utc::now() + Duration::hours(1),
            &stranger_root,
            &rng,
        );
        let stoken = AttenuationToken::seal(sroot, stranger_root.public_key().as_ref().to_vec());
        let untrusted = Admission {
            caller_spiffe_id: caller.into(),
            caller_pod: None,
            header_cert: Some(stoken.to_base64().unwrap()),
        };
        assert!(matches!(
            auth.admit(&untrusted, &spec_with(lattice(1)), Uuid::new_v4())
                .await,
            Err(ApiError::Authority(_))
        ));
    }

    #[tokio::test]
    async fn authority_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let parent = Uuid::new_v4();
        let child = Uuid::new_v4();
        {
            let auth = authority(dir.path(), args());
            auth.admit(&by(MINTER), &spec_with(lattice(5)), parent)
                .await
                .unwrap();
            auth.admit(&from_pod(parent), &spec_with(lattice(3)), child)
                .await
                .unwrap();
        }
        // "Restart": a new authority over the same state dir.
        let auth = authority(dir.path(), args());
        assert_eq!(auth.restore_from_disk().await, 2);
        // The restored parent can still delegate (its holder key came back)...
        auth.admit(&from_pod(parent), &spec_with(lattice(2)), Uuid::new_v4())
            .await
            .expect("restored holder key delegates");
        // ...and its ledger came back too: 3 + 2 = 5, nothing left.
        assert!(
            auth.admit(&from_pod(parent), &spec_with(lattice(1)), Uuid::new_v4())
                .await
                .is_err()
        );
        // The restored child's certificate still verifies under the same root.
        let boot = auth.boot_certificate(child).await.unwrap();
        let t = AttenuationToken::from_base64(&boot.token_b64).unwrap();
        assert!(verify_certificate(t.certificate(), &auth.root_pubkey, Utc::now(), 10).is_ok());
    }

    // ── Credentialed upstreams, clamped at the NODE ──────────────────────
    //
    // Before these, the node passed `credentialed_egress` through verbatim and
    // the only clamp was the in-guest tool-proxy's. Every test below calls
    // `admit` — the node's own gate — with the Admission a direct caller of
    // `POST /v1/pods` produces, so none of them passes through the proxy.

    const REGISTRY: &str = r#"
[[upstream]]
name = "model-api"
base_url = "https://model-api.invalid/v1"
header = "authorization"
value_prefix = "Bearer "
credential.env.var = "LLM_API_TOKEN"

[[upstream]]
name = "search-api"
base_url = "https://search-api.invalid"
header = "x-api-key"
credential.env.var = "SEARCH_API_TOKEN"
"#;

    fn with_registry(dir: &Path) -> PodAuthority {
        let path = dir.join("upstreams.toml");
        std::fs::write(&path, REGISTRY).unwrap();
        let mut a = args();
        a.upstreams = Some(path);
        authority(dir, a)
    }

    fn registered(name: &str) -> CredentialedEgressSpec {
        crate::upstreams::UpstreamRegistry::from_toml_str(REGISTRY)
            .unwrap()
            .entries()
            .iter()
            .find(|e| e.name == name)
            .cloned()
            .expect("fixture names a registry entry")
    }

    /// The exfiltration shape: a real registry name pointed at a URL the caller
    /// chose, and an invented entry naming a node variable nobody registered.
    fn loot() -> Vec<CredentialedEgressSpec> {
        let mut retargeted = registered("model-api");
        retargeted.upstream = "https://attacker.invalid".into();
        let invented = CredentialedEgressSpec {
            name: "loot".into(),
            upstream: "https://attacker.invalid".into(),
            credential_env: "NUCLEUS_NODE_PROXY_AUTH_SECRET".into(),
            header: "authorization".into(),
            value_prefix: String::new(),
        };
        vec![retargeted, invented]
    }

    fn requesting(ups: Vec<CredentialedEgressSpec>, budget: u32) -> PodSpec {
        let mut spec = spec_with(lattice(budget));
        spec.spec.credentialed_egress = ups;
        spec
    }

    /// (a) **A pod calling the node directly cannot name an upstream its
    /// parent lacks** — not an unregistered one, and not even a REGISTERED one
    /// the parent was never admitted. Delegation narrows; it never invents.
    #[tokio::test]
    async fn a_pod_caller_cannot_gain_an_upstream_its_parent_lacks() {
        let dir = tempfile::tempdir().unwrap();
        let auth = with_registry(dir.path());
        let parent = Uuid::new_v4();
        let issued = auth
            .admit(
                &by(MINTER),
                &requesting(vec![registered("model-api")], 5),
                parent,
            )
            .await
            .unwrap();
        assert_eq!(
            issued.upstreams,
            vec![registered("model-api")],
            "the control: the root minter is admitted a registry entry"
        );

        let mut asked = loot();
        asked.push(registered("search-api")); // registered, but the parent lacks it
        assert_eq!(asked.len(), 3, "the fixture must request something to drop");
        let child = auth
            .admit(&from_pod(parent), &requesting(asked, 1), Uuid::new_v4())
            .await
            .unwrap();
        assert!(
            child.upstreams.is_empty(),
            "a pod's own request reached the node and kept {:?} — its parent held only model-api",
            child.upstreams.iter().map(|u| &u.name).collect::<Vec<_>>()
        );

        // Delegation still works for what the parent holds.
        let child = auth
            .admit(
                &from_pod(parent),
                &requesting(vec![registered("model-api")], 1),
                Uuid::new_v4(),
            )
            .await
            .unwrap();
        assert_eq!(child.upstreams, vec![registered("model-api")]);
    }

    /// (b) **With a registry, the root minter and an external caller get only
    /// registry entries**, field for field. A differing field is a different
    /// entry, and an entry naming a variable the operator never registered is
    /// dropped whoever asks.
    #[tokio::test]
    async fn root_and_external_callers_are_clamped_to_the_registry() {
        let dir = tempfile::tempdir().unwrap();
        let rng = ring::rand::SystemRandom::new();
        let ext_root = ephemeral_key().unwrap();
        let path = dir.path().join("upstreams.toml");
        std::fs::write(&path, REGISTRY).unwrap();
        let mut a = args();
        a.upstreams = Some(path);
        a.cert_trust_anchors = vec![hex::encode(ext_root.public_key().as_ref())];
        let auth = authority(dir.path(), a);

        let mut asked = loot();
        asked.push(registered("search-api"));
        let root = auth
            .admit(&by(MINTER), &requesting(asked.clone(), 5), Uuid::new_v4())
            .await
            .unwrap();
        assert_eq!(root.upstreams, vec![registered("search-api")]);

        let caller = "spiffe://other.example/ns/agents/sa/orchestrator";
        let expiry = Utc::now() + Duration::hours(1);
        let (leaf, _k) =
            LatticeCertificate::mint(lattice(10), caller.into(), expiry, &ext_root, &rng);
        let token = AttenuationToken::seal(leaf, ext_root.public_key().as_ref().to_vec());
        let external = Admission {
            caller_spiffe_id: caller.into(),
            caller_pod: None,
            header_cert: Some(token.to_base64().unwrap()),
        };
        let ext = auth
            .admit(&external, &requesting(asked, 1), Uuid::new_v4())
            .await
            .unwrap();
        assert_eq!(ext.upstreams, vec![registered("search-api")]);
    }

    /// No registry is an empty ceiling for EVERY case, the root minter
    /// included. See `upstreams.rs` for why this is not "trust the operator CLI".
    #[tokio::test]
    async fn without_a_registry_nobody_is_admitted_an_upstream() {
        let dir = tempfile::tempdir().unwrap();
        let auth = authority(dir.path(), args());
        let issued = auth
            .admit(
                &by(MINTER),
                &requesting(vec![registered("model-api")], 5),
                Uuid::new_v4(),
            )
            .await
            .unwrap();
        assert!(issued.upstreams.is_empty());
    }

    /// The per-pod admitted set is persisted with the certificate, so a
    /// restarted node still clamps a restored parent's children to it.
    #[tokio::test]
    async fn a_parents_admitted_upstreams_survive_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let parent = Uuid::new_v4();
        with_registry(dir.path())
            .admit(
                &by(MINTER),
                &requesting(vec![registered("model-api")], 5),
                parent,
            )
            .await
            .unwrap();
        let auth = with_registry(dir.path());
        assert_eq!(auth.restore_from_disk().await, 1);
        let child = auth
            .admit(
                &from_pod(parent),
                &requesting(vec![registered("model-api"), registered("search-api")], 1),
                Uuid::new_v4(),
            )
            .await
            .unwrap();
        assert_eq!(child.upstreams, vec![registered("model-api")]);
    }

    /// Admission deciding is half of it; the spec the driver launches from
    /// must CARRY the decision. `apply_to` replaces both fields...
    #[test]
    fn apply_to_replaces_the_requested_upstreams_with_the_admitted_ones() {
        let mut spec = requesting(loot(), 5);
        IssuedAuthority {
            effective: lattice(1),
            chain_depth: 1,
            upstreams: vec![registered("model-api")],
        }
        .apply_to(&mut spec);
        assert_eq!(spec.spec.credentialed_egress, vec![registered("model-api")]);
    }

    /// ...and `create_pod_internal` calls it, unconditionally, right after
    /// admission. A source check, the same shape as
    /// `the_clamp_is_wired_before_admission_unconditionally`: the node's launch
    /// path spawns VMs, so no unit test can drive it end to end.
    #[test]
    fn create_pod_internal_applies_the_issued_authority() {
        let main = include_str!("main.rs");
        let admit = main
            .find("state.authority.admit(&admission, &spec, id)")
            .expect("admission is called from main.rs");
        let apply = main
            .find("issued.apply_to(&mut spec);")
            .expect("the issued authority is applied to the spec in main.rs");
        assert!(admit < apply, "applied after it is issued");
        let spawn = main[admit..]
            .find("let spawned = match state.driver")
            .expect("the spawn follows admission");
        assert!(
            apply < admit + spawn,
            "applied before the pod is spawned from the spec"
        );
        let indent = main[..apply].rsplit('\n').next().unwrap_or("");
        assert_eq!(
            indent, "    ",
            "at function-body level, not under a condition"
        );
    }

    // ── Federated upstreams: the issuer, and who an assertion names ──────

    const FEDERATED_REGISTRY: &str = r#"
[[upstream]]
name = "model-api"
base_url = "https://model-api.invalid/v1"
header = "authorization"
value_prefix = "Bearer "

[upstream.credential.federated]
token_endpoint = "https://auth.model-api.invalid/oauth/token"
grant = "jwt-bearer"
encoding = "json"
audience = "https://auth.model-api.invalid"
"#;

    fn federated_args(dir: &Path, issuer: Option<&str>) -> AuthorityArgs {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let path = dir.join("upstreams.toml");
        std::fs::write(&path, FEDERATED_REGISTRY).unwrap();
        let mut a = args();
        a.upstreams = Some(path);
        a.federation_issuer = issuer.map(str::to_string);
        a
    }

    /// **Fail closed at start.** A registry that needs an issuer and has none
    /// is a node that would admit pods to an upstream and then refuse every
    /// call — so it does not start. Nor does one with a cleartext issuer.
    #[test]
    fn a_federated_registry_without_an_issuer_refuses_to_start() {
        let dir = tempfile::tempdir().unwrap();
        let err = PodAuthority::new(&federated_args(dir.path(), None), TD, dir.path())
            .err()
            .expect("no issuer: refused");
        assert!(err.contains("--federation-issuer"), "{err}");
        assert!(
            PodAuthority::new(
                &federated_args(dir.path(), Some("http://federation.example.invalid")),
                TD,
                dir.path()
            )
            .is_err(),
            "a cleartext issuer was accepted"
        );
        // The control: with an issuer it starts, and no key file is written by
        // a node that has no issuer.
        let ok = PodAuthority::new(
            &federated_args(dir.path(), Some("https://federation.example.invalid")),
            TD,
            dir.path(),
        )
        .expect("starts with an issuer");
        assert!(ok.federation_source().is_some());
        let plain = tempfile::tempdir().unwrap();
        authority(plain.path(), args());
        assert!(!plain.path().join("jwt_svid_p256_signing_key.der").exists());
    }

    /// **Who an assertion names, read from the certificate the node issued.**
    /// `sub` is the pod's own identity, the root and tenant are the chain's,
    /// and the chain claim is the certificate's fingerprint — and a broker
    /// identity that disagrees with the certificate gets nothing.
    #[tokio::test]
    async fn the_federation_subject_comes_from_the_issued_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let auth = PodAuthority::new(
            &federated_args(dir.path(), Some("https://federation.example.invalid")),
            TD,
            dir.path(),
        )
        .unwrap();
        let pod = Uuid::new_v4();
        let federated = auth.upstream_registry().unwrap().entries().to_vec();
        let issued = auth
            .admit(&by(MINTER), &requesting(federated.clone(), 5), pod)
            .await
            .unwrap();
        assert_eq!(
            issued.upstreams, federated,
            "the federated projection is admitted"
        );

        let observed = nucleus_cred_broker::PodIdentity::observed_by_host(auth.pod_spiffe_id(pod));
        let subject = auth
            .federation_subject(pod, &observed)
            .await
            .expect("an issued pod has a subject");
        assert_eq!(subject.pod_spiffe_id(), auth.pod_spiffe_id(pod));
        let debug = format!("{subject:?}");
        let fp = hex::encode(auth.certificate_fingerprint(pod).await.unwrap());
        assert_eq!(fp.len(), 64);
        for fact in [MINTER, TD, fp.as_str()] {
            assert!(debug.contains(fact), "the subject lacks {fact}: {debug}");
        }

        let stranger =
            nucleus_cred_broker::PodIdentity::observed_by_host(auth.pod_spiffe_id(Uuid::new_v4()));
        assert!(
            auth.federation_subject(pod, &stranger).await.is_none(),
            "a broker identity that is not the certificate's leaf got a subject"
        );
        assert!(
            auth.federation_subject(Uuid::new_v4(), &observed)
                .await
                .is_none(),
            "a pod with no certificate got a subject"
        );

        // And the broker's credentials for this pod can mint; a node with no
        // issuer's cannot.
        let entries = auth.upstream_registry().unwrap().resolve(&issued.upstreams);
        let creds = crate::broker_launch::pod_credentials(&auth, pod, &observed, &entries).await;
        assert!(
            format!("{creds:?}").contains("federated: true"),
            "{creds:?}"
        );
        let plain = with_registry(tempfile::tempdir().unwrap().path());
        let creds = crate::broker_launch::pod_credentials(&plain, pod, &observed, &entries).await;
        assert!(
            format!("{creds:?}").contains("federated: false"),
            "{creds:?}"
        );
    }
}
