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
//! # Persistence
//!
//! `pods/<id>/authority.json` holds the certificate and the holder key
//! (0o400), following the derive-from-`pods/` convention `identity.rs` uses
//! for the VM registry: a restart rebuilds the registry from the directory
//! that already is the record of which pods exist.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use nucleus_spec::PodSpec;
use portcullis::certificate::{
    DEFAULT_MAX_CHAIN_DEPTH, LatticeCertificate, SinkScope, verify_certificate,
};
use portcullis::token::AttenuationToken;
use portcullis::{BudgetLedger, LedgerError, PermissionLattice};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{ApiError, NodeState, trust_gate};

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
}

struct PodCert {
    cert: LatticeCertificate,
    holder: Ed25519KeyPair,
    holder_pkcs8: Vec<u8>,
    ledger: BudgetLedger,
    parent: Parent,
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
}

struct Inner {
    pods: HashMap<Uuid, PodCert>,
    /// Ledgers for external callers' chains, keyed by chain fingerprint.
    external: HashMap<[u8; 32], BudgetLedger>,
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
    inner: tokio::sync::Mutex<Inner>,
}

impl PodAuthority {
    /// Build the authority for this node. The root signing key is persisted
    /// under `state_dir` like the node's other role keys (`trust_gate`).
    pub fn new(args: &AuthorityArgs, trust_domain: &str, state_dir: &Path) -> Self {
        let dalek = trust_gate::load_or_create_cert_root_signing_key(state_dir);
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

        Self {
            trust_domain: trust_domain.to_string(),
            root_minter,
            root_key,
            root_pubkey,
            anchors,
            max_children: args.max_children_per_pod,
            state_dir: state_dir.to_path_buf(),
            inner: tokio::sync::Mutex::new(Inner {
                pods: HashMap::new(),
                external: HashMap::new(),
            }),
        }
    }

    /// [`Self::new`] from the node's parsed CLI.
    pub fn from_args(args: &crate::Args) -> Self {
        Self::new(
            &args.authority,
            &args.identity_trust_domain,
            &args.state_dir,
        )
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

        let (cert, parent) = if let Some(parent_id) = admission.caller_pod {
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
            (cert, Parent::Pod(parent_id))
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
            (cert, Parent::External(fingerprint))
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
            (cert, Parent::Root)
        } else {
            // ── Case 4 ──────────────────────────────────────────────────
            return Err(ApiError::Authority(format!(
                "{} presented no certificate and is not the root minter",
                admission.caller_spiffe_id
            )));
        };

        let effective = cert.effective_permissions().clone();
        let chain_depth = cert.chain_depth();
        let entry = PodCert {
            ledger: BudgetLedger::for_parent(&effective.budget),
            cert,
            holder: child_key,
            holder_pkcs8: child_pkcs8.as_ref().to_vec(),
            parent,
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

fn ledger_denial(e: LedgerError) -> ApiError {
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
pub(crate) fn mint_task_token_for_spec(
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
    match crate::session_mint::mint_session_task_token(
        &id.to_string(),
        &policy,
        ttl_secs,
        now_unix,
        state.trust_gate.task_issuer_signing_key.as_ref(),
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
        }
    }

    fn authority(dir: &Path, args: AuthorityArgs) -> PodAuthority {
        PodAuthority::new(&args, TD, dir)
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
}
