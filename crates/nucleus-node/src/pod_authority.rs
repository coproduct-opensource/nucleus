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
//! to. Admission bounds it in the same match, by the same case:
//!
//! 1. a pod caller: by what the PARENT was admitted (kept per pod, persisted
//!    with its certificate) AND what is still in the operator registry, so
//!    delegation can narrow and never invent;
//! 2. an external caller: by the operator registry (`--upstreams`) — or, for a
//!    caller admitted through a `[[caller]]` binding, by that binding's
//!    `upstreams`, never the whole registry;
//! 3. the root minter: by the operator registry.
//!
//! An entry outside its bound REFUSES the pod (ADR 0010 §1): the caller gets
//! the pod it asked for or none, never a quieter one. The refusal names the
//! entry, not the reason, so "not in the registry", "differs from its entry"
//! and "not held by the parent" read the same (ADR 0004: no oracle). With no
//! registry configured every entry is outside, for every case. See
//! `upstreams.rs` for why that is fail-closed rather than "trust the root
//! minter".
//!
//! # Federated callers (`federation_ingress.rs`)
//!
//! A caller whose mTLS identity is in a `[[caller]]` binding's trust domain got
//! its SVID and its certificate from this node's federation exchange. It is
//! still case 2 — there is no separate admission path — with three
//! differences, all keyed by the binding:
//!
//! * **Trust anchor.** Its chain must verify against THIS node's root key. The
//!   node's own key has always been an anchor, so federated certificates need
//!   no `--cert-trust-anchors` entry; what is new is that for a federated
//!   tenant it is the ONLY anchor, so an operator-added anchor cannot mint
//!   around a binding's ceiling.
//! * **Budget.** One ledger per binding trust domain, bounded by the binding's
//!   ceiling — not one per presented chain, which would give every exchange a
//!   fresh budget and make the ceiling's budget a per-token allowance.
//! * **Upstreams.** Clamped to the binding's list.
//!
//! # Persistence
//!
//! `pods/<id>/authority.json` holds the certificate and the holder key
//! (0o400), following the derive-from-`pods/` convention `identity.rs` uses
//! for the VM registry: a restart rebuilds the registry from the directory
//! that already is the record of which pods exist.
//!
//! A ledger is persisted with its holder, because a restart must not hand
//! back budget: `Σ live allocations` is re-derived from the live children's
//! own files, but what RETIRED children consumed exists nowhere else. So:
//!
//! * a pod's `consumed` is in its own `authority.json`;
//! * an external chain's ceiling and `consumed` are in
//!   `authority/external/<fingerprint>.json`, written when the chain is first
//!   charged and on every release;
//! * a release writes the parent's record (naming the child as `retired`)
//!   BEFORE it removes the child's file, and a restore skips any child its
//!   parent names as retired. A crash between the two writes therefore
//!   restores the ledger exactly, never with the child counted twice or not
//!   at all.
//!
//! Every file is written whole and renamed into place. A record that exists
//! and cannot be read is refused, not defaulted: an unreadable chain record
//! refuses that chain, and an unreadable pod record — which cannot say whose
//! child it was — refuses every delegated admission until an operator
//! resolves it. Only the root minter, which holds no ledger, still creates.

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
use crate::federation_ingress::CallerBindings;
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
#[command(mut_args = |a| a.hide_env_values(true))]
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
    /// The inbound exchange listener (`federation_ingress.rs`).
    #[command(flatten)]
    pub ingress: crate::federation_ingress::FederationArgs,
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

/// Why the host could not build a kernel for a pod. Two causes, two variants:
/// "issued nothing" is not "issued something that no longer holds" (ADR 0007
/// A-8).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum HostKernelError {
    #[error("this node issued the pod no certificate")]
    NoCertificate,
    #[error("the pod's certificate does not verify against this node's root: {0}")]
    DoesNotVerify(String),
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
    /// Stamp the pod with its creator when that creator is a CI/CD identity,
    /// and refuse a spec that sets the stamp itself. See
    /// [`crate::auth::AuthorizationPolicy::stamp_ci_principal`].
    pub fn stamp_ci_principal(
        &self,
        policy: &crate::auth::AuthorizationPolicy,
        spec: &mut PodSpec,
    ) -> Result<(), ApiError> {
        policy
            .stamp_ci_principal(&self.caller_spiffe_id, spec)
            .map_err(ApiError::InvalidSpec)
    }

    /// From an HTTP request: the per-pod caller token (if it proved a pod),
    /// else the mTLS peer's own pod SVID; plus the delegation-cert header.
    pub fn from_http(
        policy: &crate::auth::AuthorizationPolicy,
        caller_token_pod: Option<Uuid>,
        auth_ctx: &crate::auth::AuthContext,
        headers: &axum::http::HeaderMap,
    ) -> Self {
        Self {
            caller_pod: policy.proved_pod(caller_token_pod, &auth_ctx.spiffe_id),
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
    /// The certificate's root identity: whose authority this pod runs under,
    /// and so (by its trust domain) which tenant owns it (ADR 0001).
    pub root_identity: String,
    /// The pod's hold on its budget, released unless the pod comes to run.
    reservation: Reservation,
}

/// A pod's budget reservation, from admission until the pod runs.
///
/// Dropped without [`Reservation::commit`], it hands the reservation back:
/// a spawn that failed, and equally a create whose future was dropped
/// mid-boot because its client went away (#3032). That second path used to
/// run neither arm of the spawn's `match`, so the reservation outlived the
/// request, and the process too, since `authority.json` is restored at start.
/// Now there is no path on which the release can be forgotten.
#[must_use = "dropping a Reservation releases the pod's budget; commit it once the pod runs"]
pub(crate) struct Reservation {
    release: Option<Release>,
}

struct Release {
    inner: std::sync::Arc<tokio::sync::Mutex<Inner>>,
    state_dir: PathBuf,
    pod_id: Uuid,
}

impl std::fmt::Debug for Reservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reservation")
            .field("armed", &self.release.is_some())
            .finish()
    }
}

impl Reservation {
    /// The pod runs: it keeps its budget until it is reaped.
    pub fn commit(mut self) {
        self.release = None;
    }

    /// The pod will not run: hand the reservation back NOW, so a caller that
    /// retries on the error sees its budget. (Dropping it releases too, but on
    /// a task of its own.)
    pub async fn release(mut self) {
        if let Some(r) = self.release.take() {
            release(&r.inner, &r.state_dir, r.pod_id).await;
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let Some(r) = self.release.take() else {
            return;
        };
        // Drop cannot await, and the ledger lock is async: the release runs
        // as its own task. Outside a runtime there is nothing left to release
        // against, so there is nothing to do.
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => {
                rt.spawn(async move { release(&r.inner, &r.state_dir, r.pod_id).await });
            }
            Err(_) => tracing::warn!(pod = %r.pod_id, "reservation dropped outside a runtime"),
        }
    }
}

/// Retire `pod_id`'s certificate and return its allocation to its parent's
/// ledger. The one body [`PodAuthority::release_child`] and a dropped
/// [`Reservation`] share.
///
/// The parent's record is written first, naming the child as retired, and
/// only then is the child's file removed; see the module docs. If the parent's
/// record cannot be written the child's file is KEPT, so a restart restores
/// the child as a live allocation: the same budget held, never handed back.
async fn release(inner: &tokio::sync::Mutex<Inner>, state_dir: &Path, pod_id: Uuid) {
    let mut guard = inner.lock().await;
    let inner = &mut *guard;
    let Some(entry) = inner.pods.remove(&pod_id) else {
        return;
    };
    let consumed = entry.cert.effective_permissions().budget.max_cost_usd;
    let recorded = match entry.parent {
        Parent::Root => Ok(()),
        Parent::Pod(p) => match inner.pods.get_mut(&p) {
            Some(parent) => match parent.ledger.release(pod_id.as_u128(), consumed) {
                Ok(_) => {
                    parent.retired.push(pod_id);
                    retain_unremoved(state_dir, &mut parent.retired);
                    persist_pod(state_dir, p, parent).await
                }
                Err(e) => {
                    tracing::debug!(pod = %pod_id, error = %e, "budget release found no live allocation");
                    Ok(())
                }
            },
            None => Ok(()),
        },
        Parent::External(fp) => match inner.external.get_mut(&fp) {
            Some(chain) => match chain.ledger.release(pod_id.as_u128(), consumed) {
                Ok(_) => {
                    chain.retired.push(pod_id);
                    retain_unremoved(state_dir, &mut chain.retired);
                    persist_external(state_dir, &fp, chain).await
                }
                Err(e) => {
                    tracing::debug!(pod = %pod_id, error = %e, "budget release found no live allocation");
                    Ok(())
                }
            },
            None => Ok(()),
        },
    };
    match recorded {
        Ok(()) => {
            let _ = tokio::fs::remove_file(authority_path(state_dir, pod_id)).await;
        }
        Err(e) => tracing::error!(
            pod = %pod_id,
            error = %e,
            "could not record a released allocation in its parent's ledger; the pod's \
             authority file is kept, so a restart restores it as still allocated"
        ),
    }
}

/// Keep, of `retired`, only the children whose authority file still exists:
/// the ones a restore could otherwise mistake for live. Bounded by the
/// releases whose file removal has not happened yet.
fn retain_unremoved(state_dir: &Path, retired: &mut Vec<Uuid>) {
    retired.retain(|id| authority_path(state_dir, *id).exists());
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
    ///
    /// Returns the pod's [`Reservation`]: the caller holds it across the spawn
    /// and commits it only once the pod runs.
    pub fn apply_to(self, spec: &mut PodSpec) -> Reservation {
        spec.spec.policy = nucleus_spec::PolicySpec::Inline {
            lattice: Box::new(self.effective),
        };
        spec.spec.credentialed_egress = self.upstreams;
        self.reservation
    }
}

struct PodCert {
    cert: LatticeCertificate,
    holder: Ed25519KeyPair,
    holder_pkcs8: Vec<u8>,
    ledger: BudgetLedger,
    /// Children whose release is already in `ledger`'s consumption but whose
    /// authority file may not be removed yet. See [`retain_unremoved`].
    retired: Vec<Uuid>,
    parent: Parent,
    /// What this pod was admitted — the ceiling for its own children.
    upstreams: Vec<CredentialedEgressSpec>,
}

/// An external caller chain's ledger, and its retired children as for a pod.
struct ChainLedger {
    ledger: BudgetLedger,
    retired: Vec<Uuid>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Parent {
    /// Minted by the bootstrap identity: no budget parent.
    Root,
    /// One hop below a registered pod.
    Pod(Uuid),
    /// Re-rooted from an external caller's chain, identified by fingerprint —
    /// or, for a federated tenant, by its binding's [`federated_ledger_key`].
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
    /// What this pod's retired children consumed. Absent from files written
    /// before ledgers were persisted, which recorded none.
    #[serde(default)]
    ledger: LedgerRecord,
}

/// The part of a ledger a restart cannot re-derive from live children.
#[derive(Serialize, Deserialize, Default)]
struct LedgerRecord {
    /// Consumption, in the ledger's own unit (micro-USD).
    consumed_micro: u64,
    /// Children already folded into `consumed_micro`: a restore skips them.
    retired: Vec<Uuid>,
}

/// `authority/external/<fingerprint>.json`.
#[derive(Serialize, Deserialize)]
struct PersistedChain {
    version: u8,
    /// The chain's ceiling, in micro-USD: its verified budget when first charged.
    max_micro: u64,
    ledger: LedgerRecord,
}

impl LedgerRecord {
    fn of(ledger: &BudgetLedger, retired: &[Uuid]) -> Self {
        Self {
            consumed_micro: ledger.core().parent_consumed_units(),
            retired: retired.to_vec(),
        }
    }
}

fn micro_usd(micro: u64) -> rust_decimal::Decimal {
    rust_decimal::Decimal::new(i64::try_from(micro).unwrap_or(i64::MAX), 6)
}

/// `ledger`, charged up to the `consumed_micro` its record holds. Called
/// before any child is allocated, so the charge is clamped only at `max`.
fn charged(mut ledger: BudgetLedger, consumed_micro: u64) -> BudgetLedger {
    let already = ledger.core().parent_consumed_units();
    let _ = ledger.record_parent_consumed(micro_usd(consumed_micro.saturating_sub(already)));
    ledger
}

struct Inner {
    pods: HashMap<Uuid, PodCert>,
    /// Ledgers for external callers' chains, keyed by chain fingerprint.
    external: HashMap<[u8; 32], ChainLedger>,
    /// Chains whose persisted ledger could not be read: refused, not reset.
    unreadable_chains: std::collections::HashSet<[u8; 32]>,
    /// A pod's persisted record could not be read. It cannot say whose child
    /// it was, so no delegated admission can be charged correctly: every one
    /// is refused until the file is resolved and the node restarted.
    unreadable_pod: bool,
}

/// A snapshot of [`PodAuthority`]'s state, from [`PodAuthority::held`].
#[cfg(test)]
pub(crate) struct Held {
    pub pods: std::collections::BTreeMap<Uuid, HeldPod>,
    pub external: std::collections::BTreeMap<[u8; 32], LedgerView>,
}

/// One pod's entry in a [`Held`] snapshot. Every test build reads the ledger;
/// the rest only the delegation-chain walk (`pod_api::chain_walk`) reads, and
/// that walk needs the local driver, so those fields exist only where it does.
#[cfg(test)]
pub(crate) struct HeldPod {
    #[cfg(feature = "local-driver")]
    pub cert: LatticeCertificate,
    #[cfg(feature = "local-driver")]
    pub parent: Parent,
    pub ledger: LedgerView,
    /// What the pod was admitted: the ceiling for its own children's.
    #[cfg(feature = "local-driver")]
    pub upstreams: Vec<CredentialedEgressSpec>,
}

/// A ledger in micro-USD, the unit it keeps.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LedgerView {
    pub max: u64,
    pub consumed: u64,
    pub allocated: u64,
    pub live: usize,
}

#[cfg(test)]
impl LedgerView {
    fn of(l: &BudgetLedger) -> Self {
        let core = l.core();
        Self {
            max: core.parent_max_units(),
            consumed: core.parent_consumed_units(),
            allocated: core.allocated_units(),
            live: core.live_children(),
        }
    }
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
    /// The `[[caller]]` bindings; empty when there are none.
    bindings: std::sync::Arc<CallerBindings>,
    /// Shared with every live [`Reservation`], which releases through it.
    inner: std::sync::Arc<tokio::sync::Mutex<Inner>>,
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
                    "no --upstreams registry: a pod requesting credentialed_egress is refused at admission"
                );
                None
            }
        };

        let federation = federation_source(
            args.federation_issuer.as_deref(),
            registry.as_deref(),
            state_dir,
        )?;
        let bindings = match registry.as_deref() {
            Some(reg) => CallerBindings::from_files(reg.callers(), reg, trust_domain)?,
            None => CallerBindings::default(),
        };
        if !bindings.is_empty() {
            tracing::info!(
                tenants = ?bindings.trust_domains().collect::<Vec<_>>(),
                "loaded federated caller bindings"
            );
        }

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
            bindings: std::sync::Arc::new(bindings),
            inner: std::sync::Arc::new(tokio::sync::Mutex::new(Inner {
                pods: HashMap::new(),
                external: HashMap::new(),
                unreadable_chains: std::collections::HashSet::new(),
                unreadable_pod: false,
            })),
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

    /// Admit a requested `credentialed_egress` list only if every entry is in the
    /// registry, and — for a pod caller — held by the parent as well. Otherwise
    /// refuse, naming the first entry not granted and never why.
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
    ) -> Result<Vec<CredentialedEgressSpec>, ApiError> {
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
        match dropped.first() {
            None => Ok(kept),
            Some(up) => {
                // By NAME, never by the variable's value — and not by the variable's
                // name either, which is the caller's text and may be a probe.
                tracing::warn!(
                    pod = %child_id,
                    upstream = %up.name,
                    "requested credentialed upstream is not granted (not in the operator registry, \
                     differs from its entry, or not held by the calling pod); pod refused"
                );
                Err(ApiError::Authority(format!(
                    "credentialed upstream `{}` is not granted",
                    up.name
                )))
            }
        }
    }

    /// The `[[caller]]` bindings (possibly none).
    pub fn caller_bindings(&self) -> &CallerBindings {
        &self.bindings
    }

    /// Mint the node-rooted delegation a federated caller presents at
    /// `POST /v1/pods`: root identity `principal`, permissions `ceiling`,
    /// `provenance` = `token_hash` (sha256 of the token that vouched for it).
    /// Base64 [`AttenuationToken`].
    ///
    /// The holder key is ephemeral and discarded. `mint_with_holder_key`
    /// needs the holder's PRIVATE key to sign proof-of-possession, and the
    /// caller's key is theirs — the CSR carries only its public half, and may
    /// not be Ed25519 at all. Discarding it means the caller cannot extend the
    /// chain; it does not need to, because admission requires the chain's leaf
    /// to BE the mTLS peer, and the SVID is what binds that peer to the
    /// caller's own key. The certificate alone is useless to anyone else.
    ///
    /// # Errors
    /// Key generation or serialisation failed.
    pub fn mint_federated_delegation(
        &self,
        ceiling: PermissionLattice,
        principal: String,
        not_after: DateTime<Utc>,
        token_hash: [u8; 32],
    ) -> Result<String, ApiError> {
        let holder = ephemeral_key()?;
        let cert = LatticeCertificate::mint_with_holder_key(
            ceiling,
            principal,
            not_after,
            Some(token_hash),
            &self.root_key,
            &holder,
        );
        AttenuationToken::seal(cert, self.root_pubkey.clone())
            .to_base64()
            .map_err(|e| ApiError::Authority(format!("delegation encoding: {e}")))
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

        let mut guard = self.inner.lock().await;
        let inner = &mut *guard;
        let delegated = admission.caller_pod.is_some() || admission.header_cert.is_some();
        if delegated && inner.unreadable_pod {
            return Err(ApiError::Authority(
                "this node could not restore a pod's authority record; delegated admission \
                 is refused until it is resolved"
                    .into(),
            ));
        }

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
            // A caller in a federated tenant's trust domain is held to its
            // binding: see the module docs. Decided by the AUTHENTICATED
            // identity, not by anything in the presented chain.
            let binding = crate::federation_ingress::trust_domain_of(&admission.caller_spiffe_id)
                .and_then(|td| self.bindings.by_trust_domain(td));
            // The trust decision is against OUR anchors, never the token's
            // own embedded root key (which is self-asserted) — and for a
            // federated tenant, against this node's own root key alone.
            let anchors: &[Vec<u8>] = if binding.is_some() {
                std::slice::from_ref(&self.root_pubkey)
            } else {
                &self.anchors
            };
            let verified = anchors
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
            // One ledger per binding for a federated tenant, bounded by the
            // binding's ceiling; one per presented chain otherwise. A binding's
            // ledger sits in the same persisted map as the chains', under a
            // domain-separated key (`federated_ledger_key`), so it is restored,
            // released and refused-when-unreadable by exactly the same code.
            let (key, budget) = match binding {
                Some(b) => (
                    federated_ledger_key(b.trust_domain()),
                    b.ceiling().budget.clone(),
                ),
                None => (fingerprint, verified.effective().budget.clone()),
            };
            let parent = Parent::External(key);
            if inner.unreadable_chains.contains(&key) {
                return Err(ApiError::Authority(
                    "this node could not restore the caller chain's ledger; refused".into(),
                ));
            }
            let chain = inner.external.entry(key).or_insert_with(|| ChainLedger {
                ledger: BudgetLedger::for_parent(&budget),
                retired: Vec::new(),
            });
            let ledger = &mut chain.ledger;
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
                    unreserve(inner, parent, child_id);
                    ApiError::Authority(format!("delegation refused: {e}"))
                })?;
            let ceiling = binding.map(|b| b.upstreams().to_vec());
            (cert, parent, ceiling)
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

        let upstreams = match self.admit_upstreams(
            &spec.spec.credentialed_egress,
            parent_upstreams.as_deref(),
            child_id,
        ) {
            Ok(upstreams) => upstreams,
            Err(refused) => {
                // Undo the reservation: nothing was issued. Checked only once the
                // caller's authority is established, so a caller with none learns
                // nothing about the registry from which refusal it gets.
                unreserve(inner, parent, child_id);
                return Err(refused);
            }
        };
        let effective = cert.effective_permissions().clone();
        let chain_depth = cert.chain_depth();
        let root_identity = cert.root_identity().to_string();
        let entry = PodCert {
            ledger: BudgetLedger::for_parent(&effective.budget),
            retired: Vec::new(),
            cert,
            holder: child_key,
            holder_pkcs8: child_pkcs8.as_ref().to_vec(),
            parent,
            upstreams: upstreams.clone(),
        };
        // A child that would not survive a restart would be missing from its
        // parent's ledger after one, so it is not issued. Nor is a charge to a
        // chain whose ceiling is not on disk.
        let persisted = match parent {
            Parent::External(fp) => match inner.external.get(&fp) {
                Some(chain) => persist_external(&self.state_dir, &fp, chain).await,
                None => Ok(()),
            },
            _ => Ok(()),
        };
        if let Err(e) = match persisted {
            Ok(()) => persist_pod(&self.state_dir, child_id, &entry).await,
            Err(e) => Err(e),
        } {
            tracing::error!(pod = %child_id, error = %e, "could not persist the pod's authority; refused");
            unreserve(inner, parent, child_id);
            return Err(ApiError::Authority(
                "the pod's authority could not be persisted".into(),
            ));
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
            reservation: Reservation {
                release: Some(Release {
                    inner: std::sync::Arc::clone(&self.inner),
                    state_dir: self.state_dir.clone(),
                    pod_id: child_id,
                }),
            },
            root_identity,
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

    /// A kernel deciding as `pod_id`'s certificate says, for the host's own
    /// decision service (#2702, P8).
    ///
    /// Built the way the guest builds its own: the certificate is verified
    /// against this node's root and handed to `Kernel::from_certificate` with
    /// its fingerprint. The host verifies a certificate it issued itself
    /// because `VerifiedPermissions` is minted only by verification — there is
    /// no other way to hold one, and a kernel built from an unverified lattice
    /// is the shortcut that type exists to refuse.
    pub async fn host_kernel(
        &self,
        pod_id: Uuid,
    ) -> Result<portcullis::kernel::Kernel, HostKernelError> {
        let inner = self.inner.lock().await;
        let entry = inner
            .pods
            .get(&pod_id)
            .ok_or(HostKernelError::NoCertificate)?;
        let verified = verify_certificate(
            &entry.cert,
            &self.root_pubkey,
            Utc::now(),
            DEFAULT_MAX_CHAIN_DEPTH,
        )
        .map_err(|e| HostKernelError::DoesNotVerify(e.to_string()))?;
        Ok(portcullis::kernel::Kernel::from_certificate(
            verified,
            entry.cert.fingerprint(),
        ))
    }

    /// `admit`, with the reservation committed: for tests about what admission
    /// DECIDES, which hold the pods they admit for the rest of the test.
    #[cfg(test)]
    pub(crate) async fn admit_kept(
        &self,
        admission: &Admission,
        spec: &PodSpec,
        child_id: Uuid,
    ) -> Result<IssuedAuthority, ApiError> {
        let mut issued = self.admit(admission, spec, child_id).await?;
        let reservation = std::mem::replace(&mut issued.reservation, Reservation { release: None });
        reservation.commit();
        Ok(issued)
    }

    /// Live children of `pod_id` against its ledger; `None` if it holds no
    /// certificate. For tests about the reservation's lifetime.
    #[cfg(test)]
    pub(crate) async fn live_children(&self, pod_id: Uuid) -> Option<usize> {
        let inner = self.inner.lock().await;
        Some(inner.pods.get(&pod_id)?.ledger.live_children())
    }

    /// Everything this authority holds: each pod's certificate, budget parent
    /// and ledger, and each external chain's ledger. For the delegation-chain
    /// walk (`pod_api::chain_walk`), which compares it with its model after
    /// every step.
    #[cfg(test)]
    pub(crate) async fn held(&self) -> Held {
        let inner = self.inner.lock().await;
        Held {
            pods: inner
                .pods
                .iter()
                .map(|(id, e)| {
                    let held = HeldPod {
                        #[cfg(feature = "local-driver")]
                        cert: e.cert.clone(),
                        #[cfg(feature = "local-driver")]
                        parent: e.parent,
                        ledger: LedgerView::of(&e.ledger),
                        #[cfg(feature = "local-driver")]
                        upstreams: e.upstreams.clone(),
                    };
                    (*id, held)
                })
                .collect(),
            external: inner
                .external
                .iter()
                .map(|(fp, l)| (*fp, LedgerView::of(&l.ledger)))
                .collect(),
        }
    }

    /// Retire a pod's certificate and return its budget allocation to the
    /// parent's ledger. Until children report actual spend, the whole
    /// allocation is folded into the parent's consumption (no refund).
    pub async fn release_child(&self, pod_id: Uuid) {
        release(&self.inner, &self.state_dir, pod_id).await;
    }

    /// Rebuild the registry from `pods/<id>/authority.json` after a restart,
    /// and every ledger with it: each holder's recorded consumption, then each
    /// live child re-allocated against its parent. See the module docs for
    /// what is refused when a record cannot be read.
    pub async fn restore_from_disk(&self) -> usize {
        let chains = read_chains(&self.state_dir).await;
        let mut loaded: Vec<(Uuid, PodCert)> = Vec::new();
        let mut unreadable_pod = false;
        if let Ok(mut entries) = tokio::fs::read_dir(self.state_dir.join("pods")).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let Some(id) = entry
                    .file_name()
                    .to_str()
                    .and_then(|s| Uuid::parse_str(s).ok())
                else {
                    continue;
                };
                let path = entry.path().join(AUTHORITY_FILE);
                let bytes = match tokio::fs::read(&path).await {
                    Ok(bytes) => bytes,
                    // No record: a pod that holds no authority, or whose was released.
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => {
                        tracing::error!(pod = %id, error = %e, "pod authority record unreadable");
                        unreadable_pod = true;
                        continue;
                    }
                };
                match restored_pod(&bytes) {
                    Ok(cert) => loaded.push((id, cert)),
                    Err(why) => {
                        tracing::error!(
                            pod = %id,
                            path = %path.display(),
                            why,
                            "pod authority record unreadable: delegated admission is refused \
                             until it is removed or repaired and the node restarted"
                        );
                        unreadable_pod = true;
                    }
                }
            }
        }

        let mut guard = self.inner.lock().await;
        let inner = &mut *guard;
        inner.unreadable_pod |= unreadable_pod;
        for (fp, chain) in chains {
            match chain {
                Some(chain) => {
                    inner.external.insert(fp, chain);
                }
                None => {
                    inner.unreadable_chains.insert(fp);
                }
            }
        }
        // A child its parent's record names as retired was already charged;
        // only its file outlived the release.
        let retired: std::collections::HashSet<Uuid> = loaded
            .iter()
            .flat_map(|(_, c)| c.retired.iter().copied())
            .chain(
                inner
                    .external
                    .values()
                    .flat_map(|c| c.retired.iter().copied()),
            )
            .collect();
        let mut restored = 0;
        let mut children: Vec<(Uuid, Parent, rust_decimal::Decimal)> = Vec::new();
        for (id, cert) in loaded {
            if retired.contains(&id) {
                let _ = tokio::fs::remove_file(authority_path(&self.state_dir, id)).await;
                continue;
            }
            children.push((
                id,
                cert.parent,
                cert.cert.effective_permissions().budget.max_cost_usd,
            ));
            inner.pods.insert(id, cert);
            restored += 1;
        }
        for (child, parent, amount) in children {
            let result = match parent {
                Parent::Root => Ok(()),
                Parent::Pod(p) => match inner.pods.get_mut(&p) {
                    Some(parent) => parent.ledger.try_allocate(child.as_u128(), amount),
                    None => Ok(()),
                },
                // Refused at admission anyway; nothing to charge.
                Parent::External(fp) if inner.unreadable_chains.contains(&fp) => Ok(()),
                Parent::External(fp) => inner
                    .external
                    .entry(fp)
                    // Only a node that ran before chain ledgers were persisted
                    // has a child and no record: treat what was restored as the
                    // whole ceiling, so nothing more is admitted under it.
                    .or_insert_with(|| ChainLedger {
                        ledger: BudgetLedger::for_parent(
                            &portcullis::BudgetLattice::with_cost_limit_decimal(amount),
                        ),
                        retired: Vec::new(),
                    })
                    .ledger
                    .try_allocate(child.as_u128(), amount),
            };
            if let Err(e) = result {
                tracing::warn!(pod = %child, error = %e, "restored child exceeds its parent's ledger");
            }
        }
        restored
    }

    #[cfg(test)]
    fn authority_path(&self, pod_id: Uuid) -> PathBuf {
        authority_path(&self.state_dir, pod_id)
    }
}

/// Undo a reservation made for `child_id` that will not be issued.
fn unreserve(inner: &mut Inner, parent: Parent, child_id: Uuid) {
    let ledger = match parent {
        Parent::Root => None,
        Parent::Pod(p) => inner.pods.get_mut(&p).map(|p| &mut p.ledger),
        Parent::External(fp) => inner.external.get_mut(&fp).map(|c| &mut c.ledger),
    };
    if let Some(ledger) = ledger {
        let _ = ledger.release(child_id.as_u128(), rust_decimal::Decimal::ZERO);
    }
}

/// The key a federated tenant's ledger is kept under in `Inner::external`:
/// one per binding trust domain, so every exchange under a binding draws on one
/// budget. Domain-separated from chain fingerprints, so no presented chain can
/// name a binding's ledger, nor a binding a chain's.
fn federated_ledger_key(trust_domain: &str) -> [u8; 32] {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(b"nucleus/federated-ledger/v1\0");
    h.update(trust_domain.as_bytes());
    h.finalize().into()
}

fn authority_path(state_dir: &Path, pod_id: Uuid) -> PathBuf {
    state_dir
        .join("pods")
        .join(pod_id.to_string())
        .join(AUTHORITY_FILE)
}

fn chain_path(state_dir: &Path, fp: &[u8; 32]) -> PathBuf {
    state_dir
        .join("authority")
        .join("external")
        .join(format!("{}.json", hex::encode(fp)))
}

/// A pod's record, verified as far as it can be: the holder key must be the
/// one its certificate names.
fn restored_pod(bytes: &[u8]) -> Result<PodCert, &'static str> {
    let persisted: PersistedAuthority =
        serde_json::from_slice(bytes).map_err(|_| "does not parse")?;
    let holder_pkcs8 =
        base64_decode(&persisted.holder_pkcs8_b64).map_err(|_| "holder key is not base64")?;
    let holder =
        Ed25519KeyPair::from_pkcs8(&holder_pkcs8).map_err(|_| "holder key is not a key")?;
    if holder.public_key().as_ref() != expected_next_key(&persisted.certificate) {
        return Err("holder key does not match the certificate");
    }
    let ledger = BudgetLedger::for_parent(&persisted.certificate.effective_permissions().budget);
    Ok(PodCert {
        ledger: charged(ledger, persisted.ledger.consumed_micro),
        retired: persisted.ledger.retired,
        cert: persisted.certificate,
        holder,
        holder_pkcs8,
        parent: persisted.parent,
        upstreams: persisted.upstreams,
    })
}

/// Every persisted chain ledger: `Some` restored, `None` present and unreadable.
async fn read_chains(state_dir: &Path) -> Vec<([u8; 32], Option<ChainLedger>)> {
    let mut out = Vec::new();
    let dir = state_dir.join("authority").join("external");
    let Ok(mut entries) = tokio::fs::read_dir(&dir).await else {
        return out;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name();
        let Some(fp) = name
            .to_str()
            .and_then(|n| n.strip_suffix(".json"))
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        else {
            continue; // not a record: a temporary file, or not ours
        };
        let chain = tokio::fs::read(entry.path())
            .await
            .ok()
            .and_then(|b| serde_json::from_slice::<PersistedChain>(&b).ok())
            .map(|p| ChainLedger {
                ledger: charged(
                    BudgetLedger::for_parent(&portcullis::BudgetLattice::with_cost_limit_decimal(
                        micro_usd(p.max_micro),
                    )),
                    p.ledger.consumed_micro,
                ),
                retired: p.ledger.retired,
            });
        if chain.is_none() {
            tracing::error!(
                path = %entry.path().display(),
                "caller chain ledger unreadable: that chain is refused until it is resolved"
            );
        }
        out.push((fp, chain));
    }
    out
}

async fn persist_pod(state_dir: &Path, pod_id: Uuid, entry: &PodCert) -> std::io::Result<()> {
    let persisted = PersistedAuthority {
        version: 1,
        certificate: entry.cert.clone(),
        holder_pkcs8_b64: base64_encode(&entry.holder_pkcs8),
        parent: entry.parent,
        upstreams: entry.upstreams.clone(),
        ledger: LedgerRecord::of(&entry.ledger, &entry.retired),
    };
    let bytes = serde_json::to_vec(&persisted).map_err(std::io::Error::other)?;
    write_whole(&authority_path(state_dir, pod_id), &bytes).await
}

async fn persist_external(
    state_dir: &Path,
    fp: &[u8; 32],
    chain: &ChainLedger,
) -> std::io::Result<()> {
    let persisted = PersistedChain {
        version: 1,
        max_micro: chain.ledger.core().parent_max_units(),
        ledger: LedgerRecord::of(&chain.ledger, &chain.retired),
    };
    let bytes = serde_json::to_vec(&persisted).map_err(std::io::Error::other)?;
    write_whole(&chain_path(state_dir, fp), &bytes).await
}

/// Write `bytes` to `path` whole or not at all: a sibling written owner
/// read-only (0o400) and synced, then renamed over `path`. A reader sees the
/// old record or the new one, never part of either.
async fn write_whole(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let path = path.to_path_buf();
    let bytes = bytes.to_vec();
    tokio::task::spawn_blocking(move || {
        use std::io::Write as _;
        let dir = path
            .parent()
            .ok_or_else(|| std::io::Error::other("no parent dir"))?;
        std::fs::create_dir_all(dir)?;
        let tmp = path.with_extension(format!("tmp-{}", Uuid::new_v4().simple()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o400);
        }
        let written = (|| {
            let mut f = options.open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            std::fs::rename(&tmp, &path)?;
            std::fs::File::open(dir)?.sync_all()
        })();
        if written.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        written
    })
    .await
    .map_err(std::io::Error::other)?
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
mod tests;
